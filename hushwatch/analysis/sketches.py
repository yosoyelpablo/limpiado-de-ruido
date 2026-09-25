"""Bounded-memory, mergeable streaming sketches used by the noise engine.

* :class:`SpaceSaving` — top-k heavy hitters (Metwally et al. 2005) with the classic guarantees: every key whose
  true weight exceeds ``total / capacity`` is tracked, and for every tracked key
  ``count - error <= true weight <= count``. Each entry also keeps first/last seen, a per-day weight map and an
  optional bitset of active hours. Everything an entry learns after being (re)admitted is exact; what happened
  before admission is folded into ``error``. Consequences that matter for safety: ``first_seen`` can only be
  *later* than the truth and per-day presence can only be *lower*, so novelty/persistence gates err on the side
  of "investigate".
* :class:`HyperLogLog` — distinct counting with ``2**p`` one-byte registers (p=12: 4 KiB, ~1.6% standard
  error), 64-bit BLAKE2b hashes, the ``alpha_m`` bias constant and linear counting for small cardinalities
  (Flajolet et al. 2007; with a 64-bit hash no large-range correction is needed, Heule et al. 2013).
* :class:`Reservoir` — uniform sample of ``k`` items (Vitter's algorithm R) with a seeded RNG so reports are
  reproducible.

All three support ``merge`` so rotated files can be processed independently and combined.
"""

from __future__ import annotations

import hashlib
import heapq
import itertools
import math
import random
from array import array
from collections.abc import Hashable, Iterator
from dataclasses import dataclass
from typing import Generic, TypeVar

K = TypeVar("K", bound=Hashable)
T = TypeVar("T")

RESERVOIR_SEED = 0x5EED
# Hour bitsets and day arrays never grow beyond these spans (hostile timestamps decades apart must not allocate
# huge objects); the most recent span is kept.
MAX_HOUR_SPAN = 24 * 366 * 2
MAX_DAY_SPAN = 800


@dataclass(slots=True)
class SpaceSavingEntry(Generic[K]):
    """One tracked key. ``count`` is an upper bound, ``count - error`` a lower bound of its true weight."""

    key: K
    count: int
    error: int = 0
    first_seen: float | None = None  # epoch seconds (earliest since admission)
    last_seen: float | None = None
    day_base: int | None = None  # compact per-day weights: day_counts[i] is day (day_base + i)
    day_counts: array[int] | None = None
    hours: int = 0  # bitset of active hours, bit i == hour (hour_base + i)
    hour_base: int | None = None

    @property
    def daily(self) -> dict[int, int]:
        """Day index -> weight since admission (days without activity omitted)."""
        counts, base = self.day_counts, self.day_base
        if counts is None or base is None:
            return {}
        return {base + i: c for i, c in enumerate(counts) if c}

    @property
    def guaranteed(self) -> int:
        """Lower bound of the true weight."""
        return self.count - self.error

    @property
    def days(self) -> set[int]:
        """Day indexes on which the key was seen (since admission)."""
        return set(self.daily)

    def _add_day(self, day: int, weight: int) -> None:
        counts, base = self.day_counts, self.day_base
        if counts is None or base is None:
            self.day_base, self.day_counts = day, array("Q", (weight,))
            return
        offset = day - base
        if 0 <= offset < len(counts):
            counts[offset] += weight
            return
        if offset >= len(counts):
            if offset >= MAX_DAY_SPAN:  # keep the most recent MAX_DAY_SPAN days
                new_base = day - MAX_DAY_SPAN + 1
                drop = new_base - base
                if drop >= len(counts):
                    counts = array("Q")
                else:
                    del counts[:drop]
                base, offset = new_base, day - new_base
            counts.extend(itertools.repeat(0, offset - len(counts)))
            counts.append(weight)
            self.day_base, self.day_counts = base, counts
            return
        if len(counts) - offset > MAX_DAY_SPAN:
            return  # older than the retained span
        grown = array("Q", itertools.repeat(0, -offset))
        grown.extend(counts)
        grown[0] = weight
        self.day_base, self.day_counts = day, grown

    @property
    def active_hours(self) -> int:
        """Number of distinct hours with activity (since admission; 0 when hours are not tracked)."""
        return self.hours.bit_count()

    def hour_span(self) -> int:
        """Hours between the first and last active hour, inclusive (0 when hours are not tracked)."""
        if self.hour_base is None or not self.hours:
            return 0
        return self.hours.bit_length()

    def _touch(self, weight: int, ts: float | None, day: int | None, hour: int | None) -> None:
        if ts is not None:
            if self.first_seen is None or ts < self.first_seen:
                self.first_seen = ts
            if self.last_seen is None or ts > self.last_seen:
                self.last_seen = ts
        if day is not None:
            self._add_day(day, weight)
        if hour is not None:
            self._set_hour(hour)

    def _set_hour(self, hour: int) -> None:
        base = self.hour_base
        if base is None or not self.hours:
            self.hour_base, self.hours = hour, 1
            return
        if hour >= base:
            offset = hour - base
            if offset > MAX_HOUR_SPAN:  # keep the most recent MAX_HOUR_SPAN hours only
                drop = offset - MAX_HOUR_SPAN
                self.hours >>= drop
                base += drop
                offset = MAX_HOUR_SPAN
            self.hours |= 1 << offset
            self.hour_base = base
            self._strip_hours()
            return
        shift = base - hour
        if shift + self.hours.bit_length() > MAX_HOUR_SPAN + 1:
            return  # older than the retained span
        self.hours = (self.hours << shift) | 1
        self.hour_base = hour

    def _strip_hours(self) -> None:
        """Keep bit 0 == earliest active hour."""
        if self.hours and self.hour_base is not None:
            trailing = (self.hours & -self.hours).bit_length() - 1
            if trailing:
                self.hours >>= trailing
                self.hour_base += trailing

    def _absorb(self, other: SpaceSavingEntry[K]) -> None:
        """Fold another entry's timeline (first/last seen, days, hours) into this one."""
        if other.first_seen is not None and (self.first_seen is None or other.first_seen < self.first_seen):
            self.first_seen = other.first_seen
        if other.last_seen is not None and (self.last_seen is None or other.last_seen > self.last_seen):
            self.last_seen = other.last_seen
        for day, weight in other.daily.items():
            self._add_day(day, weight)
        if other.hour_base is None or not other.hours:
            return
        if self.hour_base is None or not self.hours:
            self.hour_base, self.hours = other.hour_base, other.hours
            return
        base = min(self.hour_base, other.hour_base)
        combined = (self.hours << (self.hour_base - base)) | (other.hours << (other.hour_base - base))
        excess = combined.bit_length() - (MAX_HOUR_SPAN + 1)
        if excess > 0:  # keep the most recent span
            combined >>= excess
            base += excess
        self.hours, self.hour_base = combined, base
        self._strip_hours()


class SpaceSaving(Generic[K]):
    """Space-Saving top-k summary over hashable keys.

    ``add`` is O(log k) amortized (lazy min-heap: counts only grow, so a stale heap item is a lower bound and
    is refreshed when it reaches the top). Ties are broken by insertion order, so results are deterministic.
    """

    __slots__ = ("_entries", "_heap", "_seq", "capacity", "total")

    def __init__(self, capacity: int = 64) -> None:
        if capacity < 1:
            raise ValueError("SpaceSaving capacity must be >= 1")
        self.capacity = capacity
        self.total = 0
        self._entries: dict[K, SpaceSavingEntry[K]] = {}
        self._heap: list[tuple[int, int, K]] = []
        self._seq = itertools.count()

    # ---- updates ---------------------------------------------------------------------------------------------
    def add(
        self,
        key: K,
        weight: int = 1,
        ts: float | None = None,
        day: int | None = None,
        hour: int | None = None,
    ) -> None:
        """Count ``weight`` occurrences of ``key`` at epoch ``ts`` on day index ``day`` (and epoch ``hour``)."""
        if weight <= 0:
            if weight == 0:
                return
            raise ValueError("SpaceSaving weights must be positive")
        self.total += weight
        entry = self._entries.get(key)
        if entry is not None:  # hot path, inlined
            entry.count += weight
            if ts is not None:
                last = entry.last_seen
                if last is None or ts > last:
                    entry.last_seen = ts
                first = entry.first_seen
                if first is None or ts < first:
                    entry.first_seen = ts
            if day is not None:
                counts, base = entry.day_counts, entry.day_base
                if counts is not None and base is not None and 0 <= day - base < len(counts):
                    counts[day - base] += weight
                else:
                    entry._add_day(day, weight)
            if hour is not None:
                base = entry.hour_base
                if base is not None and entry.hours and 0 <= hour - base <= MAX_HOUR_SPAN:
                    entry.hours |= 1 << (hour - base)
                else:
                    entry._set_hour(hour)
            return
        if len(self._entries) < self.capacity:
            entry = SpaceSavingEntry(key, weight)
            entry._touch(weight, ts, day, hour)
            self._entries[key] = entry
            heapq.heappush(self._heap, (weight, next(self._seq), key))
            return
        # Evict the minimum and recycle its entry object for the new key (one heap operation, no allocation).
        victim = self._min_entry()
        del self._entries[victim.key]
        floor = victim.count
        victim.key = key
        victim.count = floor + weight
        victim.error = floor
        victim.first_seen = victim.last_seen = ts
        if day is not None:
            victim.day_base, victim.day_counts = day, array("Q", (weight,))
        else:
            victim.day_base = victim.day_counts = None
        if hour is not None:
            victim.hour_base, victim.hours = hour, 1
        else:
            victim.hour_base, victim.hours = None, 0
        self._entries[key] = victim
        heapq.heapreplace(self._heap, (victim.count, next(self._seq), key))

    def _min_entry(self) -> SpaceSavingEntry[K]:
        """The entry with the minimum count; it is left at the top of the heap (the caller replaces it)."""
        heap = self._heap
        while True:
            count, _, key = heap[0]
            entry = self._entries[key]
            if entry.count == count:
                return entry
            heapq.heapreplace(heap, (entry.count, next(self._seq), key))

    def merge(self, other: SpaceSaving[K]) -> None:
        """Merge another summary into this one (mergeable-summaries rule: keys missing from a full summary
        are charged that summary's minimum count, both as count and as error)."""
        if other is self:
            raise ValueError("cannot merge a SpaceSaving summary into itself")
        min_self = self.min_count
        min_other = other.min_count
        merged: dict[K, SpaceSavingEntry[K]] = {}
        for key in itertools.chain(self._entries, (k for k in other._entries if k not in self._entries)):
            mine = self._entries.get(key)
            theirs = other._entries.get(key)
            count = (mine.count if mine else min_self) + (theirs.count if theirs else min_other)
            error = (mine.error if mine else min_self) + (theirs.error if theirs else min_other)
            entry: SpaceSavingEntry[K] = SpaceSavingEntry(key, count, error)
            if mine is not None:
                entry._absorb(mine)
            if theirs is not None:
                entry._absorb(theirs)
            merged[key] = entry
        kept = sorted(merged.values(), key=lambda e: -e.count)[: self.capacity]
        self._entries = {e.key: e for e in kept}
        self._heap = [(e.count, next(self._seq), e.key) for e in kept]
        heapq.heapify(self._heap)
        self.total += other.total

    # ---- queries ---------------------------------------------------------------------------------------------
    @property
    def is_full(self) -> bool:
        return len(self._entries) >= self.capacity

    @property
    def min_count(self) -> int:
        """Upper bound of the weight of any key that is NOT tracked (0 while the summary is not full)."""
        if not self.is_full:
            return 0
        return min(e.count for e in self._entries.values())

    def bounds(self, key: K) -> tuple[int, int]:
        """Guaranteed ``(lower, upper)`` bounds of the true weight of ``key``."""
        entry = self._entries.get(key)
        if entry is None:
            return (0, self.min_count)
        return (entry.count - entry.error, entry.count)

    def get(self, key: K) -> SpaceSavingEntry[K] | None:
        return self._entries.get(key)

    def entries(self) -> list[SpaceSavingEntry[K]]:
        """All tracked entries (insertion order)."""
        return list(self._entries.values())

    def top(self, n: int | None = None) -> list[SpaceSavingEntry[K]]:
        """Tracked entries by decreasing count (then decreasing guaranteed count, then insertion order)."""
        ordered = sorted(self._entries.values(), key=lambda e: (-e.count, -(e.count - e.error)))
        return ordered if n is None else ordered[: max(0, n)]

    def __len__(self) -> int:
        return len(self._entries)

    def __contains__(self, key: object) -> bool:
        return key in self._entries

    def __iter__(self) -> Iterator[SpaceSavingEntry[K]]:
        return iter(list(self._entries.values()))


def _alpha(m: int) -> float:
    if m == 16:
        return 0.673
    if m == 32:
        return 0.697
    if m == 64:
        return 0.709
    return 0.7213 / (1.0 + 1.079 / m)


_INV_POW2: tuple[float, ...] = tuple(2.0**-r for r in range(66))


def hash64(item: str | bytes) -> int:
    """64-bit BLAKE2b hash of a string (UTF-8, lone surrogates tolerated) or bytes."""
    data = item.encode("utf-8", "surrogatepass") if isinstance(item, str) else bytes(item)
    return int.from_bytes(hashlib.blake2b(data, digest_size=8).digest(), "big")


class HyperLogLog:
    """HyperLogLog distinct counter with ``2**p`` registers (default p=12, ~1.6% standard error)."""

    __slots__ = ("_registers", "m", "p")

    def __init__(self, p: int = 12) -> None:
        if not 4 <= p <= 18:
            raise ValueError("HyperLogLog precision p must be in 4..18")
        self.p = p
        self.m = 1 << p
        self._registers = bytearray(self.m)

    def add(self, item: str | bytes) -> None:
        """Add one item (``str`` is hashed as UTF-8)."""
        self.add_hash(hash64(item))

    def add_hash(self, x: int) -> None:
        """Add a precomputed 64-bit hash."""
        q = 64 - self.p
        index = x >> q
        rank = q - (x & ((1 << q) - 1)).bit_length() + 1
        if rank > self._registers[index]:
            self._registers[index] = rank

    def count(self) -> int:
        """Estimated number of distinct items."""
        registers = self._registers
        m = self.m
        total = 0.0
        for r in set(registers):
            total += registers.count(r) * _INV_POW2[r]
        estimate = _alpha(m) * m * m / total
        zeros = registers.count(0)
        if estimate <= 2.5 * m and zeros:
            estimate = m * math.log(m / zeros)  # linear counting (small-range correction)
        return round(estimate)

    def merge(self, other: HyperLogLog) -> None:
        """Union with another sketch of the same precision."""
        if other.p != self.p:
            raise ValueError("cannot merge HyperLogLog sketches with different precision")
        self._registers = bytearray(map(max, self._registers, other._registers))

    def copy(self) -> HyperLogLog:
        clone = HyperLogLog(self.p)
        clone._registers = bytearray(self._registers)
        return clone

    @property
    def is_empty(self) -> bool:
        return not any(self._registers)


class Reservoir(Generic[T]):
    """Uniform random sample of at most ``k`` items from a stream (algorithm R, seeded RNG)."""

    __slots__ = ("_items", "_rng", "k", "seen")

    def __init__(self, k: int = 3, rng: random.Random | None = None) -> None:
        if k < 0:
            raise ValueError("Reservoir size must be >= 0")
        self.k = k
        self.seen = 0
        self._rng = rng if rng is not None else random.Random(RESERVOIR_SEED)
        self._items: list[T] = []

    def add(self, item: T) -> None:
        self.seen += 1
        if len(self._items) < self.k:
            self._items.append(item)
            return
        slot = self._rng.randrange(self.seen)
        if slot < self.k:
            self._items[slot] = item

    @property
    def items(self) -> list[T]:
        return list(self._items)

    def merge(self, other: Reservoir[T]) -> None:
        """Combine two reservoirs so the result is (approximately) a uniform sample of both streams."""
        pools = [list(self._items), list(other._items)]
        remaining = [self.seen, other.seen]
        out: list[T] = []
        while len(out) < self.k and (pools[0] or pools[1]):
            if pools[0] and (not pools[1] or self._rng.random() * (remaining[0] + remaining[1]) < remaining[0]):
                side = 0
            else:
                side = 1
            pool = pools[side]
            out.append(pool.pop(self._rng.randrange(len(pool))))
            remaining[side] = max(0, remaining[side] - 1)
        self._items = out
        self.seen += other.seen

    def __len__(self) -> int:
        return len(self._items)
