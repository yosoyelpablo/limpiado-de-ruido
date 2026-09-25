"""Hourly count cube for silence detection (architecture §6.1).

One streaming pass over the events fills, per key, hourly counts indexed by integer epoch hour, plus first/last
seen. Keys exist at five levels:

* ``tenant``           ``(tenant_name,)``
* ``log_source``       ``(log_source,)``           Windows channel, log file path, dataset...
* ``agent``            ``(agent,)``                the host that produced the event
* ``agent_log_source`` ``(agent, log_source)``
* ``rule``             ``(rule_id,)``              heartbeat-rule candidates ("rule went dark")

It also keeps, bounded: the (agent, log_source) pairs each rule fired on, the event codes seen per
agent/log_source (coverage) and a list of *tampering precursors* (log cleared, audit policy changed, Sysmon or
agent stopped, auditd reconfigured...) so the silence analyzer can escalate a silence that follows one.

Memory is bounded: counts live in per-key, per-UTC-day arrays of 24 unsigned ints (a sparse key only pays for the
days it was active), strings are length-capped, and the total number of keys is capped by ``max_keys``. When the cap
is hit, new keys are dropped (existing keys keep counting), ``truncated`` becomes true and the dropped events are
counted per level so the analyzer can report the analysis as incomplete (never a false green). Host-derived keys
(``agent``, ``agent_log_source``: syslog hostnames are attacker-controlled) cannot take the last 10% of the cap, so a
flood of spoofed hostnames cannot starve the rule and log-source keys; side tables (rule sources, event codes) have
their own global caps.

The indexer path fills the same cube with :meth:`CubeCollector.add_count` from composite aggregations.
"""

from __future__ import annotations

import heapq
import math
import re
from array import array
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import NamedTuple

from ..config import TenantConfig
from ..models import Event, stable_hash
from ..timeutil import UTC

__all__ = [
    "LEVELS",
    "PRECURSOR_CODES",
    "CubeCollector",
    "Precursor",
    "normalize_component",
]

LEVELS: tuple[str, ...] = ("tenant", "log_source", "agent", "agent_log_source", "rule")
_ARITY = {"tenant": 1, "log_source": 1, "agent": 1, "agent_log_source": 2, "rule": 1}
# Host-derived levels: syslog hostnames (predecoder.hostname via the manager) are attacker-controlled, so these levels
# may not use the last HOST_RESERVE share of max_keys; rules and log sources always find room.
_HOST_LEVELS = frozenset({"agent", "agent_log_source"})
HOST_RESERVE = 0.1

MAX_COMPONENT_LEN = 256
_MIN_TS = 946_684_800.0  # 2000-01-01: anything earlier is a parsing artefact, not an event
_MAX_TS = 4_102_444_800.0  # 2100-01-01
_MIN_HOUR = int(_MIN_TS // 3600)
_MAX_HOUR = int(_MAX_TS // 3600)
_MAX_COUNT = 2**53
_ZERO_DAY = array("I", [0] * 24)


class Precursor(NamedTuple):
    """An event that often precedes attacker-induced silence (possible T1070 / T1562)."""

    agent: str
    ts: float  # epoch seconds
    code: str  # canonical code, see PRECURSOR_CODES
    rule_id: str | None


# canonical precursor code -> ATT&CK technique it points to
PRECURSOR_CODES: dict[str, str] = {
    "win_1102": "T1070.001",  # Security audit log cleared
    "win_104": "T1070.001",  # System/other event log cleared
    "win_1100": "T1562.002",  # event logging service shut down
    "win_4719": "T1562.002",  # system audit policy changed
    "win_4906": "T1562.002",  # CrashOnAuditFail changed
    "sysmon_4": "T1562.001",  # Sysmon service state changed (stopped)
    "sysmon_16": "T1562.001",  # Sysmon configuration changed
    "wazuh_506": "T1562.001",  # Wazuh agent stopped
    "wazuh_504": "T1562.001",  # Wazuh agent disconnected
    "wazuh_202": "T1562.001",  # agent event queue flooding (events may be lost)
    "wazuh_203": "T1562.001",
    "wazuh_204": "T1562.001",
    "auditd_config": "T1562.012",  # auditd configuration changed
    "auditd_stop": "T1562.012",  # auditd daemon stopped / aborted
}

_SECURITY_CODES = {"1102": "win_1102", "1100": "win_1100", "4719": "win_4719", "4906": "win_4906"}
_SYSMON_CODES = {"4": "sysmon_4", "16": "sysmon_16"}
_WAZUH_RULES = {"506": "wazuh_506", "504": "wazuh_504", "202": "wazuh_202", "203": "wazuh_203", "204": "wazuh_204"}
_AUDIT_GROUPS = frozenset({"audit_configuration"})
_AUDIT_TYPES = {"CONFIG_CHANGE": "auditd_config", "DAEMON_END": "auditd_stop", "DAEMON_ABORT": "auditd_stop"}
# "ossec: Agent disconnected: '002-dc01-any'." (manager-side alert about another agent)
_AGENT_IN_MESSAGE = re.compile(
    r"Agent (?:disconnected|stopped|removed)[^']{0,40}'(?:\d{3,}-)?([^'>]{1,256}?)"
    r"(?:-(?:any|[0-9A-Fa-f:.]{2,45})|->[^']{0,256})?'"
)


def normalize_component(value: object) -> str:
    """Key component from an attacker-controllable value: ``str()``, and length-capped with a hash suffix so two
    different long values never collide and one huge value cannot blow up memory."""
    text = value if isinstance(value, str) else str(value)
    if len(text) <= MAX_COMPONENT_LEN:
        return text
    return text[: MAX_COMPONENT_LEN - 18] + "...#" + stable_hash(text, length=14)


@dataclass(slots=True)
class _KeyStats:
    first: float
    last: float
    total: int
    chunks: dict[int, array[int]]  # UTC day index (epoch hour // 24) -> 24 hourly counts


class CubeCollector:
    """Streaming, bounded, mergeable hourly count cube (one per tenant).

    ``max_keys`` caps the total number of keys across levels (``None``: ``tenant.silence.max_keys``). The single
    ``tenant`` key is always kept.
    """

    def __init__(
        self,
        tenant: TenantConfig,
        max_keys: int | None = None,
        *,
        max_rule_pairs: int = 128,
        max_event_codes: int = 128,
        max_precursors_per_agent: int = 64,
        max_precursor_agents: int = 20_000,
    ) -> None:
        self.tenant_name = normalize_component(tenant.name)
        self.max_keys = int(tenant.silence.max_keys if max_keys is None else max_keys)
        if self.max_keys < 1:
            raise ValueError("max_keys must be >= 1")
        self.max_rule_pairs = max_rule_pairs
        self.max_event_codes = max_event_codes
        self.max_precursors_per_agent = max_precursors_per_agent
        self.max_precursor_agents = max_precursor_agents
        self._data: dict[str, dict[tuple[str, ...], _KeyStats]] = {level: {} for level in LEVELS}
        self._tenant_key: tuple[str, ...] = (self.tenant_name,)
        self._n_keys = 0
        self._n_host_keys = 0
        self._host_cap = self.max_keys - int(self.max_keys * HOST_RESERVE)
        self._n_pairs = 0
        self._n_codes = 0
        self.max_side_entries = 16 * self.max_keys  # rule-source pairs and event codes, each
        self._rule_pairs: dict[str, set[tuple[str, str]]] = {}
        self._rule_pairs_overflow: set[str] = set()
        self._codes: dict[tuple[str, str], set[str]] = {}
        self._precursors: dict[str, list[tuple[float, str, str]]] = {}  # agent -> min-heap of (ts, code, rule_id)
        self.truncated = False
        self.precursors_truncated = False
        self.dropped_events: dict[str, int] = {level: 0 for level in LEVELS}
        self.dropped_keys: dict[str, int] = {level: 0 for level in LEVELS}
        self.events = 0
        self.invalid = 0  # events without a usable timestamp (not counted anywhere else)

    # ---- ingestion ------------------------------------------------------------------------------------------

    def add(self, event: Event) -> None:
        """Count one event at every level it belongs to (single pass, O(levels))."""
        t = _epoch(event.ts)
        if t is None:
            self.invalid += 1
            return
        self.events += 1
        hour = int(t // 3600)
        day, slot = divmod(hour, 24)
        data = self._data
        self._bump(data["tenant"], "tenant", self._tenant_key, day, slot, 1, t, t)
        ls = normalize_component(event.log_source) if event.log_source else None
        agent = normalize_component(event.source) if event.source else None
        if ls is not None:
            self._bump(data["log_source"], "log_source", (ls,), day, slot, 1, t, t)
        if agent is not None:
            self._bump(data["agent"], "agent", (agent,), day, slot, 1, t, t)
            if ls is not None:
                pair = (agent, ls)
                if self._bump(data["agent_log_source"], "agent_log_source", pair, day, slot, 1, t, t):
                    code = event.event_code
                    if code:
                        self._add_code(pair, str(code))
        if event.rule_id:
            rule = normalize_component(event.rule_id)
            if self._bump(data["rule"], "rule", (rule,), day, slot, 1, t, t):
                self._add_rule_pair(rule, agent or "", ls or "")
        self._detect_precursor(event, agent, ls, t)

    def add_count(
        self,
        level: str,
        key: tuple[str, ...],
        hour: int,
        count: int,
        *,
        first_seen: float | None = None,
        last_seen: float | None = None,
        rollup: bool = False,
    ) -> None:
        """Add ``count`` events to ``key`` at epoch ``hour`` (indexer path: composite aggregation buckets).

        Without explicit ``first_seen``/``last_seen`` the bucket bounds are used; ``last_seen`` defaults to the END
        of the bucket (the conservative choice: it can only make a gap look shorter). With ``rollup=True`` an
        ``agent_log_source`` count is also added to its ``agent``, ``log_source`` and ``tenant`` keys (use it only
        when those levels are not filled separately, or they would be double counted).
        """
        if level not in _ARITY:
            raise ValueError(f"unknown level {level!r}; expected one of {', '.join(LEVELS)}")
        if isinstance(hour, bool) or not isinstance(hour, int):
            raise TypeError("hour must be an int epoch hour")
        if isinstance(count, bool) or not isinstance(count, int):
            raise TypeError("count must be an int")
        if count < 0:
            raise ValueError("count must be >= 0")
        if count == 0:
            return
        if not _MIN_HOUR <= hour <= _MAX_HOUR:
            self.invalid += 1
            return
        normalized = self._normalize_key(level, key)
        lo = float(hour * 3600)
        hi = lo + 3599.0
        first = lo if first_seen is None else clamp_ts(first_seen, lo, hi)
        last = hi if last_seen is None else clamp_ts(last_seen, lo, hi)
        if first > last:
            first, last = last, first
        count = min(count, _MAX_COUNT)
        day, slot = divmod(hour, 24)
        self._bump(self._data[level], level, normalized, day, slot, count, first, last)
        if level == "agent_log_source" and rollup:
            agent, ls = normalized
            self._bump(self._data["agent"], "agent", (agent,), day, slot, count, first, last)
            self._bump(self._data["log_source"], "log_source", (ls,), day, slot, count, first, last)
            self._bump(self._data["tenant"], "tenant", self._tenant_key, day, slot, count, first, last)

    def add_series(
        self,
        level: str,
        key: tuple[str, ...],
        start_hour: int,
        counts: Sequence[int],
        *,
        first_seen: float | None = None,
        last_seen: float | None = None,
    ) -> None:
        """Bulk :meth:`add_count`: ``counts[i]`` events at hour ``start_hour + i`` (an indexer date histogram).

        ``first_seen``/``last_seen`` default to the start of the first and the end of the last non-zero bucket and
        are clamped into those buckets.
        """
        if level not in _ARITY:
            raise ValueError(f"unknown level {level!r}; expected one of {', '.join(LEVELS)}")
        if isinstance(start_hour, bool) or not isinstance(start_hour, int):
            raise TypeError("start_hour must be an int epoch hour")
        first_idx = last_idx = -1
        total = 0
        for idx, count in enumerate(counts):
            if isinstance(count, bool) or not isinstance(count, int):
                raise TypeError("counts must be ints")
            if count < 0:
                raise ValueError("counts must be >= 0")
            if count:
                if first_idx < 0:
                    first_idx = idx
                last_idx = idx
                total += count
        if first_idx < 0:
            return
        if start_hour + first_idx < _MIN_HOUR or start_hour + last_idx > _MAX_HOUR:
            self.invalid += 1
            return
        normalized = self._normalize_key(level, key)
        lo = float((start_hour + first_idx) * 3600)
        hi = float((start_hour + last_idx) * 3600 + 3599)
        first = lo if first_seen is None else clamp_ts(first_seen, lo, lo + 3599.0)
        last = hi if last_seen is None else clamp_ts(last_seen, hi - 3599.0, hi)
        mapping = self._data[level]
        st = mapping.get(normalized)
        if st is None:
            if not self._room(level):
                self.truncated = True
                self.dropped_events[level] += total
                return
            st = _KeyStats(first, last, 0, {})
            mapping[normalized] = st
            self._count_key(level)
        chunks = st.chunks
        for idx in range(first_idx, last_idx + 1):
            count = counts[idx]
            if not count:
                continue
            day, slot = divmod(start_hour + idx, 24)
            chunk = chunks.get(day)
            if chunk is None:
                chunk = array("I", _ZERO_DAY)
                chunks[day] = chunk
            chunks[day] = _add_to_chunk(chunk, slot, min(count, _MAX_COUNT))
        st.total += total
        st.first = min(st.first, first)
        st.last = max(st.last, last)

    def add_rule_source(self, rule_id: str, agent: str | None, log_source: str | None) -> None:
        """Record that ``rule_id`` fired on ``agent``/``log_source`` (indexer path)."""
        self._add_rule_pair(
            normalize_component(rule_id),
            normalize_component(agent) if agent else "",
            normalize_component(log_source) if log_source else "",
        )

    def add_event_code(self, agent: str, log_source: str, code: str) -> None:
        """Record an event code seen on ``agent``/``log_source`` (indexer path)."""
        self._add_code((normalize_component(agent), normalize_component(log_source)), str(code))

    def add_precursor(self, agent: str, ts: float, code: str, rule_id: str | None = None) -> None:
        """Record a tampering precursor (indexer path). ``code`` must be one of :data:`PRECURSOR_CODES`."""
        if code not in PRECURSOR_CODES:
            raise ValueError(f"unknown precursor code {code!r}")
        if not (_MIN_TS <= ts <= _MAX_TS):
            return
        self._push_precursor(normalize_component(agent), float(ts), code, rule_id)

    def merge(self, other: CubeCollector) -> None:
        """Merge another cube (e.g. built from another file or shard) into this one; respects ``max_keys``."""
        for level in LEVELS:
            mine = self._data[level]
            for key, st in other._data[level].items():
                target_key = self._tenant_key if level == "tenant" else key
                existing = mine.get(target_key)
                if existing is None:
                    if not self._room(level):
                        self.truncated = True
                        self.dropped_keys[level] += 1
                        self.dropped_events[level] += st.total
                        continue
                    existing = _KeyStats(st.first, st.last, 0, {})
                    mine[target_key] = existing
                    self._count_key(level)
                existing.first = min(existing.first, st.first)
                existing.last = max(existing.last, st.last)
                existing.total += st.total
                for day, chunk in st.chunks.items():
                    target = existing.chunks.get(day)
                    if target is None:
                        existing.chunks[day] = array(chunk.typecode, chunk)
                        continue
                    for slot in range(24):
                        if chunk[slot]:
                            existing.chunks[day] = target = _add_to_chunk(target, slot, chunk[slot])
        for rule, pairs in other._rule_pairs.items():
            for agent, ls in pairs:
                self._add_rule_pair(rule, agent, ls)
        self._rule_pairs_overflow |= other._rule_pairs_overflow
        for pair, codes in other._codes.items():
            for code in codes:
                self._add_code(pair, code)
        for agent, heap in other._precursors.items():
            for ts, code, rule_id in heap:
                self._push_precursor(agent, ts, code, rule_id or None)
        self.truncated = self.truncated or other.truncated
        self.precursors_truncated = self.precursors_truncated or other.precursors_truncated
        for level in LEVELS:
            self.dropped_events[level] += other.dropped_events[level]
            self.dropped_keys[level] += other.dropped_keys[level]
        self.events += other.events
        self.invalid += other.invalid

    # ---- queries --------------------------------------------------------------------------------------------

    def keys(self, level: str) -> list[tuple[str, ...]]:
        """All keys at ``level`` (sorted, deterministic)."""
        return sorted(self._level(level))

    def has(self, level: str, key: tuple[str, ...]) -> bool:
        return key in self._level(level)

    def n_keys(self) -> int:
        """Total number of keys across levels."""
        return sum(len(d) for d in self._data.values())

    def series(self, level: str, key: tuple[str, ...]) -> dict[int, int]:
        """Sparse hourly series ``{epoch_hour: count}`` (non-zero hours only)."""
        st = self._level(level).get(key)
        if st is None:
            return {}
        out: dict[int, int] = {}
        for day in sorted(st.chunks):
            chunk = st.chunks[day]
            base = day * 24
            for slot in range(24):
                value = chunk[slot]
                if value:
                    out[base + slot] = int(value)
        return out

    def dense(self, level: str, key: tuple[str, ...], start_hour: int, end_hour: int) -> list[int]:
        """Hourly counts for ``[start_hour, end_hour)`` as a dense list (zeros where nothing was seen)."""
        if end_hour <= start_hour:
            return []
        st = self._level(level).get(key)
        if st is None:
            return [0] * (end_hour - start_hour)
        out: list[int] = []
        chunks = st.chunks
        for day in range(start_hour // 24, (end_hour - 1) // 24 + 1):
            base = day * 24
            lo = max(start_hour, base) - base
            hi = min(end_hour, base + 24) - base
            chunk = chunks.get(day)
            out.extend((_ZERO_DAY if chunk is None else chunk)[lo:hi])
        return out

    def first_seen(self, level: str, key: tuple[str, ...]) -> float | None:
        st = self._level(level).get(key)
        return None if st is None else st.first

    def last_seen(self, level: str, key: tuple[str, ...]) -> float | None:
        st = self._level(level).get(key)
        return None if st is None else st.last

    def total(self, level: str, key: tuple[str, ...]) -> int:
        st = self._level(level).get(key)
        return 0 if st is None else st.total

    def rule_sources(self, rule_id: str) -> tuple[frozenset[tuple[str, str]], bool]:
        """``((agent, log_source) pairs the rule fired on, overflowed)``; empty strings mean "unknown"."""
        rule = normalize_component(rule_id)
        return frozenset(self._rule_pairs.get(rule, ())), rule in self._rule_pairs_overflow

    def event_codes(self, agent: str, log_source: str) -> frozenset[str]:
        return frozenset(self._codes.get((normalize_component(agent), normalize_component(log_source)), ()))

    @property
    def precursors(self) -> list[Precursor]:
        """Every kept precursor, sorted by agent then time."""
        out: list[Precursor] = []
        for agent in sorted(self._precursors):
            out.extend(self.precursors_for(agent))
        return out

    def precursors_for(self, agent: str) -> list[Precursor]:
        heap = self._precursors.get(normalize_component(agent), [])
        return [Precursor(agent, ts, code, rule_id or None) for ts, code, rule_id in sorted(heap)]

    def iter_level(self, level: str) -> Iterator[tuple[tuple[str, ...], float, float, int]]:
        """``(key, first_seen, last_seen, total)`` for every key at ``level`` (no copies of the counts)."""
        for key, st in self._level(level).items():
            yield key, st.first, st.last, st.total

    # ---- internals ------------------------------------------------------------------------------------------

    def _level(self, level: str) -> dict[tuple[str, ...], _KeyStats]:
        try:
            return self._data[level]
        except KeyError:
            raise ValueError(f"unknown level {level!r}; expected one of {', '.join(LEVELS)}") from None

    def _normalize_key(self, level: str, key: tuple[str, ...]) -> tuple[str, ...]:
        if level == "tenant":
            return self._tenant_key
        if not isinstance(key, tuple) or len(key) != _ARITY[level]:
            raise ValueError(f"key for level {level!r} must be a tuple of {_ARITY[level]} string(s)")
        if any(not part for part in key):
            raise ValueError("key components must be non-empty")
        return tuple(normalize_component(part) for part in key)

    def _room(self, level: str) -> bool:
        """Whether a new key may be created at ``level`` (the tenant key always can)."""
        if level == "tenant":
            return True
        if self._n_keys >= self.max_keys:
            return False
        return level not in _HOST_LEVELS or self._n_host_keys < self._host_cap

    def _count_key(self, level: str) -> None:
        self._n_keys += 1
        if level in _HOST_LEVELS:
            self._n_host_keys += 1

    def _bump(
        self,
        mapping: dict[tuple[str, ...], _KeyStats],
        level: str,
        key: tuple[str, ...],
        day: int,
        slot: int,
        count: int,
        first: float,
        last: float,
    ) -> bool:
        st = mapping.get(key)
        if st is None:
            if not self._room(level):
                self.truncated = True
                self.dropped_events[level] += count
                return False
            st = _KeyStats(first, last, 0, {})
            mapping[key] = st
            if level != "tenant" or len(mapping) == 1:
                self._count_key(level)
        chunk = st.chunks.get(day)
        if chunk is None:
            chunk = array("I", _ZERO_DAY)
            st.chunks[day] = chunk
        if count == 1 and chunk.typecode == "I" and chunk[slot] < 4_294_967_295:
            chunk[slot] += 1
        else:
            st.chunks[day] = _add_to_chunk(chunk, slot, count)
        st.total += count
        if first < st.first:
            st.first = first
        if last > st.last:
            st.last = last
        return True

    def _add_rule_pair(self, rule: str, agent: str, ls: str) -> None:
        pairs = self._rule_pairs.get(rule)
        if pairs is None:
            if len(self._rule_pairs) >= self.max_keys:
                self._rule_pairs_overflow.add(rule)
                return
            pairs = set()
            self._rule_pairs[rule] = pairs
        if (agent, ls) in pairs:
            return
        if len(pairs) >= self.max_rule_pairs or self._n_pairs >= self.max_side_entries:
            self._rule_pairs_overflow.add(rule)
            return
        pairs.add((agent, ls))
        self._n_pairs += 1

    def _add_code(self, pair: tuple[str, str], code: str) -> None:
        codes = self._codes.get(pair)
        if codes is None:
            if len(self._codes) >= self.max_keys:
                return
            codes = set()
            self._codes[pair] = codes
        if len(codes) < self.max_event_codes and self._n_codes < self.max_side_entries:
            value = normalize_component(code)[:64]
            if value not in codes:
                codes.add(value)
                self._n_codes += 1

    def _detect_precursor(self, event: Event, agent: str | None, ls: str | None, t: float) -> None:
        code_name: str | None = None
        event_code = event.event_code
        if event_code:
            code = str(event_code).strip()
            channel = (ls or "").lower()
            if "sysmon" in channel:
                code_name = _SYSMON_CODES.get(code)
            elif code in _SECURITY_CODES:
                if "security" in channel or (not channel and event.os_platform == "windows"):
                    code_name = _SECURITY_CODES[code]
            elif code == "104" and "system" in channel and "security" not in channel:
                code_name = "win_104"
        rule_id = event.rule_id
        if code_name is None and rule_id:
            code_name = _WAZUH_RULES.get(str(rule_id))
            if code_name is None and event.rule_groups and not _AUDIT_GROUPS.isdisjoint(event.rule_groups):
                code_name = "auditd_config"
        if code_name is None and event.fields:
            audit_type = event.fields.get("data.audit.type")
            if isinstance(audit_type, str):
                code_name = _AUDIT_TYPES.get(audit_type.strip().upper())
        if code_name is None:
            return
        rid = normalize_component(rule_id) if rule_id else None
        if agent is not None:
            self._push_precursor(agent, t, code_name, rid)
        if code_name == "wazuh_504" or (code_name == "wazuh_506" and event.fields.get("agent.id") == "000"):
            # Manager-side alert about ANOTHER agent: attribute it to the agent named in the message.
            for target in _agents_named_in(event):
                if target != agent:
                    self._push_precursor(target, t, code_name, rid)

    def _push_precursor(self, agent: str, ts: float, code: str, rule_id: str | None) -> None:
        heap = self._precursors.get(agent)
        if heap is None:
            if len(self._precursors) >= self.max_precursor_agents:
                self.precursors_truncated = True
                return
            heap = []
            self._precursors[agent] = heap
        item = (ts, code, rule_id or "")
        if item in heap:
            return
        if len(heap) < self.max_precursors_per_agent:
            heapq.heappush(heap, item)
        else:
            # keep the most recent ones: silence starts are recent, and an attacker spamming log clears early in
            # the window cannot evict the precursor that matters
            self.precursors_truncated = True
            if item > heap[0]:
                heapq.heapreplace(heap, item)


def _agents_named_in(event: Event) -> Iterable[str]:
    for field in ("full_log", "data.extra_data"):
        value = event.fields.get(field)
        if isinstance(value, str) and value:
            match = _AGENT_IN_MESSAGE.search(value[:2048])
            if match:
                yield normalize_component(match.group(1))
                return


def _add_to_chunk(chunk: array[int], slot: int, count: int) -> array[int]:
    """Add ``count`` to ``chunk[slot]``, widening the array to 64-bit when a 32-bit counter would overflow."""
    value = chunk[slot] + count
    if chunk.typecode == "I" and value > 4_294_967_295:
        chunk = array("q", chunk)
    chunk[slot] = min(value, _MAX_COUNT)
    return chunk


def _epoch(ts: object) -> float | None:
    if not isinstance(ts, datetime):
        return None
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=UTC)
    try:
        t = ts.timestamp()
    except (OverflowError, OSError, ValueError):
        return None
    if not (_MIN_TS <= t <= _MAX_TS):
        return None
    return t


def clamp_ts(value: float, lo: float, hi: float) -> float:
    """Clamp an epoch timestamp into ``[lo, hi]`` (NaN becomes ``hi``)."""
    if not math.isfinite(value):
        return hi
    return lo if value < lo else hi if value > hi else value
