"""Streaming sketches: Space-Saving guarantees, HyperLogLog accuracy, reservoir uniformity, merging."""

from __future__ import annotations

import random
from collections import Counter

import pytest

from hushwatch.analysis.sketches import MAX_DAY_SPAN, MAX_HOUR_SPAN, HyperLogLog, Reservoir, SpaceSaving, hash64


def _zipf_stream(n: int, distinct: int, seed: int) -> list[str]:
    rng = random.Random(seed)
    weights = [1.0 / (rank**1.1) for rank in range(1, distinct + 1)]
    return [f"198.51.100.{i % 256}-{i}" for i in rng.choices(range(distinct), weights=weights, k=n)]


# ---- Space-Saving ------------------------------------------------------------------------------------------------
def test_space_saving_guarantees_on_skewed_stream() -> None:
    stream = _zipf_stream(50_000, 5_000, seed=1)
    truth = Counter(stream)
    sketch: SpaceSaving[str] = SpaceSaving(64)
    for key in stream:
        sketch.add(key)
    assert sketch.total == len(stream)
    assert len(sketch) == 64
    floor = len(stream) / 64
    for key, count in truth.items():
        lower, upper = sketch.bounds(key)
        assert lower <= count <= upper, key
        if count > floor:
            assert key in sketch, f"heavy hitter {key} ({count}) must be tracked"
    for entry in sketch.entries():
        assert entry.guaranteed <= truth[entry.key] <= entry.count
        assert entry.error <= floor
    # untracked keys are bounded by the minimum count
    assert all(truth[k] <= sketch.min_count for k in truth if k not in sketch)


def test_space_saving_is_exact_below_capacity() -> None:
    sketch: SpaceSaving[str] = SpaceSaving(8)
    for i, key in enumerate(["a", "b", "a", "c", "a", "b"]):
        sketch.add(key, ts=float(i), day=100 + i // 3)
    assert [(e.key, e.count, e.error) for e in sketch.top()] == [("a", 3, 0), ("b", 2, 0), ("c", 1, 0)]
    assert sketch.min_count == 0
    assert sketch.bounds("zzz") == (0, 0)
    a = sketch.get("a")
    assert a is not None and a.first_seen == 0.0 and a.last_seen == 4.0
    assert a.daily == {100: 2, 101: 1} and a.days == {100, 101}


def test_space_saving_weights_and_validation() -> None:
    sketch: SpaceSaving[tuple[str, str]] = SpaceSaving(2)
    sketch.add(("dc01.corp.example", "svc_backup"), weight=5)
    sketch.add(("dc01.corp.example", "svc_backup"), weight=0)  # no-op
    assert sketch.total == 5
    with pytest.raises(ValueError):
        sketch.add(("x", "y"), weight=-1)
    with pytest.raises(ValueError):
        SpaceSaving(0)


def test_space_saving_out_of_order_timestamps_and_conservative_readmission() -> None:
    sketch: SpaceSaving[str] = SpaceSaving(1)
    sketch.add("old", ts=500.0)
    sketch.add("old", ts=100.0)
    entry = sketch.get("old")
    assert entry is not None and entry.first_seen == 100.0 and entry.last_seen == 500.0
    sketch.add("new", ts=900.0, day=3)  # evicts "old"
    replaced = sketch.get("new")
    assert replaced is not None
    assert (replaced.count, replaced.error) == (3, 2)
    # what happened before admission is unknown: first_seen can only be later than the truth (safe for novelty)
    assert replaced.first_seen == 900.0 and replaced.daily == {3: 1}


def test_space_saving_hours_bitset() -> None:
    sketch: SpaceSaving[str] = SpaceSaving(4)
    for hour in (1000, 1001, 1003, 999, 1003):
        sketch.add("203.0.113.9", hour=hour)
    entry = sketch.get("203.0.113.9")
    assert entry is not None
    assert entry.active_hours == 4
    assert entry.hour_span() == 5  # 999..1003
    # hostile timestamps decades apart never allocate unbounded integers
    sketch.add("203.0.113.9", hour=10_000_000)
    sketch.add("203.0.113.9", hour=-10_000_000)
    assert entry.hours.bit_length() <= MAX_HOUR_SPAN + 1
    assert entry.active_hours >= 1


def test_space_saving_day_counts_are_compact_and_bounded() -> None:
    sketch: SpaceSaving[str] = SpaceSaving(2)
    for day in (740_000, 740_003, 739_998, 740_003):
        sketch.add("svc_backup", day=day)
    entry = sketch.get("svc_backup")
    assert entry is not None
    assert entry.daily == {739_998: 1, 740_000: 1, 740_003: 2}
    sketch.add("svc_backup", day=740_000 + 10 * MAX_DAY_SPAN)  # far future: only the recent span is kept
    sketch.add("svc_backup", day=100)  # far past: ignored
    assert entry.day_counts is not None and len(entry.day_counts) <= MAX_DAY_SPAN
    assert entry.daily == {740_000 + 10 * MAX_DAY_SPAN: 1}
    assert entry.count == 6  # counts are never lost, only the per-day timeline is bounded


def test_space_saving_merge_keeps_bounds() -> None:
    left_stream = _zipf_stream(20_000, 2_000, seed=2)
    right_stream = _zipf_stream(20_000, 2_000, seed=3)
    left: SpaceSaving[str] = SpaceSaving(32)
    right: SpaceSaving[str] = SpaceSaving(32)
    for i, key in enumerate(left_stream):
        left.add(key, ts=float(i), day=i % 7, hour=i % 50)
    for i, key in enumerate(right_stream):
        right.add(key, ts=float(i + 100_000), day=7 + i % 7, hour=100 + i % 50)
    left.merge(right)
    truth = Counter(left_stream) + Counter(right_stream)
    assert left.total == 40_000
    assert len(left) <= 32
    for entry in left.entries():
        assert entry.count - entry.error <= truth[entry.key] <= entry.count
    for key, count in truth.items():
        if count > 40_000 / 32:
            assert key in left
    top = left.top(1)[0]
    assert top.first_seen is not None and top.last_seen is not None and top.first_seen < 100_000 < top.last_seen
    assert set(top.daily) <= set(range(14))
    with pytest.raises(ValueError):
        left.merge(left)


def test_space_saving_top_is_deterministic() -> None:
    def build() -> list[str]:
        sketch: SpaceSaving[str] = SpaceSaving(3)
        for key in ["b", "a", "c", "d", "a", "b"]:
            sketch.add(key)
        return [e.key for e in sketch.top(2)]

    assert build() == build()
    assert SpaceSaving[str](3).top(0) == []


# ---- HyperLogLog -------------------------------------------------------------------------------------------------
def test_hyperloglog_error_below_five_percent_at_100k() -> None:
    hll = HyperLogLog(12)
    for i in range(100_000):
        hll.add(f"rule:5710|10.0.{i % 250}.{i // 250}|{i}")
    estimate = hll.count()
    assert abs(estimate - 100_000) / 100_000 < 0.05


@pytest.mark.parametrize("n", [0, 1, 10, 100, 1000, 10_000])
def test_hyperloglog_small_and_mid_cardinalities(n: int) -> None:
    hll = HyperLogLog()
    for i in range(n):
        hll.add(f"cluster-{i}")
        hll.add(f"cluster-{i}")  # duplicates never count twice
    if n <= 100:
        assert abs(hll.count() - n) <= max(1, n // 50)
    else:
        assert abs(hll.count() - n) / n < 0.05


def test_hyperloglog_merge_is_union() -> None:
    a, b, both = HyperLogLog(), HyperLogLog(), HyperLogLog()
    for i in range(30_000):
        a.add(str(i))
        both.add(str(i))
    for i in range(20_000, 60_000):
        b.add(str(i))
        both.add(str(i))
    a.merge(b)
    assert a.count() == both.count()
    assert abs(a.count() - 60_000) / 60_000 < 0.05
    with pytest.raises(ValueError):
        a.merge(HyperLogLog(10))
    with pytest.raises(ValueError):
        HyperLogLog(3)


def test_hyperloglog_hostile_inputs() -> None:
    hll = HyperLogLog()
    hll.add("\ud800 lone surrogate")
    hll.add("x" * 1_000_000)
    hll.add(b"\x00\xff" * 10)
    assert hll.add_hash(0) is None  # an all-zero hash lands in the maximum rank without error
    assert hll.count() == 4
    assert hash64("abc") == hash64(b"abc")
    clone = hll.copy()
    assert clone.count() == hll.count() and not clone.is_empty
    assert HyperLogLog().is_empty


# ---- Reservoir ---------------------------------------------------------------------------------------------------
def test_reservoir_is_uniform_and_seeded() -> None:
    hits: Counter[int] = Counter()
    rng = random.Random(42)
    trials = 4000
    for _ in range(trials):
        reservoir: Reservoir[int] = Reservoir(5, rng)
        for item in range(50):
            reservoir.add(item)
        assert len(reservoir) == 5 and reservoir.seen == 50
        hits.update(reservoir.items)
    expected = trials * 5 / 50
    assert all(abs(hits[i] - expected) < expected * 0.25 for i in range(50))

    def sample() -> list[int]:
        res: Reservoir[int] = Reservoir(3)
        for item in range(1000):
            res.add(item)
        return res.items

    assert sample() == sample()  # default RNG is seeded: reports are reproducible


def test_reservoir_merge_and_edges() -> None:
    left: Reservoir[str] = Reservoir(3, random.Random(1))
    right: Reservoir[str] = Reservoir(3, random.Random(2))
    for i in range(10):
        left.add(f"l{i}")
    right.add("r0")
    left.merge(right)
    assert len(left) == 3 and left.seen == 11
    assert set(left.items) <= {f"l{i}" for i in range(10)} | {"r0"}
    empty: Reservoir[str] = Reservoir(0)
    empty.add("x")
    assert empty.items == [] and empty.seen == 1
    with pytest.raises(ValueError):
        Reservoir(-1)
