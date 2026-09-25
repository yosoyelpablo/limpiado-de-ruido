"""Silence engine tests: planted outages, traps that must NOT alarm, calibration and performance.

All data is synthetic and seeded: negative-binomial hourly counts with diurnal and weekly seasonality generated in
tenant-local time, RFC-2606 style host names and fake accounts only.

A calibrated engine raises about ``alarm_budget`` false alarms per run by design, so a trap test that probes many
"now" values would see ~budget × probes random alarms. Trap tests therefore run with a strict budget
(``TRAP_BUDGET``): a systematic trap failure (a DST shift, a weekend or a holiday read as an outage) produces
P0 values like 1e-20 and still fires, while the random background stays near zero. The random background itself is
measured by the calibration tests at the default budget.
"""

from __future__ import annotations

import math
import random
import time
from collections.abc import Callable, Iterable, Iterator
from datetime import date, datetime, timedelta, timezone
from typing import Any

import pytest

from hushwatch.analysis.cube import CubeCollector
from hushwatch.analysis.silence import STATUSES, SilenceResult, analyze_silence
from hushwatch.config import CalendarEntry, TenantConfig
from hushwatch.i18n import Entity, Message, has, render
from hushwatch.inventory import AgentInfo
from hushwatch.models import Confidence, DataBasis, Event, Finding, Severity, fingerprint, iter_entities

UTC = timezone.utc
MONDAY = datetime(2026, 8, 3, tzinfo=UTC)  # a Monday (UTC)
SYSMON = "Microsoft-Windows-Sysmon/Operational"
ARCHIVES = DataBasis(input_kind="archives", profile="wazuh4")
TRAP_BUDGET = 0.002
ALARM_KINDS = (
    "silence.silent",
    "silence.drop",
    "silence.decay",
    "silence.rule_dark",
    "silence.tampering",
    "pipeline.global_silence",
)


# ---- synthetic world ------------------------------------------------------------------------------------------


def poisson(rng: random.Random, lam: float) -> int:
    total = 0
    while lam > 0:
        piece = min(lam, 25.0)
        lam -= piece
        limit = math.exp(-piece)
        k = 0
        p = rng.random()
        while p > limit:
            k += 1
            p *= rng.random()
        total += k
    return total


def nb(rng: random.Random, mu: float, k: float) -> int:
    return 0 if mu <= 0 else poisson(rng, rng.gammavariate(k, mu / k))


PATTERNS: dict[str, Callable[[int], float]] = {
    "flat": lambda h: 1.0,
    "sine": lambda h: 1.0 + 0.6 * math.sin((h - 9) / 24 * 2 * math.pi),
    "office": lambda h: 2.4 if 8 <= h < 18 else 0.05,
    "laptop": lambda h: 2.4 if 8 <= h < 18 else 0.0,
}


class World:
    """Hourly NB streams per (agent, log source) rolled up into a cube (tenant-local seasonality)."""

    def __init__(self, tenant: TenantConfig, *, hours: int, start: datetime = MONDAY, seed: int = 1) -> None:
        self.tenant = tenant
        self.rng = random.Random(seed)
        self.start_h = int(start.timestamp() // 3600)
        self.hours = hours
        tz = tenant.tz
        self.local: list[tuple[int, int, date]] = []
        for h in range(hours):
            lt = datetime.fromtimestamp((self.start_h + h) * 3600 + 1800, tz)
            self.local.append((lt.hour, lt.weekday(), lt.date()))
        self._agg: dict[tuple[str, tuple[str, ...]], list[Any]] = {}
        self.rule_pairs: list[tuple[str, str, str]] = []

    @property
    def end(self) -> datetime:
        return datetime.fromtimestamp((self.start_h + self.hours) * 3600, UTC)

    def stream(
        self,
        agent: str,
        ls: str,
        rate: float,
        *,
        pattern: str = "flat",
        k: float = 5.0,
        weekend: float = 1.0,
        stop: datetime | None = None,
        start: datetime | None = None,
        off_prob: float = 0.0,
        holidays: Iterable[date] = (),
        rule: str | None = None,
        utc_hours: dict[int, float] | None = None,
        factor: Callable[[int], float] | None = None,
    ) -> None:
        """Add one NB stream. ``stop``/``start`` bound it in time; ``factor(h)`` scales hour index ``h``."""
        rng = self.rng
        shape = PATTERNS[pattern]
        holidays = set(holidays)
        dates = sorted({d for _, _, d in self.local})
        off = {d for d in dates if d.weekday() < 5 and rng.random() < off_prob}
        stop_ts = stop.timestamp() if stop else math.inf
        start_ts = start.timestamp() if start else -math.inf
        counts = [0] * self.hours
        first = math.inf
        last = -math.inf
        for h in range(self.hours):
            hod, dow, day = self.local[h]
            if utc_hours is not None:
                mu = rate * utc_hours.get((self.start_h + h) % 24, 0.001)
            else:
                mu = rate * shape(hod) * (weekend if dow >= 5 else 1.0)
            if day in off or day in holidays:
                mu = 0.0
            if factor is not None:
                mu *= factor(h)
            b = (self.start_h + h) * 3600.0
            lo, hi = max(b, start_ts), min(b + 3600.0, stop_ts)
            if hi <= lo:
                continue
            c = nb(rng, mu * (hi - lo) / 3600.0, k)
            if not c:
                continue
            counts[h] = c
            span = hi - lo - 1e-3
            first = min(first, lo + span * (1.0 - rng.random() ** (1.0 / c)))
            last = max(last, lo + span * rng.random() ** (1.0 / c))
        keys = [
            ("agent_log_source", (agent, ls)),
            ("agent", (agent,)),
            ("log_source", (ls,)),
            ("tenant", (self.tenant.name,)),
        ]
        if rule is not None:
            keys.append(("rule", (rule,)))
            self.rule_pairs.append((rule, agent, ls))
        for key in keys:
            entry = self._agg.setdefault(key, [[0] * self.hours, math.inf, -math.inf])
            acc = entry[0]
            for h, c in enumerate(counts):
                if c:
                    acc[h] += c
            entry[1] = min(entry[1], first)
            entry[2] = max(entry[2], last)

    def build(self, cube: CubeCollector | None = None) -> CubeCollector:
        cube = cube or CubeCollector(self.tenant)
        for (level, key), (counts, first, last) in sorted(self._agg.items()):
            if any(counts):
                cube.add_series(level, key, self.start_h, counts, first_seen=first, last_seen=last)
        for rule, agent, ls in self.rule_pairs:
            cube.add_rule_source(rule, agent, ls)
        return cube


def run(world: World, cube: CubeCollector, now: datetime, basis: DataBasis = ARCHIVES, **kw: Any) -> SilenceResult:
    return analyze_silence(cube, tenant=world.tenant, now=now, basis=basis, **kw)


def alarms(result: SilenceResult) -> list[Finding]:
    return [f for f in result.findings if f.kind in ALARM_KINDS]


def describe(findings: Iterable[Finding]) -> list[tuple[str, str]]:
    return [(f.kind, f.subject) for f in findings]


def servers(world: World, n: int, prefix: str = "srv", *, stop: dict[str, datetime] | None = None) -> list[str]:
    names = []
    stop = stop or {}
    for i in range(n):
        name = f"{prefix}-{i:02d}.example"
        names.append(name)
        world.stream(name, "Security", 25.0, pattern="sine", k=5.0, stop=stop.get(name))
        world.stream(name, "System", 4.0, k=3.0, stop=stop.get(name))
    return names


# ---- planted outages that must be detected ---------------------------------------------------------------------


def test_always_on_source_stopping_for_6h_is_detected_with_tier_severity() -> None:
    tenant = TenantConfig(name="acme", criticality={"critical": ["dc*"]})
    world = World(tenant, hours=21 * 24)
    stop = world.end - timedelta(hours=6)
    servers(world, 12, stop={"srv-07.example": stop})
    for dc in ("dc01.corp.example", "dc02.corp.example"):
        world.stream(dc, "Security", 60.0, pattern="sine", stop=stop if dc.startswith("dc02") else None)
        world.stream(dc, "System", 5.0, stop=stop if dc.startswith("dc02") else None)
    cube = world.build()
    result = run(world, cube, world.end)
    found = {f.subject: f for f in alarms(result)}
    assert set(found) == {"agent:srv-07.example", "agent:dc02.corp.example"}
    assert found["agent:dc02.corp.example"].severity is Severity.CRITICAL
    assert found["agent:srv-07.example"].severity is Severity.HIGH
    finding = found["agent:srv-07.example"]
    ev = finding.evidence
    assert ev["observed"] >= 0 and ev["expected_in_gap"] > 50
    assert ev["p0"] < ev["alpha_eff"]
    assert ev["gap_seconds"] >= 6 * 3600 - 3600
    assert ev["duty"] == "always_on" and ev["tier"] == "standard"
    assert ev["last_seen"].endswith("Z")
    assert ev["reproduce"]["filter"] == {"agent.name": Entity("host", "srv-07.example")}
    assert finding.confidence is Confidence.HIGH
    # the channels of the silent agent are explained (listed in related), not separate findings
    for ls in ("Security", "System"):
        assert result.statuses[("agent_log_source", ("srv-07.example", ls))] == "explained"
        assert fingerprint("acme", "silence.silent", f"agent:srv-07.example|ls:{ls}") in finding.related
    assert result.statuses[("agent", ("srv-07.example",))] == "silent"
    assert result.section["status"] == "fail"
    assert result.section["status_counts"]["silent"] == 2
    assert result.section["status_counts"]["explained"] >= 4


def test_business_hours_source_that_does_not_come_up_on_monday_is_detected() -> None:
    tenant = TenantConfig(name="acme", timezone="America/Argentina/Buenos_Aires")
    tenant.silence.alarm_budget = TRAP_BUDGET  # the quiet-weekend probes are traps
    world = World(tenant, hours=21 * 24 + 15, start=MONDAY + timedelta(hours=3))  # local midnight
    friday_evening = MONDAY + timedelta(days=18, hours=3 + 18)  # Friday 18:00 local of week 3
    for i in range(10):
        world.stream(
            f"app-{i:02d}.example",
            "/var/log/app/access.log",
            20.0,
            pattern="laptop",  # nothing at all outside 08-18 on weekdays
            weekend=0.0,
            stop=friday_evening if i == 3 else None,
        )
    cube = world.build()
    monday = MONDAY + timedelta(days=21, hours=3)  # Monday 00:00 local, week 4
    quiet_times = [monday - timedelta(hours=30), monday - timedelta(hours=9), monday + timedelta(hours=7)]
    for now in quiet_times:
        assert alarms(run(world, cube, now)) == [], now
    result = run(world, cube, monday + timedelta(hours=11, minutes=30))
    subjects = describe(alarms(result))
    assert ("silence.silent", "agent:app-03.example") in subjects
    assert len(subjects) == 1
    finding = alarms(result)[0]
    assert finding.evidence["duty"] == "business_hours"


def test_one_agents_sysmon_channel_stopping_is_reported_at_channel_level() -> None:
    tenant = TenantConfig(name="acme")
    world = World(tenant, hours=21 * 24)
    stop = world.end - timedelta(hours=5)
    for i in range(15):
        name = f"ws-{i:02d}.corp.example"
        world.stream(name, "Security", 20.0, pattern="sine")
        world.stream(name, "System", 3.0)
        world.stream(name, SYSMON, 40.0, pattern="sine", stop=stop if i == 5 else None)
    cube = world.build()
    result = run(world, cube, world.end)
    assert describe(alarms(result)) == [("silence.silent", f"agent:ws-05.corp.example|ls:{SYSMON}")]
    finding = alarms(result)[0]
    assert finding.evidence["reproduce"]["filter"] == {
        "agent.name": Entity("host", "ws-05.corp.example"),
        "data.win.system.channel": SYSMON,
    }
    assert result.statuses[("agent", ("ws-05.corp.example",))] in ("ok", "explained")
    assert result.statuses[("log_source", (SYSMON,))] == "ok"


def test_volume_drop_is_detected_and_attributed_to_the_channel() -> None:
    tenant = TenantConfig(name="acme")
    world = World(tenant, hours=21 * 24)
    for i in range(10):
        name = f"srv-{i:02d}.example"
        drop_from = world.hours - 30
        world.stream(
            name,
            "Security",
            40.0,
            pattern="sine",
            factor=(lambda h, cut=drop_from: 0.1 if h >= cut else 1.0) if i == 4 else None,
        )
    cube = world.build()
    result = run(world, cube, world.end)
    found = alarms(result)
    assert describe(found) == [("silence.drop", "agent:srv-04.example|ls:Security")]
    ev = found[0].evidence
    assert ev["ratio"] < 0.3 and ev["p"] < ev["alpha_eff"]
    assert result.statuses[("agent", ("srv-04.example",))] == "explained"


def test_slow_decay_is_reported_as_decay_not_drop() -> None:
    tenant = TenantConfig(name="acme")
    world = World(tenant, hours=28 * 24)
    cut = world.hours - 7 * 24
    for i in range(8):
        world.stream(
            f"srv-{i:02d}.example",
            "/var/log/auth.log",
            20.0,
            factor=(lambda h: 0.3 if h >= cut else 1.0) if i == 6 else None,
        )
    cube = world.build()
    result = run(world, cube, world.end)
    found = alarms(result)
    assert describe(found) == [("silence.decay", "agent:srv-06.example|ls:/var/log/auth.log")]
    assert found[0].evidence["decay"]["ratio"] < 0.5
    assert found[0].severity is Severity.LOW  # standard tier decay is hygiene, not an incident


def test_long_silence_keeps_a_frozen_baseline_instead_of_learning_the_outage() -> None:
    tenant = TenantConfig(name="acme")
    world = World(tenant, hours=28 * 24)
    servers(world, 6, stop={"srv-02.example": world.end - timedelta(days=6)})
    cube = world.build()
    result = run(world, cube, world.end)
    found = {f.subject: f for f in alarms(result)}
    assert set(found) == {"agent:srv-02.example"}
    assert found["agent:srv-02.example"].evidence["frozen_baseline"] is True
    assert found["agent:srv-02.example"].evidence["baseline_days"] >= 7


def test_future_timestamps_cannot_hide_a_silence() -> None:
    tenant = TenantConfig(name="acme")
    world = World(tenant, hours=21 * 24)
    servers(world, 6, stop={"srv-01.example": world.end - timedelta(hours=8)})
    cube = world.build()
    skewed = world.end + timedelta(days=2)
    cube.add(Event(ts=skewed, source="srv-01.example", log_source="Security"))
    result = run(world, cube, world.end)
    assert ("silence.silent", "agent:srv-01.example") in describe(alarms(result))


# ---- grouping, tampering, rules ---------------------------------------------------------------------------------


def test_global_outage_yields_exactly_one_pipeline_finding() -> None:
    tenant = TenantConfig(name="acme")
    world = World(tenant, hours=21 * 24)
    outage = world.end - timedelta(hours=3)
    rng = random.Random(9)
    stops = {f"srv-{i:02d}.example": outage + timedelta(minutes=rng.uniform(0, 20)) for i in range(0, 25, 5)}
    stops.update({f"srv-{i:02d}.example": outage + timedelta(minutes=rng.uniform(0, 20)) for i in range(1, 25, 5)})
    assert len(stops) == 10  # 40% of 25 agents
    names = servers(world, 25, stop=stops)
    cube = world.build()
    result = run(world, cube, world.end)
    found = alarms(result)
    assert describe(found) == [("pipeline.global_silence", "global_silence")]
    finding = found[0]
    assert finding.domain == "pipeline"
    assert finding.evidence["agents_silent"] == 10
    assert finding.evidence["agents_total"] == 25
    for name in names:
        expected = "explained" if name in stops else "ok"
        assert result.statuses[("agent", (name,))] == expected
        if name in stops:
            assert result.statuses[("agent_log_source", (name, "Security"))] == "explained"
            assert fingerprint("acme", "silence.silent", f"agent:{name}") in finding.related
    assert finding.evidence["explained_count"] >= 10


def test_whole_tenant_silence_is_one_pipeline_finding() -> None:
    tenant = TenantConfig(name="acme")
    world = World(tenant, hours=21 * 24)
    servers(world, 8)
    cube = world.build()
    result = run(world, cube, world.end + timedelta(hours=6), DataBasis(input_kind="archives", now_origin="flag"))
    found = alarms(result)
    assert describe(found) == [("pipeline.global_silence", "global_silence")]
    assert found[0].severity is Severity.CRITICAL
    assert any(isinstance(r, Message) and r.key == "silence.reason.stale_now" for r in found[0].reasons)
    assert all(v in ("explained", "silent") for v in result.statuses.values() if v not in ("ok", "not_evaluated"))


def test_tampering_precursor_before_a_dc_goes_silent_is_critical() -> None:
    tenant = TenantConfig(name="acme", criticality={"critical": ["dc*"]})
    world = World(tenant, hours=21 * 24)
    stop = world.end - timedelta(hours=4)
    servers(world, 8, stop={"srv-03.example": stop})
    world.stream("dc01.corp.example", "Security", 50.0, pattern="sine", stop=stop)
    world.stream("dc01.corp.example", "System", 5.0, stop=stop)
    world.stream("dc02.corp.example", "Security", 50.0, pattern="sine")
    cube = world.build()
    cube.add(
        Event(
            ts=stop - timedelta(minutes=5),
            source="dc01.corp.example",
            log_source="Security",
            rule_id="63103",
            event_code="1102",
        )
    )
    # a log clear on a host that keeps logging is not a silence finding
    cube.add(Event(ts=stop, source="dc02.corp.example", log_source="Security", rule_id="63103", event_code="1102"))
    result = run(world, cube, world.end)
    found = {f.subject: f for f in alarms(result)}
    assert set(found) == {"agent:dc01.corp.example", "agent:srv-03.example"}
    tamper = found["agent:dc01.corp.example"]
    assert tamper.kind == "silence.tampering"
    assert tamper.severity is Severity.CRITICAL
    assert tamper.evidence["precursors"][0]["code"] == "win_1102"
    assert {"T1070.001", "T1562.002", "T1562.001"} <= set(tamper.evidence["mitre"])
    assert found["agent:srv-03.example"].kind == "silence.silent"
    assert result.statuses[("agent", ("dc01.corp.example",))] == "tampering"


def test_heartbeat_rule_that_stops_while_its_source_is_alive_goes_dark() -> None:
    tenant = TenantConfig(name="acme")
    world = World(tenant, hours=21 * 24)
    rule_stop = world.end - timedelta(hours=10)
    for i in range(8):
        name = f"srv-{i:02d}.example"
        world.stream(name, "Security", 12.0, rule="60106", stop=rule_stop)
        world.stream(name, "Security", 8.0, rule="5710")
        world.stream(name, "Security", 10.0)
        world.stream(name, "System", 3.0)
    # heartbeat rules whose only source dies are explained by the source finding, never "dark"
    world.stream("srv-07.example", "Application", 6.0, rule="533", stop=world.end - timedelta(hours=10))
    world.stream("srv-99.example", "System", 6.0, rule="534", stop=world.end - timedelta(hours=10))
    # a rare rule (not a heartbeat) that has been quiet for days
    world.stream("srv-01.example", "Security", 0.012, rule="100200", stop=world.end - timedelta(days=6))
    cube = world.build()
    result = run(world, cube, world.end)
    subjects = describe(alarms(result))
    assert ("silence.rule_dark", "rule:60106") in subjects
    assert ("silence.silent", "agent:srv-99.example") in subjects
    assert ("silence.silent", "agent:srv-07.example|ls:Application") in subjects or (
        "silence.silent",
        "ls:Application",
    ) in subjects
    assert all(s[1] not in ("rule:533", "rule:534", "rule:100200") for s in subjects)
    assert len(subjects) == 3, subjects
    dark = next(f for f in alarms(result) if f.kind == "silence.rule_dark")
    assert dark.confidence is Confidence.HIGH
    assert dark.evidence["sources_alive"]
    assert result.statuses[("rule", ("534",))] == "explained"
    assert result.statuses[("rule", ("533",))] == "explained"
    assert result.statuses[("rule", ("100200",))] == "not_evaluated"
    assert result.statuses[("rule", ("5710",))] == "ok"


def test_sparse_critical_source_is_unmonitorable() -> None:
    tenant = TenantConfig(name="acme", criticality={"critical": ["dc*"]})
    world = World(tenant, hours=21 * 24)
    servers(world, 4)
    world.stream("dc03.corp.example", "Security", 0.3, k=2.0)
    world.stream("dc01.corp.example", "Security", 50.0, pattern="sine")
    cube = world.build()
    result = run(world, cube, world.end)
    assert alarms(result) == []
    unmon = [f for f in result.findings if f.kind == "silence.unmonitorable"]
    assert [f.subject for f in unmon] == ["agent:dc03.corp.example"]
    assert unmon[0].severity is Severity.MEDIUM
    assert unmon[0].evidence["keys"][0]["t_min_hours"] is None or unmon[0].evidence["keys"][0]["t_min_hours"] > 4
    mon = result.section["monitorability"]
    assert mon["critical_total"] == 4  # two critical agents, two critical channels
    assert mon["critical_monitorable"] == 2
    assert result.statuses[("agent", ("dc03.corp.example",))] == "unmonitorable"
    assert result.statuses[("agent", ("dc01.corp.example",))] == "ok"


# ---- traps that must NOT alarm ----------------------------------------------------------------------------------


def test_laptops_off_at_night_weekends_and_random_days_raise_nothing() -> None:
    tenant = TenantConfig(name="acme", timezone="Europe/Madrid")
    tenant.silence.alarm_budget = TRAP_BUDGET
    world = laptop_world(tenant)
    cube = world.build()
    local_monday = MONDAY - timedelta(hours=2) + timedelta(days=21)
    probes = [
        local_monday + timedelta(hours=7, minutes=30),
        local_monday + timedelta(hours=10),
        local_monday + timedelta(days=2, hours=13),
        local_monday + timedelta(days=1, hours=18, minutes=30),
        local_monday + timedelta(days=5, hours=12),
        local_monday + timedelta(days=6, hours=22),
        local_monday + timedelta(days=7, hours=9, minutes=15),
    ]
    for now in probes:
        result = run(world, cube, now)
        assert alarms(result) == [], (now, describe(alarms(result)))


def laptop_world(tenant: TenantConfig, seed: int = 1) -> World:
    """40 laptops: 08-18 local on weekdays only, and each weekday skipped with probability 0.1 (both channels)."""
    world = World(tenant, hours=28 * 24 + 10, start=MONDAY - timedelta(hours=2), seed=seed)  # local midnight (CEST)
    for i in range(40):
        name = f"lap-{i:02d}.example"
        dates = sorted({d for _, _, d in world.local})
        days_off = {d for d in dates if d.weekday() < 5 and world.rng.random() < 0.1}
        world.stream(name, "Security", 15.0, pattern="laptop", weekend=0.0, holidays=days_off)
        world.stream(name, "System", 2.0, pattern="laptop", weekend=0.0, holidays=days_off)
    return world


@pytest.mark.parametrize(
    "tz,start,transition",
    [
        ("Europe/Madrid", datetime(2026, 10, 5, tzinfo=UTC), datetime(2026, 10, 25, 1, tzinfo=UTC)),
        ("America/Santiago", datetime(2026, 8, 17, 4, tzinfo=UTC), datetime(2026, 9, 6, 4, tzinfo=UTC)),
        ("America/Santiago", datetime(2026, 3, 16, 3, tzinfo=UTC), datetime(2026, 4, 5, 3, tzinfo=UTC)),
    ],
)
def test_dst_transition_raises_nothing(tz: str, start: datetime, transition: datetime) -> None:
    tenant = TenantConfig(name="acme", timezone=tz)
    tenant.silence.alarm_budget = TRAP_BUDGET
    world = World(tenant, hours=27 * 24, start=start)
    for i in range(10):
        world.stream(f"srv-{i:02d}.example", "Security", 30.0, pattern="sine")
        world.stream(f"app-{i:02d}.example", "/var/log/app.log", 20.0, pattern="office", weekend=0.05)
    # a nightly job scheduled in UTC: it moves one local hour at the DST change
    world.stream("bkp-01.example", "/var/log/backup.log", 150.0, utc_hours={2: 1.0}, k=20.0)
    cube = world.build()
    for hours_after in (2, 3, 4, 5, 8, 26, 27, 28, 30, 33, 50, 52, 76):
        now = transition + timedelta(hours=hours_after)
        result = run(world, cube, now)
        assert alarms(result) == [], (now, describe(alarms(result)))


def test_holiday_in_calendar_raises_nothing() -> None:
    world_start = MONDAY
    holiday = (world_start + timedelta(days=23)).date()  # Wednesday of week 4
    past_holiday = (world_start + timedelta(days=9)).date()  # Wednesday of week 2 (baseline)
    tenant = TenantConfig(
        name="acme",
        calendar=[
            CalendarEntry(start=holiday, end=holiday, reason="national holiday"),
            CalendarEntry(start=past_holiday, end=past_holiday, reason="national holiday"),
        ],
    )
    tenant.silence.alarm_budget = TRAP_BUDGET
    world = World(tenant, hours=25 * 24, start=world_start)
    for i in range(12):
        world.stream(
            f"app-{i:02d}.example",
            "/var/log/app.log",
            25.0,
            pattern="office",
            weekend=0.02,
            holidays=[holiday, past_holiday],
        )
    cube = world.build()
    for now in (
        world_start + timedelta(days=23, hours=11),
        world_start + timedelta(days=23, hours=17),
        world_start + timedelta(days=24, hours=7),
    ):
        result = run(world, cube, now)
        assert alarms(result) == [], (now, describe(alarms(result)))
    # control: without the calendar entry the same holiday IS a silence (the past holiday stays in the calendar: an
    # unannounced whole-day gap in the history would rightly teach these sources that they sometimes skip a day)
    plain = TenantConfig(name="acme", calendar=[CalendarEntry(start=past_holiday, end=past_holiday)])
    plain.silence.alarm_budget = TRAP_BUDGET
    world.tenant = plain
    cube2 = world.build(CubeCollector(plain))
    result = analyze_silence(cube2, tenant=plain, now=world_start + timedelta(days=23, hours=15), basis=ARCHIVES)
    assert alarms(result)


def test_short_history_is_learning_and_never_green() -> None:
    tenant = TenantConfig(name="acme")
    world = World(tenant, hours=5 * 24)
    servers(world, 6, stop={"srv-01.example": world.end - timedelta(hours=12)})
    cube = world.build()
    result = run(world, cube, world.end)
    assert alarms(result) == []
    learning = [f for f in result.findings if f.kind == "assessment.learning"]
    assert len(learning) == 1 and learning[0].severity is Severity.MEDIUM
    assert learning[0].domain == "assessment"
    assert result.section["status"] == "not_assessed"
    assert result.section["keys_evaluated"] == 0
    assert set(result.statuses.values()) == {"learning"}


def test_a_new_agent_is_learning_while_the_others_are_evaluated() -> None:
    tenant = TenantConfig(name="acme")
    world = World(tenant, hours=21 * 24)
    servers(world, 6)
    world.stream(
        "new-01.example", "Security", 20.0, start=world.end - timedelta(days=3), stop=world.end - timedelta(hours=10)
    )
    cube = world.build()
    result = run(world, cube, world.end)
    assert alarms(result) == []
    assert result.statuses[("agent", ("new-01.example",))] == "learning"
    learning = [f for f in result.findings if f.kind == "assessment.learning"]
    assert len(learning) == 1 and learning[0].severity is Severity.LOW
    assert result.section["status"] == "ok"


# ---- confidence, inventory, robustness --------------------------------------------------------------------------


def _small_outage_world(seed: int = 3) -> tuple[World, CubeCollector]:
    tenant = TenantConfig(name="acme")
    world = World(tenant, hours=21 * 24, seed=seed)
    servers(world, 6, stop={"srv-02.example": world.end - timedelta(hours=8)})
    return world, world.build()


def test_alerts_only_input_lowers_confidence_and_says_so() -> None:
    world, cube = _small_outage_world()
    result = run(world, cube, world.end, DataBasis(input_kind="alerts", profile="wazuh4"))
    finding = alarms(result)[0]
    assert finding.confidence in (Confidence.LOW, Confidence.MEDIUM)
    assert any(isinstance(r, Message) and r.key == "silence.reason.alerts_only" for r in finding.reasons)
    assert result.section["alerts_only"] is True
    partial = run(world, cube, world.end, DataBasis(input_kind="archives", partial_failures=["shard 3 failed"]))
    assert alarms(partial)[0].confidence is Confidence.LOW


def test_agent_inventory_enriches_findings_and_never_downgrades() -> None:
    world, cube = _small_outage_world()
    now = world.end
    fresh = AgentInfo(id="003", name="srv-02.example", status="active", last_keepalive=now - timedelta(minutes=2))
    result = run(world, cube, now, agents=[fresh])
    finding = alarms(result)[0]
    assert finding.confidence is Confidence.HIGH
    assert any(isinstance(r, Message) and r.key == "silence.reason.agent_active" for r in finding.reasons)
    assert finding.evidence["agent_status"] == "active"
    other = AgentInfo(id="004", name="srv-03.example", status="active", last_keepalive=now)
    unlisted = alarms(run(world, cube, now, agents=[other]))[0]
    # a syslog device is never a Wazuh agent: absence from the inventory adds context, never lowers severity
    assert unlisted.severity is Severity.HIGH
    assert any(isinstance(r, Message) and r.key == "silence.reason.agent_unregistered" for r in unlisted.reasons)
    assert unlisted.evidence["agent_status"] == "not_registered"
    gone = AgentInfo(id="003", name="SRV-02.EXAMPLE", status="disconnected", last_keepalive=now - timedelta(hours=9))
    disconnected = alarms(run(world, cube, now, agents=[gone]))[0]
    assert any(isinstance(r, Message) and r.key == "silence.reason.agent_disconnected" for r in disconnected.reasons)


def test_ecs_profile_reproduce_hint() -> None:
    world, cube = _small_outage_world()
    result = run(world, cube, world.end, DataBasis(input_kind="indexer-archives", profile="ecs"))
    assert alarms(result)[0].evidence["reproduce"]["filter"] == {"host.name": Entity("host", "srv-02.example")}


def test_truncated_cube_is_reported_as_incomplete() -> None:
    tenant = TenantConfig(name="acme")
    world = World(tenant, hours=21 * 24)
    servers(world, 6)
    cube = world.build(CubeCollector(tenant, max_keys=5))
    result = run(world, cube, world.end)
    incomplete = [f for f in result.findings if f.kind == "assessment.incomplete"]
    assert len(incomplete) == 1 and incomplete[0].severity.rank >= Severity.MEDIUM.rank
    assert result.section["cube_truncated"] is True


def test_empty_cube_and_odd_now_values() -> None:
    tenant = TenantConfig(name="acme")
    cube = CubeCollector(tenant)
    result = analyze_silence(cube, tenant=tenant, now=datetime(2026, 9, 1), basis=DataBasis())  # naive now
    assert alarms(result) == []
    assert result.section["status"] == "not_assessed"
    assert [f.kind for f in result.findings] == ["assessment.learning"]
    world, cube = _small_outage_world()
    before = run(world, cube, world.end - timedelta(days=30))  # "now" before the data
    assert alarms(before) == []
    assert set(before.statuses.values()) == {"learning"}


def test_hostile_names_are_wrapped_and_never_break_the_analysis() -> None:
    tenant = TenantConfig(name="acme")
    world = World(tenant, hours=21 * 24)
    hostile = "[bold]<script>alert(1)</script>\x1b[2J{agent}{0}%s" + "Z" * 5000
    servers(world, 5)
    world.stream(hostile, "../../{log_source}\x00", 30.0, stop=world.end - timedelta(hours=8))
    cube = world.build()
    result = run(world, cube, world.end)
    found = alarms(result)
    assert len(found) == 1
    for lang in ("en", "es"):
        text = render(found[0].title, lang)
        assert "{" not in text.replace("{agent}{0}", "").replace("{log_source}", "")
    entities = list(iter_entities(found[0].evidence)) + list(iter_entities(found[0].title))
    assert any(e.kind == "host" and e.value.startswith("[bold]") for e in entities)


def test_i18n_every_message_is_registered_rendered_and_entities_wrapped() -> None:
    tenant = TenantConfig(name="acme", criticality={"critical": ["dc*"]})
    world = World(tenant, hours=21 * 24)
    stop = world.end - timedelta(hours=6)
    servers(world, 6, stop={"srv-01.example": stop})
    world.stream("dc01.corp.example", "Security", 50.0, stop=stop)
    world.stream("dc05.corp.example", "Security", 0.2, k=2.0)
    world.stream("srv-04.example", "Security", 10.0, rule="60106", stop=world.end - timedelta(hours=10))
    world.stream("srv-04.example", "Security", 30.0)
    cube = world.build()
    cube.add(
        Event(ts=stop - timedelta(minutes=3), source="dc01.corp.example", log_source="Security", event_code="4719")
    )
    result = run(world, cube, world.end, DataBasis(input_kind="alerts", profile="wazuh4"))
    kinds = {f.kind for f in result.findings}
    assert {"silence.silent", "silence.tampering", "silence.rule_dark", "silence.unmonitorable"} <= kinds
    hosts = {"srv-01.example", "dc01.corp.example", "dc05.corp.example", "srv-04.example"}

    def messages(value: Any) -> Iterator[Message]:
        if isinstance(value, Message):
            yield value
            for v in value.params.values():
                yield from messages(v)
        elif isinstance(value, dict):
            for v in value.values():
                yield from messages(v)
        elif isinstance(value, (list, tuple)):
            for v in value:
                yield from messages(v)

    def raw_strings(value: Any) -> Iterator[str]:
        if isinstance(value, Entity):
            return
        if isinstance(value, str):
            yield value
        elif isinstance(value, Message):
            for v in value.params.values():
                yield from raw_strings(v)
        elif isinstance(value, dict):
            for v in value.values():
                yield from raw_strings(v)
        elif isinstance(value, (list, tuple)):
            for v in value:
                yield from raw_strings(v)

    for finding in result.findings:
        parts = [finding.title, finding.recommendation, *finding.reasons]
        for msg in messages(parts):
            assert has(msg.key), msg.key
        for part in parts:
            for lang in ("en", "es"):
                text = render(part, lang)
                assert text and "{" not in text, (lang, text)
        for text in raw_strings([finding.title, finding.recommendation, finding.reasons, finding.evidence]):
            assert not any(host in text for host in hosts), (finding.kind, text)
    for row in result.section["sources"]:
        for text in raw_strings(row):
            assert not any(host in text for host in hosts), text


def test_section_shape() -> None:
    world, cube = _small_outage_world()
    result = run(world, cube, world.end)
    section = result.section
    for key in ("status", "alpha_eff", "keys_evaluated", "status_counts", "sources", "monitorability"):
        assert key in section
    assert section["alpha_eff"] == pytest.approx(0.05 / section["keys_evaluated"])
    for status in ("ok", "silent", "drop", "learning", "unmonitorable", "explained"):
        assert status in section["status_counts"]
    assert set(section["status_counts"]) <= set(STATUSES)
    assert sum(section["status_counts"].values()) == len(result.statuses)
    row = section["sources"][0]
    assert row["status"] == "silent" and row["level"] == "agent"
    for key in ("level", "key", "status", "last_seen", "observed", "expected", "p", "tier", "duty", "daily"):
        assert key in row
    assert isinstance(row["daily"], list) and all(isinstance(v, int) for v in row["daily"])
    assert len(row["daily"]) >= 20
    assert row["key"] == {"agent": Entity("host", "srv-02.example")}


# ---- calibration benchmark --------------------------------------------------------------------------------------

CALIBRATION_SEEDS = (0, 1)
CALIBRATION_BACKS = (0, 7, 13, 22, 31)


def calibration_world(seed: int) -> tuple[World, CubeCollector]:
    """150 agents × 3 channels (604 keys) over 28 days: overdispersed NB, diurnal + weekly seasonality, no outage."""
    tenant = TenantConfig(name="acme", timezone="Europe/Madrid")
    world = World(tenant, hours=28 * 24, seed=seed)
    rng = random.Random(1000 + seed)
    for a in range(150):
        for ls in ("Security", "System", SYSMON):
            world.stream(
                f"srv-{a:03d}.example",
                ls,
                math.exp(rng.uniform(math.log(0.05), math.log(200.0))),
                k=rng.uniform(0.8, 20.0),
                pattern=rng.choice(["flat", "sine", "sine", "office"]),
                weekend=rng.uniform(0.2, 1.0),
            )
    return world, world.build()


@pytest.fixture(scope="module")
def calibration_worlds() -> list[tuple[World, CubeCollector]]:
    return [calibration_world(seed) for seed in CALIBRATION_SEEDS]


@pytest.mark.parametrize("budget", [1.0, 0.05])
def test_calibration_false_alarm_rate_within_budget(
    calibration_worlds: list[tuple[World, CubeCollector]], budget: float
) -> None:
    false_alarms = 0
    runs = 0
    for world, cube in calibration_worlds:
        world.tenant.silence.alarm_budget = budget
        for back in CALIBRATION_BACKS:
            result = run(world, cube, world.end - timedelta(hours=back))
            assert result.section["keys_evaluated"] >= 500
            false_alarms += len(alarms(result))
            runs += 1
    rate = false_alarms / runs
    # expected false alarms per run is the budget; allow 2x plus small-sample slack (measured ~0.1-0.3x)
    assert rate <= 2 * budget + 2.0 / runs, (false_alarms, runs)


def test_calibration_planted_outages_are_found_among_hundreds_of_keys(
    calibration_worlds: list[tuple[World, CubeCollector]],
) -> None:
    world, _ = calibration_worlds[0]
    world.tenant.silence.alarm_budget = 0.05
    extra = World(world.tenant, hours=world.hours, seed=77)
    extra._agg = {k: [list(v[0]), v[1], v[2]] for k, v in world._agg.items()}
    stop = world.end - timedelta(hours=6)
    extra.stream("dc-new.example", "Security", 40.0, pattern="sine", stop=stop)
    extra.stream("dc-new.example", "System", 3.0, stop=stop)
    cube = extra.build()
    result = analyze_silence(cube, tenant=world.tenant, now=world.end, basis=ARCHIVES)
    assert ("silence.silent", "agent:dc-new.example") in describe(alarms(result))
    assert len(alarms(result)) <= 2


def test_calibration_laptop_fleet_with_random_days_off() -> None:
    """Laptops skip random weekdays: at the default budget the false-alarm rate stays within ~2x budget."""
    false_alarms = runs = 0
    for seed in (1, 2):
        tenant = TenantConfig(name="acme", timezone="Europe/Madrid")
        world = laptop_world(tenant, seed=seed)
        cube = world.build()
        base = MONDAY - timedelta(hours=2) + timedelta(days=21)
        for hours in range(7, 7 * 24, 13):
            false_alarms += len(alarms(run(world, cube, base + timedelta(hours=hours))))
            runs += 1
    assert false_alarms / runs <= 2 * 0.05 + 2.0 / runs, (false_alarms, runs)


# ---- performance ----------------------------------------------------------------------------------------------


def test_performance_2000_keys_30_days() -> None:
    tenant = TenantConfig(name="acme", timezone="Europe/Madrid")
    cube = CubeCollector(tenant)
    rng = random.Random(4)
    start_h = int(MONDAY.timestamp() // 3600)
    hours = 30 * 24
    diurnal = [1.0 + 0.5 * math.sin(h / 24 * 2 * math.pi) for h in range(24)]
    tenant_counts = [0] * hours
    for a in range(500):
        agent_counts = [0] * hours
        for ls in ("Security", "System", SYSMON, "Application"):
            base = rng.uniform(0.5, 50.0)
            counts = [max(0, int(base * diurnal[h % 24] + rng.gauss(0, math.sqrt(base)))) for h in range(hours)]
            cube.add_series("agent_log_source", (f"host-{a:03d}.example", ls), start_h, counts)
            agent_counts = [x + y for x, y in zip(agent_counts, counts, strict=True)]
        cube.add_series("agent", (f"host-{a:03d}.example",), start_h, agent_counts)
        tenant_counts = [x + y for x, y in zip(tenant_counts, agent_counts, strict=True)]
    for r in range(60):
        cube.add_series("rule", (str(60000 + r),), start_h, [rng.randint(0, 20) for _ in range(hours)])
    cube.add_series("tenant", ("acme",), start_h, tenant_counts)
    assert cube.n_keys() >= 2500
    t0 = time.perf_counter()
    result = analyze_silence(
        cube, tenant=tenant, now=datetime.fromtimestamp((start_h + hours) * 3600, UTC), basis=ARCHIVES
    )
    elapsed = time.perf_counter() - t0
    assert result.section["keys_evaluated"] >= 2500
    assert elapsed < 12.0, elapsed  # typically 2-4 s on a laptop core


# ---- configuration variants and integration paths -------------------------------------------------------------


def test_hour_of_week_regime_with_a_long_baseline() -> None:
    tenant = TenantConfig(name="acme", timezone="Europe/Madrid")
    tenant.silence.baseline = timedelta(days=35)
    world = World(tenant, hours=35 * 24 + 11, start=MONDAY - timedelta(hours=2))
    stop = world.end - timedelta(hours=5)
    servers(world, 8, stop={"srv-05.example": stop})
    for i in range(8):
        world.stream(f"app-{i:02d}.example", "/var/log/app.log", 20.0, pattern="office", weekend=0.02)
    cube = world.build()
    result = run(world, cube, world.end)
    found = alarms(result)
    assert describe(found) == [("silence.silent", "agent:srv-05.example")]
    assert found[0].evidence["model"] == "hour_of_week"
    assert found[0].evidence["baseline_days"] >= 21


def test_short_window_and_custom_ingest_lag() -> None:
    tenant = TenantConfig(name="acme")
    tenant.silence.window = timedelta(hours=6)
    tenant.silence.ingest_lag = timedelta(hours=1)
    world = World(tenant, hours=21 * 24)
    servers(world, 6, stop={"srv-04.example": world.end - timedelta(hours=4)})
    cube = world.build()
    result = run(world, cube, world.end)
    assert describe(alarms(result)) == [("silence.silent", "agent:srv-04.example")]
    # an outage shorter than the ingest lag is not evaluated yet (late data is excluded)
    world2 = World(tenant, hours=21 * 24, seed=5)
    servers(world2, 6, stop={"srv-04.example": world2.end - timedelta(minutes=40)})
    assert alarms(run(world2, world2.build(), world2.end)) == []


def test_indexer_path_without_rule_sources_still_detects_dark_rules() -> None:
    tenant = TenantConfig(name="acme")
    world = World(tenant, hours=21 * 24)
    for i in range(6):
        world.stream(f"srv-{i:02d}.example", "Security", 15.0, rule="60106", stop=world.end - timedelta(hours=12))
        world.stream(f"srv-{i:02d}.example", "Security", 30.0)
    world.rule_pairs = []  # composite aggregations by rule only: no (agent, log source) pairs recorded
    cube = world.build()
    result = run(world, cube, world.end)
    assert describe(alarms(result)) == [("silence.rule_dark", "rule:60106")]
    assert alarms(result)[0].evidence["sources_alive"] == [{"tenant": "acme"}]


def test_merged_cubes_analyze_like_one() -> None:
    tenant = TenantConfig(name="acme")
    world = World(tenant, hours=21 * 24)
    servers(world, 6, stop={"srv-02.example": world.end - timedelta(hours=8)})
    whole = world.build()
    left, right = CubeCollector(tenant), CubeCollector(tenant)
    for (level, key), (counts, first, last) in sorted(world._agg.items()):
        half = len(counts) // 2
        if any(counts[:half]):
            left.add_series(level, key, world.start_h, counts[:half])
        if any(counts[half:]):
            right.add_series(level, key, world.start_h + half, counts[half:], last_seen=last)
    left.merge(right)
    a = run(world, whole, world.end)
    b = run(world, left, world.end)
    assert describe(alarms(a)) == describe(alarms(b)) == [("silence.silent", "agent:srv-02.example")]


def test_odd_configuration_values_do_not_crash() -> None:
    tenant = TenantConfig(name="acme", sla={"critical": timedelta(hours=1)}, criticality={"critical": ["*"]})
    tenant.silence.alarm_budget = 0.0
    tenant.silence.baseline = timedelta(hours=12)
    tenant.silence.window = timedelta(0)
    tenant.silence.min_history_days = 0
    tenant.silence.global_fraction = 0.0
    world = World(tenant, hours=10 * 24)
    servers(world, 4, stop={"srv-01.example": world.end - timedelta(hours=30)})
    cube = world.build()
    result = run(world, cube, world.end)
    # a 12 h baseline can never hold two full days: nothing is evaluable, and that is said (never green)
    assert result.section["keys_evaluated"] == 0 and result.section["status"] == "not_assessed"
    assert [f.kind for f in result.findings] == ["assessment.learning"]
    tenant.silence.baseline = timedelta(days=7)
    result = run(world, cube, world.end)
    assert result.section["keys_evaluated"] > 0
    assert ("silence.silent", "agent:srv-01.example") in describe(alarms(result))


def test_every_cube_key_gets_a_status() -> None:
    world, cube = _small_outage_world()
    cube.add_series("rule", ("100001",), world.start_h, [0] * 100 + [1])
    result = run(world, cube, world.end)
    expected: set[tuple[str, tuple[str, ...]]] = set()
    for level in ("tenant", "log_source", "agent", "agent_log_source", "rule"):
        expected.update((level, key) for key in cube.keys(level))
    assert set(result.statuses) == expected
    assert set(result.statuses.values()) <= set(STATUSES)


def test_all_silence_messages_have_spanish() -> None:
    from hushwatch import i18n

    registered = i18n.keys()
    silence_keys = [name for name in registered if name.startswith("silence.")]
    assert len(silence_keys) > 60
    for key in silence_keys:
        entry = i18n._CATALOG[key]
        assert entry.get("es"), key
        assert entry["es"] != entry["en"] or key.startswith("silence.filter."), key


def test_audit_policy_change_followed_by_a_drop_is_tampering() -> None:
    tenant = TenantConfig(name="acme", criticality={"critical": ["dc*"]})
    world = World(tenant, hours=21 * 24)
    cut = world.hours - 20
    servers(world, 6)
    world.stream("dc01.corp.example", "Security", 80.0, pattern="sine", factor=lambda h: 0.04 if h >= cut else 1.0)
    world.stream("dc01.corp.example", "System", 5.0)
    cube = world.build()
    change = datetime.fromtimestamp((world.start_h + cut) * 3600 - 300, UTC)
    cube.add(Event(ts=change, source="dc01.corp.example", log_source="Security", rule_id="60112", event_code="4719"))
    result = run(world, cube, world.end)
    found = alarms(result)
    assert describe(found) == [("silence.tampering", "agent:dc01.corp.example|ls:Security")]
    assert found[0].severity is Severity.CRITICAL
    assert found[0].evidence["status"] == "drop"
    assert found[0].evidence["precursors"][0]["code"] == "win_4719"
    assert "T1562.002" in found[0].evidence["mitre"]


def test_findings_and_section_are_strict_json() -> None:
    import json

    tenant = TenantConfig(name="acme", criticality={"critical": ["dc*"]})
    world = World(tenant, hours=21 * 24)
    stop = world.end - timedelta(hours=6)
    servers(world, 6, stop={"srv-01.example": stop})
    world.stream("dc01.corp.example", "Security", 50.0, stop=stop)
    world.stream("dc05.corp.example", "Security", 0.2, k=2.0)
    world.stream("srv-04.example", "Security", 10.0, rule="60106", stop=world.end - timedelta(hours=10))
    world.stream("srv-04.example", "Security", 30.0)
    cube = world.build()
    cube.add(
        Event(ts=stop - timedelta(minutes=3), source="dc01.corp.example", log_source="Security", event_code="1102")
    )
    result = run(world, cube, world.end, agents=[AgentInfo(id="001", name="srv-01.example", status="active")])

    def default(obj: object) -> object:
        if isinstance(obj, Entity):
            return {"kind": obj.kind, "value": obj.value}
        raise TypeError(type(obj))

    for finding in result.findings:
        text = json.dumps(finding.evidence, default=default, allow_nan=False)
        assert "1970-01-01" not in text
    json.dumps(result.section, default=default, allow_nan=False)
    json.dumps({f"{level}|{'|'.join(key)}": v for (level, key), v in result.statuses.items()}, allow_nan=False)
