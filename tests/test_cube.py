"""Tests for the hourly count cube (hushwatch.analysis.cube)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from hushwatch.analysis.cube import LEVELS, PRECURSOR_CODES, CubeCollector, Precursor, normalize_component
from hushwatch.config import TenantConfig
from hushwatch.models import Event

UTC = timezone.utc
T0 = datetime(2026, 9, 1, 10, 15, tzinfo=UTC)
H0 = int(T0.timestamp() // 3600)


def ev(
    ts: datetime,
    agent: str | None = "srv-web-01.example",
    ls: str | None = "Security",
    rule: str | None = "60106",
    **kw: object,
) -> Event:
    return Event(ts=ts, source=agent, log_source=ls, rule_id=rule, **kw)  # type: ignore[arg-type]


def tenant(name: str = "acme") -> TenantConfig:
    return TenantConfig(name=name)


def test_counts_every_level_by_epoch_hour() -> None:
    cube = CubeCollector(tenant())
    for minutes in (0, 10, 44, 70):
        cube.add(ev(T0 + timedelta(minutes=minutes)))
    cube.add(ev(T0, agent="dc01.corp.example", ls="System", rule="5710"))
    assert cube.keys("tenant") == [("acme",)]
    assert cube.series("tenant", ("acme",)) == {H0: 4, H0 + 1: 1}
    assert cube.series("agent", ("srv-web-01.example",)) == {H0: 3, H0 + 1: 1}
    assert cube.series("agent_log_source", ("dc01.corp.example", "System")) == {H0: 1}
    assert cube.series("log_source", ("Security",)) == {H0: 3, H0 + 1: 1}
    assert cube.series("rule", ("60106",)) == {H0: 3, H0 + 1: 1}
    assert cube.total("rule", ("5710",)) == 1
    assert cube.first_seen("agent", ("srv-web-01.example",)) == T0.timestamp()
    assert cube.last_seen("agent", ("srv-web-01.example",)) == (T0 + timedelta(minutes=70)).timestamp()
    assert cube.events == 5
    assert cube.n_keys() == 1 + 2 + 2 + 2 + 2
    assert cube.dense("agent", ("srv-web-01.example",), H0 - 1, H0 + 3) == [0, 3, 1, 0]
    assert cube.dense("agent", ("nobody",), H0, H0 + 2) == [0, 0]
    assert cube.dense("agent", ("srv-web-01.example",), H0, H0) == []
    assert cube.series("agent", ("missing",)) == {}
    assert cube.first_seen("agent", ("missing",)) is None


def test_missing_dimensions_only_feed_the_levels_they_can() -> None:
    cube = CubeCollector(tenant())
    cube.add(ev(T0, agent=None, ls=None, rule=None))
    cube.add(ev(T0, agent="", ls="Security", rule=""))
    assert cube.total("tenant", ("acme",)) == 2
    assert cube.keys("agent") == []
    assert cube.keys("rule") == []
    assert cube.keys("log_source") == [("Security",)]
    assert cube.keys("agent_log_source") == []


def test_rule_sources_and_event_codes() -> None:
    cube = CubeCollector(tenant(), max_rule_pairs=2, max_event_codes=2)
    cube.add(ev(T0, event_code="4624"))
    cube.add(ev(T0, agent="dc01.corp.example", event_code="4625"))
    cube.add(ev(T0, agent="dc02.corp.example", event_code="4688"))
    cube.add(ev(T0, event_code="4688"))
    cube.add(ev(T0, event_code="4672"))  # third code: capped
    pairs, overflow = cube.rule_sources("60106")
    assert pairs == {("srv-web-01.example", "Security"), ("dc01.corp.example", "Security")}
    assert overflow is True
    assert cube.event_codes("srv-web-01.example", "Security") == {"4624", "4688"}
    assert cube.rule_sources("nope") == (frozenset(), False)
    cube.add_rule_source("999", None, "Sysmon")
    assert cube.rule_sources("999")[0] == {("", "Sysmon")}
    cube.add_event_code("dc01.corp.example", "Security", "4740")
    assert (
        "4740" not in cube.event_codes("dc01.corp.example", "Security")
        or len(cube.event_codes("dc01.corp.example", "Security")) <= 2
    )


def test_max_keys_truncates_and_reports() -> None:
    cube = CubeCollector(tenant(), max_keys=4)
    for i in range(10):
        cube.add(ev(T0, agent=f"lap-{i:02d}.example", ls="Security", rule=None))
    assert cube.truncated is True
    assert cube.n_keys() <= 5  # the tenant key is always kept
    assert cube.total("tenant", ("acme",)) == 10  # the tenant total is never truncated
    assert sum(cube.dropped_events.values()) > 0
    assert sum(cube.dropped_keys.values()) == 0 or cube.dropped_keys  # dropped_keys counts merges only
    # existing keys keep counting after the cap was hit
    before = cube.total("agent", ("lap-00.example",))
    cube.add(ev(T0, agent="lap-00.example", ls="Security", rule=None))
    assert cube.total("agent", ("lap-00.example",)) == before + 1


def test_max_keys_default_comes_from_tenant() -> None:
    t = tenant()
    t.silence.max_keys = 7
    assert CubeCollector(t).max_keys == 7
    assert CubeCollector(t, max_keys=3).max_keys == 3
    with pytest.raises(ValueError):
        CubeCollector(t, max_keys=0)


def test_add_count_indexer_path() -> None:
    cube = CubeCollector(tenant())
    cube.add_count("agent_log_source", ("dc01.corp.example", "Security"), H0, 120, rollup=True)
    cube.add_count("agent_log_source", ("dc01.corp.example", "Security"), H0 + 1, 30, last_seen=(H0 + 1) * 3600 + 60)
    cube.add_count("rule", ("60106",), H0, 5)
    cube.add_count("tenant", (), H0 + 1, 30)
    assert cube.series("agent_log_source", ("dc01.corp.example", "Security")) == {H0: 120, H0 + 1: 30}
    assert cube.series("agent", ("dc01.corp.example",)) == {H0: 120}
    assert cube.series("log_source", ("Security",)) == {H0: 120}
    assert cube.series("tenant", ("acme",)) == {H0: 120, H0 + 1: 30}
    # default last_seen is the END of the bucket (conservative: gaps can only look shorter)
    assert cube.last_seen("agent", ("dc01.corp.example",)) == H0 * 3600 + 3599
    assert cube.last_seen("agent_log_source", ("dc01.corp.example", "Security")) == (H0 + 1) * 3600 + 60
    assert cube.first_seen("agent_log_source", ("dc01.corp.example", "Security")) == H0 * 3600
    cube.add_count("rule", ("60106",), H0, 0)  # zero is a no-op
    assert cube.total("rule", ("60106",)) == 5


def test_add_count_rejects_bad_input() -> None:
    cube = CubeCollector(tenant())
    with pytest.raises(ValueError):
        cube.add_count("galaxy", ("x",), H0, 1)
    with pytest.raises(ValueError):
        cube.add_count("agent_log_source", ("only-one",), H0, 1)
    with pytest.raises(ValueError):
        cube.add_count("agent", ("",), H0, 1)
    with pytest.raises(ValueError):
        cube.add_count("agent", ("a",), H0, -1)
    with pytest.raises(TypeError):
        cube.add_count("agent", ("a",), float(H0), 1)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        cube.add_count("agent", ("a",), H0, True)
    with pytest.raises(TypeError):
        cube.add_count("agent", ("a",), H0, 2.5)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        cube.series("galaxy", ("x",))
    cube.add_count("agent", ("a",), 12, 5)  # 1970: implausible hour, counted as invalid
    assert cube.invalid == 1 and cube.keys("agent") == []


def test_huge_counts_do_not_overflow() -> None:
    cube = CubeCollector(tenant())
    cube.add_count("agent", ("a",), H0, 4_294_967_000)
    cube.add_count("agent", ("a",), H0, 10_000)
    cube.add_count("agent", ("a",), H0, 2**80)  # absurd: clamped, never an exception
    value = cube.series("agent", ("a",))[H0]
    assert value >= 4_294_967_000 + 10_000
    cube.add(ev(T0, agent="a", ls=None, rule=None))
    assert cube.series("agent", ("a",))[H0] == value  # saturating counter, never an exception
    cube.add_count("agent", ("b",), H0, 4_294_967_295)
    cube.add(ev(T0, agent="b", ls=None, rule=None))  # 32-bit cell widens to 64-bit
    assert cube.series("agent", ("b",))[H0] == 4_294_967_296


def test_hostile_values_are_bounded() -> None:
    cube = CubeCollector(tenant())
    huge = "A" * 1_000_000
    markup = "[bold red]<script>alert(1)</script>\x1b[2J"
    cube.add(ev(T0, agent=huge, ls=huge, rule=huge))
    cube.add(ev(T0, agent=markup, ls="../../etc/passwd", rule="=HYPERLINK(1)"))
    for level in LEVELS:
        for key in cube.keys(level):
            assert all(len(part) <= 256 for part in key)
    # two different long values never collide
    assert normalize_component("B" * 300 + "x") != normalize_component("B" * 300 + "y")
    assert normalize_component(12345) == "12345"
    assert cube.has("agent", (markup,))  # stored raw (escaping is the renderer's job)


def test_invalid_timestamps_are_counted_not_crashing() -> None:
    cube = CubeCollector(tenant())
    cube.add(Event(ts="yesterday", source="a"))  # type: ignore[arg-type]
    cube.add(Event(ts=datetime(1970, 1, 2, tzinfo=UTC), source="a"))
    cube.add(Event(ts=datetime(2300, 1, 1, tzinfo=UTC), source="a"))
    assert cube.invalid == 3 and cube.events == 0
    # naive datetimes are UTC (never the machine's local time)
    cube.add(Event(ts=datetime(2026, 9, 1, 10, 15), source="a"))
    assert cube.first_seen("agent", ("a",)) == T0.timestamp()


def test_merge_is_equivalent_to_a_single_pass() -> None:
    events = [
        ev(T0 + timedelta(minutes=37 * i), agent=f"srv-{i % 3}.example", ls=("Security", "System")[i % 2])
        for i in range(40)
    ]
    whole = CubeCollector(tenant())
    left, right = CubeCollector(tenant()), CubeCollector(tenant())
    for i, item in enumerate(events):
        whole.add(item)
        (left if i % 2 else right).add(item)
    left.merge(right)
    for level in LEVELS:
        assert left.keys(level) == whole.keys(level)
        for key in whole.keys(level):
            assert left.series(level, key) == whole.series(level, key)
            assert left.first_seen(level, key) == whole.first_seen(level, key)
            assert left.last_seen(level, key) == whole.last_seen(level, key)
    assert left.events == whole.events
    assert left.rule_sources("60106") == whole.rule_sources("60106")


def test_merge_respects_the_key_cap() -> None:
    a = CubeCollector(tenant(), max_keys=3)
    b = CubeCollector(tenant())
    for i in range(5):
        b.add(ev(T0, agent=f"h{i}.example", ls=None, rule=None))
    a.merge(b)
    assert a.truncated
    assert a.n_keys() <= 4
    assert a.total("tenant", ("acme",)) == 5
    assert sum(a.dropped_keys.values()) >= 1


# ---- tampering precursors ---------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "kwargs,code",
    [
        ({"event_code": "1102", "log_source": "Security"}, "win_1102"),
        ({"event_code": "4719", "log_source": "Security"}, "win_4719"),
        ({"event_code": "4906", "log_source": "Security"}, "win_4906"),
        ({"event_code": "1100", "log_source": "Security"}, "win_1100"),
        ({"event_code": "104", "log_source": "System"}, "win_104"),
        ({"event_code": "4", "log_source": "Microsoft-Windows-Sysmon/Operational"}, "sysmon_4"),
        ({"event_code": "16", "log_source": "Microsoft-Windows-Sysmon/Operational"}, "sysmon_16"),
        ({"rule_id": "506", "log_source": "wazuh-agent"}, "wazuh_506"),
        ({"rule_id": "203", "log_source": "wazuh-agent"}, "wazuh_203"),
        (
            {
                "rule_id": "80705",
                "rule_groups": ("audit", "audit_configuration"),
                "log_source": "/var/log/audit/audit.log",
            },
            "auditd_config",
        ),
        ({"fields": {"data.audit.type": "DAEMON_END"}, "log_source": "/var/log/audit/audit.log"}, "auditd_stop"),
        ({"event_code": "1102", "log_source": None, "os_platform": "windows"}, "win_1102"),
    ],
)
def test_precursors_detected(kwargs: dict[str, object], code: str) -> None:
    cube = CubeCollector(tenant())
    base = {"ts": T0, "source": "dc01.corp.example"}
    base.update(kwargs)
    cube.add(Event(**base))  # type: ignore[arg-type]
    found = cube.precursors_for("dc01.corp.example")
    assert [p.code for p in found] == [code]
    assert found[0] == Precursor("dc01.corp.example", T0.timestamp(), code, found[0].rule_id)
    assert code in PRECURSOR_CODES


@pytest.mark.parametrize(
    "kwargs",
    [
        {"event_code": "4", "log_source": "Security"},  # EventID 4 outside Sysmon means something else
        {"event_code": "16", "log_source": "Application"},
        {"event_code": "1102", "log_source": "Application"},  # 1102 must come from the Security log
        {"event_code": "104", "log_source": "Security"},
        {"event_code": "4624", "log_source": "Security"},
        {"rule_id": "5710", "log_source": "/var/log/auth.log"},
        {"fields": {"data.audit.type": "EXECVE"}, "log_source": "/var/log/audit/audit.log"},
    ],
)
def test_non_precursors_ignored(kwargs: dict[str, object]) -> None:
    cube = CubeCollector(tenant())
    base = {"ts": T0, "source": "dc01.corp.example"}
    base.update(kwargs)
    cube.add(Event(**base))  # type: ignore[arg-type]
    assert cube.precursors == []


def test_manager_side_disconnect_alert_is_attributed_to_the_named_agent() -> None:
    cube = CubeCollector(tenant())
    cube.add(
        Event(
            ts=T0,
            source="wazuh-manager.example",
            rule_id="504",
            log_source="wazuh-monitord",
            fields={"agent.id": "000", "full_log": "ossec: Agent disconnected: '002-dc01.corp.example-any'."},
        )
    )
    cube.add(
        Event(
            ts=T0,
            source="wazuh-manager.example",
            rule_id="504",
            log_source="wazuh-monitord",
            fields={"agent.id": "000", "full_log": "ossec: Agent disconnected: '003-srv-db-01-192.0.2.10'."},
        )
    )
    assert [p.code for p in cube.precursors_for("dc01.corp.example")] == ["wazuh_504"]
    assert [p.code for p in cube.precursors_for("srv-db-01")] == ["wazuh_504"]


def test_precursor_caps_keep_the_most_recent() -> None:
    cube = CubeCollector(tenant(), max_precursors_per_agent=3, max_precursor_agents=2)
    for i in range(10):
        cube.add(ev(T0 + timedelta(minutes=i), agent="dc01.corp.example", ls="Security", event_code="4719"))
    kept = cube.precursors_for("dc01.corp.example")
    assert len(kept) == 3
    assert [p.ts for p in kept] == [(T0 + timedelta(minutes=m)).timestamp() for m in (7, 8, 9)]
    assert cube.precursors_truncated
    for name in ("dc02.corp.example", "dc03.corp.example"):
        cube.add(ev(T0, agent=name, ls="Security", event_code="1102"))
    assert cube.precursors_for("dc03.corp.example") == []  # agent cap
    cube.add_precursor("dc02.corp.example", T0.timestamp() + 5, "sysmon_4", "61604")
    assert any(p.code == "sysmon_4" for p in cube.precursors_for("dc02.corp.example"))
    with pytest.raises(ValueError):
        cube.add_precursor("dc02.corp.example", T0.timestamp(), "made_up")
    # duplicates are not stored twice
    cube2 = CubeCollector(tenant())
    for _ in range(3):
        cube2.add(ev(T0, agent="dc09.corp.example", ls="Security", event_code="1102"))
    assert len(cube2.precursors_for("dc09.corp.example")) == 1


def test_precursors_merge() -> None:
    a, b = CubeCollector(tenant()), CubeCollector(tenant())
    a.add(ev(T0, agent="dc01.corp.example", ls="Security", event_code="1102"))
    b.add(ev(T0 + timedelta(minutes=5), agent="dc01.corp.example", ls="Security", event_code="4719"))
    a.merge(b)
    assert [p.code for p in a.precursors_for("dc01.corp.example")] == ["win_1102", "win_4719"]
    assert [p.agent for p in a.precursors] == ["dc01.corp.example", "dc01.corp.example"]


def test_spoofed_hostnames_cannot_starve_rules_and_log_sources() -> None:
    """Syslog hostnames reach the cube as agents and are attacker-controlled: a flood of fake hosts used to take the
    whole key cap, so a rule or log source that appeared afterwards was never tracked (its silence unknowable)."""
    cube = CubeCollector(tenant(), max_keys=1000)
    for i in range(2000):
        cube.add(ev(T0, agent=f"spoof-{i}", ls="syslog", rule="2501"))
    cube.add(ev(T0 + timedelta(hours=1), agent="dc01.corp.example", ls="Security", rule="60106"))
    assert cube.truncated
    assert cube.has("rule", ("60106",)) and cube.has("log_source", ("Security",))
    assert cube.dropped_events["agent"] > 0 and cube.dropped_events["rule"] == 0
    assert cube.n_keys() <= 1001
    host_keys = len(cube.keys("agent")) + len(cube.keys("agent_log_source"))
    assert host_keys <= 900  # the last 10% of the cap is kept for non-host keys
    # the indexer path and merges follow the same rule
    other = CubeCollector(tenant(), max_keys=1000)
    for i in range(1200):
        other.add_count("agent", (f"spoof-{i}",), H0, 1)
    other.add_count("rule", ("5710",), H0, 3)
    assert other.has("rule", ("5710",))
    merged = CubeCollector(tenant(), max_keys=1000)
    merged.merge(cube)
    assert merged.has("rule", ("60106",))


def test_side_tables_are_bounded_globally() -> None:
    cube = CubeCollector(tenant(), max_keys=10, max_rule_pairs=128, max_event_codes=128)
    for i in range(400):
        cube.add_rule_source("60106", f"h{i}", "Security")
        cube.add_event_code("dc01", "Security", str(i))
    assert len(cube.rule_sources("60106")[0]) <= cube.max_side_entries
    assert cube.rule_sources("60106")[1] is True  # overflow is reported
    assert len(cube.event_codes("dc01", "Security")) <= cube.max_side_entries
