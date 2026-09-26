"""Backtest: exact replay of suggestions (Suggestion.matches) and the safety re-checks on hidden events."""

from __future__ import annotations

from collections.abc import Iterable
from datetime import date, datetime, timedelta, timezone
from typing import Any

from hushwatch import i18n
from hushwatch.analysis import gates as g
from hushwatch.analysis.backtest import (
    EXAMPLE_MAX_CHARS,
    BacktestWatch,
    clip_document,
    downgrade_reasons,
    run_backtest,
    summary_message,
)
from hushwatch.analysis.dispositions import Dispositions
from hushwatch.config import TenantConfig
from hushwatch.models import Event
from hushwatch.tuning import Condition, Suggestion

UTC = timezone.utc
T0 = datetime(2026, 9, 1, tzinfo=UTC)


def _event(
    minutes: float,
    *,
    rule: str = "5710",
    level: int = 5,
    agent: str = "srv-app-01.corp.example",
    srcip: str | None = "10.20.0.15",
    user: str | None = None,
    event_id: str | None = None,
    groups: tuple[str, ...] = ("syslog", "sshd"),
    extra: dict[str, Any] | None = None,
) -> Event:
    fields: dict[str, Any] = {"rule.id": rule, "rule.level": level, "agent.id": "001", "agent.name": agent}
    if srcip is not None:
        fields["data.srcip"] = srcip
    if user is not None:
        fields["data.dstuser"] = user
    if event_id is not None:
        fields["id"] = event_id
    fields.update(extra or {})
    return Event(
        ts=T0 + timedelta(minutes=minutes),
        rule_id=rule,
        severity=level,
        source=agent,
        fields=fields,
        event_id=event_id,
        rule_groups=groups,
    )


def _suggestion(rule: str, *conds: tuple[str, str], fp: str = "s1") -> Suggestion:
    return Suggestion(
        rule_id=rule,
        conditions=tuple(Condition(f, v) for f, v in conds),
        verdict="watch",
        fingerprint=fp,
        expires=date(2026, 12, 1),
    )


def _window(days: int = 10) -> g.Window:
    first = T0.date().toordinal()
    return g.Window(T0.timestamp(), T0.timestamp() + days * 86400 - 1, first, first + days - 1)


def test_counts_what_matches_exactly() -> None:
    tenant = TenantConfig(triage_level=5)
    events: list[Event] = []
    for day in range(10):
        for k in range(12):
            events.append(_event(day * 1440 + k * 60, event_id=f"e{day}-{k}"))  # hidden
        events.append(_event(day * 1440 + 5, srcip="10.20.0.16"))  # other IP: kept
        events.append(_event(day * 1440 + 6, rule="5716"))  # other rule: ignored
        events.append(_event(day * 1440 + 7, level=3))  # hidden but below triage
    suggestion = _suggestion("5710", ("data.srcip", "10.20.0.15"))
    stats = run_backtest([suggestion], events, tenant=tenant, dispositions=None)["s1"]
    assert stats.hidden_total == 130
    assert stats.hidden_analyst_facing == 120
    assert stats.rule_total == 140 and stats.rule_analyst_facing == 130
    assert stats.share_of_rule == 130 / 140
    assert set(stats.per_day.values()) == {13}
    assert stats.agents_affected == 1
    assert stats.levels == {5: 120, 3: 10}
    assert not stats.hides_high and stats.tp_hidden == 0
    assert 1 <= len(stats.examples.items) <= 3 and len(stats.example_docs()) == len(stats.examples.items)
    # hourly alerts are distinct 15-minute clusters; the level-3 one at minute 7 joins the minute-0 cluster
    assert abs(stats.clusters.count() - 120) <= 2
    assert abs(stats.analyst_facing_clusters.count() - 120) <= 2
    assert stats.first_seen == events[0].ts.timestamp()
    assert downgrade_reasons(stats, tenant=tenant, window=_window()) == []
    text = i18n.render(summary_message(stats, tenant=tenant, days=10), "es")
    assert "130" in text and "13,0/día" in text


def test_matching_is_exact_and_case_sensitive() -> None:
    tenant = TenantConfig()
    events = [
        _event(1, user="svc_backup"),
        _event(2, user="SVC_BACKUP"),
        _event(3, user="svc_backup_evil"),
        _event(4, user=None, extra={"data.dstuser": ["alice", "svc_backup"]}),  # list: any element matches
    ]
    suggestion = _suggestion("5710", ("data.dstuser", "svc_backup"))
    stats = run_backtest([suggestion], events, tenant=tenant, dispositions=None)["s1"]
    assert stats.hidden_total == sum(1 for e in events if suggestion.matches(e)) == 2


def test_high_level_and_true_positives_downgrade() -> None:
    tenant = TenantConfig()
    disp = Dispositions.from_rows(
        [
            {"alert_id": "tp-1", "verdict": "tp"},
            {"alert_id": "fp-1", "verdict": "fp"},
            {"rule_id": "5710", "field": "data.dstuser", "value": "root", "verdict": "tp"},
            {"rule_id": "5710", "field": "data.dstuser", "value": "admin", "verdict": "tp", "closed_at": "2020-01-01"},
        ]
    )
    events = [
        _event(1, event_id="tp-1"),
        _event(2, event_id="fp-1"),
        _event(3, user="root"),
        _event(4, user="admin"),  # TP scope row outside the look-back window
        _event(5, level=12),
    ]
    suggestion = _suggestion("5710", ("data.srcip", "10.20.0.15"))
    watch = BacktestWatch(since=datetime(2026, 6, 1, tzinfo=UTC))
    stats = run_backtest([suggestion], events, tenant=tenant, dispositions=disp, watch=watch)["s1"]
    assert stats.tp_hidden == 2 and stats.hidden_high == 1 and stats.hides_high
    assert stats.dispositions.tp == 1 and stats.dispositions.fp == 1
    keys = [m.key for m in downgrade_reasons(stats, tenant=tenant)]
    assert keys[:2] == ["noise.backtest.high", "noise.backtest.tp"]


def test_co_occurrence_on_actors_not_targets() -> None:
    tenant = TenantConfig()
    index = g.HighAlertIndex()
    hour = int(T0.timestamp() // 3600)
    index.add("ip", "10.0.5.23", hour + 10)  # an internal actor seen in a level-12 alert
    index.add("host", "srv-web-01.example", hour + 10)  # an attacked host
    index.add("ip", "10.0.0.80", hour + 10)  # an internal TARGET (destination)
    watch = BacktestWatch(high=index, co_window_hours=24)
    events = [
        _event(60, agent="srv-web-01.example", srcip="10.0.5.23"),
        _event(61, agent="srv-web-01.example", srcip="10.20.0.15", extra={"data.dstip": "10.0.0.80"}),
        _event(62 + 60 * 48, agent="srv-web-01.example", srcip="10.0.5.23"),  # outside ±24h
    ]
    scoped = _suggestion("5710", ("data.srcip", "10.0.5.23"), fp="actor")
    scanner = _suggestion("5710", ("data.srcip", "10.20.0.15"), fp="scanner")
    host_wide = _suggestion("5710", ("agent.name", "srv-web-01.example"), fp="host")
    stats = run_backtest([scoped, scanner, host_wide], events, tenant=tenant, dispositions=None, watch=watch)
    assert stats["actor"].co_occurring == 1 and stats["actor"].co_values == [("ip", "10.0.5.23")]
    assert stats["scanner"].co_occurring == 0  # the attacked host and the internal target are not the actor
    assert stats["host"].co_occurring == 2  # host-anchored: hiding the host hides whatever hits it
    reason = downgrade_reasons(stats["actor"], tenant=tenant)[0]
    assert reason.key == "noise.backtest.co_occurrence"
    assert all(isinstance(e, i18n.Entity) for e in reason.params["entities"])


def test_attempted_usernames_are_not_actors() -> None:
    tenant = TenantConfig()
    index = g.HighAlertIndex()
    index.add("user", "admin", int(T0.timestamp() // 3600))
    watch = BacktestWatch(high=index)
    failed = _event(5, user="admin", groups=("sshd", "authentication_failed"))
    success = _event(6, user="admin", groups=("sshd", "authentication_success"))
    stats = run_backtest(
        [_suggestion("5710", ("data.srcip", "10.20.0.15"))],
        [failed, success],
        tenant=tenant,
        dispositions=None,
        watch=watch,
    )["s1"]
    assert stats.co_occurring == 1  # only the successful logon of "admin" links to the high alert


def test_beacon_addresses_downgrade() -> None:
    tenant = TenantConfig()
    events = [_event(i, extra={"data.dstip": "198.51.100.77" if i % 2 else "10.0.0.1"}) for i in range(10)]
    suggestion = _suggestion("5710", ("agent.name", "srv-app-01.corp.example"))
    # a public address with sustained activity that is not a steady outbound beacon still blocks tuning...
    watch = BacktestWatch(beacons={"5710": frozenset({"198.51.100.77"})})
    stats = run_backtest([suggestion], events, tenant=tenant, dispositions=None, watch=watch)["s1"]
    assert stats.beacon_hits == 0 and stats.sustained_hits == 5 and stats.sustained_values == ["198.51.100.77"]
    assert [m.key for m in downgrade_reasons(stats, tenant=tenant)] == ["noise.backtest.sustained"]
    # ...and is called beaconing only when pass 1 found it periodic (outbound, steady interval)
    periodic = BacktestWatch(
        beacons={"5710": frozenset({"198.51.100.77"})}, periodic={"5710": frozenset({"198.51.100.77"})}
    )
    stats = run_backtest([suggestion], events, tenant=tenant, dispositions=None, watch=periodic)["s1"]
    assert stats.beacon_hits == 5 and stats.beacon_values == ["198.51.100.77"]
    assert [m.key for m in downgrade_reasons(stats, tenant=tenant)] == ["noise.backtest.beacon"]


def test_burst_in_hidden_series_downgrades() -> None:
    tenant = TenantConfig()
    events = [_event(day * 1440 + k) for day in range(10) for k in range(10)]
    events += [_event(9 * 1440 + 100 + k) for k in range(60)]  # last day: 70 vs median 10
    stats = run_backtest([_suggestion("5710", ("data.srcip", "10.20.0.15"))], events, tenant=tenant, dispositions=None)[
        "s1"
    ]
    reasons = downgrade_reasons(stats, tenant=tenant, window=_window())
    assert [m.key for m in reasons] == ["noise.backtest.burst"]
    assert reasons[0].params["peak"] == 70


def test_empty_inputs() -> None:
    tenant = TenantConfig()
    assert run_backtest([], [_event(1)], tenant=tenant, dispositions=None) == {}
    stats = run_backtest([_suggestion("5710", ("data.srcip", "10.20.0.15"))], [], tenant=tenant, dispositions=None)[
        "s1"
    ]
    assert stats.hidden_total == 0 and stats.share_of_rule == 0.0 and stats.share_of_analyst_facing == 0.0
    assert downgrade_reasons(stats, tenant=tenant, window=None) == []
    no_rule = Event(ts=T0, rule_id=None, fields={})
    assert run_backtest([_suggestion("5710")], [no_rule], tenant=tenant, dispositions=None)["s1"].rule_total == 0


def test_duplicate_fingerprints_and_single_pass() -> None:
    tenant = TenantConfig()
    consumed: list[int] = []

    def once() -> Iterable[Event]:
        for i in range(5):
            consumed.append(i)
            yield _event(i)

    a = _suggestion("5710", ("data.srcip", "10.20.0.15"), fp="same")
    b = _suggestion("5710", ("agent.name", "srv-app-01.corp.example"), fp="same")
    stats = run_backtest([a, b], once(), tenant=tenant, dispositions=None)
    assert list(stats) == ["same"] and stats["same"].hidden_total == 5 and consumed == [0, 1, 2, 3, 4]


def test_clip_document_bounds_examples() -> None:
    nested: dict[str, Any] = {"a": {}}
    cursor = nested["a"]
    for _ in range(20):
        cursor["b"] = {}
        cursor = cursor["b"]
    doc = {
        "full_log": "x" * (EXAMPLE_MAX_CHARS + 10),
        "data.srcip": "10.0.0.1",
        "deep": nested,
        "list": list(range(1000)),
    }
    clipped = clip_document(doc)
    assert clipped["full_log"].startswith("x" * EXAMPLE_MAX_CHARS) and clipped["full_log"].endswith("+10 chars]")
    assert clipped["data.srcip"] == "10.0.0.1"
    assert len(clipped["list"]) == 500
    depth, cursor = 0, clipped["deep"]
    while isinstance(cursor, dict) and cursor:
        cursor = next(iter(cursor.values()))
        depth += 1
    assert depth <= 10
    assert doc["full_log"] == "x" * (EXAMPLE_MAX_CHARS + 10)  # the original is untouched


def test_backtest_finds_new_actors_and_periodic_public_peers_on_its_own() -> None:
    tenant = TenantConfig()
    window = _window(10)
    events = [_event(i * 30, srcip=f"10.0.1.{i % 20}") for i in range(10 * 48)]  # routine internal sources
    events += [_event(8 * 1440 + i * 10, srcip="10.66.6.6") for i in range(200)]  # new heavy actor, last 2 days
    events += [_event(i * 60, srcip="10.0.1.1", extra={"data.dstip": "198.51.100.99"}) for i in range(24 * 3)]
    host_wide = _suggestion("5710", ("agent.name", "srv-app-01.corp.example"))
    stats = run_backtest([host_wide], events, tenant=tenant, dispositions=None, watch=BacktestWatch(window=window))[
        "s1"
    ]
    assert [(k, v) for k, v, _ in stats.novel_actors] == [("ip", "10.66.6.6")]
    assert stats.beacon_values == ["198.51.100.99"] and stats.beacon_hits >= 72
    keys = [m.key for m in downgrade_reasons(stats, tenant=tenant, window=window)]
    assert "noise.backtest.novel_actor" in keys and "noise.backtest.beacon" in keys
    pinned = _suggestion("5710", ("data.srcip", "10.66.6.6"), fp="pinned")
    only = run_backtest([pinned], events, tenant=tenant, dispositions=None, watch=BacktestWatch(window=window))
    assert only["pinned"].novel_actors == []  # the suggestion's own anchor is gated in pass 1, not here


# ---- review regressions ------------------------------------------------------------------------------------------
def test_exposure_is_measured_on_the_hidden_events() -> None:
    tenant = TenantConfig()
    events = [_event(i * 10, srcip=f"203.0.113.{i % 200 + 1}", extra={"data.url": "/wp-login.php"}) for i in range(300)]
    events += [_event(i * 10 + 5, srcip="10.1.1.9", extra={"data.url": "/app"}) for i in range(100)]
    login = _suggestion("5710", ("agent.name", "srv-app-01.corp.example"), ("data.url", "/wp-login.php"))
    stats = run_backtest([login], events, tenant=tenant, dispositions=None, watch=BacktestWatch(window=_window(1)))[
        "s1"
    ]
    assert stats.hidden_external == 300 and stats.external_share == 1.0
    keys = [m.key for m in downgrade_reasons(stats, tenant=tenant, window=_window(1))]
    assert "noise.backtest.exposure" in keys
    assert "noise.backtest.novel_actor" not in keys  # ever-new Internet addresses ARE the exposure


def test_a_single_alert_from_a_late_actor_is_enough() -> None:
    tenant = TenantConfig()
    window = _window(10)
    events = [_event(i * 30, srcip=f"10.0.1.{i % 20}") for i in range(10 * 48)]
    events.append(_event(9 * 1440, srcip="10.66.6.6"))
    host_wide = _suggestion("5710", ("agent.name", "srv-app-01.corp.example"))
    stats = run_backtest([host_wide], events, tenant=tenant, dispositions=None, watch=BacktestWatch(window=window))[
        "s1"
    ]
    assert [(k, v, n) for k, v, n in stats.novel_actors] == [("ip", "10.66.6.6", 1)]
    assert "noise.backtest.novel_actor" in [m.key for m in downgrade_reasons(stats, tenant=tenant, window=window)]


def test_too_many_actors_cannot_be_verified(monkeypatch: Any) -> None:
    import hushwatch.analysis.backtest as bt

    monkeypatch.setattr(bt, "MAX_ACTORS", 5)
    tenant = TenantConfig()
    events = [_event(i, srcip=f"10.0.2.{i}") for i in range(20)]
    stats = bt.run_backtest(
        [_suggestion("5710", ("agent.name", "srv-app-01.corp.example"))], events, tenant=tenant, dispositions=None
    )["s1"]
    assert stats.actors_truncated
    assert "noise.backtest.actors_truncated" in [m.key for m in bt.downgrade_reasons(stats, tenant=tenant)]


def test_new_host_inside_a_scope_that_does_not_pin_one() -> None:
    tenant = TenantConfig()
    window = _window(10)
    events = [_event(i * 60, agent=f"srv-app-0{i % 3}.corp.example") for i in range(240)]
    events += [_event(9 * 1440 + m, agent="dc01.corp.example") for m in range(3)]
    scanner = _suggestion("5710", ("data.srcip", "10.20.0.15"), fp="ip")
    host = _suggestion("5710", ("agent.name", "dc01.corp.example"), fp="host")
    stats = run_backtest([scanner, host], events, tenant=tenant, dispositions=None, watch=BacktestWatch(window=window))
    assert stats["ip"].novel_hosts == [("dc01.corp.example", 3)]
    keys = [m.key for m in downgrade_reasons(stats["ip"], tenant=tenant, window=window)]
    assert "noise.backtest.novel_host" in keys
    assert stats["host"].novel_hosts == []  # a scope that pins the host cannot reach another one
    wide = _suggestion("5710", fp="wide")
    rule_wide = run_backtest([wide], events, tenant=tenant, dispositions=None, watch=BacktestWatch(window=window))
    assert rule_wide["wide"].novel_hosts == []  # an explicit rule-wide opt-in mutes every host by definition


def test_unknown_levels_downgrade() -> None:
    tenant = TenantConfig()
    event = _event(1)
    event.severity = None
    stats = run_backtest(
        [_suggestion("5710", ("data.srcip", "10.20.0.15"))], [event], tenant=tenant, dispositions=None
    )["s1"]
    assert stats.hidden_unknown_level == 1
    assert downgrade_reasons(stats, tenant=tenant)[0].key == "noise.backtest.unknown_level"


def test_true_positive_rows_match_case_space_and_short_names() -> None:
    tenant = TenantConfig()
    disp = Dispositions.from_rows(
        [
            {"rule_id": "5710", "field": "srcip", "value": "10.20.0.15 ", "verdict": "tp"},
            {"rule_id": "5710", "field": "user", "value": "ROOT", "verdict": "TP"},
        ]
    )
    events = [_event(1, srcip="10.20.0.16"), _event(2, srcip="10.20.0.15"), _event(3, srcip="10.20.0.16", user="root")]
    stats = run_backtest(
        [_suggestion("5710", ("agent.name", "srv-app-01.corp.example"))], events, tenant=tenant, dispositions=disp
    )["s1"]
    assert stats.tp_hidden == 2


def test_syslog_sender_scope_is_host_anchored() -> None:
    tenant = TenantConfig()
    index = g.HighAlertIndex()
    hour = int(T0.timestamp() // 3600)
    index.add("host", "fw-edge-01", hour)
    watch = BacktestWatch(high=index, co_window_hours=24)
    event = _event(
        5,
        agent="wazuh-manager",
        srcip="10.0.0.9",
        extra={"agent.id": "000", "predecoder.hostname": "fw-edge-01", "location": "10.10.0.1"},
    )
    stats = run_backtest(
        [_suggestion("5710", ("location", "10.10.0.1"))], [event], tenant=tenant, dispositions=None, watch=watch
    )["s1"]
    assert stats.co_occurring == 1 and stats.co_values == [("host", "fw-edge-01")]
