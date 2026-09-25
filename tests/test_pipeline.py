"""Tests for hushwatch.analysis.pipeline (input completeness, skew, freshness, daemon stats, ingest lag).

Synthetic data only: *.example hosts, RFC 5737 addresses.
"""

from __future__ import annotations

import copy
import json
import math
import random
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from hushwatch import i18n
from hushwatch.analysis.pipeline import (
    LAG_MIN_SAMPLES,
    LagCollector,
    PipelineResult,
    analyze_pipeline,
    lag_seconds,
    parse_daemon_stats,
)
from hushwatch.config import TenantConfig
from hushwatch.i18n import Entity, Message, render
from hushwatch.inventory import AgentInfo
from hushwatch.models import DataBasis, Event, Finding, Severity
from hushwatch.timeutil import parse_ts

UTC = timezone.utc
NOW = datetime(2026, 9, 25, 12, 0, tzinfo=UTC)


def complete_basis(**kwargs: Any) -> DataBasis:
    values: dict[str, Any] = {
        "input_kind": "alerts",
        "profile": "wazuh4",
        "events": 10_000,
        "start": NOW - timedelta(days=14),
        "end": NOW - timedelta(minutes=5),
        "now": NOW - timedelta(minutes=5),
        "now_origin": "data",
    }
    values.update(kwargs)
    return DataBasis(**values)


def run(basis: DataBasis | None = None, tenant: TenantConfig | None = None, **kwargs: Any) -> PipelineResult:
    return analyze_pipeline(basis or complete_basis(), tenant=tenant or TenantConfig(), now=NOW, **kwargs)


def by_kind(result: PipelineResult, kind: str) -> list[Finding]:
    return [f for f in result.findings if f.kind == kind]


def check(result: PipelineResult, name: str) -> dict[str, Any]:
    return next(c for c in result.section["checks"] if c["check"] == name)


# ---- input completeness -------------------------------------------------------------------------------------------


def test_complete_basis_has_no_findings() -> None:
    result = run()
    assert result.findings == []
    assert result.section["status"] == "ok"
    assert check(result, "input_completeness")["status"] == "ok"
    assert check(result, "freshness")["status"] == "ok"


def test_partial_failures_make_the_analysis_incomplete() -> None:
    huge = "shard failure on wazuh-alerts-4.x-2026.09.24: " + "x" * 1_000_000
    result = run(complete_basis(partial_failures=["timeout on wazuh-alerts-4.x-2026.09.25", huge, "a", "b"]))
    findings = by_kind(result, "assessment.incomplete")
    assert len(findings) == 1
    finding = findings[0]
    assert finding.domain == "assessment"
    assert finding.severity is Severity.HIGH
    assert finding.subject == "basis"
    assert finding.evidence["partial_failures"] == 4
    assert all(len(example) <= 201 for example in finding.evidence["partial_failure_examples"])
    text = render(finding.reasons[0])
    assert "Partial failures while reading the input: 4" in text
    assert len(text) < 1000
    assert check(result, "input_completeness")["status"] == "fail"


def test_truncated_and_empty_inputs() -> None:
    truncated = by_kind(run(complete_basis(truncated=True)), "assessment.incomplete")[0]
    assert truncated.severity is Severity.HIGH
    assert truncated.evidence["triggers"] == ["truncated"]
    empty_result = run(complete_basis(events=0, now=None, sampled=True, not_evaluated=["fields"]))
    empty = by_kind(empty_result, "assessment.incomplete")[0]
    assert empty.severity is Severity.HIGH
    assert "no_events" in empty.evidence["triggers"]
    reasons = " ".join(render(r) for r in empty.reasons)
    assert "No events were read" in reasons
    assert "Not evaluated with this input: fields" in reasons
    assert "sample" in reasons
    # nothing could run: grey, not green
    assert empty_result.section["status"] == "not_assessed"


def test_unparseable_timestamps_and_lines() -> None:
    finding = by_kind(run(complete_basis(bad_timestamps=500)), "assessment.incomplete")[0]
    assert finding.severity is Severity.MEDIUM
    assert finding.evidence["bad_timestamps"] == 500
    assert "%" in render(finding.reasons[0])
    finding = by_kind(run(complete_basis(malformed=300)), "assessment.incomplete")[0]
    assert finding.evidence["triggers"] == ["malformed"]
    # a handful of bad lines in a big input is reported in the section only
    result = run(complete_basis(bad_timestamps=3, malformed=2))
    assert by_kind(result, "assessment.incomplete") == []
    assert check(result, "input_completeness")["bad_timestamps"] == 3


# ---- clock skew and freshness ------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("future", "events", "severity"),
    [(3, 1_000_000, Severity.LOW), (10, 1000, Severity.MEDIUM), (100, 1000, Severity.HIGH)],
)
def test_future_timestamps_are_clock_skew(future: int, events: int, severity: Severity) -> None:
    result = run(complete_basis(future_timestamps=future, events=events))
    finding = by_kind(result, "pipeline.clock_skew")[0]
    assert finding.domain == "pipeline"
    assert finding.severity is severity
    assert finding.subject == "basis:future_timestamps"
    assert finding.evidence["future_timestamps"] == future
    assert str(future) in render(finding.title)
    assert "futuro" in render(finding.title, "es")


def test_stale_export_is_an_informational_assessment_finding() -> None:
    result = run(complete_basis(now=NOW - timedelta(days=3), end=NOW - timedelta(days=3)))
    findings = by_kind(result, "assessment.incomplete")
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity is Severity.INFO  # a caveat: must not force exit code 3
    assert finding.subject == "basis:stale"
    assert "3d" in render(finding.title)
    assert "relative to the end of the data" in render(finding.reasons[0])
    assert check(result, "freshness")["age_hours"] == 72.0


def test_now_given_by_flag_is_not_stale() -> None:
    result = run(complete_basis(now=NOW - timedelta(days=30), now_origin="flag"))
    assert result.findings == []


# ---- daemon stats ---------------------------------------------------------------------------------------------------


def api_daemon_stats(**overrides: Any) -> dict[str, Any]:
    """Shape of GET /manager/daemons/stats in Wazuh 4.14 (values from the documentation example)."""
    analysisd = {
        "uptime": "2025-11-25T11:08:56+00:00",
        "timestamp": "2025-11-25T11:12:19+00:00",
        "name": "wazuh-analysisd",
        "metrics": {
            "bytes": {"received": 14507032},
            "eps": {"available_credits": 0, "events_dropped": 0, "events_dropped_not_eps": 0, "seconds_over_limit": 0},
            "events": {
                "processed": 8690,
                "received": 9849,
                "received_breakdown": {
                    "decoded_breakdown": {"agent": 0, "dbsync": 1155, "syslog": 0},
                    "dropped_breakdown": {
                        "agent": 0,
                        "agentless": 0,
                        "dbsync": 0,
                        "integrations_breakdown": {"virustotal": 0},
                        "modules_breakdown": {
                            "aws": 0,
                            "logcollector_breakdown": {"eventchannel": 0, "eventlog": 0, "macos": 0, "others": 0},
                            "syscheck": 0,
                        },
                        "monitor": 0,
                        "remote": 0,
                        "syslog": 0,
                    },
                },
                "written_breakdown": {"alerts": 1142, "archives": 0},
            },
            "queues": {
                "alerts": {"size": 16384, "usage": 0},
                "eventchannel": {"size": 16384, "usage": 0},
                "syscheck": {"size": 16384, "usage": 0},
            },
        },
    }
    remoted = {
        "uptime": "2025-11-25T11:08:55+00:00",
        "timestamp": "2025-11-25T11:12:19+00:00",
        "name": "wazuh-remoted",
        "metrics": {
            "bytes": {"received": 6804778, "sent": 1958},
            "messages": {
                "received_breakdown": {"control": 22, "discarded": 0, "event": 8341},
                "sent_breakdown": {"ack": 22, "discarded": 0},
            },
            "queues": {"received": {"size": 131072, "usage": 0}},
            "tcp_sessions": 1,
        },
    }
    db = {"name": "wazuh-db", "metrics": {"queries": {"received": 4624}}}
    doc = {
        "data": {
            "affected_items": [remoted, analysisd, db],
            "total_affected_items": 3,
            "failed_items": [],
            "total_failed_items": 0,
        },
        "message": "Statistical information for each daemon was successfully read",
        "error": 0,
    }
    for path, value in overrides.items():
        node: Any = doc
        keys = path.split("/")
        for key in keys[:-1]:
            node = node[int(key)] if isinstance(node, list) else node[key]
        node[keys[-1]] = value
    return doc


def test_healthy_daemon_stats_have_no_findings() -> None:
    result = run(daemon_stats=api_daemon_stats())
    assert result.findings == []
    row = check(result, "manager_daemons")
    assert row["status"] == "ok"
    assert {d["daemon"] for d in row["daemons"]} == {"wazuh-analysisd", "wazuh-remoted"}


def test_analysisd_drops_are_not_double_counted() -> None:
    stats = api_daemon_stats()
    metrics = stats["data"]["affected_items"][1]["metrics"]
    metrics["eps"]["events_dropped"] = 100
    metrics["eps"]["events_dropped_not_eps"] = 20
    dropped = metrics["events"]["received_breakdown"]["dropped_breakdown"]
    dropped["modules_breakdown"]["logcollector_breakdown"]["eventchannel"] = 90
    dropped["agent"] = 60
    metrics["eps"]["seconds_over_limit"] = 42
    result = run(daemon_stats=stats)
    findings = by_kind(result, "pipeline.manager_drops")
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity is Severity.HIGH
    assert finding.subject == "daemon:wazuh-analysisd"
    assert finding.evidence["dropped"] == 150  # max(EPS counters, breakdown), never their sum
    assert finding.evidence["dropped_breakdown"] == {"modules.logcollector.eventchannel": 90, "agent": 60}
    assert finding.evidence["eps_seconds_over_limit"] == 42
    assert "150" in render(finding.title)
    reasons = " ".join(render(r) for r in finding.reasons)
    assert "modules.logcollector.eventchannel" in reasons
    assert "2025-11-25T11:08:56Z" in reasons  # counters are cumulative since uptime
    assert "descartó" in render(finding.title, "es")


def test_tiny_cumulative_loss_is_medium() -> None:
    stats = api_daemon_stats()
    metrics = stats["data"]["affected_items"][1]["metrics"]
    metrics["eps"]["events_dropped"] = 5
    metrics["events"]["received"] = 50_000_000  # months of uptime
    finding = by_kind(run(daemon_stats=stats), "pipeline.manager_drops")[0]
    assert finding.severity is Severity.MEDIUM
    assert finding.evidence["loss_ratio"] == pytest.approx(1e-7)
    # without a denominator any loss is HIGH
    del metrics["events"]["received"]
    assert by_kind(run(daemon_stats=stats), "pipeline.manager_drops")[0].severity is Severity.HIGH


def test_remoted_discards_and_full_queue() -> None:
    stats = api_daemon_stats()
    remoted = stats["data"]["affected_items"][0]["metrics"]
    remoted["messages"]["received_breakdown"]["discarded"] = 23
    remoted["queues"]["received"]["usage"] = 130_000  # a count out of 131072
    result = run(daemon_stats=stats)
    finding = by_kind(result, "pipeline.manager_drops")[0]
    assert finding.subject == "daemon:wazuh-remoted"
    assert finding.severity is Severity.HIGH
    assert finding.evidence["queues"]["received"] == pytest.approx(130_000 / 131_072, abs=1e-4)
    assert "queue_size" in render(finding.recommendation)


def test_queue_nearly_full_without_drops_is_medium() -> None:
    stats = api_daemon_stats()
    stats["data"]["affected_items"][1]["metrics"]["queues"]["eventchannel"]["usage"] = 0.95
    finding = by_kind(run(daemon_stats=stats), "pipeline.manager_drops")[0]
    assert finding.severity is Severity.MEDIUM
    assert "eventchannel" in render(finding.title)
    assert "95%" in render(finding.title)
    # queue usage is instantaneous: no "cumulative since start" note
    assert all(r.key != "pipeline.drops.reason.cumulative" for r in finding.reasons if isinstance(r, Message))


def test_eps_limit_and_sent_discards_alone() -> None:
    stats = api_daemon_stats()
    stats["data"]["affected_items"][1]["metrics"]["eps"]["seconds_over_limit"] = 30
    stats["data"]["affected_items"][0]["metrics"]["messages"]["sent_breakdown"]["discarded"] = 4
    found = {f.subject: f for f in by_kind(run(daemon_stats=stats), "pipeline.manager_drops")}
    assert found["daemon:wazuh-analysisd"].severity is Severity.MEDIUM
    assert found["daemon:wazuh-remoted"].severity is Severity.LOW


def test_daemon_stats_shapes() -> None:
    new = api_daemon_stats()
    new["data"]["affected_items"][1]["metrics"]["eps"]["events_dropped"] = 7
    items = new["data"]["affected_items"]
    shapes: list[Any] = [
        new,  # full API response
        new["data"],  # data part
        items,  # affected_items list
        {"wazuh-analysisd": items[1], "wazuh-remoted": items[0]},  # keyed by daemon name
        {"analysisd": {k: v for k, v in items[1].items() if k != "name"}},  # short key, no name
        items[1],  # single item
    ]
    for shape in shapes:
        healths = {h.daemon: h for h in parse_daemon_stats(shape)}
        assert healths["wazuh-analysisd"].dropped == 7, shape
        assert not healths["wazuh-analysisd"].legacy


def test_legacy_flat_shapes_with_string_values() -> None:
    analysisd = {
        "data": {
            "affected_items": [
                {
                    "total_events_decoded": "112.00",
                    "events_dropped": "12",
                    "event_queue_usage": "0.95",
                    "event_queue_size": "16384",
                    "alerts_queue_usage": "0.04",
                    "alerts_queue_size": "16384",
                }
            ]
        }
    }
    remoted_state = {"queue_size": "'0'", "total_queue_size": "'131072'", "discarded_count": "'23'", "evt_count": 5}
    healths = parse_daemon_stats(analysisd) + parse_daemon_stats(remoted_state)
    assert [h.daemon for h in healths] == ["wazuh-analysisd", "wazuh-remoted"]
    assert healths[0].legacy and healths[0].dropped == 12
    assert healths[0].queues == {"event": 0.95, "alerts": 0.04}
    assert healths[1].legacy and healths[1].dropped == 23 and healths[1].queues == {"received": 0.0}
    result = run(daemon_stats=analysisd)
    finding = by_kind(result, "pipeline.manager_drops")[0]
    assert finding.evidence["legacy_format"] is True
    assert finding.evidence["dropped"] == 12


def test_queue_usage_semantics() -> None:
    def usage(value: Any, size: Any = 16384) -> float | None:
        item = {"name": "wazuh-analysisd", "metrics": {"queues": {"q": {"usage": value, "size": size}}}}
        return parse_daemon_stats(item)[0].queues.get("q")

    assert usage(0.5) == 0.5  # fraction (Wazuh 4.x: elements / (size - 1))
    assert usage(85) == 0.85  # tolerated as a percentage
    assert usage(8192) == 0.5  # tolerated as a count when above 100
    assert usage(-1) is None  # the "queue not allocated" sentinel
    assert usage(20000) is None  # more items than capacity: nonsense
    assert usage(float("nan")) is None


def test_hostile_daemon_stats_never_crash() -> None:
    deep: dict[str, Any] = {}
    node = deep
    for _ in range(5000):
        node["x"] = {}
        node = node["x"]
    hostile_item = {
        "name": "wazuh-analysisd",
        "metrics": {
            "eps": {"events_dropped": float("nan"), "events_dropped_not_eps": -5, "seconds_over_limit": "1e999"},
            "events": {
                "received_breakdown": {
                    "dropped_breakdown": {
                        "agent": True,
                        "remote": "1e999",
                        "syslog": 10**400,
                        "monitor": "12; DROP TABLE",
                        "deep": deep,
                        "<script>": {"x": 1e300},
                    }
                }
            },
            "queues": {"alerts": {"usage": float("inf"), "size": 0}, "archives": {"usage": "abc"}, "q" * 500: {}},
        },
    }
    shapes: list[Any] = [
        None,
        "garbage",
        42,
        [],
        {},
        [1, "a", None],
        {"data": "x"},
        {"data": {"affected_items": "nope"}},
        {"data": {"affected_items": [hostile_item] * 10_000}},
        {"error": 1, "data": {"affected_items": [], "failed_items": [{"error": {"code": 1017}}]}},
        {"name": "wazuh-db", "metrics": {"queries": {}}},
        {"wazuh-analysisd": "not a mapping"},
        deep,
    ]
    for shape in shapes:
        result = run(daemon_stats=shape)
        row = check(result, "manager_daemons")
        assert row["status"] in ("ok", "warn", "fail", "not_assessed")
        for finding in result.findings:
            assert all(math.isfinite(v) for v in finding.evidence.get("queues", {}).values())
    # the hostile item is parsed (capped) but yields no drop: every counter is invalid
    healths = parse_daemon_stats({"data": {"affected_items": [hostile_item] * 10_000}})
    assert len(healths) == 64
    assert healths[0].dropped == 0 and healths[0].queues == {}
    assert check(run(daemon_stats={}), "manager_daemons")["status"] == "not_assessed"
    assert check(run(daemon_stats=None), "manager_daemons")["reason"] == "no_stats"


def test_cluster_nodes_are_separate_subjects_and_entities() -> None:
    first = copy.deepcopy(api_daemon_stats()["data"]["affected_items"][1])
    first["metrics"]["eps"]["events_dropped"] = 5
    second = copy.deepcopy(first)
    first["node_name"] = "master-node"
    second["node_name"] = "worker-01"
    result = run(daemon_stats=[first, second])
    subjects = sorted(f.subject for f in by_kind(result, "pipeline.manager_drops"))
    assert subjects == ["daemon:wazuh-analysisd|node:master-node", "daemon:wazuh-analysisd|node:worker-01"]
    assert all(isinstance(f.evidence["node"], Entity) for f in result.findings)


# ---- lag_seconds ----------------------------------------------------------------------------------------------------


def event(ts: str | datetime, fields: dict[str, Any], source: str = "ws-01.example") -> Event:
    when = ts if isinstance(ts, datetime) else parse_ts(ts)
    assert when is not None
    return Event(ts=when, source=source, fields=fields)


def test_lag_seconds_windows_system_time() -> None:
    e = event("2026-09-25T10:20:11.302+0000", {"data.win.system.systemTime": "2026-09-25T10:20:10.8841234Z"})
    assert lag_seconds(e) == pytest.approx(0.4179, abs=1e-3)
    nested = event(
        "2026-09-25T10:25:10.000+0000", {"data": {"win": {"system": {"systemTime": "2026-09-25T10:20:10Z"}}}}
    )
    assert lag_seconds(nested) == pytest.approx(300.0)


def test_lag_seconds_syslog_uses_manager_offset() -> None:
    fields = {"timestamp": "2026-09-25T13:15:32.481+0300", "predecoder.timestamp": "Sep 25 13:15:31"}
    assert lag_seconds(event("2026-09-25T13:15:32.481+0300", fields)) == pytest.approx(1.481, abs=1e-3)
    fields = {"timestamp": "2026-09-25T07:15:32.481-0300", "predecoder.timestamp": "Sep 25 07:10:31"}
    assert lag_seconds(event("2026-09-25T07:15:32.481-0300", fields)) == pytest.approx(301.481, abs=1e-3)
    # classic syslog pads the day with a space
    fields = {"timestamp": "2026-09-05T07:15:32.000-0300", "predecoder.timestamp": "Sep  5 07:15:30"}
    assert lag_seconds(event("2026-09-05T07:15:32.000-0300", fields)) == pytest.approx(2.0)


def test_lag_seconds_syslog_without_offset_is_not_guessed() -> None:
    e = event("2026-09-25T10:15:32Z", {"predecoder.timestamp": "Sep 25 10:15:31"})
    assert lag_seconds(e) is None


def test_lag_seconds_syslog_year_boundary() -> None:
    fields = {"timestamp": "2027-01-01T00:00:05.000+0000", "predecoder.timestamp": "Dec 31 23:59:59"}
    assert lag_seconds(event("2027-01-01T00:00:05.000+0000", fields)) == pytest.approx(6.0)
    fields = {"timestamp": "2026-12-31T23:59:59.000+0000", "predecoder.timestamp": "Jan  1 00:00:04"}
    assert lag_seconds(event("2026-12-31T23:59:59.000+0000", fields)) == pytest.approx(-5.0)


def test_lag_seconds_syslog_iso_with_offset() -> None:
    fields = {"predecoder.timestamp": "2026-09-25T12:15:31.000+02:00"}
    assert lag_seconds(event("2026-09-25T10:16:31Z", fields)) == pytest.approx(60.0)


def test_lag_seconds_ecs() -> None:
    fields = {"event.ingested": "2026-09-25T10:30:00Z", "@timestamp": "2026-09-25T10:00:00.000Z"}
    assert lag_seconds(event("2026-09-25T10:30:00Z", fields)) == pytest.approx(1800.0)
    nested = {"event": {"ingested": "2026-09-25T10:00:10Z"}, "@timestamp": "2026-09-25T10:00:00Z"}
    assert lag_seconds(event("2026-09-25T10:00:10Z", nested)) == pytest.approx(10.0)
    # Wazuh indexer documents: @timestamp is a copy of the arrival time, no event.ingested -> no lag information
    assert lag_seconds(event("2026-09-25T10:00:10Z", {"@timestamp": "2026-09-25T10:00:10Z"})) is None


@pytest.mark.parametrize(
    "fields",
    [
        {},
        {"data.win.system.systemTime": "x" * 1000},
        {"data.win.system.systemTime": ["2026-09-25T10:20:10Z"]},
        {"data.win.system.systemTime": {"a": 1}},
        {"data.win.system.systemTime": True},
        {"data.win.system.systemTime": "not a date"},
        {"data.win.system.systemTime": "1000-01-01T00:00:00Z"},  # absurd: > 5 years
        {"timestamp": "2026-09-25T10:00:00+0000", "predecoder.timestamp": "Feb 30 10:00:00"},
        {"timestamp": "2026-09-25T10:00:00+9999", "predecoder.timestamp": "Sep 25 10:00:00"},
        {"timestamp": "x" * 100, "predecoder.timestamp": "Sep 25 10:00:00"},
        {"timestamp": "2026-09-25T10:00:00+0000", "predecoder.timestamp": 12345},
        {"timestamp": "2026-09-25T10:00:00+0000", "predecoder.timestamp": ""},
        {"event.ingested": "2026-09-25T10:00:00Z"},
        {"event.ingested": "garbage", "@timestamp": "2026-09-25T10:00:00Z"},
    ],
)
def test_lag_seconds_hostile_or_missing(fields: dict[str, Any]) -> None:
    assert lag_seconds(event("2026-09-25T10:00:10Z", fields)) is None


# ---- LagCollector ---------------------------------------------------------------------------------------------------


def windows_event(host: str, arrival: datetime, lag: float) -> Event:
    origin = arrival - timedelta(seconds=lag)
    return Event(
        ts=arrival,
        source=host,
        fields={"data.win.system.systemTime": origin.strftime("%Y-%m-%dT%H:%M:%S.%fZ")},
    )


def test_lag_collector_reservoir_is_bounded_and_deterministic() -> None:
    events = [windows_event("ws-01.example", NOW + timedelta(seconds=i), float(i % 100)) for i in range(5000)]
    events.append(Event(ts=NOW, source="ws-01.example", fields={"other": 1}))  # no origin time
    events.append(Event(ts=NOW, source=None, fields={"data.win.system.systemTime": "2026-09-25T10:00:00Z"}))
    first, second = LagCollector(per_agent=64), LagCollector(per_agent=64)
    for e in events:
        first.add(e)
        second.add(e)
    samples = first.samples()
    assert list(samples) == ["ws-01.example"]
    assert len(samples["ws-01.example"]) == 64
    assert samples == second.samples()
    assert all(0 <= v < 100 for v in samples["ws-01.example"])
    assert first.stats()["with_origin"] == 5000
    assert first.stats()["events"] == 5002
    # roughly uniform: the mean of 0..99 is 49.5
    assert 30 < sum(samples["ws-01.example"]) / 64 < 70


def test_lag_collector_caps_sources_and_counts_unparseable() -> None:
    collector = LagCollector(per_agent=4, max_agents=2)
    for host in ("a.example", "b.example", "c.example"):
        collector.add(windows_event(host, NOW, 5.0))
    collector.add(Event(ts=NOW, source="a.example", fields={"data.win.system.systemTime": "garbage"}))
    stats = collector.stats()
    assert stats["sources"] == 2
    assert stats["sources_overflow"] == 1
    assert stats["unparseable"] == 1


def syslog_event(host: str, arrival: datetime, lag: float, device_offset_h: float) -> Event:
    """A Wazuh syslog alert: manager ``timestamp`` in UTC, device header in the device's local time, no zone."""
    local_origin = (arrival - timedelta(seconds=lag)).astimezone(timezone(timedelta(hours=device_offset_h)))
    return Event(
        ts=arrival,
        source=host,
        fields={
            "timestamp": arrival.strftime("%Y-%m-%dT%H:%M:%S.000+0000"),
            "predecoder.timestamp": local_origin.strftime("%b %d %H:%M:%S").replace(" 0", "  ", 1)
            if local_origin.day < 10
            else local_origin.strftime("%b %d %H:%M:%S"),
        },
    )


def test_timezone_less_syslog_offsets_are_not_lag_or_skew() -> None:
    rng = random.Random(12)
    collector = LagCollector()
    for i in range(200):
        arrival = NOW - timedelta(minutes=5 * i)
        # a firewall logging local time in UTC-3 (manager in UTC), with a small real delay
        collector.add(syslog_event("fw-edge-01.example", arrival, rng.uniform(1, 30), -3))
        # a Nepal-time device (+5:45)
        collector.add(syslog_event("srv-ktm-01.example", arrival, rng.uniform(1, 30), 5.75))
    raw = [lag_seconds(syslog_event("fw-edge-01.example", NOW, 10, -3))]
    assert raw[0] == pytest.approx(3 * 3600 + 10, abs=1)  # the raw measurement includes the zone difference
    samples = collector.samples()
    assert collector.tz_normalized == {"fw-edge-01.example": 3.0, "srv-ktm-01.example": -5.75}
    assert all(0 < v <= 31 for v in samples["fw-edge-01.example"])
    result = run(lag_samples=samples)
    assert result.findings == []


def test_timezone_less_backlog_is_still_lag() -> None:
    rng = random.Random(13)
    collector = LagCollector()
    for i in range(200):
        collector.add(syslog_event("srv-01.example", NOW - timedelta(minutes=5 * i), rng.uniform(600, 4800), 0))
    samples = collector.samples()
    assert collector.tz_normalized == {}  # checked after samples(), which computes it
    findings = by_kind(run(lag_samples=samples), "pipeline.lag")
    assert [f.subject for f in findings] == ["agent:srv-01.example"]


def test_absolute_time_offsets_are_still_reported() -> None:
    collector = LagCollector()
    for i in range(100):
        collector.add(windows_event("ws-01.example", NOW - timedelta(minutes=i), 3 * 3600 + 5.0 + (i % 7)))
    samples = collector.samples()
    assert collector.tz_normalized == {}  # explicit UTC origin times keep their offset
    finding = by_kind(run(lag_samples=samples), "pipeline.clock_skew")[0]
    assert finding.subject == "agent:ws-01.example|tz_offset"


def test_lag_collector_merge() -> None:
    left, right = LagCollector(per_agent=32, seed=1), LagCollector(per_agent=32, seed=2)
    for i in range(500):
        left.add(windows_event("ws-01.example", NOW + timedelta(seconds=i), 10.0))
        right.add(windows_event("ws-01.example", NOW + timedelta(seconds=i), 20.0))
        right.add(windows_event("ws-02.example", NOW + timedelta(seconds=i), 30.0))
    left.merge(right)
    samples = left.samples()
    assert len(samples["ws-01.example"]) == 32
    assert set(samples["ws-01.example"]) <= {10.0, 20.0}
    assert len(set(samples["ws-01.example"])) == 2  # both halves represented
    assert samples["ws-02.example"] == [30.0] * 32
    assert left.stats()["with_origin"] == 1500


# ---- lag analysis ---------------------------------------------------------------------------------------------------


def normal_samples(rng: random.Random, center: float, spread: float, n: int = 100) -> list[float]:
    return [center + rng.uniform(-spread, spread) for _ in range(n)]


def test_one_lagging_source_gets_its_own_finding() -> None:
    rng = random.Random(1)
    samples = {f"ws-{i:02d}.example": normal_samples(rng, 20, 15) for i in range(9)}
    samples["ws-09.example"] = normal_samples(rng, 60, 30, 90) + [1800.0 + 60 * i for i in range(10)]
    result = run(lag_samples=samples)
    findings = by_kind(result, "pipeline.lag")
    assert len(findings) == 1
    finding = findings[0]
    assert finding.subject == "agent:ws-09.example"
    assert finding.severity is Severity.MEDIUM
    assert finding.evidence["p95_seconds"] > 900
    assert isinstance(finding.evidence["agent"], Entity)
    assert "p95" in render(finding.title)
    row = check(result, "ingest_lag")
    assert row["sources_assessed"] == 10 and row["lagging"] == 1
    assert row["worst"][0]["agent"] == Entity("host", "ws-09.example")


def test_lag_beyond_tier_sla_is_high() -> None:
    tenant = TenantConfig(criticality={"critical": ["dc*"]})
    rng = random.Random(2)
    samples = {"dc01.example": normal_samples(rng, 5 * 3600, 600)}
    finding = by_kind(run(lag_samples=samples, tenant=tenant), "pipeline.lag")[0]
    assert finding.severity is Severity.HIGH


def test_most_sources_lagging_is_one_pipeline_finding() -> None:
    rng = random.Random(3)
    samples = {f"ws-{i:02d}.example": normal_samples(rng, 3000, 1500) for i in range(8)}
    samples.update({f"srv-{i:02d}.example": normal_samples(rng, 10, 5) for i in range(2)})
    findings = by_kind(run(lag_samples=samples), "pipeline.lag")
    assert len(findings) == 1
    assert findings[0].subject == "lag:global"
    assert findings[0].evidence["sources_lagging"] == 8
    assert "8" in render(findings[0].title) and "10" in render(findings[0].title)


def test_constant_offset_suggests_clock_behind() -> None:
    rng = random.Random(4)
    samples = {"ws-01.example": normal_samples(rng, 1200, 30)}
    finding = by_kind(run(lag_samples=samples), "pipeline.lag")[0]
    assert any(isinstance(r, Message) and r.key == "pipeline.lag.reason.constant" for r in finding.reasons)


def test_whole_hour_offset_is_a_timezone_problem_not_lag() -> None:
    rng = random.Random(5)
    samples = {"fw-edge-01.example": normal_samples(rng, 3 * 3600, 40)}
    samples.update({f"ws-{i:02d}.example": normal_samples(rng, 20, 10) for i in range(5)})
    result = run(lag_samples=samples)
    assert by_kind(result, "pipeline.lag") == []
    finding = by_kind(result, "pipeline.clock_skew")[0]
    assert finding.subject == "agent:fw-edge-01.example|tz_offset"
    assert finding.evidence["offset_hours"] == 3.0
    assert "+3" in render(finding.title)


def test_quarter_hour_timezone_offset() -> None:
    rng = random.Random(15)
    samples = {"ws-ktm-01.example": normal_samples(rng, -5.75 * 3600, 30)}
    finding = by_kind(run(lag_samples=samples), "pipeline.clock_skew")[0]
    assert finding.evidence["offset_hours"] == -5.75
    assert "-5.75" in render(finding.title)


def test_shared_timezone_offset_is_one_finding() -> None:
    rng = random.Random(6)
    samples = {f"fw-{i:02d}.example": normal_samples(rng, -3 * 3600, 30) for i in range(6)}
    samples.update({f"ws-{i:02d}.example": normal_samples(rng, 20, 10) for i in range(2)})
    findings = by_kind(run(lag_samples=samples), "pipeline.clock_skew")
    assert [f.subject for f in findings] == ["clock:tz_offset:-3"]
    assert findings[0].evidence["sources_offset"] == 6


def test_same_offset_on_a_minority_of_sources_is_still_one_finding() -> None:
    rng = random.Random(14)
    samples = {f"fw-{i:02d}.example": normal_samples(rng, -3 * 3600, 30) for i in range(5)}
    samples.update({f"ws-{i:02d}.example": normal_samples(rng, 20, 10) for i in range(10)})
    findings = by_kind(run(lag_samples=samples), "pipeline.clock_skew")
    assert [f.subject for f in findings] == ["clock:tz_offset:-3"]


def test_source_clock_ahead() -> None:
    rng = random.Random(7)
    samples = {"ws-01.example": normal_samples(rng, -900, 300)}
    samples.update({f"ws-{i:02d}.example": normal_samples(rng, 20, 10) for i in range(2, 8)})
    finding = by_kind(run(lag_samples=samples), "pipeline.clock_skew")[0]
    assert finding.subject == "agent:ws-01.example"
    assert "ahead" in render(finding.title)
    assert "adelantado" in render(finding.title, "es")


def test_too_few_or_hostile_lag_samples() -> None:
    few = {"ws-01.example": [5000.0] * (LAG_MIN_SAMPLES - 1)}
    result = run(lag_samples=few)
    assert result.findings == []
    assert check(result, "ingest_lag")["status"] == "not_assessed"
    junk: list[Any] = [float("nan"), float("inf"), -float("inf"), "5000", None, True, 1e20, [1], {"a": 1}]
    hostile: dict[Any, Any] = {
        "ws-01.example": junk * 10 + [10.0] * (LAG_MIN_SAMPLES - 1),
        "": [5000.0] * 50,
        None: [5000.0] * 50,
        "ws-02.example": "not a list",
        "x" * 10_000: [5000.0] * 50,
    }
    result = run(lag_samples=hostile)
    row = check(result, "ingest_lag")
    assert row["sources_assessed"] == 1  # only the 10 000-char name had enough valid samples
    finding = by_kind(result, "pipeline.lag")[0]
    assert len(finding.evidence["agent"].value) == 256
    assert check(run(lag_samples="nope"), "ingest_lag")["status"] == "not_assessed"  # type: ignore[arg-type]


def test_many_independently_lagging_sources_are_one_finding() -> None:
    # 60 laptops late on their own (a minority of 260 sources): one grouped finding, not 60
    rng = random.Random(8)
    samples = {f"lap-{i:03d}.example": normal_samples(rng, 3000, 1500) for i in range(60)}
    samples.update({f"srv-{i:03d}.example": normal_samples(rng, 10, 5) for i in range(200)})
    findings = by_kind(run(lag_samples=samples), "pipeline.lag")
    assert [f.subject for f in findings] == ["lag:sources"]
    finding = findings[0]
    assert finding.severity is Severity.MEDIUM
    assert finding.evidence["sources_lagging"] == 60 and finding.evidence["shared_backlog"] is False
    assert len(finding.evidence["sources"]) == 50
    keys = [r.key for r in finding.reasons if isinstance(r, Message)]
    assert keys == ["pipeline.lag.reason.sources"]
    assert "60" in render(finding.title) and "260" in render(finding.title, "es")


def test_grouped_lag_never_buries_a_critical_or_late_source() -> None:
    tenant = TenantConfig(criticality={"critical": ["zz-dc*"]})
    rng = random.Random(18)
    samples = {f"lap-{i:03d}.example": normal_samples(rng, 3000 + i, 1500) for i in range(80)}
    samples["zz-dc01.example"] = normal_samples(rng, 1200, 300)  # least late of all, but critical
    samples["zz-dc02.example"] = normal_samples(rng, 5 * 3600 + 420, 300)  # beyond the 4 h critical SLA
    samples.update({f"srv-{i:03d}.example": normal_samples(rng, 10, 5) for i in range(200)})
    finding = by_kind(run(lag_samples=samples, tenant=tenant), "pipeline.lag")[0]
    assert finding.subject == "lag:sources"
    assert finding.severity is Severity.HIGH  # a source beyond its SLA
    listed = [s["agent"].value for s in finding.evidence["sources"]]
    assert listed[:2] == ["zz-dc02.example", "zz-dc01.example"]  # beyond SLA first, then critical
    assert Entity("host", "zz-dc01.example") in finding.evidence["critical_sources"]
    assert finding.evidence["sources_beyond_sla"] == [Entity("host", "zz-dc02.example")]
    text = " ".join(render(r) for r in finding.reasons)
    assert "zz-dc01.example" in text and "zz-dc02.example" in text


def test_many_sources_with_clocks_ahead_are_one_finding() -> None:
    rng = random.Random(19)
    samples = {f"ws-{i:02d}.example": normal_samples(rng, -900, 60) for i in range(6)}
    samples.update({f"srv-{i:02d}.example": normal_samples(rng, 10, 5) for i in range(20)})
    findings = by_kind(run(lag_samples=samples), "pipeline.clock_skew")
    assert [f.subject for f in findings] == ["clock:ahead:sources"]
    assert findings[0].evidence["sources_ahead"] == 6
    for lang in ("en", "es"):
        assert "{" not in render(findings[0].title, lang)
        assert all("{" not in render(r, lang) for r in findings[0].reasons)


# ---- section and rendering ------------------------------------------------------------------------------------------


def test_section_shape_agents_and_json() -> None:
    agents = [
        AgentInfo(id="000", name="wazuh-manager", status="active"),
        AgentInfo(id="001", name="ws-01.example", status="active"),
        AgentInfo(id="002", name="ws-02.example", status="disconnected"),
        AgentInfo(id="003", name="ws-03.example", status="never_connected"),
        AgentInfo(id="004", name="ws-04.example", status="x" * 100),
    ]
    stats = api_daemon_stats()
    stats["data"]["affected_items"][1]["metrics"]["eps"]["events_dropped"] = 500
    rng = random.Random(9)
    result = run(
        complete_basis(future_timestamps=40, events=1000),
        daemon_stats=stats,
        lag_samples={"ws-01.example": normal_samples(rng, 3000, 1000)},
        agents=agents,
    )
    section = result.section
    assert section["status"] == "fail"
    assert section["agents"] == {"total": 4, "active": 1, "disconnected": 1, "never_connected": 1, "unknown": 1}
    assert [c["check"] for c in section["checks"]] == [
        "input_completeness",
        "clock_skew",
        "freshness",
        "manager_daemons",
        "ingest_lag",
    ]
    assert all(c["status"] in ("ok", "warn", "fail", "not_assessed") for c in section["checks"])
    json.dumps(section, default=lambda o: o.value if isinstance(o, Entity) else str(o))
    assert result.findings[0].severity is Severity.HIGH  # sorted most severe first
    assert all(f.tenant == "default" for f in result.findings)


def test_all_findings_render_in_both_languages() -> None:
    stats = api_daemon_stats()
    stats["data"]["affected_items"][1]["metrics"]["eps"]["events_dropped"] = 9
    stats["data"]["affected_items"][1]["metrics"]["eps"]["seconds_over_limit"] = 3
    stats["data"]["affected_items"][1]["metrics"]["queues"]["alerts"]["usage"] = 0.97
    stats["data"]["affected_items"][0]["metrics"]["messages"]["received_breakdown"]["discarded"] = 2
    stats["data"]["affected_items"][0]["metrics"]["messages"]["sent_breakdown"]["discarded"] = 2
    rng = random.Random(10)
    samples = {
        "a.example": normal_samples(rng, 3000, 1000),
        "b.example": normal_samples(rng, -900, 100),
        "c.example": normal_samples(rng, 7200, 30),
        "d.example": normal_samples(rng, 1200, 20),
    }
    basis = complete_basis(
        partial_failures=["timeout"],
        truncated=True,
        bad_timestamps=900,
        malformed=500,
        future_timestamps=10,
        sampled=True,
        not_evaluated=["fields", "noise"],
        now=NOW - timedelta(days=2),
    )
    result = run(basis, daemon_stats=stats, lag_samples=samples)
    assert {f.kind for f in result.findings} == {
        "assessment.incomplete",
        "pipeline.clock_skew",
        "pipeline.manager_drops",
        "pipeline.lag",
    }
    for finding in result.findings:
        for lang in ("en", "es"):
            for msg in [finding.title, *finding.reasons, finding.recommendation]:
                text = render(msg, lang)
                assert text and "{" not in text, (finding.kind, lang, text)


def test_every_pipeline_message_has_spanish() -> None:
    keys = [k for k in i18n.keys() if k.startswith("pipeline.")]  # noqa: SIM118 (i18n.keys is a function)
    assert len(keys) > 30
    for key in keys:
        assert i18n._CATALOG[key].get("es"), key


def test_engine_style_call() -> None:
    """The engine calls analyze_pipeline(basis, tenant=, now=, daemon_stats=, lag_samples=) with a LagCollector."""
    collector = LagCollector()
    for i in range(50):
        collector.add(windows_event("ws-01.example", NOW - timedelta(minutes=i), 1000.0 + 60 * i))
    result = analyze_pipeline(
        complete_basis(), tenant=TenantConfig(), now=NOW, daemon_stats=None, lag_samples=collector.samples()
    )
    assert [f.kind for f in result.findings] == ["pipeline.lag"]


# ---- regression tests (review) --------------------------------------------------------------------------------------


def test_batching_forwarder_lag_is_not_erased_as_a_timezone() -> None:
    # a relay that ships timezone-less syslog every 30 minutes: lag uniform in [0, 30] min, median ~15 min. Read from
    # the median this looked like a quarter-hour zone and the whole backlog was subtracted (no finding at all).
    rng = random.Random(21)
    collector = LagCollector()
    for i in range(300):
        collector.add(syslog_event("srv-batch-01.example", NOW - timedelta(minutes=3 * i), rng.uniform(0, 1800), 0))
    samples = collector.samples()
    assert collector.tz_normalized == {}  # (filled by samples())
    findings = by_kind(run(lag_samples=samples), "pipeline.lag")
    assert [f.subject for f in findings] == ["agent:srv-batch-01.example"]
    # ... while a device in another zone with the same backlog is normalized by its zone only (lag still reported)
    collector = LagCollector()
    for i in range(300):
        collector.add(syslog_event("fw-edge-01.example", NOW - timedelta(minutes=3 * i), rng.uniform(5, 1800), -3))
    samples = collector.samples()
    assert collector.tz_normalized == {"fw-edge-01.example": 3.0}
    assert max(samples["fw-edge-01.example"]) < 1800
    assert [f.subject for f in by_kind(run(lag_samples=samples), "pipeline.lag")] == ["agent:fw-edge-01.example"]


def test_wazuh_api_client_shape_with_fallback_daemon_keys() -> None:
    # WazuhAPI.daemon_stats() keys items by their "name", or "daemon-<n>" when an item has none
    item = copy.deepcopy(api_daemon_stats()["data"]["affected_items"][1])
    del item["name"]
    item["metrics"]["eps"]["events_dropped"] = 7
    healths = parse_daemon_stats({"daemon-0": item, "wazuh-db": {"name": "wazuh-db", "metrics": {}}})
    assert [(h.daemon, h.dropped) for h in healths] == [("wazuh-analysisd", 7)]


def test_duplicated_daemon_items_give_one_finding() -> None:
    item = copy.deepcopy(api_daemon_stats()["data"]["affected_items"][1])
    item["metrics"]["eps"]["events_dropped"] = 5
    findings = by_kind(run(daemon_stats=[item] * 20), "pipeline.manager_drops")
    assert len(findings) == 1


def test_fingerprints_are_tenant_scoped() -> None:
    from hushwatch.models import fingerprint

    result = run(complete_basis(future_timestamps=40, events=1000), tenant=TenantConfig(name="acme"))
    assert result.findings
    for finding in result.findings:
        assert finding.tenant == "acme"
        assert finding.fingerprint == fingerprint("acme", finding.kind, finding.subject)


def test_partial_sla_override_keeps_the_default_critical_sla() -> None:
    tenant = TenantConfig(criticality={"critical": ["dc*"]}, sla={"standard": timedelta(hours=12)})
    rng = random.Random(22)
    samples = {"dc01.example": normal_samples(rng, 5 * 3600 + 420, 300)}  # 5 h late > 4 h default critical SLA
    finding = by_kind(run(lag_samples=samples, tenant=tenant), "pipeline.lag")[0]
    assert finding.severity is Severity.HIGH
