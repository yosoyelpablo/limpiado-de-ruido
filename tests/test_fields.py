"""Tests for field health (hushwatch.analysis.fields): silence.field_lost."""

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from hushwatch.analysis.fields import DETECTION_FIELDS, FieldCollector, _absent, analyze_fields
from hushwatch.config import TenantConfig
from hushwatch.i18n import Entity, Message, has, render
from hushwatch.models import Confidence, DataBasis, Event, Severity, is_empty, iter_entities

UTC = timezone.utc
START = datetime(2026, 8, 3, tzinfo=UTC)
FW = "/var/log/fw/firewall.log"
FW_HOST = "fw-edge-01.example"


def fw_event(
    ts: datetime, rng: random.Random, *, with_srcip: bool = True, extra: dict[str, Any] | None = None
) -> Event:
    fields: dict[str, Any] = {
        "timestamp": ts.isoformat(),
        "agent.name": "fw-edge-01.example",
        "location": FW,
        "decoder.name": "fw-decoder",
        "data.action": rng.choice(["allow", "deny"]),
        "data.dstip": f"198.51.100.{rng.randint(1, 250)}",
        "data.protocol": "tcp",
    }
    if with_srcip:
        fields["data.srcip"] = f"10.0.{rng.randint(0, 3)}.{rng.randint(1, 250)}"
        fields["data.srcport"] = str(rng.randint(1024, 65535))
    else:  # parser change: the fields are gone or come back empty
        fields["data.srcport"] = rng.choice(["-", "", "(NULL)", None])
    if rng.random() < 0.5:
        fields["data.url"] = "http://www.example.com/"
    if extra:
        fields.update(extra)
    return Event(ts=ts, source="fw-edge-01.example", log_source=FW, fields=fields)


def firewall_collector(
    tenant: TenantConfig, *, days: int = 28, lose_after_day: int | None = 20, per_day: int = 200, seed: int = 1
) -> FieldCollector:
    rng = random.Random(seed)
    collector = FieldCollector(tenant)
    for day in range(days):
        for i in range(per_day):
            ts = START + timedelta(days=day, seconds=(86400 / per_day) * i + rng.uniform(0, 30))
            collector.add(fw_event(ts, rng, with_srcip=lose_after_day is None or day < lose_after_day))
            # a second, healthy source keeps all its fields
            collector.add(
                Event(
                    ts=ts,
                    source="srv-web-01.example",
                    log_source="/var/log/auth.log",
                    fields={"data.srcuser": "alice", "data.srcip": "10.1.2.3", "program_name": "sshd"},
                )
            )
    return collector


def test_firewall_field_lost_after_day_20() -> None:
    tenant = TenantConfig(name="acme")
    collector = firewall_collector(tenant)
    now = START + timedelta(days=28)
    findings, section = analyze_fields(collector, tenant=tenant, now=now)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.kind == "silence.field_lost" and finding.domain == "silence"
    assert finding.subject == f"agent:{FW_HOST}|ls:{FW}|fields:data.srcip,data.srcport"
    assert finding.evidence["agent"] == Entity("host", FW_HOST)
    assert finding.severity is Severity.HIGH  # data.srcip is detection-relevant
    lost = {item["field"]: item for item in finding.evidence["fields"]}
    assert set(lost) == {"data.srcip", "data.srcport"}
    assert lost["data.srcip"]["before"] == 1.0 and lost["data.srcip"]["after"] == 0.0
    assert lost["data.srcip"]["since"] == (START + timedelta(days=20)).date().isoformat()
    assert lost["data.srcip"]["events_before"] >= 100 and lost["data.srcip"]["events_after"] >= 100
    assert "data.url" not in lost  # present ~50%: never a "lost" candidate
    assert section["status"] == "fail"
    assert section["log_sources"] == 2
    assert {row["field"] for row in section["lost"]} == {"data.srcip", "data.srcport"}
    assert all(row["hosts"] == [Entity("host", FW_HOST)] for row in section["lost"])
    assert finding.confidence is Confidence.MEDIUM
    for lang in ("en", "es"):
        assert FW_HOST in render(finding.title, lang)


def test_no_finding_while_fields_are_healthy_or_evidence_is_thin() -> None:
    tenant = TenantConfig(name="acme")
    healthy = firewall_collector(tenant, lose_after_day=None)
    findings, section = analyze_fields(healthy, tenant=tenant, now=START + timedelta(days=28))
    assert findings == [] and section["status"] == "ok"
    # the loss started less than a day's worth of events ago: below field_min_events -> no verdict yet
    thin = firewall_collector(tenant, days=21, lose_after_day=20, per_day=60)
    assert analyze_fields(thin, tenant=tenant, now=START + timedelta(days=21))[0] == []
    # a source that went silent is the cube's business, not a field loss
    silent = firewall_collector(tenant, days=20, lose_after_day=None)
    assert analyze_fields(silent, tenant=tenant, now=START + timedelta(days=28))[0] == []


def test_mid_day_transition_and_intermittent_fields() -> None:
    tenant = TenantConfig(name="acme")
    rng = random.Random(3)
    collector = FieldCollector(tenant)
    cut = START + timedelta(days=10, hours=13)
    for i in range(14 * 24 * 12):
        ts = START + timedelta(minutes=5 * i)
        collector.add(fw_event(ts, rng, with_srcip=ts < cut, extra={"data.flag": "x" if rng.random() < 0.9 else "-"}))
    findings, _ = analyze_fields(collector, tenant=tenant, now=START + timedelta(days=14))
    assert len(findings) == 1
    fields = {item["field"]: item for item in findings[0].evidence["fields"]}
    assert set(fields) == {"data.srcip", "data.srcport"}  # data.flag is 90% present: below the 95% threshold
    # the field vanished mid-day on day 10: that is the date of the loss (not the next day), and the finding says
    # exactly when the field was last seen (the last event before the cut)
    assert fields["data.srcip"]["since"] == (START + timedelta(days=10)).date().isoformat()
    last_seen = datetime.fromisoformat(fields["data.srcip"]["last_seen"].replace("Z", "+00:00"))
    assert cut - timedelta(minutes=5) <= last_seen < cut
    assert findings[0].evidence["last_seen"] == fields["data.srcip"]["last_seen"]
    assert findings[0].evidence["reproduce"]["from"] == fields["data.srcip"]["last_seen"]
    assert "last seen 2026-08-13T12:5" in render(findings[0].reasons[0], "en")


def test_empty_values_count_as_absent_and_fast_path_matches_is_empty() -> None:
    samples: list[Any] = [
        None,
        "",
        " ",
        "-",
        " - ",
        "null",
        "NULL",
        "(NULL)",
        "None",
        "N/A",
        "n/a",
        "unknown",
        "Unknown",
        "0",
        0,
        0.0,
        False,
        True,
        [],
        [None],
        {},
        {"a": 1},
        (),
        set(),
        "x",
        "\x00",
        "\t\n",
        "a ",
        b"",
    ]
    for value in samples:
        assert _absent(value) == is_empty(value), repr(value)


def test_local_days_follow_the_tenant_timezone() -> None:
    tenant = TenantConfig(name="acme", timezone="America/Santiago")
    collector = FieldCollector(tenant)
    ts = datetime(2026, 9, 1, 2, 30, tzinfo=UTC)  # still Aug 31 in Santiago
    collector.add(Event(ts=ts, log_source="Security", fields={"data.win.system.eventID": "4624"}))
    presence = collector.presence("Security", "data.win.system.eventID")
    assert list(presence) == [datetime(2026, 8, 31).date()]
    assert presence[datetime(2026, 8, 31).date()] == (1, 1)
    assert collector.presence("nope", "x") == {}
    assert collector.fields("Security") == ["data.win.system.eventID"]


def test_skips_events_without_log_source_fields_or_time() -> None:
    tenant = TenantConfig(name="acme")
    collector = FieldCollector(tenant)
    collector.add(Event(ts=START, log_source=None, fields={"a": 1}))
    collector.add(Event(ts=START, log_source="x", fields={}))
    collector.add(Event(ts="soon", log_source="x", fields={"a": 1}))  # type: ignore[arg-type]
    collector.add(Event(ts=datetime(2026, 8, 3), log_source="x", fields={"a": 1}))  # naive: UTC
    assert collector.skipped == 3 and collector.events == 1


def test_bounded_memory_with_hostile_documents() -> None:
    tenant = TenantConfig(name="acme")
    collector = FieldCollector(tenant, max_fields_per_source=20, max_sources=3, max_fields_per_event=50)
    rng = random.Random(5)
    for i in range(3000):
        ts = START + timedelta(minutes=i)
        # a stable field plus attacker-chosen dynamic keys (never repeated) and a huge key
        fields: dict[Any, Any] = {"data.srcip": "10.0.0.1", ("Z" * 10_000) + str(i % 3): "v"}
        for j in range(100):
            fields[f"data.dyn_{rng.getrandbits(40)}_{j}"] = "x"
        fields[12345] = "numeric key"
        collector.add(Event(ts=ts, log_source="/var/log/app.log", fields=fields))
    for name in ("a", "b", "c", "d"):
        collector.add(Event(ts=START, log_source=name * 1000, fields={"x": 1}))
    assert len(collector.log_sources()) == 3
    assert collector.truncated
    tracked = collector.fields("/var/log/app.log")
    assert len(tracked) <= 20
    assert "data.srcip" in tracked
    assert all(len(name) <= 200 for name in tracked)
    _, section = analyze_fields(collector, tenant=tenant, now=START + timedelta(days=3))
    assert section["truncated"] is True


def test_merge_matches_single_pass() -> None:
    tenant = TenantConfig(name="acme")
    rng = random.Random(8)
    events = [fw_event(START + timedelta(hours=i), rng, with_srcip=i < 500) for i in range(28 * 24)]
    whole = FieldCollector(tenant)
    left, right = FieldCollector(tenant), FieldCollector(tenant)
    for i, item in enumerate(events):
        whole.add(item)
        (left if i < 300 else right).add(item)
    left.merge(right)
    assert left.log_sources() == whole.log_sources()
    for field_name in whole.fields(FW):
        assert left.presence(FW, field_name) == whole.presence(FW, field_name)
    now = START + timedelta(days=28)
    assert [f.subject for f in analyze_fields(left, tenant=tenant, now=now)[0]] == [
        f.subject for f in analyze_fields(whole, tenant=tenant, now=now)[0]
    ]


def test_alerts_only_confidence_severity_and_i18n() -> None:
    tenant = TenantConfig(name="acme")
    rng = random.Random(2)
    collector = FieldCollector(tenant)
    for day in range(20):
        for i in range(150):
            ts = START + timedelta(days=day, minutes=9 * i)
            fields = {"data.custom_tag": "abc" if day < 14 else "-", "program_name": "app"}
            collector.add(Event(ts=ts, log_source="/var/log/app.log", fields=fields))
    findings, _ = analyze_fields(
        collector, tenant=tenant, now=START + timedelta(days=20), basis=DataBasis(input_kind="alerts")
    )
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity is Severity.MEDIUM  # not a detection-relevant field
    assert "data.custom_tag" not in DETECTION_FIELDS
    assert finding.confidence is Confidence.LOW
    assert any(isinstance(r, Message) and r.key == "silence.field.alerts_only" for r in finding.reasons)
    for part in [finding.title, finding.recommendation, *finding.reasons]:
        if isinstance(part, Message):
            assert has(part.key)
        for lang in ("en", "es"):
            text = render(part, lang)
            assert text and "{" not in text
    assert "desapareció" in render(finding.title, "es")
    assert finding.subject == "ls:/var/log/app.log|field:data.custom_tag"  # no host on these events
    del rng


def test_sender_mix_change_is_flagged_with_low_confidence() -> None:
    tenant = TenantConfig(name="acme")
    collector = FieldCollector(tenant)
    for day in range(16):
        # the big sender (with the field) goes silent after day 10; a small sender without it remains
        if day < 10:
            for i in range(600):
                ts = START + timedelta(days=day, seconds=140 * i)
                collector.add(Event(ts=ts, log_source="/var/log/app.log", fields={"data.tx": "1", "host": "a"}))
        for i in range(25):
            ts = START + timedelta(days=day, hours=i * 0.9)
            collector.add(Event(ts=ts, log_source="/var/log/app.log", fields={"host": "b"}))
    findings, _ = analyze_fields(collector, tenant=tenant, now=START + timedelta(days=16))
    assert len(findings) == 1
    assert findings[0].confidence is Confidence.LOW
    assert findings[0].evidence["volume_ratio"] < 0.5
    assert any(isinstance(r, Message) and r.key == "silence.field.mix_change" for r in findings[0].reasons)


def test_many_lost_fields_are_one_finding() -> None:
    tenant = TenantConfig(name="acme")
    collector = FieldCollector(tenant)
    names = [f"data.f{i:02d}" for i in range(12)]
    for day in range(16):
        for i in range(120):
            ts = START + timedelta(days=day, minutes=11 * i)
            fields = {name: ("v" if day < 10 else None) for name in names}
            fields["data.keep"] = "y"
            collector.add(Event(ts=ts, log_source="parser-x", fields=fields))
    findings, section = analyze_fields(collector, tenant=tenant, now=START + timedelta(days=16))
    assert len(findings) == 1
    assert findings[0].evidence["fields_lost"] == 12
    assert findings[0].subject.startswith("ls:parser-x|fields:data.f00,data.f01,")
    assert "+2#" in findings[0].subject
    assert "+7" in render(findings[0].title, "en")
    assert len(section["lost"]) == 12


def syslog_world(
    tenant: TenantConfig, *, upgraded: set[str], lost: str = "data.dstport", days: int = 21, upgrade_day: int = 14
) -> FieldCollector:
    """Ten syslog devices relayed by the manager (agent 000): log_source "syslog", host = predecoder.hostname."""
    rng = random.Random(11)
    collector = FieldCollector(tenant)
    devices = [f"fw-edge-{i:02d}.example" for i in range(1, 11)]
    for day in range(days):
        for i in range(160):
            ts = START + timedelta(days=day, seconds=540 * i)
            for device in devices:
                fields: dict[str, Any] = {
                    "agent.id": "000",
                    "predecoder.hostname": device,
                    "location": "syslog",
                    "data.srcip": f"10.9.{rng.randint(0, 9)}.{rng.randint(1, 250)}",
                    "data.dstip": f"203.0.113.{rng.randint(1, 250)}",
                    "data.dstport": str(rng.choice([443, 53, 22])),
                    "data.action": "deny",
                }
                if device in upgraded and day >= upgrade_day:
                    del fields[lost]  # the new firmware's log format no longer carries it
                collector.add(Event(ts=ts, source=device, log_source="syslog", fields=fields))
    return collector


def test_one_syslog_device_losing_a_field_is_named() -> None:
    """Regression (demo scenario k): fw-edge-01 loses data.dstport after a firmware upgrade; 9 siblings are fine."""
    tenant = TenantConfig(name="acme", criticality={"critical": ["fw-*"]})
    collector = syslog_world(tenant, upgraded={"fw-edge-01.example"})
    findings, section = analyze_fields(collector, tenant=tenant, now=START + timedelta(days=21))
    assert [f.subject for f in findings] == ["agent:fw-edge-01.example|ls:syslog|field:data.dstport"]
    finding = findings[0]
    assert finding.evidence["agent"] == Entity("host", "fw-edge-01.example")
    assert [item["field"] for item in finding.evidence["fields"]] == ["data.dstport"]
    assert finding.evidence["fields"][0]["since"] == (START + timedelta(days=14)).date().isoformat()
    assert finding.severity is Severity.HIGH
    assert Entity("host", "fw-edge-01.example") in list(iter_entities(finding.title))
    for lang in ("en", "es"):
        assert "fw-edge-01.example" in render(finding.title, lang)
    assert section["lost"][0]["hosts"] == [Entity("host", "fw-edge-01.example")]
    # the log source as a whole still carries the field 90% of the time: only per-host keys can see this
    assert collector.presence("syslog", "data.dstport")[(START + timedelta(days=20)).date()][0] > 0
    assert collector.hosts("syslog") == [f"fw-edge-{i:02d}.example" for i in range(1, 11)]


def test_a_field_lost_on_many_hosts_is_one_log_source_finding() -> None:
    tenant = TenantConfig(name="acme")
    everyone = {f"fw-edge-{i:02d}.example" for i in range(1, 11)}
    collector = syslog_world(tenant, upgraded=everyone)  # e.g. a decoder change on the manager
    findings, _ = analyze_fields(collector, tenant=tenant, now=START + timedelta(days=21))
    assert [f.subject for f in findings] == ["ls:syslog|field:data.dstport"]
    finding = findings[0]
    assert finding.evidence["hosts_affected"] == 10
    assert set(finding.evidence["hosts"]) == {Entity("host", h) for h in everyone}
    assert any(isinstance(r, Message) and r.key == "silence.field.hosts" for r in finding.reasons)
    # two devices upgraded: still one finding (grouped), naming both
    two = syslog_world(tenant, upgraded={"fw-edge-03.example", "fw-edge-07.example"})
    findings, _ = analyze_fields(two, tenant=tenant, now=START + timedelta(days=21))
    assert [f.subject for f in findings] == ["ls:syslog|field:data.dstport"]
    assert findings[0].evidence["hosts"] == [Entity("host", "fw-edge-03.example"), Entity("host", "fw-edge-07.example")]


def test_host_key_cap_pools_the_rest_and_reports_truncation() -> None:
    tenant = TenantConfig(name="acme")
    collector = FieldCollector(tenant, max_keys=3)
    for i in range(10):
        collector.add(Event(ts=START, source=f"h{i}.example", log_source="syslog", fields={"data.srcip": "10.0.0.1"}))
    assert collector.truncated and collector.overflow_events == 7
    assert collector.hosts("syslog") == ["h0.example", "h1.example", "h2.example"]
    assert collector.presence("syslog", "data.srcip")[START.date()] == (10, 10)


def test_bounded_history_keeps_the_most_recent_days() -> None:
    tenant = TenantConfig(name="acme")
    collector = FieldCollector(tenant)
    assert collector.max_days == 2 * (14 + 3)
    for day in range(60):
        collector.add(Event(ts=START + timedelta(days=day), source="h.example", log_source="x", fields={"a": 1}))
    kept = collector.presence("x", "a")
    assert len(kept) == collector.max_days
    assert min(kept) == (START + timedelta(days=60 - collector.max_days)).date()
    # a late event for a forgotten day is dropped (counted), never re-grows the history
    collector.add(Event(ts=START, source="h.example", log_source="x", fields={"a": 1}))
    assert len(collector.presence("x", "a")) == collector.max_days


def test_empty_collector() -> None:
    tenant = TenantConfig(name="acme")
    findings, section = analyze_fields(FieldCollector(tenant), tenant=tenant, now=datetime(2026, 9, 1))
    assert findings == [] and section["status"] == "not_assessed"
    with pytest.raises(ValueError):
        FieldCollector(tenant, max_fields_per_source=0)


def test_forged_far_future_dates_cannot_push_the_baseline_out() -> None:
    """A few events with forged dates (a spoofed or skewed device) used to evict the oldest real days, silently
    losing the baseline: the field loss went unreported and the section said nothing was truncated."""
    tenant = TenantConfig(name="acme")
    rng = random.Random(1)
    collector = FieldCollector(tenant)
    for day in range(28):
        for i in range(200):
            ts = START + timedelta(days=day, seconds=(86400 / 200) * i)
            collector.add(fw_event(ts, rng, with_srcip=day < 20))
            if day == 25 and i < 40:
                collector.add(fw_event(START + timedelta(days=400 + i), rng))
    findings, section = analyze_fields(collector, tenant=tenant, now=START + timedelta(days=28))
    assert [f.kind for f in findings] == ["silence.field_lost"]
    assert section["dropped_days"] > 0
    # heavy forged days that push real history out are reported as truncation instead of a silent gap
    heavy = FieldCollector(tenant)
    for day in range(28):
        for i in range(50):
            heavy.add(fw_event(START + timedelta(days=day, seconds=1700 * i), rng))
    for j in range(40):
        for i in range(50):
            heavy.add(fw_event(START + timedelta(days=500 + j, seconds=1700 * i), rng))
    assert analyze_fields(heavy, tenant=tenant, now=START + timedelta(days=28))[1]["truncated"] is True


def test_field_subjects_escape_separators() -> None:
    tenant = TenantConfig(name="acme")
    collector = FieldCollector(tenant)
    for day in range(28):
        for i in range(120):
            fields = {"data.x|ls:Security": "1", "data.a,b": "2", "keep": "3"} if day < 20 else {"keep": "3"}
            collector.add(
                Event(ts=START + timedelta(days=day, seconds=600 * i), source="h|1", log_source="app", fields=fields)
            )
    findings, _ = analyze_fields(collector, tenant=tenant, now=START + timedelta(days=28))
    assert [f.subject for f in findings] == ["agent:h%7C1|ls:app|fields:data.a%2Cb,data.x%7Cls:Security"]
