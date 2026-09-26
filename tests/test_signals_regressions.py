"""Regression tests for silence, coverage, field health and pipeline.

Synthetic data only (``*.example`` hosts, RFC 1918 / 5737 addresses).
"""

from __future__ import annotations

import math
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from hushwatch.analysis import silence as silence_mod
from hushwatch.analysis.coverage import CoverageCollector, analyze_coverage
from hushwatch.analysis.cube import CubeCollector
from hushwatch.analysis.pipeline import analyze_pipeline
from hushwatch.analysis.silence import analyze_silence
from hushwatch.config import Expectation, InputConfig, TenantConfig
from hushwatch.i18n import Entity, Message, render
from hushwatch.ingest import files as _files  # noqa: F401  (registers the ingest messages used below)
from hushwatch.models import DataBasis, Event, Finding, Severity

UTC = timezone.utc
MONDAY = datetime(2026, 8, 3, tzinfo=UTC)
SYSMON = "Microsoft-Windows-Sysmon/Operational"
ARCHIVES = DataBasis(input_kind="archives", profile="wazuh4", events=1)


# ---- silence helpers ---------------------------------------------------------------------------------------------


class Hours:
    """Explicit hourly counts per (agent, log source), rolled up into a cube like the ingest path does."""

    def __init__(self, tenant: TenantConfig, days: int) -> None:
        self.tenant = tenant
        self.start_h = int(MONDAY.timestamp() // 3600)
        self.hours = days * 24
        self.series: dict[tuple[str, str], list[int]] = {}

    def add(self, agent: str, ls: str, per_hour: dict[int, int] | None = None, *, daily: dict[int, int] | None = None,
            until_day: int | None = None, from_hour: int = 0) -> None:  # fmt: skip
        """``daily`` = {hour of day: count} repeated every day (until ``until_day``); ``per_hour`` = absolute hours."""
        counts = self.series.setdefault((agent, ls), [0] * self.hours)
        if daily:
            for h in range(from_hour, self.hours):
                if until_day is not None and h // 24 >= until_day:
                    break
                counts[h] += daily.get(h % 24, 0)
        for h, c in (per_hour or {}).items():
            counts[h] += c

    def build(self) -> CubeCollector:
        cube = CubeCollector(self.tenant)
        for (agent, ls), counts in sorted(self.series.items()):
            for h, c in enumerate(counts):
                for i in range(c):  # spread evenly inside the hour, like real traffic
                    ts = datetime.fromtimestamp((self.start_h + h) * 3600 + (i + 0.5) * 3600 / c, UTC)
                    cube.add(Event(ts=ts, source=agent, log_source=ls, rule_id="5501"))
        return cube

    def at(self, hour: float) -> datetime:
        return datetime.fromtimestamp((self.start_h + hour) * 3600, UTC)


def background(world: Hours, n: int = 6) -> None:
    for i in range(n):
        world.add(f"srv-{i:02d}.example", "Security", daily={h: 6 + (h * 7 + i) % 5 for h in range(24)})


def silence_run(world: Hours, now: datetime, **kw: Any) -> silence_mod.SilenceResult:
    return analyze_silence(world.build(), tenant=world.tenant, now=now, basis=kw.pop("basis", ARCHIVES), **kw)


def of_kind(findings: list[Finding], kind: str) -> list[Finding]:
    return [f for f in findings if f.kind == kind]


# ---- decay is about volume through "now", and a silent child explains its parent --------------------------------


def _mail_and_vpn(tenant: TenantConfig) -> tuple[Hours, datetime]:
    """A generic-CSV case: mail-01 sends 5/day and stops 4 days before the end; vpn-01 sends nothing
    until a burst of 80 events in the last 20 hours (the current, partial day)."""
    world = Hours(tenant, days=21)
    background(world)
    world.add("mail-01.example", "linux_secure", daily={1: 1, 5: 1, 9: 1, 13: 1, 17: 1}, until_day=17)
    last = world.hours - 1
    world.add("vpn-01.example", "linux_secure", {h: 4 for h in range(last - 20, last)})
    return world, world.at(world.hours - 1 + 40 / 60)  # data ends at 23:40 of the last day


def test_decay_counts_the_partial_current_day_so_a_resumed_source_is_not_declining() -> None:
    world, now = _mail_and_vpn(TenantConfig(name="acme"))
    result = silence_run(world, now)
    decay = [f for f in of_kind(result.findings, "silence.decay") if "linux_secure" in f.subject]
    assert decay == [], [(f.subject, render(f.title)) for f in decay]
    silent = of_kind(result.findings, "silence.silent")
    assert [f.subject for f in silent] == ["agent:mail-01.example"]


def test_without_the_partial_day_the_same_data_would_claim_a_decay(monkeypatch: pytest.MonkeyPatch) -> None:
    # guards the regression test above: the scenario really is the reported one (a false "fell to 0%")
    monkeypatch.setattr(silence_mod._Engine, "_partial_day", lambda self, p1, last_day: None)
    world, now = _mail_and_vpn(TenantConfig(name="acme"))
    result = silence_run(world, now)
    assert any("linux_secure" in f.subject for f in of_kind(result.findings, "silence.decay"))


def test_decay_numbers_are_sums_over_the_claimed_span() -> None:
    tenant = TenantConfig(name="acme")
    world = Hours(tenant, days=28)
    background(world)
    # a source that loses 80% of its volume for the last 6 days (never silent: it still trickles)
    world.add("app-01.example", "app", daily={h: 10 for h in range(8, 20)}, until_day=22)
    world.add("app-01.example", "app", daily={h: 2 for h in range(8, 20)}, from_hour=22 * 24)
    result = silence_run(world, world.at(world.hours - 0.5))
    found = [f for f in result.findings if f.kind in ("silence.decay", "silence.drop") and "app" in f.subject]
    assert found, [(f.kind, f.subject) for f in result.findings]
    decay = [f for f in found if f.kind == "silence.decay"]
    for f in decay:
        ev = f.evidence
        assert ev["observed"] == ev["decay"]["observed"] and ev["expected"] == ev["decay"]["expected"]
        assert math.isclose(ev["ratio"], ev["observed"] / ev["expected"], rel_tol=1e-6)
        assert "recent_median" not in ev["decay"]  # the claim is never a median of a few days
        text = render(f.reasons[0])
        assert f"{round(ev['observed'])} events" in text


def test_log_source_decay_is_explained_by_its_silent_host() -> None:
    tenant = TenantConfig(name="acme")
    world = Hours(tenant, days=28)
    background(world)
    # mail-01 carries 80% of linux_secure and went silent 5 days ago; web-01 keeps its 20%
    world.add("mail-01.example", "linux_secure", daily={h: 2 for h in range(6, 22)}, until_day=23)
    world.add("web-01.example", "linux_secure", daily={h: 1 for h in range(9, 17)})
    result = silence_run(world, world.at(world.hours - 0.5))
    subjects = {f.subject: f for f in result.findings if f.domain in ("silence", "pipeline")}
    assert "ls:linux_secure" not in subjects, sorted(subjects)
    mail = subjects["agent:mail-01.example"]
    assert mail.kind == "silence.silent"
    items = mail.evidence.get("explained", [])
    assert items and all(isinstance(item, Message) for item in items)
    assert any("log source linux_secure" in render(item) for item in items)


def test_explained_evidence_is_readable_in_both_languages() -> None:
    world, now = _mail_and_vpn(TenantConfig(name="acme"))
    result = silence_run(world, now)
    mail = next(f for f in result.findings if f.subject == "agent:mail-01.example")
    item = mail.evidence["explained"][0]
    assert render(item) == "linux_secure on mail-01.example (silent)"
    assert render(item, "es") == "linux_secure en mail-01.example: en silencio"


# ---- learning is LOW everywhere --------------------------------------------------------------------------------


def test_nothing_evaluable_is_a_low_learning_finding_and_the_section_stays_grey() -> None:
    tenant = TenantConfig(name="acme")
    world = Hours(tenant, days=3)
    background(world)
    result = silence_run(world, world.at(world.hours - 0.5))
    learning = of_kind(result.findings, "assessment.learning")
    assert len(learning) == 1 and learning[0].severity is Severity.LOW
    assert result.section["status"] == "not_assessed"


# ---- reproduce hints use the input's own field names ----------------------------------------------------------


def _generic_hint(tenant: TenantConfig) -> tuple[str, dict[str, Any]]:
    world = Hours(tenant, days=21)
    background(world)
    world.add("mail-01.example", "linux_secure", daily={h: 3 for h in range(24)}, until_day=19)
    basis = DataBasis(input_kind="unknown", profile="generic", events=1)
    result = silence_run(world, world.at(world.hours - 0.5), basis=basis)
    mail = next(f for f in result.findings if f.subject == "agent:mail-01.example")
    return render(mail.recommendation), mail.evidence["reproduce"]["filter"]


def test_generic_reproduce_hint_uses_the_mapped_column() -> None:
    mapping = {"rule_id": "signature", "source": "host", "log_source": "sourcetype"}
    tenant = TenantConfig(name="acme", inputs=[InputConfig(path="x.csv", profile="generic", mapping=mapping)])
    text, filt = _generic_hint(tenant)
    assert 'host:"mail-01.example"' in text and "source:" not in text
    assert list(filt) == ["host"]


def test_generic_reproduce_hint_without_a_mapping_describes_instead_of_guessing() -> None:
    text, filt = _generic_hint(TenantConfig(name="acme"))
    assert list(filt) == ["host"]
    assert 'the events of host "mail-01.example"' in text
    assert 'source:"' not in text


# ---- Wazuh wording only for Wazuh input -----------------------------------------------------------------------


def test_global_silence_advice_names_wazuh_daemons_only_for_wazuh_data() -> None:
    tenant = TenantConfig(name="acme")
    world = Hours(tenant, days=21)
    for i in range(8):
        world.add(f"srv-{i:02d}.example", "Security", daily={h: 8 for h in range(24)}, until_day=20)
    for profile, wazuh in (("wazuh4", True), ("ecs", False), ("generic", False)):
        basis = DataBasis(input_kind="archives", profile=profile, events=1)
        result = silence_run(world, world.at(world.hours - 0.5), basis=basis)
        outage = of_kind(result.findings, "pipeline.global_silence")
        assert len(outage) == 1, profile
        text = render(outage[0].recommendation)
        assert ("remoted" in text) is wazuh and ("Filebeat" in text) is wazuh, (profile, text)


def _pipeline(profile: str, **kw: Any) -> dict[str, Any]:
    basis = DataBasis(input_kind="alerts", profile=profile, events=100, now=MONDAY, end=MONDAY, start=MONDAY)
    return analyze_pipeline(basis, tenant=TenantConfig(name="acme"), now=MONDAY, **kw).section


def test_manager_daemons_check_is_only_listed_for_wazuh() -> None:
    assert "manager_daemons" in {c["check"] for c in _pipeline("wazuh4")["checks"]}
    for profile in ("ecs", "generic"):
        assert "manager_daemons" not in {c["check"] for c in _pipeline(profile)["checks"]}, profile
    # stats supplied explicitly are always shown (whatever the profile)
    assert "manager_daemons" in {c["check"] for c in _pipeline("ecs", daemon_stats={})["checks"]}


def test_shared_ingest_backlog_advice_is_generic_outside_wazuh() -> None:
    samples = {f"host-{i:02d}.example": [1800.0 + i] * 40 for i in range(6)}
    for profile, wazuh in (("wazuh4", True), ("ecs", False)):
        basis = DataBasis(input_kind="archives", profile=profile, events=100, now=MONDAY)
        result = analyze_pipeline(basis, tenant=TenantConfig(name="acme"), now=MONDAY, lag_samples=samples)
        lag = [f for f in result.findings if f.kind == "pipeline.lag"]
        assert lag, profile
        text = render(lag[0].reasons[0])
        assert ("Filebeat" in text) is wazuh, (profile, text)


def test_partial_failure_messages_are_rendered_per_language() -> None:
    from hushwatch.i18n import M

    failure = M("ingest.failure", file=Entity("file", "/data/a.json"), reason=M("ingest.reason.permission"))
    basis = DataBasis(input_kind="alerts", profile="wazuh4", events=10, now=MONDAY, partial_failures=[failure, "raw"])
    result = analyze_pipeline(basis, tenant=TenantConfig(name="acme"), now=MONDAY)
    incomplete = next(f for f in result.findings if f.kind == "assessment.incomplete")
    assert "/data/a.json: permission denied; raw" in render(incomplete.reasons[0])
    assert "permiso denegado" in render(incomplete.reasons[0], "es")
    assert incomplete.evidence["partial_failure_examples"][0] is failure


# ---- coverage: never a false green, relayed hosts report, not assessed per row ----------------


def _host_events(host: str, start: datetime, end: datetime, sources: tuple[str, ...], step_h: float = 1.0,
                 platform: str = "windows", **kw: Any) -> list[Event]:  # fmt: skip
    out = []
    ts = start
    while ts < end:
        for ls in sources:
            out.append(Event(ts=ts, source=host, log_source=ls, os_platform=platform, rule_id="60106", **kw))
        ts += timedelta(hours=step_h)
    return out


def _coverage(events: list[Event], tenant: TenantConfig, now: datetime) -> dict[str, Any]:
    collector = CoverageCollector(tenant)
    for event in events:
        collector.add(event)
    basis = DataBasis(input_kind="archives", profile="wazuh4", events=len(events))
    return analyze_coverage(collector, tenant=tenant, now=now, basis=basis).section


def test_coverage_on_a_few_hours_of_data_is_not_assessed_even_without_findings() -> None:
    names = [f"ws-{i:02d}.example" for i in range(8)]
    start = MONDAY
    end = MONDAY + timedelta(hours=6)
    events = [e for n in names for e in _host_events(n, start, end, ("Security", SYSMON), step_h=2.0)]
    events += _host_events("ws-99.example", start, end, ("Security",), step_h=2.0)  # lacks Sysmon: unjudgeable
    section = _coverage(events, TenantConfig(name="acme"), end)
    assert section["status"] == "not_assessed", section["status_reasons"]
    assert "short_history" in section["status_reasons"] and section["history_days"] < 1
    row = next(r for r in section["expected_sources"] if r["basis"] == "peers" and r["log_source"] == SYSMON)
    assert row["not_assessed"] == 1 and row["missing"] == 0  # the unjudged host is visible, not hidden


def test_coverage_with_unjudged_gaps_is_warn_never_ok() -> None:
    names = [f"ws-{i:02d}.example" for i in range(8)]
    start = MONDAY
    end = MONDAY + timedelta(days=10)
    events = [e for n in names for e in _host_events(n, start, end, ("Security", SYSMON), step_h=6.0)]
    # a host that appeared an hour ago without Sysmon: too little data to call it a gap
    events += _host_events("ws-new.example", end - timedelta(hours=1), end, ("Security",), step_h=0.5)
    section = _coverage(events, TenantConfig(name="acme"), end)
    assert section["status"] == "warn" and section["status_reasons"] == ["gaps_not_assessed"]
    assert section["gaps_not_assessed"] >= 1


def test_coverage_with_enough_history_and_nothing_open_is_ok() -> None:
    names = [f"ws-{i:02d}.example" for i in range(8)]
    end = MONDAY + timedelta(days=10)
    events = [e for n in names for e in _host_events(n, MONDAY, end, ("Security", SYSMON), step_h=6.0)]
    section = _coverage(events, TenantConfig(name="acme"), end)
    assert section["status"] == "ok" and section["status_reasons"] == []


def test_relayed_syslog_devices_count_as_reporting() -> None:
    end = MONDAY + timedelta(days=10)
    events = [e for i in range(6) for e in _host_events(f"ws-{i:02d}.example", MONDAY, end, ("Security",), 6.0)]
    fw = [
        Event(
            ts=MONDAY + timedelta(hours=h),
            source="fw-edge-01.example",
            log_source="syslog",
            os_platform="network",
            rule_id="4101",
            fields={"agent.id": "000", "agent.name": "wazuh-manager", "predecoder.hostname": "fw-edge-01.example"},
        )
        for h in range(0, 240, 2)
    ]
    section = _coverage(events + fw, TenantConfig(name="acme"), end)
    network = section["platforms"]["network"]
    assert network["hosts"] == 1 and network["reporting"] == 1 and network["peer_comparable"] == 0
    assert network["peer_group"] is False
    windows = section["platforms"]["windows"]
    assert windows["reporting"] == windows["peer_comparable"] == 6


def test_contract_rows_carry_not_assessed_first_and_name_the_unjudged_hosts() -> None:
    end = MONDAY + timedelta(days=10)
    contract = Expectation(name="dcs", match={"platform": "windows", "name": "dc*"}, log_sources=["Security", SYSMON])
    tenant = TenantConfig(name="acme", expectations=[contract])
    events = _host_events("dc01.example", MONDAY, end, ("Security", SYSMON), 1.0)
    # dc02 went quiet two days ago (silence owns it): the contract cannot judge it
    events += _host_events("dc02.example", MONDAY, end - timedelta(days=2), ("Security", SYSMON), 1.0)
    section = _coverage(events, tenant, end)
    rows = [r for r in section["expected_sources"] if r["basis"] == "contract"]
    assert rows and all(r["matched"] == 2 and r["present"] == 1 and r["not_assessed"] == 1 for r in rows)
    first_eight = list(rows[0])[:8]  # renderers show the first columns: every state is among them
    assert first_eight == ["basis", "name", "log_source", "matched", "present", "missing", "silent", "not_assessed"]
    assert [e.value for e in rows[0]["not_assessed_hosts"]] == ["dc02.example"]
