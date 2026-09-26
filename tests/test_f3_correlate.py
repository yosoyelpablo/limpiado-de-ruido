"""Tests for hushwatch.analysis.correlate.link_findings: one incident, one finding.

Synthetic findings only (``*.example`` hosts); shapes mirror what silence / coverage / pipeline emit.
"""

from __future__ import annotations

import copy
from typing import Any

import pytest

from hushwatch.analysis.correlate import link_findings
from hushwatch.i18n import Entity, M, Message, render
from hushwatch.models import Finding, Severity, iter_entities

TENANT = "acme"
SYSMON = "Microsoft-Windows-Sysmon/Operational"


def finding(kind: str, subject: str, severity: Severity, evidence: dict[str, Any], **kw: Any) -> Finding:
    domain = kind.split(".", 1)[0]
    return Finding(
        kind=kind,
        domain=domain,
        title=M(f"test.{kind}", host=evidence.get("agent") or evidence.get("host") or Entity("host", "?")),
        severity=severity,
        subject=subject,
        evidence=evidence,
        tenant=TENANT,
        **kw,
    )


def silence(kind: str, host: str, severity: Severity = Severity.HIGH, ls: str | None = None, **kw: Any) -> Finding:
    evidence: dict[str, Any] = {"level": "agent" if ls is None else "agent_log_source", "agent": Entity("host", host)}
    subject = f"agent:{host}"
    if ls is not None:
        evidence["log_source"] = ls
        subject += f"|ls:{ls}"
    return finding(kind, subject, severity, evidence, **kw)


def no_data(host: str, severity: Severity = Severity.MEDIUM) -> Finding:
    return finding("pipeline.agent_no_data", f"agent:{host}", severity, {"host": Entity("host", host)})


def disconnected(host: str, severity: Severity = Severity.HIGH) -> Finding:
    return finding("pipeline.agent_disconnected", f"agent:{host}", severity, {"host": Entity("host", host)})


def unmonitorable(host: str) -> Finding:
    return finding(
        "silence.unmonitorable", f"agent:{host}", Severity.LOW, {"level": "agent", "agent": Entity("host", host)}
    )


def contract(
    hosts: list[str], state: str = "silent", severity: Severity = Severity.HIGH, total: int | None = None
) -> Finding:
    evidence = {
        "check": "contract",
        "contract": "windows servers",
        "log_source": SYSMON,
        "state": state,
        "hosts": [Entity("host", h) for h in hosts],
        "hosts_total": total if total is not None else len(hosts),
    }
    return finding("coverage.missing_source", f"contract:windows servers|ls:{SYSMON}|state:{state}", severity, evidence)


def kinds(findings: list[Finding]) -> list[tuple[str, str]]:
    return [(f.kind, f.subject) for f in findings]


def test_tampering_explains_no_data_and_unmonitorable_on_the_same_host() -> None:
    tamper = silence("silence.tampering", "dc02.example", Severity.CRITICAL, related=["child-fp"])
    items = [no_data("dc02.example"), tamper, unmonitorable("dc02.example"), no_data("srv-09.example")]
    out = link_findings(items)
    assert kinds(out) == [
        ("silence.tampering", "agent:dc02.example"),
        ("pipeline.agent_no_data", "agent:srv-09.example"),
    ]
    keeper = out[0]
    # folded findings stay "present" for cron mode (related) and readable in the report (evidence + reasons)
    assert keeper.related == ["child-fp", items[0].fingerprint, items[2].fingerprint]
    assert keeper.evidence["explained_count"] == 2
    explained = keeper.evidence["explained"]
    assert all(isinstance(item, Message) for item in explained)
    assert {e.value for e in iter_entities(explained)} == {"dc02.example"}
    texts = [render(r) for r in keeper.reasons]
    assert any("Same incident" in t and "(Pipeline)" in t for t in texts)
    assert any("Mismo incidente" in render(r, "es") for r in keeper.reasons)


def test_input_is_not_modified_and_order_is_kept() -> None:
    items = [no_data("dc02.example"), silence("silence.silent", "dc02.example", Severity.CRITICAL)]
    before = copy.deepcopy(items)
    out = link_findings(items)
    assert items == before  # pure: the originals keep their evidence, reasons and related
    assert kinds(out) == [("silence.silent", "agent:dc02.example")]
    assert out[0] is not items[1] and out[0].fingerprint == items[1].fingerprint


def test_disconnection_is_the_more_specific_cause_of_a_silence() -> None:
    silent = silence("silence.silent", "srv-legacy-01.example", Severity.HIGH, related=["kid"])
    down = disconnected("srv-legacy-01.example", Severity.HIGH)
    out = link_findings([silent, down])
    assert kinds(out) == [("pipeline.agent_disconnected", "agent:srv-legacy-01.example")]
    assert out[0].related == [silent.fingerprint, "kid"]


def test_a_louder_silence_is_never_folded_into_a_quieter_disconnection() -> None:
    silent = silence("silence.silent", "dc01.example", Severity.CRITICAL)
    stale = disconnected("dc01.example", Severity.MEDIUM)  # e.g. a stale enrollment, one severity step lower
    out = link_findings([stale, silent])
    assert kinds(out) == [("silence.silent", "agent:dc01.example")]  # the critical one keeps its finding
    assert out[0].related == [stale.fingerprint]


def test_tampering_explains_a_disconnection() -> None:
    tamper = silence("silence.tampering", "dc02.example", Severity.CRITICAL)
    out = link_findings([disconnected("dc02.example"), tamper])
    assert kinds(out) == [("silence.tampering", "agent:dc02.example")]


def test_never_drop_a_finding_more_severe_than_its_explainer() -> None:
    drop = silence("silence.drop", "lap-01.example", Severity.LOW)
    loud = no_data("lap-01.example", Severity.HIGH)
    out = link_findings([drop, loud, unmonitorable("lap-01.example")])
    # no_data (HIGH) stays; the LOW unmonitorable note is folded into the (equally LOW) drop
    assert kinds(out) == [("silence.drop", "agent:lap-01.example"), ("pipeline.agent_no_data", "agent:lap-01.example")]


def test_channel_silence_explains_the_contract_gap_it_caused() -> None:
    sysmon = silence("silence.silent", "srv-backup-01.example", Severity.HIGH, ls=SYSMON)
    gap = contract(["srv-backup-01.example"])
    out = link_findings([gap, sysmon])
    assert kinds(out) == [("silence.silent", f"agent:srv-backup-01.example|ls:{SYSMON}")]
    assert out[0].related == [gap.fingerprint]


@pytest.mark.parametrize(
    "gap",
    [
        contract(["srv-backup-01.example"], state="missing", severity=Severity.MEDIUM),  # never seen: coverage
        contract(["srv-backup-01.example", "srv-app-02.example"]),  # a second host nothing explains
        contract(["srv-backup-01.example"], total=4),  # hosts beyond the evidence cap: not all known
    ],
)
def test_contract_gaps_not_fully_explained_by_silence_stay(gap: Finding) -> None:
    sysmon = silence("silence.silent", "srv-backup-01.example", Severity.HIGH, ls=SYSMON)
    out = link_findings([gap, sysmon])
    assert len(out) == 2 and out[1].related == []


def test_a_different_channel_does_not_explain_the_contract_gap() -> None:
    security = silence("silence.silent", "srv-backup-01.example", Severity.HIGH, ls="Security")
    out = link_findings([contract(["srv-backup-01.example"]), security])
    assert len(out) == 2


def test_whole_host_silence_explains_the_contract_gap_too() -> None:
    host = silence("silence.silent", "SRV-BACKUP-01.example", Severity.HIGH)  # host names compare case-insensitively
    out = link_findings([contract(["srv-backup-01.example"]), host])
    assert kinds(out) == [("silence.silent", "agent:SRV-BACKUP-01.example")]


def test_grouped_no_data_is_folded_only_when_every_host_is_explained() -> None:
    group = finding(
        "pipeline.agent_no_data",
        "agents:no_data|tier:standard",
        Severity.MEDIUM,
        {"hosts": [Entity("host", "a.example"), Entity("host", "b.example")], "hosts_total": 2},
    )
    only_a = [group, silence("silence.silent", "a.example")]
    assert len(link_findings(only_a)) == 2
    both = [*only_a, silence("silence.drop", "b.example", Severity.MEDIUM)]
    out = link_findings(both)
    assert ("pipeline.agent_no_data", "agents:no_data|tier:standard") not in kinds(out)
    keeper = next(f for f in out if f.subject == "agent:a.example")  # the most severe explainer
    assert group.fingerprint in keeper.related


def test_global_outage_explains_no_data_of_its_agents() -> None:
    outage = finding(
        "pipeline.global_silence",
        "global_silence",
        Severity.CRITICAL,
        {
            "level": "tenant",
            "agents": [Entity("host", "a.example"), Entity("host", "b.example")],
            "explained": [M("silence.explained.item", key="x", status="y")],
            "explained_count": 7,
        },
    )
    out = link_findings([no_data("a.example"), outage])
    assert kinds(out) == [("pipeline.global_silence", "global_silence")]
    assert out[0].evidence["explained_count"] == 8 and len(out[0].evidence["explained"]) == 2


def test_unrelated_findings_pass_through_untouched() -> None:
    items = [
        silence("silence.silent", "a.example"),
        no_data("b.example"),
        finding("noise.tune", "rule:5710|data.srcip:10.20.0.15", Severity.LOW, {}),
        silence("silence.field_lost", "a.example"),
    ]
    out = link_findings(items)
    assert out == items and all(a is b for a, b in zip(out, items, strict=True))


def test_many_folded_findings_are_summarized_in_the_reasons() -> None:
    tamper = silence("silence.tampering", "dc02.example", Severity.CRITICAL)
    extra = [
        contract(["dc02.example"], severity=Severity.HIGH),
        no_data("dc02.example"),
        unmonitorable("dc02.example"),
        disconnected("dc02.example"),
    ]
    out = link_findings([tamper, *extra])
    assert len(out) == 1 and out[0].evidence["explained_count"] == 4
    assert len(out[0].reasons) == 4  # one line per folded finding (below the MAX_REASONS cap)
