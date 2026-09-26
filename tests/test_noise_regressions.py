"""Regression tests for the noise engine and the Wazuh ruleset/emitter/audit.

Synthetic data only (RFC 5737 / RFC 1918 addresses, *.example hosts).
"""

from __future__ import annotations

import json
import random
from collections.abc import Iterator
from datetime import date, timedelta
from pathlib import Path
from typing import Any

import pytest
from test_noise import (
    END,
    FIM,
    FW_DROP,
    SSHD_BRUTE,
    SSHD_INVALID,
    START,
    TASK,
    TENANT,
    Rule,
    alert,
    every,
    finding_for,
    human_background,
    run,
    service_automation,
    tune,
    with_value,
)

from hushwatch import i18n
from hushwatch.analysis import gates as g
from hushwatch.analysis.dispositions import Dispositions
from hushwatch.analysis.noise import NoiseCollector, analyze_noise, apply_backtest
from hushwatch.analysis.sketches import SpaceSaving
from hushwatch.config import TenantConfig
from hushwatch.i18n import Entity, Message
from hushwatch.models import Event, Finding, Severity, fingerprint
from hushwatch.net import RemoteError
from hushwatch.tuning import Condition, Suggestion
from hushwatch.wazuh.audit import audit_ruleset
from hushwatch.wazuh.emitter import SPEC_FILE, VALIDATION_FILE, EmitError, emit_suppressions
from hushwatch.wazuh.ruleset import DependentIds, Ruleset, load_ruleset, parse_rules_text

FIXTURES = Path(__file__).parent / "fixtures" / "wazuh"
STOCK = FIXTURES / "ruleset" / "rules"
LOCAL = FIXTURES / "etc" / "rules"
NOW = date(2026, 9, 25)
EXPIRES = date(2026, 12, 24)


def text(msg: Message | str | None, lang: str = "en") -> str:
    return i18n.render(msg, lang)


def keys(finding: Finding) -> list[str]:
    return [r.key for r in finding.reasons if isinstance(r, Message)]


def noise_findings(result: Any, kind: str) -> list[Finding]:
    return [f for f in result.findings if f.kind == kind]


def sug(rule_id: str, *conditions: tuple[str, str], **kwargs: Any) -> Suggestion:
    params: dict[str, Any] = {"verdict": "tune", "fingerprint": "f2fp0001", "expires": EXPIRES}
    params.update(kwargs)
    return Suggestion(rule_id=rule_id, conditions=tuple(Condition(f, v) for f, v in conditions), **params)


def emit(tmp_path: Path, suggestions: list[Suggestion], ruleset: Ruleset | None, **kwargs: Any) -> Any:
    params: dict[str, Any] = {"ruleset": ruleset, "id_range": (110000, 119999), "out_dir": tmp_path / "out", "now": NOW}
    params.update(kwargs)
    return emit_suppressions(suggestions, **params)


# ---- a ruleset without stock rules cannot verify correlation -----------------------------------------------------
def test_local_only_ruleset_marks_dependents_unverified() -> None:
    local_only = load_ruleset([LOCAL])
    assert local_only.rules and not local_only.has_stock
    deps = local_only.dependents("5710")
    assert isinstance(deps, DependentIds) and deps.verified is False
    full = load_ruleset([STOCK, LOCAL])
    assert full.has_stock and full.dependents("5710").verified is True
    assert full.dependents("5710") == ("5712", "60204")  # still a plain tuple of ids


def test_noise_requires_review_when_correlation_is_not_verified() -> None:
    events = service_automation() + human_background(TASK)
    local_only = load_ruleset([LOCAL])
    result = run(events, dependents=local_only.dependents)
    tuned = tune(result)
    assert len(tuned) == 1
    suggestion = tuned[0]
    assert suggestion.review_required and not suggestion.dependents_verified
    assert "noise.reason.dependents_no_stock" in [r.key for r in suggestion.reasons if isinstance(r, Message)]
    finding = finding_for(result, suggestion)
    assert isinstance(finding.recommendation, Message) and finding.recommendation.key == "noise.rec.tune_unverified"
    assert finding.evidence["review_required"] is True and finding.evidence["dependents_verified"] is False
    # never "safely" for a suggestion that needs review, and never counted as a safe candidate
    assert isinstance(finding.title, Message) and finding.title.key == "noise.title.tune_review"
    assert "safely" not in text(finding.title) and "segura" not in text(finding.title, "es")
    assert result.section["safe_tuning_candidates"] == 0 and result.section["review_required_candidates"] == 1
    # no ruleset at all, on Wazuh data: the same (the emitter marks such rules REVIEW REQUIRED too)
    no_ruleset = tune(run(events, dependents=None))
    assert no_ruleset and all(s.review_required and not s.dependents_verified for s in no_ruleset)
    # non-Wazuh data has no Wazuh correlation to verify
    generic = tune(run(events, dependents=None, profile="ecs"))
    assert all(s.dependents_verified for s in generic)


def test_report_and_xml_agree_on_review(tmp_path: Path) -> None:
    local_only = load_ruleset([LOCAL])
    events = service_automation() + human_background(TASK)
    tuned = tune(run(events, dependents=local_only.dependents))
    ruleset = parse_rules_text(
        '<group name="local,"><rule id="100200" level="8"><if_sid>5500</if_sid><description>task</description>'
        "</rule></group>",
        file="/var/ossec/etc/rules/local_rules.xml",
    )
    result = emit(tmp_path, tuned, ruleset)
    assert result.rules and result.review_required == [rule_id for rule_id, _ in result.rules]
    assert any(w.key == "wazuh.emit.warn.no_stock" for w in result.warnings)
    xml = result.paths[0].read_text(encoding="utf-8")
    assert "review_required=yes" in xml and "REVIEW REQUIRED" in xml
    assert tuned[0].review_required


def test_audit_reports_missing_stock_rules() -> None:
    result = audit_ruleset(load_ruleset([LOCAL]), tenant=TenantConfig(), now=NOW)
    gap = [f for f in result.findings if f.subject == "ruleset:no-stock"]
    assert len(gap) == 1 and gap[0].kind == "assessment.incomplete" and gap[0].severity is Severity.MEDIUM
    assert "not verified" in text(gap[0].title)
    assert "/var/ossec/ruleset/rules" in text(gap[0].recommendation)
    assert result.section["stock_rules_loaded"] is False and result.section["correlation_verified"] is False
    # a suppression of a stock rule that was not loaded says so instead of silently dropping the check
    risky = [f for f in result.findings if f.kind == "tuning.risky_suppression"]
    assert risky and any("correlation_unverified" in f.evidence["checks"] for f in risky)
    full = audit_ruleset(load_ruleset([STOCK, LOCAL]), tenant=TenantConfig(), now=NOW)
    assert not [f for f in full.findings if f.subject == "ruleset:no-stock"]
    assert full.section["stock_rules_loaded"] is True


# ---- nothing to gain -> never "tune"; index volume apart --------------------------------------------
def test_nothing_to_gain_is_index_volume_not_tune() -> None:
    low = Rule("100700", 3, ("local", "scheduled_task"), description="Scheduled task (low)")
    below_triage = Rule("100701", 5, ("local", "scheduled_task"), description="Scheduled task (medium)")
    tenant = TenantConfig(trusted_entities={"user": ["svc_backup"]}, triage_level=7)
    for rule, key in (
        (low, "noise.reason.nothing_to_gain.demoted"),
        (below_triage, "noise.reason.nothing_to_gain.triage"),
    ):
        result = run(service_automation(rule) + human_background(rule), tenant=tenant)
        assert tune(result) == [], rule.id
        volume = [s for s in result.suggestions if s.index_volume]
        assert len(volume) == 1 and volume[0].verdict == "watch" and volume[0].impact == "index_volume"
        assert volume[0].reasons[0].key == key  # type: ignore[union-attr]
        finding = finding_for(result, volume[0])
        assert finding.kind == "noise.index_volume" and finding.severity is Severity.LOW
        assert "no_log" in text(finding.recommendation) and "log_alert_level" in text(finding.recommendation)
        assert result.section["index_volume_candidates"] == 1 and result.section["safe_tuning_candidates"] == 0
        assert result.section["time_saved_minutes_per_day"] is None
        # the rules table never says "tune" for it
        row = next(r for r in result.section["rules"] if r["rule_id"] == rule.id)
        assert row["verdict"] == "watch"


def test_backtest_texts_say_demote_not_hide() -> None:
    result = run(service_automation() + human_background(TASK))
    reasons = [text(r) for s in tune(result) for r in s.reasons]
    assert any(r.startswith("Backtest: would demote") for r in reasons)
    assert not any("would hide" in r for r in reasons)


def test_emitter_skips_children_that_do_not_lower_the_level(tmp_path: Path) -> None:
    rs = load_ruleset([STOCK, LOCAL])
    result = emit(tmp_path, [sug("60106", ("agent.name", "dc01"))], rs)  # 60106 is level 3
    assert result.rules == [] and result.paths == []
    assert [(fp, m.key) for fp, m in result.skipped] == [("f2fp0001", "wazuh.emit.skip.not_lower")]
    assert not any(w.key == "wazuh.emit.skip.not_lower" for w in result.warnings)


def test_index_volume_is_explained_in_validation_never_written(tmp_path: Path) -> None:
    rs = load_ruleset([STOCK, LOCAL])
    volume = sug("60106", ("agent.name", "dc01"), verdict="watch", impact="index_volume", fingerprint="vol0001")
    real = sug("5503", ("agent.name", "srv-app-01.example"), fingerprint="tune0001")
    result = emit(tmp_path, [volume, real], rs)
    assert [fp for _, fp in result.rules] == ["tune0001"]
    assert result.index_volume == ["vol0001"] and result.skipped == []
    validation = (tmp_path / "out" / VALIDATION_FILE).read_text(encoding="utf-8")
    assert "Index volume only" in validation and "Solo volumen del índice" in validation
    assert "vol0001" in validation and "no_log" in validation and "overwrite" in validation
    spec = json.loads((tmp_path / "out" / SPEC_FILE).read_text(encoding="utf-8"))
    assert spec["index_volume"][0]["fingerprint"] == "vol0001" and spec["index_volume"][0]["rule_written"] is False
    assert "vol0001" not in result.paths[0].read_text(encoding="utf-8")


# ---- skipped suggestions are not warnings ------------------------------------------------------------------------
def test_skipped_are_kept_apart_from_warnings(tmp_path: Path) -> None:
    rs = load_ruleset([STOCK, LOCAL])
    bad = sug("5503", ("agent.name", "a"), ("predecoder.hostname", "b"), fingerprint="skipme")
    good = sug("5503", ("agent.name", "srv-app-01.example"), fingerprint="keepme")
    result = emit(tmp_path, [bad, good], rs)
    assert [fp for fp, _ in result.skipped] == ["skipme"]
    assert not {w.key for w in result.warnings} & {m.key for _, m in result.skipped}
    validation = (tmp_path / "out" / VALIDATION_FILE).read_text(encoding="utf-8")
    assert "Suggestions not written as rules" in validation and "skipme" in validation


# ---- audit advice for rules that feed correlation ----------------------------------------------------------------
def test_audit_never_recommends_a_child_that_keeps_groups() -> None:
    result = audit_ruleset(load_ruleset([FIXTURES]), tenant=TenantConfig(), now=NOW)
    correlation = [
        f
        for f in result.findings
        if isinstance(f.recommendation, Message) and f.recommendation.key == "wazuh.audit.rec.correlation"
    ]
    assert correlation
    for lang in ("en", "es"):
        advice = text(correlation[0].recommendation, lang)
        assert "keeps the parent's groups" not in advice and "conserve los grupos" not in advice
        assert "no_log" in advice and "overwrite" in advice
    assert "ANY child" in text(correlation[0].recommendation)


# ---- exposure names public sources, never the anchor; firewall drops aggregate; FIM per rule ---------------------
def test_m4a_firewall_drops_aggregate_and_never_block_the_sender() -> None:
    rng = random.Random(3)
    drops = [
        alert(
            FW_DROP,
            t,
            "wazuh-manager",
            agent_id="000",
            data={"srcip": f"203.0.113.{rng.randint(1, 40)}", "dstip": "10.10.1.5"},
        )
        for t in every(START, END, timedelta(minutes=5), seed=42)
    ]
    result = run(drops, tenant=TenantConfig())
    firewall = [f for f in result.findings if f.kind == "noise.aggregate"]
    assert firewall, [(f.kind, f.subject) for f in result.findings]
    finding = firewall[0]
    assert finding.evidence["verdict"] == "aggregate"
    title, advice = text(finding.title), text(finding.recommendation)
    sources = finding.title.params["sources"]  # type: ignore[union-attr]
    assert sources and all(e.kind == "ip" and e.value.startswith("203.0.113.") for e in sources)
    assert "10.10.0.1" not in [e.value for e in sources]  # the firewall's own address is never "the source"
    assert "public addresses such as 203.0.113." in title
    assert "Never block or filter 10.10.0.1 itself" in advice and "frequency" in advice
    assert "Restrict exposure: block" not in advice


def test_m4a_exposure_names_the_public_sources() -> None:
    web = Rule("31101", 5, ("web", "accesslog"), (), (), "Web server 400 error code.", "web", "/var/log/nginx/a.log")
    rng = random.Random(8)
    events = [
        alert(web, t, "srv-web-09.example", data={"srcip": f"198.51.100.{rng.randint(1, 60)}"})
        for t in every(START, END, timedelta(minutes=10), seed=5)
    ]
    result = run(events)
    exposure = [f for f in result.findings if f.kind == "noise.fix_at_source"]
    assert exposure, [(f.kind, f.subject) for f in result.findings]
    finding = exposure[0]
    sources = finding.title.params["sources"]  # type: ignore[union-attr]
    assert sources and all(e.kind == "ip" and e.value.startswith("198.51.100.") for e in sources)
    assert sources[0].value in text(finding.recommendation)
    assert "srv-web-09.example" not in [e.value for e in sources]


def test_m4b_fim_noise_is_one_finding_per_rule_with_the_path_set() -> None:
    paths = ["/var/log/app/app.log", "/var/log/app/worker.log", "/var/log/app/api.log"]
    fim = [
        alert(FIM, t, host, extra={"syscheck.path": path, "syscheck.event": "modified"})
        for h, host in enumerate(("srv-db-01.example", "srv-db-02.example", "srv-db-03.example"))
        for p, path in enumerate(paths)
        for t in every(START, END, timedelta(minutes=50 + 7 * p + 3 * h), jitter=120, seed=15 + p + h)
    ]
    one_off = [alert(FIM, END - timedelta(hours=2), "srv-db-01.example", extra={"syscheck.path": "/etc/passwd"})]
    result = run(fim + one_off)
    fim_findings = [f for f in result.findings if f.domain == "noise" and f.subject.startswith("rule:550")]
    assert [f.subject for f in fim_findings] == ["rule:550|fim"]
    finding = fim_findings[0]
    listed = {p["path"].value for p in finding.evidence["paths"]}
    assert listed == set(paths)  # every recurring path, including the one below the candidate share
    assert "/etc/passwd" not in listed  # a one-off change is exactly what FIM is for
    assert {h["host"].value for h in finding.evidence["hosts"]} == {
        "srv-db-01.example",
        "srv-db-02.example",
        "srv-db-03.example",
    }
    advice = text(finding.recommendation)
    assert '<ignore type="sregex">^/var/log/app/\\S+.log$</ignore>' in advice
    assert "<syscheck>" in advice and "agent.conf" in advice
    assert "agent.name" not in advice  # syscheck <ignore> takes paths, never a host
    assert finding.evidence["ignore_pattern"] == Entity("file", "^/var/log/app/\\S+.log$")


def test_m4b_sregex_is_only_proposed_for_a_common_directory_and_extension() -> None:
    from hushwatch.analysis.noise import _sregex_for

    assert _sregex_for(["/var/log/app/a.log", "/var/log/app/b.log"]) == "^/var/log/app/\\S+.log$"
    assert _sregex_for(["/var/log/app/a.log"]) is None
    assert _sregex_for(["/var/log/app/a.log", "/opt/b.log"]) is None
    assert _sregex_for(["/var/log/app/a.log", "/var/log/app/b.txt"]) is None
    assert _sregex_for(["/srv/(x)/a.log", "/srv/(x)/b.log"]) == "^/srv/\\(x\\)/\\S+.log$"  # OS_Regex escapes


# ---- true positives are attacks, not noise -----------------------------------------------------------------------
def test_true_positive_scope_is_high_and_framed_as_an_attack() -> None:
    events = service_automation() + human_background(TASK)
    one = next(e for e in events if e.fields["agent.name"] == "srv-backup-01.corp.example")
    disp = Dispositions.from_rows([{"alert_id": one.event_id, "verdict": "tp", "closed_at": "2026-09-10"}])
    result = run(events, dispositions=disp)
    blocked = with_value(result, "svc_backup")
    finding = finding_for(result, blocked[0])
    assert finding.severity is Severity.HIGH
    assert "attack activity" in text(finding.title) and "actividad de ataque" in text(finding.title, "es")
    assert "fixing its cause" not in text(finding.recommendation)
    assert keys(finding)[0] == "noise.reason.tp"  # the most important reason first
    row = next(r for r in result.section["rules"] if r["rule_id"] == "100200")
    assert row["verdict"] == "do_not_tune"  # the rules table agrees with the finding


# ---- noisy threshold, wording, dominant external entity, beacons vs sprays ---------------------------------------
def test_rules_below_the_noisy_threshold_are_not_called_noisy() -> None:
    critical = Rule("63103", 12, ("windows", "log_cleared"), description="The audit log was cleared.")
    events = [alert(critical, START + timedelta(days=d), "dc01.example") for d in range(0, 21, 5)]
    events += service_automation()
    result = run(events)
    assert not [f for f in result.findings if f.subject == "rule:63103"]
    row = next(r for r in result.section["rules"] if r["rule_id"] == "63103")
    assert row["verdict"] == "do_not_tune" and row["noisy"] is False
    assert result.section["noisy_threshold"] == {"alerts": 50, "per_day": 5.0}


def test_high_level_rule_wording() -> None:
    critical = Rule("62123", 12, ("windows", "windows_defender"), description="Defender: PUA")
    noisy = [alert(critical, t, "ws-03.example") for t in every(START, END, timedelta(minutes=20), seed=16)]
    result = run(noisy)
    finding = next(f for f in result.findings if f.subject == "rule:62123")
    assert "high-severity rule, out of scope for tuning" in text(finding.title)
    assert "is noisy, but" not in text(finding.title)


def test_brute_force_finding_names_the_attacking_address() -> None:
    background = [
        alert(SSHD_INVALID, t, "srv-web-02.example", data={"srcip": f"10.0.{i % 5}.7", "srcuser": "admin"})
        for i, t in enumerate(every(START, END, timedelta(minutes=30), seed=31))
    ]
    attack = [
        alert(SSHD_INVALID, t, "srv-web-02.example", data={"srcip": "203.0.113.50", "srcuser": f"u{i}"})
        for i, t in enumerate(every(END - timedelta(days=2), END, timedelta(seconds=90), seed=32))
    ]
    correlated = [
        alert(SSHD_BRUTE, t, "srv-web-02.example", data={"srcip": "203.0.113.50"}) for t in [e.ts for e in attack][::40]
    ]
    result = run(background + attack + correlated)
    host = [f for f in result.findings if f.subject == "rule:5710|agent.name:srv-web-02.example"]
    assert host, [f.subject for f in result.findings]
    finding = host[0]
    assert finding.kind == "noise.investigate" and finding.severity is Severity.HIGH
    assert "203.0.113.50" in text(finding.title)
    assert finding.evidence["public_sources"][0]["entity"] == Entity("ip", "203.0.113.50")


def test_beacon_names_the_destination_not_the_host_address() -> None:
    net = Rule("100310", 8, ("sysmon", "sysmon_event3"), description="Network connection")
    beacon = [
        alert(
            net,
            t,
            "lap-07.example",
            win={"sourceIp": "10.40.1.107", "destinationIp": "192.0.2.77", "image": "C:\\\\Users\\\\x\\\\u.exe"},
        )
        for t in every(START, END, timedelta(minutes=5), jitter=8, seed=11)
    ]
    result = run(beacon)
    findings = [f for f in result.findings if f.kind == "noise.investigate" and "lap-07.example" in f.subject]
    assert findings
    finding = findings[0]
    title = text(finding.title)
    assert "192.0.2.77" in title and "beacon" in title and "10.40.1.107" not in title
    assert finding.severity is Severity.HIGH
    assert keys(finding)[0] in ("noise.reason.beacon", "noise.backtest.beacon")


def test_password_spray_is_not_called_beaconing() -> None:
    logon_fail = Rule(
        "60122", 5, ("windows", "authentication_failed"), ("Credential Access",), ("T1110",), "Logon failure"
    )
    rng = random.Random(4)
    spray: list[Event] = []
    t = END - timedelta(days=3)
    user = 0
    while t < END:  # low and slow, around the clock: every hour is active, but the gaps are irregular
        spray.append(
            alert(
                logon_fail,
                t,
                "dc01.example",
                win={"ipAddress": "198.51.100.23", "targetUserName": f"user{user % 200}", "logonType": "3"},
            )
        )
        user += 1
        t += timedelta(seconds=rng.randint(35, 80))
    background = [
        alert(logon_fail, t, "dc01.example", win={"ipAddress": "10.0.0.9", "targetUserName": "bob"})
        for t in every(START, END, timedelta(minutes=20), seed=9)
    ]
    result = run(spray + background)
    reasons = {r.key for s in result.suggestions for r in s.reasons if isinstance(r, Message)}
    assert "noise.reason.beacon" not in reasons and "noise.backtest.beacon" not in reasons
    assert "noise.reason.sustained_from" in reasons
    spray_scopes = with_value(result, "198.51.100.23")
    assert spray_scopes and all(s.verdict != "tune" for s in spray_scopes)
    rendered = " ".join(text(f.title) + " " + " ".join(text(r) for r in f.reasons) for f in result.findings)
    assert "beacon" not in rendered


def test_regularity_separates_beacons_from_sprays() -> None:
    rng = random.Random(1)
    sketch: SpaceSaving[str] = SpaceSaving(4)
    ts = 1_000_000.0
    for _ in range(300):
        sketch.add("beacon", 1, ts, 0, int(ts // 3600))
        ts += 300 + rng.uniform(-4, 4)
    ts = 2_000_000.0
    for _ in range(300):
        sketch.add("spray", 1, ts, 0, int(ts // 3600))
        ts += rng.uniform(35, 80)
    regular = {e.key: e.regularity() for e in sketch.entries()}
    assert regular["beacon"] is not None and regular["beacon"] > 0.9
    assert regular["spray"] is not None and regular["spray"] < g.PERIODIC_MIN_SHARE
    few: SpaceSaving[str] = SpaceSaving(2)
    for i in range(5):
        few.add("x", 1, 1000.0 + i * 60, 0, 0)
    assert few.entries()[0].regularity() is None  # too few gaps: unknown, never "periodic"


# ---- one day count for per-day figures ---------------------------------------------------------------------------
def test_minor_per_day_uses_elapsed_days() -> None:
    result = run(service_automation() + human_background(TASK))
    section = result.section
    days = section["totals"]["days"]
    assert section["window"]["days"] == days and section["window"]["dates"] >= days
    row = next(r for r in section["rules"] if r["rule_id"] == "100200")
    assert row["per_day"] == pytest.approx(row["total"] / days, rel=0.01)


# ---- the child keeps the parent's output options, MITRE and compliance groups ------------------------------------
def test_child_copies_options_and_mitre(tmp_path: Path) -> None:
    rs = load_ruleset([STOCK, LOCAL])
    result = emit(tmp_path, [sug("60122", ("agent.name", "dc01"))], rs)
    xml = result.paths[0].read_text(encoding="utf-8")
    assert "<options>no_full_log</options>" in xml and "<id>T1110</id>" in xml
    spec = json.loads((tmp_path / "out" / SPEC_FILE).read_text(encoding="utf-8"))
    assert spec["suppressions"][0]["options"] == ["no_full_log"] and spec["suppressions"][0]["mitre"] == ["T1110"]


def test_compliance_groups_are_rebuilt_from_alerts_without_a_ruleset(tmp_path: Path) -> None:
    extra = {"rule.pci_dss": ["10.2.4", "10.2.5"], "rule.gdpr": ["IV_35.7.d"], "rule.nist_800_53": ["AU.14"]}
    events = [
        alert(
            TASK,
            t,
            "srv-backup-01.corp.example",
            agent_id="002",
            win={"subjectUserName": "svc_backup", "targetUserName": "svc_backup", "logonType": "5"},
            extra=extra,
        )
        for t in every(START, END, timedelta(minutes=15), jitter=90, seed=1)
    ] + human_background(TASK)
    tuned = tune(run(events))
    assert tuned
    groups = set(tuned[0].rule_groups)
    assert {"pci_dss_10.2.4", "pci_dss_10.2.5", "gdpr_IV_35.7.d", "nist_800_53_AU.14"} <= groups
    result = emit(tmp_path, tuned, None)
    xml = result.paths[0].read_text(encoding="utf-8")
    assert "pci_dss_10.2.4," in xml and "gdpr_IV_35.7.d," in xml


# ---- Wazuh has no rule expiry ------------------------------------------------------------------------------------
def test_expiry_is_explained(tmp_path: Path) -> None:
    rs = load_ruleset([STOCK, LOCAL])
    emit(tmp_path, [sug("5503", ("agent.name", "srv-app-01.example"))], rs)
    validation = (tmp_path / "out" / VALIDATION_FILE).read_text(encoding="utf-8")
    assert "Wazuh has no rule expiry" in validation and "tuning.expired" in validation
    assert "Wazuh no hace vencer las reglas" in validation
    result = run(service_automation() + human_background(TASK))
    finding = finding_for(result, tune(result)[0])
    advice = text(finding.recommendation)
    assert "never expire by themselves" in advice and "hushwatch audit" in advice


# ---- the rules table agrees with the findings -------------------------------------------------------------------
def test_rules_table_marks_scoped_verdicts() -> None:
    result = run(service_automation() + human_background(TASK))
    row = next(r for r in result.section["rules"] if r["rule_id"] == "100200")
    assert row["verdict"] == "tune" and row["verdict_scoped"] is True
    assert row["verdict_counts"].get("tune") == 1


# ---- one fingerprint across finding, rule and spec --------------------------------------------------------------
def test_one_fingerprint_for_finding_rule_and_spec(tmp_path: Path) -> None:
    result = run(service_automation() + human_background(TASK))
    suggestion = tune(result)[0]
    finding = finding_for(result, suggestion)
    assert finding.fingerprint == suggestion.fingerprint == fingerprint(TENANT.name, "noise.tune", finding.subject)
    rs = parse_rules_text(
        '<group name="local,"><rule id="100200" level="8"><if_sid>5500</if_sid><description>t</description></rule>'
        "</group>",
        file="/var/ossec/ruleset/rules/0100-x_rules.xml",
        is_local=False,
    )
    emitted = emit(tmp_path, [suggestion], rs)
    assert emitted.rules[0][1] == finding.fingerprint
    assert f"fp:{finding.fingerprint}" in emitted.paths[0].read_text(encoding="utf-8")
    spec = json.loads((tmp_path / "out" / SPEC_FILE).read_text(encoding="utf-8"))
    assert spec["suppressions"][0]["fingerprint"] == finding.fingerprint


# ---- the "already exists" error names the real CLI flag ---------------------------------------------------------
def test_existing_files_mention_force(tmp_path: Path) -> None:
    rs = load_ruleset([STOCK, LOCAL])
    emit(tmp_path, [sug("5503", ("agent.name", "srv-app-01.example"))], rs)
    with pytest.raises(EmitError) as excinfo:
        emit(tmp_path, [sug("5503", ("agent.name", "srv-app-01.example"))], rs)
    assert "--force" in str(excinfo.value) and "overwrite=True" not in str(excinfo.value)
    assert "--force" in text(excinfo.value.message, "es")


# ---- a remote failure during the backtest never crashes and never tunes -----------------------------------------
class _LostPit:
    """A re-iterable source whose second pass fails like an indexer that lost its point-in-time."""

    def __init__(self, events: list[Event]) -> None:
        self.events = events
        self.passes = 0

    def __iter__(self) -> Iterator[Event]:
        self.passes += 1
        if self.passes > 1:
            raise RemoteError("point in time expired", kind="http", status=404)
        return iter(self.events)


def test_remote_error_in_the_backtest_is_not_backtested() -> None:
    events = sorted(service_automation() + human_background(TASK), key=lambda e: e.ts)
    source = _LostPit(events)
    collector = NoiseCollector(TENANT, "wazuh4")
    for event in source:
        collector.add(event)
    result = analyze_noise(collector, tenant=TENANT, now=END, dependents=lambda _rule: ())
    result = apply_backtest(result, source, tenant=TENANT)
    assert not result.backtested
    assert [s for s in result.suggestions if s.verdict == "tune"] == []
    incomplete = [f for f in result.findings if f.subject == "noise:backtest"]
    assert incomplete and incomplete[0].severity is Severity.MEDIUM
    assert any("point in time expired" in text(r) for r in incomplete[0].reasons)


# ---- wording glitches --------------------------------------------------------------------------------------------
def test_counts_rates_and_shares_read_correctly() -> None:
    from hushwatch.analysis.backtest import pct, rate
    from hushwatch.analysis.noise import _alerts

    assert text(_alerts(1)) == "1 alert" and text(_alerts(2)) == "2 alerts" and text(_alerts(1), "es") == "1 alerta"
    assert text(rate(0.05)) == "0.05/day" and text(rate(0.001)) == "<0.01/day" and text(rate(12.34)) == "12.3/day"
    assert text(pct(0.00001)) == "<0.1%" and text(pct(0.004)) == "0.4%" and text(pct(0.5)) == "50%"


def test_external_share_and_missing_evidence_wording() -> None:
    facts_all = g.CandidateFacts(
        rule_id="1",
        conditions=(),
        count_lower=10,
        count_upper=10,
        rule_total=10,
        window=g.Window(0.0, 86400.0 * 21, 1, 21),
        rule_level=5,
        external_share=1.0,
    )
    outcome = next(o for o in g.evaluate(facts_all, TENANT.noise, TENANT).outcomes if o.gate == "external")
    assert text(outcome.message).startswith("All of these alerts come from public addresses")
    from hushwatch.analysis.dispositions import DispositionCounts

    gap = g.evidence_gap(DispositionCounts(), None, TENANT.noise)
    assert gap is not None and "only 0 triaged" in text(gap) and "FP ≥ 0%" not in text(gap)


def test_named_service_account_is_not_called_trusted() -> None:
    task = Rule("100450", 8, ("local", "scheduled_task"), ("Persistence",), ("T1053",), "Scheduled task created")
    events = [
        alert(task, t, "db-01.example", win={"subjectUserName": "svc_sql"})
        for t in every(START, END, timedelta(minutes=20), jitter=60, seed=7)
    ]
    result = run(events, tenant=TenantConfig())
    rendered = [text(r) for s in result.suggestions for r in s.reasons]
    assert not any("the anchor is trusted" in r for r in rendered)
    assert any("by its name only" in r or "trusted only because its name" in r for r in rendered)
