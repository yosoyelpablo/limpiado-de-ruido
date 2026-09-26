"""Tests for hushwatch.wazuh.audit: risky suppressions in LOCAL Wazuh rules."""

from __future__ import annotations

import time
from datetime import date
from pathlib import Path
from typing import Any

import pytest

from hushwatch import i18n
from hushwatch.config import NoiseSettings, TenantConfig
from hushwatch.i18n import Entity, Message
from hushwatch.models import Finding, Severity, iter_entities
from hushwatch.wazuh import audit as audit_module
from hushwatch.wazuh.audit import AuditResult, audit_ruleset, technique_tactics
from hushwatch.wazuh.ruleset import RuleCondition, Ruleset, load_ruleset, parse_rules_text

FIXTURES = Path(__file__).parent / "fixtures" / "wazuh"
NOW = date(2026, 9, 25)
STOCK = FIXTURES / "ruleset" / "rules"


@pytest.fixture(scope="module")
def result() -> AuditResult:
    return audit_ruleset(load_ruleset([FIXTURES]), tenant=TenantConfig(), now=NOW)


def risky(result: AuditResult, rule_id: str) -> Finding:
    found = [f for f in result.findings if f.kind == "tuning.risky_suppression" and f.evidence["rule_id"] == rule_id]
    assert len(found) == 1, [f.subject for f in result.findings]
    return found[0]


def checks(result: AuditResult, rule_id: str) -> set[str]:
    return set(risky(result, rule_id).evidence["checks"])


def audit_local(local_xml: str, tenant: TenantConfig | None = None, *, with_stock: bool = True) -> AuditResult:
    ruleset = load_ruleset([STOCK]) if with_stock else Ruleset()
    parse_rules_text(local_xml, file="/var/ossec/etc/rules/local_rules.xml", is_local=True, into=ruleset)
    return audit_ruleset(ruleset, tenant=tenant or TenantConfig(), now=NOW)


def local_group(*rules: str) -> str:
    return '<group name="local,">' + "".join(rules) + "</group>"


# ---- the synthetic catalogue ----------------------------------------------------------------------------------------


def test_whole_rule_mute_of_an_attack_rule(result: AuditResult) -> None:
    finding = risky(result, "100001")
    assert finding.severity is Severity.HIGH
    assert checks(result, "100001") == {"whole_rule", "breaks_correlation", "sensitive_parent"}
    assert finding.evidence["parents"] == ["5710"]
    assert finding.domain == "tuning" and finding.subject == "rule:100001|file:local_rules.xml"
    correlation = next(r for r in finding.reasons if isinstance(r, Message) and r.key.endswith("breaks_correlation"))
    assert correlation.params["dependents"] == "5712, 60204"


def test_unanchored_match_on_log_text_only(result: AuditResult) -> None:
    assert risky(result, "100002").severity is Severity.HIGH
    assert {"unanchored", "attacker_only", "breaks_correlation", "sensitive_parent"} <= checks(result, "100002")


def test_internal_network_is_a_stable_anchor_but_correlation_still_breaks(result: AuditResult) -> None:
    found = checks(result, "100003")
    assert "attacker_only" not in found and "whole_rule" not in found and "unanchored" not in found
    assert "breaks_correlation" in found
    sensitive = [r for r in risky(result, "100003").reasons if isinstance(r, Message) and r.key.endswith("sensitive")]
    assert sensitive  # narrow + stable: listed, but at medium severity
    assert not any(f.kind == "tuning.expired" and f.evidence["rule_id"] == "100003" for f in result.findings)


def test_no_log_child_on_unanchored_username(result: AuditResult) -> None:
    assert {"unanchored", "attacker_only", "breaks_correlation", "sensitive_parent"} <= checks(result, "100005")
    assert risky(result, "100005").evidence["options"] == ["no_log"]


def test_pcre2_with_an_unanchored_alternative(result: AuditResult) -> None:
    assert "unanchored" in checks(result, "100006")


def test_well_scoped_suppression_is_not_flagged(result: AuditResult) -> None:
    assert not [f for f in result.findings if f.evidence.get("rule_id") == "100010"]


def test_expired_suppression(result: AuditResult) -> None:
    expired = [f for f in result.findings if f.kind == "tuning.expired"]
    assert [f.evidence["rule_id"] for f in expired] == ["100011"]
    finding = expired[0]
    assert finding.severity is Severity.MEDIUM
    assert finding.evidence["expires"] == "2026-01-31" and finding.evidence["days_overdue"] == 237
    assert finding.subject == "rule:100011|file:local_rules.xml|expired"
    assert not [
        f for f in result.findings if f.kind == "tuning.risky_suppression" and f.evidence["rule_id"] == "100011"
    ]


def test_missing_description_only(result: AuditResult) -> None:
    finding = risky(result, "100012")
    assert finding.severity is Severity.LOW and checks(result, "100012") == {"no_description"}
    assert isinstance(finding.title, Message) and finding.title.key == "wazuh.audit.title.undocumented"


def test_frequency_rule_chained_by_if_sid_counts_as_correlation(result: AuditResult) -> None:
    finding = risky(result, "100013")
    reason = next(r for r in finding.reasons if isinstance(r, Message) and r.key.endswith("breaks_correlation"))
    assert reason.params["dependents"] == "5557, 60204"


def test_overwrite_weakening_a_stock_correlation_rule(result: AuditResult) -> None:
    finding = risky(result, "5712")
    assert finding.evidence["overwrite"] is True
    assert {"overwrite_level", "overwrite_threshold", "high_level_parent"} <= checks(result, "5712")
    assert finding.severity is Severity.HIGH  # a level-10 rule pushed below the triage level
    thresholds = [r.params["attribute"] for r in finding.reasons if isinstance(r, Message) and "threshold" in r.key]
    assert sorted(thresholds) == ["frequency", "ignore"]


def test_if_group_mute_reaches_every_matching_rule(result: AuditResult) -> None:
    finding = risky(result, "100050")
    assert finding.evidence["parents"] == ["5501", "5715", "60106"]
    assert checks(result, "100050") == {"sensitive_parent", "preempts"}
    # Level 0 is tried before every sibling: the level-12 "Direct root login accepted" (100030, a child of 5715)
    # can never fire on that host again.
    assert finding.severity is Severity.HIGH
    reason = next(r for r in finding.reasons if isinstance(r, Message) and r.key.endswith("preempts"))
    assert reason.params["rules"] == "100030" and reason.params["level"] == 12


def test_detection_rules_are_not_suppressions(result: AuditResult) -> None:
    assert not [f for f in result.findings if f.evidence.get("rule_id") in ("100030", "100200")]


def test_hushwatch_demote_correlation_semantics(result: AuditResult) -> None:
    finding = risky(result, "100100")
    reason = next(r for r in finding.reasons if isinstance(r, Message) and r.key.endswith("breaks_correlation"))
    # 5557 (frequency via if_sid, level 10) is tried before the level-3 child and counts every recent event;
    # 60204 wired its if_matched_group list when it loaded (stock file), before the local child existed, so the
    # copied authentication_failed group does not make it count the child's events.
    assert reason.params["dependents"] == "60204"
    assert "unanchored" not in checks(result, "100100") and "attacker_only" not in checks(result, "100100")


def test_group_correlation_loaded_after_the_child_is_kept() -> None:
    local = local_group(
        '<rule id="100001" level="3"><if_sid>5503</if_sid><hostname>^h$</hostname><description>d</description>'
        "<group>authentication_failed,</group></rule>",
        '<rule id="100002" level="10" frequency="4"><if_matched_group>authentication_failed</if_matched_group>'
        "<description>local correlation</description></rule>",
    )
    reason = next(
        r
        for r in risky(audit_local(local), "100001").reasons
        if isinstance(r, Message) and r.key.endswith("breaks_correlation")
    )
    assert reason.params["dependents"] == "60204"  # 100002 loads after the child and matches its groups


def test_stock_rules_are_not_audited(result: AuditResult) -> None:
    flagged = {f.evidence.get("rule_id") for f in result.findings}
    assert not flagged & {"5700", "60000", "60001", "60103", "60105", "1001", "5500"}


def test_duplicate_ids_are_incomplete_assessment(result: AuditResult) -> None:
    duplicates = [f for f in result.findings if f.subject.startswith("duplicate-rule-ids:")]
    assert len(duplicates) == 1
    finding = duplicates[0]
    assert finding.kind == "assessment.incomplete" and finding.domain == "assessment"
    assert finding.severity is Severity.MEDIUM and finding.evidence["ids"] == ["100012"]


def test_section(result: AuditResult) -> None:
    section = result.section
    assert section["status"] == "fail"
    assert section["rules_parsed"] == 34 and section["local_rules"] == 15 and section["files"] == 6
    assert section["risky"] == len([f for f in result.findings if f.kind == "tuning.risky_suppression"])
    assert section["expired"] == 1 and section["duplicate_ids"] == 1 and section["parse_errors"] == 0
    assert {"status", "rules_parsed", "local_rules", "risky"} <= set(section)


def test_findings_are_stable_across_runs(result: AuditResult) -> None:
    again = audit_ruleset(load_ruleset([FIXTURES]), tenant=TenantConfig(), now=NOW)
    assert [f.fingerprint for f in again.findings] == [f.fingerprint for f in result.findings]
    assert len({f.fingerprint for f in result.findings}) == len(result.findings)


def test_file_paths_are_entities_and_messages_are_translated(result: AuditResult) -> None:
    for finding in result.findings:
        for entity in iter_entities(finding.evidence):
            assert isinstance(entity, Entity) and entity.kind == "file"
        assert all(isinstance(v, Entity) for k, v in finding.evidence.items() if k.endswith("file"))
        messages: list[Any] = [finding.title, finding.recommendation, *finding.reasons]
        for message in messages:
            if message is None:
                continue
            assert isinstance(message, Message)
            english, spanish = i18n.render(message, "en"), i18n.render(message, "es")
            assert i18n.has(message.key) and english != spanish
            assert "{" not in english and "{" not in spanish


# ---- targeted cases -----------------------------------------------------------------------------------------------


def test_high_level_parent() -> None:
    local = local_group(
        '<rule id="100001" level="0"><if_sid>5712</if_sid><srcip>10.0.0.5</srcip>'
        "<description>x, expires 2027-01-01</description></rule>"
    )
    finding = risky(audit_local(local), "100001")
    assert "high_level_parent" in finding.evidence["checks"] and finding.severity is Severity.HIGH


def test_tenant_sensitive_tactics_are_configurable(result: AuditResult) -> None:
    quiet = TenantConfig(noise=NoiseSettings(sensitive_tactics=()))
    rerun = audit_ruleset(load_ruleset([FIXTURES]), tenant=quiet, now=NOW)
    assert checks(rerun, "100050") == {"preempts"}
    assert "sensitive_parent" not in checks(rerun, "100001")


def test_trusted_user_is_a_stable_anchor() -> None:
    local = local_group(
        '<rule id="100001" level="0"><if_sid>5501</if_sid><user>^alice$</user><description>d</description></rule>'
    )
    assert "attacker_only" in checks(audit_local(local), "100001")
    trusted = TenantConfig(trusted_entities={"user": ["alice"]})
    assert not [f for f in audit_local(local, trusted).findings if f.evidence.get("rule_id") == "100001"]
    service = local.replace("alice", "svc_monitoring")
    assert not [f for f in audit_local(service).findings if f.evidence.get("rule_id") == "100001"]


@pytest.mark.parametrize(
    ("condition", "expected"),
    [
        ("<srcip>203.0.113.7</srcip>", {"attacker_only"}),
        ("<srcip>10.1.2.3</srcip>", set()),
        ("<srcip>10.0.0.0/8</srcip>", {"broad_network"}),
        ("<srcip>any</srcip>", {"whole_rule"}),
        ('<srcip negate="yes">10.0.0.0/8</srcip>', {"whole_rule"}),
        ("<hostname>web01</hostname>", {"unanchored"}),
        ("<hostname>^web01$</hostname>", set()),
        ("<match>!error</match>", {"whole_rule"}),
        ('<field name="win.eventdata.commandLine" type="pcre2">^backup\\.exe /s$</field>', {"attacker_only"}),
        ('<field name="win.eventdata.image" type="pcre2">(?i)^C:\\\\Tools\\\\a\\.exe$</field>', set()),
        ('<field name="win.eventdata.image">\\\\a.exe</field>', {"unanchored", "attacker_only"}),
        ('<field name="win.system.eventID">^4624$</field>', set()),
        ('<field name="win.eventdata.ipAddress" type="pcre2">^10\\.0\\.0\\.5$</field>', set()),
        ("<time>6 pm - 8:30 am</time>", {"whole_rule"}),
        ("<location>^(web01)</location>", set()),
        ("<location>web01</location>", {"unanchored"}),
        ('<location type="pcre2">->/var/log/secure$</location>', set()),
        ("<url>/health</url>", {"unanchored", "attacker_only"}),
    ],
)
def test_condition_checks(condition: str, expected: set[str]) -> None:
    local = local_group(
        f'<rule id="100001" level="0"><if_sid>5502</if_sid>{condition}<description>d</description></rule>'
    )
    found = [f for f in audit_local(local).findings if f.evidence.get("rule_id") == "100001"]
    assert (set(found[0].evidence["checks"]) if found else set()) == expected


def test_low_level_and_demoted_children() -> None:
    local = local_group(
        '<rule id="100001" level="2"><if_sid>5503</if_sid><description>d</description></rule>',
        '<rule id="100002" level="4"><if_sid>5503</if_sid><hostname>^h$</hostname><description>d</description></rule>',
        '<rule id="100003" level="12"><if_sid>5503</if_sid><hostname>^h$</hostname><description>d</description></rule>',
    )
    result = audit_local(local)
    assert "whole_rule" in checks(result, "100001") and risky(result, "100001").severity is Severity.HIGH
    assert "breaks_correlation" in checks(result, "100002")  # a demote also changes the final rule id
    assert not [f for f in result.findings if f.evidence.get("rule_id") == "100003"]


def test_muting_a_grouping_parent_hides_every_detection_below_it() -> None:
    # 5700 is a level-0 grouping rule: a level-0 child is tried before 5710/5715/5716/5760, so on that host no
    # sshd rule fires any more (brute force 5712/5720 included), although each condition looks narrow.
    local = local_group(
        '<rule id="100001" level="0"><if_sid>5700</if_sid><hostname type="pcre2">^srv\\-web\\-01$</hostname>'
        "<description>quiet sshd on srv-web-01, expires 2027-01-01</description></rule>"
    )
    finding = risky(audit_local(local), "100001")
    assert finding.severity is Severity.HIGH and set(finding.evidence["checks"]) == {"preempts"}
    reason = next(r for r in finding.reasons if isinstance(r, Message) and r.key.endswith("preempts"))
    assert reason.params["rules"] == "5712, 5720, 5710, 5716, 5760, 5715" and reason.params["level"] == 10


def test_no_log_child_tried_after_a_frequency_rule_keeps_it() -> None:
    local = local_group(
        '<rule id="100001" level="4"><if_sid>5503</if_sid><hostname>^h$</hostname><options>no_log</options>'
        "<description>d</description><group>authentication_failed,</group></rule>",
        '<rule id="100002" level="0"><if_sid>5503</if_sid><hostname>^h$</hostname><description>d</description></rule>',
    )
    result = audit_local(local)
    breaks = {
        rule_id: next(
            r.params["dependents"]
            for r in risky(result, rule_id).reasons
            if isinstance(r, Message) and r.key.endswith("breaks_correlation")
        )
        for rule_id in ("100001", "100002")
    }
    assert breaks == {"100001": "60204", "100002": "5557, 60204"}  # level 0 is never recorded


def test_missing_parent_is_reported_when_the_stock_ruleset_is_loaded() -> None:
    local = local_group(
        '<rule id="100001" level="0"><if_sid>424242</if_sid><hostname>^h$</hostname><description>d</description></rule>'
    )
    assert "missing_parent" in checks(audit_local(local), "100001")
    # parents unknowable: nothing to claim about the rule, but the audit says it could not verify correlation
    unverified = audit_local(local, with_stock=False)
    assert [(f.kind, f.subject, f.severity) for f in unverified.findings] == [
        ("assessment.incomplete", "ruleset:no-stock", Severity.MEDIUM)
    ]
    assert unverified.section["stock_rules_loaded"] is False and unverified.section["status"] == "ok"


def test_parent_loaded_after_the_child_counts_as_missing() -> None:
    ruleset = load_ruleset([STOCK])
    child = local_group(
        '<rule id="100001" level="0"><if_sid>100900</if_sid><hostname>^h$</hostname><description>d</description></rule>'
    )
    parse_rules_text(child, file="/var/ossec/etc/rules/local_rules.xml", is_local=True, into=ruleset)
    parent = local_group('<rule id="100900" level="5"><decoded_as>x</decoded_as><description>p</description></rule>')
    parse_rules_text(parent, file="/var/ossec/etc/rules/zz_custom.xml", is_local=True, into=ruleset)
    result = audit_ruleset(ruleset, tenant=TenantConfig(), now=NOW)
    assert "missing_parent" in checks(result, "100001")


def test_overwrite_that_mutes_or_drops_groups() -> None:
    mute = (
        '<group name="syslog,sshd,"><rule id="5710" level="0" overwrite="yes"><if_sid>5700</if_sid>'
        "<description>m</description></rule></group>"
    )
    result = audit_local(mute)
    assert {"overwrite_mute", "breaks_correlation", "sensitive_parent"} <= checks(result, "5710")
    regroup = (
        '<group name="syslog,sshd,"><rule id="5716" level="5" overwrite="yes"><if_sid>5700</if_sid>'
        "<match>^Failed</match><description>d</description><group>renamed,</group></rule></group>"
    )
    # Stock 60204 wired its group list to 5716 when it loaded; an overwrite does not unwire it.
    assert not [f for f in audit_local(regroup).findings if f.kind.startswith("tuning.")]
    later = regroup + local_group(
        '<rule id="100002" level="10" frequency="4"><if_matched_group>authentication_failed</if_matched_group>'
        "<description>local correlation loaded after the overwrite</description></rule>"
    )
    finding = risky(audit_local(later), "5716")
    assert "overwrite_groups" in finding.evidence["checks"]
    reason = next(r for r in finding.reasons if isinstance(r, Message) and r.key.endswith("overwrite_groups"))
    assert reason.params["dependents"] == "100002"


def test_harmless_overwrite_is_not_flagged() -> None:
    raise_level = (
        '<group name="syslog,sshd,"><rule id="5710" level="7" overwrite="yes"><if_sid>5700</if_sid>'
        "<match>invalid user</match><description>raised</description>"
        "<group>authentication_failed,invalid_login,</group></rule></group>"
    )
    assert not [f for f in audit_local(raise_level).findings if f.kind.startswith("tuning.")]


@pytest.mark.parametrize(
    ("description", "expired"),
    [
        ("Expires: 2025-01-01", True),
        ("temporary, EXPIRES 2026-09-24", True),
        ("expiry=2026-01-01 owner soc", True),
        ("caduca el 2026-02-01", True),
        ("vence 2026-03-01", True),
        ("expires 2026-09-25", False),
        ("expires 2027-01-01", False),
        ("expires 2025-02-30", False),
        ("no expiry mentioned 2020-01-01", False),
    ],
)
def test_expiry_parsing(description: str, expired: bool) -> None:
    local = local_group(
        f'<rule id="100001" level="3"><if_sid>5502</if_sid><description>{description}</description></rule>'
    )
    found = [f for f in audit_local(local).findings if f.kind == "tuning.expired"]
    assert bool(found) is expired


def test_parse_errors_become_incomplete_assessment() -> None:
    ruleset = load_ruleset(
        [STOCK, FIXTURES / "broken" / "bad_semantics.xml", FIXTURES / "broken" / "unclosed_rules.xml"]
    )
    result = audit_ruleset(ruleset, tenant=TenantConfig(), now=NOW)
    incomplete = [f for f in result.findings if f.subject.startswith("ruleset-errors:")]
    assert {f.subject for f in incomplete} == {"ruleset-errors:bad_semantics.xml", "ruleset-errors:unclosed_rules.xml"}
    assert all(f.kind == "assessment.incomplete" and f.severity is Severity.HIGH for f in incomplete)
    semantics = next(f for f in incomplete if "bad_semantics" in f.subject)
    assert len(semantics.reasons) == 6  # five errors + "... and N more"
    assert semantics.evidence["errors"] == 12
    assert result.section["status"] == "fail" and result.section["parse_errors"] == 13
    assert not [f for f in result.findings if f.evidence.get("rule_id", "").startswith("1003")]  # invalid: skipped


def test_errors_in_stock_files_are_medium(tmp_path: Path) -> None:
    stock = tmp_path / "ruleset" / "rules"
    stock.mkdir(parents=True)
    (stock / "0100-broken_rules.xml").write_text(
        '<group name="g,"><rule id="1" level="3" bogus="1"><description>x</description></rule></group>'
    )
    result = audit_ruleset(load_ruleset([stock]), tenant=TenantConfig(), now=NOW)
    assert [f.severity for f in result.findings] == [Severity.MEDIUM]
    assert result.section["status"] == "warn"


def test_empty_ruleset_is_not_assessed(tmp_path: Path) -> None:
    result = audit_ruleset(load_ruleset([tmp_path]), tenant=TenantConfig(), now=NOW)
    assert result.section["status"] == "not_assessed"
    assert any(f.subject == "ruleset-empty" and f.severity is Severity.HIGH for f in result.findings)
    empty = audit_ruleset(Ruleset(), tenant=TenantConfig(), now=NOW)
    assert empty.section["status"] == "not_assessed" and empty.section["rules_parsed"] == 0


def test_clean_local_rules_give_ok() -> None:
    local = local_group(
        '<rule id="100010" level="2"><if_sid>5501</if_sid><hostname type="pcre2">^srv-backup-01\\.example$</hostname>'
        '<user type="pcre2">^svc_backup$</user><description>backup, expires 2027-06-30</description></rule>'
    )
    result = audit_local(local)
    assert result.findings == [] and result.section["status"] == "ok"


# ---- helpers --------------------------------------------------------------------------------------------------------


def cond(tag: str, text: str, **attrs: str) -> RuleCondition:
    return RuleCondition(tag, dict(attrs), text)


@pytest.mark.parametrize(
    ("condition", "expected"),
    [
        (cond("match", "^admin$"), True),
        (cond("match", "admin"), False),
        (cond("match", "^a$|^b$"), True),
        (cond("match", "^a$|b"), False),
        (cond("match", "^a$|"), False),
        (cond("regex", "^\\S+ admin$"), True),
        (cond("regex", "^admin\\$"), False),
        (cond("field", "^a$|^b$", name="x"), True),
        (cond("field", "^(a|b)$", name="x", type="pcre2"), True),
        (cond("field", "^a|b$", name="x", type="pcre2"), False),
        (cond("field", "(?i)^a$", name="x", type="pcre2"), True),
        (cond("field", "^[|]$", name="x", type="pcre2"), True),
        (cond("field", "^[]|]$", name="x", type="pcre2"), True),
        (cond("field", "^a\\z", name="x", type="pcre2"), True),
        (cond("field", "\\Aa$", name="x", type="pcre2"), True),
        (cond("field", "^a\\$", name="x", type="pcre2"), False),
        (cond("field", "^a\\\\$", name="x", type="pcre2"), True),
        (cond("location", "^(web01)"), True),
        (cond("location", "^\\x{28}web01\\x{29}\\x{20}", type="pcre2"), True),
        (cond("location", "^web01"), False),
        (cond("match", "admin", negate="yes"), None),
        (cond("match", "!admin"), None),
        (cond("srcip", "10.0.0.1"), None),
        (cond("decoded_as", "sshd"), None),
        (cond("match", "   "), None),
    ],
)
def test_anchoring(condition: RuleCondition, expected: bool | None) -> None:
    assert audit_module._anchored(condition) is expected


@pytest.mark.parametrize(
    ("condition", "expected"),
    [
        (cond("user", "^svc_backup$"), "svc_backup"),
        (cond("user", "^svc_backup$", type="pcre2"), "svc_backup"),
        (cond("user", "^svc\\x{5f}backup\\x{24}$", type="pcre2"), "svc_backup$"),
        (cond("user", "^caf\\x{c3}\\x{a9}$", type="pcre2"), "caf\u00e9"),
        (cond("user", "^a.b$", type="pcre2"), None),
        (cond("user", "^a\\.b$", type="pcre2"), "a.b"),
        (cond("user", "^\\w+$", type="pcre2"), None),
        (cond("user", "^a|b$"), None),
        (cond("user", "admin"), None),
        (cond("field", "^a\\.b$", name="x"), None),
        (cond("field", "^a\\$b$", name="x"), "a$b"),
        (cond("user", "^svc\\x{5f}backup\\z", type="pcre2"), "svc_backup"),  # hushwatch's own anchoring
        (cond("user", "^svc_backup\\\\z", type="pcre2"), None),  # an escaped backslash, then "z"
    ],
)
def test_literal_extraction(condition: RuleCondition, expected: str | None) -> None:
    assert audit_module._literal(condition) == expected


def test_technique_tactics() -> None:
    assert technique_tactics("T1110.001") == ("credential access",)
    assert "lateral movement" in technique_tactics("t1021.004")
    assert technique_tactics("T9999") == ()


def test_audit_performance() -> None:
    parts = []
    for block in range(30):
        rules = "".join(
            f'<rule id="{200000 + block * 100 + i}" level="{3 + i % 8}"><if_sid>1</if_sid><match>m{i}</match>'
            f"<description>d</description><mitre><id>T1110</id></mitre></rule>"
            for i in range(100)
        )
        parts.append(f'<group name="g{block},authentication_failed,">{rules}</group>')
    parts.append(
        '<group name="c,"><rule id="300000" level="10" frequency="8"><if_matched_group>authentication_failed'
        "</if_matched_group><description>c</description></rule></group>"
    )
    ruleset = parse_rules_text("".join(parts), file="/x/ruleset/rules/0001-perf.xml", is_local=False)
    local = "".join(
        f'<rule id="{100000 + i}" level="0"><if_sid>{200000 + i * 7}</if_sid><match>x{i}</match></rule>'
        for i in range(400)
    )
    parse_rules_text(f'<group name="local,">{local}</group>', file="/x/etc/rules/local_rules.xml", into=ruleset)
    started = time.perf_counter()
    result = audit_ruleset(ruleset, tenant=TenantConfig(), now=NOW)
    assert time.perf_counter() - started < 10
    assert result.section["risky"] == 400


def test_rules_that_never_run_are_not_audited() -> None:
    duplicate_mute = local_group(
        '<rule id="100001" level="3"><if_sid>5502</if_sid><hostname>^h$</hostname><description>d</description></rule>',
        '<rule id="100001" level="0"><if_sid>5710</if_sid>'
        "<description>skipped by Wazuh, expires 2020-01-01</description></rule>",
    )
    result = audit_local(duplicate_mute)
    assert [f.subject.split(":")[0] for f in result.findings] == ["duplicate-rule-ids"]
    chain = (
        '<group name="syslog,sshd,"><rule id="5712" level="0" overwrite="yes"><if_matched_sid>5710</if_matched_sid>'
        "<description>first</description></rule>"
        '<rule id="5712" level="12" overwrite="yes"><if_matched_sid>5710</if_matched_sid><same_source_ip />'
        "<description>second</description><group>authentication_failures,</group></rule></group>"
    )
    assert not [f for f in audit_local(chain).findings if f.kind.startswith("tuning.")]  # only the last one runs


def test_local_paths_accept_directories(tmp_path: Path) -> None:
    folder = tmp_path / "custom"
    folder.mkdir()
    (folder / "0095-custom_rules.xml").write_text(
        '<group name="g,"><rule id="1" level="0"><if_sid>2</if_sid><description>x</description></rule></group>'
    )
    assert load_ruleset([folder]).all_rules[0].is_local is False
    assert load_ruleset([folder], local_paths=[folder]).all_rules[0].is_local is True
