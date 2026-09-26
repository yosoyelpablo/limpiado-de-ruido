"""Safety gates and anchor-field handling of the noise engine (architecture §5.2, §5.4)."""

from __future__ import annotations

import re
from dataclasses import replace
from datetime import date, datetime, timedelta, timezone
from typing import Any

import pytest

from hushwatch import i18n
from hushwatch.analysis import gates as g
from hushwatch.analysis.dispositions import DispositionCounts
from hushwatch.analysis.sketches import SpaceSaving
from hushwatch.config import NoiseSettings, TenantConfig
from hushwatch.i18n import Entity, Message

UTC = timezone.utc
START = datetime(2026, 9, 1, tzinfo=UTC).timestamp()
DAY = 86400.0


def _window(days: int = 21) -> g.Window:
    first = date(2026, 9, 1).toordinal()
    return g.Window(START, START + days * DAY - 60, first, first + days - 1)


def _cond(path: str, value: str, tenant: TenantConfig, *, failure: bool = False, fim: bool = False) -> g.CondFact:
    item = g.all_fields(tenant)[path]
    return g.CondFact(path, value, item, g.classify(item, value, tenant, failure_rule=failure, fim_rule=fim))


def _facts(tenant: TenantConfig, *conds: g.CondFact, days: int = 21, per_day: int = 40, **kw: Any) -> g.CandidateFacts:
    window = _window(days)
    base: dict[str, Any] = {
        "rule_id": "31101",
        "conditions": conds,
        "count_lower": per_day * days,
        "count_upper": per_day * days,
        "rule_total": per_day * days,
        "window": window,
        "rule_level": 5,
        "first_seen": START + 60,
        "last_seen": window.end,
        "daily": {day: per_day for day in window.days()},
        "rule_clusters": per_day * days,
        "dependents": (),
    }
    base.update(kw)
    return g.CandidateFacts(**base)


@pytest.fixture
def tenant() -> TenantConfig:
    return TenantConfig(trusted_entities={"user": ["svc_backup"], "data.srcip": ["10.20.0.15"]})


def _render_all(decision: g.Decision) -> list[str]:
    out = []
    for lang in ("en", "es"):
        for reason in decision.reasons:
            text = i18n.render(reason, lang)
            assert not re.search(r"\{[a-z_0-9]+[^}]*\}", text), text  # every placeholder resolved
            out.append(text)
    return out


# ---- classification ----------------------------------------------------------------------------------------------
def test_classify_roles(tenant: TenantConfig) -> None:
    fields = g.all_fields(tenant)

    def cls(path: str, value: str, **kw: bool) -> g.ValueClass:
        return g.classify(
            fields[path], value, tenant, failure_rule=kw.get("failure", False), fim_rule=kw.get("fim", False)
        )

    assert cls("agent.name", "srv-web-01.example").alone
    internal = cls("data.srcip", "10.20.0.15")
    assert internal.alone and internal.internal and internal.trusted and not internal.attacker
    external = cls("data.srcip", "203.0.113.7")
    assert not external.alone and external.attacker and external.external
    assert cls("data.srcip", "not-an-ip").attacker
    assert not cls("data.dstip", "10.0.0.8").alone  # peer IPs only paired with a host
    assert cls("data.dstip", "198.51.100.77").external
    # accounts narrow a host scope, they never stand alone: a scope on an account follows its credentials anywhere
    service = cls("data.win.eventdata.targetUserName", "CORP\\svc_backup")
    assert not service.alone and service.trusted and not service.attacker
    prefixed = cls("data.dstuser", "svc_monitoring")
    assert not prefixed.alone and prefixed.trusted
    machine = cls("data.win.eventdata.subjectUserName", "DC01$")
    assert not machine.alone and not machine.trusted and not machine.attacker  # not an actor, not trusted
    human = cls("data.win.eventdata.targetUserName", "alice")
    assert not human.alone and human.attacker
    failed = cls("data.srcuser", "svc_backup", failure=True)
    assert not failed.alone and failed.attacker  # usernames in failed logons are attacker-chosen
    subject = cls("data.win.eventdata.subjectUserName", "SRV-01$", failure=True)
    assert not subject.attacker and not subject.alone  # the subject is not chosen, but it is not a place either
    # image paths narrow a host scope; interpreters / generic parents never scope anything
    agent = cls("data.win.eventdata.image", "C:\\\\Program Files\\\\Backup\\\\agent.exe")
    assert not agent.alone and not agent.attacker and not agent.never
    assert cls("data.win.eventdata.image", "agent.exe").attacker
    for generic in (
        "C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe",
        "C:\\Windows\\System32\\svchost.exe",
        "C:\\Windows\\explorer.exe",
        "/usr/bin/python3.11",
        "/bin/bash",
        "RUNDLL32.EXE",
    ):
        assert cls("data.win.eventdata.parentImage", generic).never, generic
    assert cls("syscheck.path", "/var/log/app/app.log", fim=True).alone
    assert cls("file.path", "/tmp/x", fim=False).attacker
    assert cls("data.win.eventdata.commandLine", "backup.exe /all").attacker
    assert not cls("decoder.name", "sshd").alone  # a log-source type alone would mute the rule everywhere
    assert cls("location", "192.0.2.10").host_like
    assert cls("location", "fw01->/var/log/messages").alone
    assert not cls("location", "/var/log/auth.log").alone


def test_service_and_machine_account_helpers() -> None:
    patterns = g.DEFAULT_SERVICE_ACCOUNT_PATTERNS
    assert g.is_service_account("svc_backup@corp.example", patterns)
    assert g.is_service_account("CORP\\\\service-sql", patterns)
    assert not g.is_service_account("svchost", patterns)
    assert not g.is_service_account("alice", patterns)
    assert g.is_machine_account("WS07$") and not g.is_machine_account("$")
    assert g.is_own_machine_account("SRV-BACKUP-01$", "srv-backup-01.corp.example")
    assert not g.is_own_machine_account("DC01$", "srv-backup-01.corp.example")
    assert g.is_full_path("/usr/bin/rsync") and g.is_full_path("\\\\fileserver\\share\\x.exe")
    assert not g.is_full_path("C:\\temp\\*.exe")


# ---- extraction --------------------------------------------------------------------------------------------------
def test_extract_flat_and_nested_documents(tenant: TenantConfig) -> None:
    spec = g.spec_for("wazuh4", tenant)
    flat = {
        "agent.id": "001",
        "agent.name": "srv-web-01.example",
        "predecoder.hostname": "srv-web-01.example",
        "location": "/var/log/auth.log",
        "decoder.name": "sshd",
        "data.srcip": "203.0.113.7",
        "data.srcuser": "-",
        "data.dstuser": ["svc_backup", "svc_backup", "(NULL)", 7, True, {"x": 1}],
        "data.win.eventdata.commandLine": "x" * (g.MAX_VALUE_LEN + 1),
        "rule.groups": ["syslog", "sshd", "authentication_failed"],
    }
    nested = {
        "agent": {"id": "001", "name": "srv-web-01.example"},
        "predecoder": {"hostname": "srv-web-01.example"},
        "location": "/var/log/auth.log",
        "decoder": {"name": "sshd"},
        "data": {"srcip": "203.0.113.7", "srcuser": "-", "dstuser": ["svc_backup", "svc_backup", "(NULL)", 7, True]},
        "rule": {"groups": ["syslog", "sshd", "authentication_failed"]},
    }
    for doc in (flat, nested):
        out = g.extract(spec, doc)
        values = [(item.path, value) for item, value in out.values]
        assert out.host is not None and out.host[1] == "srv-web-01.example"
        assert ("data.srcip", "203.0.113.7") in values
        assert ("data.dstuser", "svc_backup") in values and ("data.dstuser", "7") in values
        assert not any(path == "data.srcuser" for path, _ in values)  # "-" carries no information
        assert not any(path == "predecoder.hostname" for path, _ in values)  # same as the host
        assert not any(path == "data.win.eventdata.commandLine" for path, _ in values)  # oversized
        assert out.failure and not out.fim


def test_extract_syslog_device_behind_agent_000(tenant: TenantConfig) -> None:
    spec = g.spec_for("wazuh4", tenant)
    doc = {
        "agent.id": "000",
        "agent.name": "wazuh-manager",
        "predecoder.hostname": "fw-edge-01",
        "location": "192.0.2.10",
        "data.srcip": "198.51.100.23",
    }
    out = g.extract(spec, doc, ("firewall",))
    assert out.host is not None and out.host[0].path == "predecoder.hostname" and out.host[1] == "fw-edge-01"
    assert all(item.path != "agent.name" for item, _ in out.values)  # the manager is not the device
    assert ("location", "192.0.2.10") in [(i.path, v) for i, v in out.values]
    static = g.extract(spec, {"agent.name": "ws-01", "location": "EventChannel"})
    assert all(item.path != "location" for item, _ in static.values)


def test_extract_ecs_context_flags(tenant: TenantConfig) -> None:
    spec = g.spec_for("ecs", tenant)
    doc = {"host.name": "ws-07.corp.example", "event.outcome": "failure", "user.name": "alice"}
    out = g.extract(spec, doc)
    assert out.failure and out.host is not None and out.host[1] == "ws-07.corp.example"
    fim = g.extract(spec, {"host.name": "h", "event.module": "file_integrity", "file.path": "/etc/app.conf"})
    assert fim.fim
    assert g.detect_profile({"decoder.name": "sshd"}) == "wazuh4"
    assert g.detect_profile({"ecs.version": "8.11.0"}) == "ecs"
    assert g.detect_profile({"message": "x"}) == "auto"


def test_cluster_hash_ignores_volatile_tokens(tenant: TenantConfig) -> None:
    item = g.all_fields(tenant)["data.win.eventdata.commandLine"]
    one = [(item, "backup.exe /job {1b4e28ba-2fa1-11d2-883f-0016d3cca427} /pid 4312")]
    two = [(item, "backup.exe /job {9f1c2d3e-0000-11d2-883f-0016d3cca427} /pid 8810")]
    assert g.cluster_hash("60106", one, 7) == g.cluster_hash("60106", two, 7)
    assert g.cluster_hash("60106", one, 7) != g.cluster_hash("60106", one, 8)
    assert g.cluster_hash("60106", one, 7) != g.cluster_hash("5710", one, 7)


# ---- supporting structures ---------------------------------------------------------------------------------------
def test_high_alert_index_window_and_cap() -> None:
    index = g.HighAlertIndex(max_values=2)
    index.add("host", "DC01.corp.example", 1000)
    index.add("host", "dc01.corp.example", 1030, count=2)
    index.add("ip", "203.0.113.7", 500)
    index.add("user", "mallory", 1)  # beyond the cap
    assert index.truncated
    assert index.count_near("host", "dc01.CORP.example", 1024, 24) == 3
    assert index.count_near("host", "dc01.corp.example", 1050, 24) == 2
    assert index.count_near("ip", "203.0.113.7", 600, 24) == 0
    assert index.count_near("user", "mallory", 1, 24) == 0
    other = g.HighAlertIndex()
    other.add("ip", "203.0.113.7", 510)
    index.merge(other)
    assert index.count_near("ip", "203.0.113.7", 505, 24) == 2
    assert dict(index.hours("ip", "203.0.113.7")) == {500: 1, 510: 1}


def test_beacon_like() -> None:
    sketch: SpaceSaving[str] = SpaceSaving(4)
    for hour in range(48):  # every hour for two days
        sketch.add("198.51.100.77", hour=500_000 + hour)
    for hour in range(0, 24 * 7, 14):  # 12 hours scattered over a week
        sketch.add("198.51.100.78", hour=500_000 + hour)
    for hour in range(11):
        sketch.add("198.51.100.79", hour=500_000 + hour)
    entries = {e.key: e for e in sketch.entries()}
    assert g.beacon_like(entries["198.51.100.77"])
    assert not g.beacon_like(entries["198.51.100.78"])
    assert not g.beacon_like(entries["198.51.100.79"])


def test_day_index_uses_tenant_local_dates() -> None:
    buenos_aires = TenantConfig(timezone="America/Argentina/Buenos_Aires").tz
    index = g.DayIndex(buenos_aires)
    ts = datetime(2026, 9, 2, 1, 30, tzinfo=UTC).timestamp()  # 22:30 on Sep 1st local (UTC-3)
    assert index.day(ts) == date(2026, 9, 1).toordinal()
    assert index.day(ts) == date(2026, 9, 1).toordinal()  # cached
    assert index.start_of(date(2026, 9, 1).toordinal()) == datetime(2026, 9, 1, 3, tzinfo=UTC).timestamp()


# ---- gates -------------------------------------------------------------------------------------------------------
def test_clean_candidate_is_tune_and_every_gate_is_explained(tenant: TenantConfig) -> None:
    facts = _facts(tenant, _cond("agent.name", "srv-web-01.example", tenant), _cond("data.srcip", "10.20.0.15", tenant))
    decision = g.evaluate(facts, tenant.noise, tenant)
    assert decision.verdict == "tune" and decision.action == "demote"
    gates = {o.gate for o in decision.outcomes}
    assert {
        "share",
        "level",
        "tp",
        "novelty",
        "persistence",
        "burst",
        "co_occurrence",
        "sensitive",
        "dependents",
    } <= gates
    assert all(o.passed for o in decision.outcomes)
    texts = _render_all(decision)
    assert any("100%" in t for t in texts)  # numbers are in the reasons
    assert any("Presente en 21 de 21 días" in t for t in texts)  # Spanish catalog


def test_learning(tenant: TenantConfig) -> None:
    facts = _facts(tenant, _cond("agent.name", "h", tenant), days=5)
    decision = g.evaluate(facts, tenant.noise, tenant)
    assert decision.verdict == "learning" and [o.gate for o in decision.outcomes] == ["learning"]


@pytest.mark.parametrize(
    ("level", "verdict"), [(9, "tune"), (10, "do_not_tune"), (12, "do_not_tune"), (None, "do_not_tune")]
)
def test_level_gate(tenant: TenantConfig, level: int | None, verdict: str) -> None:
    facts = _facts(tenant, _cond("data.srcip", "10.20.0.15", tenant), rule_level=level)
    assert g.evaluate(facts, tenant.noise, tenant).verdict == verdict


def test_true_positive_dispositions_block(tenant: TenantConfig) -> None:
    anchor = _cond("data.srcip", "10.20.0.15", tenant)
    scoped = _facts(tenant, anchor, dispositions=DispositionCounts(fp=30, tp=1), dispositions_loaded=True)
    decision = g.evaluate(scoped, tenant.noise, tenant)
    assert decision.verdict == "do_not_tune" and decision.failed("tp")
    rule_wide = _facts(tenant, anchor, tp_rule_wide=2, dispositions_loaded=True)
    assert g.evaluate(rule_wide, tenant.noise, tenant).failed("tp_rule_wide")


def test_novelty_persistence_and_burst(tenant: TenantConfig) -> None:
    anchor = _cond("data.srcip", "10.20.0.15", tenant)
    window = _window()
    novel = _facts(tenant, anchor, first_seen=window.end - 2 * DAY)
    assert g.evaluate(novel, tenant.noise, tenant).failed("novelty")
    sparse_daily = {day: 40 for i, day in enumerate(window.days()) if i % 3 == 0}
    sparse = _facts(tenant, anchor, daily=sparse_daily)
    decision = g.evaluate(sparse, tenant.noise, tenant)
    assert decision.verdict == "investigate" and decision.failed("persistence")
    bursty_daily = {day: 40 for day in window.days()}
    bursty_daily[window.last_day - 1] = 200  # 5x the median
    bursty = _facts(tenant, anchor, daily=bursty_daily)
    decision = g.evaluate(bursty, tenant.noise, tenant)
    assert decision.verdict == "investigate" and decision.failed("burst")
    assert decision.failed("burst") and not decision.failed("persistence")


def test_co_occurrence_and_truncated_index(tenant: TenantConfig) -> None:
    anchor = _cond("data.srcip", "10.0.5.23", tenant)
    hit = _facts(tenant, anchor, co_hits=(g.CoHit("ip", "10.0.5.23", 1),))
    decision = g.evaluate(hit, tenant.noise, tenant)
    assert decision.verdict == "investigate" and decision.co_occurs
    reason = next(o.message for o in decision.outcomes if o.gate == "co_occurrence")
    assert isinstance(reason.params["entity"], Entity) and reason.params["entity"].value == "10.0.5.23"
    truncated = _facts(tenant, anchor, co_index_truncated=True)
    assert g.evaluate(truncated, tenant.noise, tenant).verdict == "investigate"


def test_beacon_gate(tenant: TenantConfig) -> None:
    host = _cond("agent.name", "ws-07.corp.example", tenant)
    facts = _facts(tenant, host, beacons=(g.BeaconHit("198.51.100.77", 504, 504),))
    decision = g.evaluate(facts, tenant.noise, tenant)
    assert decision.verdict == "investigate" and decision.failed("beacon")


def test_sensitive_tactics(tenant: TenantConfig) -> None:
    settings = tenant.noise
    host = _cond("agent.name", "srv-backup-01.corp.example", tenant)
    svc = _cond("data.win.eventdata.targetUserName", "svc_backup", tenant)
    human = _cond("data.win.eventdata.targetUserName", "alice", tenant)
    tactics = ("Defense Evasion", "Initial Access")
    # no evidence: investigate
    no_evidence = _facts(tenant, host, svc, tactics=tactics, rule_level=3)
    assert g.evaluate(no_evidence, settings, tenant).verdict == "investigate"
    # trusted internal anchor + strong FP evidence: tune
    evidence = DispositionCounts(fp=20, btp=10)
    ok = _facts(tenant, host, svc, tactics=tactics, rule_level=3, dispositions=evidence, dispositions_loaded=True)
    decision = g.evaluate(ok, settings, tenant)
    assert decision.verdict == "tune", _render_all(decision)
    # the same evidence on a human account is not enough (not a trusted anchor)
    human_facts = _facts(tenant, host, human, tactics=tactics, dispositions=evidence, dispositions_loaded=True)
    assert g.evaluate(human_facts, settings, tenant).verdict == "investigate"
    # small n is never "100% FP"
    small = _facts(tenant, host, svc, tactics=tactics, dispositions=DispositionCounts(fp=9), dispositions_loaded=True)
    assert g.evaluate(small, settings, tenant).verdict == "investigate"
    # shortnames and names both match
    assert g.sensitive_tactics(["credential-access", "Discovery", "Credential Access"], settings) == [
        "Credential Access",
        "credential-access",
    ]


def test_aggregate_for_duplicate_storms_of_sensitive_rules(tenant: TenantConfig) -> None:
    host = _cond("agent.name", "srv-web-01.example", tenant)
    facts = _facts(tenant, host, tactics=("Credential Access",), rule_clusters=40)  # 840 alerts, 40 clusters
    decision = g.evaluate(facts, tenant.noise, tenant)
    assert decision.verdict == "aggregate" and decision.failed("aggregate")
    not_dup = replace(facts, rule_clusters=800)
    assert g.evaluate(not_dup, tenant.noise, tenant).verdict == "investigate"


def test_external_anchor_routes_to_fix_at_source(tenant: TenantConfig) -> None:
    host = _cond("agent.name", "srv-web-01.example", tenant)
    public = _cond("data.srcip", "198.51.100.23", tenant)
    facts = _facts(tenant, host, public)
    decision = g.evaluate(facts, tenant.noise, tenant)
    assert decision.verdict == "fix_at_source" and decision.fix_kind == "exposure"
    # still fix_at_source for a sensitive rule (no suppression is proposed, only closing the exposure)
    sensitive = _facts(tenant, host, public, tactics=("Credential Access",))
    assert g.evaluate(sensitive, tenant.noise, tenant).verdict == "fix_at_source"
    # ...but a NEW public address is investigated first
    novel = _facts(tenant, host, public, first_seen=_window().end - DAY)
    assert g.evaluate(novel, tenant.noise, tenant).verdict == "investigate"


def test_fim_and_rootcheck_route_to_fix_at_source(tenant: TenantConfig) -> None:
    path = _cond("syscheck.path", "/var/log/app/app.log", tenant, fim=True)
    fim = _facts(tenant, path, fim=True, tactics=("Impact",), rule_level=7)
    decision = g.evaluate(fim, tenant.noise, tenant)
    assert decision.verdict == "fix_at_source" and decision.fix_kind == "fim"
    check = _facts(tenant, _cond("agent.name", "h", tenant), check=True)
    assert g.evaluate(check, tenant.noise, tenant).fix_kind == "check"
    bursty = dict(fim.daily)
    bursty[fim.window.last_day] = 1000
    assert g.evaluate(replace(fim, daily=bursty), tenant.noise, tenant).verdict == "investigate"


def test_dependents_require_review(tenant: TenantConfig) -> None:
    anchor = _cond("data.srcip", "10.20.0.15", tenant)
    with_deps = g.evaluate(_facts(tenant, anchor, dependents=("5712", "5720")), tenant.noise, tenant)
    assert with_deps.verdict == "tune" and with_deps.action == "review"
    broken = g.evaluate(_facts(tenant, anchor, dependents=(), dependents_error=True), tenant.noise, tenant)
    assert broken.action == "review"
    unknown = g.evaluate(_facts(tenant, anchor, dependents=None), tenant.noise, tenant)
    assert unknown.action == "demote"
    assert any(o.message.key == "noise.reason.dependents_unknown" for o in unknown.outcomes)


def test_low_severity_and_regularity_are_never_benign_evidence(tenant: TenantConfig) -> None:
    """A perfectly regular level-3 stream from a public address is not made tunable by being quiet."""
    host = _cond("agent.name", "ws-07.corp.example", tenant)
    public = _cond("data.dstip", "198.51.100.77", tenant)
    facts = _facts(tenant, host, public, rule_level=3, beacons=(g.BeaconHit("198.51.100.77", 504, 504),))
    assert g.evaluate(facts, tenant.noise, tenant).verdict == "investigate"


def test_every_noise_message_has_spanish() -> None:
    import hushwatch.analysis.backtest
    import hushwatch.analysis.noise

    assert hushwatch.analysis.backtest and hushwatch.analysis.noise  # imported for their catalogs

    noise_keys = [key for key in i18n._CATALOG if key.startswith("noise.")]
    assert len(noise_keys) > 50 and all(i18n.has(key) for key in noise_keys)
    missing = [key for key in noise_keys if "es" not in i18n._CATALOG[key]]
    assert missing == []
    for key in noise_keys:
        if key.startswith("noise."):
            placeholders = {lang: set(re.findall(r"\{(\w+)", i18n._CATALOG[key][lang])) for lang in ("en", "es")}
            assert placeholders["es"] == placeholders["en"], key


def test_reason_messages_carry_numbers(tenant: TenantConfig) -> None:
    facts = _facts(tenant, _cond("data.srcip", "10.20.0.15", tenant), per_day=7)
    decision = g.evaluate(facts, NoiseSettings(persistence=0.9), tenant)
    persistent = next(o.message for o in decision.outcomes if o.gate == "persistence")
    assert isinstance(persistent, Message)
    assert persistent.params["present"] == 21 and persistent.params["days"] == 21
    assert i18n.render(persistent, "es").startswith("Presente en 21 de 21 días")
    assert timedelta(hours=24) == tenant.noise.co_occurrence_window


@pytest.mark.parametrize(
    "value",
    ["10.20.0.15", "203.0.113.7", "192.168.1.1", "172.31.255.255", "172.32.0.1", "010.1.1.1", "1.2.3", "::1",
     "2001:db8::1", "fc00::5", "not-an-ip", "", " 10.0.0.1", "10.0.0.1 ", "999.1.1.1", "0.0.0.0"],
)  # fmt: skip
def test_ip_classifier_agrees_with_tenant(value: str) -> None:
    tenant = TenantConfig()
    classifier = g.IpClassifier(tenant)
    assert classifier.kind(value) == g.ip_kind(value, tenant)
    assert classifier.kind(value) == g.ip_kind(value, tenant)  # cached


# ---- adversarial classification -------------------------------------------------------------------------
def test_machine_accounts_are_never_trusted_even_with_a_star_dollar_pattern() -> None:
    tenant = TenantConfig()
    assert "*$" not in tenant.noise.service_account_patterns  # no longer shipped by default
    item = g.all_fields(tenant)["data.win.eventdata.targetUserName"]
    patterns = (*tenant.noise.service_account_patterns, "*$")  # even if a user configures it
    machine = g.classify(item, "EVIL$", tenant, failure_rule=False, fim_rule=False, service_patterns=patterns)
    assert not machine.trusted and not machine.alone  # any domain user can create "EVIL$"
    configured = TenantConfig(trusted_entities={"user": ["backup01$"]})
    explicit = g.classify(item, "BACKUP01$", configured, failure_rule=False, fim_rule=False)
    assert explicit.trusted and not explicit.alone  # explicit configuration still counts, but never alone
    service = g.classify(item, "svc_sql", tenant, failure_rule=False, fim_rule=False, service_patterns=patterns)
    assert service.trusted and not service.alone


def test_padded_addresses_are_not_internal() -> None:
    tenant = TenantConfig()
    assert g.ip_kind("10.0.0.5", tenant) == "internal"
    assert g.ip_kind(" 10.0.0.5", tenant) == "invalid" and g.ip_kind("10.0.0.5 ", tenant) == "invalid"
    item = g.all_fields(tenant)["data.srcip"]
    assert not g.classify(item, "10.0.0.5 ", tenant, failure_rule=False, fim_rule=False).alone


@pytest.mark.parametrize(
    ("value", "generic"),
    [
        ("C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe", True),
        ("C:\\Windows\\System32\\cmd.exe", True),
        ('"C:\\Windows\\System32\\rundll32.exe" shell32.dll,Control_RunDLL', True),
        ("C:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\POWERSHELL.EXE", True),
        ("C:\\Windows\\System32\\svchost.exe", True),
        ("C:\\Windows\\explorer.exe", True),
        ("/usr/bin/python3.11", True),
        ("/bin/sh", True),
        ("/usr/bin/bash", True),
        ("pwsh", True),
        ("", True),
        ("C:\\Program Files\\Backup\\agent.exe", False),
        ("/opt/app/bin/worker", False),
        ("C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE", False),
    ],
)
def test_generic_process_detection(value: str, generic: bool) -> None:
    assert g.is_generic_process(value) is generic


def test_process_creation_detection(tenant: TenantConfig) -> None:
    spec = g.spec_for("wazuh4", tenant)
    sysmon = {
        "agent.name": "ws-01",
        "data.win.system.eventID": "1",
        "data.win.system.providerName": "Microsoft-Windows-Sysmon",
    }
    assert g.extract(spec, sysmon).process
    assert g.extract(spec, {"agent.name": "ws-01", "data.win.system.eventID": "4688"}).process
    assert g.extract(spec, {"agent.name": "ws-01"}, ("windows", "sysmon_event1")).process
    assert g.extract(spec, {"agent.name": "ws-01"}, ("audit", "audit_command")).process
    not_sysmon = {"agent.name": "ws-01", "data.win.system.eventID": "1", "data.win.system.providerName": "Other"}
    assert not g.extract(spec, not_sysmon).process
    ecs = g.spec_for("ecs", tenant)
    assert g.extract(ecs, {"host.name": "h", "event.category": ["process"], "event.type": ["start"]}).process
    assert not g.extract(ecs, {"host.name": "h", "event.category": ["process"], "event.type": ["end"]}).process


def test_process_creation_rules_are_sensitive(tenant: TenantConfig) -> None:
    host = _cond("agent.name", "srv-app-01.corp.example", tenant)
    decision = g.evaluate(_facts(tenant, host, process_creation=True), NoiseSettings(), tenant)
    assert decision.verdict == "investigate" and decision.failed("sensitive")
    rendered = _render_all(decision)
    assert any("process creation" in text for text in rendered)
    assert any("creación de procesos" in text for text in rendered)
    user = _cond("data.win.eventdata.targetUserName", "svc_backup", tenant)
    counts = DispositionCounts(fp=30)
    trusted = g.evaluate(
        _facts(tenant, host, user, process_creation=True, dispositions=counts), NoiseSettings(), tenant
    )
    assert trusted.verdict == "tune"  # a trusted service account on one host, with FP evidence


def test_manager_name_is_never_a_host(tenant: TenantConfig) -> None:
    spec = g.spec_for("wazuh4", tenant)
    doc = {"agent.id": "000", "agent.name": "wazuh-manager", "location": "10.10.0.1", "data.srcip": "10.0.0.9"}
    out = g.extract(spec, doc)
    assert out.host is not None and out.host[0].path == "location" and out.host[1] == "10.10.0.1"  # the sender
    assert all(item.path != "agent.name" for item, _ in out.values)
    long_host = dict(doc, **{"predecoder.hostname": "x" * (g.MAX_VALUE_LEN + 1)})
    assert g.extract(spec, long_host).host == out.host  # an oversized hostname never falls back to the manager
    local = dict(doc, location="/var/log/auth.log")  # the manager's own log file: no device at all
    assert g.extract(spec, local).host is None
    assert all(item.path != "agent.name" for item, _ in g.extract(spec, local).values)


def test_duty_cycled_beacons_are_beacon_like() -> None:
    sketch: SpaceSaving[str] = SpaceSaving(8)
    base = 500_000
    for day in range(14):  # every hour 08-18 (10 consecutive hours) for two weeks
        for hour in range(8, 18):
            sketch.add("198.51.100.77", hour=base + day * 24 + hour)
    for day in range(14):  # a person browsing: 3 scattered hours a day
        for hour in (9, 13, 16):
            sketch.add("198.51.100.78", hour=base + day * 24 + hour)
    for day in range(14):  # a nightly job: one hour a day
        sketch.add("198.51.100.79", hour=base + day * 24 + 2)
    entries = {e.key: e for e in sketch.entries()}
    assert g.beacon_like(entries["198.51.100.77"])
    assert not g.beacon_like(entries["198.51.100.78"])
    assert not g.beacon_like(entries["198.51.100.79"])


def test_logon_type_is_a_companion(tenant: TenantConfig) -> None:
    fields = g.all_fields(tenant)
    assert fields["data.win.eventdata.targetUserName"].companion == "data.win.eventdata.logonType"
    context = fields["data.win.eventdata.logonType"]
    cls = g.classify(context, "4", tenant, failure_rule=False, fim_rule=False)
    assert not cls.alone and not cls.attacker
    assert g.companion_value({"data.win.eventdata.logonType": "4"}, "data.win.eventdata.logonType") == "4"
    assert g.companion_value({"data.win.eventdata.logonType": ["3", "10"]}, "data.win.eventdata.logonType") is None
    assert g.companion_value({"data.win.eventdata.logonType": "-"}, "data.win.eventdata.logonType") is None


def test_learning_needs_elapsed_days_not_just_dates(tenant: TenantConfig) -> None:
    first = date(2026, 9, 1).toordinal()
    start = datetime(2026, 9, 1, 23, 0, tzinfo=UTC).timestamp()
    short = g.Window(start, start + 5 * DAY + 2 * 3600, first, first + 6)  # 5 days 2 hours over 7 dates
    assert short.n_days == 7 and short.is_learning(7)
    host = _cond("agent.name", "srv-app-01.corp.example", tenant)
    facts = _facts(tenant, host, window=short)
    assert g.evaluate(facts, NoiseSettings(), tenant).verdict == "learning"
    assert not _window(7).is_learning(7)


def test_cooccurrence_keys_link_spellings_of_the_same_entity() -> None:
    index = g.HighAlertIndex()
    index.add("ip", "::ffff:203.0.113.5", 100)
    index.add("user", "CORP\\\\Mallory", 100)
    index.add("host", "SRV-01.corp.example", 100)
    index.add("host", "10.0.0.7", 100)
    assert index.count_near("ip", "203.0.113.5", 100, 1) == 1
    assert index.count_near("user", "mallory@corp.example", 100, 1) == 1
    assert index.count_near("host", "srv-01", 100, 1) == 1
    assert index.count_near("host", "10.0.0.7", 100, 1) == 1 and index.count_near("host", "10", 100, 1) == 0
