"""Report renderers: content, structure, languages, statuses, redaction and the multi-tenant summary.

Every report here is built by hand with synthetic data only (RFC 5737 / RFC 1918 IPs, *.example hosts,
fake users).
"""

from __future__ import annotations

import io
import json
import re
import time
from datetime import datetime, timedelta, timezone
from html.parser import HTMLParser
from typing import Any

import pytest
from rich.console import Console

from hushwatch.i18n import Entity, M, register
from hushwatch.models import SCHEMA_VERSION, Confidence, DataBasis, Finding, Report, Severity
from hushwatch.redact import Redactor
from hushwatch.report import FORMATS, print_console, print_console_many, render, render_many
from hushwatch.report.common import (
    RenderContext,
    domain_statuses,
    normalize_lang,
    prepare_context,
    sanitize,
    sparkline_text,
)
from hushwatch.report.html import render_html, sparkline_svg
from hushwatch.report.markdown import md_escape

UTC = timezone.utc
NOW = datetime(2026, 9, 25, 10, 0, tzinfo=UTC)

register(
    {
        "testrep.tune.title": {
            "en": "Rule {rule} on {host}: scheduled {user} logons (safe to tune)",
            "es": "Regla {rule} en {host}: inicios de sesión programados de {user} (ajuste seguro)",
        },
        "testrep.tune.reason": {
            "en": "{share:.0%} of the rule volume comes from {user} on {host} every night for {days} days",
            "es": "El {share:.0%} del volumen de la regla proviene de {user} en {host} cada noche durante {days} días",
        },
        "testrep.scanner.title": {
            "en": "Rule 5710: internal scanner {ip} (tune, review correlation)",
            "es": "Regla 5710: escáner interno {ip} (ajustar, revisar correlación)",
        },
        "testrep.bruteforce.title": {
            "en": "Rule 5710: new external source {ip} against {host}",
            "es": "Regla 5710: nuevo origen externo {ip} contra {host}",
        },
        "testrep.gate.novel": {
            "en": "Novel: first seen {ago} ago, after the first quarter of the window",
            "es": "Novedoso: visto por primera vez hace {ago}, después del primer cuarto de la ventana",
        },
        "testrep.gate.external": {
            "en": "External anchor {ip}: restrict exposure instead of muting",
            "es": "Ancla externa {ip}: restrinja la exposición en lugar de silenciar",
        },
        "testrep.silent.title": {
            "en": "{host} stopped sending {ls} events {ago} ago",
            "es": "{host} dejó de enviar eventos de {ls} hace {ago}",
        },
        "testrep.tamper.title": {
            "en": "Possible tampering: audit log cleared on {host} before it went silent",
            "es": "Posible manipulación: se borró el registro de auditoría en {host} antes de quedar en silencio",
        },
        "testrep.reco.heartbeat": {
            "en": "Check the agent on {host} and restore collection; add a heartbeat.",
            "es": "Revise el agente en {host} y restablezca la recolección; agregue un heartbeat.",
        },
        "testrep.generic": {"en": "{what}", "es": "{what}"},
        "testrep.warning": {
            "en": "Timestamps without offset were read as {tz}",
            "es": "Las marcas de tiempo sin desfase se leyeron como {tz}",
        },
    }
)

HOSTS = ("dc01.corp.example", "dc02.corp.example", "srv-web-02.example", "srv-backup-01.corp.example")
USERS = ("svc_backup", "alice")
IPS = ("10.20.0.15", "203.0.113.50", "198.51.100.23", "192.0.2.77", "10.30.0.99")


def _f(kind: str, severity: Severity, subject: str, title: Any, **kw: Any) -> Finding:
    return Finding(
        kind=kind,
        domain=kind.split(".", 1)[0],
        title=title,
        severity=severity,
        subject=subject,
        tenant="acme",
        **kw,
    )


def build_findings() -> list[Finding]:
    """One finding of every kind in the architecture registry (§2.1)."""
    dc02 = Entity("host", "dc02.corp.example")
    backup = Entity("host", "srv-backup-01.corp.example")
    web02 = Entity("host", "srv-web-02.example")
    svc = Entity("user", "svc_backup")
    daily = [120, 118, 131, 125, 119, 122, 127, 130, 121, 118, 124, 126, 129, 0, 0]
    return [
        _f(
            "noise.tune",
            Severity.MEDIUM,
            "rule:60106|agent:srv-backup-01.corp.example|user:svc_backup",
            M("testrep.tune.title", rule="60106", host=backup, user=svc),
            reasons=[M("testrep.tune.reason", share=0.84, user=svc, host=backup, days=21)],
            evidence={
                "rule_id": "60106",
                "conditions": [
                    {"field": "agent.name", "value": backup},
                    {"field": "data.win.eventdata.targetUserName", "value": svc},
                ],
                "hidden_per_day": 412.5,
                "share_of_rule": 0.84,
                "hidden_analyst_facing": 0,
                "agents_affected": 1,
                "expires": "2026-12-24",
                "daily": daily,
            },
            recommendation=M("testrep.generic", what="Deploy the demote rule after review."),
            confidence=Confidence.HIGH,
            score=412.5,
        ),
        _f(
            "noise.tune",
            Severity.MEDIUM,
            "rule:5710|srcip:10.20.0.15",
            M("testrep.scanner.title", ip=Entity("ip", "10.20.0.15")),
            evidence={
                "rule_id": "5710",
                "conditions": [{"field": "data.srcip", "value": Entity("ip", "10.20.0.15")}],
                "hidden_per_day": 88.0,
                "share_of_rule": 0.61,
                "hidden_analyst_facing": 31,
                "dependents": ["5712", "5720"],
                "expires": "2026-12-24",
            },
            score=31.0,
        ),
        _f(
            "noise.investigate",
            Severity.HIGH,
            "rule:5710|srcip:203.0.113.50",
            M("testrep.bruteforce.title", ip=Entity("ip", "203.0.113.50"), host=web02),
            reasons=[
                M("testrep.gate.novel", ago="2d"),
                M("testrep.gate.external", ip=Entity("ip", "203.0.113.50")),
            ],
            evidence={"first_seen": "2026-09-23T08:00:00Z", "per_day": 5400.0, "co_occurs_with": ["5712"]},
        ),
        _f(
            "noise.fix_at_source",
            Severity.LOW,
            "rule:550|file:/var/log/app/app.log",
            "FIM noise on /var/log/app/app.log: ignore the path in agent.conf",
            evidence={"file": Entity("file", "/var/log/app/app.log"), "per_day": 960},
        ),
        _f(
            "noise.aggregate",
            Severity.LOW,
            "rule:60122",
            "Rule 60122 duplicates: aggregate with frequency/timeframe instead of muting",
            evidence={"clusters_per_day": 3.2, "per_day": 4100},
        ),
        _f("noise.do_not_tune", Severity.INFO, "rule:100200", "Rule 100200 is level 12: never tuned automatically"),
        _f(
            "silence.silent",
            Severity.HIGH,
            "agent:srv-backup-01.corp.example|ls:Microsoft-Windows-Sysmon/Operational",
            M("testrep.silent.title", host=backup, ls="Microsoft-Windows-Sysmon/Operational", ago="2d"),
            evidence={
                "observed": 0,
                "expected": 2210.4,
                "p0": 1.2e-9,
                "last_seen": "2026-09-23T09:58:00Z",
                "daily": [2300, 2250, 2190, 2280, 2240, 0, 0],
            },
            recommendation=M("testrep.reco.heartbeat", host=backup),
            confidence=Confidence.MEDIUM,
        ),
        _f(
            "silence.drop",
            Severity.HIGH,
            "ls:/var/log/auth.log",
            "Volume of /var/log/auth.log dropped by 92%",
            evidence={"observed": 120, "expected": 1510.0, "p": 0.00002, "ratio": 0.08},
        ),
        _f("silence.decay", Severity.MEDIUM, "agent:srv-web-01.example", "srv-web-01.example: slow decline (x0.41)"),
        _f(
            "silence.rule_dark", Severity.MEDIUM, "rule:19004|agent:srv-db-02.example", "Heartbeat rule 19004 went dark"
        ),
        _f(
            "silence.field_lost",
            Severity.MEDIUM,
            "ls:fw-edge-01|field:data.dstport",
            "Field data.dstport vanished",
            evidence={"presence_before": 0.99, "presence_after": 0.0},
        ),
        _f(
            "silence.tampering",
            Severity.CRITICAL,
            "agent:dc02.corp.example",
            M("testrep.tamper.title", host=dc02),
            reasons=["EventID 1102 on dc02.corp.example 20 min before the silence (T1070.001)"],
            evidence={"precursor": "1102", "techniques": ["T1070.001", "T1562.002"], "gap_hours": 30},
            confidence=Confidence.HIGH,
        ),
        _f("silence.unmonitorable", Severity.MEDIUM, "agent:fw-edge-01", "fw-edge-01 is too sparse to monitor in 4h"),
        _f("pipeline.global_silence", Severity.CRITICAL, "tenant", "40% of always-on agents went silent together"),
        _f("pipeline.agent_disconnected", Severity.HIGH, "agent:lap-013", "Agent lap-013 disconnected for 9d"),
        _f("pipeline.agent_no_data", Severity.HIGH, "agent:srv-app-03", "Agent srv-app-03 alive but sends nothing"),
        _f("pipeline.lag", Severity.MEDIUM, "agent:srv-db-01", "Ingest lag p95 42 min on srv-db-01"),
        _f("pipeline.clock_skew", Severity.LOW, "clock", "3 events have future timestamps"),
        _f("pipeline.manager_drops", Severity.HIGH, "manager", "analysisd dropped 1,204 events"),
        _f(
            "coverage.missing_source",
            Severity.HIGH,
            "agent:srv-app-01|ls:Microsoft-Windows-Sysmon/Operational",
            "srv-app-01 sends no Sysmon while 95% of its peers do",
        ),
        _f(
            "coverage.missing_event_type",
            Severity.MEDIUM,
            "agent:srv-app-02|ls:Security|code:4688",
            "srv-app-02: 4624 present but 4688 never seen (process creation auditing off)",
        ),
        _f(
            "tuning.risky_suppression",
            Severity.HIGH,
            "rule:100050",
            "Rule 100050 mutes 5710 with only if_sid and breaks correlation rule 5712",
        ),
        _f("tuning.expired", Severity.MEDIUM, "rule:100051", "Suppression 100051 expired on 2026-08-01"),
        _f("assessment.learning", Severity.INFO, "rule:60200", "Rule 60200: only 5 days of history (learning)"),
    ]


def build_sections() -> dict[str, dict[str, Any]]:
    """Sections in the shapes of architecture §2.2."""
    return {
        "noise": {
            "status": "warn",
            "totals": {
                "alerts": 184233,
                "analyst_facing": 5120,
                "rules": 142,
                "days": 21.0,
                "clusters": 1830,
                "top5_share": 0.62,
            },
            "rules": [
                {
                    "rule_id": "60106",
                    "description": "Windows logon success",
                    "level": 3,
                    "total": 41000,
                    "per_day": 1952.4,
                    "analyst_facing": 0,
                    "share": 0.22,
                    "clusters": 21,
                    "days_active": 21,
                    "days": 21,
                    "top_anchor": {
                        "field": "agent.name",
                        "value": Entity("host", "srv-backup-01.corp.example"),
                        "share": 0.84,
                    },
                    "verdict": "tune",
                    "daily": [1900 + (i * 37) % 120 for i in range(21)],
                },
                {
                    "rule_id": "5710",
                    "description": "sshd: Attempt to login using a non-existent user",
                    "level": 5,
                    "total": 30500,
                    "per_day": 1452.4,
                    "analyst_facing": 0,
                    "share": 0.17,
                    "clusters": 310,
                    "days_active": 21,
                    "days": 21,
                    "top_anchor": {"field": "data.srcip", "value": Entity("ip", "10.20.0.15"), "share": 0.61},
                    "verdict": "investigate",
                    "daily": [900] * 19 + [5400, 5600],
                },
                {
                    "rule_id": "100200",
                    "description": "High-severity custom rule",
                    "level": 12,
                    "total": 9000,
                    "per_day": 428.6,
                    "analyst_facing": 9000,
                    "share": 0.05,
                    "clusters": 400,
                    "days_active": 20,
                    "days": 21,
                    "top_anchor": None,
                    "verdict": "do_not_tune",
                    "daily": [428] * 21,
                },
            ],
            "time_saved_minutes_per_day": [31.0, 155.0],
            "suppressions_file": "/srv/hushwatch/out/suppressions/hushwatch_local_rules.xml",
        },
        "silence": {
            "status": "fail",
            "alpha_eff": 0.0001,
            "keys_evaluated": 500,
            "status_counts": {"ok": 431, "silent": 3, "drop": 1, "learning": 12, "unmonitorable": 2, "explained": 51},
            "sources": [
                {
                    "level": "agent",
                    "key": {"agent": Entity("host", "dc02.corp.example")},
                    "status": "silent",
                    "last_seen": "2026-09-24T04:00:00Z",
                    "observed": 0,
                    "expected": 5100.0,
                    "p": 1e-12,
                    "tier": "critical",
                    "duty": "always_on",
                    "daily": [5200, 5100, 5000, 5300, 5150, 2100, 0],
                },
                {
                    "level": "agent_log_source",
                    "key": {
                        "agent": Entity("host", "srv-backup-01.corp.example"),
                        "log_source": "Microsoft-Windows-Sysmon/Operational",
                    },
                    "status": "silent",
                    "last_seen": "2026-09-23T09:58:00Z",
                    "observed": 0,
                    "expected": 2210.4,
                    "p": 3e-9,
                    "tier": "standard",
                    "duty": "always_on",
                    "daily": [2300, 2250, 2190, 2280, 2240, 0, 0],
                },
                {
                    "level": "log_source",
                    "key": {"log_source": "/var/log/auth.log"},
                    "status": "drop",
                    "last_seen": "2026-09-25T09:40:00Z",
                    "observed": 120,
                    "expected": 1510.0,
                    "p": 0.00002,
                    "tier": "standard",
                    "duty": "business_hours",
                    "daily": [1500, 1520, 1480, 1510, 1490, 300, 120],
                },
            ],
            "monitorability": {"critical_total": 8, "critical_monitorable": 6},
        },
        "coverage": {
            "status": "fail",
            "platforms": {"windows": 25, "linux": 12, "network": 1},
            "matrix": [
                {
                    "agent": Entity("host", "dc01.corp.example"),
                    "platform": "windows",
                    "log_sources": {"Security": "present", "Microsoft-Windows-Sysmon/Operational": "present"},
                },
                {
                    "agent": Entity("host", "dc02.corp.example"),
                    "platform": "windows",
                    "log_sources": {"Security": "silent", "Microsoft-Windows-Sysmon/Operational": "silent"},
                },
                {
                    "agent": Entity("host", "srv-app-01.corp.example"),
                    "platform": "windows",
                    "log_sources": {"Security": "present", "Microsoft-Windows-Sysmon/Operational": "missing"},
                },
                {
                    "agent": Entity("host", "srv-web-02.example"),
                    "platform": "linux",
                    "log_sources": {"/var/log/auth.log": "present"},
                },
            ],
            "expected_sources": ["Security", "Microsoft-Windows-Sysmon/Operational"],
        },
        "pipeline": {
            "status": "fail",
            "agents": {"active": 36, "disconnected": 2, "never_connected": 1},
            "checks": [
                {"name": "analysisd events dropped", "status": "fail", "value": 1204},
                {"name": "ingest lag p95", "status": "warn", "value": "42 min"},
                {"name": "clock skew", "ok": True},
            ],
        },
        "tuning": {"status": "fail", "rules_parsed": 3120, "local_rules": 14, "risky": 2},
    }


def build_basis(**overrides: Any) -> DataBasis:
    values: dict[str, Any] = {
        "input_kind": "alerts",
        "profile": "wazuh4",
        "sources": ["/var/ossec/logs/alerts/alerts.json", "/var/ossec/logs/alerts/2026/Sep/ossec-alerts-24.json.gz"],
        "start": NOW - timedelta(days=21),
        "end": NOW - timedelta(minutes=1),
        "now": NOW - timedelta(minutes=1),
        "now_origin": "data",
        "events": 184233,
        "malformed": 3,
        "bad_timestamps": 2,
        "future_timestamps": 1,
        "warnings": [M("testrep.warning", tz="UTC")],
    }
    values.update(overrides)
    return DataBasis(**values)


def build_full_report(**basis_overrides: Any) -> Report:
    return Report(
        tenant="acme",
        generated_at=NOW,
        tool_version="0.1.0",
        data_basis=build_basis(**basis_overrides),
        findings=build_findings(),
        sections=build_sections(),
        assessment={
            "noise": "warn",
            "silence": "fail",
            "pipeline": "fail",
            "coverage": "fail",
            "tuning": "fail",
            "assessment": "ok",
        },
    )


def build_incomplete_report() -> Report:
    report = build_full_report(
        truncated=True,
        partial_failures=["indexer https://indexer.corp.example:9200: 2 of 10 shards failed"],
    )
    report.findings.append(
        _f(
            "assessment.incomplete",
            Severity.HIGH,
            "wazuh-api",
            "Wazuh API unavailable: part of the analysis did not run",
        )
    )
    report.assessment["assessment"] = "fail"
    return report


def build_empty_report() -> Report:
    return Report(tenant="empty", generated_at=NOW, tool_version="0.1.0", data_basis=DataBasis())


def render_console(
    report: Report,
    *,
    lang: str = "en",
    redactor: Redactor | None = None,
    width: int = 140,
    verbose: bool = False,
    color: bool = False,
) -> str:
    buffer = io.StringIO()
    console = Console(
        file=buffer,
        width=width,
        force_terminal=color,
        color_system="truecolor" if color else None,
        highlight=False,
        legacy_windows=False,
    )
    print_console(report, lang=lang, redactor=redactor, console=console, verbose=verbose)
    return buffer.getvalue()


def all_outputs(report: Report, *, lang: str = "en", redactor: Redactor | None = None) -> dict[str, str]:
    outputs = {fmt: render(report, fmt, lang=lang, redactor=redactor) for fmt in FORMATS}
    outputs["console"] = render_console(report, lang=lang, redactor=redactor, verbose=True)
    outputs["html+json"] = render_html(report, lang=lang, redactor=redactor, embed_json=True)
    return outputs


class _Collector(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.tags: list[tuple[str, dict[str, str | None]]] = []
        self.stack: list[str] = []
        self.text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.append((tag, dict(attrs)))
        if tag not in ("meta", "br", "hr", "img", "link", "path", "circle", "rect", "polyline"):
            self.stack.append(tag)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.append((tag, dict(attrs)))

    def handle_endtag(self, tag: str) -> None:
        if tag in ("path", "circle", "rect", "polyline"):
            return
        assert self.stack and self.stack[-1] == tag, f"unbalanced </{tag}> (open: {self.stack[-3:]})"
        self.stack.pop()

    def handle_data(self, data: str) -> None:
        self.text.append(data)


def parse_html(text: str) -> _Collector:
    parser = _Collector()
    parser.feed(text)
    parser.close()
    assert parser.stack == [], f"unclosed tags: {parser.stack}"
    return parser


def visible_text(text: str) -> str:
    return " ".join(parse_html(text).text)


# ---- formats & structure --------------------------------------------------------------------------------------


@pytest.mark.parametrize("lang", ["en", "es"])
def test_every_format_renders_every_section(lang: str) -> None:
    report = build_full_report()
    out = all_outputs(report, lang=lang)
    for fmt in ("md", "html", "console"):
        text = out[fmt]
        for rule_id in ("60106", "5710", "100200"):
            assert rule_id in text, (fmt, rule_id)
        assert "dc02.corp.example" in text
        assert "0.1.0" in text
    doc = json.loads(out["json"])
    assert doc["schema_version"] == SCHEMA_VERSION
    assert doc["lang"] == lang
    assert len(doc["findings"]) == len(report.findings)
    assert set(doc["sections"]) == {"noise", "silence", "coverage", "pipeline", "tuning"}


def test_json_is_deterministic_sorted_and_versioned() -> None:
    report = build_full_report()
    first = render(report, "json")
    assert first == render(report, "json")
    doc = json.loads(first)
    assert list(doc) == sorted(doc)
    assert doc["document"] == "hushwatch.report"
    assert doc["tool"] == {"name": "hushwatch", "version": "0.1.0"}
    assert doc["generated_at"] == "2026-09-25T10:00:00Z"
    assert doc["data_basis"]["start"] == "2026-09-04T10:00:00Z"
    assert doc["data_basis"]["alerts_only"] is True
    assert doc["data_basis"]["caveats"]
    assert doc["summary"]["by_severity"]["critical"] == 2
    assert doc["assessment"]["silence"] == "fail"
    assert doc["incomplete"] is False
    assert first.endswith("\n")


def test_json_messages_keep_text_key_and_params() -> None:
    doc = json.loads(render(build_full_report(), "json", lang="es"))
    tune = next(f for f in doc["findings"] if f["subject"].startswith("rule:60106"))
    title = tune["title"]
    assert title["key"] == "testrep.tune.title"
    assert title["params"] == {"rule": "60106", "host": "srv-backup-01.corp.example", "user": "svc_backup"}
    assert title["text"].startswith("Regla 60106 en srv-backup-01.corp.example")
    reason = tune["reasons"][0]
    assert reason["params"]["share"] == 0.84
    assert "84%" in reason["text"]
    plain = next(f for f in doc["findings"] if f["kind"] == "noise.aggregate")
    assert plain["title"]["key"] is None and plain["title"]["params"] == {}
    assert tune["evidence"]["conditions"][0] == {"field": "agent.name", "value": "srv-backup-01.corp.example"}
    assert tune["confidence"] == "high" and tune["severity"] == "medium"
    assert doc["data_basis"]["warnings"][0]["text"].startswith("Las marcas de tiempo")


def test_findings_are_ordered_most_severe_first() -> None:
    doc = json.loads(render(build_full_report(), "json"))
    ranks = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    severities = [ranks[f["severity"]] for f in doc["findings"]]
    assert severities == sorted(severities, reverse=True)


def test_data_basis_banner_comes_first_everywhere() -> None:
    report = build_full_report()
    md = render(report, "md")
    headings = re.findall(r"^## \d+\. (.+)$", md, re.MULTILINE)
    assert headings[0] == "Data basis"
    assert headings[1] == "Status by domain"
    assert headings[-1] == "All findings"
    html = render(report, "html")
    sections = re.findall(r'<section id="([a-z]+)"', html)
    assert sections[:3] == ["basis", "status", "numbers"]
    assert sections[-1] == "findings"
    console = render_console(report)
    assert console.index("Data basis") < console.index("Status by domain") < console.index("All findings")


def test_banner_lists_every_data_basis_fact() -> None:
    report = build_full_report()
    md = render(report, "md")
    for label in (
        "Input",
        "Profile",
        "Time range",
        "Reference “now”",
        "Events analyzed",
        "Malformed records",
        "Unparseable timestamps",
        "Future timestamps",
        "Sampled",
        "Truncated (caps hit)",
        "Partial failures",
        "Sources",
        "Warnings",
        "Analyses not evaluated",
    ):
        assert f"**{label}**" in md, label
    assert "184,233" in md
    assert "newest event in the input" in md
    assert "Alerts only" in md and "log\\_alert\\_level" in md  # the alerts-only caveat
    assert "/var/ossec/logs/alerts/alerts.json" in md


def test_alerts_only_caveat_absent_for_archives() -> None:
    doc = json.loads(render(build_full_report(input_kind="archives"), "json"))
    assert doc["data_basis"]["alerts_only"] is False
    assert doc["data_basis"]["caveats"] == []
    md = render(build_full_report(input_kind="archives"), "md")
    assert "All events (archives)" in md
    assert "[!WARNING]" not in md


def test_incomplete_analysis_is_visually_loud() -> None:
    report = build_incomplete_report()
    md = render(report, "md")
    assert md.index("> [!CAUTION]") < md.index("## 1. Data basis")
    assert "Caps were hit" in md and "1 partial failure(s)" in md
    assert "Wazuh API unavailable" in md
    html = render(report, "html")
    assert 'class="alert bad" role="alert"' in html
    assert "<title>⚠ Analysis incomplete" in html
    assert 'class="chip bad"' in html
    console = render_console(report)
    assert "ANALYSIS INCOMPLETE" in console
    doc = json.loads(render(report, "json"))
    assert doc["incomplete"] is True
    assert doc["assessment"]["assessment"] == "fail"
    assert len(doc["data_basis"]["incomplete_reasons"]) == 3


def test_domain_status_cards_never_a_single_score() -> None:
    report = build_full_report()
    md = render(report, "md")
    for label, status in (("Noise", "Problem"), ("Silence", "Problem"), ("Assessment", "OK")):
        assert re.search(rf"\| {label} \| \S+ {status} \|", md), label
    for fmt in FORMATS:
        text = render(report, fmt).lower()
        assert "/100" not in text and "hygiene score" not in text


def test_key_numbers() -> None:
    md = render(build_full_report(), "md")
    assert "| Alert volume from the top 5 rules | **62%** |" in md
    assert "| Safe tuning candidates | ✅ **2** | review required: 1 |" in md
    assert "| Silent or dropped sources | ❌ **4** |" in md
    assert "| Critical sources monitorable within SLA | ⚠️ **75%** | 6 of 8 |" in md
    assert "| Coverage gaps | ⚠️ **2** |" in md
    assert "| Risky or expired suppressions | ⚠️ **3** |" in md
    assert "| Analyst-facing alerts per day | **244** | over 21 days |" in md


def test_noise_section_content() -> None:
    report = build_full_report()
    md = render(report, "md")
    assert "Top rules by analyst-facing volume" in md
    assert "sshd: Attempt to login using a non-existent user" in md
    assert "▁" in md or "█" in md  # text sparkline
    assert "Review required" in md and "5712, 5720" in md
    assert "Ready for review" in md
    assert "Noisy but not safe to tune" in md
    assert "Novel: first seen 2d ago" in md
    assert "**Time saved (upper-bound estimate):** 31–155 min/day" in md
    assert "Upper-bound estimate" in md
    assert "hushwatch\\_local\\_rules.xml" in md
    html = render(report, "html")
    assert html.count('class="spark"') >= 3 + 3
    assert 'class="b review"' in html
    assert "31–155 min/day" in html
    assert 'href="#f-' in html  # suggestions link to their finding


def test_silence_coverage_pipeline_tuning_sections() -> None:
    report = build_full_report()
    md = render(report, "md")
    assert "Silent: **3**" in md and "Explained: **51**" in md
    assert "75% (6 of 8)" in md
    assert "dc02.corp.example" in md and "Always on" in md
    assert "● Present" in md and "✖ Missing" in md and "◌ Silent" in md
    assert "Agents by status" in md and "analysisd events dropped" in md
    assert "**Rules parsed**" in md and "3,120" in md
    html = render(report, "html")
    assert 'class="matrix"' in html
    assert html.count('class="m m-missing"') == 1
    assert 'class="b s-silent"' in html


def test_all_findings_grouped_by_domain_with_details() -> None:
    report = build_full_report()
    md = render(report, "md")
    order = [md.index(f"### {label} (") for label in ("Noise", "Silence", "Pipeline", "Coverage", "Tuning debt")]
    assert order == sorted(order)
    tamper = next(f for f in report.findings if f.kind == "silence.tampering")
    assert f"`{tamper.fingerprint}`" in md
    assert "Possible tampering: audit log cleared on dc02.corp.example" in md
    assert "**Recommended action:** Check the agent on srv-backup-01.corp.example" in md
    assert "high confidence" in md
    assert "T1070.001, T1562.002" in md
    html = render(report, "html")
    assert html.count("<article ") == len(report.findings)
    assert f'id="f-{tamper.fingerprint}"' in html


def test_footer() -> None:
    report = build_full_report()
    for fmt in ("md", "html"):
        text = render(report, fmt)
        assert "hushwatch never writes to your SIEM" in text
        assert f"Report schema {SCHEMA_VERSION}" in text
        assert "hushwatch 0.1.0" in text
        assert "Generated 2026-09-25 10:00 UTC" in text
    assert "contains real host names" in render(report, "md")
    assert "never writes to your SIEM" in render_console(report)


def test_spanish_output() -> None:
    report = build_full_report()
    md = render(report, "md", lang="es")
    for text in (
        "Datos analizados",
        "Estado por dominio",
        "Cifras clave",
        "Todos los hallazgos",
        "Ruido: qué se puede ajustar con seguridad",
        "hushwatch nunca escribe en su SIEM",
        "Tiempo ahorrado (estimación máxima)",
        "Requiere revisión",
        "Solo alertas",
        "Regla 60106 en srv-backup-01.corp.example",
        "184.233",
        "Ruidosas, pero no seguras de ajustar",
    ):
        assert text in md, text
    assert "Data basis" not in md and "All findings" not in md
    html = render(report, "html", lang="es")
    assert '<html lang="es">' in html
    console = render_console(report, lang="es")
    assert "Datos analizados" in console and "Estado por dominio" in console


def test_missing_sections_render_not_assessed() -> None:
    report = build_full_report()
    report.sections = {"noise": report.sections["noise"]}
    report.assessment = {"noise": "warn"}
    md = render(report, "md")
    assert md.count("⬜ _Not assessed: this analysis did not run") == 4
    html = render(report, "html")
    assert html.count('class="empty na"') == 4
    assert 'class="card st-not_assessed"' not in html  # every domain has findings → statuses escalate
    assert domain_statuses(report)["assessment"] == "ok"  # complete basis, only an info assessment finding
    doc = json.loads(render(report, "json"))
    assert set(doc["sections"]) == {"noise"}


def test_empty_report_renders_everywhere() -> None:
    report = build_empty_report()
    out = all_outputs(report)
    assert "No findings, but the analysis was incomplete" in out["md"]
    assert "No events were analyzed" in out["md"]
    assert out["md"].count("Not assessed") >= 5
    assert "ANALYSIS INCOMPLETE" in out["console"]
    doc = json.loads(out["json"])
    assert doc["findings"] == [] and doc["incomplete"] is True
    assert doc["assessment"] == {
        "noise": "not_assessed",
        "silence": "not_assessed",
        "pipeline": "not_assessed",
        "coverage": "not_assessed",
        "tuning": "not_assessed",
        "assessment": "fail",
    }
    parse_html(out["html"])


def test_html_document_structure() -> None:
    html = render(build_full_report(), "html")
    assert html.startswith('<!doctype html>\n<html lang="en">')
    head = html[: html.index("</head>")]
    assert head.index('<meta charset="utf-8">') < head.index("Content-Security-Policy") < head.index("<style>")
    assert "default-src 'none'; style-src 'unsafe-inline'; img-src data:" in head
    assert "<script" not in html and "<link" not in html and "@import" not in html and "url(" not in html
    assert "prefers-color-scheme:dark" in html and "@media print" in html and "max-width:640px" in html
    parsed = parse_html(html)
    tags = {tag for tag, _ in parsed.tags}
    assert {"header", "nav", "main", "section", "footer", "table", "caption", "thead", "tbody", "svg"} <= tags
    for tag, attrs in parsed.tags:
        for name, value in attrs.items():
            assert not name.startswith("on")
            if name == "href":
                assert value is not None and value.startswith("#")
        if tag == "th" and attrs.get("scope") is None:
            raise AssertionError("every header cell has a scope")


def test_html_embedded_json_is_inert_and_parseable() -> None:
    report = build_full_report()
    html = render_html(report, embed_json=True)
    match = re.search(r'<script type="application/json" id="hushwatch-data">(.*?)</script>', html, re.S)
    assert match is not None
    assert html.count("<script") == 1
    doc = json.loads(match.group(1))
    assert doc["schema_version"] == SCHEMA_VERSION and len(doc["findings"]) == len(report.findings)


def test_console_width_aware_and_verbose() -> None:
    report = build_full_report()
    wide = render_console(report, width=160)
    narrow = render_console(report, width=60)
    assert "Description" in wide and "Description" not in narrow
    assert "Windows logon success" in wide
    verbose = render_console(report, width=140, verbose=True)
    terse = render_console(report, width=140, verbose=False)
    assert "Hidden per day" in verbose and "412" in verbose
    assert "Share of rule          84%" in verbose  # shares shown as percentages
    assert "agent.name = srv-backup-01.corp.example ∧" in verbose  # conditions shown as a scope
    assert "P(no events)" in verbose and "P(no events)" not in terse


def test_console_ascii_fallback_encoding() -> None:
    buffer = io.TextIOWrapper(io.BytesIO(), encoding="latin-1", errors="strict")
    console = Console(file=buffer, width=120, force_terminal=False, color_system=None, legacy_windows=False)
    report = build_full_report()
    report.findings[0].reasons.append("unicode ☃ ✓ Ω name")
    print_console(report, console=console, verbose=True)  # must not raise UnicodeEncodeError
    buffer.flush()


def test_console_many() -> None:
    buffer = io.StringIO()
    console = Console(file=buffer, width=150, color_system=None)
    print_console_many([build_full_report(), build_empty_report()], console=console)
    text = buffer.getvalue()
    assert "Fleet summary" in text and "acme" in text and "empty" in text


# ---- statuses ---------------------------------------------------------------------------------------------------


def test_domain_statuses_never_greener_than_the_evidence() -> None:
    report = build_full_report()
    report.assessment = {"noise": "ok", "silence": "ok", "pipeline": "bogus", "assessment": "ok"}
    statuses = domain_statuses(report)
    assert statuses["noise"] == "fail"  # a high noise.investigate finding
    assert statuses["silence"] == "fail"
    assert statuses["pipeline"] == "fail"  # unknown value → section says fail
    assert statuses["assessment"] == "ok"
    empty = domain_statuses(build_empty_report())
    assert empty["assessment"] == "fail" and empty["noise"] == "not_assessed"
    sampled = build_full_report(sampled=True)
    assert domain_statuses(sampled)["assessment"] == "warn"


# ---- redaction --------------------------------------------------------------------------------------------------


def test_redaction_removes_every_identifier_in_every_format() -> None:
    report = build_incomplete_report()
    report.findings.append(
        _f(
            "pipeline.lag",
            Severity.LOW,
            "agent:ws-finance-07.corp.example|user:bob.smith",
            "Plain text mentioning 10.30.0.99, ws-finance-07.corp.example, bob.smith and CORP\\carol",
            reasons=["user carol@corp.example logged from fe80::1ff:fe23:4567:890a via C:\\Users\\dave\\app.exe"],
        )
    )
    redactor = Redactor(b"k" * 32)
    raw = [
        *HOSTS,
        *USERS,
        *IPS,
        "ws-finance-07",
        "bob.smith",
        "carol",
        "fe80::1ff:fe23:4567:890a",
        "dave",
        "indexer.corp.example",
        "srv-app-01.corp.example",
    ]
    for lang in ("en", "es"):
        for fmt, text in all_outputs(report, lang=lang, redactor=redactor).items():
            leaked = [value for value in raw if value in text]
            assert not leaked, (fmt, lang, leaked)
            assert "host-" in text and "ip-" in text and "user-" in text
    doc = json.loads(render(report, "json", redactor=redactor))
    assert doc["redacted"] is True
    assert all(f["subject"].startswith("val-") for f in doc["findings"])
    tune = next(f for f in doc["findings"] if f["title"]["key"] == "testrep.tune.title")
    assert tune["title"]["params"]["host"] == redactor.token("srv-backup-01.corp.example", "host")
    assert "Pseudonymized" in render(report, "md", redactor=redactor)


def test_redaction_tokens_are_stable_across_formats() -> None:
    redactor = Redactor(b"k" * 32)
    token = redactor.token("dc02.corp.example", "host")
    for text in all_outputs(build_full_report(), redactor=redactor).values():
        assert token in text


def test_without_redactor_values_are_shown() -> None:
    md = render(build_full_report(), "md")
    assert "srv-backup-01.corp.example" in md and "svc\\_backup" in md and "10.20.0.15" in md


# ---- fleet ------------------------------------------------------------------------------------------------------


def _tenant(name: str, report: Report) -> Report:
    report.tenant = name
    return report


def test_render_many_fleet_summary() -> None:
    reports = [
        _tenant("globex", build_empty_report()),
        _tenant("acme", build_full_report()),
        _tenant("initech", build_incomplete_report()),
    ]
    doc = json.loads(render_many(reports, "json"))
    assert doc["document"] == "hushwatch.fleet" and doc["schema_version"] == SCHEMA_VERSION
    names = [row["tenant"] for row in doc["tenants"]]
    assert names == ["initech", "acme", "globex"]  # 2 critical each, initech has one more high; then empty
    acme = doc["tenants"][1]
    assert acme["findings"] == {"critical": 2, "high": 8, "total": len(build_findings())}
    assert acme["assessment"]["silence"] == "fail" and acme["incomplete"] is False
    assert acme["most_severe"]["severity"] == "critical"
    assert doc["tenants"][0]["incomplete"] is True
    assert doc["tenants"][2]["incomplete"] is True and doc["tenants"][2]["most_severe"] is None
    md = render_many(reports, "md", lang="es")
    assert "Resumen multicliente" in md and "| **acme** |" in md and "Clientes: 3" in md
    html = render_many(reports, "html")
    parse_html(html)
    assert html.count("<tr>") == 1 + 3 and "Fleet summary" in html
    assert "default-src 'none'" in html


def test_render_many_redacts_per_tenant() -> None:
    reports = [_tenant("acme", build_full_report()), _tenant("globex", build_full_report())]
    for report in reports:  # make the tampering finding (it names dc02) the most severe one
        next(f for f in report.findings if f.kind == "silence.tampering").score = 100.0
    keys = {"acme": Redactor(b"a" * 32), "globex": Redactor(b"b" * 32)}
    for fmt in FORMATS:
        text = render_many(reports, fmt, redactor=keys)
        assert "dc02.corp.example" not in text
        assert keys["acme"].token("dc02.corp.example", "host") in text
        assert keys["globex"].token("dc02.corp.example", "host") in text


def test_render_many_empty() -> None:
    assert "No tenant reports." in render_many([], "md")
    assert json.loads(render_many([], "json"))["tenants"] == []
    parse_html(render_many([], "html"))


# ---- API & helpers ----------------------------------------------------------------------------------------------


def test_unknown_format_rejected_and_aliases() -> None:
    report = build_empty_report()
    with pytest.raises(ValueError, match="unknown report format"):
        render(report, "pdf")
    assert render(report, "markdown") == render(report, "md")
    assert render(report, "HTML").startswith("<!doctype html>")


def test_language_normalization() -> None:
    assert normalize_lang("es-AR") == "es" and normalize_lang("ES_es") == "es"
    assert normalize_lang("fr") == "en" and normalize_lang(None) == "en"
    assert "Datos analizados" in render(build_empty_report(), "md", lang="es-CL")


@pytest.mark.parametrize(
    ("lang", "value", "expected"),
    [
        ("en", 1234567, "1,234,567"),
        ("es", 1234567, "1.234.567"),
        ("en", 1234.5, "1,234"),
        ("es", 12.34, "12,3"),
        ("en", 0.25, "0.25"),
        ("en", 0.0004, "4.0e-04"),
        ("en", float("nan"), "—"),
        ("en", float("inf"), "∞"),
        ("en", None, "—"),
    ],
)
def test_number_formatting(lang: str, value: Any, expected: str) -> None:
    assert RenderContext(None, lang).num(value) == expected


def test_percent_and_pvalue_formatting() -> None:
    en, es = RenderContext(None, "en"), RenderContext(None, "es")
    assert en.pct(0.843) == "84%" and en.pct(0.004) == "<1%" and en.pct(0.999) == ">99%" and en.pct(None) == "—"
    assert en.pct(84.3) == "84%"
    assert en.pvalue(0.00001) == "<0.0001" and es.pvalue(0.0123) == "0,012" and en.pvalue(0.004) == "0.0040"
    assert en.dt(NOW) == "2026-09-25 10:00 UTC" and en.dt("2026-09-25T10:00:00Z") == "2026-09-25 10:00 UTC"


def test_sparkline_text_keeps_silence_visible() -> None:
    assert sparkline_text([0, 5, 10, 0]) == "·▅█·"
    assert sparkline_text([0, 0]) == "··"
    assert sparkline_text([]) == ""


def test_sanitize_strips_controls_and_bidi() -> None:
    assert sanitize("a\x1b[2Jb\x07c\x9bd") == "a[2Jbcd"
    assert sanitize("x\u202eevil\u200b") == "xevil"
    assert sanitize("line1\nline2\r\tz") == "line1 line2  z"
    assert sanitize("bad\udcffsurrogate") == "bad\ufffdsurrogate"


def test_md_escape() -> None:
    assert md_escape("a|b") == "a\\|b"
    assert md_escape("*x* _y_ `z` [l](u) ~s~ $m$ #h") == "\\*x\\* \\_y\\_ \\`z\\` \\[l\\](u) \\~s\\~ \\$m\\$ \\#h"
    assert md_escape("<b>&lt;") == "&lt;b&gt;&amp;lt;"
    assert md_escape("see https://x.example/a www.example.com") == "see https\\[:\\]//x.example/a www\\[.\\]example.com"
    assert md_escape("C:\\temp") == "C:\\\\temp"


def test_prepare_context_learns_entities_and_subjects() -> None:
    report = build_full_report()
    report.findings.append(
        _f(
            "coverage.missing_source",
            Severity.LOW,
            "agent:ws-only-in-subject.corp|ls:Security",
            "ws-only-in-subject.corp misses Security",
        )
    )
    redactor = Redactor(b"k" * 32)
    ctx = prepare_context(report, "en", redactor)
    assert ctx.text("svc_backup ran on dc01.corp.example") == (
        f"{redactor.token('svc_backup', 'user')} ran on {redactor.token('dc01.corp.example', 'host')}"
    )
    assert "ws-only-in-subject.corp" not in ctx.text("ws-only-in-subject.corp misses Security")
    assert "Security" in ctx.text("ws-only-in-subject.corp misses Security")  # log sources are not entities


def test_minor_assessment_gaps_are_caveats_not_incomplete() -> None:
    """Same rule as the engine's exit code 3: only assessment findings at medium or above mean "incomplete"."""
    report = build_full_report()
    report.findings.append(
        _f("assessment.incomplete", Severity.INFO, "emit-warnings", "2 suggestion(s) were not written as Wazuh rules")
    )
    doc = json.loads(render(report, "json"))
    assert doc["incomplete"] is False and doc["assessment"]["assessment"] == "ok"
    md = render(report, "md")
    assert "[!CAUTION]" not in md
    assert "> [!WARNING]\n> 2 suggestion(s) were not written as Wazuh rules" in md
    report.findings.append(_f("assessment.learning", Severity.MEDIUM, "learning", "Too little history"))
    assert json.loads(render(report, "json"))["incomplete"] is True


def test_real_analyzer_section_shapes() -> None:
    """Shapes the analyzers actually emit: nested backtest evidence, dict-based expected sources, named checks."""
    report = build_full_report()
    tune = report.findings[0]
    tune.evidence = {
        "rule_id": "60106",
        "conditions": [{"field": "agent.name", "value": Entity("host", "srv-backup-01.corp.example")}],
        "share_of_rule": 0.3412,
        "review_required": False,
        "dependents": [],
        "backtest": {
            "hidden_per_day": 150.25,
            "share_of_rule": 0.3398,
            "hidden_analyst_facing": 0,
            "agents": 1,
            "daily": [150, 149, 151, 150, 0, 152, 150],
        },
        "gates": {"novelty": True, "burst": True},
    }
    report.sections["coverage"]["expected_sources"] = [
        {"basis": "contract", "name": "windows servers", "log_source": "Security", "matched": 4, "present": 4},
        {
            "basis": "peers",
            "name": "windows",
            "log_source": "Microsoft-Windows-Sysmon/Operational",
            "matched": 26,
            "present": 25,
            "missing": 1,
        },
    ]
    report.sections["coverage"]["matrix"][0]["tier"] = "critical"
    report.sections["coverage"]["matrix_total"] = 250
    report.sections["pipeline"]["checks"] = [
        {"check": "input_completeness", "status": "ok", "events": 10, "partial_failures": 0, "not_evaluated": []},
        {"check": "ingest_lag", "status": "not_assessed", "reason": "no_samples"},
    ]
    report.sections["tuning"].update({"risky_high": 1, "expired": 1, "parse_errors": 0, "duplicate_ids": 2})
    report.sections["silence"]["monitorability"]["sla_hours"] = 4.0
    report.sections["silence"]["sources"][0]["status"] = "not_evaluated"
    md = render(report, "md")
    assert "| 150 | 34% |" in md  # backtest numbers win over the pre-backtest estimate (34.12%)
    assert "Backtest › Hidden per day: 150" in md and "Safety gates › Novelty: yes" in md
    assert "| Basis | Name | Log source | Matched | Present | Missing |" in md
    assert "dc01.corp.example (Critical)" in md and "246 more not shown" in md
    assert "Input completeness" in md and "Events: 10" in md and "Not evaluated" in md
    assert "**Duplicate rule ids** | ⚠️ 2" in md and "**High-risk suppressions** | ⚠️ 1" in md
    assert "75% (6 of 8) · SLA 4 h" in md
    html = render(report, "html")
    parse_html(html)
    assert "Expected sources</caption>" in html


# ---- regressions (review) ---------------------------------------------------------------------------------------


def _outputs_redacted(report: Report, redactor: Redactor) -> dict[str, str]:
    return {
        **{fmt: render(report, fmt, redactor=redactor) for fmt in FORMATS},
        "console": render_console(report, redactor=redactor, verbose=True, width=200),
    }


def _small_report(findings: list[Finding], sections: dict[str, dict[str, Any]] | None = None) -> Report:
    basis = DataBasis(input_kind="archives", profile="wazuh4", start=NOW - timedelta(days=21), end=NOW, now=NOW)
    basis.events = 1000
    return Report("acme", NOW, "0.1.0", basis, findings, sections or {})


def test_identifier_keys_are_redacted_before_being_humanized() -> None:
    """Keys were humanized first ("dc01.corp.example" -> "dc01 › corp › example"), which defeated redaction."""
    finding = _f(
        "silence.drop",
        Severity.HIGH,
        "agent:dc01.corp.example",
        "Volume dropped",
        evidence={
            "per_host": {"dc01.corp.example": 5, "10.20.0.15": 3, "svc_backup": 2},
            "host": Entity("host", "dc01.corp.example"),
            "account": Entity("user", "svc_backup"),
            "hidden_per_day": 4,
            "days_present": 12,
        },
    )
    sections = {"pipeline": {"status": "warn", "agents": {"dc01.corp.example": "active"}, "per_ip": {"10.20.0.15": 1}}}
    redactor = Redactor(b"k" * 32)
    for fmt, text in _outputs_redacted(_small_report([finding], sections), redactor).items():
        for leaked in ("dc01", "10 › 20", "10.20.0.15", "svc backup", "svc_backup", "svc\\_backup"):
            assert leaked not in text, (fmt, leaked)
    md = render(_small_report([finding], sections), "md")
    assert "Per host › dc01.corp.example: 5" in md  # without redaction, identifiers stay readable
    assert "Days present: 12" in md  # code-style keys are humanized and capitalized


def test_long_values_never_split_an_identifier_across_redaction_calls() -> None:
    """Redaction used to run on 512-char chunks: an IP or a /home/<user> path across a boundary leaked."""
    redactor = Redactor(b"k" * 32)
    ctx = RenderContext(None, "en", redactor)
    samples = {
        "x" * 300 + "," + "y" * 200 + "/home/alice_notes.txt" + "z" * 200: "alice",
        "q=" + "a" * 500 + "&ip=10.20.30.40&x=" + "b" * 100: "10.20.",
        "C:\\Tools\\" + "p" * 480 + ",C:\\Users\\dave\\run.exe": "dave",
    }
    for text, secret in samples.items():
        assert secret not in ctx.text(text), secret
    # a value cut at MAX_TEXT does not keep a partial (unrecognizable) identifier at the cut
    long_value = "k=" + "v" * 3000 + "&host=dc09.corp.example" + "w" * 2000
    out = RenderContext(None, "en").text(long_value)
    assert "dc09" not in out and "more characters]" in out


def test_plain_identifiers_under_identifying_keys_are_redacted() -> None:
    """Defense in depth: a module that forgot Entity() for {"agent": "..."} must not leak the value."""
    finding = _f(
        "coverage.missing_source",
        Severity.HIGH,
        "coverage-1",
        "ws-fin-07 misses Sysmon",
        evidence={"agent": "ws-fin-07", "user": "bob", "srcip": "10.9.9.9", "agents": ["ws-fin-10"], "host": "unknown"},
    )
    sections = {
        "silence": {
            "status": "warn",
            "sources": [{"level": "agent", "key": {"agent": "ws-fin-08"}, "status": "silent"}],
        },
        "coverage": {
            "status": "warn",
            "matrix": [{"agent": "ws-fin-09", "platform": "windows", "log_sources": {"Security": "missing"}}],
        },
    }
    report = _small_report([finding], sections)
    report.findings[0].reasons = ["the host is unknown"]
    redactor = Redactor(b"k" * 32)
    for fmt, text in _outputs_redacted(report, redactor).items():
        for leaked in ("ws-fin-07", "ws-fin-08", "ws-fin-09", "ws-fin-10", "bob", "10.9.9.9"):
            assert leaked not in text, (fmt, leaked)
        assert "unknown" in text  # empty-ish values ("unknown", "-", "N/A") are never learned as names


def test_message_defaults_and_unregistered_keys_are_redacted_whole() -> None:
    finding = _f(
        "silence.drop",
        Severity.HIGH,
        "s",
        M(
            "x.unregistered.review",
            "Host dc07.corp.example at 10.1.2.3 went quiet ({host})",
            host=Entity("host", "dc08"),
        ),
        reasons=[M("testrep.generic", what=M("x.unregistered.nested", "seen from 10.1.2.4"))],
    )
    redactor = Redactor(b"k" * 32)
    for fmt, text in _outputs_redacted(_small_report([finding]), redactor).items():
        for leaked in ("dc07", "10.1.2.3", "10.1.2.4", "dc08"):
            assert leaked not in text, (fmt, leaked)
        assert redactor.token("dc08", "host") in text  # the entity pseudonym survives the whole-text pass intact
    # registered templates are code: only their params are redacted, the template text is untouched
    ctx = prepare_context(build_full_report(), "en", redactor)
    title = ctx.msg(M("testrep.tune.title", rule="60106", host=Entity("host", "h1.example"), user=Entity("user", "u1")))
    assert title.startswith("Rule 60106 on host-") and ": scheduled user-" in title


def test_url_host_after_removed_credentials_is_redacted() -> None:
    report = _small_report([])
    report.data_basis.sources = ["https://admin:s3cret@indexer.corp.example:9200/wazuh-alerts-*"]
    redactor = Redactor(b"k" * 32)
    for fmt, text in _outputs_redacted(report, redactor).items():
        assert "indexer.corp.example" not in text and "s3cret" not in text, fmt
    for fmt in FORMATS:
        assert "s3cret" not in render(report, fmt) and "admin:" not in render(report, fmt)


def test_statuses_never_green_on_incomplete_or_unevaluated_data() -> None:
    clean = {d: "ok" for d in ("noise", "silence", "pipeline", "coverage", "tuning", "assessment")}
    sections = {d: {"status": "ok"} for d in ("noise", "silence", "pipeline", "coverage", "tuning")}
    report = _small_report([], sections)
    report.assessment = dict(clean)
    assert set(domain_statuses(report).values()) == {"ok"}
    report.data_basis.truncated = True  # caps hit: "no findings" rests on partial data
    statuses = domain_statuses(report)
    assert statuses == {**{d: "warn" for d in ("noise", "silence", "pipeline", "coverage")}, "tuning": "ok"} | {
        "assessment": "fail"
    }
    md = render(report, "md")
    assert "No findings in the data that could be read, but the analysis was incomplete" in md
    assert "✅ **0**" not in md  # zero counts on partial data are not shown as green KPIs
    report.data_basis.truncated = False
    report.data_basis.not_evaluated = ["silence"]
    report.sections["coverage"]["status"] = "not_assessed"  # the analyzer knows it could not assess
    statuses = domain_statuses(report)
    assert statuses["silence"] == "not_assessed" and statuses["coverage"] == "not_assessed"
    assert statuses["assessment"] == "warn"


def test_console_without_verbose_shows_the_most_severe_findings_of_the_whole_report() -> None:
    """The console limit used to take the first 60 findings in domain order: 60 noise findings hid a critical
    tampering finding."""
    findings = [_f("noise.investigate", Severity.MEDIUM, f"rule:{i}", f"Noisy rule {i}") for i in range(80)] + [
        _f("silence.tampering", Severity.CRITICAL, "agent:dc02", "Audit log cleared on dc02 before silence")
    ]
    out = render_console(_small_report(findings), width=140)
    assert "Audit log cleared on dc02 before silence" in out
    assert "Noise (80)" in out and "21 more finding(s) not shown" in out


def test_markdown_data_cannot_open_blocks_or_mention_people() -> None:
    markdown_it = pytest.importorskip("markdown_it")
    finding = _f(
        "noise.investigate",
        Severity.HIGH,
        "rule:1",
        "@octocat and alice@evil.example",
        reasons=["1. item", "- bullet", "+ plus", "---", "2) other", "mailto:bob@evil.example", "184.233 events"],
    )
    md = render(_small_report([finding]), "md")
    tokens = markdown_it.MarkdownIt("commonmark").enable("table").parse(md)
    kinds = {t.type for t in tokens}
    assert "ordered_list_open" not in kinds and "hr" in kinds  # the only rule is the footer separator
    assert sum(1 for t in tokens if t.type == "hr") == 1
    nested = [t for t in tokens if t.type == "bullet_list_open" and t.level > 2]
    assert not nested
    assert re.search(r"(?<!\[)@", md) is None  # every @ is defanged: no e-mail autolink, no @mention
    assert "184.233 events" in md  # numbers are not mistaken for list markers


def test_fleet_redacts_tenants_missing_from_the_mapping() -> None:
    reports = [_tenant("acme", build_full_report()), _tenant("globex", build_full_report())]
    for report in reports:
        next(f for f in report.findings if f.kind == "silence.tampering").score = 100.0
    for fmt in FORMATS:
        text = render_many(reports, fmt, redactor={"acme": Redactor(b"a" * 32)})
        assert "dc02.corp.example" not in text, fmt
    assert "dc02.corp.example" in render_many(reports, "md", redactor={"acme": Redactor(b"a" * 32), "globex": None})


def test_fleet_footer_names_version_time_and_schema() -> None:
    reports = [_tenant("acme", build_full_report())]
    for fmt in ("md", "html"):
        text = render_many(reports, fmt)
        assert "hushwatch 0.1.0" in text and f"Report schema {SCHEMA_VERSION}" in text
        assert "hushwatch never writes to your SIEM" in text
    buffer = io.StringIO()
    print_console_many(reports, console=Console(file=buffer, width=160, color_system=None))
    assert f"Report schema {SCHEMA_VERSION}" in buffer.getvalue()


def test_json_caveats_match_the_banner() -> None:
    report = _small_report([])
    report.data_basis.input_kind = "unknown"
    report.data_basis.profile = "wazuh5"
    report.data_basis.sampled = True
    caveats = json.loads(render(report, "json"))["data_basis"]["caveats"]
    assert len(caveats) == 3 and any("Wazuh 5.x" in c for c in caveats) and any("Sampled" in c for c in caveats)


def test_json_keys_that_render_alike_are_all_kept() -> None:
    finding = _f("pipeline.lag", Severity.LOW, "s", "t", evidence={f"k{c}": i for i, c in enumerate("\x00\x01\x02")})
    evidence = json.loads(render(_small_report([finding]), "json"))["findings"][0]["evidence"]
    assert evidence == {"k": 0, "k (2)": 1, "k (3)": 2}


def test_odd_values_format_safely() -> None:
    ctx = RenderContext(None, "es")
    assert ctx.num(10**2000) == "∞" and ctx.dur(float("nan")) == "desconocido" and ctx.value([]) == "—"
    finding = _f("pipeline.lag", Severity.LOW, "s", "t", evidence={"beacons": [], "huge": 10**5000})
    doc = json.loads(render(_small_report([finding]), "json"))
    assert doc["findings"][0]["evidence"] == {"beacons": [], "huge": None}
    assert "Beacons: —" in render(_small_report([finding]), "md")


def test_five_thousand_findings_render_in_bounded_time() -> None:
    report = build_full_report()
    for i in range(5000):
        host = Entity("host", f"srv-{i % 2000:04d}.corp.example")
        report.findings.append(
            _f(
                "noise.investigate",
                list(Severity)[i % 5],
                f"rule:{i}|agent:{host.value}",
                M("testrep.bruteforce.title", ip=Entity("ip", f"10.1.{i % 250}.{i % 199 + 1}"), host=host),
                reasons=[f"seen on {host.value}", M("testrep.gate.novel", ago="2d")],
                evidence={"per_day": i * 1.5, "daily": [i % 7, 3, 5, 0, 2, 9, 1], "agent": host},
            )
        )
    started = time.perf_counter()
    html = render(report, "html")
    assert 'id="findings" class="many"' in html  # off-screen cards skip layout: the page stays responsive
    render(report, "md", redactor=Redactor(b"k" * 32))
    render_console(report, width=140)
    assert time.perf_counter() - started < 90


def test_silence_sources_are_listed_worst_first() -> None:
    """Analyzers may list OK critical sources before silent ones: the silent ones must come first."""
    rows = [
        {"level": "agent", "key": {"agent": Entity("host", f"ok-{i:02d}")}, "status": "ok", "tier": "critical"}
        for i in range(250)
    ]
    rows += [
        {"level": "agent", "key": {"agent": Entity("host", "quiet-std")}, "status": "silent", "tier": "standard"},
        {"level": "agent", "key": {"agent": Entity("host", "weird-01")}, "status": "strange", "tier": "low"},
        {"level": "agent", "key": {"agent": Entity("host", "quiet-crit")}, "status": "silent", "tier": "critical"},
        {"level": "agent", "key": {"agent": Entity("host", "gone-01")}, "status": "tampering", "tier": "standard"},
    ]
    report = _small_report([], {"silence": {"status": "fail", "sources": rows}})
    md = render(report, "md")
    order = [md.index(name) for name in ("gone-01", "quiet-crit", "quiet-std", "weird-01", "ok-00")]
    assert order == sorted(order)
    assert "54 more not shown" in md  # the display cap drops OK rows, never the silent ones


_EXTREMES: list[Any] = [
    float("nan"),
    float("inf"),
    -float("inf"),
    10**5000,  # str() refuses ints over 4300 digits
    -(10**5000),
    10**400,  # beyond the float range
    1e308,
    -1e308,
    5e-324,
    -0.0,
    datetime.min,
    datetime.max,
    datetime.min.replace(tzinfo=timezone(timedelta(hours=14))),  # overflows when converted to UTC
    datetime.max.replace(tzinfo=timezone(timedelta(hours=-12))),
    timedelta.max,
    timedelta.min,
    "9" * 5000,
    "9999-12-31T23:59:59-12:00",
    None,
    True,
]


@pytest.mark.parametrize("lang", ["en", "es"])
def test_every_formatter_is_total_on_extreme_values(lang: str) -> None:
    """NaN, infinities, huge ints and out-of-range dates never raise, in any formatter or renderer."""
    ctx = RenderContext(None, lang)
    for value in _EXTREMES:
        for name in ("num", "pct", "pvalue", "dt", "dur", "value", "text"):
            assert isinstance(getattr(ctx, name)(value), str), (name, type(value))
    for series in ([float("nan"), 1.0], [float("inf"), 1.0], [10**400, 1], [1e308, 1e308], [-5, 0]):
        assert sparkline_text(series)
        svg = sparkline_svg(series, "x")
        assert "nan" not in svg and "inf" not in svg
        assert ctx.spark_summary(series)
    evidence = {f"k{i}": value for i, value in enumerate(_EXTREMES)}
    evidence.update({"share": 10**5000, "p": float("nan"), "last_seen": datetime.max, "gap": timedelta.max})
    evidence["daily"] = [10**400, float("inf"), 3, 4, 5, 6, 7]
    finding = _f(
        "silence.drop",
        Severity.HIGH,
        "s",
        M("testrep.generic", what=10**5000),
        reasons=[M("testrep.tune.reason", share=float("nan"), user="u", host="h", days=10**5000)],
        evidence=evidence,
        score=10**5000,  # type: ignore[arg-type]
    )
    sections: dict[str, dict[str, Any]] = {
        "noise": {
            "status": "ok",
            "totals": {"alerts": 10**5000, "days": 1e-300, "analyst_facing": 1e308, "top5_share": 10**400},
            "rules": [{"rule_id": "1", "per_day": 10**5000, "share": float("inf"), "daily": [10**400, 1, 2]}],
            "time_saved_minutes_per_day": [10**5000, float("nan")],
        },
        "silence": {
            "status": "warn",
            "alpha_eff": 10**5000,
            "status_counts": {"silent": 10**5000},
            "monitorability": {"critical_total": 10**5000, "critical_monitorable": 1, "sla_hours": float("inf")},
            "sources": [{"key": {"agent": "a1"}, "status": "silent", "last_seen": datetime.max, "p": 10**5000}],
        },
    }
    report = _small_report([finding], sections)
    report.data_basis.start, report.data_basis.end = datetime.min, datetime.max
    report.data_basis.now = datetime.max.replace(tzinfo=timezone(timedelta(hours=-12)))
    report.generated_at = datetime.min.replace(tzinfo=timezone(timedelta(hours=14)))
    report.data_basis.events = 10**5000
    for fmt in FORMATS:
        render(report, fmt, lang=lang)
        render_many([report, report], fmt, lang=lang)
    json.loads(render(report, "json", lang=lang))
    render_console(report, lang=lang, verbose=True)
