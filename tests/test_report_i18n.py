"""Report wording and layout: every label in the Spanish report is Spanish, and the report reads like a sentence.

The demo report is rendered in Spanish (Markdown, HTML, console at 80 and 120 columns, terse and verbose) and must
not leak English labels, raw snake_case keys or enum values, "(s)" plurals or dict dumps. Smaller synthetic
reports pin the layout rules: safety gates read "passed / tripped", the expected-sources table accounts for every
host, index-volume-only scopes have their own subsection, audits show rules instead of events, the data basis
tells the newest event apart from the reference "now". Synthetic data only (RFC 5737 / 1918 addresses,
``*.example`` hosts).
"""

from __future__ import annotations

import html
import io
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest
from rich.console import Console

from hushwatch.config import load_config
from hushwatch.demo import generate, load_demo_agents
from hushwatch.engine import ALL_ANALYSES, AnalysisOptions, analyze, open_sources
from hushwatch.i18n import Entity, M, Message, register
from hushwatch.i18n import render as render_message
from hushwatch.models import DataBasis, Finding, Report, Severity
from hushwatch.report import print_console, render
from hushwatch.report.markdown import md_escape

NOW = datetime(2026, 9, 25, 10, 0, tzinfo=timezone.utc)

register(
    {
        "testi18n.title": {"en": "Test finding {n}", "es": "Hallazgo de prueba {n}"},
        "testi18n.partial": {"en": "Shard {n} failed", "es": "Falló el shard {n}"},
    }
)

# ---- the demo report in Spanish --------------------------------------------------------------------------------


@pytest.fixture(scope="module")
def demo_report(tmp_path_factory: pytest.TempPathFactory) -> Report:
    out = tmp_path_factory.mktemp("demo-i18n")
    manifest = generate(out)
    tenant = load_config(manifest.config_path).tenant()
    opts = AnalysisOptions(
        analyses=frozenset(ALL_ANALYSES),
        dispositions=str(manifest.dispositions_path),
        ruleset_dirs=[str(manifest.rules_dir)],
        emit_suppressions=out / "suppressions",
        use_api=False,
    )
    source = open_sources(tenant, paths=[str(manifest.alerts_path)], options=opts)
    agents = load_demo_agents(manifest.agents_path)
    return analyze(tenant, source, options=opts, agents=agents, wallclock=manifest.now).report


def _console(report: Report, lang: str, width: int, verbose: bool = False) -> str:
    buffer = io.StringIO()
    console = Console(file=buffer, width=width, color_system=None, force_terminal=False, highlight=False)
    print_console(report, lang=lang, console=console, verbose=verbose)
    return buffer.getvalue()


def _html_text(page: str) -> str:
    page = re.sub(r"(?s)<(script|style)\b.*?</\1>", " ", page)
    return html.unescape(re.sub(r"<[^>]+>", " ", page))


def _outputs(report: Report, lang: str) -> dict[str, str]:
    return {
        "md": render(report, "md", lang=lang).replace("\\_", "_"),
        "html": _html_text(render(report, "html", lang=lang)),
        "console80": _console(report, lang, 80),
        "console_wide": _console(report, lang, 400),
        "console_verbose": _console(report, lang, 400, verbose=True),
    }


def _without_data(report: Report, text: str) -> str:
    """Remove what is data, not label: rule descriptions, finding kinds and subjects, ATT&CK tactic names."""
    data: set[str] = set()
    for rule in report.sections.get("noise", {}).get("rules", []):
        if rule.get("description"):
            data.add(str(rule["description"]))
    for finding in report.findings:
        data.update((finding.kind, finding.subject))
    text = re.sub(r"\s+", " ", text)  # console wrapping may cut a data string in two
    for item in sorted(data, key=len, reverse=True):
        item = re.sub(r"\s+", " ", item)
        text = text.replace(item, " ").replace(md_escape(item).replace("\\_", "_"), " ")
    text = re.sub(r"'[a-z_]+'", " ", text)  # a raw value quoted on purpose ("the API reports 'disconnected'")
    return re.sub(
        r"\((?:[A-Z][a-z]+(?: [A-Za-z]+)*, )*[A-Z][a-z]+(?: [A-Za-z]+)*\)", " ", text
    )  # "(Credential Access)"


# Label words that leaked in English before (section keys, evidence keys, enum values).
_ENGLISH_LABELS = (
    "Backtested",
    "Learning",
    "Verdicts",
    "Skipped events",
    "Alarm budget",
    "Input kind",
    "Partial failures",
    "Data end",
    "Now origin",
    "Age hours",
    "Reason",
    "Gap seconds",
    "Expected in gap",
    "Baseline days",
    "Novelty",
    "Persistence:",
    "Burst:",
    "Suggestion",
    "Alerts upper bound",
    "Analyst facing",
    "Days present",
    "Days elapsed",
    "Dependents verified",
    "Public sources",
    "Co occurrence",
    "Peer comparable",
    "Api only",
    "Data only",
    "Relayed",
    "By status",
    "Threshold seconds",
    "Not assessed",
    "Counters",
    "Peer gaps",
    "Event types",
    "Status reasons",
    "History days",
    "Stock rules",
    "Correlation verified",
    "Hidden per day",
    "Analyst-facing hidden",
    "Sources assessed",
    "Lagging",
    "Tz offset",
    "Worst:",
    "Explained count",
    "Sla hours",
    "Last event",
    "Agent id",
    "Rate per hour",
    "Frozen baseline",
    "Off day",
    "Name patterns",
    "Anchor code",
    "Days overdue",
    "Window:",
    "Start:",
    "End:",
    "Network",
    "Unknown",
    "monitorizab",
    "arriesgad",
    "caducad",
    "Añada",
)
# Enum values and keys that must never be shown raw in the Spanish report.
_RAW_VALUES = re.compile(
    r"\b(?:investigate|review|demote|do_not_tune|fix_at_source|never_connected|disconnected|active|contract|peers|"
    r"no_stats|gaps_not_assessed|short_history|p50_seconds|p95_seconds|not_assessed_hosts|verdict_counts|"
    r"peer_comparable|days_present|alerts_upper_bound|analyst_facing|upper_bound_estimate)\b"
)
# snake_case words that are legitimately shown: Wazuh settings and rule syntax, file names, user names.
_ALLOWED_SNAKE = frozenset(
    {
        "log_alert_level",
        "logall_json",
        "trusted_entities",
        "if_matched_group",
        "if_matched_sid",
        "same_srcip",
        "no_log",
        "hushwatch_local_rules",
        "local_rules",
        "svc_backup",
        "naive_timezone",
    }
)


def test_spanish_demo_report_has_no_english_labels_or_raw_keys(demo_report: Report) -> None:
    for fmt, text in _outputs(demo_report, "es").items():
        clean = _without_data(demo_report, text)
        for label in _ENGLISH_LABELS:
            assert label not in clean, (fmt, label)
        raw = _RAW_VALUES.search(clean)
        assert raw is None, (
            fmt,
            raw.group(0) if raw else "",
            clean[max(0, raw.start() - 80) : raw.end() + 40] if raw else "",
        )
        snake = set(re.findall(r"\b[a-z][a-z0-9]*_[a-z0-9_]+\b", clean)) - _ALLOWED_SNAKE
        assert not snake, (fmt, sorted(snake))
        assert "(s)" not in clean and "(es)" not in clean, fmt
        assert "check: win_4688" not in clean and "kind: ok" not in clean, fmt  # no dict dumps


def test_spanish_demo_report_uses_the_domain_vocabulary(demo_report: Report) -> None:
    md = render(demo_report, "md", lang="es")
    assert "monitoreables" in md and "Supresiones riesgosas" in md and "vencida" in md
    assert "Degradadas por día" in md and "Degradadas visibles para analistas" in md
    assert "No evaluado / explicado" in md  # the expected-sources column
    assert "✓ superado" in md and "✗ disparado" in md  # safety gates
    assert "Solo volumen del índice" in md  # index-volume scopes have their own subsection
    assert "Ajustar (con alcance)" in md  # a scoped tune verdict in the rules table


def test_english_demo_report_reads_well(demo_report: Report) -> None:
    for fmt, text in _outputs(demo_report, "en").items():
        clean = _without_data(demo_report, text)
        assert "(s)" not in clean, fmt
        assert not re.search(r"(?<![\d.,])\b1 (alerts|events|agents|findings|rules|days)\b", clean), fmt
        assert "0–0 min/day" not in clean and "last event -" not in clean and "about >" not in clean, fmt
        assert "Hidden per day" not in clean and "Demoted per day" in text, fmt
    md = render(demo_report, "md")
    assert "Safe tuning candidates | ✅ **1** | +1 that require review · 1 index-volume only" in md


def test_console_at_80_columns_never_cuts_identifiers(demo_report: Report) -> None:
    for lang in ("es", "en"):
        text = _console(demo_report, lang, 80)
        assert "Microsoft-Windows-Sysmon/Operational" in text, lang
        for broken in ("Microsof\n", "Sysmon/Op\n", "Coincid\n", "Contrat\n"):
            assert broken not in text, (lang, broken)
        assert all(len(line) <= 80 for line in text.splitlines()), lang


# ---- small synthetic reports --------------------------------------------------------------------------------------


def _finding(kind: str, **kw: Any) -> Finding:
    kw.setdefault("severity", Severity.MEDIUM)
    kw.setdefault("subject", kind)
    kw.setdefault("title", M("testi18n.title", n=1))
    return Finding(kind=kind, domain=kind.split(".", 1)[0], tenant="acme", **kw)


def _report(findings: list[Finding], sections: dict[str, Any] | None = None, **basis: Any) -> Report:
    values: dict[str, Any] = {
        "input_kind": "archives",
        "profile": "wazuh4",
        "start": NOW - timedelta(days=21),
        "end": NOW,
        "now": NOW,
        "events": 1000,
    }
    values.update(basis)
    return Report("acme", NOW, "0.1.0", DataBasis(**values), findings, sections or {})


def test_safety_gates_read_passed_or_tripped() -> None:
    finding = _finding("noise.investigate", evidence={"gates": {"burst": False, "novelty": True}})
    for lang, passed, tripped in (("en", "✓ passed", "✗ tripped"), ("es", "✓ superado", "✗ disparado")):
        md = render(_report([finding]), "md", lang=lang)
        assert passed in md and tripped in md, lang
        assert "Burst: no" not in md and "Picos: no" not in md


def test_expected_sources_table_accounts_for_every_host() -> None:
    row = {
        "basis": "contract",
        "name": "domain controllers",
        "log_source": "Security",
        "matched": 2,
        "present": 1,
        "missing": 0,
        "silent": 0,
        "not_assessed": 1,
        "not_assessed_hosts": [Entity("host", "dc02.example")],
        "low": 0,
    }
    sections = {"coverage": {"status": "warn", "expected_sources": [row], "matrix": []}}
    md = render(_report([], sections), "md", lang="es")
    header = next(line for line in md.splitlines() if line.startswith("| Base |"))
    assert "No evaluado / explicado" in header
    assert "| Contrato | domain controllers | Security | 2 | 1 | 0 | 0 | 1 (dc02.example) |" in md


def test_explained_findings_are_listed_instead_of_bare_fingerprints() -> None:
    item = M("testi18n.title", n=7)
    finding = _finding(
        "silence.tampering",
        related=["c8d36e179bd8e76627bc"],
        evidence={"explained": [item], "explained_count": 1},
    )
    for lang, heading in (("en", "Also explains"), ("es", "También explica")):
        for fmt in ("md", "html"):
            text = render(_report([finding]), fmt, lang=lang)
            assert heading in text and "c8d36e179bd8e76627bc" not in text, (lang, fmt)
        assert render_message(item, lang) in render(_report([finding]), "md", lang=lang)


def test_audit_report_shows_rules_not_events() -> None:
    sections = {"tuning": {"status": "fail", "rules_parsed": 51, "risky": 2}}
    report = _report(
        [_finding("tuning.risky_suppression", severity=Severity.HIGH)],
        sections,
        input_kind="ruleset",
        start=None,
        end=None,
        now=NOW,
        now_origin="wallclock",
        events=51,
    )
    for lang, rules, events, period in (
        ("en", "Rules parsed", "Events analyzed", "Period"),
        ("es", "Reglas analizadas", "Eventos analizados", "Periodo"),
    ):
        md = render(report, "md", lang=lang)
        assert rules in md and events not in md and f"**{period}:**" not in md, lang
        status = md.split("## 2.", 1)[1].split("## 3.", 1)[0]
        assert ("Tuning debt" if lang == "en" else "Deuda de tuning") in status
        for other in ("Noise", "Silence", "Coverage") if lang == "en" else ("Ruido", "Silencio", "Cobertura"):
            assert other not in status, (lang, other)
        text = _console(report, lang, 100)
        assert rules in text and "(?)" not in text


def test_alerts_only_banner_names_wazuh_only_for_wazuh_input() -> None:
    wazuh = render(_report([], input_kind="alerts", profile="wazuh4"), "md", lang="es")
    ecs = render(_report([], input_kind="alerts", profile="ecs"), "md", lang="es")
    assert "log\\_alert\\_level" in wazuh
    banner = ecs.split("## 1.", 1)[0]
    assert "Solo alertas" in banner and "Wazuh" not in banner and "log\\_alert\\_level" not in banner


def test_now_flag_keeps_newest_event_and_reference_now_apart() -> None:
    end = NOW - timedelta(days=5)
    report = _report(
        [],
        {"pipeline": {"status": "ok", "checks": [{"check": "freshness", "status": "ok", "age_hours": 0}]}},
        end=end,
        now=NOW,
        now_origin="flag",
    )
    md = render(report, "md", lang="es")
    assert "**Evento más reciente de la entrada** | 2026-09-20 10:00 UTC" in md
    assert "fijado con --now" in md
    freshness = next(line for line in md.splitlines() if line.startswith("| Actualidad de los datos"))
    assert "2026-09-20 10:00 UTC" in freshness and "2026-09-25 10:00 UTC" in freshness


def test_data_age_is_measured_from_the_newest_event() -> None:
    report = _report([], end=NOW - timedelta(days=3), now=NOW, now_origin="flag")
    report.generated_at = NOW
    md = render(report, "md")
    assert "data ends 3d before this report was generated" in md


def test_partial_failures_and_exclusions_render_in_the_report_language() -> None:
    report = _report(
        [],
        partial_failures=[M("testi18n.partial", n=3), "indexer https://indexer.example:9200 timed out"],
        excluded_by_window=12,
        excluded_newest=NOW - timedelta(days=30),
        skipped_files=["notes.txt"],
        not_evaluated=["agent-inventory"],
    )
    md = render(report, "md", lang="es")
    assert "Falló el shard 3" in md and "testi18n.partial" not in md
    assert "Eventos fuera de la ventana de análisis" in md and "2026-08-26 10:00 UTC" in md
    assert "Archivos omitidos" in md and "notes.txt" in md
    status = md.split("## 2.", 1)[1].split("## 3.", 1)[0]
    assert "No evaluado: Inventario de agentes" in status  # shown on the pipeline card
    doc = json.loads(render(report, "json", lang="es"))
    first = doc["data_basis"]["partial_failures"][0]
    assert first["text"] == "Falló el shard 3" and first["key"] == "testi18n.partial"


def test_noise_section_keys_and_index_volume_subsection() -> None:
    index = _finding(
        "noise.index_volume",
        severity=Severity.LOW,
        evidence={"verdict": "watch", "impact": "index_volume", "backtest": {"hidden_per_day": 150.0}},
    )
    sections = {
        "noise": {
            "status": "warn",
            "totals": {"alerts": 1, "analyst_facing": 1, "rules": 1, "days": 21.0, "clusters": 1},
            "rules": [{"rule_id": "60106", "verdict": "tune", "verdict_scoped": True, "share": 0.0004}],
            "time_saved_minutes_per_day": [0.0, 0.0],
            "safe_tuning_candidates": 0,
            "review_required_candidates": 0,
            "index_volume_candidates": 1,
            "window": {"start": "2026-09-04T10:00:00Z", "end": "2026-09-25T10:00:00Z", "days": 21.0, "dates": 22},
        }
    }
    md = render(_report([index], sections), "md", lang="es")
    assert "### Solo volumen del índice (ningún analista ve estas alertas)" in md
    assert "Ajustar (con alcance)" in md and "&lt;0,1%" in md
    assert "ninguno: ninguna sugerencia quita alertas visibles para analistas" in md and "0–0" not in md
    assert "Días transcurridos: 21" in md and "Días de calendario: 22" in md
    assert "1 alerta en 21 días" in md and "1 regla" in md
    en = render(_report([index], sections), "md")
    assert "1 alert over 21 days" in en and "none: no suggestion removes analyst-facing alerts" in en


def test_pipeline_details_are_sentences_not_dict_dumps() -> None:
    lag = {
        "check": "ingest_lag",
        "status": "ok",
        "threshold_seconds": 900.0,
        "worst": [{"agent": Entity("host", "lap-010.example"), "samples": 256, "p50_seconds": 1.3, "p95_seconds": 2.4}],
    }
    daemons = {"check": "manager_daemons", "status": "not_assessed", "reason": "no_stats", "daemons": []}
    md = render(_report([], {"pipeline": {"status": "ok", "checks": [lag, daemons]}}), "md", lang="es")
    assert "lap-010.example: mediana 1,3 s, p95 2,4 s (256 muestras)" in md
    assert "Umbral de retraso: 15m" in md
    assert "No hubo estadísticas del manager de Wazuh" in md and "no_stats" not in md.replace("\\_", "_")


def test_plural_format_spec() -> None:
    register({"testi18n.plural": {"en": "{n} {n:plural:alert|alerts}", "es": "{n} {n:plural:alerta|alertas}"}})
    assert render_message(M("testi18n.plural", n=1)) == "1 alert"
    assert render_message(M("testi18n.plural", n=2)) == "2 alerts"
    assert render_message(M("testi18n.plural", n=0), "es") == "0 alertas"
    assert render_message(M("testi18n.plural", n=1), "es") == "1 alerta"
    assert render_message(M("testi18n.plural", n="1")) == "1 alert"  # already-formatted numbers work too
    assert isinstance(M("testi18n.plural", n=1), Message)


def test_small_shares_are_never_zero_percent() -> None:
    from hushwatch.report.common import RenderContext

    en, es = RenderContext(None, "en"), RenderContext(None, "es")
    assert en.pct(0.000004) == "<0.1%" and es.pct(0.000004) == "<0,1%"
    assert en.pct(0.004) == "0.4%" and en.pct(0.0) == "0%"


def test_every_demo_catalog_text_has_spanish(tmp_path: Path) -> None:
    """Every registered message has a Spanish text (new keys must not fall back to English)."""
    import importlib
    import pkgutil

    import hushwatch
    from hushwatch import i18n

    for module in pkgutil.walk_packages(hushwatch.__path__, "hushwatch."):
        importlib.import_module(module.name)
    missing = [key for key in i18n._CATALOG if not key.startswith("test") and not i18n._CATALOG[key].get("es")]
    assert not missing, missing[:20]


def test_uuid_rule_ids_are_shortened_next_to_the_rule_name() -> None:
    uuid = "0b6a2b8e-3c1d-4f5e-9a7b-1c2d3e4f5a6b"
    sections = {"noise": {"status": "ok", "rules": [{"rule_id": uuid, "description": "Suspicious PowerShell"}]}}
    md = render(_report([], sections, profile="ecs"), "md")
    row = next(line for line in md.splitlines() if "Suspicious PowerShell" in line)
    assert "0b6a2b8e…" in row and uuid not in row
