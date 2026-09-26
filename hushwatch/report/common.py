"""Shared building blocks for every report renderer (JSON, Markdown, console, HTML).

Every renderer goes through a :class:`RenderContext`, the single place where report data becomes display text.
Each data-derived string passes through four steps, in this order:

1. **Sanitize** — C0/C1 control characters (ANSI ``ESC`` included), bidi overrides, zero-width and Unicode tag
   characters are removed, line breaks become spaces, lone surrogates become U+FFFD. No data string can move
   the terminal cursor, spoof text direction, hide text or crash a UTF-8 write.
2. **Cap** — strings longer than :data:`MAX_TEXT` are cut at a separator and marked, so a 1 MB log value can
   neither bloat a report nor make redaction slow.
3. **Redact** (only with a :class:`~hushwatch.redact.Redactor`) — :class:`~hushwatch.i18n.Entity` values become
   pseudonyms, free text goes through ``Redactor.text`` plus a conservative FQDN pass (host names inside URLs),
   and ``Finding.subject`` becomes a ``val-…`` token. A rendered message is redacted as a whole (its template
   too, in case a module put a raw value in a default text), never piecewise, so no identifier is split across
   two redaction calls. Before rendering, every entity in the report, every identifier found in structured
   subjects, and every plain string stored under an identifying key (``agent``, ``user``, ``srcip``...) is
   taught to the redactor, so it is also caught inside free text. Keys are redacted before they are humanized
   (``dc01.corp.example`` must not become an unrecognizable ``dc01 › corp › example``).
4. **Escape** — done by each renderer for its own sink (HTML, Markdown, Rich); never here.

:func:`build_view` turns a :class:`~hushwatch.models.Report` into a :class:`ReportView` made only of display
strings and numbers, which the Markdown, console and HTML renderers lay out. The JSON renderer uses the same
context for its values. All labels are registered here in English and Spanish (keys ``report.*``).
"""

from __future__ import annotations

import math
import re
import sys
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from enum import Enum
from typing import Any

from ..i18n import DEFAULT_LANG, LANGS, Entity, M, Message, has, register
from ..i18n import render as render_message
from ..models import DOMAINS, SCHEMA_VERSION, DataBasis, Finding, Report, Severity, is_empty
from ..redact import Redactor
from ..timeutil import UTC, humanize, parse_ts
from .labels import ENUM_KEYS  # importing it registers the report.ev.* / report.val.* labels

__all__ = [
    "DOMAIN_SECTIONS",
    "FORMATS",
    "MAX_TEXT",
    "SEVERITY_ORDER",
    "STATUSES",
    "BasisView",
    "CheckRow",
    "CoverageView",
    "DomainCard",
    "EvidenceRow",
    "Fact",
    "FindingGroup",
    "FindingView",
    "FleetRow",
    "InvestigateRow",
    "KeyNumber",
    "MatrixRow",
    "NoiseView",
    "PipelineView",
    "RenderContext",
    "ReportView",
    "RuleRow",
    "SilenceView",
    "SourceRow",
    "TuneRow",
    "TuningView",
    "basis_caveats",
    "basis_complete",
    "build_view",
    "domain_statuses",
    "finite_series",
    "fleet_footer",
    "fleet_rows",
    "incomplete_reasons",
    "is_alerts_only",
    "is_audit",
    "iso_utc",
    "normalize_lang",
    "order_findings",
    "prepare_context",
    "reasons_of",
    "sanitize",
    "severity_name",
    "sparkline_text",
]

FORMATS: tuple[str, ...] = ("json", "md", "html")
STATUSES: tuple[str, ...] = ("ok", "warn", "fail", "not_assessed")
SEVERITY_ORDER: tuple[str, ...] = ("critical", "high", "medium", "low", "info")
DOMAIN_SECTIONS: tuple[str, ...] = ("noise", "silence", "coverage", "pipeline", "tuning")

MAX_TEXT = 4096  # longest data string kept (characters), before display-specific truncation
_MAX_LEARN = 4096  # entity values longer than this are not taught to the redactor (they are capped anyway)
_MAX_ITEMS = 12  # items shown when a list/dict value is rendered inline
_MAX_DEPTH = 6
_CACHE_LIMIT = 50_000

_STATUS_RANK = {"not_assessed": -1, "ok": 0, "warn": 1, "fail": 2}
_SPARK_BLOCKS = "▁▂▃▄▅▆▇█"

# ---- sanitization ---------------------------------------------------------------------------------------------

_SURROGATES = re.compile("[\ud800-\udfff]")
_SPACES = re.compile("[\t\n\r\x0b\x0c\x85  ]")
_CONTROLS = re.compile(
    "[\x00-\x08\x0e-\x1f\x7f-\x9f"  # C0 (minus the whitespace handled above), DEL, C1 (incl. CSI \x9b)
    "؜᠎​-‏‪-‮⁠-⁤⁦-⁩﻿￹-￻"  # bidi, zero-width
    "\U000e0000-\U000e007f]"  # Unicode tag characters (invisible "ASCII smuggling")
)
_USERINFO = re.compile(r"(?i)\b([a-z][a-z0-9+.-]{1,15}://)[^/@\s]{1,256}@")


def sanitize(text: str) -> str:
    """Remove every character that could control a terminal, reorder text, hide text or break encoding."""
    text = _SURROGATES.sub("�", text)
    text = _SPACES.sub(" ", text)
    return _CONTROLS.sub("", text)


# Conservative FQDN detector (second redaction pass): dotted names ending in a TLD that is rarely a file
# extension. It complements the core host-name detector of ``Redactor.text`` (same lower-cased token).
_TLDS = (
    "com|net|org|edu|gov|mil|int|info|biz|io|co|me|dev|cloud|online|site|tech|local|localdomain|localhost|"
    "internal|intranet|corp|lan|priv|private|example|test|invalid|arpa|es|ar|cl|mx|uy|pe|br|bo|ec|ve|cr|gt|"
    "hn|ni|pa|sv|cu|uk|de|fr|it|pt|nl|be|ch|se|dk|fi|ie|eu|us|ca|au|nz|jp|cn|ru"
)
# Unlike the core detector it also matches after "/" and "@", i.e. the host of a URL (``https://x.corp.example``)
# and of a URL whose credentials were removed (``https://***@x.corp.example``). E-mail addresses never reach
# it: ``Redactor.text`` has already replaced them.
_FQDN = re.compile(
    r"(?<![\w.-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.){1,10}(?:" + _TLDS + r")(?![\w-])",
    re.IGNORECASE,
)
_SEPARATORS = frozenset(" ,;|\"'<>()[]{}/\\")

# ---- label catalog --------------------------------------------------------------------------------------------

_LABELS: dict[str, dict[str, str]] = {
    # document
    "report.title": {"en": "SIEM hygiene report", "es": "Informe de higiene del SIEM"},
    "report.tagline": {"en": "Hush the noise, watch the silence.", "es": "Acallar el ruido, vigilar el silencio."},
    "report.tenant": {"en": "Tenant", "es": "Cliente"},
    "report.generated": {"en": "Generated", "es": "Generado"},
    "report.period": {"en": "Period", "es": "Periodo"},
    "report.language": {"en": "Language", "es": "Idioma"},
    "report.redaction": {"en": "Identifiers", "es": "Identificadores"},
    "report.redaction.on": {"en": "Pseudonymized", "es": "Seudonimizados"},
    "report.redaction.off": {"en": "Real values", "es": "Valores reales"},
    "report.contents": {"en": "Contents", "es": "Contenido"},
    "report.eyebrow": {"en": "Read-only analysis", "es": "Análisis de solo lectura"},
    "report.toc.status": {"en": "Status", "es": "Estado"},
    "report.toc.findings": {"en": "Findings", "es": "Hallazgos"},
    "report.skip": {"en": "Skip to content", "es": "Ir al contenido"},
    "report.unknown": {"en": "unknown", "es": "desconocido"},
    "report.none": {"en": "none", "es": "ninguno"},
    "report.yes": {"en": "yes", "es": "sí"},
    "report.no": {"en": "no", "es": "no"},
    "report.dash": {"en": "—", "es": "—"},
    "report.truncated": {"en": "… [{n} more characters]", "es": "… [{n} caracteres más]"},
    "report.more_rows": {"en": "{n} more not shown", "es": "{n} más sin mostrar"},
    "report.more_items": {"en": "+{n} more", "es": "+{n} más"},
    "report.range": {"en": "{start} → {end} ({duration})", "es": "{start} → {end} ({duration})"},
    "report.ago": {"en": "{duration} ago", "es": "hace {duration}"},
    "report.per_day": {"en": "{value}/day", "es": "{value}/día"},
    "report.of": {"en": "{part} of {total}", "es": "{part} de {total}"},
    "report.not_assessed.section": {
        "en": "Not assessed: this analysis did not run or the input could not support it. This is not a green light.",
        "es": "No evaluado: este análisis no se ejecutó o la entrada no lo permitía. Esto no es una luz verde.",
    },
    "report.no_details": {"en": "No details available.", "es": "No hay detalles disponibles."},
    "report.details": {"en": "Other details", "es": "Otros detalles"},
    # section headings
    "report.section.basis": {"en": "Data basis", "es": "Datos analizados"},
    "report.section.status": {"en": "Status by domain", "es": "Estado por dominio"},
    "report.section.numbers": {"en": "Key numbers", "es": "Cifras clave"},
    "report.section.noise": {
        "en": "Noise: what can be safely tuned",
        "es": "Ruido: qué se puede ajustar con seguridad",
    },
    "report.section.silence": {"en": "Silence: what stopped reporting", "es": "Silencio: qué dejó de reportar"},
    "report.section.coverage": {"en": "Coverage", "es": "Cobertura"},
    "report.section.pipeline": {"en": "Pipeline health", "es": "Salud del pipeline"},
    "report.section.tuning": {
        "en": "Tuning audit (existing suppressions)",
        "es": "Auditoría de supresiones existentes",
    },
    "report.section.findings": {"en": "All findings", "es": "Todos los hallazgos"},
    "report.section.other": {"en": "Other analyses", "es": "Otros análisis"},
    # data basis banner
    "report.basis.input": {"en": "Input", "es": "Entrada"},
    "report.basis.profile": {"en": "Profile", "es": "Perfil"},
    "report.basis.sources": {"en": "Sources", "es": "Fuentes"},
    "report.basis.range": {"en": "Time range", "es": "Intervalo temporal"},
    "report.basis.now": {"en": "Reference “now”", "es": "Referencia de «ahora»"},
    "report.basis.age": {"en": "Data age", "es": "Antigüedad de los datos"},
    "report.basis.age_value": {
        "en": "data ends {duration} before this report was generated",
        "es": "los datos terminan {duration} antes de generar este informe",
    },
    "report.basis.events": {"en": "Events analyzed", "es": "Eventos analizados"},
    "report.basis.rules": {"en": "Rules parsed", "es": "Reglas analizadas"},
    "report.basis.newest": {"en": "Newest event in the input", "es": "Evento más reciente de la entrada"},
    "report.basis.excluded": {
        "en": "Events outside the analysis window (read, not analyzed)",
        "es": "Eventos fuera de la ventana de análisis (leídos, no analizados)",
    },
    "report.basis.excluded_newest": {"en": "the newest of them: {at}", "es": "el más reciente: {at}"},
    "report.basis.skipped_files": {
        "en": "Files skipped (not JSON, NDJSON or CSV)",
        "es": "Archivos omitidos (no son JSON, NDJSON ni CSV)",
    },
    "report.basis.malformed": {"en": "Malformed records", "es": "Registros mal formados"},
    "report.basis.bad_ts": {"en": "Unparseable timestamps", "es": "Marcas de tiempo ilegibles"},
    "report.basis.future_ts": {"en": "Future timestamps", "es": "Marcas de tiempo futuras"},
    "report.basis.sampled": {"en": "Sampled", "es": "Muestreado"},
    "report.basis.truncated": {"en": "Truncated (caps hit)", "es": "Truncado (límites alcanzados)"},
    "report.basis.partial": {"en": "Partial failures", "es": "Fallos parciales"},
    "report.basis.warnings": {"en": "Warnings", "es": "Advertencias"},
    "report.basis.not_evaluated": {"en": "Analyses not evaluated", "es": "Análisis no evaluados"},
    "report.basis.complete": {"en": "Analysis complete", "es": "Análisis completo"},
    "report.basis.complete_body": {
        "en": "Every requested analysis ran over the data described below.",
        "es": "Todos los análisis solicitados se ejecutaron sobre los datos descritos a continuación.",
    },
    "report.basis.incomplete": {"en": "Analysis incomplete", "es": "Análisis incompleto"},
    "report.basis.incomplete_body": {
        "en": "Part of the analysis could not run or saw partial data. Missing findings do NOT mean all is well.",
        "es": "Parte del análisis no pudo ejecutarse o vio datos parciales. "
        "La ausencia de hallazgos NO significa que todo esté bien.",
    },
    "report.basis.reason.no_events": {"en": "No events were analyzed.", "es": "No se analizó ningún evento."},
    "report.basis.reason.truncated": {
        "en": "Caps were hit: part of the input was not analyzed.",
        "es": "Se alcanzaron límites: parte de la entrada no se analizó.",
    },
    "report.basis.reason.partial": {
        "en": "{n} partial {n:plural:failure|failures}: some data could not be read.",
        "es": "{n} {n:plural:fallo parcial|fallos parciales}: no se pudieron leer algunos datos.",
    },
    "report.basis.reason.assessment": {
        "en": "The assessment domain reports a problem.",
        "es": "El dominio de evaluación informa de un problema.",
    },
    "report.input.alerts": {"en": "Alerts only", "es": "Solo alertas"},
    "report.input.indexer-alerts": {"en": "Alerts only (indexer)", "es": "Solo alertas (indexador)"},
    "report.input.archives": {"en": "All events (archives)", "es": "Todos los eventos (archives)"},
    "report.input.indexer-archives": {
        "en": "All events (indexer archives)",
        "es": "Todos los eventos (archives del indexador)",
    },
    "report.input.mixed": {"en": "Mixed (alerts and archives)", "es": "Mixta (alertas y archives)"},
    "report.input.ruleset": {"en": "Ruleset only", "es": "Solo reglas (ruleset)"},
    "report.input.unknown": {"en": "Unknown", "es": "Desconocida"},
    "report.profile.wazuh4": {"en": "Wazuh 4.x", "es": "Wazuh 4.x"},
    "report.profile.wazuh5": {"en": "Wazuh 5.x (best effort)", "es": "Wazuh 5.x (soporte parcial)"},
    "report.profile.ecs": {"en": "Elastic Common Schema (ECS)", "es": "Elastic Common Schema (ECS)"},
    "report.profile.generic": {"en": "Generic field mapping", "es": "Mapeo de campos genérico"},
    "report.profile.mixed": {"en": "Mixed", "es": "Mixto"},
    "report.profile.unknown": {"en": "Unknown", "es": "Desconocido"},
    "report.caveat.alerts_only": {
        "en": "Alerts only: this input holds only rule matches at or above the Wazuh log_alert_level (3 by default). "
        "Silence measured here is alert silence, not log-source silence, so silence findings carry reduced "
        "confidence and quiet sources that never raise alerts are invisible.",
        "es": "Solo alertas: esta entrada contiene únicamente coincidencias de reglas iguales o superiores al "
        "log_alert_level de Wazuh (3 por defecto). El silencio medido aquí es silencio de alertas, no de la "
        "fuente de logs: los hallazgos de silencio tienen confianza reducida y las fuentes que nunca generan "
        "alertas son invisibles.",
    },
    "report.caveat.alerts_only_generic": {
        "en": "Alerts only: this input holds only detection-rule matches (alerts), not every log event. Silence "
        "measured here is alert silence, not log-source silence, so silence findings carry reduced confidence and "
        "quiet sources that never raise alerts are invisible.",
        "es": "Solo alertas: esta entrada contiene únicamente coincidencias de reglas de detección (alertas), no "
        "todos los eventos de los logs. El silencio medido aquí es silencio de alertas, no de la fuente de logs: "
        "los hallazgos de silencio tienen confianza reducida y las fuentes que nunca generan alertas son "
        "invisibles.",
    },
    "report.caveat.mixed": {
        "en": "Part of this input is alerts-only: for those sources, silence is alert silence, not log-source silence.",
        "es": "Parte de esta entrada es solo de alertas: para esas fuentes, el silencio es silencio de alertas, "
        "no de la fuente de logs.",
    },
    "report.caveat.unknown": {
        "en": "Unknown input kind: silence may reflect alert silence rather than log-source silence.",
        "es": "Tipo de entrada desconocido: el silencio puede reflejar silencio de alertas y no de la fuente de logs.",
    },
    "report.caveat.wazuh5": {
        "en": "Wazuh 5.x data is parsed on a best-effort basis; suppression rules are never generated for it.",
        "es": "Los datos de Wazuh 5.x se interpretan con soporte parcial; nunca se generan reglas de supresión.",
    },
    "report.caveat.sampled": {
        "en": "Sampled input: counts are estimates and rare events may be missing.",
        "es": "Entrada muestreada: los conteos son estimaciones y pueden faltar eventos poco frecuentes.",
    },
    "report.now_origin.data": {"en": "newest event in the input", "es": "evento más reciente de la entrada"},
    "report.now_origin.flag": {"en": "set with --now", "es": "fijado con --now"},
    "report.now_origin.wallclock": {"en": "system clock", "es": "reloj del sistema"},
    # status cards
    "report.card.no_findings": {"en": "No findings", "es": "Sin hallazgos"},
    "report.card.not_assessed": {
        "en": "Not run or not supported by this input: not a green light.",
        "es": "No se ejecutó o la entrada no lo permite: no es una luz verde.",
    },
    "report.card.incomplete": {
        "en": "No findings in the data that could be read, but the analysis was incomplete: not a green light.",
        "es": "Sin hallazgos en los datos que se pudieron leer, pero el análisis estuvo incompleto: "
        "no es una luz verde.",
    },
    "report.card.assessment_incomplete": {
        "en": "Analysis incomplete: see the data basis above.",
        "es": "Análisis incompleto: vea los datos analizados más arriba.",
    },
    "report.card.count": {"en": "{n} {severity}", "es": "{severity}: {n}"},
    "report.card.findings": {"en": "{n} {n:plural:finding|findings}", "es": "{n} {n:plural:hallazgo|hallazgos}"},
    "report.card.not_evaluated": {"en": "Not evaluated: {what}", "es": "No evaluado: {what}"},
    # key numbers
    "report.kpi.events": {"en": "Events analyzed", "es": "Eventos analizados"},
    "report.kpi.analyst_facing": {"en": "Analyst-facing alerts per day", "es": "Alertas para analistas por día"},
    "report.kpi.top5": {
        "en": "Alert volume from the top 5 rules",
        "es": "Volumen de alertas de las 5 reglas principales",
    },
    "report.kpi.tune": {"en": "Safe tuning candidates", "es": "Candidatos de ajuste seguros"},
    "report.kpi.tune_hint": {"en": "+{n} that require review", "es": "+{n} con revisión obligatoria"},
    "report.kpi.index_hint": {
        "en": "{n} index-volume only",
        "es": "{n} solo de volumen del índice",
    },
    "report.kpi.rules": {"en": "Rules parsed", "es": "Reglas analizadas"},
    "report.kpi.silent": {"en": "Silent or dropped sources", "es": "Fuentes silenciosas o en caída"},
    "report.kpi.monitorable": {
        "en": "Critical sources monitorable within SLA",
        "es": "Fuentes críticas monitoreables dentro del SLA",
    },
    "report.kpi.coverage": {"en": "Coverage gaps", "es": "Brechas de cobertura"},
    "report.kpi.risky": {"en": "Risky or expired suppressions", "es": "Supresiones riesgosas o vencidas"},
    "report.kpi.na": {"en": "not assessed", "es": "no evaluado"},
    "report.kpi.days": {"en": "over {days} days", "es": "en {days} días"},
    # columns
    "report.col.domain": {"en": "Domain", "es": "Dominio"},
    "report.col.status": {"en": "Status", "es": "Estado"},
    "report.col.findings": {"en": "Findings", "es": "Hallazgos"},
    "report.col.metric": {"en": "Metric", "es": "Métrica"},
    "report.col.value": {"en": "Value", "es": "Valor"},
    "report.col.note": {"en": "Note", "es": "Nota"},
    "report.col.item": {"en": "Item", "es": "Elemento"},
    "report.col.rule": {"en": "Rule", "es": "Regla"},
    "report.col.description": {"en": "Description", "es": "Descripción"},
    "report.col.level": {"en": "Level", "es": "Nivel"},
    "report.col.total": {"en": "Total", "es": "Total"},
    "report.col.per_day": {"en": "Per day", "es": "Por día"},
    "report.col.analyst_facing": {"en": "Analyst-facing", "es": "Para analistas"},
    "report.col.share": {"en": "Share", "es": "Proporción"},
    "report.col.clusters": {"en": "Clusters", "es": "Clústeres"},
    "report.col.days_active": {"en": "Days active", "es": "Días activos"},
    "report.col.anchor": {"en": "Top anchor", "es": "Ancla principal"},
    "report.col.verdict": {"en": "Verdict", "es": "Veredicto"},
    "report.col.trend": {"en": "Daily trend", "es": "Tendencia diaria"},
    "report.col.suggestion": {"en": "Suggestion", "es": "Sugerencia"},
    "report.col.scope": {"en": "Scope", "es": "Alcance"},
    "report.col.hidden_per_day": {"en": "Demoted per day", "es": "Degradadas por día"},
    "report.col.share_of_rule": {"en": "Share of rule", "es": "Proporción de la regla"},
    "report.col.af_hidden": {"en": "Analyst-facing demoted", "es": "Degradadas visibles para analistas"},
    "report.col.agents": {"en": "Agents", "es": "Agentes"},
    "report.col.expires": {"en": "Expires", "es": "Vence"},
    "report.col.review": {"en": "Review", "es": "Revisión"},
    "report.col.source": {"en": "Source", "es": "Fuente"},
    "report.col.source_level": {"en": "Level", "es": "Nivel"},
    "report.col.last_seen": {"en": "Last seen", "es": "Visto por última vez"},
    "report.col.observed": {"en": "Observed", "es": "Observado"},
    "report.col.expected": {"en": "Expected", "es": "Esperado"},
    "report.col.p": {"en": "p", "es": "p"},
    "report.col.tier": {"en": "Tier", "es": "Criticidad"},
    "report.col.duty": {"en": "Activity pattern", "es": "Patrón de actividad"},
    "report.col.agent": {"en": "Agent", "es": "Agente"},
    "report.col.platform": {"en": "Platform", "es": "Plataforma"},
    "report.col.check": {"en": "Check", "es": "Control"},
    "report.col.detail": {"en": "Detail", "es": "Detalle"},
    "report.col.severity": {"en": "Severity", "es": "Severidad"},
    "report.col.finding": {"en": "Finding", "es": "Hallazgo"},
    "report.col.tenant": {"en": "Tenant", "es": "Cliente"},
    "report.col.critical": {"en": "Critical", "es": "Críticos"},
    "report.col.high": {"en": "High", "es": "Altos"},
    "report.col.events": {"en": "Events", "es": "Eventos"},
    "report.col.data": {"en": "Data", "es": "Datos"},
    "report.col.worst": {"en": "Most severe finding", "es": "Hallazgo más grave"},
    # noise
    "report.noise.summary": {
        "en": "{alerts} {alerts:plural:alert|alerts} over {days} days · {analyst_facing} analyst-facing · "
        "{rules} {rules:plural:rule|rules} · {clusters} clusters",
        "es": "{alerts} {alerts:plural:alerta|alertas} en {days} días · {analyst_facing} para analistas · "
        "{rules} {rules:plural:regla|reglas} · {clusters} clústeres",
    },
    "report.noise.top_rules": {
        "en": "Top rules by analyst-facing volume",
        "es": "Reglas principales por volumen para analistas",
    },
    "report.noise.suggestions": {
        "en": "Tuning suggestions (passed every safety gate and the backtest)",
        "es": "Sugerencias de ajuste (superaron todos los controles de seguridad y el backtest)",
    },
    "report.noise.no_suggestions": {"en": "No safe tuning candidates.", "es": "No hay candidatos de ajuste seguros."},
    "report.noise.review_required": {"en": "Review required", "es": "Requiere revisión"},
    "report.noise.review_hint": {
        "en": "Other rules correlate on this one ({rules}): check them before deploying.",
        "es": "Otras reglas correlacionan con esta ({rules}): revíselas antes de desplegar.",
    },
    "report.noise.ready": {"en": "Ready for review", "es": "Lista para revisión"},
    "report.noise.investigate": {"en": "Noisy but not safe to tune", "es": "Ruidosas, pero no seguras de ajustar"},
    "report.noise.investigate_hint": {
        "en": "A safety gate tripped: these may be attacks or need a fix elsewhere. Never mute them blindly.",
        "es": "Saltó un control de seguridad: pueden ser ataques o requerir una corrección en otro lugar. "
        "Nunca los silencie a ciegas.",
    },
    "report.noise.none_investigate": {"en": "Nothing in this list.", "es": "Nada en esta lista."},
    "report.noise.index_volume": {
        "en": "Index volume only (no analyst sees these alerts)",
        "es": "Solo volumen del índice (ningún analista ve estas alertas)",
    },
    "report.noise.index_volume_hint": {
        "en": "These alerts are already below the analyst-facing level: demoting them changes nothing for analysts. "
        "Keep them searchable unless index volume is a real problem.",
        "es": "Estas alertas ya están por debajo del nivel visible para analistas: degradarlas no cambia nada para "
        "ellos. Consérvelas para poder buscarlas, salvo que el volumen del índice sea un problema real.",
    },
    "report.noise.index_volume_badge": {"en": "Index volume", "es": "Volumen del índice"},
    "report.noise.time_saved_none": {
        "en": "none: no suggestion removes analyst-facing alerts",
        "es": "ninguno: ninguna sugerencia quita alertas visibles para analistas",
    },
    "report.noise.time_saved": {
        "en": "Time saved (upper-bound estimate)",
        "es": "Tiempo ahorrado (estimación máxima)",
    },
    "report.noise.time_saved_value": {"en": "{low}–{high} min/day", "es": "{low}–{high} min/día"},
    "report.noise.time_saved_hint": {
        "en": "Upper-bound estimate: analyst-facing alert clusters demoted per day × minutes per alert. "
        "It is not a measured saving.",
        "es": "Estimación máxima: clústeres de alertas para analistas degradados por día × minutos por alerta. "
        "No es un ahorro medido.",
    },
    "report.noise.suppressions_file": {
        "en": "Suppressions file (review before deploying)",
        "es": "Archivo de supresiones (revisar antes de desplegar)",
    },
    "report.noise.no_rules": {"en": "No rule statistics.", "es": "Sin estadísticas de reglas."},
    "report.noise.totals": {"en": "Totals", "es": "Totales"},
    "report.verdict.tune": {"en": "Tune", "es": "Ajustar"},
    "report.verdict.tune_scoped": {"en": "Tune (scoped)", "es": "Ajustar (con alcance)"},
    "report.verdict.investigate": {"en": "Investigate", "es": "Investigar"},
    "report.verdict.fix_at_source": {"en": "Fix at source", "es": "Corregir en origen"},
    "report.verdict.aggregate": {"en": "Aggregate", "es": "Agregar"},
    "report.verdict.do_not_tune": {"en": "Do not tune", "es": "No ajustar"},
    "report.verdict.watch": {"en": "Watch", "es": "Vigilar"},
    "report.verdict.learning": {"en": "Learning", "es": "Aprendiendo"},
    # silence
    "report.silence.counts": {"en": "Source status", "es": "Estado de las fuentes"},
    "report.silence.monitorability": {
        "en": "Critical sources monitorable within SLA",
        "es": "Fuentes críticas monitoreables dentro del SLA",
    },
    "report.silence.monitorability_value": {"en": "{pct} ({part} of {total})", "es": "{pct} ({part} de {total})"},
    "report.silence.no_critical": {
        "en": "No critical sources are configured.",
        "es": "No hay fuentes críticas configuradas.",
    },
    "report.silence.alpha": {
        "en": "Alarm threshold α = {alpha} over {keys} keys evaluated",
        "es": "Umbral de alarma α = {alpha} sobre {keys} claves evaluadas",
    },
    "report.silence.sources": {
        "en": "Sources needing attention, and every critical source",
        "es": "Fuentes que requieren atención y todas las fuentes críticas",
    },
    "report.silence.no_sources": {
        "en": "No source needs attention.",
        "es": "Ninguna fuente requiere atención.",
    },
    "report.silence.tenant_key": {"en": "(whole tenant)", "es": "(todo el cliente)"},
    "report.sstatus.ok": {"en": "OK", "es": "OK"},
    "report.sstatus.silent": {"en": "Silent", "es": "Silenciosa"},
    "report.sstatus.drop": {"en": "Drop", "es": "Caída"},
    "report.sstatus.decay": {"en": "Decay", "es": "Declive"},
    "report.sstatus.learning": {"en": "Learning", "es": "Aprendiendo"},
    "report.sstatus.unmonitorable": {
        "en": "Unmonitorable",
        "es": "No monitoreable",
    },
    "report.sstatus.explained": {"en": "Explained", "es": "Explicada"},
    "report.sstatus.rule_dark": {"en": "Rule dark", "es": "Regla apagada"},
    "report.sstatus.field_lost": {"en": "Field lost", "es": "Campo perdido"},
    "report.sstatus.tampering": {"en": "Possible tampering", "es": "Posible manipulación"},
    "report.sstatus.not_evaluated": {"en": "Not evaluated", "es": "No evaluada"},
    "report.silence.sla": {"en": "SLA {hours} h", "es": "SLA {hours} h"},
    "report.check.input_completeness": {"en": "Input completeness", "es": "Integridad de la entrada"},
    "report.check.clock_skew": {"en": "Clock skew", "es": "Desfase de reloj"},
    "report.check.freshness": {"en": "Data freshness", "es": "Actualidad de los datos"},
    "report.check.manager_daemons": {
        "en": "Manager daemons (dropped events)",
        "es": "Demonios del manager (eventos descartados)",
    },
    "report.check.ingest_lag": {"en": "Ingest lag", "es": "Retraso de ingesta"},
    "report.tuning.risky_high": {"en": "High-risk suppressions", "es": "Supresiones de alto riesgo"},
    "report.tuning.parse_errors": {
        "en": "Rule files that failed to parse",
        "es": "Archivos de reglas con errores de análisis",
    },
    "report.tuning.duplicate_ids": {"en": "Duplicate rule ids", "es": "IDs de regla duplicados"},
    "report.tuning.files": {"en": "Rule files", "es": "Archivos de reglas"},
    "report.tuning.local_files": {"en": "Local rule files", "es": "Archivos de reglas locales"},
    "report.level.tenant": {"en": "Tenant", "es": "Cliente"},
    "report.level.log_source": {"en": "Log source", "es": "Fuente de logs"},
    "report.level.agent": {"en": "Agent", "es": "Agente"},
    "report.level.agent_log_source": {"en": "Agent · log source", "es": "Agente · fuente de logs"},
    "report.level.rule": {"en": "Rule", "es": "Regla"},
    "report.duty.always_on": {"en": "Always on", "es": "Siempre activa"},
    "report.duty.business_hours": {"en": "Business hours", "es": "Horario laboral"},
    "report.duty.intermittent": {"en": "Intermittent", "es": "Intermitente"},
    "report.duty.unknown": {"en": "Unknown", "es": "Desconocido"},
    "report.tier.critical": {"en": "Critical", "es": "Crítica"},
    "report.tier.standard": {"en": "Standard", "es": "Estándar"},
    "report.tier.low": {"en": "Low", "es": "Baja"},
    # coverage
    "report.coverage.matrix": {"en": "Agents × log sources", "es": "Agentes × fuentes de logs"},
    "report.coverage.platforms": {"en": "Platforms", "es": "Plataformas"},
    "report.coverage.expected": {"en": "Expected sources", "es": "Fuentes esperadas"},
    "report.coverage.present": {"en": "Present", "es": "Presente"},
    "report.coverage.missing": {"en": "Missing", "es": "Ausente"},
    "report.coverage.silent": {"en": "Silent", "es": "Silenciosa"},
    "report.coverage.na": {"en": "Not applicable", "es": "No aplica"},
    "report.coverage.legend": {"en": "Legend", "es": "Leyenda"},
    "report.coverage.no_matrix": {"en": "No coverage matrix.", "es": "Sin matriz de cobertura."},
    "report.coverage.more_cols": {"en": "{n} more log sources not shown", "es": "{n} fuentes de logs más sin mostrar"},
    # pipeline / tuning
    "report.pipeline.agents": {"en": "Agents by status", "es": "Agentes por estado"},
    "report.pipeline.checks": {"en": "Checks", "es": "Controles"},
    "report.agent.active": {"en": "Active", "es": "Activos"},
    "report.agent.disconnected": {"en": "Disconnected", "es": "Desconectados"},
    "report.agent.never_connected": {"en": "Never connected", "es": "Nunca conectados"},
    "report.agent.pending": {"en": "Pending", "es": "Pendientes"},
    "report.agent.unknown": {"en": "Unknown", "es": "Desconocido"},
    "report.agent.total": {"en": "Total", "es": "Total"},
    "report.tuning.rules_parsed": {"en": "Rules parsed", "es": "Reglas analizadas"},
    "report.tuning.local_rules": {"en": "Local rules", "es": "Reglas locales"},
    "report.tuning.risky": {"en": "Risky suppressions", "es": "Supresiones riesgosas"},
    "report.tuning.expired": {"en": "Expired suppressions", "es": "Supresiones vencidas"},
    "report.tuning.errors": {"en": "Parse errors", "es": "Errores de análisis"},
    # findings
    "report.findings.none": {"en": "No findings.", "es": "Sin hallazgos."},
    "report.findings.none_incomplete": {
        "en": "No findings, but the analysis was incomplete: this is not an all-clear.",
        "es": "Sin hallazgos, pero el análisis estuvo incompleto: esto no significa que todo esté bien.",
    },
    "report.findings.summary": {
        "en": "{n} {n:plural:finding|findings}",
        "es": "{n} {n:plural:hallazgo|hallazgos}",
    },
    "report.finding.why": {"en": "Why", "es": "Por qué"},
    "report.finding.evidence": {"en": "Evidence", "es": "Evidencia"},
    "report.finding.recommendation": {"en": "Recommended action", "es": "Acción recomendada"},
    "report.finding.confidence": {"en": "Confidence", "es": "Confianza"},
    "report.finding.fingerprint": {"en": "Fingerprint", "es": "Huella"},
    "report.finding.subject": {"en": "Subject", "es": "Elemento"},
    "report.finding.kind": {"en": "Kind", "es": "Tipo"},
    "report.finding.related": {"en": "Related", "es": "Relacionados"},
    "report.finding.explained": {
        "en": "Also explains (same incident, not reported separately)",
        "es": "También explica (mismo incidente, no se informa por separado)",
    },
    "report.gate.passed": {"en": "✓ passed", "es": "✓ superado"},
    "report.gate.tripped": {"en": "✗ tripped", "es": "✗ disparado"},
    "report.no_events": {"en": "no events", "es": "sin eventos"},
    "report.seconds": {"en": "{value} s", "es": "{value} s"},
    "report.fmt.alerts": {"en": "{count} {n:plural:alert|alerts}", "es": "{count} {n:plural:alerta|alertas}"},
    "report.fmt.alerts_of": {
        "en": "{who} ({count} {n:plural:alert|alerts})",
        "es": "{who} ({count} {n:plural:alerta|alertas})",
    },
    "report.fmt.beaconing": {"en": " · beacon-like", "es": " · patrón de beacon"},
    "report.fmt.active_hours": {
        "en": "{who}: active {active} of {span} hours, regularity {regularity}{beacon}",
        "es": "{who}: activa {active} de {span} horas, regularidad {regularity}{beacon}",
    },
    "report.fmt.path": {
        "en": "{path} ({alerts}, changed on {days} days)",
        "es": "{path} ({alerts}, con cambios en {days} días)",
    },
    "report.fmt.lag": {
        "en": "{who}: median {p50}, p95 {p95} ({samples} samples)",
        "es": "{who}: mediana {p50}, p95 {p95} ({samples} muestras)",
    },
    "report.fmt.event_type": {
        "en": "{check}: never sent by {missing} of {peers} comparable peers, stopped on {stopped}",
        "es": "{check}: {missing} de {peers} pares comparables nunca lo enviaron; se detuvo en {stopped}",
    },
    "report.fmt.precursor": {
        "en": "{what} on {agent} at {ts} (rule {rule}, ATT&CK {technique})",
        "es": "{what} en {agent} a las {ts} (regla {rule}, ATT&CK {technique})",
    },
    "report.fmt.event_type_na": {
        "en": "{check}: not assessed (no comparable peers)",
        "es": "{check}: no evaluado (sin pares comparables)",
    },
    "report.finding.more": {
        "en": "{n} more {n:plural:finding is|findings are} not shown here (use --verbose, or the HTML/JSON report).",
        "es": "{n} {n:plural:hallazgo más no se muestra|hallazgos más no se muestran} aquí (use --verbose "
        "o el informe HTML/JSON).",
    },
    # sparkline
    "report.spark.label": {
        "en": "Daily counts over {n} days: min {min}, max {max}, last {last}",
        "es": "Conteos diarios en {n} días: mín. {min}, máx. {max}, último {last}",
    },
    "report.spark.summary": {
        "en": "min {min} · max {max} · last {last}",
        "es": "mín. {min} · máx. {max} · último {last}",
    },
    # footer
    "report.footer.readonly": {
        "en": "hushwatch never writes to your SIEM. Suggestions are files for humans to review.",
        "es": "hushwatch nunca escribe en su SIEM. Las sugerencias son archivos para revisión humana.",
    },
    "report.footer.tool": {"en": "hushwatch {version}", "es": "hushwatch {version}"},
    "report.footer.schema": {"en": "Report schema {schema}", "es": "Esquema del informe {schema}"},
    "report.footer.generated": {"en": "Generated {at}", "es": "Generado el {at}"},
    "report.footer.redacted": {
        "en": "Hosts, users and IPs are pseudonymized with a per-tenant key.",
        "es": "Equipos, usuarios e IP están seudonimizados con una clave por cliente.",
    },
    "report.footer.not_redacted": {
        "en": "This report contains real host names, user names and IPs. Share it with care (see --redact).",
        "es": "Este informe contiene nombres de equipo, usuarios e IP reales. Compártalo con cuidado (vea --redact).",
    },
    # fleet
    "report.fleet.title": {"en": "Fleet summary", "es": "Resumen multicliente"},
    "report.fleet.tenants": {"en": "Tenants: {n}", "es": "Clientes: {n}"},
    "report.fleet.count": {"en": "Tenants", "es": "Clientes"},
    "report.fleet.empty": {"en": "No tenant reports.", "es": "No hay informes de clientes."},
    "report.fleet.complete": {"en": "Complete", "es": "Completos"},
    "report.fleet.incomplete": {"en": "Incomplete", "es": "Incompletos"},
    "report.data.complete": {"en": "Complete", "es": "Completo"},
    "report.data.incomplete": {"en": "Incomplete", "es": "Incompleto"},
    "report.fleet.order": {
        "en": "Tenants are ordered by critical, then high findings, then incomplete data.",
        "es": "Los clientes se ordenan por hallazgos críticos, luego altos y luego datos incompletos.",
    },
}

register(_LABELS)

_VERDICTS = ("tune", "investigate", "fix_at_source", "aggregate", "do_not_tune", "watch", "learning")
_SOURCE_STATUSES = (
    "tampering",
    "silent",
    "drop",
    "decay",
    "rule_dark",
    "field_lost",
    "unmonitorable",
    "learning",
    "explained",
    "not_evaluated",
    "ok",
)
_INPUT_KINDS = ("alerts", "indexer-alerts", "archives", "indexer-archives", "mixed", "ruleset", "unknown")
_ALERTS_ONLY_KINDS = ("alerts", "indexer-alerts")
_SERIES_KEYS = frozenset({"daily", "series", "daily_counts", "counts_per_day", "per_day_counts", "hourly"})
_NOISE_OTHER_KINDS = ("noise.investigate", "noise.fix_at_source", "noise.aggregate", "noise.do_not_tune")

# ---- small value helpers --------------------------------------------------------------------------------------


def normalize_lang(lang: str | None) -> str:
    """``"es-AR"`` -> ``"es"``; unknown languages fall back to English."""
    code = (lang or DEFAULT_LANG).strip().lower().replace("_", "-").split("-", 1)[0]
    return code if code in LANGS else DEFAULT_LANG


def _as_map(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _as_list(value: Any) -> list[Any]:
    return list(value) if isinstance(value, (list, tuple)) else []


def _as_float(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        number = float(value)
    except OverflowError:  # an int beyond the float range
        return None
    return number if math.isfinite(number) else None


def _as_int(value: Any) -> int | None:
    number = _as_float(value)
    return int(number) if number is not None else None


def _series(value: Any, limit: int = 120) -> list[float]:
    """Numbers of a sparkline series (non-numbers and non-finite values become 0; negatives are clamped)."""
    out: list[float] = []
    for item in _as_list(value)[-limit:]:
        number = _as_float(item)
        out.append(max(0.0, number) if number is not None else 0.0)
    return out


def _is_series(key: str, value: Any) -> bool:
    if not isinstance(value, (list, tuple)) or len(value) < 3:
        return False
    if not all(isinstance(v, (int, float)) and not isinstance(v, bool) for v in value):
        return False
    return key in _SERIES_KEYS or len(value) >= 7


def _norm_status(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    lowered = value.strip().lower()
    aliases = {
        "error": "fail",
        "failed": "fail",
        "failure": "fail",
        "critical": "fail",
        "warning": "warn",
        "degraded": "warn",
        "skipped": "not_assessed",
        "unknown": "not_assessed",
        "n/a": "not_assessed",
        "passed": "ok",
        "pass": "ok",
        "good": "ok",
    }
    lowered = aliases.get(lowered, lowered)
    return lowered if lowered in _STATUS_RANK else None


def _section(report: Report, name: str) -> Mapping[str, Any]:
    """``report.sections[name]`` as a mapping (a missing or mistyped section reads as empty)."""
    return _as_map(_as_map(report.sections).get(name))


def _count(value: Any) -> int:
    """A DataBasis counter as a non-negative int (anything else counts as 0)."""
    number = _as_int(value)
    return number if number is not None and number > 0 else 0


def basis_complete(basis: DataBasis) -> bool:
    """``DataBasis.complete`` that tolerates mistyped fields (a report must render, never raise)."""
    return not _as_list(basis.partial_failures) and not bool(basis.truncated) and _count(basis.events) > 0


_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def order_findings(findings: Iterable[Finding]) -> list[Finding]:
    """Same order as :func:`hushwatch.models.sort_findings` (most severe, highest score, kind, subject), but
    tolerant of mistyped fields."""

    def key(finding: Finding) -> tuple[int, float, str, str]:
        score = _as_float(finding.score)
        return (-_RANK[_severity_value(finding.severity)], -(score or 0.0), str(finding.kind), str(finding.subject))

    return sorted(findings, key=key)


def reasons_of(finding: Finding) -> list[Any]:
    """``Finding.reasons`` as a list, even when a single message or string was stored."""
    reasons = finding.reasons
    if isinstance(reasons, (str, Message)):
        return [reasons]
    return _as_list(reasons)


def severity_name(value: Any) -> str:
    """A finding severity as one of :data:`SEVERITY_ORDER` (anything unrecognized reads as ``info``)."""
    return _severity_value(value)


def _severity_value(value: Any) -> str:
    if isinstance(value, Severity):
        return value.value
    text = str(value.value if isinstance(value, Enum) else value).strip().lower()
    return text if text in SEVERITY_ORDER else "info"


def _pick(maps: Sequence[Mapping[str, Any]], *keys: str) -> Any:
    for mapping in maps:
        for key in keys:
            value = mapping.get(key)
            if value is not None and value != "" and value != [] and value != {}:
                return value
    return None


_PLAIN_KEY = re.compile(r"^[a-z][a-z0-9_]*$")
_FIELD_PATH = re.compile(r"^[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+$")


def _humanize_key(key: str) -> str:
    """``hidden_per_day`` -> ``hidden per day``; ``backtest.share`` -> ``backtest › share``. Values that are not
    code-style names (host names, IPs, paths) keep their dots and underscores."""
    if _PLAIN_KEY.match(key):
        return key.replace("_", " ").strip() or key
    if _FIELD_PATH.match(key) and not _FQDN.fullmatch(key):
        return key.replace("_", " ").replace(".", " › ").strip()
    return key


_WORD_CHAR = re.compile(r"[\w.@:%+-]")


def _cap(text: str, limit: int) -> tuple[str, int]:
    """Cut ``text`` to at most ``limit`` characters at a separator (never inside an identifier if avoidable).

    A cut inside a word would leave a partial identifier (``dc01.corp.exa``) that redaction no longer
    recognizes, so without a separator in the second half the trailing partial word is dropped too (unless the
    whole text is one giant word, which no identifier detector matches anyway).
    """
    if len(text) <= limit:
        return text, 0
    cut = limit
    if text[limit] not in _SEPARATORS and text[limit - 1] not in _SEPARATORS:
        floor = limit // 2
        index = limit - 1
        while index > floor and text[index] not in _SEPARATORS:
            index -= 1
        if index > floor:
            cut = index + 1
        else:
            start = limit
            while start > floor and _WORD_CHAR.match(text, start - 1):
                start -= 1
            if start > floor:
                cut = start
    kept = text[:cut].rstrip()
    return kept, len(text) - len(kept)


def _cut(text: str, limit: int | None) -> str:
    """Display truncation of already-redacted text."""
    if limit is None or len(text) <= limit:
        return text
    return text[: max(1, limit - 1)].rstrip() + "…"


def finite_series(values: Sequence[Any]) -> list[float]:
    """Plot-safe copy of a series: non-numbers, NaN and negatives -> 0, huge values and +inf -> the float max."""
    out: list[float] = []
    for value in values:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            out.append(0.0)
            continue
        try:
            number = float(value)
        except OverflowError:
            number = math.inf if value > 0 else 0.0
        out.append(0.0 if math.isnan(number) or number <= 0 else min(number, sys.float_info.max))
    return out


def sparkline_text(values: Sequence[float], *, zero: str = "·", blocks: str = _SPARK_BLOCKS) -> str:
    """Unicode block sparkline; zero days are shown as ``zero`` so silence stays visible."""
    values = finite_series(values)
    peak = max(values, default=0.0)
    if peak <= 0:
        return zero * len(values)
    top = len(blocks) - 1
    return "".join(zero if v <= 0 else blocks[min(top, round(v / peak * top))] for v in values)


# Subject keys that name identifying values (``agent:dc01|ls:Security`` -> learn "dc01" as a host).
_SUBJECT_SPLIT = re.compile(r"[|;]")
_HOST_KEYS = frozenset(
    {"agent", "host", "hostname", "computer", "device", "workstation", "machine", "source", "agent_name", "system_name"}
)
_FILE_KEYS = frozenset(
    {"image", "parentimage", "process", "parent_process", "executable", "file", "path", "filename", "targetfilename"}
)
_CMD_KEYS = frozenset({"commandline", "command_line", "cmd", "cmdline"})


def _subject_kind(key: str) -> str | None:
    full = key.strip().lower()
    last = full.rsplit(".", 1)[-1]
    if last in _HOST_KEYS or full in ("agent.name", "host.name", "predecoder.hostname", "observer.name"):
        return "host"
    if last.endswith("ip") or last in ("address", "ip_address", "src", "dst"):
        return "ip"
    if "user" in last or "account" in last:
        return "user"
    if "url" in last or last == "uri":
        return "url"
    if last in _FILE_KEYS:
        return "file"
    if last in _CMD_KEYS:
        return "cmd"
    if last == "domain":
        return "domain"
    return None


def _subject_entities(subject: str) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    for part in _SUBJECT_SPLIT.split(subject):
        positions = [i for i in (part.find(":"), part.find("=")) if i > 0]
        if not positions:
            continue
        split = min(positions)
        kind = _subject_kind(part[:split])
        value = part[split + 1 :].strip()
        if kind and value:
            found.append((kind, value))
    return found


# ---- render context -------------------------------------------------------------------------------------------


class RenderContext:
    """Language + redaction for one rendering. Turns any report value into safe, display-ready plain text.

    The text it returns is sanitized and (with a redactor) pseudonymized, but NOT escaped: every renderer
    escapes for its own sink.
    """

    __slots__ = ("_cache", "_labels", "lang", "redactor", "report")

    def __init__(self, report: Report | None, lang: str = DEFAULT_LANG, redactor: Redactor | None = None) -> None:
        self.report = report
        self.lang = normalize_lang(lang)
        self.redactor = redactor
        self._cache: dict[str, str] = {}
        self._labels: dict[str, str] = {}

    @property
    def redacted(self) -> bool:
        """True when identifiers are pseudonymized."""
        return self.redactor is not None

    @property
    def entity_formatter(self) -> Callable[[Entity], str]:
        """Entity -> display text (a pseudonym with a redactor), usable as ``i18n.render(..., entity=...)``."""
        return self._entity_text

    # -- our own labels --------------------------------------------------------------------------------------
    def t(self, key: str, **params: Any) -> str:
        """A ``report.*`` label (or any registered key). Params must be numbers or already-processed text."""
        if not params:
            cached = self._labels.get(key)
            if cached is None:
                cached = self._labels[key] = sanitize(render_message(M(key), self.lang))
            return cached
        return sanitize(render_message(M(key, **params), self.lang))

    def label(self, prefix: str, value: Any) -> str:
        """Localized label for an enumerated value (``report.verdict.tune``), else the value, redacted first and
        then humanized (``never_connected`` -> ``never connected``)."""
        text = str(value) if value is not None else ""
        key = f"{prefix}.{text}"
        if text and has(key):
            return self.t(key)
        return _humanize_key(self.text(text)) if text else self.t("report.unknown")

    # -- data ------------------------------------------------------------------------------------------------
    def text(self, value: object, limit: int | None = None) -> str:
        """Data-derived free text: sanitized, capped at :data:`MAX_TEXT`, redacted; ``limit`` truncates further."""
        if isinstance(value, str):
            raw = value
        else:
            try:
                raw = str(value)
            except Exception:  # an int over 4300 digits, an object whose __str__ raises
                return self.t("report.unknown")
        processed = self._cache.get(raw)
        if processed is None:
            processed = self._process(raw)
            if len(self._cache) < _CACHE_LIMIT:
                self._cache[raw] = processed
        return _cut(processed, limit)

    @staticmethod
    def cut(text: str, limit: int | None) -> str:
        """Display truncation (with ``…``) of text that was already processed by this context."""
        return _cut(text, limit)

    def _clean(self, raw: str) -> str:
        """Sanitized, credential-free and capped (NOT redacted) text."""
        clean = _USERINFO.sub(r"\1***@", sanitize(raw))
        kept, dropped = _cap(clean, MAX_TEXT)
        if dropped:
            kept = f"{kept} {self.t('report.truncated', n=self.num(dropped))}"
        return kept

    def _process(self, raw: str) -> str:
        clean = self._clean(raw)
        return self._redact(clean) if self.redactor is not None else clean

    def _redact(self, text: str) -> str:
        """Redact one whole string (never piecewise: a split could cut an identifier in two)."""
        assert self.redactor is not None
        redactor = self.redactor
        out = redactor.text(text)
        return _FQDN.sub(lambda m: redactor.token(m.group(0).lower(), "host"), out)

    def _redact_around(self, text: str, tokens: Sequence[str]) -> str:
        """Redact ``text`` except the pseudonyms in ``tokens`` (already final: a second pass could garble them)."""
        if not tokens:
            return self._redact(text)
        pattern = re.compile("|".join(re.escape(t) for t in sorted(set(tokens), key=len, reverse=True)))
        parts: list[str] = []
        start = 0
        for match in pattern.finditer(text):
            if match.start() > start:
                parts.append(self._redact(text[start : match.start()]))
            parts.append(match.group(0))
            start = match.end()
        if start < len(text):
            parts.append(self._redact(text[start:]))
        return "".join(parts)

    def ent(self, entity: Entity, limit: int | None = None) -> str:
        """An entity: pseudonym with a redactor (same token as :func:`hushwatch.i18n.entity_formatter`), else its
        sanitized raw value."""
        if self.redactor is not None:
            return sanitize(self.redactor.token(str(entity.value), str(entity.kind)))
        return self.text(str(entity.value), limit)

    def subject(self, finding: Finding, limit: int | None = None) -> str:
        """``Finding.subject``: a ``val-…`` token with a redactor (the raw subject embeds identifiers)."""
        if self.redactor is not None:
            return sanitize(self.redactor.token(str(finding.subject), "val"))
        return self.text(str(finding.subject), limit)

    def msg(self, message: Message | str | None, limit: int | None = None) -> str:
        """Render an analyzer :class:`Message` (or plain string) in the context language, redacted.

        Registered templates are code (reviewed catalog text with placeholders): only their params are redacted.
        A message whose text comes from ``Message.default`` or from an unregistered key may carry raw values
        in the template itself, so it is rendered with cleaned (not yet redacted) params and the whole text is
        redacted once, around the entity pseudonyms.
        """
        if message is None:
            return ""
        if isinstance(message, str):
            return self.text(message, limit)
        if not isinstance(message, Message):
            return self.value(message, limit)
        whole = self.redactor is not None and not _catalog_only(message, 0)
        tokens: list[str] = []

        def entity_text(entity: Entity) -> str:
            text = self.ent(entity)
            tokens.append(text)
            return text

        try:
            prepared = self._prepare_message(message, 0, whole)
            rendered = sanitize(render_message(prepared, self.lang, entity_text))
            if whole:
                rendered = self._redact_around(rendered, tokens)
        except Exception:  # a hostile/buggy message must degrade, never break the report
            rendered = self.text(message.key)
        return _cut(rendered, limit if limit is not None else MAX_TEXT * 2)

    def _entity_text(self, entity: Entity) -> str:
        return self.ent(entity)

    def _prepare_message(self, message: Message, depth: int, whole: bool = False) -> Message:
        params = {str(k): self._prepare_param(v, depth + 1, whole) for k, v in _as_map(message.params).items()}
        return Message(message.key, params, message.default)

    def _prepare_param(self, value: Any, depth: int, whole: bool = False) -> Any:
        if depth > _MAX_DEPTH:
            return "…"
        if isinstance(value, Entity):
            return value
        if isinstance(value, Message):
            return self._prepare_message(value, depth, whole)
        if isinstance(value, bool):
            return value
        if isinstance(value, (int, float)):
            return value if math.isfinite(value) else self.num(value)
        if isinstance(value, str):
            return self._clean(value) if whole else self.text(value)  # whole: redacted with the full text
        if isinstance(value, (list, tuple)):
            items = [self._prepare_param(v, depth + 1, whole) for v in list(value)[:_MAX_ITEMS]]
            if len(value) > _MAX_ITEMS:
                items.append(self.t("report.more_items", n=self.num(len(value) - _MAX_ITEMS)))
            if not items:
                return self.t("report.dash")
            # i18n joins a list of Entity/str with the message's entity formatter (pseudonyms stay protected)
            return [v if isinstance(v, (Entity, str)) else self.value(v) for v in items]
        return self.value(value)

    def value(self, value: Any, limit: int | None = None, _depth: int = 0) -> str:
        """Any section/evidence value as display text (entities pseudonymized, numbers localized)."""
        if _depth > _MAX_DEPTH:
            return "…"
        if value is None:
            return self.t("report.dash")
        if isinstance(value, Entity):
            return self.ent(value, limit)
        if isinstance(value, Message):
            return self.msg(value, limit)
        if isinstance(value, bool):
            return self.t("report.yes" if value else "report.no")
        if isinstance(value, (int, float)):
            return self.num(value)
        if isinstance(value, datetime):
            return self.dt(value)
        if isinstance(value, date):
            return value.isoformat()
        if isinstance(value, timedelta):
            return self.dur(value)
        if isinstance(value, Enum):
            return self.value(value.value, limit, _depth + 1)
        if isinstance(value, str):
            return self.text(value, limit)
        if isinstance(value, (Mapping, list, tuple, set, frozenset)) and not value:
            return self.t("report.dash")
        if isinstance(value, Mapping):
            items = list(value.items())
            parts = [f"{self.evidence_label(str(k))}: {self.value(v, None, _depth + 1)}" for k, v in items[:_MAX_ITEMS]]
            if len(items) > _MAX_ITEMS:
                parts.append(self.t("report.more_items", n=self.num(len(items) - _MAX_ITEMS)))
            return _cut("; ".join(parts), limit if limit is not None else MAX_TEXT)
        if isinstance(value, (list, tuple, set, frozenset)):
            seq = list(value) if isinstance(value, (list, tuple)) else sorted(value, key=str)
            parts = [self.value(v, None, _depth + 1) for v in seq[:_MAX_ITEMS]]
            if len(seq) > _MAX_ITEMS:
                parts.append(self.t("report.more_items", n=self.num(len(seq) - _MAX_ITEMS)))
            return _cut(", ".join(parts), limit if limit is not None else MAX_TEXT)
        try:
            return self.text(str(value), limit)
        except Exception:  # an object whose __str__ raises
            return self.t("report.unknown")

    # -- numbers, dates ---------------------------------------------------------------------------------------
    def _localize(self, text: str) -> str:
        if self.lang == "es":
            return text.replace(",", "\x00").replace(".", ",").replace("\x00", ".")
        return text

    def num(self, value: Any, decimals: int | None = None) -> str:
        """Localized number (``1,234.5`` / ``1.234,5``); ``—`` for anything that is not a number."""
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return self.t("report.dash") if value is None else self.text(str(value))
        if isinstance(value, int):
            if value.bit_length() > 256:  # beyond any real count (and str() refuses > 4300 digits)
                return "∞" if value > 0 else "-∞"
            return self._localize(f"{value:,d}")
        if math.isnan(value):
            return self.t("report.dash")
        if math.isinf(value):
            return "∞" if value > 0 else "-∞"
        if decimals is None:
            magnitude = abs(value)
            if (value == int(value) and magnitude < 1e15) or magnitude >= 100:
                decimals = 0
            elif magnitude >= 1:
                decimals = 1
            elif magnitude >= 0.01:
                decimals = 2
            else:
                return self._localize(f"{value:.1e}")
        return self._localize(f"{value:,.{decimals}f}")

    def pct(self, value: Any) -> str:
        """A share in [0, 1] as a percentage (values in (1, 100] are taken as already-percent)."""
        number = _as_float(value)
        if number is None:
            return self.t("report.dash")
        percent = number * 100 if number <= 1 else number
        if not math.isfinite(percent):
            return "∞%" if percent > 0 else "-∞%"
        if 0 < percent < 0.1:
            return self._localize("<0.1%")  # never "0%" for a share that is not zero
        if 0 < percent < 1:
            return self._localize(f"{percent:.1f}%")
        if 99 < percent < 100:
            return self._localize(">99%")
        return f"{self.num(round(percent))}%"

    def pvalue(self, value: Any) -> str:
        """A p-value / probability (``<0.0001`` below the display floor)."""
        number = _as_float(value)
        if number is None:
            return self.t("report.dash")
        if number < 0.0001:
            return self._localize("<0.0001")
        return self._localize(f"{number:.4f}" if number < 0.01 else f"{number:.3f}")

    def dt(self, value: Any) -> str:
        """``2026-09-25 10:00 UTC`` for datetimes and ISO strings; anything else as sanitized text."""
        parsed: datetime | None
        if isinstance(value, datetime):
            parsed = value if value.tzinfo is not None else value.replace(tzinfo=UTC)
        elif isinstance(value, str):
            parsed = parse_ts(value) if len(value) <= 64 else None
            if parsed is None:
                return self.text(value, 64)
        else:
            return self.t("report.dash") if value is None else self.value(value)
        try:
            return parsed.astimezone(UTC).strftime("%Y-%m-%d %H:%M UTC")
        except (OverflowError, ValueError, OSError):
            return self.t("report.unknown")

    def dur(self, value: timedelta | float | int | None) -> str:
        """A duration (timedelta or seconds) as ``1d 2h``."""
        if value is None:
            return self.t("report.dash")
        try:
            delta = value if isinstance(value, timedelta) else timedelta(seconds=float(value))
            return humanize(delta)
        except (OverflowError, ValueError, TypeError):
            return self.t("report.unknown")

    def evidence_label(self, key: str, parent: str | None = None) -> str:
        """Label for an evidence/section key: registered ``report.ev.<parent>.<key>`` / ``report.ev.<key>`` text,
        or the label of an enumerated value used as a key (``{"investigate": 5}``, ``{"active": 36}``), else the
        key redacted first and then humanized (a key can be an identifier: ``{"dc01.corp.example": 5}``)."""
        for registered in _label_keys(key, parent):
            if has(registered):
                return self.t(registered)
        processed = self.text(key)
        label = _humanize_key(processed)
        if processed == key and _PLAIN_KEY.match(key):  # a code-style key such as "days_present"
            label = label[:1].upper() + label[1:]
        return _cut(label, 80)

    def spark_summary(self, values: Sequence[float]) -> str:
        """``min · max · last`` of a daily series (the textual twin of a sparkline)."""
        if not values:
            return self.t("report.dash")
        return self.t(
            "report.spark.summary", min=self.num(min(values)), max=self.num(max(values)), last=self.num(values[-1])
        )

    def spark_label(self, values: Sequence[float]) -> str:
        """Accessible description of a sparkline (used as SVG ``aria-label`` / ``<title>``)."""
        if not values:
            return self.t("report.dash")
        return self.t(
            "report.spark.label",
            n=self.num(len(values)),
            min=self.num(min(values)),
            max=self.num(max(values)),
            last=self.num(values[-1]),
        )


def _catalog_only(message: Message, depth: int) -> bool:
    """True when ``message`` and every nested message render from registered catalog templates."""
    if depth > _MAX_DEPTH or not has(str(message.key)):
        return False
    for value in _as_map(message.params).values():
        items = value if isinstance(value, (list, tuple)) else (value,)
        for item in list(items)[:_MAX_ITEMS]:
            if isinstance(item, Message) and not _catalog_only(item, depth + 1):
                return False
    return True


def _learnable(kind: str, value: str) -> Iterable[tuple[str, str]]:
    if not isinstance(value, str) or not 3 <= len(value) <= _MAX_LEARN or is_empty(value):
        return ()  # "unknown", "N/A", "-"... must not turn every such word in the report into a pseudonym
    clean = sanitize(value)
    return ((kind, value), (kind, clean)) if clean != value else ((kind, value),)


# Keys whose plain-string values are identifiers even when a module forgot to wrap them in an Entity
# (defense in depth: ``{"agent": "ws-fin-07"}`` in a section or in evidence is still pseudonymized).
_ID_KEYS: dict[str, str] = {
    **dict.fromkeys(
        ("agent", "agent_name", "host", "hostname", "host_name", "computer", "workstation", "machine", "system_name"),
        "host",
    ),
    **dict.fromkeys(
        ("ip", "srcip", "dstip", "src_ip", "dst_ip", "source_ip", "destination_ip", "client_ip", "remote_ip"), "ip"
    ),
    **dict.fromkeys(
        ("user", "username", "user_name", "srcuser", "dstuser", "targetusername", "subjectusername", "account"),
        "user",
    ),
}
_ID_LIST_KEYS = {"agents": "host", "hosts": "host", "users": "user", "ips": "ip"}
_NAME_LIKE = re.compile(r"[^\W\d]|\d[.:]\d")  # a letter, or an IP-like digit group
_WALK_DEPTH = 24


def _id_kind(key: Any, value: Any) -> str | None:
    name = str(key).strip().lower().rsplit(".", 1)[-1]
    if isinstance(value, (list, tuple)):
        return _ID_KEYS.get(name) or _ID_LIST_KEYS.get(name)
    return _ID_KEYS.get(name)


def _walk_identifiers(value: Any, found: dict[tuple[str, str], None], depth: int = 0) -> None:
    """Every Entity nested in ``value`` (like :func:`hushwatch.models.iter_entities`, but depth-bounded) plus
    plain strings stored under identifying keys."""
    if depth > _WALK_DEPTH:
        return
    if isinstance(value, Entity):
        for pair in _learnable(str(value.kind), str(value.value)):
            found[pair] = None
    elif isinstance(value, Message):
        _walk_identifiers(value.params, found, depth + 1)
    elif isinstance(value, Mapping):
        for key, item in value.items():
            kind = _id_kind(key, item)
            if kind is not None:
                for raw in item if isinstance(item, (list, tuple)) else (item,):
                    if isinstance(raw, str) and _NAME_LIKE.search(raw):  # "000" is an id, not a name
                        for pair in _learnable(kind, raw):
                            found[pair] = None
            _walk_identifiers(item, found, depth + 1)
    elif isinstance(value, (list, tuple, set, frozenset)):
        for item in value:
            _walk_identifiers(item, found, depth + 1)


def collect_entities(report: Report) -> list[tuple[str, str]]:
    """Every (kind, value) identifying value in ``report``: entities anywhere, identifiers in subjects, and plain
    strings under identifying keys (``agent``, ``user``, ``srcip``...) in sections and evidence."""
    found: dict[tuple[str, str], None] = {}
    _walk_identifiers([report.sections, report.data_basis.warnings], found)
    for finding in report.findings:
        _walk_identifiers([finding.title, finding.reasons, finding.evidence, finding.recommendation], found)
        for kind, value in _subject_entities(str(finding.subject)):
            for pair in _learnable(kind, value):
                found[pair] = None
    return list(found)


def prepare_context(report: Report | None, lang: str = DEFAULT_LANG, redactor: Redactor | None = None) -> RenderContext:
    """Create the render context; with a redactor, first teach it every identifier found in the report."""
    if redactor is not None and report is not None:
        redactor.learn(collect_entities(report))
    return RenderContext(report, lang, redactor)


# ---- statuses -------------------------------------------------------------------------------------------------


def _severity_counts(findings: Iterable[Finding]) -> dict[str, dict[str, int]]:
    counts: dict[str, dict[str, int]] = {}
    for finding in findings:
        per_domain = counts.setdefault(str(finding.domain), dict.fromkeys(SEVERITY_ORDER, 0))
        per_domain[_severity_value(finding.severity)] += 1
    return counts


# Domains whose "ok" rests on the events read (tuning audits the ruleset; assessment is the basis itself).
_DATA_DOMAINS = ("noise", "silence", "pipeline", "coverage")


def domain_statuses(report: Report) -> dict[str, str]:
    """Status per domain (ok | warn | fail | not_assessed) that can never read greener than the evidence.

    Starts from ``report.assessment`` (or the section's ``status``), escalates when the section or the findings
    say worse (high/critical finding -> fail, medium -> warn), and never shows green when:

    * the section itself says ``not_assessed`` or the data basis lists the domain in ``not_evaluated``
      (-> ``not_assessed``, grey);
    * the data basis is incomplete (no events, truncated, partial failures): an "ok" computed on partial data
      becomes ``warn``, and the ``assessment`` domain fails.
    """
    counts = _severity_counts(report.findings)
    assessment = _as_map(report.assessment)
    basis = report.data_basis
    complete = basis_complete(basis)
    not_evaluated = {str(n).strip().lower() for n in _as_list(basis.not_evaluated)}
    out: dict[str, str] = {}
    for domain in DOMAINS:
        status = _norm_status(assessment.get(domain))
        section_status = _norm_status(_section(report, domain).get("status"))
        if status is None:
            status = section_status or "not_assessed"
        elif section_status and status != "not_assessed" and _STATUS_RANK[section_status] > _STATUS_RANK[status]:
            status = section_status
        if status == "ok" and (section_status == "not_assessed" or domain in not_evaluated):
            status = "not_assessed"
        per = counts.get(domain, {})
        serious = per.get("critical", 0) + per.get("high", 0)
        if domain == "assessment":  # engine parity: any medium+ assessment finding means an incomplete analysis
            serious += per.get("medium", 0)
        from_findings = "fail" if serious else "warn" if per.get("medium", 0) else None
        if from_findings and _STATUS_RANK[from_findings] > _STATUS_RANK[status]:
            status = from_findings
        if status == "ok" and not complete and domain in _DATA_DOMAINS:
            status = "warn"  # "nothing found" in data that was only partly read is not a green light
        out[domain] = status
    if not complete:
        out["assessment"] = "fail"
    else:
        if out["assessment"] == "not_assessed":  # the data basis itself was assessed: it is complete
            out["assessment"] = "ok"
        if out["assessment"] == "ok" and (basis.sampled or not_evaluated):
            out["assessment"] = "warn"
    return out


def is_alerts_only(report: Report) -> bool:
    """True when the input held only rule matches (Wazuh ``alerts.json`` / ``wazuh-alerts-*``), not all events."""
    return str(report.data_basis.input_kind) in _ALERTS_ONLY_KINDS


def incomplete_reasons(ctx: RenderContext, report: Report, statuses: Mapping[str, str] | None = None) -> list[str]:
    """Why the analysis is incomplete (empty list when it is complete)."""
    basis = report.data_basis
    reasons: list[str] = []
    if _count(basis.events) <= 0:
        reasons.append(ctx.t("report.basis.reason.no_events"))
    if basis.truncated:
        reasons.append(ctx.t("report.basis.reason.truncated"))
    failures = _as_list(basis.partial_failures)
    if failures:
        reasons.append(ctx.t("report.basis.reason.partial", n=ctx.num(len(failures))))
    # Same rule as the engine (exit code 3): any assessment-domain finding at medium or above.
    for finding in order_findings(f for f in report.findings if str(f.domain) == "assessment"):
        if _RANK[_severity_value(finding.severity)] >= _RANK["medium"]:
            reasons.append(ctx.msg(finding.title, 300))
    status = (statuses or domain_statuses(report)).get("assessment")
    if not reasons and status == "fail":
        reasons.append(ctx.t("report.basis.reason.assessment"))
    return reasons


# ---- view model -----------------------------------------------------------------------------------------------


@dataclass(slots=True)
class Fact:
    """One labelled value. ``level``: normal | warn | fail | muted. ``items``: multi-valued detail."""

    label: str
    value: str
    level: str = "normal"
    items: list[str] = field(default_factory=list)
    more: int = 0
    span: int = 1  # layout hint: how many grid columns a long value deserves


@dataclass(slots=True)
class BasisView:
    complete: bool
    reasons: list[str]
    caveats: list[str]
    facts: list[Fact]


@dataclass(slots=True)
class DomainCard:
    domain: str
    label: str
    status: str
    status_label: str
    counts: dict[str, int]
    detail: str
    notes: list[str] = field(default_factory=list)  # parts of the domain that could not be evaluated


@dataclass(slots=True)
class KeyNumber:
    label: str
    value: str
    hint: str = ""
    tone: str = "neutral"  # neutral | ok | warn | fail | na


@dataclass(slots=True)
class EvidenceRow:
    key: str
    label: str
    value: str
    series: list[float] | None = None


@dataclass(slots=True)
class FindingView:
    fingerprint: str
    anchor: str
    kind: str
    domain: str
    severity: str
    severity_label: str
    confidence: str
    confidence_label: str
    title: str
    subject: str
    reasons: list[str]
    evidence: list[EvidenceRow]
    recommendation: str
    explained: list[str]  # other findings this one explains (folded into it: same incident)
    review_required: bool


@dataclass(slots=True)
class FindingGroup:
    domain: str
    label: str
    findings: list[FindingView]
    count: int = -1  # findings in the domain (``findings`` may hold fewer when the view was built with a limit)

    def __post_init__(self) -> None:
        if self.count < 0:
            self.count = len(self.findings)


@dataclass(slots=True)
class RuleRow:
    rule_id: str
    description: str
    level: str
    total: str
    per_day: str
    analyst_facing: str
    share: str
    share_value: float | None
    clusters: str
    days_active: str
    anchor: str
    verdict: str
    verdict_label: str
    daily: list[float]


@dataclass(slots=True)
class TuneRow:
    anchor: str
    title: str
    rule: str
    scope: str
    hidden_per_day: str
    share_of_rule: str
    share_value: float | None
    af_hidden: str
    agents: str
    expires: str
    review_required: bool
    dependents: str


@dataclass(slots=True)
class InvestigateRow:
    anchor: str
    title: str
    verdict: str
    verdict_label: str
    severity: str
    severity_label: str
    reasons: list[str]


@dataclass(slots=True)
class NoiseView:
    assessed: bool
    status: str
    summary: str
    totals: list[Fact]
    rules: list[RuleRow]
    rules_more: int
    tune: list[TuneRow]
    investigate: list[InvestigateRow]
    index_volume: list[InvestigateRow]  # scopes that only add index volume: nothing to gain for analysts
    time_saved: str
    suppressions_file: str
    extra: list[Fact]


@dataclass(slots=True)
class SourceRow:
    level: str
    level_label: str
    key: str
    status: str
    status_label: str
    last_seen: str
    silent_for: str
    observed: str
    expected: str
    p: str
    tier: str
    tier_label: str
    duty_label: str
    daily: list[float]


@dataclass(slots=True)
class SilenceView:
    assessed: bool
    status: str
    counts: list[tuple[str, str, int]]
    monitorability: str
    monitorability_value: float | None
    alpha: str
    sources: list[SourceRow]
    sources_more: int
    extra: list[Fact]


@dataclass(slots=True)
class MatrixRow:
    agent: str
    platform: str
    cells: list[str]  # present | missing | silent | na
    tier_label: str = ""


@dataclass(slots=True)
class RecordTable:
    """A list of homogeneous records shown as a table (columns = the union of their keys)."""

    columns: list[str]
    rows: list[list[str]]
    more: int = 0


def _record_table(
    ctx: RenderContext, items: Sequence[Mapping[str, Any]], max_cols: int = 8, max_rows: int = 60
) -> RecordTable | None:
    keys: list[str] = []
    for item in items:
        for key in item:
            if str(key) not in keys:
                keys.append(str(key))
    if not items or not keys:
        return None
    keys = keys[:max_cols]
    rows = [[_evidence_value(ctx, k, item.get(k)) for k in keys] for item in items[:max_rows]]
    return RecordTable([ctx.evidence_label(k) for k in keys], rows, max(0, len(items) - max_rows))


# Expected-sources columns, in reading order: Matched = Present + Missing + Silent + Not assessed / explained.
_EXPECTED_COLUMNS = ("basis", "name", "log_source", "matched", "present", "missing", "silent", "not_assessed")


def _expected_table(ctx: RenderContext, items: Sequence[Mapping[str, Any]], max_rows: int = 60) -> RecordTable | None:
    """The expected-sources table (contracts and peer groups) with every host accounted for in a column."""
    if not items:
        return None
    keys = [k for k in _EXPECTED_COLUMNS if any(k in item for item in items)]
    if any(_as_float(item.get("low")) for item in items):
        keys.append("low")
    if any(item.get("min_events_per_day") is not None for item in items):
        keys.append("min_events_per_day")
    skip = {*keys, "not_assessed_hosts", "low", "min_events_per_day"}
    keys += list(dict.fromkeys(str(k) for item in items for k in item if str(k) not in skip))  # never dropped
    rows: list[list[str]] = []
    for item in items[:max_rows]:
        row = []
        for key in keys:
            text = _evidence_value(ctx, key, item.get(key))
            if key == "name" and item.get("basis") == "peers":  # a peer group is named after its platform
                text = _enum_text(ctx, "platform", str(item.get(key))) or text
            hosts = _as_list(item.get("not_assessed_hosts"))
            if key == "not_assessed" and hosts:
                names = ", ".join(ctx.value(h, 120) for h in hosts[:5])
                more = f" {ctx.t('report.more_items', n=ctx.num(len(hosts) - 5))}" if len(hosts) > 5 else ""
                text = f"{text} ({names}{more})"
            row.append(text)
        rows.append(row)
    return RecordTable([ctx.evidence_label(k) for k in keys], rows, max(0, len(items) - max_rows))


@dataclass(slots=True)
class CoverageView:
    assessed: bool
    status: str
    columns: list[str]
    columns_more: int
    rows: list[MatrixRow]
    rows_more: int
    platforms: list[Fact]
    expected: list[str]
    expected_table: RecordTable | None
    extra: list[Fact]


@dataclass(slots=True)
class CheckRow:
    name: str
    status: str | None
    status_label: str
    detail: str


@dataclass(slots=True)
class PipelineView:
    assessed: bool
    status: str
    agents: list[Fact]
    checks: list[CheckRow]
    extra: list[Fact]


@dataclass(slots=True)
class TuningView:
    assessed: bool
    status: str
    facts: list[Fact]
    extra: list[Fact]


@dataclass(slots=True)
class ReportView:
    lang: str
    title: str
    tagline: str
    tenant: str
    generated_at: str
    period: str
    redacted: bool
    incomplete: bool
    statuses: dict[str, str]
    basis: BasisView
    cards: list[DomainCard]
    numbers: list[KeyNumber]
    noise: NoiseView
    silence: SilenceView
    coverage: CoverageView
    pipeline: PipelineView
    tuning: TuningView
    others: list[tuple[str, list[Fact]]]
    groups: list[FindingGroup]
    total_findings: int
    severity_counts: dict[str, int]
    footer: list[str]
    audit: bool = False  # a ruleset audit: only the tuning audit applies (no events, no period)


def _anchor(fingerprint: str) -> str:
    return "f-" + (re.sub(r"[^A-Za-z0-9_-]", "", fingerprint)[:40] or "x")


def _generic_facts(
    ctx: RenderContext, section: Mapping[str, Any], consumed: Iterable[str], parent: str | None = None
) -> list[Fact]:
    """Keys of a section that no dedicated view consumed: never dropped silently, always labelled."""
    skip = set(consumed)
    facts: list[Fact] = []
    for key, value in section.items():
        if key in skip:
            continue
        name = str(key)
        label = ctx.evidence_label(name, parent)
        if isinstance(value, Mapping) and value and name.lower() not in _SCOPE_KEYS and name != "top_anchor":
            scope = parent if parent and any(has(f"report.ev.{parent}.{k}") for k in value) else name
            items = [
                f"{ctx.evidence_label(str(k), scope)}: {_evidence_value(ctx, str(k), v, name)}"
                for k, v in list(value.items())[:40]
            ]
            facts.append(Fact(label, "", items=items, more=max(0, len(value) - 40)))
        elif isinstance(value, (list, tuple)) and value and not _is_series(name, value):
            items = _list_items(ctx, name, list(value)[:40], parent)
            facts.append(Fact(label, ctx.num(len(value)), items=items, more=max(0, len(value) - 40)))
        else:
            facts.append(Fact(label, _cut(_evidence_value(ctx, name, value, parent), 500)))
    return facts


# Evidence keys shown elsewhere in a finding view (or redundant with another key), never as evidence rows.
_HIDDEN_EVIDENCE = frozenset({"explained", "time_saved_kind"})


def _finding_view(ctx: RenderContext, finding: Finding) -> FindingView:
    severity = _severity_value(finding.severity)
    confidence = str(getattr(finding.confidence, "value", finding.confidence) or "medium").lower()
    evidence: list[EvidenceRow] = []
    raw = _as_map(finding.evidence)
    items = [(k, v) for k, v in raw.items() if str(k) not in _HIDDEN_EVIDENCE]
    if "gap" in raw:  # "gap_seconds" is the same duration as "gap", only less readable
        items = [(k, v) for k, v in items if str(k) != "gap_seconds"]
    shown = 0
    for key, value in items:
        if len(evidence) >= _MAX_EVIDENCE_ROWS:
            break
        shown += 1
        name = str(key)
        if isinstance(value, Mapping) and value and name.lower() not in _SCOPE_KEYS and name not in _INLINE_MAPS:
            # one level of nesting (e.g. "backtest": {...}) becomes labelled rows: "Backtest › Demoted per day"
            parent = ctx.evidence_label(name)
            for sub_key, sub_value in list(value.items())[: _MAX_EVIDENCE_ROWS - len(evidence)]:
                sub_name = str(sub_key)
                label = f"{parent} › {ctx.evidence_label(sub_name, name)}"
                evidence.append(_evidence_row(ctx, f"{name}.{sub_name}", sub_name, sub_value, label, name))
        else:
            evidence.append(_evidence_row(ctx, name, name, value, ctx.evidence_label(name)))
    if shown < len(items):
        more = ctx.t("report.more_items", n=ctx.num(len(items) - shown))
        evidence.append(EvidenceRow("…", "…", more))
    all_reasons = reasons_of(finding)
    reasons = [ctx.msg(r, 1000) for r in all_reasons[:30]]
    if len(all_reasons) > 30:
        reasons.append(ctx.t("report.more_items", n=ctx.num(len(all_reasons) - 30)))
    explained_raw = raw.get("explained")
    explained = [ctx.value(e, 400) for e in _as_list(explained_raw)[:50]]
    return FindingView(
        fingerprint=ctx.text(finding.fingerprint, 64),
        anchor=_anchor(str(finding.fingerprint)),
        kind=ctx.text(finding.kind, 80),
        domain=str(finding.domain),
        severity=severity,
        severity_label=ctx.t(f"severity.{severity}"),
        confidence=confidence if confidence in ("high", "medium", "low") else "medium",
        confidence_label=ctx.label("confidence", confidence),
        title=ctx.msg(finding.title, 400) or ctx.text(finding.kind, 80),
        subject=ctx.subject(finding, 300),
        reasons=reasons,
        evidence=evidence,
        recommendation=ctx.msg(finding.recommendation, 1500),
        explained=explained,
        review_required=str(finding.domain) == "noise" and _review_required(finding),
    )


_PERCENT_KEYS = frozenset(
    {
        "share",
        "share_of_rule",
        "peer_share",
        "presence_before",
        "presence_after",
        "fp_rate",
        "fp_lower_bound",
        "regularity",
        "before",
        "after",
        "peer_coverage",
        "top5_share",
        "off_day_probability",
        "low_day_probability",
    }
)
_PVALUE_KEYS = frozenset({"p", "p0", "p_value", "pvalue", "q", "alpha", "alpha_eff", "cdf"})
_SCOPE_KEYS = frozenset({"conditions", "condition", "scope"})
_SECONDS_KEYS = frozenset({"gap_seconds", "threshold_seconds", "p50_seconds", "p95_seconds", "lag_seconds"})
# Nested mappings rendered inline as one value instead of one evidence row per key.
_INLINE_MAPS = frozenset({"top_anchor", "levels", "filter", "anchor"})


_MAX_EVIDENCE_ROWS = 40
_DATE_ONLY = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_TIME_SUFFIXES = ("_seen", "_at", "_time", "keepalive", "_event")
_TIME_KEYS = frozenset({"since", "data_end", "evaluated_until", "from", "to", "start", "end", "ts"})


def _evidence_row(
    ctx: RenderContext, path: str, key: str, value: Any, label: str, parent: str | None = None
) -> EvidenceRow:
    if _is_series(key, value):
        series = _series(value)
        return EvidenceRow(ctx.text(path, 80), label, ctx.spark_summary(series), series)
    return EvidenceRow(ctx.text(path, 80), label, _evidence_value(ctx, key, value, parent))


def _label_keys(key: str, parent: str | None) -> list[str]:
    """Catalog keys that can label ``key`` (under ``parent``), most specific first."""
    keys = [f"report.ev.{parent}.{key}"] if parent else []
    keys.append(f"report.ev.{key}")
    if parent in ("verdicts", "verdict_counts"):
        keys.append(f"report.verdict.{key}")
    elif parent == "status_counts":
        keys.append(f"report.sstatus.{key}")
    elif parent == "by_status":
        keys.append(f"report.agent.{key}")
    keys.append(f"report.val.{key}")
    return keys


def _enum_text(ctx: RenderContext, key: str, value: str) -> str | None:
    """The label of an enumerated value (``investigate`` -> "Investigar"), or None when it is not one."""
    candidates = [f"report.val.{key}.{value}"]
    prefixes = {
        "verdict": ("report.verdict",),
        "status": ("report.sstatus", "report.val", "status"),
        "agent_status": ("report.val",),
        "tier": ("report.tier",),
        "duty": ("report.duty",),
        "level": ("report.level",),
        "input_kind": ("report.input",),
        "basis": ("report.val", "report.input"),
        "now_origin": ("report.now_origin",),
        "check": ("report.check", "report.val"),
        "not_evaluated": ("domain",),
    }
    candidates += [f"{prefix}.{value}" for prefix in prefixes.get(key, ("report.val",))]
    for candidate in candidates:
        if has(candidate):
            return ctx.t(candidate)
    return None


def _seconds_text(ctx: RenderContext, seconds: float) -> str:
    if abs(seconds) < 60:
        return ctx.t("report.seconds", value=ctx.num(round(seconds, 1)))
    return ctx.dur(seconds)


def _count_text(ctx: RenderContext, template: str, number: Any, **params: str) -> str:
    """A labelled count whose noun agrees with the number ("1 alert", "2 alerts")."""
    plural = number if _as_float(number) is not None else 0
    return sanitize(render_message(M(template, n=plural, **params), ctx.lang))


def _record_text(ctx: RenderContext, parent: str, item: Mapping[str, Any]) -> str:
    """One record of a list (``{"entity": ..., "alerts": 2}``) as a readable line."""
    keys = set(item)
    if "entity" in keys or ("host" in keys and keys <= {"host", "alerts"}):
        who = ctx.value(item.get("entity", item.get("host")), 200)
        if keys <= {"entity", "host", "alerts"}:
            return _count_text(
                ctx, "report.fmt.alerts_of", item.get("alerts"), who=who, count=ctx.num(item.get("alerts"))
            )
        if {"active_hours", "span_hours"} <= keys:
            beacon = ctx.t("report.fmt.beaconing") if item.get("beaconing") else ""
            return ctx.t(
                "report.fmt.active_hours",
                who=who,
                active=ctx.num(item.get("active_hours")),
                span=ctx.num(item.get("span_hours")),
                regularity=ctx.pct(item.get("regularity")),
                beacon=beacon,
            ).strip()
    if "path" in keys and "alerts" in keys:
        return ctx.t(
            "report.fmt.path",
            path=ctx.value(item.get("path"), 300),
            alerts=_count_text(ctx, "report.fmt.alerts", item.get("alerts"), count=ctx.num(item.get("alerts"))),
            days=ctx.num(item.get("days_present")),
        )
    if parent == "worst" and "p95_seconds" in keys:
        p50, p95 = _as_float(item.get("p50_seconds")), _as_float(item.get("p95_seconds"))
        text = ctx.t(
            "report.fmt.lag",
            who=ctx.value(item.get("agent", item.get("source")), 200),
            p50=_seconds_text(ctx, p50) if p50 is not None else ctx.t("report.dash"),
            p95=_seconds_text(ctx, p95) if p95 is not None else ctx.t("report.dash"),
            samples=ctx.num(item.get("samples")),
        )
        kind = item.get("kind")
        if isinstance(kind, str) and kind != "ok":
            text += f" · {_enum_text(ctx, 'kind', kind) or ctx.text(kind, 40)}"
        return text
    if parent == "precursors" and "code" in keys:
        code = str(item.get("code"))
        what = ctx.t(f"silence.precursor.{code}") if has(f"silence.precursor.{code}") else ctx.text(code, 60)
        return ctx.t(
            "report.fmt.precursor",
            what=what,
            agent=ctx.value(item.get("agent"), 120),
            ts=ctx.dt(item.get("ts")),
            rule=ctx.value(item.get("rule_id"), 20),
            technique=ctx.value(item.get("technique"), 40),
        )
    if parent == "event_types" and "check" in keys:
        name = _enum_text(ctx, "check", str(item.get("check"))) or ctx.text(item.get("check"), 60)
        if not item.get("assessed"):
            return ctx.t("report.fmt.event_type_na", check=name)
        return ctx.t(
            "report.fmt.event_type",
            check=name,
            peers=ctx.num(item.get("peers")),
            missing=ctx.num(item.get("missing")),
            stopped=ctx.num(item.get("stopped")),
        )
    parts = [
        f"{ctx.evidence_label(str(k), parent)}: {_evidence_value(ctx, str(k), v, parent)}"
        for k, v in list(item.items())[:_MAX_ITEMS]
        if v not in (None, "", [], {})
    ]
    return " · ".join(parts) or ctx.t("report.dash")


def _list_items(ctx: RenderContext, key: str, values: Sequence[Any], parent: str | None = None) -> list[str]:
    """The items of a list value, each as display text (records as readable lines, enums translated)."""
    out: list[str] = []
    for value in values:
        if isinstance(value, Mapping):
            out.append(_cut(_record_text(ctx, key, value), 600))
        elif isinstance(value, str) and key in ENUM_KEYS:
            out.append(_enum_text(ctx, key, value) or ctx.text(value, 300))
        else:
            out.append(ctx.value(value, 300))
    return out


def _evidence_value(ctx: RenderContext, key: str, value: Any, parent: str | None = None) -> str:
    """Evidence values formatted by what their key means (shares as %, p-values, conditions, timestamps, gate
    results, enumerated values and records as readable text)."""
    lowered = key.lower()
    if parent == "gates" and isinstance(value, bool):
        return ctx.t("report.gate.passed" if value else "report.gate.tripped")
    number = _as_float(value)
    if number is not None and (lowered in _PERCENT_KEYS or lowered.endswith(("_share", "_rate"))) and 0 <= number <= 1:
        return ctx.pct(number)
    if number is not None and lowered in _PVALUE_KEYS:
        return ctx.pvalue(number)
    if number is not None and lowered in _SECONDS_KEYS:
        return _seconds_text(ctx, number)
    if lowered in _SCOPE_KEYS and value is not None and not isinstance(value, (int, float)):
        return _cut(_scope_text(ctx, value), 1000)
    if lowered == "filter" and isinstance(value, Mapping):
        # field paths stay as they are (they go into a SIEM query); pseudo-fields such as "log_source" get a label
        parts = [
            f"{ctx.text(str(k), 80) if '.' in str(k) else ctx.evidence_label(str(k))} = {ctx.value(v, 160)}"
            for k, v in list(value.items())[:6]
        ]
        return _cut(" ∧ ".join(parts), 1000)
    if lowered in ("top_anchor", "anchor") and isinstance(value, Mapping):
        return _anchor_text(ctx, value)
    if value is None and lowered in ("last_event", "last_seen"):
        return ctx.t("report.no_events")
    if isinstance(value, str) and _DATE_ONLY.match(value):
        return value  # a calendar day: no invented midnight
    if isinstance(value, str) and (lowered.endswith(_TIME_SUFFIXES) or lowered in _TIME_KEYS):
        return ctx.dt(value)
    if isinstance(value, str) and lowered in ENUM_KEYS:
        return _enum_text(ctx, lowered, value) or ctx.text(value, 1000)
    if isinstance(value, Mapping) and value:
        parts = [
            f"{ctx.evidence_label(str(k), key)}: {_evidence_value(ctx, str(k), v, key)}"
            for k, v in list(value.items())[:_MAX_ITEMS]
        ]
        if len(value) > _MAX_ITEMS:
            parts.append(ctx.t("report.more_items", n=ctx.num(len(value) - _MAX_ITEMS)))
        return _cut(" · ".join(parts), 1000)
    if isinstance(value, (list, tuple)) and value:
        items = _list_items(ctx, key, list(value)[:_MAX_ITEMS], parent)
        if len(value) > _MAX_ITEMS:
            items.append(ctx.t("report.more_items", n=ctx.num(len(value) - _MAX_ITEMS)))
        separator = "; " if any(isinstance(v, Mapping) for v in value) else ", "
        return _cut(separator.join(items), 1000)
    return ctx.value(value, 1000)


def _review_required(finding: Finding) -> bool:
    evidence = _as_map(finding.evidence)
    backtest = _as_map(evidence.get("backtest"))
    return bool(
        evidence.get("review_required")
        or _pick([evidence, backtest], "dependents", "dependent_rules")
        or evidence.get("action") == "review"
    )


def is_audit(report: Report) -> bool:
    """True for an ``audit`` report: the input was a Wazuh ruleset, not events."""
    return str(report.data_basis.input_kind) == "ruleset"


_WAZUH_PROFILES = frozenset({"wazuh4", "wazuh5"})


def basis_caveats(ctx: RenderContext, report: Report) -> list[str]:
    """Caveats about what the input can support (alerts-only input, Wazuh 5.x, sampling, minor gaps)."""
    basis = report.data_basis
    kind = str(basis.input_kind or "unknown")
    wazuh = str(basis.profile) in _WAZUH_PROFILES
    caveats: list[str] = []
    if kind in _ALERTS_ONLY_KINDS:
        caveats.append(ctx.t("report.caveat.alerts_only" if wazuh else "report.caveat.alerts_only_generic"))
    elif kind == "mixed":
        caveats.append(ctx.t("report.caveat.mixed"))
    elif (kind not in _INPUT_KINDS or kind == "unknown") and not is_audit(report):
        caveats.append(ctx.t("report.caveat.unknown"))
    if str(basis.profile) == "wazuh5":
        caveats.append(ctx.t("report.caveat.wazuh5"))
    if basis.sampled:
        caveats.append(ctx.t("report.caveat.sampled"))
    for finding in order_findings(f for f in report.findings if f.kind == "assessment.incomplete"):
        if _RANK[_severity_value(finding.severity)] < _RANK["medium"]:  # minor gaps: said, but not "incomplete"
            caveats.append(ctx.msg(finding.title, 300))
    return caveats


def _failure_text(ctx: RenderContext, value: Any) -> str:
    """A partial failure: a translatable :class:`Message` (rendered in the report language) or plain text."""
    return ctx.msg(value, 500) if isinstance(value, Message) else ctx.text(value, 500)


def _basis_view(ctx: RenderContext, report: Report, statuses: Mapping[str, str]) -> BasisView:
    basis = report.data_basis
    reasons = incomplete_reasons(ctx, report, statuses)
    kind = str(basis.input_kind or "unknown")
    profile = str(basis.profile or "unknown")
    caveats = basis_caveats(ctx, report)
    audit = is_audit(report)

    def count_fact(label: str, raw: Any, bad: str) -> Fact:
        value = _count(raw)
        return Fact(ctx.t(label), ctx.num(value), bad if value > 0 else "normal")

    facts = [
        Fact(
            ctx.t("report.basis.input"),
            ctx.label("report.input", kind),
            "warn" if kind in _ALERTS_ONLY_KINDS or kind in ("mixed", "unknown") else "normal",
        ),
        Fact(
            ctx.t("report.basis.profile"),
            ctx.label("report.profile", profile),
            "warn" if profile == "wazuh5" else "normal",
        ),
    ]
    if audit:  # a ruleset has no time range, no "now" and no events: say what was actually read
        rules = _as_int(_section(report, "tuning").get("rules_parsed"))
        count = rules if rules is not None else _count(basis.events)
        facts.append(Fact(ctx.t("report.basis.rules"), ctx.num(count), "fail" if count <= 0 else "normal"))
    else:
        facts.append(
            Fact(
                ctx.t("report.basis.range"),
                _range_text(ctx, basis.start, basis.end),
                "normal" if basis.start else "warn",
                span=2,
            )
        )
        if basis.now is not None:
            now_text = f"{ctx.dt(basis.now)} · {ctx.label('report.now_origin', basis.now_origin)}"
            facts.append(Fact(ctx.t("report.basis.now"), now_text, span=2))
            shift = _safe_delta(basis.now, basis.end)
            if shift is not None and abs(shift) >= timedelta(minutes=1):  # --now away from the newest event
                facts.append(Fact(ctx.t("report.basis.newest"), ctx.dt(basis.end), span=2))
        else:
            facts.append(Fact(ctx.t("report.basis.now"), ctx.t("report.unknown"), "warn"))
        age = _safe_delta(report.generated_at, basis.end)  # how old the NEWEST EVENT is, whatever --now says
        if age is not None and age > timedelta(days=1):
            facts.append(
                Fact(ctx.t("report.basis.age"), ctx.t("report.basis.age_value", duration=ctx.dur(age)), "warn")
            )
        events = _count(basis.events)
        facts.append(Fact(ctx.t("report.basis.events"), ctx.num(events), "fail" if events <= 0 else "normal"))
        facts.append(count_fact("report.basis.malformed", basis.malformed, "warn"))
        facts.append(count_fact("report.basis.bad_ts", basis.bad_timestamps, "warn"))
        facts.append(count_fact("report.basis.future_ts", basis.future_timestamps, "warn"))
        facts.append(
            Fact(ctx.t("report.basis.sampled"), ctx.value(bool(basis.sampled)), "warn" if basis.sampled else "normal")
        )
        facts.append(
            Fact(
                ctx.t("report.basis.truncated"),
                ctx.value(bool(basis.truncated)),
                "fail" if basis.truncated else "normal",
            )
        )
        excluded = _count(getattr(basis, "excluded_by_window", 0))
        if excluded:
            newest = getattr(basis, "excluded_newest", None)
            items = [ctx.t("report.basis.excluded_newest", at=ctx.dt(newest))] if newest is not None else []
            facts.append(Fact(ctx.t("report.basis.excluded"), ctx.num(excluded), "warn", items))
    failures = [_failure_text(ctx, p) for p in _as_list(basis.partial_failures)]
    facts.append(
        Fact(
            ctx.t("report.basis.partial"),
            ctx.num(len(failures)),
            "fail" if failures else "normal",
            failures[:20],
            max(0, len(failures) - 20),
        )
    )
    sources = [ctx.text(s, 300) for s in _as_list(basis.sources)]
    facts.append(
        Fact(ctx.t("report.basis.sources"), ctx.num(len(sources)), "normal", sources[:10], max(0, len(sources) - 10))
    )
    skipped = [ctx.text(s, 300) for s in _as_list(getattr(basis, "skipped_files", []))]
    if skipped:
        facts.append(
            Fact(
                ctx.t("report.basis.skipped_files"),
                ctx.num(len(skipped)),
                "warn",
                skipped[:10],
                max(0, len(skipped) - 10),
            )
        )
    warnings = [ctx.msg(w, 500) for w in _as_list(basis.warnings)]
    if warnings:
        facts.append(
            Fact(
                ctx.t("report.basis.warnings"),
                ctx.num(len(warnings)),
                "warn",
                warnings[:20],
                max(0, len(warnings) - 20),
            )
        )
    not_evaluated = [_not_evaluated_label(ctx, n) for n in _as_list(basis.not_evaluated)]
    facts.append(
        Fact(
            ctx.t("report.basis.not_evaluated"),
            ctx.num(len(not_evaluated)) if not_evaluated else ctx.t("report.none"),
            "warn" if not_evaluated else "normal",
            not_evaluated[:20],
        )
    )
    return BasisView(complete=not reasons, reasons=reasons, caveats=caveats, facts=facts)


def _not_evaluated_label(ctx: RenderContext, name: Any) -> str:
    text = str(name)
    return ctx.t(f"domain.{text}") if has(f"domain.{text}") else ctx.text(text, 100)


# not_evaluated markers that are parts of a domain (the domain itself ran): shown on that domain's card
_NOT_EVALUATED_DOMAIN = {
    "agent-inventory": "pipeline",
    "wazuh-api": "pipeline",
    "wazuh-manager-stats": "pipeline",
}


def iso_utc(value: Any) -> str | None:
    """``2026-09-25T10:00:00Z`` for a datetime (naive ones are taken as UTC); ``None`` for anything else."""
    if not isinstance(value, datetime):
        return None
    aware = value if value.tzinfo is not None else value.replace(tzinfo=UTC)
    try:
        return aware.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, ValueError, OSError):
        return None


def _safe_delta(later: Any, earlier: Any) -> timedelta | None:
    if not isinstance(later, datetime) or not isinstance(earlier, datetime):
        return None
    try:
        a = later if later.tzinfo else later.replace(tzinfo=UTC)
        b = earlier if earlier.tzinfo else earlier.replace(tzinfo=UTC)
        return a - b
    except (OverflowError, TypeError):
        return None


def _range_text(ctx: RenderContext, start: Any, end: Any) -> str:
    if not isinstance(start, datetime) or not isinstance(end, datetime):
        return ctx.t("report.unknown")
    delta = _safe_delta(end, start)
    return ctx.t("report.range", start=ctx.dt(start), end=ctx.dt(end), duration=ctx.dur(delta) if delta else "?")


def _cards(ctx: RenderContext, report: Report, statuses: Mapping[str, str]) -> list[DomainCard]:
    counts = _severity_counts(report.findings)
    cards: list[DomainCard] = []
    for domain in DOMAINS:
        status = statuses.get(domain, "not_assessed")
        per = counts.get(domain, dict.fromkeys(SEVERITY_ORDER, 0))
        total = sum(per.values())
        if total:
            parts = [
                ctx.t("report.card.count", n=ctx.num(per[s]), severity=ctx.t(f"severity.{s}"))
                for s in SEVERITY_ORDER
                if per[s]
            ]
            detail = " · ".join(parts)
        elif status == "not_assessed":
            detail = ctx.t("report.card.not_assessed")
        elif domain in _DATA_DOMAINS and not basis_complete(report.data_basis):
            detail = ctx.t("report.card.incomplete")
        elif domain == "assessment" and status == "fail":
            detail = ctx.t("report.card.assessment_incomplete")
        else:
            detail = ctx.t("report.card.no_findings")
        notes = [
            ctx.t("report.card.not_evaluated", what=_not_evaluated_label(ctx, marker))
            for marker in _as_list(report.data_basis.not_evaluated)
            if _NOT_EVALUATED_DOMAIN.get(str(marker)) == domain
        ]
        cards.append(
            DomainCard(domain, ctx.t(f"domain.{domain}"), status, ctx.t(f"status.{status}"), dict(per), detail, notes)
        )
    if is_audit(report):  # an audit reads a ruleset: only the tuning audit (and a failed assessment) apply
        cards = [c for c in cards if c.domain == "tuning" or (c.domain == "assessment" and c.status != "ok")]
    return cards


def _count_kinds(report: Report, *kinds: str) -> int:
    return sum(1 for f in report.findings if f.kind in kinds)


def _key_numbers(ctx: RenderContext, report: Report, statuses: Mapping[str, str]) -> list[KeyNumber]:
    na = ctx.t("report.kpi.na")
    dash = ctx.t("report.dash")
    noise = _section(report, "noise")
    totals = _as_map(noise.get("totals"))
    silence = _section(report, "silence")
    tuning = _section(report, "tuning")
    numbers = [
        KeyNumber(
            ctx.t("report.kpi.events"),
            ctx.num(_count(report.data_basis.events)),
            tone="fail" if _count(report.data_basis.events) <= 0 else "neutral",
        )
    ]

    noise_ok = bool(noise) and statuses.get("noise") != "not_assessed"
    days = _as_float(totals.get("days"))
    analyst_facing = _as_float(totals.get("analyst_facing"))
    if noise_ok and analyst_facing is not None and days:
        numbers.append(
            KeyNumber(
                ctx.t("report.kpi.analyst_facing"),
                ctx.num(analyst_facing / days),
                ctx.t("report.kpi.days", days=ctx.num(days)),
            )
        )
    else:
        numbers.append(KeyNumber(ctx.t("report.kpi.analyst_facing"), dash, na, "na"))
    top5 = _as_float(totals.get("top5_share"))
    numbers.append(
        KeyNumber(ctx.t("report.kpi.top5"), ctx.pct(top5), "", "neutral")
        if noise_ok and top5 is not None
        else KeyNumber(ctx.t("report.kpi.top5"), dash, na, "na")
    )
    if noise_ok:
        tunes = [f for f in report.findings if f.kind == "noise.tune"]
        review = sum(1 for f in tunes if _review_required(f))
        safe = _as_int(noise.get("safe_tuning_candidates"))
        if safe is None:  # older sections: every tune finding, review-required ones included
            safe = len(tunes)
        else:
            review = _as_int(noise.get("review_required_candidates")) or 0
        hints = [ctx.t("report.kpi.tune_hint", n=ctx.num(review))] if review else []
        index_only = _as_int(noise.get("index_volume_candidates")) or 0
        if index_only:
            hints.append(ctx.t("report.kpi.index_hint", n=ctx.num(index_only)))
        tone = "ok" if safe else "neutral"
        numbers.append(KeyNumber(ctx.t("report.kpi.tune"), ctx.num(safe), " · ".join(hints), tone))
    else:
        numbers.append(KeyNumber(ctx.t("report.kpi.tune"), dash, na, "na"))

    if silence and statuses.get("silence") != "not_assessed":
        status_counts = _as_map(silence.get("status_counts"))
        if status_counts:
            silent = sum(_as_int(status_counts.get(k)) or 0 for k in ("silent", "drop", "tampering"))
        else:
            silent = _count_kinds(
                report, "silence.silent", "silence.drop", "silence.tampering", "pipeline.global_silence"
            )
        numbers.append(KeyNumber(ctx.t("report.kpi.silent"), ctx.num(silent), "", "fail" if silent else "ok"))
        mon = _as_map(silence.get("monitorability"))
        total = _as_int(mon.get("critical_total"))
        part = _as_int(mon.get("critical_monitorable"))
        if total:
            numbers.append(
                KeyNumber(
                    ctx.t("report.kpi.monitorable"),
                    ctx.pct((part or 0) / total),
                    ctx.t("report.of", part=ctx.num(part or 0), total=ctx.num(total)),
                    "ok" if (part or 0) >= total else "warn",
                )
            )
        else:
            numbers.append(KeyNumber(ctx.t("report.kpi.monitorable"), dash, ctx.t("report.silence.no_critical"), "na"))
    else:
        numbers.append(KeyNumber(ctx.t("report.kpi.silent"), dash, na, "na"))
        numbers.append(KeyNumber(ctx.t("report.kpi.monitorable"), dash, na, "na"))

    if statuses.get("coverage") != "not_assessed":
        gaps = _count_kinds(report, "coverage.missing_source", "coverage.missing_event_type")
        numbers.append(KeyNumber(ctx.t("report.kpi.coverage"), ctx.num(gaps), "", "warn" if gaps else "ok"))
    else:
        numbers.append(KeyNumber(ctx.t("report.kpi.coverage"), dash, na, "na"))
    if statuses.get("tuning") != "not_assessed":
        risky = _as_int(tuning.get("risky"))
        expired = _count_kinds(report, "tuning.expired")
        if risky is None:
            risky = _count_kinds(report, "tuning.risky_suppression")
        value = risky + expired
        numbers.append(KeyNumber(ctx.t("report.kpi.risky"), ctx.num(value), "", "warn" if value else "ok"))
    else:
        numbers.append(KeyNumber(ctx.t("report.kpi.risky"), dash, na, "na"))
    if is_audit(report):  # a ruleset audit: rules instead of events, and only the tuning numbers apply
        rules = _as_int(tuning.get("rules_parsed"))
        count = rules if rules is not None else _count(report.data_basis.events)
        numbers = [
            KeyNumber(ctx.t("report.kpi.rules"), ctx.num(count), tone="fail" if count <= 0 else "neutral"),
            numbers[-1],
        ]
    if not basis_complete(report.data_basis):  # a count of zero on partial data is not a green light
        for number in numbers:
            if number.tone == "ok":
                number.tone = "neutral"
    return numbers


def _anchor_text(ctx: RenderContext, value: Any) -> str:
    anchor = _as_map(value)
    if not anchor:
        return ctx.t("report.dash") if value in (None, {}, "") else ctx.value(value, 200)
    field_name = ctx.text(anchor.get("field", "?"), 60)
    share = _as_float(anchor.get("share"))
    shown = f"{field_name} = {ctx.value(anchor.get('value'), 120)}"
    return f"{shown} ({ctx.pct(share)})" if share is not None else shown


def _verdict(ctx: RenderContext, value: Any) -> tuple[str, str]:
    text = str(value).strip().lower() if isinstance(value, str) else ""
    if text in _VERDICTS:
        return text, ctx.t(f"report.verdict.{text}")
    return "other", ctx.text(value, 40) if value is not None else ctx.t("report.dash")


def _scope_text(ctx: RenderContext, value: Any) -> str:
    if value is None:
        return ctx.t("report.dash")
    if isinstance(value, Mapping) and not ("field" in value and "value" in value):
        return " ∧ ".join(f"{ctx.text(str(k), 80)} = {ctx.value(v, 160)}" for k, v in list(value.items())[:6])
    items = value if isinstance(value, (list, tuple)) else [value]
    parts: list[str] = []
    for item in list(items)[:6]:
        mapping = _as_map(item)
        if "field" in mapping:
            parts.append(f"{ctx.text(mapping.get('field'), 80)} = {ctx.value(mapping.get('value'), 160)}")
        else:
            parts.append(ctx.value(item, 200))
    return " ∧ ".join(parts)


def _noise_view(ctx: RenderContext, report: Report, status: str) -> NoiseView:
    section = _section(report, "noise")
    totals = _as_map(section.get("totals"))
    assessed = bool(section) and status != "not_assessed"
    summary = ""
    total_facts: list[Fact] = []
    if totals:
        summary = ctx.t(
            "report.noise.summary",
            alerts=ctx.num(totals.get("alerts")),
            days=ctx.num(totals.get("days")),
            analyst_facing=ctx.num(totals.get("analyst_facing")),
            rules=ctx.num(totals.get("rules")),
            clusters=ctx.num(totals.get("clusters")),
        )
        total_facts = _generic_facts(ctx, totals, ())
    rules: list[RuleRow] = []
    raw_rules = _as_list(section.get("rules"))
    for raw in raw_rules[:100]:
        rule = _as_map(raw)
        verdict, verdict_label = _verdict(ctx, rule.get("verdict"))
        if verdict == "tune" and rule.get("verdict_scoped"):  # the verdict covers one scope, not the whole rule
            verdict_label = ctx.t("report.verdict.tune_scoped")
        days_active = _as_int(rule.get("days_active"))
        days = _as_int(rule.get("days"))
        share = _as_float(rule.get("share"))
        rules.append(
            RuleRow(
                rule_id=_short_rule_id(ctx.text(rule.get("rule_id", "?"), 60)),
                description=ctx.text(rule.get("description") or "", 160),
                level=ctx.num(rule.get("level")),
                total=ctx.num(rule.get("total")),
                per_day=ctx.num(rule.get("per_day")),
                analyst_facing=ctx.num(rule.get("analyst_facing")),
                share=ctx.pct(share),
                share_value=None if share is None else max(0.0, min(1.0, share if share <= 1 else share / 100)),
                clusters=ctx.num(rule.get("clusters")),
                days_active=f"{ctx.num(days_active)}/{ctx.num(days)}"
                if days_active is not None
                else ctx.t("report.dash"),
                anchor=_anchor_text(ctx, rule.get("top_anchor")),
                verdict=verdict,
                verdict_label=verdict_label,
                daily=_series(rule.get("daily")),
            )
        )
    tune: list[TuneRow] = []
    investigate: list[InvestigateRow] = []
    index_volume: list[InvestigateRow] = []
    for finding in order_findings(report.findings):
        if finding.kind == "noise.tune":
            ev = _as_map(finding.evidence)
            maps = [_as_map(ev.get("backtest")), ev]  # backtest numbers (what would really be hidden) win
            share = _as_float(_pick(maps, "share_of_rule", "hidden_share", "share"))
            dependents = _pick(maps, "dependents", "dependent_rules")
            tune.append(
                TuneRow(
                    anchor=_anchor(str(finding.fingerprint)),
                    title=ctx.msg(finding.title, 300),
                    rule=ctx.value(_pick(maps, "rule_id", "rule"), 60),
                    scope=_scope_text(ctx, _pick(maps, "conditions", "condition", "scope", "anchor")),
                    hidden_per_day=ctx.num(_pick(maps, "hidden_per_day", "alerts_hidden_per_day")),
                    share_of_rule=ctx.pct(share),
                    share_value=None if share is None else max(0.0, min(1.0, share if share <= 1 else share / 100)),
                    af_hidden=ctx.num(_pick(maps, "hidden_analyst_facing", "analyst_facing_hidden")),
                    agents=ctx.value(_pick(maps, "agents_affected", "agents", "hosts_affected"), 120),
                    expires=ctx.value(_pick(maps, "expires", "expiry"), 40),
                    review_required=_review_required(finding),
                    dependents=ctx.value(dependents, 200) if dependents else "",
                )
            )
        elif finding.kind in _NOISE_OTHER_KINDS or finding.kind == "noise.index_volume":
            index_only = finding.kind == "noise.index_volume"
            if index_only:
                verdict, verdict_label = "watch", ctx.t("report.noise.index_volume_badge")
            else:
                verdict, verdict_label = _verdict(ctx, finding.kind.split(".", 1)[1])
            severity = _severity_value(finding.severity)
            (index_volume if index_only else investigate).append(
                InvestigateRow(
                    anchor=_anchor(str(finding.fingerprint)),
                    title=ctx.msg(finding.title, 300),
                    verdict=verdict,
                    verdict_label=verdict_label,
                    severity=severity,
                    severity_label=ctx.t(f"severity.{severity}"),
                    reasons=[ctx.msg(r, 1000) for r in reasons_of(finding)[:8]],
                )
            )
    time_saved = ""
    saved = _as_list(section.get("time_saved_minutes_per_day"))
    low, high = (_as_float(saved[0]), _as_float(saved[1])) if len(saved) >= 2 else (None, None)
    if low is not None and high is not None:
        if high <= 0:  # "0–0 min/day" reads like a bug: say it plainly
            time_saved = ctx.t("report.noise.time_saved_none")
        else:
            time_saved = ctx.t("report.noise.time_saved_value", low=ctx.num(low), high=ctx.num(high))
    suppressions = section.get("suppressions_file")
    consumed = ("status", "totals", "rules", "time_saved_minutes_per_day", "time_saved_kind", "suppressions_file")
    return NoiseView(
        assessed=assessed,
        status=status,
        summary=summary,
        totals=total_facts,
        rules=rules,
        rules_more=max(0, len(raw_rules) - 100),
        tune=tune,
        investigate=investigate,
        index_volume=index_volume,
        time_saved=time_saved,
        suppressions_file=ctx.text(suppressions, 500) if suppressions else "",
        extra=_generic_facts(ctx, section, consumed),
    )


_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


def _short_rule_id(rule_id: str) -> str:
    """ECS/Elastic rule ids are UUIDs: the table shows their first block (the rule name is in the next column)."""
    return f"{rule_id[:8]}…" if _UUID.match(rule_id) else rule_id


def _key_text(ctx: RenderContext, key: Any) -> str:
    mapping = _as_map(key)
    if mapping:
        return " · ".join(ctx.value(v, 120) for v in mapping.values()) or ctx.t("report.silence.tenant_key")
    if isinstance(key, (list, tuple)):
        return " · ".join(ctx.value(v, 120) for v in key) or ctx.t("report.silence.tenant_key")
    if key in (None, "", {}):
        return ctx.t("report.silence.tenant_key")
    return ctx.value(key, 240)


def _silence_view(ctx: RenderContext, report: Report, status: str) -> SilenceView:
    section = _section(report, "silence")
    assessed = bool(section) and status != "not_assessed"
    raw_counts = _as_map(section.get("status_counts"))
    ordered = [k for k in _SOURCE_STATUSES if k in raw_counts] + sorted(
        str(k) for k in raw_counts if k not in _SOURCE_STATUSES
    )
    counts = [(key, ctx.label("report.sstatus", key), _as_int(raw_counts.get(key)) or 0) for key in ordered]
    mon = _as_map(section.get("monitorability"))
    monitorability = ""
    mon_value: float | None = None
    total = _as_int(mon.get("critical_total"))
    if mon:
        if total:
            part = _as_int(mon.get("critical_monitorable")) or 0
            mon_value = max(0.0, min(1.0, part / total))
            monitorability = ctx.t(
                "report.silence.monitorability_value", pct=ctx.pct(mon_value), part=ctx.num(part), total=ctx.num(total)
            )
            sla = _as_float(mon.get("sla_hours"))
            if sla is not None:
                monitorability += " · " + ctx.t("report.silence.sla", hours=ctx.num(sla))
        else:
            monitorability = ctx.t("report.silence.no_critical")
    alpha = ""
    if _as_float(section.get("alpha_eff")) is not None:
        alpha = ctx.t(
            "report.silence.alpha",
            alpha=ctx.pvalue(section.get("alpha_eff")),
            keys=ctx.num(section.get("keys_evaluated")),
        )
    now = report.data_basis.now
    sources: list[SourceRow] = []
    raw_sources = _as_list(section.get("sources"))
    # Worst first (tampering, silent, drop... ok last), critical tier first: a silent source must never sit
    # below twenty OK rows, or past the display cap.
    status_rank = {name: i for i, name in enumerate(_SOURCE_STATUSES)}
    tier_rank = {"critical": 0, "standard": 1, "low": 2}

    def source_order(raw: Any) -> tuple[float, int]:
        src = _as_map(raw)
        st = str(src.get("status") or "").lower()
        rank = status_rank.get(st, status_rank["ok"] - 0.5)  # an unknown status is never filed with the OK ones
        return (rank, tier_rank.get(str(src.get("tier") or ""), 3))

    for raw in sorted(raw_sources, key=source_order)[:200]:
        src = _as_map(raw)
        level = str(src.get("level") or "")
        st = str(src.get("status") or "").lower()
        tier = str(src.get("tier") or "")
        last_seen = src.get("last_seen")
        silent_for = ""
        parsed = parse_ts(last_seen) if isinstance(last_seen, (str, datetime)) and len(str(last_seen)) <= 64 else None
        gap = _safe_delta(now, parsed) if parsed is not None else None
        if gap is not None and gap > timedelta(0):
            silent_for = ctx.t("report.ago", duration=ctx.dur(gap))
        sources.append(
            SourceRow(
                level=level,
                level_label=ctx.label("report.level", level) if level else ctx.t("report.dash"),
                key=_key_text(ctx, src.get("key")),
                status=st if st in _SOURCE_STATUSES else "other",
                status_label=ctx.label("report.sstatus", st) if st else ctx.t("report.dash"),
                last_seen=ctx.dt(last_seen) if last_seen else ctx.t("report.dash"),
                silent_for=silent_for,
                observed=ctx.num(src.get("observed")),
                expected=ctx.num(src.get("expected")),
                p=ctx.pvalue(src.get("p")),
                tier=tier if tier in ("critical", "standard", "low") else "other",
                tier_label=ctx.label("report.tier", tier) if tier else ctx.t("report.dash"),
                duty_label=ctx.label("report.duty", src.get("duty")) if src.get("duty") else ctx.t("report.dash"),
                daily=_series(src.get("daily")),
            )
        )
    consumed = ("status", "status_counts", "monitorability", "alpha_eff", "keys_evaluated", "sources")
    return SilenceView(
        assessed=assessed,
        status=status,
        counts=counts,
        monitorability=monitorability,
        monitorability_value=mon_value,
        alpha=alpha,
        sources=sources,
        sources_more=max(0, len(raw_sources) - 200),
        extra=_generic_facts(ctx, section, consumed),
    )


def _coverage_view(
    ctx: RenderContext, report: Report, status: str, max_cols: int = 16, max_rows: int = 150
) -> CoverageView:
    section = _section(report, "coverage")
    assessed = bool(section) and status != "not_assessed"
    raw_rows = [_as_map(r) for r in _as_list(section.get("matrix"))]
    expected_raw = _as_list(section.get("expected_sources"))
    expected_names: list[str] = []
    for item in expected_raw:
        name = item if isinstance(item, str) else _as_map(item).get("log_source")
        if isinstance(name, str) and name not in expected_names:
            expected_names.append(name)
    frequency: dict[str, int] = {}
    for row in raw_rows:
        for name, cell in _as_map(row.get("log_sources")).items():
            frequency[str(name)] = frequency.get(str(name), 0) + (1 if cell == "present" else 0)
    ordered = [n for n in expected_names if n in frequency]
    ordered += sorted((n for n in frequency if n not in ordered), key=lambda n: (-frequency[n], n))
    columns_raw = ordered[:max_cols]
    rows: list[MatrixRow] = []
    for row in raw_rows[:max_rows]:
        cells_map = {str(k): v for k, v in _as_map(row.get("log_sources")).items()}
        cells = []
        for name in columns_raw:
            cell = cells_map.get(name)
            cells.append(cell if cell in ("present", "missing", "silent") else "na")
        tier = row.get("tier")
        rows.append(
            MatrixRow(
                agent=ctx.value(row.get("agent"), 120),
                platform=_enum_text(ctx, "platform", str(row.get("platform") or ""))
                or ctx.text(row.get("platform") or "", 40),
                cells=cells,
                tier_label=ctx.label("report.tier", tier) if isinstance(tier, str) and tier else "",
            )
        )
    platforms = _generic_facts(ctx, _as_map(section.get("platforms")), (), "platforms")
    consumed = ("status", "matrix", "matrix_total", "matrix_truncated", "expected_sources", "platforms")
    total_rows = max(len(raw_rows), _as_int(section.get("matrix_total")) or 0)
    records = [item for item in expected_raw if isinstance(item, Mapping)]
    return CoverageView(
        assessed=assessed,
        status=status,
        columns=[ctx.text(c, 60) for c in columns_raw],
        columns_more=max(0, len(ordered) - max_cols),
        rows=rows,
        rows_more=max(0, total_rows - len(rows)),
        platforms=platforms,
        expected=[ctx.value(e, 200) for e in expected_raw[:40] if not isinstance(e, Mapping)],
        expected_table=_expected_table(ctx, records),
        extra=_generic_facts(ctx, section, consumed),
    )


# pipeline check fields that only repeat what the data-basis banner already says, or are empty lists
_CHECK_SKIP = frozenset({"not_evaluated"})


def _check_detail(ctx: RenderContext, mapping: Mapping[str, Any], skip: Iterable[str], basis: DataBasis | None) -> str:
    check = str(mapping.get("check") or "")
    if check == "freshness" and basis is not None:
        # the newest EVENT (basis.end) and the reference "now" (basis.now, maybe set with --now) are shown apart
        parts = [f"{ctx.t('report.basis.newest')}: {ctx.dt(basis.end) if basis.end else ctx.t('report.unknown')}"]
        if basis.now is not None:
            origin = ctx.label("report.now_origin", basis.now_origin)
            parts.append(f"{ctx.t('report.basis.now')}: {ctx.dt(basis.now)} ({origin})")
        age = _as_float(mapping.get("age_hours"))
        if age is not None:
            parts.append(f"{ctx.evidence_label('age_hours')}: {ctx.num(age)}")
        return " · ".join(parts)
    rest: list[str] = []
    for key, value in mapping.items():
        name = str(key)
        if name in skip or name in _CHECK_SKIP or value in (None, "", [], {}):
            continue
        if isinstance(value, (list, tuple)) and value and all(isinstance(v, Mapping) for v in value):
            shown = _list_items(ctx, name, list(value)[:3])
            if len(value) > 3:
                shown.append(ctx.t("report.more_items", n=ctx.num(len(value) - 3)))
            rest.append(f"{ctx.evidence_label(name)}: {'; '.join(shown)}")
        else:
            rest.append(f"{ctx.evidence_label(name)}: {_evidence_value(ctx, name, value)}")
    return " · ".join(rest[:12])


def _check_row(ctx: RenderContext, item: Any, basis: DataBasis | None = None) -> CheckRow:
    mapping = _as_map(item)
    if not mapping:
        return CheckRow(ctx.value(item, 300), None, "", "")
    name_key = next((k for k in ("name", "check", "id", "kind", "title") if mapping.get(k) is not None), None)
    status: str | None = _norm_status(mapping.get("status"))
    if status is None and isinstance(mapping.get("ok"), bool):
        status = "ok" if mapping["ok"] else "fail"
    detail = _check_detail(ctx, mapping, (name_key or "", "status", "ok"), basis)
    return CheckRow(
        name=(
            ctx.label("report.check", mapping.get(name_key))
            if name_key and isinstance(mapping.get(name_key), str)
            else ctx.value(mapping.get(name_key), 200)
            if name_key
            else ctx.t("report.dash")
        ),
        status=status,
        status_label=ctx.t(f"status.{status}") if status else ctx.value(mapping.get("status"), 40),
        detail=_cut(detail, 700),
    )


def _pipeline_view(ctx: RenderContext, report: Report, status: str) -> PipelineView:
    section = _section(report, "pipeline")
    assessed = bool(section) and status != "not_assessed"
    agents = [
        Fact(ctx.label("report.agent", str(k)), ctx.value(v, 200)) for k, v in _as_map(section.get("agents")).items()
    ]
    checks = [_check_row(ctx, item, report.data_basis) for item in _as_list(section.get("checks"))[:100]]
    return PipelineView(
        assessed=assessed,
        status=status,
        agents=agents,
        checks=checks,
        extra=_generic_facts(ctx, section, ("status", "agents", "checks")),
    )


def _tuning_view(ctx: RenderContext, report: Report, status: str) -> TuningView:
    section = _section(report, "tuning")
    assessed = bool(section) and status != "not_assessed"
    facts: list[Fact] = []
    known = (
        "rules_parsed",
        "local_rules",
        "risky",
        "risky_high",
        "expired",
        "parse_errors",
        "errors",
        "duplicate_ids",
        "files",
        "local_files",
    )
    for key in known:
        if key in section:
            value = section[key]
            warn_keys = ("risky", "risky_high", "expired", "parse_errors", "errors", "duplicate_ids")
            level = "warn" if key in warn_keys and (_as_float(value) or 0) > 0 else "normal"
            if isinstance(value, (list, tuple)):
                facts.append(
                    Fact(
                        ctx.t(f"report.tuning.{key}"),
                        ctx.num(len(value)),
                        level,
                        [ctx.value(v, 300) for v in value[:20]],
                        max(0, len(value) - 20),
                    )
                )
            else:
                facts.append(Fact(ctx.t(f"report.tuning.{key}"), ctx.value(value, 200), level))
    return TuningView(
        assessed=assessed, status=status, facts=facts, extra=_generic_facts(ctx, section, ("status", *known))
    )


def build_view(ctx: RenderContext, report: Report, *, finding_limit: int | None = None) -> ReportView:
    """Everything the Markdown, console and HTML renderers show, as display-ready (unescaped) text.

    ``finding_limit`` builds detailed views for only the N most severe findings of the whole report (never
    "the first N of the first domain": a critical silence finding must not hide behind 60 noise ones); group
    counts and totals still cover every finding.
    """
    statuses = domain_statuses(report)
    basis = _basis_view(ctx, report, statuses)
    findings = order_findings(report.findings)
    detailed = {id(f) for f in findings[: finding_limit if finding_limit is not None else len(findings)]}
    groups: list[FindingGroup] = []
    known = set(DOMAINS)
    by_domain: dict[str, list[Finding]] = {}
    for finding in findings:
        by_domain.setdefault(str(finding.domain), []).append(finding)
    for domain in (*DOMAINS, *sorted(set(by_domain) - known)):
        members = by_domain.get(domain, [])
        if members:
            views = [_finding_view(ctx, f) for f in members if id(f) in detailed]
            label = ctx.t(f"domain.{domain}") if domain in known else ctx.text(domain, 60)
            groups.append(FindingGroup(domain, label, views, len(members)))
    severity_counts = dict.fromkeys(SEVERITY_ORDER, 0)
    for finding in findings:
        severity_counts[_severity_value(finding.severity)] += 1
    others = [
        (ctx.text(str(name), 80), _generic_facts(ctx, _as_map(section), ()))
        for name, section in sorted(_as_map(report.sections).items(), key=lambda item: str(item[0]))
        if name not in DOMAINS
    ]
    basis_obj = report.data_basis
    audit = is_audit(report)
    period = "" if audit else _range_text(ctx, basis_obj.start, basis_obj.end)
    footer = [
        ctx.t("report.footer.readonly"),
        ctx.t("report.footer.redacted" if ctx.redacted else "report.footer.not_redacted"),
        " · ".join(
            [
                ctx.t("report.footer.tool", version=ctx.text(report.tool_version, 40)),
                ctx.t("report.footer.generated", at=ctx.dt(report.generated_at)),
                ctx.t("report.footer.schema", schema=SCHEMA_VERSION),
            ]
        ),
    ]
    return ReportView(
        lang=ctx.lang,
        title=ctx.t("report.title"),
        tagline=ctx.t("report.tagline"),
        tenant=ctx.text(report.tenant, 120),
        generated_at=ctx.dt(report.generated_at),
        period=period,
        redacted=ctx.redacted,
        incomplete=not basis.complete,
        statuses=statuses,
        basis=basis,
        cards=_cards(ctx, report, statuses),
        numbers=_key_numbers(ctx, report, statuses),
        noise=_noise_view(ctx, report, statuses["noise"]),
        silence=_silence_view(ctx, report, statuses["silence"]),
        coverage=_coverage_view(ctx, report, statuses["coverage"]),
        pipeline=_pipeline_view(ctx, report, statuses["pipeline"]),
        tuning=_tuning_view(ctx, report, statuses["tuning"]),
        others=others,
        groups=groups,
        total_findings=len(findings),
        severity_counts=severity_counts,
        footer=footer,
        audit=audit,
    )


# ---- fleet ----------------------------------------------------------------------------------------------------


@dataclass(slots=True)
class FleetRow:
    tenant: str
    generated_at: str
    generated_at_iso: str | None
    statuses: dict[str, str]
    critical: int
    high: int
    total: int
    events: int
    incomplete: bool
    period: str
    worst_title: str
    worst_severity: str
    worst_fingerprint: str


def fleet_rows(
    reports: Sequence[Report],
    lang: str,
    redactor_for: Mapping[str, Redactor | None] | Redactor | None,
) -> tuple[RenderContext, list[FleetRow]]:
    """One summary row per tenant, worst first (critical, then high findings, then incomplete data).

    ``redactor_for`` is one redactor for every tenant or a ``{tenant: Redactor | None}`` mapping (per-tenant keys).
    With a mapping, a tenant that is missing from it is still pseudonymized (with a throw-away random key):
    asking for redaction must never silently leave one tenant in clear text. Map a tenant to ``None``
    explicitly to show its real values.
    """
    base = RenderContext(None, lang, None)
    rows: list[tuple[tuple[int, int, int, str], FleetRow]] = []
    for report in reports:
        redactor: Redactor | None
        if isinstance(redactor_for, Mapping):
            redactor = redactor_for[report.tenant] if report.tenant in redactor_for else Redactor()
        else:
            redactor = redactor_for
        ctx = prepare_context(report, lang, redactor)
        statuses = domain_statuses(report)
        incomplete = bool(incomplete_reasons(ctx, report, statuses))
        findings = order_findings(report.findings)
        severities = [_severity_value(f.severity) for f in findings]
        critical = severities.count("critical")
        high = severities.count("high")
        worst = findings[0] if findings else None
        row = FleetRow(
            tenant=base.text(report.tenant, 120),
            generated_at=ctx.dt(report.generated_at),
            generated_at_iso=iso_utc(report.generated_at),
            statuses=statuses,
            critical=critical,
            high=high,
            total=len(findings),
            events=_count(report.data_basis.events),
            incomplete=incomplete,
            period=_range_text(ctx, report.data_basis.start, report.data_basis.end),
            worst_title=ctx.msg(worst.title, 200) if worst else "",
            worst_severity=_severity_value(worst.severity) if worst else "",
            worst_fingerprint=ctx.text(worst.fingerprint, 64) if worst else "",
        )
        rows.append(((-critical, -high, -int(incomplete), row.tenant), row))
    rows.sort(key=lambda item: item[0])
    return base, [row for _, row in rows]


def fleet_footer(ctx: RenderContext, reports: Sequence[Report]) -> list[str]:
    """Footer lines of a fleet summary: the read-only notice, then tool version, generation time and schema."""
    versions = sorted({ctx.text(r.tool_version, 40) for r in reports})
    generated = [r.generated_at for r in reports if isinstance(r.generated_at, datetime)]
    parts = [ctx.t("report.footer.tool", version=", ".join(versions))] if versions else []
    if generated:
        parts.append(ctx.t("report.footer.generated", at=ctx.dt(max(generated, key=_utc_key))))
    parts.append(ctx.t("report.footer.schema", schema=SCHEMA_VERSION))
    return [ctx.t("report.footer.readonly"), " · ".join(parts)]


def _utc_key(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)
