"""Stable, versioned JSON report.

* ``schema_version`` comes from :data:`hushwatch.models.SCHEMA_VERSION`; ``document`` names the shape
  (``hushwatch.report`` or ``hushwatch.fleet``).
* Every message is kept twice: ``text`` rendered in the chosen language, plus its ``key`` and ``params``
  (entities inside params rendered, and pseudonymized when a redactor is given), so machines can re-render it.
* Timestamps are ISO-8601 UTC (``2026-09-25T10:00:00Z``); keys are sorted, output is deterministic.
* Non-finite floats become ``null`` (strict JSON); strings are sanitized and capped like every other format.
"""

from __future__ import annotations

import json
import math
from collections.abc import Mapping, Sequence
from datetime import date, datetime, timedelta
from enum import Enum
from typing import Any

from ..i18n import Entity, Message
from ..models import DOMAINS, SCHEMA_VERSION, Finding, Report
from ..redact import Redactor
from .common import (
    SEVERITY_ORDER,
    RenderContext,
    basis_caveats,
    basis_complete,
    domain_statuses,
    fleet_rows,
    incomplete_reasons,
    is_alerts_only,
    iso_utc,
    order_findings,
    prepare_context,
    reasons_of,
    severity_name,
)

__all__ = ["build_document", "render_json", "render_json_many", "report_document"]

_MAX_DEPTH = 32


def _seq(value: Any) -> list[Any]:
    """A list-typed field as a list (a mistyped string must not be iterated character by character)."""
    return list(value) if isinstance(value, (list, tuple)) else []


_iso = iso_utc


class _Jsonifier:
    """Converts report structures to JSON-safe values through a :class:`RenderContext`."""

    def __init__(self, ctx: RenderContext) -> None:
        self.ctx = ctx

    def value(self, value: Any, depth: int = 0) -> Any:
        ctx = self.ctx
        if depth > _MAX_DEPTH:
            return None
        if value is None or isinstance(value, bool):
            return value
        if isinstance(value, int):
            return value if value.bit_length() <= 256 else None  # json refuses ints over 4300 digits
        if isinstance(value, float):
            return value if math.isfinite(value) else None
        if isinstance(value, str):
            return ctx.text(value)
        if isinstance(value, Entity):
            return ctx.ent(value)
        if isinstance(value, Message):
            return self.message(value)
        if isinstance(value, datetime):
            return _iso(value)
        if isinstance(value, date):
            return value.isoformat()
        if isinstance(value, timedelta):
            return value.total_seconds()
        if isinstance(value, Enum):
            return self.value(value.value, depth + 1)
        if isinstance(value, Mapping):
            out: dict[str, Any] = {}
            for key, item in value.items():
                name = ctx.text(str(key))
                if name in out:  # two raw keys that render alike (control chars, pseudonyms): keep both
                    suffix = 2
                    while f"{name} ({suffix})" in out:
                        suffix += 1
                    name = f"{name} ({suffix})"
                out[name] = self.value(item, depth + 1)
            return out
        if isinstance(value, (list, tuple)):
            return [self.value(item, depth + 1) for item in value]
        if isinstance(value, (set, frozenset)):
            return [self.value(item, depth + 1) for item in sorted(value, key=str)]
        try:
            return ctx.text(str(value))
        except Exception:  # an object whose __str__ raises
            return None

    def message(self, message: Message | str | None) -> dict[str, Any] | None:
        ctx = self.ctx
        if message is None:
            return None
        if isinstance(message, str):
            return {"text": ctx.text(message), "key": None, "params": {}}
        if not isinstance(message, Message):
            return {"text": ctx.value(message), "key": None, "params": {}}
        params = message.params if isinstance(message.params, Mapping) else {}
        return {
            "text": ctx.msg(message),
            "key": ctx.text(message.key),
            "params": {ctx.text(str(k)): self.param(v) for k, v in params.items()},
        }

    def param(self, value: Any) -> Any:
        if isinstance(value, Entity):
            return self.ctx.ent(value)
        if isinstance(value, Message):
            return self.message(value)
        return self.value(value)

    def finding(self, finding: Finding) -> dict[str, Any]:
        ctx = self.ctx
        severity = severity_name(finding.severity)
        confidence = getattr(finding.confidence, "value", finding.confidence)
        score = (
            finding.score if isinstance(finding.score, (int, float)) and not isinstance(finding.score, bool) else None
        )
        return {
            "fingerprint": ctx.text(finding.fingerprint),
            "kind": ctx.text(finding.kind),
            "domain": ctx.text(finding.domain),
            "severity": ctx.text(severity),
            "confidence": ctx.text(confidence),
            "score": self.value(score),
            "tenant": ctx.text(finding.tenant) if finding.tenant is not None else None,
            "subject": ctx.subject(finding),
            "title": self.message(finding.title),
            "reasons": [self.message(r) for r in reasons_of(finding)],
            "evidence": self.value(finding.evidence),
            "recommendation": self.message(finding.recommendation),
            "related": [ctx.text(r) for r in _seq(finding.related)],
        }


def report_document(report: Report, *, lang: str = "en", redactor: Redactor | None = None) -> dict[str, Any]:
    """The JSON document for one report, as a plain dict (what :func:`render_json` serializes)."""
    ctx = prepare_context(report, lang, redactor)
    return build_document(ctx, report)


def build_document(ctx: RenderContext, report: Report) -> dict[str, Any]:
    """The JSON document for ``report`` rendered through an existing context (shared with the HTML embed)."""
    conv = _Jsonifier(ctx)
    basis = report.data_basis
    statuses = domain_statuses(report)
    reasons = incomplete_reasons(ctx, report, statuses)
    findings = order_findings(report.findings)
    by_severity = dict.fromkeys(SEVERITY_ORDER, 0)
    by_domain = dict.fromkeys(DOMAINS, 0)
    for finding in findings:
        by_severity[severity_name(finding.severity)] += 1
        domain = ctx.text(str(finding.domain), 60)
        by_domain[domain] = by_domain.get(domain, 0) + 1
    caveats = basis_caveats(ctx, report)
    return {
        "schema_version": SCHEMA_VERSION,
        "document": "hushwatch.report",
        "tool": {"name": "hushwatch", "version": ctx.text(report.tool_version)},
        "tenant": ctx.text(report.tenant),
        "generated_at": _iso(report.generated_at),
        "lang": ctx.lang,
        "redacted": ctx.redacted,
        "incomplete": bool(reasons),
        "notice": ctx.t("report.footer.readonly"),
        "data_basis": {
            "input_kind": ctx.text(basis.input_kind),
            "alerts_only": is_alerts_only(report),
            "profile": ctx.text(basis.profile),
            "sources": [ctx.text(s) for s in _seq(basis.sources)],
            "start": _iso(basis.start),
            "end": _iso(basis.end),
            "now": _iso(basis.now),
            "now_origin": ctx.text(basis.now_origin),
            "events": conv.value(basis.events),
            "malformed": conv.value(basis.malformed),
            "bad_timestamps": conv.value(basis.bad_timestamps),
            "future_timestamps": conv.value(basis.future_timestamps),
            "sampled": bool(basis.sampled),
            "truncated": bool(basis.truncated),
            "partial_failures": [conv.message(p) for p in _seq(basis.partial_failures)],
            "warnings": [conv.message(w) for w in _seq(basis.warnings)],
            "not_evaluated": [ctx.text(n) for n in _seq(basis.not_evaluated)],
            "complete": basis_complete(basis),
            "caveats": caveats,
            "incomplete_reasons": reasons,
        },
        "assessment": statuses,
        "summary": {"findings": len(findings), "by_severity": by_severity, "by_domain": by_domain},
        "sections": conv.value(report.sections),
        "findings": [conv.finding(f) for f in findings],
    }


def _dumps(document: Mapping[str, Any]) -> str:
    return json.dumps(document, sort_keys=True, ensure_ascii=False, indent=2, allow_nan=False) + "\n"


def render_json(report: Report, *, lang: str = "en", redactor: Redactor | None = None) -> str:
    """Render one report as deterministic, versioned JSON text."""
    return _dumps(report_document(report, lang=lang, redactor=redactor))


def render_json_many(
    reports: Sequence[Report],
    *,
    lang: str = "en",
    redactor: Redactor | Mapping[str, Redactor | None] | None = None,
) -> str:
    """Multi-tenant fleet summary: one row per tenant (statuses, finding counts, data completeness)."""
    base, rows = fleet_rows(reports, lang, redactor)
    generated = max((r.generated_at_iso for r in rows if r.generated_at_iso), default=None)
    document = {
        "schema_version": SCHEMA_VERSION,
        "document": "hushwatch.fleet",
        "tool": {"name": "hushwatch", "version": base.text(reports[0].tool_version) if reports else None},
        "generated_at": generated,
        "lang": base.lang,
        "notice": base.t("report.footer.readonly"),
        "tenants": [
            {
                "tenant": row.tenant,
                "generated_at": row.generated_at_iso,
                "assessment": row.statuses,
                "incomplete": row.incomplete,
                "events": row.events,
                "findings": {"critical": row.critical, "high": row.high, "total": row.total},
                "most_severe": (
                    {"title": row.worst_title, "severity": row.worst_severity, "fingerprint": row.worst_fingerprint}
                    if row.total
                    else None
                ),
            }
            for row in rows
        ],
    }
    return _dumps(document)
