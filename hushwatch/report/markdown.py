"""GitHub-flavoured Markdown report.

Every data-derived string goes through :func:`md_escape`: Markdown metacharacters (backslash, backtick,
asterisk, underscore, square brackets, pipe, tilde, dollar, hash) are backslash-escaped, ``<``/``>`` and
entity-like ``&`` become HTML entities, URLs are defanged (``http[:]//``, ``www[.]``) and so is ``@``
(``alice[@]corp.example``: no GFM e-mail autolink, no GitHub @mention that would notify someone). No link,
image, autolink, raw HTML, table break, heading, math block or emphasis can come from log content. Data never
starts a line, and a leading list marker (``-``, ``+``, ``1.``) is escaped, so no block structure (lists,
quotes, rules) can be injected either, not even inside a list item.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence

from ..models import DOMAINS, Report
from ..redact import Redactor
from .common import (
    Fact,
    FindingView,
    RenderContext,
    ReportView,
    build_view,
    fleet_footer,
    fleet_rows,
    prepare_context,
    sparkline_text,
)

__all__ = ["md_escape", "render_markdown", "render_markdown_many"]

_MD_CHARS = re.compile(r"[`*_\[\]|~$#]")
_ENTITY_LIKE = re.compile(r"&(?=#?[A-Za-z0-9]+;)")
_SCHEME = re.compile(r"(?i)\b(https?|ftps?|sftp|file|smb|ldaps?|wss?)://")
_WWW = re.compile(r"(?i)\bwww\.")
_CODE_SAFE = re.compile(r"^[A-Za-z0-9_.:\-]{1,80}$")
_AT = re.compile(r"@(?=[\w.+-])")
# What would open a block after a line prefix ("- ", "> "): a bullet ("- x", "+ x"), a rule ("---"), an ordered
# item ("1. x", "2) x"). "*" and "#" are always escaped; a negative number ("-5") or a version ("1.2") is left alone.
_LEADING_BLOCK = re.compile(r"^(?:([-+])(?=[\s-]|$)|(\d{1,9})([.)])(?=\s|$))")

_STATUS_ICON = {"ok": "✅", "warn": "⚠️", "fail": "❌", "not_assessed": "⬜"}
_SEVERITY_ICON = {"critical": "🟥", "high": "🟧", "medium": "🟨", "low": "🟦", "info": "⬜"}
_TONE_ICON = {"ok": "✅", "warn": "⚠️", "fail": "❌", "na": "⬜", "neutral": ""}
_LEVEL_ICON = {"warn": "⚠️ ", "fail": "❌ "}
_CELL = {"present": "●", "missing": "✖", "silent": "◌"}
_SPARK_POINTS = 30


def md_escape(text: str) -> str:
    """Escape display text (already sanitized: no newlines or control characters) for inline Markdown."""
    text = _SCHEME.sub(lambda m: m.group(1) + "[:]//", text)
    text = _WWW.sub(lambda m: m.group(0)[:3] + "[.]", text)
    text = _AT.sub("[@]", text)
    text = text.replace("\\", "\\\\")
    text = _MD_CHARS.sub(lambda m: "\\" + m.group(0), text)
    text = _ENTITY_LIKE.sub("&amp;", text)
    text = text.replace("<", "&lt;").replace(">", "&gt;")
    return _LEADING_BLOCK.sub(_escape_marker, text)


def _escape_marker(match: re.Match[str]) -> str:
    if match.group(1):
        return "\\" + match.group(1)
    return f"{match.group(2)}\\{match.group(3)}"


def _code(text: str) -> str:
    """Inline code only for identifier-like values (fingerprints, kinds); anything else is escaped text."""
    return f"`{text}`" if _CODE_SAFE.match(text) else md_escape(text)


def _row(cells: Iterable[str]) -> str:
    return "| " + " | ".join(c if c else " " for c in cells) + " |"


def _table(headers: Sequence[str], rows: Iterable[Sequence[str]], numeric: Sequence[int] = ()) -> list[str]:
    align = ["---:" if i in numeric else "---" for i in range(len(headers))]
    out = [_row(md_escape(h) for h in headers), "|" + "|".join(align) + "|"]
    out.extend(_row(r) for r in rows)
    return out


def _spark(values: Sequence[float]) -> str:
    return sparkline_text(values[-_SPARK_POINTS:]) if values else ""


class _MarkdownWriter:
    def __init__(self, view: ReportView, ctx: RenderContext) -> None:
        self.v = view
        self.ctx = ctx
        self.lines: list[str] = []
        self.section = 0

    # -- helpers -------------------------------------------------------------------------------------------------
    def t(self, key: str, **params: object) -> str:
        """An escaped label; int params are localized."""
        values = {k: self.ctx.num(v) if isinstance(v, int) else v for k, v in params.items()}
        return md_escape(self.ctx.t(key, **values))

    def add(self, *lines: str) -> None:
        self.lines.extend(lines)

    def heading(self, key: str) -> None:
        self.section += 1
        self.add("", f"## {self.section}. {self.t(key)}", "")

    def sub(self, key: str) -> None:
        self.add(f"### {self.t(key)}", "")

    def note(self, key: str, **params: object) -> None:
        self.add(f"_{self.t(key, **params)}_", "")

    def status_line(self, status: str) -> None:
        self.add(f"{_STATUS_ICON.get(status, '')} **{self.t('report.col.status')}:** {self.t('status.' + status)}", "")

    def facts(self, facts: Sequence[Fact]) -> None:
        if not facts:
            return
        rows = []
        for fact in facts:
            parts = [md_escape(fact.value)] if fact.value else []
            if fact.items:
                shown = [md_escape(item) for item in fact.items]
                if fact.more:
                    shown.append(self.t("report.more_items", n=fact.more))
                parts.append("; ".join(shown))
            rows.append([f"**{md_escape(fact.label)}**", _LEVEL_ICON.get(fact.level, "") + ": ".join(parts)])
        self.add(*_table([self.ctx.t("report.col.item"), self.ctx.t("report.col.value")], rows), "")

    # -- document ------------------------------------------------------------------------------------------------
    def render(self) -> str:
        v = self.v
        self.add(f"# hushwatch · {md_escape(v.title)}", "")
        redaction = "report.redaction.on" if v.redacted else "report.redaction.off"
        meta = [
            f"**{self.t('report.tenant')}:** {md_escape(v.tenant)}",
            f"**{self.t('report.generated')}:** {md_escape(v.generated_at)}",
        ]
        if v.period:
            meta.append(f"**{self.t('report.period')}:** {md_escape(v.period)}")
        meta.append(f"**{self.t('report.redaction')}:** {self.t(redaction)}")
        self.add(" · ".join(meta), "", f"_{md_escape(v.tagline)}_", "")
        self._basis()
        self._status()
        self._numbers()
        if not v.audit:  # a ruleset audit has no events: only the tuning audit applies
            self._noise()
            self._silence()
            self._coverage()
            self._pipeline()
        self._tuning()
        self._others()
        self._findings()
        self.add("", "---", "")
        self.add(*(f"<sub>{md_escape(line)}</sub><br>" for line in v.footer))
        return "\n".join(self.lines).rstrip() + "\n"

    def _basis(self) -> None:
        basis = self.v.basis
        if not basis.complete:
            title = self.t("report.basis.incomplete")
            self.add("> [!CAUTION]", f"> **{title}.** {self.t('report.basis.incomplete_body')}", ">")
            self.add(*(f"> - {md_escape(r)}" for r in basis.reasons), "")
        for caveat in basis.caveats:
            self.add("> [!WARNING]", f"> {md_escape(caveat)}", "")
        self.heading("report.section.basis")
        if basis.complete:
            self.add(f"✅ **{self.t('report.basis.complete')}.** {self.t('report.basis.complete_body')}", "")
        self.facts(basis.facts)

    def _status(self) -> None:
        self.heading("report.section.status")
        headers = [self.ctx.t(k) for k in ("report.col.domain", "report.col.status", "report.col.findings")]
        rows = [
            [
                md_escape(c.label),
                f"{_STATUS_ICON.get(c.status, '')} {md_escape(c.status_label)}",
                " · ".join(md_escape(part) for part in (c.detail, *c.notes)),
            ]
            for c in self.v.cards
        ]
        self.add(*_table(headers, rows), "")

    def _numbers(self) -> None:
        self.heading("report.section.numbers")
        headers = [self.ctx.t(k) for k in ("report.col.metric", "report.col.value", "report.col.note")]
        rows = [
            [md_escape(n.label), f"{_TONE_ICON.get(n.tone, '')} **{md_escape(n.value)}**".strip(), md_escape(n.hint)]
            for n in self.v.numbers
        ]
        self.add(*_table(headers, rows, numeric=(1,)), "")

    def _not_assessed(self) -> None:
        self.add(f"⬜ _{self.t('report.not_assessed.section')}_", "")

    def _noise(self) -> None:
        n = self.v.noise
        self.heading("report.section.noise")
        self.status_line(n.status)
        if not n.assessed:
            self._not_assessed()
            return
        if n.summary:
            self.add(f"**{md_escape(n.summary)}**", "")
        self.sub("report.noise.top_rules")
        if n.rules:
            keys: tuple[str, ...] = (
                "rule",
                "description",
                "level",
                "per_day",
                "analyst_facing",
                "share",
                "clusters",
                "verdict",
                "trend",
            )
            rows = [
                [
                    _code(r.rule_id),
                    md_escape(r.description),
                    md_escape(r.level),
                    md_escape(r.per_day),
                    md_escape(r.analyst_facing),
                    md_escape(r.share),
                    md_escape(r.clusters),
                    md_escape(r.verdict_label),
                    _spark(r.daily),
                ]
                for r in n.rules
            ]
            self.add(*_table([self.ctx.t("report.col." + k) for k in keys], rows, numeric=(2, 3, 4, 5, 6)))
            if n.rules_more:
                self.add("", f"_{self.t('report.more_rows', n=n.rules_more)}_")
            self.add("")
        else:
            self.note("report.noise.no_rules")
        self.sub("report.noise.suggestions")
        if n.tune:
            keys = (
                "suggestion",
                "scope",
                "hidden_per_day",
                "share_of_rule",
                "af_hidden",
                "agents",
                "expires",
                "review",
            )
            rows = []
            for s in n.tune:
                if s.review_required:
                    review = f"⚠️ **{self.t('report.noise.review_required')}**"
                    if s.dependents:
                        review += " " + md_escape(self.ctx.t("report.noise.review_hint", rules=s.dependents))
                else:
                    review = self.t("report.noise.ready")
                rows.append(
                    [
                        md_escape(s.title),
                        md_escape(s.scope),
                        md_escape(s.hidden_per_day),
                        md_escape(s.share_of_rule),
                        md_escape(s.af_hidden),
                        md_escape(s.agents),
                        md_escape(s.expires),
                        review,
                    ]
                )
            self.add(*_table([self.ctx.t("report.col." + k) for k in keys], rows, numeric=(2, 3, 4)), "")
        else:
            self.note("report.noise.no_suggestions")
        self.sub("report.noise.investigate")
        self.note("report.noise.investigate_hint")
        if n.investigate:
            for item in n.investigate:
                icon = _SEVERITY_ICON.get(item.severity, "")
                self.add(f"- {icon} **{md_escape(item.verdict_label)}** — {md_escape(item.title)}")
                self.add(*(f"  - {md_escape(r)}" for r in item.reasons))
            self.add("")
        else:
            self.note("report.noise.none_investigate")
        if n.index_volume:
            self.sub("report.noise.index_volume")
            self.note("report.noise.index_volume_hint")
            for item in n.index_volume:
                self.add(f"- {_SEVERITY_ICON.get(item.severity, '')} {md_escape(item.title)}")
                self.add(*(f"  - {md_escape(r)}" for r in item.reasons[:3]))
            self.add("")
        if n.time_saved:
            self.add(f"**{self.t('report.noise.time_saved')}:** {md_escape(n.time_saved)}  ")
            self.note("report.noise.time_saved_hint")
        if n.suppressions_file:
            self.add(f"**{self.t('report.noise.suppressions_file')}:** {md_escape(n.suppressions_file)}", "")
        if n.extra:
            self.sub("report.details")
            self.facts(n.extra)

    def _silence(self) -> None:
        s = self.v.silence
        self.heading("report.section.silence")
        self.status_line(s.status)
        if not s.assessed:
            self._not_assessed()
            return
        if s.counts:
            chips = " · ".join(
                f"{md_escape(label)}: **{md_escape(self.ctx.num(count))}**" for _, label, count in s.counts
            )
            self.add(f"**{self.t('report.silence.counts')}:** {chips}", "")
        if s.monitorability:
            self.add(f"**{self.t('report.silence.monitorability')}:** {md_escape(s.monitorability)}", "")
        if s.alpha:
            self.add(f"_{md_escape(s.alpha)}_", "")
        self.sub("report.silence.sources")
        if s.sources:
            keys: tuple[str, ...] = (
                "source",
                "source_level",
                "status",
                "last_seen",
                "observed",
                "expected",
                "p",
                "tier",
                "duty",
                "trend",
            )
            rows = [
                [
                    md_escape(r.key),
                    md_escape(r.level_label),
                    f"**{md_escape(r.status_label)}**",
                    md_escape(r.last_seen + (f" ({r.silent_for})" if r.silent_for else "")),
                    md_escape(r.observed),
                    md_escape(r.expected),
                    md_escape(r.p),
                    md_escape(r.tier_label),
                    md_escape(r.duty_label),
                    _spark(r.daily),
                ]
                for r in s.sources
            ]
            self.add(*_table([self.ctx.t("report.col." + k) for k in keys], rows, numeric=(4, 5, 6)))
            if s.sources_more:
                self.add("", f"_{self.t('report.more_rows', n=s.sources_more)}_")
            self.add("")
        else:
            self.note("report.silence.no_sources")
        if s.extra:
            self.sub("report.details")
            self.facts(s.extra)

    def _coverage(self) -> None:
        c = self.v.coverage
        self.heading("report.section.coverage")
        self.status_line(c.status)
        if not c.assessed:
            self._not_assessed()
            return
        if c.platforms:
            self.sub("report.coverage.platforms")
            self.facts(c.platforms)
        if c.expected:
            self.add(f"**{self.t('report.coverage.expected')}:** " + ", ".join(md_escape(e) for e in c.expected), "")
        if c.expected_table is not None:
            self.sub("report.coverage.expected")
            rows = [[md_escape(cell) for cell in row] for row in c.expected_table.rows]
            self.add(*_table(c.expected_table.columns, rows))
            if c.expected_table.more:
                self.add("", f"_{self.t('report.more_rows', n=c.expected_table.more)}_")
            self.add("")
        self.sub("report.coverage.matrix")
        if c.rows and c.columns:
            legend = " · ".join(
                f"{_CELL[k]} {self.t('report.coverage.' + k)}" for k in ("present", "missing", "silent")
            )
            self.add(f"_{self.t('report.coverage.legend')}:_ {legend}", "")
            headers = [self.ctx.t("report.col.agent"), self.ctx.t("report.col.platform"), *c.columns]
            rows = [
                [
                    md_escape(r.agent + (f" ({r.tier_label})" if r.tier_label else "")),
                    md_escape(r.platform),
                    *[
                        f"{_CELL[cell]} {self.t('report.coverage.' + cell)}" if cell in _CELL else ""
                        for cell in r.cells
                    ],
                ]
                for r in c.rows
            ]
            self.add(*_table(headers, rows))
            if c.rows_more:
                self.add("", f"_{self.t('report.more_rows', n=c.rows_more)}_")
            if c.columns_more:
                self.add("", f"_{self.t('report.coverage.more_cols', n=c.columns_more)}_")
            self.add("")
        else:
            self.note("report.coverage.no_matrix")
        if c.extra:
            self.sub("report.details")
            self.facts(c.extra)

    def _pipeline(self) -> None:
        p = self.v.pipeline
        self.heading("report.section.pipeline")
        self.status_line(p.status)
        if not p.assessed:
            self._not_assessed()
            return
        if p.agents:
            self.sub("report.pipeline.agents")
            self.facts(p.agents)
        if p.checks:
            self.sub("report.pipeline.checks")
            headers = [self.ctx.t(k) for k in ("report.col.check", "report.col.status", "report.col.detail")]
            rows = [
                [
                    md_escape(c.name),
                    f"{_STATUS_ICON.get(c.status or '', '')} {md_escape(c.status_label)}".strip(),
                    md_escape(c.detail),
                ]
                for c in p.checks
            ]
            self.add(*_table(headers, rows), "")
        if p.extra:
            self.sub("report.details")
            self.facts(p.extra)
        if not (p.agents or p.checks or p.extra):
            self.note("report.no_details")

    def _tuning(self) -> None:
        tv = self.v.tuning
        self.heading("report.section.tuning")
        self.status_line(tv.status)
        if not tv.assessed:
            self._not_assessed()
            return
        self.facts([*tv.facts, *tv.extra])
        if not (tv.facts or tv.extra):
            self.note("report.no_details")

    def _others(self) -> None:
        if not self.v.others:
            return
        self.heading("report.section.other")
        for name, facts in self.v.others:
            self.add(f"### {md_escape(name)}", "")
            self.facts(facts)

    def _findings(self) -> None:
        self.heading("report.section.findings")
        if not self.v.groups:
            self.note("report.findings.none_incomplete" if self.v.incomplete else "report.findings.none")
            return
        counts = " · ".join(
            f"{_SEVERITY_ICON[s]} {self.t('severity.' + s)}: **{md_escape(self.ctx.num(n))}**"
            for s, n in self.v.severity_counts.items()
            if n
        )
        self.add(counts, "")
        for group in self.v.groups:
            self.add(f"### {md_escape(group.label)} ({md_escape(self.ctx.num(len(group.findings)))})", "")
            for finding in group.findings:
                self._finding(finding)

    def _finding(self, f: FindingView) -> None:
        icon = _SEVERITY_ICON.get(f.severity, "")
        self.add(f"#### {icon} {md_escape(f.severity_label.upper())} · {md_escape(f.title)}", "")
        meta = [
            f"**{self.t('report.finding.kind')}:** {_code(f.kind)}",
            md_escape(f.confidence_label),
            f"**{self.t('report.finding.fingerprint')}:** {_code(f.fingerprint)}",
        ]
        if f.review_required:
            meta.append(f"⚠️ **{self.t('report.noise.review_required')}**")
        self.add("- " + " · ".join(meta))
        self.add(f"- **{self.t('report.finding.subject')}:** {md_escape(f.subject)}")
        if f.reasons:
            self.add(f"- **{self.t('report.finding.why')}:**")
            self.add(*(f"  - {md_escape(r)}" for r in f.reasons))
        if f.evidence:
            self.add(f"- **{self.t('report.finding.evidence')}:**")
            for row in f.evidence:
                spark = f" `{_spark(row.series)}`" if row.series else ""
                self.add(f"  - {md_escape(row.label)}: {md_escape(row.value)}{spark}")
        if f.recommendation:
            self.add(f"- **{self.t('report.finding.recommendation')}:** {md_escape(f.recommendation)}")
        if f.explained:
            self.add(f"- **{self.t('report.finding.explained')}:**")
            self.add(*(f"  - {md_escape(item)}" for item in f.explained))
        self.add("")


def render_markdown(report: Report, *, lang: str = "en", redactor: Redactor | None = None) -> str:
    """Render one report as GitHub-flavoured Markdown."""
    ctx = prepare_context(report, lang, redactor)
    return _MarkdownWriter(build_view(ctx, report), ctx).render()


def render_markdown_many(
    reports: Sequence[Report],
    *,
    lang: str = "en",
    redactor: Redactor | Mapping[str, Redactor | None] | None = None,
) -> str:
    """Multi-tenant fleet summary as a Markdown table (one row per tenant, worst first)."""
    ctx, rows = fleet_rows(reports, lang, redactor)
    lines = [f"# hushwatch · {md_escape(ctx.t('report.fleet.title'))}", ""]
    if not rows:
        lines += [f"_{md_escape(ctx.t('report.fleet.empty'))}_", ""]
    else:
        count = md_escape(ctx.t("report.fleet.tenants", n=ctx.num(len(rows))))
        lines += [f"**{count}** · {md_escape(ctx.t('report.fleet.order'))}", ""]
        headers = [
            ctx.t("report.col.tenant"),
            *[ctx.t(f"domain.{d}") for d in DOMAINS],
            ctx.t("report.col.critical"),
            ctx.t("report.col.high"),
            ctx.t("report.col.findings"),
            ctx.t("report.col.events"),
            ctx.t("report.col.data"),
            ctx.t("report.col.worst"),
        ]
        table_rows = []
        for row in rows:
            data_key = "report.basis.incomplete" if row.incomplete else "report.basis.complete"
            data = ("❌ " if row.incomplete else "✅ ") + md_escape(ctx.t(data_key))
            worst = f"{_SEVERITY_ICON.get(row.worst_severity, '')} {md_escape(row.worst_title)}".strip()
            statuses = [
                f"{_STATUS_ICON.get(row.statuses[d], '')} {md_escape(ctx.t('status.' + row.statuses[d]))}"
                for d in DOMAINS
            ]
            counts = [md_escape(ctx.num(x)) for x in (row.critical, row.high, row.total, row.events)]
            table_rows.append([f"**{md_escape(row.tenant)}**", *statuses, *counts, data, worst])
        lines += _table(headers, table_rows, numeric=tuple(range(len(DOMAINS) + 1, len(DOMAINS) + 5)))
        lines.append("")
    lines += ["---", ""]
    lines += [f"<sub>{md_escape(line)}</sub><br>" for line in fleet_footer(ctx, reports)]
    return "\n".join(lines).rstrip() + "\n"
