"""Terminal report with rich.

Safety: every string handed to rich is a :class:`rich.text.Text` (never a ``str``, which rich would parse as
markup and could raise ``MarkupError``), built from context text that is already stripped of C0/C1 control
characters (so no ANSI escape from log content reaches the terminal). On consoles whose encoding is not UTF-8,
symbols fall back to ASCII and data is transliterated with ``?`` instead of raising ``UnicodeEncodeError``.

The layout adapts to ``console.width``: narrow terminals drop the less important columns.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from rich import box
from rich.console import Console, Group, RenderableType
from rich.padding import Padding
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

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

__all__ = ["print_console", "print_console_many"]

_STATUS_STYLE = {"ok": "green", "warn": "yellow", "fail": "bold red", "not_assessed": "dim"}
_SEVERITY_STYLE = {
    "critical": "bold white on red",
    "high": "bold red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}
_LEVEL_STYLE = {"warn": "yellow", "fail": "bold red", "muted": "dim", "normal": ""}
_TONE_STYLE = {"ok": "green", "warn": "yellow", "fail": "bold red", "na": "dim", "neutral": "bold"}
_VERDICT_STYLE = {
    "tune": "green",
    "investigate": "yellow",
    "fix_at_source": "cyan",
    "aggregate": "cyan",
    "do_not_tune": "magenta",
    "watch": "dim",
    "learning": "dim",
}
_SOURCE_STYLE = {
    "tampering": "bold white on red",
    "silent": "bold red",
    "drop": "red",
    "decay": "yellow",
    "rule_dark": "yellow",
    "field_lost": "yellow",
    "unmonitorable": "yellow",
    "learning": "dim",
    "explained": "dim",
    "ok": "green",
}
_CELL_STYLE = {"present": "green", "missing": "bold red", "silent": "yellow", "na": "dim"}

_UNICODE_SYMBOLS = {
    "ok": "✔",
    "warn": "▲",
    "fail": "✖",
    "not_assessed": "○",
    "present": "●",
    "missing": "✖",
    "silent": "◌",
    "na": "·",
    "bullet": "•",
    "arrow": "→",
    "sep": "·",
}
_ASCII_SYMBOLS = {
    "ok": "OK",
    "warn": "!",
    "fail": "X",
    "not_assessed": "-",
    "present": "+",
    "missing": "X",
    "silent": "o",
    "na": ".",
    "bullet": "*",
    "arrow": "->",
    "sep": "|",
}
_MAX_FINDINGS = 60


class _ConsoleWriter:
    def __init__(self, console: Console, ctx: RenderContext, verbose: bool) -> None:
        self.console = console
        self.ctx = ctx
        self.verbose = verbose
        encoding = (console.encoding or "utf-8").lower().replace("_", "-")
        self.utf = encoding.startswith("utf")
        self.encoding = encoding
        self.sym = _UNICODE_SYMBOLS if self.utf else _ASCII_SYMBOLS
        self.width = max(40, console.width)

    # -- text helpers --------------------------------------------------------------------------------------------
    def txt(self, value: str, style: str = "") -> Text:
        """Plain (never markup-parsed) text, encodable on the target console."""
        if not self.utf:
            try:
                value = value.encode(self.encoding, "replace").decode(self.encoding)
            except LookupError:
                value = value.encode("ascii", "replace").decode("ascii")
        return Text(value, style=style)

    def label(self, key: str, style: str = "", **params: object) -> Text:
        values = {k: self.ctx.num(v) if isinstance(v, int) else v for k, v in params.items()}
        return self.txt(self.ctx.t(key, **values), style)

    def status(self, status: str) -> Text:
        symbol = self.sym.get(status, "")
        return self.txt(f"{symbol} {self.ctx.t('status.' + status)}".strip(), _STATUS_STYLE.get(status, ""))

    def spark(self, values: Sequence[float], points: int = 14) -> Text:
        if not values:
            return Text("")
        if self.utf:
            return Text(sparkline_text(values[-points:]), style="cyan")
        return Text(sparkline_text(values[-points:], zero=".", blocks="_.-=#"), style="cyan")

    def print(self, *renderables: RenderableType) -> None:
        """Print each renderable on its own line (rich would join several with a space)."""
        for renderable in renderables:
            self.console.print(renderable)

    def rule(self, key: str) -> None:
        self.console.print()
        self.console.rule(self.label(key, "bold"), style="cyan", align="left")

    def table(self, *headers: tuple[str, str], title: Text | None = None) -> Table:
        table = Table(
            box=box.SIMPLE_HEAD,
            show_edge=False,
            pad_edge=False,
            title=title,
            title_justify="left",
            header_style="bold",
            expand=False,
        )
        for key, justify in headers:
            if key == "report.col.trend":
                table.add_column(self.label(key), no_wrap=True, overflow="crop")
            elif key in ("report.col.source", "report.col.rule"):
                table.add_column(self.label(key), overflow="fold", min_width=8 if key == "report.col.rule" else 22)
            else:
                table.add_column(self.label(key), justify="right" if justify == "r" else "left", overflow="fold")
        return table

    def facts_table(self, facts: Sequence[Fact]) -> Table:
        grid = Table.grid(padding=(0, 2))
        grid.add_column(style="bold", no_wrap=True)
        grid.add_column(overflow="fold")
        for fact in facts:
            value = self.txt(fact.value, _LEVEL_STYLE.get(fact.level, ""))
            if fact.items:
                lines = [f"{self.sym['bullet']} {item}" for item in fact.items]
                if fact.more:
                    lines.append(self.ctx.t("report.more_items", n=self.ctx.num(fact.more)))
                value = (
                    Text("\n").join([value, *(self.txt(line) for line in lines)])
                    if fact.value
                    else Text("\n").join(self.txt(line) for line in lines)
                )
            grid.add_row(self.txt(fact.label), value)
        return grid

    # -- document ------------------------------------------------------------------------------------------------
    def render(self, v: ReportView) -> None:
        header = Text.assemble(
            self.txt("hushwatch", "bold cyan"),
            self.txt(f" {self.sym['sep']} "),
            self.txt(v.title, "bold"),
            self.txt(f"  {self.sym['sep']}  "),
            self.txt(v.tenant, "bold"),
        )
        redaction = "report.redaction.on" if v.redacted else "report.redaction.off"
        meta = self.txt(
            f"{self.ctx.t('report.generated')}: {v.generated_at}   {self.ctx.t('report.period')}: {v.period}   "
            f"{self.ctx.t('report.redaction')}: {self.ctx.t(redaction)}",
            "dim",
        )
        self.print(header, meta)
        self._basis(v)
        self._status(v)
        self._numbers(v)
        self._noise(v)
        self._silence(v)
        self._coverage(v)
        self._pipeline(v)
        self._tuning(v)
        self._others(v)
        self._findings(v)
        self.print()
        for line in v.footer:
            self.print(self.txt(line, "dim"))

    def _basis(self, v: ReportView) -> None:
        basis = v.basis
        parts: list[RenderableType] = []
        if not basis.complete:
            parts.append(
                self.txt(f" {self.sym['fail']} {self.ctx.t('report.basis.incomplete').upper()} ", "bold white on red")
            )
            parts.append(self.label("report.basis.incomplete_body", "bold red"))
            parts.extend(self.txt(f"  {self.sym['bullet']} {r}", "red") for r in basis.reasons)
            parts.append(Text(""))
        for caveat in basis.caveats:
            parts.append(self.txt(f"{self.sym['warn']} {caveat}", "yellow"))
        if basis.caveats:
            parts.append(Text(""))
        parts.append(self.facts_table(basis.facts))
        title = self.label("report.section.basis", "bold")
        border = "red" if not basis.complete else ("yellow" if basis.caveats else "cyan")
        self.print(Panel(Group(*parts), title=title, title_align="left", border_style=border, box=box.ROUNDED))

    def _status(self, v: ReportView) -> None:
        self.rule("report.section.status")
        table = self.table(("report.col.domain", "l"), ("report.col.status", "l"), ("report.col.findings", "l"))
        for card in v.cards:
            table.add_row(self.txt(card.label, "bold"), self.status(card.status), self.txt(card.detail))
        self.print(table)

    def _numbers(self, v: ReportView) -> None:
        self.rule("report.section.numbers")
        table = self.table(("report.col.metric", "l"), ("report.col.value", "r"), ("report.col.note", "l"))
        for number in v.numbers:
            table.add_row(
                self.txt(number.label),
                self.txt(number.value, _TONE_STYLE.get(number.tone, "")),
                self.txt(number.hint, "dim"),
            )
        self.print(table)

    def _section_status(self, status: str, assessed: bool) -> bool:
        self.print(Text.assemble(self.label("report.col.status", "bold"), Text(": "), self.status(status)))
        if not assessed:
            self.print(self.label("report.not_assessed.section", "dim italic"))
        return assessed

    def _noise(self, v: ReportView) -> None:
        n = v.noise
        self.rule("report.section.noise")
        if not self._section_status(n.status, n.assessed):
            return
        if n.summary:
            self.print(self.txt(n.summary))
        if n.rules:
            wide = self.width >= 120
            medium = self.width >= 90
            cols: list[tuple[str, str]] = [("report.col.rule", "l")]
            if medium:
                cols.append(("report.col.description", "l"))
            cols += [("report.col.level", "r"), ("report.col.per_day", "r")]
            if wide:
                cols += [("report.col.analyst_facing", "r"), ("report.col.clusters", "r")]
            cols += [("report.col.share", "r"), ("report.col.verdict", "l")]
            if medium:
                cols.append(("report.col.trend", "l"))
            table = self.table(*cols, title=self.label("report.noise.top_rules", "bold"))
            for r in n.rules:
                row: list[RenderableType] = [self.txt(r.rule_id, "bold")]
                if medium:
                    row.append(self.txt(self.ctx.cut(r.description, 60 if not wide else 90)))
                row += [self.txt(r.level), self.txt(r.per_day)]
                if wide:
                    row += [self.txt(r.analyst_facing), self.txt(r.clusters)]
                row += [self.txt(r.share), self.txt(r.verdict_label, _VERDICT_STYLE.get(r.verdict, ""))]
                if medium:
                    row.append(self.spark(r.daily))
                table.add_row(*row)
            self.print(table)
            if n.rules_more:
                self.print(self.label("report.more_rows", "dim", n=n.rules_more))
        else:
            self.print(self.label("report.noise.no_rules", "dim"))
        self.print(Text(""), self.label("report.noise.suggestions", "bold"))
        if n.tune:
            for s in n.tune:
                badge = (
                    self.txt(
                        f" {self.sym['warn']} {self.ctx.t('report.noise.review_required')} ", "bold black on yellow"
                    )
                    if s.review_required
                    else self.txt(f" {self.ctx.t('report.noise.ready')} ", "bold black on green")
                )
                self.print(
                    Text.assemble(self.txt(f"{self.sym['bullet']} "), self.txt(s.title, "bold"), Text(" "), badge)
                )
                pairs = (
                    ("report.col.scope", s.scope),
                    ("report.col.hidden_per_day", s.hidden_per_day),
                    ("report.col.share_of_rule", s.share_of_rule),
                    ("report.col.af_hidden", s.af_hidden),
                    ("report.col.agents", s.agents),
                    ("report.col.expires", s.expires),
                )
                detail = "   ".join(f"{self.ctx.t(key)}: {value}" for key, value in pairs)
                self.print(Padding(self.txt(detail, "dim"), (0, 0, 0, 4)))
                if s.dependents:
                    hint = self.ctx.t("report.noise.review_hint", rules=s.dependents)
                    self.print(Padding(self.txt(hint, "yellow"), (0, 0, 0, 4)))
        else:
            self.print(self.label("report.noise.no_suggestions", "dim"))
        self.print(Text(""), self.label("report.noise.investigate", "bold"))
        self.print(self.label("report.noise.investigate_hint", "dim italic"))
        if n.investigate:
            for item in n.investigate:
                self.print(
                    Text.assemble(
                        self.txt(f"{self.sym['bullet']} "),
                        self.txt(f"[{item.verdict_label}]", _VERDICT_STYLE.get(item.verdict, "")),
                        Text(" "),
                        self.txt(item.title),
                    )
                )
                limit = None if self.verbose else 3
                for reason in item.reasons[:limit]:
                    self.print(Padding(self.txt(f"- {reason}", "dim"), (0, 0, 0, 4)))
        else:
            self.print(self.label("report.noise.none_investigate", "dim"))
        if n.time_saved:
            self.print(
                Text(""),
                Text.assemble(self.label("report.noise.time_saved", "bold"), Text(": "), self.txt(n.time_saved)),
                self.label("report.noise.time_saved_hint", "dim italic"),
            )
        if n.suppressions_file:
            self.print(
                Text.assemble(
                    self.label("report.noise.suppressions_file", "bold"), Text(": "), self.txt(n.suppressions_file)
                )
            )
        if n.extra and self.verbose:
            self.print(self.facts_table(n.extra))

    def _silence(self, v: ReportView) -> None:
        s = v.silence
        self.rule("report.section.silence")
        if not self._section_status(s.status, s.assessed):
            return
        if s.counts:
            parts: list[Text] = [self.label("report.silence.counts", "bold"), Text(": ")]
            for i, (key, label, count) in enumerate(s.counts):
                if i:
                    parts.append(Text("  "))
                parts.append(self.txt(f"{label} {self.ctx.num(count)}", _SOURCE_STYLE.get(key, "") if count else "dim"))
            self.print(Text.assemble(*parts))
        if s.monitorability:
            self.print(
                Text.assemble(
                    self.label("report.silence.monitorability", "bold"), Text(": "), self.txt(s.monitorability)
                )
            )
        if s.alpha:
            self.print(self.txt(s.alpha, "dim"))
        if s.sources:
            wide = self.width >= 120
            medium = self.width >= 90
            cols: list[tuple[str, str]] = [
                ("report.col.source", "l"),
                ("report.col.status", "l"),
                ("report.col.last_seen", "l"),
            ]
            if wide:
                cols += [("report.col.source_level", "l"), ("report.col.observed", "r"), ("report.col.expected", "r")]
            if medium:
                cols += [("report.col.tier", "l"), ("report.col.trend", "l")]
            table = self.table(*cols, title=self.label("report.silence.sources", "bold"))
            for r in s.sources:
                last = r.last_seen + (f" ({r.silent_for})" if r.silent_for else "")
                row: list[RenderableType] = [
                    self.txt(r.key, "bold"),
                    self.txt(r.status_label, _SOURCE_STYLE.get(r.status, "")),
                    self.txt(last),
                ]
                if wide:
                    row += [self.txt(r.level_label), self.txt(r.observed), self.txt(r.expected)]
                if medium:
                    row += [self.txt(r.tier_label), self.spark(r.daily)]
                table.add_row(*row)
            self.print(table)
            if s.sources_more:
                self.print(self.label("report.more_rows", "dim", n=s.sources_more))
        else:
            self.print(self.label("report.silence.no_sources", "dim"))
        if s.extra and self.verbose:
            self.print(self.facts_table(s.extra))

    def _coverage(self, v: ReportView) -> None:
        c = v.coverage
        self.rule("report.section.coverage")
        if not self._section_status(c.status, c.assessed):
            return
        if c.platforms:
            self.print(self.facts_table(c.platforms))
        if c.expected_table is not None:
            table = Table(
                box=box.SIMPLE_HEAD,
                show_edge=False,
                pad_edge=False,
                header_style="bold",
                title=self.label("report.coverage.expected", "bold"),
                title_justify="left",
            )
            for column in c.expected_table.columns:
                table.add_column(self.txt(column), overflow="fold")
            for record in c.expected_table.rows:
                table.add_row(*(self.txt(cell) for cell in record))
            self.print(table)
            if c.expected_table.more:
                self.print(self.label("report.more_rows", "dim", n=c.expected_table.more))
        if c.rows and c.columns:
            fit = max(1, (self.width - 34) // 12)
            columns = c.columns[:fit]
            table = Table(
                box=box.SIMPLE_HEAD,
                show_edge=False,
                pad_edge=False,
                header_style="bold",
                title=self.label("report.coverage.matrix", "bold"),
                title_justify="left",
            )
            table.add_column(self.label("report.col.agent"), overflow="fold")
            table.add_column(self.label("report.col.platform"), overflow="fold")
            for name in columns:
                table.add_column(self.txt(self.ctx.cut(name, 11)), justify="center", overflow="fold")
            for row in c.rows:
                cells = [self.txt(self.sym[cell], _CELL_STYLE[cell]) for cell in row.cells[: len(columns)]]
                table.add_row(self.txt(row.agent, "bold"), self.txt(row.platform), *cells)
            self.print(table)
            legend = "   ".join(
                f"{self.sym[k]} {self.ctx.t('report.coverage.' + k)}" for k in ("present", "missing", "silent")
            )
            self.print(self.txt(legend, "dim"))
            hidden = c.columns_more + len(c.columns) - len(columns)
            if hidden:
                self.print(self.label("report.coverage.more_cols", "dim", n=hidden))
            if c.rows_more:
                self.print(self.label("report.more_rows", "dim", n=c.rows_more))
        else:
            self.print(self.label("report.coverage.no_matrix", "dim"))
        if c.extra and self.verbose:
            self.print(self.facts_table(c.extra))

    def _pipeline(self, v: ReportView) -> None:
        p = v.pipeline
        self.rule("report.section.pipeline")
        if not self._section_status(p.status, p.assessed):
            return
        if p.agents:
            self.print(self.facts_table(p.agents))
        if p.checks:
            table = self.table(("report.col.check", "l"), ("report.col.status", "l"), ("report.col.detail", "l"))
            for check in p.checks:
                status = self.status(check.status) if check.status else self.txt(check.status_label)
                table.add_row(self.txt(check.name), status, self.txt(self.ctx.cut(check.detail, 200), "dim"))
            self.print(table)
        if p.extra:
            self.print(self.facts_table(p.extra))

    def _tuning(self, v: ReportView) -> None:
        tv = v.tuning
        self.rule("report.section.tuning")
        if not self._section_status(tv.status, tv.assessed):
            return
        if tv.facts or tv.extra:
            self.print(self.facts_table([*tv.facts, *tv.extra]))

    def _others(self, v: ReportView) -> None:
        if not v.others:
            return
        self.rule("report.section.other")
        for name, facts in v.others:
            self.print(self.txt(name, "bold"))
            self.print(self.facts_table(facts))

    def _findings(self, v: ReportView) -> None:
        self.rule("report.section.findings")
        if not v.groups:
            key = "report.findings.none_incomplete" if v.incomplete else "report.findings.none"
            self.print(self.label(key, "bold red" if v.incomplete else "green"))
            return
        shown = 0
        for group in v.groups:  # without --verbose the view holds only the most severe findings of the report
            self.print(Text(""), self.txt(f"{group.label} ({self.ctx.num(group.count)})", "bold underline"))
            for finding in group.findings:
                self._finding(finding)
                shown += 1
        if v.total_findings > shown:
            self.print(Text(""), self.label("report.finding.more", "yellow", n=v.total_findings - shown))

    def _finding(self, f: FindingView) -> None:
        badge = self.txt(f" {f.severity_label.upper()} ", _SEVERITY_STYLE.get(f.severity, ""))
        head = Text.assemble(badge, Text(" "), self.txt(f.title, "bold"))
        if f.review_required:
            head.append_text(self.txt(f"  [{self.ctx.t('report.noise.review_required')}]", "yellow"))
        self.print(head)
        indent = (0, 0, 0, 3)
        reasons = f.reasons if self.verbose else f.reasons[:2]
        for reason in reasons:
            self.print(Padding(self.txt(f"{self.sym['bullet']} {reason}"), indent))
        if self.verbose and f.evidence:
            grid = Table.grid(padding=(0, 2))
            grid.add_column(style="dim", no_wrap=True)
            grid.add_column(overflow="fold")
            for row in f.evidence:
                value: Text = self.txt(row.value)
                if row.series:
                    value = Text.assemble(self.spark(row.series, 30), Text("  "), self.txt(row.value, "dim"))
                grid.add_row(self.txt(row.label), value)
            self.print(Padding(grid, indent))
        if f.recommendation:
            self.print(Padding(self.txt(f"{self.sym['arrow']} {f.recommendation}", "green"), indent))
        meta = f"{f.kind} {self.sym['sep']} {f.confidence_label} {self.sym['sep']} {f.fingerprint}"
        if self.verbose:
            meta += f" {self.sym['sep']} {self.ctx.t('report.finding.subject')}: {f.subject}"
        self.print(Padding(self.txt(meta, "dim"), indent))


def print_console(
    report: Report,
    *,
    lang: str = "en",
    redactor: Redactor | None = None,
    console: Console | None = None,
    verbose: bool = False,
) -> None:
    """Print one report to the terminal (``console`` defaults to stdout with highlighting off)."""
    target = console if console is not None else Console(highlight=False)
    ctx = prepare_context(report, lang, redactor)
    view = build_view(ctx, report, finding_limit=None if verbose else _MAX_FINDINGS)
    _ConsoleWriter(target, ctx, verbose).render(view)


def print_console_many(
    reports: Sequence[Report],
    *,
    lang: str = "en",
    redactor: Redactor | Mapping[str, Redactor | None] | None = None,
    console: Console | None = None,
) -> None:
    """Print the multi-tenant fleet summary (one row per tenant, worst first)."""
    target = console if console is not None else Console(highlight=False)
    ctx, rows = fleet_rows(reports, lang, redactor)
    writer = _ConsoleWriter(target, ctx, verbose=False)
    writer.print(
        Text.assemble(
            writer.txt("hushwatch", "bold cyan"),
            writer.txt(f" {writer.sym['sep']} "),
            writer.label("report.fleet.title", "bold"),
        )
    )
    if not rows:
        writer.print(writer.label("report.fleet.empty", "dim"))
        return
    writer.print(
        writer.txt(f"{ctx.t('report.fleet.tenants', n=ctx.num(len(rows)))} · {ctx.t('report.fleet.order')}", "dim")
    )
    compact = writer.width < 150
    table = Table(box=box.SIMPLE_HEAD, show_edge=False, pad_edge=False, header_style="bold")
    table.add_column(writer.label("report.col.tenant"), overflow="fold", min_width=12)
    for domain in DOMAINS:
        table.add_column(writer.label(f"domain.{domain}"), justify="center" if compact else "left")
    for key in ("report.col.critical", "report.col.high", "report.col.findings"):
        table.add_column(writer.label(key), justify="right")
    table.add_column(writer.label("report.col.data"))
    for row in rows:
        cells: list[RenderableType] = [writer.txt(row.tenant, "bold")]
        for domain in DOMAINS:
            status = row.statuses[domain]
            text = (
                writer.sym.get(status, "") if compact else f"{writer.sym.get(status, '')} {ctx.t('status.' + status)}"
            )
            cells.append(writer.txt(text, _STATUS_STYLE.get(status, "")))
        cells += [
            writer.txt(ctx.num(row.critical), "bold red" if row.critical else "dim"),
            writer.txt(ctx.num(row.high), "red" if row.high else "dim"),
            writer.txt(ctx.num(row.total)),
            writer.label("report.data.incomplete", "bold red")
            if row.incomplete
            else writer.label("report.data.complete", "green"),
        ]
        table.add_row(*cells)
    writer.print(table)
    if compact:
        legend = "   ".join(
            f"{writer.sym[st]} {ctx.t('status.' + st)}" for st in ("ok", "warn", "fail", "not_assessed")
        )
        writer.print(writer.txt(legend, "dim"))
    writer.print()
    for line in fleet_footer(ctx, reports):
        writer.print(writer.txt(line, "dim"))
