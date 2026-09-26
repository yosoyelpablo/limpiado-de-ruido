"""hushwatch command-line interface.

Exit codes: 0 = no findings at/above --fail-on; 1 = findings at/above --fail-on; 2 = usage/config error;
3 = the analysis was incomplete (data unreachable, partial results, nothing to analyze, a notification that could
not be delivered in cron mode, or an unexpected error).

Errors are one clean line (in the ``--lang`` language), never a traceback; ``-v`` adds the details.
"""

from __future__ import annotations

import contextlib
import logging
import os
import re
import stat
import sys
import tempfile
import traceback
import warnings
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Annotated, Any
from zoneinfo import ZoneInfo

import typer
from rich.console import Console
from rich.text import Text

from . import __version__
from .config import Config, ConfigError, TenantConfig, load_config
from .engine import (
    ALL_ANALYSES,
    AnalysisOptions,
    analyze,
    exit_code,
    open_sources,
    unassessed_kinds,
)
from .engine import load_agent_inventory as _load_agents
from .i18n import Message, register, render
from .models import DOMAINS, DataBasis, Finding, Report, Severity
from .timeutil import UTC, iso, parse_duration, parse_ts

app = typer.Typer(
    name="hushwatch",
    help="SIEM hygiene: hush the noise (alerts you can safely tune) and watch the silence "
    "(detections and log sources that stopped working).",
    no_args_is_help=True,
    add_completion=False,
    rich_markup_mode=None,
    pretty_exceptions_enable=False,
)

err = Console(stderr=True, highlight=False)
out = Console(highlight=False)
log = logging.getLogger("hushwatch")

register(
    {
        "cli.error": {"en": "error: {message}", "es": "error: {message}"},
        "cli.warning": {"en": "warning: {message}", "es": "advertencia: {message}"},
        "cli.unexpected": {
            "en": "unexpected {error} ({hint})",
            "es": "fallo inesperado: {error} ({hint})",
        },
        "cli.hint_verbose": {"en": "use -v for details", "es": "use -v para ver los detalles"},
        "cli.interrupted": {"en": "interrupted", "es": "interrumpido"},
        "cli.written": {"en": "report written to {path}", "es": "informe escrito en {path}"},
        "cli.written_md": {
            "en": "report written to {path} (Markdown: -f console writes Markdown to files)",
            "es": "informe escrito en {path} (Markdown: -f console escribe Markdown en archivos)",
        },
        "cli.no_input": {
            "en": "no input: pass alert files/directories, or configure 'inputs' for the tenant.",
            "es": "no hay entrada: indique archivos o directorios de alertas, o configure 'inputs' para el tenant.",
        },
        "cli.redact_emit": {
            "en": "--redact cannot be combined with --emit-suppressions: rules need real values to work.",
            "es": "--redact no se puede combinar con --emit-suppressions: las reglas necesitan los valores reales "
            "para funcionar.",
        },
        "cli.since_bad": {
            "en": "--since: cannot parse {value} (use 7d, 24h or an ISO date)",
            "es": "--since: no se puede interpretar {value} (use 7d, 24h o una fecha ISO)",
        },
        "cli.now_bad": {
            "en": "--now: cannot parse {value} (use an ISO timestamp)",
            "es": "--now: no se puede interpretar {value} (use una marca de tiempo ISO)",
        },
        "cli.since_after_now": {
            "en": "--since ({since}) must be earlier than --now ({now})",
            "es": "--since ({since}) debe ser anterior a --now ({now})",
        },
        "cli.ruleset_missing": {
            "en": "ruleset path not found: {paths}",
            "es": "no se encontró la ruta del ruleset: {paths}",
        },
        "cli.output_dir": {
            "en": "-o {path} is a directory: give a file name",
            "es": "-o {path} es un directorio: indique un nombre de archivo",
        },
        "cli.output_link": {
            "en": "-o {path}: refusing to write through a symbolic link or to a special file",
            "es": "-o {path}: no se escribe a través de un enlace simbólico ni en un archivo especial",
        },
        "cli.output_parent": {
            "en": "-o {path}: cannot write in {parent} ({error})",
            "es": "-o {path}: no se puede escribir en {parent} ({error})",
        },
        "cli.emit_not_dir": {
            "en": "--emit-suppressions {path} exists and is not a directory",
            "es": "--emit-suppressions {path} existe y no es un directorio",
        },
        "cli.emit_exists": {
            "en": "--emit-suppressions {path} already contains a suppression file set ({names}); pass --force to "
            "replace it, or choose another directory",
            "es": "--emit-suppressions {path} ya contiene un conjunto de archivos de supresión ({names}); agregue "
            "--force para reemplazarlo, o elija otro directorio",
        },
        "cli.file_missing": {
            "en": "{option} {path}: file not found",
            "es": "{option} {path}: no se encontró el archivo",
        },
        "cli.no_inputs": {
            "en": "{tenant}: no inputs configured, skipped",
            "es": "{tenant}: no hay entradas configuradas, se omite",
        },
        "cli.tenant_failed": {"en": "{tenant}: {error}", "es": "{tenant}: {error}"},
        "cli.tenant_failed.title": {
            "en": "The run for this tenant failed: nothing was analyzed",
            "es": "La ejecución de este tenant falló: no se analizó nada",
        },
        "cli.demo.generating": {
            "en": "Generating a synthetic Wazuh dataset in {path} ...",
            "es": "Generando un conjunto de datos sintético de Wazuh en {path} ...",
        },
        "cli.analyzing": {"en": "Analyzing ...", "es": "Analizando ..."},
        "cli.analyzing_tenant": {"en": "analyzing {tenant} ...", "es": "analizando {tenant} ..."},
        "cli.demo.html": {"en": "HTML report: {path}", "es": "Informe HTML: {path}"},
        "cli.demo.rules": {
            "en": "Suggested Wazuh rules (review before deploying): {path}",
            "es": "Reglas de Wazuh sugeridas (revíselas antes de desplegarlas): {path}",
        },
        "cli.fleet.none": {"en": "no tenant could be analyzed", "es": "no se pudo analizar ningún tenant"},
        "cli.check.summary": {
            "en": "{tenant}: {findings} {findings:plural:finding|findings}, {opened} opened, {resolved} "
            "resolved, {delivered} of {total} {total:plural:notification|notifications} delivered",
            "es": "{tenant}: {findings} {findings:plural:hallazgo|hallazgos}, {opened} "
            "{opened:plural:abierto|abiertos}, {resolved} {resolved:plural:resuelto|resueltos}, "
            "{delivered} de {total} {total:plural:notificación entregada|notificaciones entregadas}",
        },
        "cli.check.summary_dry": {
            "en": "{tenant}: {findings} {findings:plural:finding|findings}, {opened} opened, {resolved} "
            "resolved, {total} {total:plural:notification|notifications} not sent (dry run: the next "
            "run sends them)",
            "es": "{tenant}: {findings} {findings:plural:hallazgo|hallazgos}, {opened} "
            "{opened:plural:abierto|abiertos}, {resolved} {resolved:plural:resuelto|resueltos}, {total} "
            "{total:plural:notificación|notificaciones} sin enviar (simulación: las envía la próxima "
            "ejecución)",
        },
        "cli.check.summary_none": {
            "en": "{tenant}: {findings} {findings:plural:finding|findings}, {opened} opened, {resolved} "
            "resolved, {total} {total:plural:change|changes}, no notification target configured",
            "es": "{tenant}: {findings} {findings:plural:hallazgo|hallazgos}, {opened} "
            "{opened:plural:abierto|abiertos}, {resolved} {resolved:plural:resuelto|resueltos}, {total} "
            "{total:plural:cambio|cambios}, sin destino de notificación configurado",
        },
        "cli.check.notify_failed": {
            "en": "{tenant}: notification not delivered: {error}",
            "es": "{tenant}: no se entregó la notificación: {error}",
        },
        "cli.check.heartbeat_failed": {
            "en": "{tenant}: heartbeat not delivered: {error}",
            "es": "{tenant}: no se entregó el latido: {error}",
        },
        "cli.check.failed_title": {
            "en": "The monitoring run could not analyze this tenant",
            "es": "La ejecución de monitoreo no pudo analizar este tenant",
        },
        "cli.check.ok_detail": {"en": "check", "es": "check"},
    }
)


class Fmt(str, Enum):
    console = "console"
    html = "html"
    md = "md"
    json = "json"


class Lang(str, Enum):
    en = "en"
    es = "es"


class FailOn(str, Enum):
    none = "none"
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


# ---- shared options -------------------------------------------------------------------------------------------

InputsArg = Annotated[
    list[str] | None,
    typer.Argument(
        help="Alert/event files, directories or globs (Wazuh alerts.json, archives.json, NDJSON, CSV, .gz)."
    ),
]
ConfigOpt = Annotated[
    Path | None,
    typer.Option(
        "--config",
        "-c",
        help="Config file (default: $HUSHWATCH_CONFIG). Relative paths inside it are relative to the file.",
        show_default=False,
    ),
]
TenantOpt = Annotated[str | None, typer.Option("--tenant", "-t", help="Tenant to analyze (multi-tenant configs).")]
FormatOpt = Annotated[Fmt, typer.Option("--format", "-f", help="Output format.")]
OutputOpt = Annotated[
    Path | None,
    typer.Option(
        "--output",
        "-o",
        help="Write the report to this file (mode 0600, replaced atomically). -f console writes Markdown to a file.",
    ),
]
LangOpt = Annotated[Lang, typer.Option("--lang", "-l", help="Language of the report and of the messages.")]
RedactOpt = Annotated[
    bool,
    typer.Option(
        "--redact",
        help="Pseudonymize hosts, users and IPs in the report (for sharing). Pseudonyms come from a per-tenant key "
        "created on first use in <state dir>/keys/ (mode 0600; default state dir ~/.local/state/hushwatch) or "
        "derived from $HUSHWATCH_REDACT_KEY; keep the key to get the same pseudonyms in every report.",
    ),
]
FailOnOpt = Annotated[FailOn, typer.Option("--fail-on", help="Exit 1 when a finding at/above this severity exists.")]
ProfileOpt = Annotated[str, typer.Option("--profile", help="Input profile: auto, wazuh4, wazuh5, ecs, generic.")]
SinceOpt = Annotated[
    str | None,
    typer.Option(
        "--since",
        help="Only events after this time: an ISO date (in the tenant's timezone when it has no offset) or a "
        "duration such as 21d, counted back from --now (default: the system clock).",
    ),
]
NowOpt = Annotated[
    str | None,
    typer.Option(
        "--now",
        help="Analyze as of this moment (ISO; tenant timezone when it has no offset). Events after it are not "
        "analyzed. Default: the newest event in the input.",
    ),
]
NoApiOpt = Annotated[bool, typer.Option("--no-api", help="Do not query the Wazuh API even if configured.")]
VerboseOpt = Annotated[bool, typer.Option("--verbose", "-v", help="Show evidence details and debug logs.")]
AgentsOpt = Annotated[
    Path | None,
    typer.Option(
        "--agents",
        help="Agent inventory: a JSON export of the Wazuh API GET /agents (when the API is not reachable). "
        "Enables the agent connectivity checks.",
    ),
]
ForceOpt = Annotated[
    bool, typer.Option("--force", help="Replace an existing suppression file set in --emit-suppressions DIR.")
]
DispositionsOpt = Annotated[Path | None, typer.Option(help="Dispositions CSV (alert verdicts).")]
EmitOpt = Annotated[Path | None, typer.Option(help="Write review-ready Wazuh suppression rules to this directory.")]


def _version_callback(value: bool) -> None:
    if value:
        out.print(f"hushwatch {__version__}", markup=False)
        raise typer.Exit(0)


@app.callback()
def main_callback(
    version: Annotated[
        bool, typer.Option("--version", callback=_version_callback, is_eager=True, help="Show the version.")
    ] = False,
) -> None:
    """hushwatch — SIEM hygiene toolkit."""


# ---- commands -------------------------------------------------------------------------------------------------


@dataclass(slots=True)
class _RunArgs:
    analyses: frozenset[str]
    inputs: list[str] | None
    config: Path | None
    tenant: str | None
    fmt: Fmt
    output: Path | None
    lang: Lang
    redact: bool
    fail_on: FailOn
    profile: str
    since: str | None
    now: str | None
    dispositions: Path | None = None
    ruleset: list[Path] | None = None
    emit_suppressions: Path | None = None
    force: bool = False
    agents: Path | None = None
    no_api: bool = False
    verbose: bool = False


@app.command()
def report(
    inputs: InputsArg = None,
    config: ConfigOpt = None,
    tenant: TenantOpt = None,
    fmt: FormatOpt = Fmt.console,
    output: OutputOpt = None,
    lang: LangOpt = Lang.en,
    redact: RedactOpt = False,
    fail_on: FailOnOpt = FailOn.none,
    profile: ProfileOpt = "auto",
    since: SinceOpt = None,
    now: NowOpt = None,
    dispositions: DispositionsOpt = None,
    ruleset: Annotated[
        list[Path] | None,
        typer.Option(
            help="Wazuh ruleset dirs/files, stock AND local (e.g. --ruleset /var/ossec/ruleset/rules "
            "--ruleset /var/ossec/etc/rules): correlation checks and tuning audit."
        ),
    ] = None,
    emit_suppressions: EmitOpt = None,
    force: ForceOpt = False,
    agents: AgentsOpt = None,
    no_api: NoApiOpt = False,
    verbose: VerboseOpt = False,
) -> None:
    """Full hygiene report: noise, silence, coverage, pipeline and tuning debt."""
    _run(
        _RunArgs(
            frozenset(ALL_ANALYSES), inputs, config, tenant, fmt, output, lang, redact, fail_on, profile, since, now,
            dispositions, ruleset, emit_suppressions, force, agents, no_api, verbose,
        )
    )  # fmt: skip


@app.command()
def noise(
    inputs: InputsArg = None,
    config: ConfigOpt = None,
    tenant: TenantOpt = None,
    fmt: FormatOpt = Fmt.console,
    output: OutputOpt = None,
    lang: LangOpt = Lang.en,
    redact: RedactOpt = False,
    fail_on: FailOnOpt = FailOn.none,
    profile: ProfileOpt = "auto",
    since: SinceOpt = None,
    now: NowOpt = None,
    dispositions: DispositionsOpt = None,
    ruleset: Annotated[
        list[Path] | None,
        typer.Option(help="Wazuh ruleset dirs/files, stock AND local (correlation dependency checks)."),
    ] = None,
    emit_suppressions: EmitOpt = None,
    force: ForceOpt = False,
    agents: AgentsOpt = None,
    verbose: VerboseOpt = False,
) -> None:
    """Which alerts can be SAFELY tuned — gated, backtested, scoped suggestions."""
    _run(
        _RunArgs(
            frozenset({"noise", "pipeline"}), inputs, config, tenant, fmt, output, lang, redact, fail_on, profile,
            since, now, dispositions, ruleset, emit_suppressions, force, agents, True, verbose,
        )
    )  # fmt: skip


@app.command()
def silence(
    inputs: InputsArg = None,
    config: ConfigOpt = None,
    tenant: TenantOpt = None,
    fmt: FormatOpt = Fmt.console,
    output: OutputOpt = None,
    lang: LangOpt = Lang.en,
    redact: RedactOpt = False,
    fail_on: FailOnOpt = FailOn.none,
    profile: ProfileOpt = "auto",
    since: SinceOpt = None,
    now: NowOpt = None,
    agents: AgentsOpt = None,
    no_api: NoApiOpt = False,
    verbose: VerboseOpt = False,
) -> None:
    """Which log sources, rules and fields went quiet — calibrated, grouped by root cause."""
    _run(
        _RunArgs(
            frozenset({"silence", "fields", "coverage", "pipeline"}), inputs, config, tenant, fmt, output, lang,
            redact, fail_on, profile, since, now, agents=agents, no_api=no_api, verbose=verbose,
        )
    )  # fmt: skip


@app.command()
def audit(
    ruleset: Annotated[
        list[Path],
        typer.Argument(
            help="Wazuh ruleset dirs/files, stock AND local (/var/ossec/ruleset/rules /var/ossec/etc/rules)."
        ),
    ],
    config: ConfigOpt = None,
    tenant: TenantOpt = None,
    fmt: FormatOpt = Fmt.console,
    output: OutputOpt = None,
    lang: LangOpt = Lang.en,
    fail_on: FailOnOpt = FailOn.none,
    verbose: VerboseOpt = False,
) -> None:
    """Audit EXISTING Wazuh suppressions: whole-rule mutes, broken correlation, unanchored matches, expiry."""
    from .engine import assess
    from .models import sort_findings
    from .wazuh.audit import audit_ruleset
    from .wazuh.ruleset import load_ruleset

    _set_lang(lang)
    _setup_logging(verbose)
    with _guard(verbose):
        tenant_cfg = _tenant(config, tenant)
        missing = [str(p) for p in ruleset if not p.exists()]
        if missing:
            _usage_error(_m("cli.ruleset_missing", paths=", ".join(missing)))
        _check_output(output)
        rs = load_ruleset([str(p) for p in ruleset])
        wall = datetime.now(UTC)
        result = audit_ruleset(rs, tenant=tenant_cfg, now=wall.date())
        basis = DataBasis(
            input_kind="ruleset", profile="wazuh4", sources=[str(p) for p in ruleset], events=max(1, len(rs.rules)),
            start=wall, end=wall, now=wall, now_origin="wallclock",
        )  # fmt: skip
        findings = sort_findings(result.findings)
        sections = {"tuning": result.section}
        rep = Report(
            tenant=tenant_cfg.name,
            generated_at=wall,
            tool_version=__version__,
            data_basis=basis,
            findings=findings,
            sections=sections,
            assessment=assess(findings, sections, frozenset({"tuning"}), basis, has_ruleset=True),
        )
        _emit_report(rep, fmt, output, lang.value, None, verbose=False)
    raise typer.Exit(exit_code(rep, fail_on.value))


@app.command()
def demo(
    out_dir: Annotated[
        Path, typer.Option("--out", help="Directory for the demo dataset and report (its files are replaced).")
    ] = Path("hushwatch-demo"),
    seed: Annotated[int, typer.Option(help="Random seed (the dataset is deterministic).")] = 7,
    lang: LangOpt = Lang.en,
    open_report: Annotated[bool, typer.Option("--open/--no-open", help="Open the HTML report when done.")] = True,
    fail_on: FailOnOpt = FailOn.none,
    verbose: VerboseOpt = False,
) -> None:
    """Generate a realistic synthetic Wazuh dataset with planted problems and analyze it (no SIEM needed)."""
    from .demo import generate, load_demo_agents

    _set_lang(lang)
    _setup_logging(verbose)
    with _guard(verbose):
        _say(err, "cli.demo.generating", path=str(out_dir))
        manifest = generate(out_dir, seed=seed)
        _make_private(manifest.config_path)  # it names the demo's files; nothing else may edit it
        tenant_cfg = load_config(manifest.config_path).tenant()
        opts = AnalysisOptions(
            analyses=frozenset(ALL_ANALYSES),
            dispositions=str(manifest.dispositions_path),
            ruleset_dirs=[str(manifest.rules_dir)],
            emit_suppressions=out_dir / "suppressions",
            overwrite=True,  # the demo owns its output directory: running it again replaces its files
            use_api=False,
        )
        source = open_sources(tenant_cfg, paths=[str(manifest.alerts_path)], options=opts)
        agents = load_demo_agents(manifest.agents_path)
        _say(err, "cli.analyzing")
        # the dataset is frozen at manifest.now: analyze it "as of" that moment so results never drift with time
        outcome = analyze(tenant_cfg, source, options=opts, agents=agents, wallclock=manifest.now)
        html_path = out_dir / ("report.es.html" if lang is Lang.es else "report.html")
        _emit_report(outcome.report, Fmt.console, None, lang.value, None, verbose=False)
        _emit_report(outcome.report, Fmt.html, html_path, lang.value, None, verbose=False, quiet=True)
        out.print()
        _say(out, "cli.demo.html", path=str(html_path))
        if outcome.emitted is not None and getattr(outcome.emitted, "paths", None):
            _say(out, "cli.demo.rules", path=str(out_dir / "suppressions"))
    if open_report:
        _open(html_path)
    raise typer.Exit(exit_code(outcome.report, fail_on.value))


@app.command()
def check(
    config: ConfigOpt = None,
    tenant: Annotated[str | None, typer.Option("--tenant", "-t", help="Only this tenant (default: all).")] = None,
    lang: LangOpt = Lang.en,
    no_api: NoApiOpt = False,
    dry_run: Annotated[
        bool,
        typer.Option(
            "--dry-run",
            help="Record the lifecycle but send nothing; the changes stay pending and the next real run sends them.",
        ),
    ] = False,
    fail_on: FailOnOpt = FailOn.none,
    verbose: VerboseOpt = False,
) -> None:
    """Cron mode: analyze configured inputs, track finding lifecycle, notify only on changes, send heartbeats.

    Each tenant is independent: one tenant's outage is reported (failed heartbeat, incomplete run) and the others
    still run. Exit 3 when any tenant could not be fully analyzed or any notification could not be delivered."""
    _set_lang(lang)
    _setup_logging(verbose)
    with _guard(verbose):
        cfg = _config(config)
        names = _select(cfg, tenant)
        worst = 0
        for name in names:
            worst = max(worst, _check_tenant(cfg, name, lang.value, no_api, dry_run, fail_on.value, verbose))
    raise typer.Exit(worst)


@app.command()
def fleet(
    config: ConfigOpt = None,
    fmt: FormatOpt = Fmt.console,
    output: OutputOpt = None,
    lang: LangOpt = Lang.en,
    redact: RedactOpt = False,
    no_api: NoApiOpt = False,
    fail_on: FailOnOpt = FailOn.none,
    data_now: Annotated[
        bool,
        typer.Option(
            "--data-now",
            help="Measure each tenant as of its newest event instead of the system clock (for exported data).",
        ),
    ] = False,
    verbose: VerboseOpt = False,
) -> None:
    """MSSP view: analyze every configured tenant and summarize them side by side.

    Live inputs are measured against the system clock (a feed that stopped IS the finding); a tenant that cannot
    be analyzed gets an "incomplete" row and the exit code is 3."""
    from .report import print_console_many, render_many

    _set_lang(lang)
    _setup_logging(verbose)
    with _guard(verbose):
        cfg = _config(config)
        _check_output(output)
        reports: list[Report] = []
        for name in cfg.select(None):
            rep = _fleet_tenant(cfg, name, no_api=no_api, data_now=data_now, verbose=verbose)
            if rep is not None:
                reports.append(rep)
        if not reports:
            _usage_error(_m("cli.fleet.none"))
        redactors = {r.tenant: _redactor(cfg.tenants[r.tenant]) for r in reports} if redact else None
        if fmt is Fmt.console and output is None:
            print_console_many(reports, lang=lang.value, redactor=redactors, console=out)
        else:
            text = render_many(reports, "md" if fmt is Fmt.console else fmt.value, lang=lang.value, redactor=redactors)
            if output is None:
                sys.stdout.write(text)
            else:
                _write_private(output, text)
                _say(err, "cli.written_md" if fmt is Fmt.console else "cli.written", path=str(output))
        worst = max(exit_code(r, fail_on.value) for r in reports)
    raise typer.Exit(worst)


@app.command()
def doctor(
    config: ConfigOpt = None,
    tenant: Annotated[str | None, typer.Option("--tenant", "-t", help="Only this tenant (default: all).")] = None,
    lang: LangOpt = Lang.en,
    verbose: VerboseOpt = False,
) -> None:
    """Check configuration, inputs, indexer and Wazuh API connectivity, with the exact fix for each problem."""
    from .doctor import run_doctor

    _set_lang(lang)
    _setup_logging(verbose)
    with _guard(verbose):
        cfg = _config(config)
        names = _select(cfg, tenant)
        ok = run_doctor(cfg, names, console=out, lang=lang.value)
    raise typer.Exit(0 if ok else 1)


@app.command()
def version() -> None:
    """Show the version."""
    out.print(f"hushwatch {__version__}", markup=False)


# ---- report / noise / silence ---------------------------------------------------------------------------------


def _run(a: _RunArgs) -> None:
    _set_lang(a.lang)
    _setup_logging(a.verbose)
    with _guard(a.verbose):
        tenant_cfg = _tenant(a.config, a.tenant)
        if a.emit_suppressions is not None and a.redact:
            _usage_error(_m("cli.redact_emit"))
        if not a.inputs and not tenant_cfg.inputs:
            _usage_error(_m("cli.no_input"))
        tz = _tz(tenant_cfg)
        now = _parse_now(a.now, tz)
        since, relative = _parse_since(a.since, now, tz)
        if since is not None and now is not None and since >= now:
            _usage_error(_m("cli.since_after_now", since=iso(since), now=iso(now)))
        # validate every file argument BEFORE the (long) analysis: a typo must not cost a full run
        _check_output(a.output)
        if a.emit_suppressions is not None:
            _check_emit_dir(a.emit_suppressions, a.force)
        if a.dispositions is not None and "noise" in a.analyses:
            _check_file(a.dispositions, "--dispositions")
        if a.agents is not None:
            _check_file(a.agents, "--agents")
        opts = AnalysisOptions(
            analyses=a.analyses,
            since=since,
            # --now means "as of": later events are left out (and counted) instead of skewing silence
            until=now + timedelta(seconds=1) if now is not None else None,
            now=now,
            since_relative=relative,
            profile=a.profile,
            dispositions=str(a.dispositions) if a.dispositions else None,
            ruleset_dirs=[str(p) for p in a.ruleset or []],
            emit_suppressions=a.emit_suppressions,
            overwrite=a.force,
            agents_file=str(a.agents) if a.agents else None,
            use_api=not a.no_api,
        )
        redactor = _redactor(tenant_cfg) if a.redact else None  # key problems are config errors: before analysis
        source = open_sources(
            tenant_cfg, paths=a.inputs or [], inputs=() if a.inputs else tenant_cfg.inputs, options=opts
        )
        outcome = analyze(tenant_cfg, source, options=opts, wallclock=now)
        _window_warnings(outcome.report)
        _emit_report(outcome.report, a.fmt, a.output, a.lang.value, redactor, verbose=a.verbose)
    raise typer.Exit(exit_code(outcome.report, a.fail_on.value))


def _emit_report(
    rep: Any, fmt: Fmt, output: Path | None, lang: str, redactor: Any, *, verbose: bool, quiet: bool = False
) -> None:
    from .report import print_console, render

    if fmt is Fmt.console and output is None:
        print_console(rep, lang=lang, redactor=redactor, console=out, verbose=verbose)
        return
    text = render(rep, "md" if fmt is Fmt.console else fmt.value, lang=lang, redactor=redactor)
    if output is None:
        sys.stdout.write(text)
        return
    _write_private(output, text)
    if not quiet:
        _say(err, "cli.written_md" if fmt is Fmt.console else "cli.written", path=str(output))


def _window_warnings(rep: Report) -> None:
    """Say on stderr when --since/--now left events out (the report may otherwise just say "no events")."""
    for warning in rep.data_basis.warnings:
        if isinstance(warning, Message) and warning.key.startswith("engine.window."):
            _say(err, "cli.warning", message=warning)


# ---- check ------------------------------------------------------------------------------------------------------


def _check_tenant(cfg: Config, name: str, lang: str, no_api: bool, dry_run: bool, fail_on: str, verbose: bool) -> int:
    """One tenant of ``hushwatch check``. Returns its exit code; never raises for a tenant-level problem."""
    from .ingest import IngestError
    from .state import (
        ACCEPT_FILENAME,
        STATE_FILENAME,
        AcceptFileError,
        StateError,
        StateStore,
        load_accept_file,
        prepare_state_dir,
    )

    try:
        tenant_cfg = cfg.tenant(name)
    except ConfigError as exc:
        _say(err, "cli.tenant_failed", tenant=name, error=str(exc), style="red")
        return 2
    if not tenant_cfg.inputs:
        _say(err, "cli.no_inputs", tenant=name, style="yellow")
        return 2
    wall = datetime.now(UTC)
    try:
        state_dir = prepare_state_dir(tenant_cfg.resolved_state_dir())
        store = StateStore(state_dir / STATE_FILENAME)
    except StateError as exc:
        _say(err, "cli.tenant_failed", tenant=name, error=exc.render(_lang()), style="red")
        return 2
    with store:
        redactor = None
        try:
            redactor = _redactor(tenant_cfg)
            accept = load_accept_file(state_dir / ACCEPT_FILENAME, now=wall)
        except (AcceptFileError, ValueError) as exc:  # includes RedactKeyError
            message = _error_message(exc)
            _say(err, "cli.tenant_failed", tenant=name, error=message, style="red")
            _failed_run(tenant_cfg, store, wall, message, redactor, lang, dry_run, accept=None)
            return 2
        opts = AnalysisOptions(
            analyses=frozenset(ALL_ANALYSES), now=wall, now_origin="wallclock", use_api=not no_api
        )  # cron mode measures silence against the wall clock: if data stops arriving, that IS the finding
        try:
            source = open_sources(tenant_cfg, inputs=tenant_cfg.inputs, options=opts)
            rep = analyze(tenant_cfg, source, options=opts, wallclock=wall).report
        except Exception as exc:  # one tenant's outage never stops the others
            code, message = _classify(exc, verbose)
            _say(err, "cli.tenant_failed", tenant=name, error=message, style="red")
            try:
                _failed_run(tenant_cfg, store, wall, message, redactor, lang, dry_run, accept=accept)
            except StateError as state_exc:
                _say(err, "cli.tenant_failed", tenant=name, error=state_exc.render(_lang()), style="red")
            # an input that vanished or a SIEM that is down is an incomplete monitoring run, not a usage error
            return 3 if isinstance(exc, IngestError) or code == 3 else code
        incomplete = rep.assessment.get("assessment") == "fail"
        if incomplete:  # nothing absent from a partial run proves it went away: only assessment findings may recover
            assessed: set[str] = {"assessment"}
        else:
            assessed = {d for d, st in rep.assessment.items() if st != "not_assessed"}
        detail: Message | str = _m("cli.check.ok_detail") if not incomplete else _incomplete_detail(rep)
        try:
            run = store.record_run(
                tenant_cfg.name, rep.findings, now=wall, accept=accept, assessed=assessed,
                unassessed_kinds=unassessed_kinds(rep),
            )  # fmt: skip
            failures = _deliver(tenant_cfg, store, run, rep.findings, not incomplete, detail, lang, redactor, dry_run)
            store.heartbeat(tenant_cfg.name, wall, not incomplete, detail)
        except StateError as exc:
            _say(err, "cli.tenant_failed", tenant=name, error=exc.render(_lang()), style="red")
            return 3
    code = 3 if incomplete else exit_code(rep, fail_on)
    return max(code, 3) if failures else code


def _failed_run(
    tenant_cfg: TenantConfig,
    store: Any,
    wall: datetime,
    reason: Message | str,
    redactor: Any,
    lang: str,
    dry_run: bool,
    *,
    accept: Any,
) -> bool:
    """A run that could not analyze the tenant still leaves a trace: an incomplete run (an ``assessment``
    finding, notified like any other), a failed heartbeat stored and sent. Nothing else changes state.
    Returns True when a notification could not be delivered."""
    finding = Finding(
        kind="assessment.incomplete",
        domain="assessment",
        title=_m("cli.check.failed_title"),
        severity=Severity.HIGH,
        subject="check-run",
        reasons=[reason],
        tenant=tenant_cfg.name,
    )
    run = store.record_run(tenant_cfg.name, [finding], now=wall, accept=accept, assessed=())
    failures = _deliver(tenant_cfg, store, run, [finding], False, reason, lang, redactor, dry_run)
    store.heartbeat(tenant_cfg.name, wall, False, reason)
    return failures > 0


def _deliver(
    tenant_cfg: TenantConfig,
    store: Any,
    run: Any,
    findings: Sequence[Finding],
    ok: bool,
    detail: Message | str,
    lang: str,
    redactor: Any,
    dry_run: bool,
) -> int:
    """Send the digest and the heartbeat to every target; print one line per failure and a summary line.
    Returns the number of failed deliveries."""
    from .notify import build_payload, send, send_heartbeat

    name = tenant_cfg.name
    total = len(run.transitions)
    counts: dict[str, Any] = {"tenant": name, "opened": len(run.opened), "resolved": len(run.resolved), "total": total}
    findings_count = run.counts.get("findings", len(findings))
    if dry_run:
        if run.transitions:  # a dry run must not swallow notifications: the next real run sends them
            store.mark_undelivered(name, run.run_id)
        _say(out, "cli.check.summary_dry", findings=findings_count, **counts)
        return 0
    if not tenant_cfg.notify:
        _say(out, "cli.check.summary_none", findings=findings_count, **counts)
        return 0
    by_fp = {f.fingerprint: f for f in findings}
    eligible: set[str] = set()  # transitions at/above some target's min_severity
    delivered: set[str] = set()
    failures = 0
    for target in tenant_cfg.notify:
        payload = build_payload(
            name, run, by_fp, lang=lang, include_entities=target.include_entities, redactor=redactor
        )
        result = send(target, payload)
        eligible.update(result.fingerprints)
        if result.ok:
            delivered.update(result.fingerprints)
        else:
            failures += 1
            store.mark_undelivered(name, run.run_id, result.fingerprints)
            _say(err, "cli.check.notify_failed", tenant=name, error=result.message or result.error or "?",
                 style="red")  # fmt: skip
        beat = send_heartbeat(
            target, name, now=run.run_at, ok=ok, detail=detail, run_id=run.run_id, counts=run.counts, lang=lang,
            redactor=redactor,
        )  # fmt: skip
        if not beat.ok:
            failures += 1
            _say(err, "cli.check.heartbeat_failed", tenant=name, error=beat.message or beat.error or "?",
                 style="red")  # fmt: skip
    counts["total"] = len(eligible)
    _say(out, "cli.check.summary", findings=findings_count, delivered=len(delivered & eligible), **counts)
    return failures


def _incomplete_detail(rep: Report) -> Message | str:
    """Why a run is incomplete, for the heartbeat: the most severe assessment finding's title."""
    for f in rep.findings:  # sorted most severe first
        if f.domain == "assessment" and f.severity.rank >= Severity.MEDIUM.rank:
            return f.title
    return _m("cli.tenant_failed.title")


# ---- fleet ------------------------------------------------------------------------------------------------------


def _fleet_tenant(cfg: Config, name: str, *, no_api: bool, data_now: bool, verbose: bool) -> Report | None:
    """One fleet row: the tenant's report, or an "incomplete" report when it could not be analyzed."""
    wall = datetime.now(UTC)
    try:
        tenant_cfg = cfg.tenant(name)
    except ConfigError as exc:
        _say(err, "cli.tenant_failed", tenant=name, error=str(exc), style="red")
        return _failed_report(name, str(exc), wall)
    if not tenant_cfg.inputs:
        _say(err, "cli.no_inputs", tenant=name, style="yellow")
        return None
    opts = AnalysisOptions(
        use_api=not no_api, now=None if data_now else wall, now_origin="wallclock"
    )  # live inputs: the system clock, like check (a feed that stopped must not look healthy)
    _say(err, "cli.analyzing_tenant", tenant=name)
    try:
        source = open_sources(tenant_cfg, inputs=tenant_cfg.inputs, options=opts)
        return analyze(tenant_cfg, source, options=opts, wallclock=None if data_now else wall).report
    except Exception as exc:  # one tenant's outage never hides the others
        _code, message = _classify(exc, verbose)
        _say(err, "cli.tenant_failed", tenant=name, error=message, style="red")
        return _failed_report(name, message, wall)


def _failed_report(tenant: str, reason: Message | str, wall: datetime) -> Report:
    finding = Finding(
        kind="assessment.incomplete",
        domain="assessment",
        title=_m("cli.tenant_failed.title"),
        severity=Severity.HIGH,
        subject="fleet-run",
        reasons=[reason],
        tenant=tenant,
    )
    basis = DataBasis(partial_failures=[reason], now=wall, now_origin="wallclock")
    status = {d: "not_assessed" for d in DOMAINS}
    status["assessment"] = "fail"
    return Report(
        tenant=tenant,
        generated_at=wall,
        tool_version=__version__,
        data_basis=basis,
        findings=[finding],
        assessment=status,
    )


# ---- validation -------------------------------------------------------------------------------------------------


def _check_output(path: Path | None) -> None:
    """Refuse an output target that cannot be written safely, before any analysis runs."""
    if path is None:
        return
    target = path.expanduser()
    shown = str(path)
    try:
        st = os.lstat(target)
    except FileNotFoundError:
        st = None
    except OSError as exc:
        _usage_error(_m("cli.output_parent", path=shown, parent=str(target.parent), error=exc.strerror or "error"))
    if st is not None:
        if stat.S_ISDIR(st.st_mode):
            _usage_error(_m("cli.output_dir", path=shown))
        if not stat.S_ISREG(st.st_mode):
            _usage_error(_m("cli.output_link", path=shown))
    parent = target.parent
    while not os.path.lexists(parent) and parent != parent.parent:
        parent = parent.parent
    if not parent.is_dir() or not os.access(parent, os.W_OK | os.X_OK):
        problem = "not a directory" if not parent.is_dir() else "permission denied"
        _usage_error(_m("cli.output_parent", path=shown, parent=str(parent), error=problem))


def _check_emit_dir(path: Path, force: bool) -> None:
    from .wazuh.emitter import SPEC_FILE, VALIDATION_FILE, XML_FILE

    target = path.expanduser()
    if os.path.lexists(target) and not target.is_dir():
        _usage_error(_m("cli.emit_not_dir", path=str(path)))
    if force or not target.is_dir():
        return
    existing = [n for n in (XML_FILE, SPEC_FILE, VALIDATION_FILE) if os.path.lexists(target / n)]
    if existing:
        _usage_error(_m("cli.emit_exists", path=str(path), names=", ".join(existing)))


def _check_file(path: Path, option: str) -> None:
    if not path.expanduser().is_file():
        _usage_error(_m("cli.file_missing", option=option, path=str(path)))


# ---- private files ------------------------------------------------------------------------------------------------


def _write_private(path: Path, text: str) -> None:
    """Write ``text`` to ``path`` atomically with mode 0600 (reports hold real identifiers).

    A temporary file in the target directory is written, chmod-ed 0600 through its descriptor and renamed over
    the target: an existing file never keeps a looser mode, a symlink or special file is never written through,
    and a reader never sees half a report. Missing parent directories are created 0700."""
    _check_output(path)
    target = path.expanduser()
    _private_parents(target.parent)
    fd, tmp = tempfile.mkstemp(dir=str(target.parent), prefix=f".{target.name}.", suffix=".tmp")
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
        os.replace(tmp, target)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def _private_parents(directory: Path) -> None:
    missing: list[Path] = []
    current = directory
    while not os.path.lexists(current) and current != current.parent:
        missing.append(current)
        current = current.parent
    for item in reversed(missing):
        with contextlib.suppress(FileExistsError):
            os.mkdir(item, 0o700)
            os.chmod(item, 0o700)


def _make_private(path: Path) -> None:
    with contextlib.suppress(OSError):
        st = os.lstat(path)
        if stat.S_ISREG(st.st_mode) and st.st_mode & 0o077:
            os.chmod(path, 0o600)


# ---- parsing ------------------------------------------------------------------------------------------------------


def _tz(tenant: TenantConfig) -> Any:
    try:
        return ZoneInfo(tenant.timezone)
    except (KeyError, ValueError):  # validated at load; defensive
        return UTC


def _parse_since(value: str | None, now: datetime | None, tz: Any) -> tuple[datetime | None, bool]:
    """``--since``: a duration counted back from ``now`` (``--now``) or the system clock, or an ISO date/time
    (naive values are in the tenant's timezone). Returns the cutoff and whether it was relative."""
    if value is None:
        return None, False
    try:
        delta = parse_duration(value)
    except ValueError:
        delta = None
    if delta is not None:
        return (now or datetime.now(UTC)) - delta, True
    parsed = parse_ts(value, naive_tz=tz)
    if parsed is None:
        _usage_error(_m("cli.since_bad", value=repr(value)))
    return parsed, False


def _parse_now(value: str | None, tz: Any) -> datetime | None:
    if value is None:
        return None
    parsed = parse_ts(value, naive_tz=tz)
    if parsed is None:
        _usage_error(_m("cli.now_bad", value=repr(value)))
    return parsed


# ---- config and tenants -------------------------------------------------------------------------------------------


def _config(config: Path | None) -> Config:
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        cfg = load_config(config)  # ConfigError -> exit 2 via _guard
    for w in caught:
        _say(err, "cli.warning", message=str(w.message), style="yellow")
    return cfg


def _tenant(config: Path | None, tenant: str | None) -> TenantConfig:
    return _config(config).tenant(tenant)


def _select(cfg: Config, tenant: str | None) -> list[str]:
    return cfg.select(tenant)


def _redactor(tenant: TenantConfig) -> Any:
    from .redact import REDACT_KEY_ENV, Redactor
    from .state import prepare_state_dir

    if os.environ.get(REDACT_KEY_ENV):
        return Redactor.for_tenant(tenant.name, None)  # derived from the environment key: nothing on disk
    # the keys live in the state directory: create it privately (or migrate a database left in its place)
    return Redactor.for_tenant(tenant.name, prepare_state_dir(tenant.resolved_state_dir()))


def load_agent_inventory(path: Path) -> list[Any]:
    """Agent inventory from a JSON export of ``GET /agents`` (see :func:`hushwatch.engine.load_agent_inventory`)."""
    return _load_agents(path)


# ---- messages, errors and logging -----------------------------------------------------------------------------------

_UI = {"lang": "en"}


def _set_lang(lang: Lang | str) -> None:
    _UI["lang"] = lang.value if isinstance(lang, Lang) else str(lang)


def _lang() -> str:
    return _UI["lang"]


def _m(key: str, **params: Any) -> Message:
    return Message(key, params)


def _say(console: Console, key: str, *, style: str | None = None, **params: Any) -> None:
    """Print one localized line (no Rich markup: values may contain brackets)."""
    console.print(Text(render(Message(key, params), _lang()), style=style or ""), soft_wrap=True)


def _usage_error(message: Message | str) -> None:
    text = render(message, _lang()) if isinstance(message, Message) else message
    _say(err, "cli.error", message=text, style="red")
    raise typer.Exit(2)


def _error_message(exc: BaseException) -> str:
    """A safe, localized one-line description of an expected error."""
    render_method = getattr(exc, "render", None)
    if callable(render_method):
        try:
            return str(render_method(_lang()))
        except TypeError:
            pass
    message = getattr(exc, "message", None)
    if isinstance(message, Message):
        return render(message, _lang())
    return _scrub(str(exc)) or type(exc).__name__


def _classify(exc: BaseException, verbose: bool) -> tuple[int, str]:
    """Exit code (2 usage/config, 3 runtime) and a one-line message for an exception."""
    from .ingest import IngestError
    from .net import RemoteError
    from .redact import RedactKeyError
    from .state import StateError

    if isinstance(exc, (ConfigError, IngestError, RedactKeyError)):
        return 2, _error_message(exc)
    if isinstance(exc, RemoteError):
        return (2 if exc.kind == "config" else 3), _error_message(exc)
    if isinstance(exc, StateError):
        return 2, _error_message(exc)
    if isinstance(exc, OSError):
        return 3, _scrub(f"{exc.strerror or type(exc).__name__}: {exc.filename}" if exc.filename else str(exc))
    if verbose:
        err.print(Text(_scrub("".join(traceback.format_exception(exc)))), soft_wrap=True)
    detail = _scrub(str(exc)).splitlines()[0][:200] if str(exc) else ""
    name = type(exc).__name__ + (f": {detail}" if detail else "")
    return 3, render(_m("cli.unexpected", error=name, hint=_m("cli.hint_verbose")), _lang())


@contextlib.contextmanager
def _guard(verbose: bool) -> Iterator[None]:
    """Turn every error into one clean line and the documented exit code (2 usage/config, 3 runtime)."""
    try:
        yield
    except (typer.Exit, typer.Abort, typer.TyperException):
        raise
    except KeyboardInterrupt:
        _say(err, "cli.interrupted")
        raise typer.Exit(130) from None
    except Exception as exc:
        code, message = _classify(exc, verbose)
        _say(err, "cli.error", message=message, style="red")
        raise typer.Exit(code) from None


_URL = re.compile(r"(?i)\b([a-z][a-z0-9+.-]{1,15})://(?:[^\s/?#]*@)?([^\s/?#@]+)([^\s]*)")


def _url_origin(match: re.Match[str]) -> str:
    return f"{match.group(1)}://{match.group(2)}" + ("/…" if match.group(3) else "")


def _scrub(text: str) -> str:
    """URLs reduced to their origin (paths, queries and user info of webhooks and APIs are secrets)."""
    return _URL.sub(_url_origin, text)


class _UrlScrubFilter(logging.Filter):
    """Reduce every URL in a log record to its origin (a webhook URL path or query is a credential)."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:  # a broken record is not ours to fix
            return True
        clean = _scrub(message)
        if clean != message:
            record.msg, record.args = clean, None
        return True


_FILTER = _UrlScrubFilter()


def _setup_logging(verbose: bool) -> None:
    logging.basicConfig(level=logging.DEBUG if verbose else logging.WARNING, format="%(levelname)s %(message)s")
    # HTTP client libraries log full request URLs at INFO/DEBUG (Slack webhook URLs ARE the secret): never below
    # WARNING, even with -v
    for name in ("httpx", "httpcore", "hpack", "urllib3"):
        logging.getLogger(name).setLevel(logging.WARNING)
    root = logging.getLogger()
    root.setLevel(logging.DEBUG if verbose else logging.WARNING)
    for handler in root.handlers:
        if _FILTER not in handler.filters:
            handler.addFilter(_FILTER)


def _open(path: Path) -> None:
    import webbrowser

    try:
        webbrowser.open(path.resolve().as_uri())
    except Exception as exc:  # opening a browser is best effort (headless servers)
        log.debug("could not open a browser: %s", exc)


def main() -> None:
    """Console entry point: a last safety net so a user never sees a traceback without asking for it."""
    verbose = any(arg in ("-v", "--verbose") for arg in sys.argv[1:])
    try:
        app()
    except KeyboardInterrupt:
        err.print(render(_m("cli.interrupted"), _lang()), markup=False)
        sys.exit(130)
    except SystemExit:
        raise
    except Exception as exc:
        code, message = _classify(exc, verbose)
        err.print(Text(render(_m("cli.error", message=message), _lang()), style="red"), soft_wrap=True)
        sys.exit(code)
