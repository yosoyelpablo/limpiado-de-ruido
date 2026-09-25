"""hushwatch command-line interface.

Exit codes: 0 = no findings at/above --fail-on; 1 = findings at/above --fail-on; 2 = usage/config error;
3 = the analysis was incomplete (data unreachable, partial results, nothing to analyze).
"""

from __future__ import annotations

import logging
import os
import sys
import warnings
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.console import Console
from rich.markup import escape

from . import __version__
from .config import ConfigError, TenantConfig, load_config
from .engine import ALL_ANALYSES, AnalysisOptions, analyze, exit_code, open_sources
from .timeutil import UTC, parse_duration, parse_ts

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
    Path | None, typer.Option("--config", "-c", help="Config file (default: $HUSHWATCH_CONFIG).", show_default=False)
]
TenantOpt = Annotated[str | None, typer.Option("--tenant", "-t", help="Tenant to analyze (multi-tenant configs).")]
FormatOpt = Annotated[Fmt, typer.Option("--format", "-f", help="Output format.")]
OutputOpt = Annotated[Path | None, typer.Option("--output", "-o", help="Write the report to this file.")]
LangOpt = Annotated[Lang, typer.Option("--lang", "-l", help="Report language.")]
RedactOpt = Annotated[
    bool, typer.Option("--redact", help="Pseudonymize hosts, users and IPs in the report (for sharing).")
]
FailOnOpt = Annotated[FailOn, typer.Option("--fail-on", help="Exit 1 when a finding at/above this severity exists.")]
ProfileOpt = Annotated[str, typer.Option("--profile", help="Input profile: auto, wazuh4, wazuh5, ecs, generic.")]
SinceOpt = Annotated[str | None, typer.Option("--since", help="Only events after this time (ISO date or e.g. 21d).")]
NowOpt = Annotated[
    str | None, typer.Option("--now", help="Reference 'now' (ISO). Default: the newest event in the input.")
]
NoApiOpt = Annotated[bool, typer.Option("--no-api", help="Do not query the Wazuh API even if configured.")]
VerboseOpt = Annotated[bool, typer.Option("--verbose", "-v", help="Show evidence details and debug logs.")]


def _version_callback(value: bool) -> None:
    if value:
        out.print(f"hushwatch {__version__}")
        raise typer.Exit(0)


@app.callback()
def main_callback(
    version: Annotated[
        bool, typer.Option("--version", callback=_version_callback, is_eager=True, help="Show the version.")
    ] = False,
) -> None:
    """hushwatch — SIEM hygiene toolkit."""


# ---- commands -------------------------------------------------------------------------------------------------


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
    dispositions: Annotated[Path | None, typer.Option(help="Dispositions CSV (alert verdicts).")] = None,
    ruleset: Annotated[
        list[Path] | None, typer.Option(help="Wazuh ruleset dirs/files (correlation checks, tuning audit).")
    ] = None,
    emit_suppressions: Annotated[
        Path | None, typer.Option(help="Write reviewed-ready Wazuh suppression rules to this directory.")
    ] = None,
    no_api: NoApiOpt = False,
    verbose: VerboseOpt = False,
) -> None:
    """Full hygiene report: noise, silence, coverage, pipeline and tuning debt."""
    _run(
        set(ALL_ANALYSES), inputs, config, tenant, fmt, output, lang, redact, fail_on, profile, since, now,
        dispositions, ruleset, emit_suppressions, no_api, verbose,
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
    dispositions: Annotated[Path | None, typer.Option(help="Dispositions CSV (alert verdicts).")] = None,
    ruleset: Annotated[list[Path] | None, typer.Option(help="Wazuh ruleset dirs/files (correlation checks).")] = None,
    emit_suppressions: Annotated[
        Path | None, typer.Option(help="Write reviewed-ready Wazuh suppression rules to this directory.")
    ] = None,
    verbose: VerboseOpt = False,
) -> None:
    """Which alerts can be SAFELY tuned — gated, backtested, scoped suggestions."""
    _run(
        {"noise", "pipeline"}, inputs, config, tenant, fmt, output, lang, redact, fail_on, profile, since, now,
        dispositions, ruleset, emit_suppressions, True, verbose,
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
    no_api: NoApiOpt = False,
    verbose: VerboseOpt = False,
) -> None:
    """Which log sources, rules and fields went quiet — calibrated, grouped by root cause."""
    _run(
        {"silence", "fields", "coverage", "pipeline"}, inputs, config, tenant, fmt, output, lang, redact, fail_on,
        profile, since, now, None, None, None, no_api, verbose,
    )  # fmt: skip


@app.command()
def audit(
    ruleset: Annotated[list[Path], typer.Argument(help="Wazuh ruleset dirs/files (e.g. /var/ossec/etc/rules).")],
    config: ConfigOpt = None,
    tenant: TenantOpt = None,
    fmt: FormatOpt = Fmt.console,
    output: OutputOpt = None,
    lang: LangOpt = Lang.en,
    fail_on: FailOnOpt = FailOn.none,
) -> None:
    """Audit EXISTING Wazuh suppressions: whole-rule mutes, broken correlation, unanchored matches, expiry."""
    from .engine import assess
    from .models import DataBasis, Report, sort_findings
    from .wazuh.audit import audit_ruleset
    from .wazuh.ruleset import load_ruleset

    tenant_cfg = _tenant(config, tenant)
    missing = [str(p) for p in ruleset if not p.exists()]
    if missing:
        _usage_error(f"ruleset path not found: {', '.join(missing)}")
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
    out_dir: Annotated[Path, typer.Option("--out", help="Directory for the demo dataset and report.")] = Path(
        "hushwatch-demo"
    ),
    seed: Annotated[int, typer.Option(help="Random seed (the dataset is deterministic).")] = 7,
    lang: LangOpt = Lang.en,
    open_report: Annotated[bool, typer.Option("--open/--no-open", help="Open the HTML report when done.")] = True,
    fail_on: FailOnOpt = FailOn.none,
) -> None:
    """Generate a realistic synthetic Wazuh dataset with planted problems and analyze it (no SIEM needed)."""
    from .demo import generate

    err.print(f"Generating a synthetic Wazuh dataset in {out_dir} ...", markup=False)
    manifest = generate(out_dir, seed=seed)
    tenant_cfg = load_config(manifest.config_path).tenant()
    opts = AnalysisOptions(
        analyses=frozenset(ALL_ANALYSES),
        dispositions=str(manifest.dispositions_path),
        ruleset_dirs=[str(manifest.rules_dir)],
        emit_suppressions=out_dir / "suppressions",
        use_api=False,
    )
    source = open_sources(tenant_cfg, paths=[str(manifest.alerts_path)], options=opts)
    from .demo import load_demo_agents

    agents = load_demo_agents(manifest.agents_path)
    err.print("Analyzing ...")
    # the dataset is frozen at manifest.now: analyze it "as of" that moment so results never drift with time
    outcome = analyze(tenant_cfg, source, options=opts, agents=agents, wallclock=manifest.now)
    html_path = out_dir / ("report.es.html" if lang is Lang.es else "report.html")
    _emit_report(outcome.report, Fmt.console, None, lang.value, None, verbose=False)
    _emit_report(outcome.report, Fmt.html, html_path, lang.value, None, verbose=False)
    out.print(f"\nHTML report: {html_path}", markup=False)
    if outcome.emitted is not None and getattr(outcome.emitted, "paths", None):
        out.print(f"Suggested Wazuh rules (review before deploying): {out_dir / 'suppressions'}", markup=False)
    if open_report:
        _open(html_path)
    raise typer.Exit(exit_code(outcome.report, fail_on.value))


@app.command()
def check(
    config: ConfigOpt = None,
    tenant: Annotated[str | None, typer.Option("--tenant", "-t", help="Only this tenant (default: all).")] = None,
    lang: LangOpt = Lang.en,
    no_api: NoApiOpt = False,
    dry_run: Annotated[bool, typer.Option("--dry-run", help="Record state but do not send notifications.")] = False,
    verbose: VerboseOpt = False,
) -> None:
    """Cron mode: analyze configured inputs, track finding lifecycle, notify only on changes, send heartbeats."""
    from .notify import build_payload, send, send_heartbeat
    from .state import ACCEPT_FILENAME, StateStore, load_accept_file

    _setup_logging(verbose)
    cfg = _config(config)
    tenants = [cfg.tenant(tenant)] if tenant else list(cfg.tenants.values())
    worst = 0
    for tenant_cfg in tenants:
        if not tenant_cfg.inputs:
            err.print(f"[yellow]{escape(tenant_cfg.name)}: no inputs configured, skipped[/]")
            worst = max(worst, 2)
            continue
        wall = datetime.now(UTC)
        # cron mode measures silence against the wall clock: if data stops arriving, that IS the finding
        opts = AnalysisOptions(analyses=frozenset(ALL_ANALYSES), now=wall, use_api=not no_api)
        try:
            source = open_sources(tenant_cfg, inputs=tenant_cfg.inputs, options=opts)
        except ValueError as exc:
            err.print(f"[red]{escape(tenant_cfg.name)}: {escape(str(exc))}[/]")
            worst = max(worst, 3)
            continue
        rep = analyze(tenant_cfg, source, options=opts, wallclock=wall).report
        state_dir = tenant_cfg.resolved_state_dir()
        store = StateStore(state_dir)
        accept = load_accept_file(state_dir / ACCEPT_FILENAME)
        assessed = {d for d, st in rep.assessment.items() if st != "not_assessed"}
        run = store.record_run(tenant_cfg.name, rep.findings, now=wall, accept=accept, assessed=assessed)
        ok = rep.assessment.get("assessment") != "fail"
        redactor = _redactor(tenant_cfg)
        by_fp = {f.fingerprint: f for f in rep.findings}
        if not dry_run:
            for target in tenant_cfg.notify:
                payload = build_payload(
                    tenant_cfg.name, run, by_fp, lang=lang.value,
                    include_entities=target.include_entities, redactor=redactor,
                )  # fmt: skip
                result = send(target, payload)
                if not result.ok:
                    store.mark_undelivered(tenant_cfg.name, run.run_id, result.fingerprints)
                    err.print(f"[red]{escape(tenant_cfg.name)}: notification failed: {escape(str(result.error))}[/]")
                send_heartbeat(
                    target, tenant_cfg.name, now=wall, ok=ok, run_id=run.run_id, counts=run.counts,
                    lang=lang.value, redactor=redactor,
                )  # fmt: skip
        store.heartbeat(tenant_cfg.name, wall, ok, "check")
        opened, resolved = len(run.opened), len(run.resolved)
        out.print(
            f"{tenant_cfg.name}: {len(rep.findings)} findings, {opened} opened, {resolved} resolved, "
            f"{len(run.transitions)} notification(s){' (dry run)' if dry_run else ''}",
            markup=False,
        )
        worst = max(worst, 3 if not ok else 0)
    raise typer.Exit(worst)


@app.command()
def fleet(
    config: ConfigOpt = None,
    fmt: FormatOpt = Fmt.console,
    output: OutputOpt = None,
    lang: LangOpt = Lang.en,
    redact: RedactOpt = False,
    no_api: NoApiOpt = False,
) -> None:
    """MSSP view: analyze every configured tenant and summarize them side by side."""
    from .report import print_console_many, render_many

    cfg = _config(config)
    reports = []
    for tenant_cfg in cfg.tenants.values():
        if not tenant_cfg.inputs:
            err.print(f"[yellow]{escape(tenant_cfg.name)}: no inputs configured, skipped[/]")
            continue
        opts = AnalysisOptions(use_api=not no_api)
        try:
            source = open_sources(tenant_cfg, inputs=tenant_cfg.inputs, options=opts)
        except ValueError as exc:
            err.print(f"[red]{escape(tenant_cfg.name)}: {escape(str(exc))}[/]")
            continue
        err.print(f"analyzing {tenant_cfg.name} ...", markup=False)
        reports.append(analyze(tenant_cfg, source, options=opts).report)
    if not reports:
        _usage_error("no tenant could be analyzed")
    redactors = {r.tenant: _redactor(cfg.tenant(r.tenant)) for r in reports} if redact else None
    if fmt is Fmt.console and output is None:
        print_console_many(reports, lang=lang.value, redactor=redactors, console=out)
    else:
        text = render_many(reports, "md" if fmt is Fmt.console else fmt.value, lang=lang.value, redactor=redactors)
        if output is None:
            sys.stdout.write(text)
        else:
            _write_private(output, text)
            err.print(f"report written to {output}", markup=False)
    worst = max(exit_code(r, "none") for r in reports)
    raise typer.Exit(worst)


@app.command()
def doctor(
    config: ConfigOpt = None,
    tenant: Annotated[str | None, typer.Option("--tenant", "-t", help="Only this tenant (default: all).")] = None,
) -> None:
    """Check configuration, inputs, indexer and Wazuh API connectivity, with the exact fix for each problem."""
    from .doctor import run_doctor

    cfg = _config(config)
    tenants = [cfg.tenant(tenant)] if tenant else list(cfg.tenants.values())
    ok = run_doctor(cfg, tenants, console=out)
    raise typer.Exit(0 if ok else 1)


@app.command()
def version() -> None:
    """Show the version."""
    out.print(f"hushwatch {__version__}")


# ---- implementation -------------------------------------------------------------------------------------------


def _run(
    analyses: set[str],
    inputs: list[str] | None,
    config: Path | None,
    tenant: str | None,
    fmt: Fmt,
    output: Path | None,
    lang: Lang,
    redact: bool,
    fail_on: FailOn,
    profile: str,
    since: str | None,
    now: str | None,
    dispositions: Path | None,
    ruleset: list[Path] | None,
    emit_suppressions: Path | None,
    no_api: bool,
    verbose: bool,
) -> None:
    _setup_logging(verbose)
    tenant_cfg = _tenant(config, tenant)
    if emit_suppressions is not None and redact:
        _usage_error("--redact cannot be combined with --emit-suppressions: rules need real values to work.")
    if not inputs and not tenant_cfg.inputs:
        _usage_error("no input: pass alert files/directories, or configure 'inputs' for the tenant.")
    opts = AnalysisOptions(
        analyses=frozenset(analyses),
        since=_parse_since(since),
        now=_parse_now(now),
        profile=profile,
        dispositions=str(dispositions) if dispositions else None,
        ruleset_dirs=[str(p) for p in ruleset or []],
        emit_suppressions=emit_suppressions,
        use_api=not no_api,
    )
    try:
        source = open_sources(tenant_cfg, paths=inputs or [], inputs=() if inputs else tenant_cfg.inputs, options=opts)
    except ValueError as exc:  # IngestError: missing path, bad profile/timezone, empty glob...
        _usage_error(str(exc))
        raise
    outcome = analyze(tenant_cfg, source, options=opts)
    redactor = _redactor(tenant_cfg) if redact else None
    _emit_report(outcome.report, fmt, output, lang.value, redactor, verbose=verbose)
    raise typer.Exit(exit_code(outcome.report, fail_on.value))


def _emit_report(rep: Any, fmt: Fmt, output: Path | None, lang: str, redactor: Any, *, verbose: bool) -> None:
    from .report import print_console, render

    if fmt is Fmt.console and output is None:
        print_console(rep, lang=lang, redactor=redactor, console=out, verbose=verbose)
        return
    text = render(rep, "md" if fmt is Fmt.console else fmt.value, lang=lang, redactor=redactor)
    if output is None:
        sys.stdout.write(text)
        return
    _write_private(output, text)
    err.print(f"report written to {output}", markup=False)


def _write_private(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(text)


def _tenant(config: Path | None, tenant: str | None) -> TenantConfig:
    cfg = _config(config)
    try:
        return cfg.tenant(tenant)  # type: ignore[no-any-return]
    except ConfigError as exc:
        _usage_error(str(exc))
        raise


def _redactor(tenant: TenantConfig) -> Any:
    from .redact import Redactor

    return Redactor.for_tenant(tenant.name, tenant.resolved_state_dir())


def _parse_since(value: str | None) -> datetime | None:
    if value is None:
        return None
    try:
        return datetime.now(UTC) - parse_duration(value)
    except ValueError:
        parsed = parse_ts(value)
        if parsed is None:
            _usage_error(f"--since: cannot parse {value!r} (use 7d, 24h or an ISO date)")
        return parsed


def _parse_now(value: str | None) -> datetime | None:
    if value is None:
        return None
    parsed = parse_ts(value)
    if parsed is None:
        _usage_error(f"--now: cannot parse {value!r} (use an ISO timestamp)")
    return parsed


def _usage_error(message: str) -> None:
    err.print(f"[red]error:[/] {escape(message)}", markup=True)
    raise typer.Exit(2)


def _setup_logging(verbose: bool) -> None:
    logging.basicConfig(level=logging.DEBUG if verbose else logging.WARNING, format="%(levelname)s %(message)s")


def _open(path: Path) -> None:
    import webbrowser

    try:
        webbrowser.open(path.resolve().as_uri())
    except Exception as exc:  # opening a browser is best effort (headless servers)
        logging.getLogger("hushwatch").debug("could not open a browser: %s", exc)


def load_agent_inventory(path: Path) -> list[Any] | None:
    """Agent inventory from a JSON export of ``GET /agents`` (list of items, or the full API response)."""
    import json

    from .ingest.wazuh_api import parse_agent

    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if isinstance(raw, dict):
        raw = raw.get("data", raw)
        raw = raw.get("affected_items", raw) if isinstance(raw, dict) else raw
    if not isinstance(raw, list):
        return None
    agents = [parse_agent(item) for item in raw]
    return [a for a in agents if a is not None]


def _config(config: Path | None) -> Any:
    try:
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            cfg = load_config(config)
        for w in caught:
            err.print(f"warning: {w.message}", markup=False)
        return cfg
    except ConfigError as exc:
        _usage_error(str(exc))
        raise


def main() -> None:
    try:
        app()
    except KeyboardInterrupt:
        err.print("interrupted")
        sys.exit(130)
