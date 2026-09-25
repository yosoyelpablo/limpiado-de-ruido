"""Orchestration: one pass over the input feeds every collector, then each analyzer runs and a Report is built.

This module wires the analyzers together; it contains no detection logic of its own.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterable, Iterator, Sequence
from dataclasses import dataclass, field, replace
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Any

from . import __version__
from .config import InputConfig, TenantConfig
from .i18n import M, register
from .inventory import AgentInfo
from .models import (
    DataBasis,
    Finding,
    Report,
    Severity,
    fingerprint,
    sort_findings,
)
from .timeutil import UTC

log = logging.getLogger("hushwatch")

ALL_ANALYSES: tuple[str, ...] = ("noise", "silence", "fields", "coverage", "pipeline", "tuning")

register(
    {
        "engine.api_failed": {
            "en": "Could not query the Wazuh API ({error}); agent inventory, keepalive and manager checks "
            "were skipped.",
            "es": "No se pudo consultar la API de Wazuh ({error}); se omitieron inventario de agentes, keepalive y "
            "controles del manager.",
        },
        "engine.api_failed.title": {
            "en": "Wazuh API unavailable: part of the analysis did not run",
            "es": "API de Wazuh no disponible: parte del análisis no se ejecutó",
        },
        "engine.ruleset_failed.title": {
            "en": "Ruleset could not be loaded: correlation checks and tuning audit skipped",
            "es": "No se pudo cargar el ruleset: se omitieron los controles de correlación y la auditoría de tuning",
        },
        "engine.ruleset_failed": {"en": "{error}", "es": "{error}"},
        "engine.emit_refused.title": {
            "en": "Suppression file not written",
            "es": "No se escribió el archivo de supresiones",
        },
        "engine.emit_refused": {"en": "{error}", "es": "{error}"},
        "engine.emit_profile": {
            "en": "Suppression rules are only generated for Wazuh 4.x alert data (input profile: {profile}).",
            "es": "Las reglas de supresión solo se generan para alertas de Wazuh 4.x (perfil de entrada: {profile}).",
        },
        "engine.emit_warnings.title": {
            "en": "{count} suggestion(s) were not written as Wazuh rules (see reasons)",
            "es": "{count} sugerencia(s) no se escribieron como reglas de Wazuh (ver motivos)",
        },
        "engine.no_input.title": {
            "en": "No input events: nothing could be assessed",
            "es": "No hay eventos de entrada: no se pudo evaluar nada",
        },
    }
)


@dataclass(slots=True)
class AnalysisOptions:
    analyses: frozenset[str] = frozenset(ALL_ANALYSES)
    since: datetime | None = None
    until: datetime | None = None
    now: datetime | None = None
    profile: str = "auto"
    max_events: int | None = None
    dispositions: str | None = None
    ruleset_dirs: Sequence[str] = ()
    emit_suppressions: Path | None = None
    use_api: bool = True
    on_progress: Callable[[int, int], None] | None = None


@dataclass(slots=True)
class AnalysisOutcome:
    report: Report
    suggestions: list[Any] = field(default_factory=list)
    emitted: Any | None = None  # EmitResult when suppressions were written


# ---- event sources --------------------------------------------------------------------------------------------


class ChainedSource:
    """Concatenate several EventSources; the merged DataBasis is recomputed after each full iteration."""

    def __init__(self, sources: Sequence[Any]) -> None:
        self._sources = list(sources)
        self.basis = DataBasis()

    def __iter__(self) -> Iterator[Any]:
        for source in self._sources:
            yield from source
        self.basis = merge_basis([s.basis for s in self._sources])

    def close(self) -> None:
        for source in self._sources:
            close = getattr(source, "close", None)
            if callable(close):
                close()


def merge_basis(bases: Sequence[DataBasis]) -> DataBasis:
    if not bases:
        return DataBasis()
    if len(bases) == 1:
        return bases[0]
    kinds = {b.input_kind for b in bases}
    profiles = {b.profile for b in bases}
    starts = [b.start for b in bases if b.start]
    ends = [b.end for b in bases if b.end]
    nows = [b.now for b in bases if b.now]
    merged = DataBasis(
        input_kind=kinds.pop() if len(kinds) == 1 else "mixed",
        profile=profiles.pop() if len(profiles) == 1 else "mixed",
        sources=[s for b in bases for s in b.sources],
        start=min(starts) if starts else None,
        end=max(ends) if ends else None,
        now=max(nows) if nows else None,
        now_origin=bases[0].now_origin,
        events=sum(b.events for b in bases),
        malformed=sum(b.malformed for b in bases),
        bad_timestamps=sum(b.bad_timestamps for b in bases),
        future_timestamps=sum(b.future_timestamps for b in bases),
        sampled=any(b.sampled for b in bases),
        truncated=any(b.truncated for b in bases),
        partial_failures=[p for b in bases for p in b.partial_failures],
        warnings=[w for b in bases for w in b.warnings],
        not_evaluated=sorted({n for b in bases for n in b.not_evaluated}),
    )
    return merged


def open_sources(
    tenant: TenantConfig,
    *,
    paths: Sequence[str] = (),
    inputs: Sequence[InputConfig] = (),
    options: AnalysisOptions,
) -> Any:
    """Build the EventSource for CLI paths and/or configured inputs."""
    from .ingest import open_files

    sources: list[Any] = []
    if paths:
        sources.append(
            open_files(
                list(paths),
                profile=options.profile,
                tenant=tenant,
                since=options.since,
                until=options.until,
                max_events=options.max_events,
                on_progress=options.on_progress,
            )
        )
    for item in inputs:
        if item.type == "file" and item.path:
            sources.append(
                open_files(
                    [item.path],
                    profile=item.profile if options.profile == "auto" else options.profile,
                    tenant=tenant,
                    since=options.since,
                    until=options.until,
                    max_events=item.max_events or options.max_events,
                    on_progress=options.on_progress,
                    input_cfg=item,
                )
            )
        elif item.type == "indexer":
            from .ingest.indexer_source import IndexerEventSource

            sources.append(IndexerEventSource(item, tenant=tenant, options=options))
    if len(sources) == 1:
        return sources[0]
    return ChainedSource(sources)


# ---- main entry point -----------------------------------------------------------------------------------------


def analyze(
    tenant: TenantConfig,
    source: Any,
    *,
    options: AnalysisOptions,
    wallclock: datetime | None = None,
    agents: list[AgentInfo] | None = None,
) -> AnalysisOutcome:
    """Run every requested analysis over ``source`` for ``tenant`` and build a Report.

    ``agents`` supplies an asset inventory directly (e.g. an exported agent list); otherwise the Wazuh API
    is queried when configured.
    """
    from .analysis.coverage import CoverageCollector, analyze_coverage
    from .analysis.cube import CubeCollector
    from .analysis.fields import FieldCollector, analyze_fields
    from .analysis.noise import NoiseCollector, analyze_noise, apply_backtest
    from .analysis.pipeline import LagCollector, analyze_pipeline
    from .analysis.silence import analyze_silence

    wall = wallclock or datetime.now(UTC)
    wanted = options.analyses
    extra_findings: list[Finding] = []
    sections: dict[str, dict[str, Any]] = {}

    # Context that does not depend on events ------------------------------------------------------------------
    if agents is not None:
        daemon_stats, api_client = None, None
    else:
        agents, daemon_stats, api_client = _query_api(tenant, options, extra_findings)
    ruleset = _load_ruleset(tenant, options, extra_findings)
    dispositions = _load_dispositions(tenant, options)

    # Pass 1 ------------------------------------------------------------------------------------------------
    profile = options.profile
    noise_c = cube_c = fields_c = coverage_c = lag_c = None
    collectors: list[Any] = []
    if "noise" in wanted:
        noise_c = NoiseCollector(tenant, profile, dispositions)
        collectors.append(noise_c)
    if "silence" in wanted:
        cube_c = CubeCollector(tenant, max_keys=tenant.silence.max_keys)
        collectors.append(cube_c)
    if "fields" in wanted:
        fields_c = FieldCollector(tenant)
        collectors.append(fields_c)
    if "coverage" in wanted:
        coverage_c = CoverageCollector(tenant)
        collectors.append(coverage_c)
    if "pipeline" in wanted:
        lag_c = LagCollector()
        collectors.append(lag_c)

    adders = [c.add for c in collectors]
    for event in source:
        for add in adders:
            add(event)
    basis: DataBasis = source.basis
    if api_client is not None:
        api_client.apply_to(basis)
    if coverage_c is not None and getattr(coverage_c, "truncated", False):
        basis.truncated = True
    if noise_c is not None and hasattr(noise_c, "profile") and basis.profile not in ("unknown", "mixed"):
        noise_c.profile = basis.profile

    now = options.now or basis.now or wall
    if options.now is not None:
        basis.now, basis.now_origin = options.now, "flag"
    elif basis.now is None:
        basis.now, basis.now_origin = wall, "wallclock"

    # Analyses ----------------------------------------------------------------------------------------------
    findings: list[Finding] = list(extra_findings)
    suggestions: list[Any] = []
    if basis.events == 0:
        if "pipeline" not in wanted:  # the pipeline analyzer reports empty input itself
            findings.append(
                Finding(
                    kind="assessment.incomplete",
                    domain="assessment",
                    title=M("engine.no_input.title"),
                    severity=Severity.HIGH,
                    subject="no-input",
                )
            )
    else:
        if noise_c is not None:
            dependents = ruleset.dependents if ruleset is not None else None
            noise = analyze_noise(noise_c, tenant=tenant, now=now, dependents=dependents)
            if noise.suggestions and _reiterable(source):
                noise = apply_backtest(noise, source, tenant=tenant)
            findings.extend(noise.findings)
            sections["noise"] = noise.section
            suggestions = list(noise.suggestions)
        if cube_c is not None:
            silence = analyze_silence(cube_c, tenant=tenant, now=now, basis=basis, agents=agents)
            findings.extend(silence.findings)
            sections["silence"] = silence.section
        if fields_c is not None:
            field_findings, field_section = analyze_fields(fields_c, tenant=tenant, now=now, basis=basis)
            findings.extend(field_findings)
            sections.setdefault("silence", {})["fields"] = field_section
        if coverage_c is not None:
            coverage = analyze_coverage(coverage_c, tenant=tenant, now=now, agents=agents, basis=basis, wallclock=wall)
            findings.extend(coverage.findings)
            sections["coverage"] = coverage.section
    if "pipeline" in wanted:
        lag_samples = lag_c.samples() if lag_c is not None else None
        pipeline = analyze_pipeline(
            basis, tenant=tenant, now=wall, daemon_stats=daemon_stats, lag_samples=lag_samples, agents=agents
        )
        findings.extend(pipeline.findings)
        sections["pipeline"] = pipeline.section
    if "tuning" in wanted and ruleset is not None:
        from .wazuh.audit import audit_ruleset

        audit = audit_ruleset(ruleset, tenant=tenant, now=now.date())
        findings.extend(audit.findings)
        sections["tuning"] = audit.section

    # Suppressions ------------------------------------------------------------------------------------------
    emitted = None
    if options.emit_suppressions is not None:
        emitted = _emit(tenant, suggestions, ruleset, basis, options.emit_suppressions, now.date(), findings)
        if emitted is not None and "noise" in sections:
            sections["noise"]["suppressions_file"] = str(emitted.paths[0]) if emitted.paths else None

    close = getattr(source, "close", None)
    if callable(close):
        close()
    if "pipeline" in wanted and tenant.wazuh_api is not None and options.use_api and daemon_stats is None:
        basis.not_evaluated.append("wazuh-manager-stats")
    findings = _assign_tenant(findings, tenant.name)
    report = Report(
        tenant=tenant.name,
        generated_at=wall,
        tool_version=__version__,
        data_basis=basis,
        findings=sort_findings(findings),
        sections=sections,
        assessment=assess(findings, sections, wanted, basis, has_ruleset=ruleset is not None),
    )
    return AnalysisOutcome(report=report, suggestions=suggestions, emitted=emitted)


# ---- helpers --------------------------------------------------------------------------------------------------


def _reiterable(source: Any) -> bool:
    return not isinstance(source, Iterator)


def _query_api(
    tenant: TenantConfig, options: AnalysisOptions, findings: list[Finding]
) -> tuple[list[AgentInfo] | None, dict[str, Any] | None, Any]:
    """Agent inventory + manager stats from the Wazuh API. Failures become assessment findings, never zeros."""
    if not options.use_api or tenant.wazuh_api is None:
        return None, None, None
    from .ingest.wazuh_api import WazuhAPI
    from .net import RemoteError

    try:
        with WazuhAPI(tenant.wazuh_api) as api:
            agents = api.agents()
            stats = api.daemon_stats()
            return agents, stats, api
    except (RemoteError, OSError) as exc:
        findings.append(
            Finding(
                kind="assessment.incomplete",
                domain="assessment",
                title=M("engine.api_failed.title"),
                severity=Severity.HIGH,
                subject="wazuh-api",
                reasons=[M("engine.api_failed", error=str(exc))],
            )
        )
        return None, None, None


def _load_ruleset(tenant: TenantConfig, options: AnalysisOptions, findings: list[Finding]) -> Any:
    dirs = list(options.ruleset_dirs) or list(tenant.ruleset_dirs)
    if not dirs:
        return None
    from .wazuh.ruleset import load_ruleset

    try:
        return load_ruleset(dirs)
    except (OSError, ValueError) as exc:
        findings.append(
            Finding(
                kind="assessment.incomplete",
                domain="assessment",
                title=M("engine.ruleset_failed.title"),
                severity=Severity.MEDIUM,
                subject="ruleset",
                reasons=[M("engine.ruleset_failed", error=str(exc))],
            )
        )
        return None


def _load_dispositions(tenant: TenantConfig, options: AnalysisOptions) -> Any:
    path = options.dispositions or tenant.dispositions
    if not path:
        return None
    from .analysis.dispositions import Dispositions

    return Dispositions.load(path)


def _emit(
    tenant: TenantConfig,
    suggestions: Iterable[Any],
    ruleset: Any,
    basis: DataBasis,
    out_dir: Path,
    today: date,
    findings: list[Finding],
) -> Any:
    """Write reviewed-ready Wazuh rules for ``tune`` suggestions. Refused for non-Wazuh-4 data."""
    from .wazuh.emitter import EmitError, emit_suppressions

    if basis.profile != "wazuh4":
        findings.append(
            Finding(
                kind="noise.emit_skipped",
                domain="noise",
                title=M("engine.emit_refused.title"),
                severity=Severity.LOW,
                subject="emit",
                reasons=[M("engine.emit_profile", profile=basis.profile)],
            )
        )
        return None
    tune = [s for s in suggestions if getattr(s, "verdict", None) == "tune"]
    try:
        result = emit_suppressions(
            tune,
            ruleset=ruleset,
            id_range=tenant.suppression_id_range,
            out_dir=out_dir,
            now=today,
            profile="wazuh4",
            allow_rule_wide=tenant.noise.allow_rule_wide,
        )
    except (EmitError, OSError) as exc:
        reason = exc.message if isinstance(exc, EmitError) else M("engine.emit_refused", error=str(exc))
        findings.append(
            Finding(
                kind="assessment.incomplete",
                domain="assessment",
                title=M("engine.emit_refused.title"),
                severity=Severity.MEDIUM,
                subject="emit",
                reasons=[reason],
            )
        )
        return None
    if result.warnings:
        findings.append(
            Finding(
                kind="noise.emit_skipped",
                domain="noise",
                title=M("engine.emit_warnings.title", count=len(result.warnings)),
                severity=Severity.INFO,
                subject="emit-warnings",
                reasons=list(result.warnings),
            )
        )
    return result


def _assign_tenant(findings: list[Finding], tenant: str) -> list[Finding]:
    """Stamp the tenant and recompute fingerprints (and the ``related`` links that reference them)."""
    remap: dict[str, str] = {}
    out: list[Finding] = []
    for f in findings:
        new_fp = fingerprint(tenant, f.kind, f.subject)
        remap[f.fingerprint] = new_fp
        out.append(replace(f, tenant=tenant, fingerprint=new_fp))
    for f in out:
        f.related = [remap.get(r, r) for r in f.related]
    return out


_DOMAIN_ANALYSES = {
    "noise": ("noise",),
    "silence": ("silence", "fields"),
    "pipeline": ("pipeline",),
    "coverage": ("coverage",),
    "tuning": ("tuning",),
}


def assess(
    findings: Sequence[Finding],
    sections: dict[str, dict[str, Any]],
    wanted: frozenset[str],
    basis: DataBasis,
    *,
    has_ruleset: bool,
) -> dict[str, str]:
    """Per-domain status: fail (high/critical finding), warn (medium), ok, or not_assessed (grey)."""
    status: dict[str, str] = {}
    for domain, analyses in _DOMAIN_ANALYSES.items():
        ran = any(a in wanted for a in analyses) and basis.events > 0
        if domain == "tuning":
            ran = "tuning" in wanted and has_ruleset
        if domain == "pipeline":
            ran = "pipeline" in wanted
        if not ran:
            status[domain] = "not_assessed"
            continue
        section_status = sections.get(domain, {}).get("status")
        if section_status == "not_assessed":  # e.g. noise still learning, or no alerts to analyze
            status[domain] = "not_assessed"
            continue
        ranks = [f.severity.rank for f in findings if f.domain == domain]
        if any(r >= Severity.HIGH.rank for r in ranks):
            status[domain] = "fail"
        elif any(r >= Severity.MEDIUM.rank for r in ranks):
            status[domain] = "warn"
        else:
            status[domain] = "ok"
    incomplete = [f for f in findings if f.domain == "assessment" and f.severity.rank >= Severity.MEDIUM.rank]
    status["assessment"] = "fail" if (incomplete or not basis.complete) else "ok"
    return status


def exit_code(report: Report, fail_on: str) -> int:
    """0 clean, 1 findings at/above ``fail_on`` (info..critical, or 'none'), 3 incomplete analysis."""
    if report.assessment.get("assessment") == "fail":
        return 3
    if fail_on == "none":
        return 0
    threshold = Severity(fail_on).rank
    return 1 if any(f.severity.rank >= threshold for f in report.findings) else 0


def days_between(start: datetime | None, end: datetime | None) -> float:
    if start is None or end is None:
        return 0.0
    return max(0.0, (end - start) / timedelta(days=1))
