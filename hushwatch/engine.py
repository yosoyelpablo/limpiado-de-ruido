"""Orchestration: one pass over the input feeds every collector, then each analyzer runs and a Report is built.

This module wires the analyzers together; it contains no detection logic of its own. It is also where the
report's honesty about its own coverage is decided (never a false green): which requested analyses could not run
and why (``DataBasis.not_evaluated`` + a warning each), the per-domain status (:func:`assess`), and whether the
run as a whole is incomplete (exit code 3).
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable, Collection, Iterable, Iterator, Sequence
from dataclasses import dataclass, field, replace
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Any

from . import __version__
from .config import ConfigError, InputConfig, TenantConfig
from .i18n import M, Message, register
from .inventory import AgentInfo
from .models import (
    DataBasis,
    Finding,
    Report,
    Severity,
    fingerprint,
    sort_findings,
)
from .timeutil import UTC, iso

log = logging.getLogger("hushwatch")

ALL_ANALYSES: tuple[str, ...] = ("noise", "silence", "fields", "coverage", "pipeline", "tuning")

# Finding kinds that only an agent inventory (Wazuh API or an exported agent list) can produce: a run without one
# cannot confirm that such a finding went away.
INVENTORY_KINDS: frozenset[str] = frozenset({"pipeline.agent_disconnected", "pipeline.agent_no_data"})
# not_evaluated markers written by the engine (rendered through the ``domain.<marker>`` labels registered below)
NOT_EVALUATED_INVENTORY = "agent-inventory"
NOT_EVALUATED_API = "wazuh-api"
NOT_EVALUATED_MANAGER_STATS = "wazuh-manager-stats"

register(
    {
        "engine.api_failed": {
            "en": "Could not query the Wazuh API ({error}); agent inventory, keepalive and manager checks "
            "were skipped.",
            "es": "No se pudo consultar la API de Wazuh ({error}); se omitieron el inventario de agentes, el "
            "keepalive y los controles del manager.",
        },
        "engine.api_failed.title": {
            "en": "Wazuh API unavailable: part of the analysis did not run",
            "es": "API de Wazuh no disponible: parte del análisis no se ejecutó",
        },
        "engine.stats_failed": {
            "en": "Wazuh manager statistics could not be read ({error}); event-drop checks were skipped (the agent "
            "inventory was used).",
            "es": "No se pudieron leer las estadísticas del manager de Wazuh ({error}); se omitieron los controles "
            "de eventos descartados (sí se usó el inventario de agentes).",
        },
        "engine.ruleset_failed.title": {
            "en": "Ruleset could not be loaded: correlation checks and tuning audit skipped",
            "es": "No se pudo cargar el ruleset: se omitieron los controles de correlación y la auditoría del ajuste",
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
        "engine.emit_skipped.title": {
            "en": "{count} tuning {count:plural:suggestion was|suggestions were} not written as Wazuh rules "
            "(see the reasons)",
            "es": "{count} {count:plural:sugerencia|sugerencias} de ajuste no se "
            "{count:plural:escribió|escribieron} como reglas de Wazuh (vea los motivos)",
        },
        "engine.emit_notes.title": {
            "en": "Notes about the generated suppression file ({count})",
            "es": "Notas sobre el archivo de supresiones generado ({count})",
        },
        "engine.no_input.title": {
            "en": "No input events: nothing could be assessed",
            "es": "No hay eventos de entrada: no se pudo evaluar nada",
        },
        "engine.no_input.window_title": {
            "en": "No events inside the analysis window: all {count} events read were outside it",
            "es": "No hay eventos dentro de la ventana de análisis: los {count} eventos leídos quedaron fuera",
        },
        "engine.nothing_assessed.title": {
            "en": "Nothing could be assessed: every requested analysis is still learning or not supported by "
            "this input",
            "es": "No se pudo evaluar nada: todos los análisis solicitados siguen en aprendizaje o esta entrada no "
            "los admite",
        },
        "engine.nothing_assessed.reason": {
            "en": "Not assessed: {domains}. See 'Analyses not evaluated' in the data basis for the reasons.",
            "es": "Sin evaluar: {domains}. Los motivos figuran en «Análisis no evaluados» de la base de datos.",
        },
        "engine.noise_no_rule.title": {
            "en": "Noise could not be assessed: none of the {count} events carries a rule id",
            "es": "No se pudo evaluar el ruido: ninguno de los {count} eventos tiene un identificador de regla",
        },
        "engine.noise_no_rule.rec": {
            "en": "Map the rule id of your export with the input's mapping (inputs[].mapping.rule_id: <field>), or "
            "analyze an alerts export (for Wazuh: alerts.json, not archives.json).",
            "es": "Mapee el identificador de regla de su exportación con el mapping de la entrada "
            "(inputs[].mapping.rule_id: <campo>), o analice una exportación de alertas (en Wazuh: alerts.json, no "
            "archives.json).",
        },
        # why a requested analysis did not run (DataBasis warnings)
        "engine.skip.inventory": {
            "en": "Pipeline: agent connectivity was not checked (disconnected agents, agents alive but sending "
            "nothing): no agent inventory. Configure wazuh_api, or pass --agents with a JSON export of the Wazuh "
            "API GET /agents (agents_file: in the config).",
            "es": "Pipeline: no se verificó la conectividad de los agentes (agentes desconectados, agentes vivos que "
            "no envían nada): no hay inventario de agentes. Configure wazuh_api, o pase --agents con una exportación "
            "JSON de GET /agents de la API de Wazuh (agents_file: en la configuración).",
        },
        "engine.skip.inventory_generic": {
            "en": "Pipeline: agent connectivity was not checked (agents that send nothing): no agent inventory "
            "(--agents FILE or agents_file: in the config).",
            "es": "Pipeline: no se verificó la conectividad de los agentes (agentes que no envían nada): no hay "
            "inventario de agentes (--agents ARCHIVO o agents_file: en la configuración).",
        },
        "engine.skip.tuning_generic": {
            "en": "Tuning debt: not evaluated, the audit of existing suppressions reads Wazuh rule files only.",
            "es": "Deuda de ajuste: no se evaluó, la auditoría de las supresiones existentes solo lee archivos de "
            "reglas de Wazuh.",
        },
        "engine.skip.tuning": {
            "en": "Tuning debt: not evaluated, no Wazuh ruleset given (use --ruleset /var/ossec/ruleset/rules "
            "--ruleset /var/ossec/etc/rules, or ruleset_dirs in the config).",
            "es": "Deuda de ajuste: no se evaluó, no se indicó un ruleset de Wazuh (use --ruleset "
            "/var/ossec/ruleset/rules --ruleset /var/ossec/etc/rules, o ruleset_dirs en la configuración).",
        },
        "engine.skip.noise_learning": {
            "en": "Noise: not evaluated yet, less than {days} days of alert history (learning).",
            "es": "Ruido: aún no se evaluó, hay menos de {days} días de historial de alertas (aprendizaje).",
        },
        "engine.skip.noise_no_rule": {
            "en": "Noise: not evaluated, none of the {count} events carries a rule id.",
            "es": "Ruido: no se evaluó, ninguno de los {count} eventos tiene un identificador de regla.",
        },
        "engine.skip.noise_archives": {
            "en": "Noise: not evaluated, archives contain every event, not rule matches; analyze the alerts for noise.",
            "es": "Ruido: no se evaluó, los archives contienen todos los eventos y no coincidencias de reglas; analice "
            "las alertas para el ruido.",
        },
        "engine.skip.learning": {
            "en": "{domain}: not evaluated yet, less than {days} days of history (learning).",
            "es": "{domain}: aún no se evaluó, hay menos de {days} días de historial (aprendizaje).",
        },
        "engine.skip.domain": {
            "en": "{domain}: not evaluated with this input (see its section).",
            "es": "{domain}: no se evaluó con esta entrada (vea su sección).",
        },
        "engine.skip.silence_truncated": {
            "en": "Silence: only partly evaluated, the source-key cap was reached (see the finding).",
            "es": "Silencio: evaluado solo en parte, se alcanzó el límite de claves de fuentes (vea el hallazgo).",
        },
        # --since / --now window
        "engine.window.since": {
            "en": "{count} {count:plural:event|events} older than the --since cutoff ({cutoff}) "
            "{count:plural:was|were} read but not analyzed.",
            "es": "{count} {count:plural:evento anterior|eventos anteriores} al corte de --since ({cutoff}) "
            "se {count:plural:leyó|leyeron} pero no se {count:plural:analizó|analizaron}.",
        },
        "engine.window.until": {
            "en": "{count} {count:plural:event|events} later than --now ({until}) {count:plural:was|were} "
            "read but not analyzed.",
            "es": "{count} {count:plural:evento posterior|eventos posteriores} a --now ({until}) se "
            "{count:plural:leyó|leyeron} pero no se {count:plural:analizó|analizaron}.",
        },
        "engine.window.both": {
            "en": "{count} {count:plural:event|events} outside the analysis window ({cutoff} to {until}) "
            "{count:plural:was|were} read but not analyzed.",
            "es": "{count} {count:plural:evento|eventos} fuera de la ventana de análisis ({cutoff} a {until}) "
            "se {count:plural:leyó|leyeron} pero no se {count:plural:analizó|analizaron}.",
        },
        "engine.window.newest": {
            "en": "The newest of them is from {newest}.",
            "es": "El más reciente es del {newest}.",
        },
        "engine.window.tip": {
            "en": "A relative --since counts back from the system clock; for an older export pass --now with the "
            "export's end date (e.g. --now {example}).",
            "es": "Un --since relativo se cuenta hacia atrás desde el reloj del sistema; para una exportación más "
            "antigua pase --now con la fecha final de la exportación (p. ej. --now {example}).",
        },
        # labels for the not_evaluated markers (the report renders DataBasis.not_evaluated through domain.<name>)
        "domain.agent-inventory": {
            "en": "Agent inventory (agent connectivity)",
            "es": "Inventario de agentes (conectividad de los agentes)",
        },
        "domain.wazuh-api": {"en": "Wazuh API (query failed)", "es": "API de Wazuh (falló la consulta)"},
        "domain.wazuh-manager-stats": {
            "en": "Wazuh manager statistics (event drops)",
            "es": "Estadísticas del manager de Wazuh (eventos descartados)",
        },
    }
)


@dataclass(slots=True)
class AnalysisOptions:
    analyses: frozenset[str] = frozenset(ALL_ANALYSES)
    since: datetime | None = None
    until: datetime | None = None
    now: datetime | None = None
    now_origin: str = "flag"  # where ``now`` came from when set: flag (--now) | wallclock (cron / fleet)
    since_relative: bool = False  # --since was a duration (7d): counted back from ``now`` or the system clock
    profile: str = "auto"
    max_events: int | None = None
    dispositions: str | None = None
    ruleset_dirs: Sequence[str] = ()
    emit_suppressions: Path | None = None
    overwrite: bool = False  # replace an existing suppression file set (--force)
    agents_file: str | None = None  # exported agent inventory (--agents); wins over the API and agents_file:
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

    def iter_rules(self, rule_ids: Collection[str]) -> Iterator[Any]:
        """Only events of ``rule_ids`` (the backtest pass); sources without a fast path are filtered here."""
        wanted = frozenset(rule_ids)
        for source in self._sources:
            fast = getattr(source, "iter_rules", None)
            if callable(fast):
                yield from fast(wanted)
            else:
                yield from (e for e in source if e.rule_id in wanted)

    def close(self) -> None:
        for source in self._sources:
            close = getattr(source, "close", None)
            if callable(close):
                close()


_KIND_FAMILY = {"alerts": "alerts", "indexer-alerts": "alerts", "archives": "archives", "indexer-archives": "archives"}


def merge_basis(bases: Sequence[DataBasis]) -> DataBasis:
    """One DataBasis for several inputs. Inputs that delivered no events do not change the input kind/profile;
    alerts from files and from an alerts index are still "alerts" (archives likewise); duplicates are dropped."""
    if not bases:
        return DataBasis()
    if len(bases) == 1:
        return bases[0]
    with_events = [b for b in bases if b.events > 0] or list(bases)
    kinds = {b.input_kind for b in with_events}
    families = {_KIND_FAMILY.get(k) for k in kinds}
    if len(kinds) == 1:
        kind = next(iter(kinds))
    elif len(families) == 1 and None not in families:
        kind = str(next(iter(families)))
    else:
        kind = "mixed"
    profiles = {b.profile for b in with_events}
    starts = [b.start for b in bases if b.start]
    ends = [b.end for b in bases if b.end]
    nows = [b.now for b in bases if b.now]
    newest = [b.excluded_newest for b in bases if b.excluded_newest]
    merged = DataBasis(
        input_kind=kind,
        profile=profiles.pop() if len(profiles) == 1 else "mixed",
        sources=_unique(s for b in bases for s in b.sources),
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
        partial_failures=_unique(p for b in bases for p in b.partial_failures),
        excluded_by_window=sum(b.excluded_by_window for b in bases),
        excluded_newest=max(newest) if newest else None,
        skipped_files=_unique(f for b in bases for f in b.skipped_files),
        warnings=_unique(w for b in bases for w in b.warnings),
        not_evaluated=sorted({n for b in bases for n in b.not_evaluated}),
    )
    return merged


def _unique(items: Iterable[Any]) -> list[Any]:
    """Order-preserving de-duplication for values that may be unhashable (Messages carry dict params)."""
    out: list[Any] = []
    for item in items:
        if item not in out:
            out.append(item)
    return out


def open_sources(
    tenant: TenantConfig,
    *,
    paths: Sequence[str] = (),
    inputs: Sequence[InputConfig] = (),
    options: AnalysisOptions,
) -> Any:
    """Build the EventSource for CLI paths and/or configured inputs.

    Raises ``IngestError`` (a ValueError) for unusable file inputs and ``RemoteError`` when an indexer client cannot
    even be built (kind ``config``: e.g. an unreadable ``ca_cert``). Already opened sources are closed first."""
    from .ingest import open_files

    sources: list[Any] = []
    try:
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
    except BaseException:
        for source in sources:
            _close(source)
        raise
    if len(sources) == 1:
        return sources[0]
    return ChainedSource(sources)


def load_agent_inventory(path: str | Path) -> list[AgentInfo]:
    """Agent inventory from a JSON export of the Wazuh API ``GET /agents`` (the full response, its ``data``
    object or the bare list of items). Raises :class:`ConfigError` when it cannot be used."""
    from .ingest.wazuh_api import parse_agent

    file_path = Path(path).expanduser()
    try:
        with file_path.open("rb") as handle:
            data = handle.read(64 * 1024 * 1024 + 1)
    except OSError as exc:
        raise ConfigError(
            f"cannot read the agent inventory {file_path}: {exc.strerror or type(exc).__name__}"
        ) from None
    if len(data) > 64 * 1024 * 1024:
        raise ConfigError(f"agent inventory {file_path} is larger than 64 MiB")
    try:
        raw: Any = json.loads(data.decode("utf-8-sig"))
    except (UnicodeDecodeError, ValueError):
        raise ConfigError(f"agent inventory {file_path} is not JSON (export of the Wazuh API GET /agents)") from None
    if isinstance(raw, dict):
        raw = raw.get("data", raw)
        raw = raw.get("affected_items", raw) if isinstance(raw, dict) else raw
    if not isinstance(raw, list):
        raise ConfigError(
            f"agent inventory {file_path}: expected the GET /agents response (data.affected_items) or a list of agents"
        )
    agents = [a for a in (parse_agent(item) for item in raw) if a is not None]
    if raw and not agents:
        raise ConfigError(f"agent inventory {file_path}: no entry has an agent id")
    return agents


# ---- main entry point -----------------------------------------------------------------------------------------


@dataclass(slots=True)
class _Context:
    """What the run could use besides the events (drives not_evaluated and the pipeline status)."""

    inventory: bool = False
    api_failed: bool = False
    stats_missing: bool = False
    notes: list[Message] = field(default_factory=list)


def analyze(
    tenant: TenantConfig,
    source: Any,
    *,
    options: AnalysisOptions,
    wallclock: datetime | None = None,
    agents: list[AgentInfo] | None = None,
    generated_at: datetime | None = None,
) -> AnalysisOutcome:
    """Run every requested analysis over ``source`` for ``tenant`` and build a Report.

    ``agents`` supplies an asset inventory directly; otherwise ``options.agents_file`` (``--agents``), the Wazuh
    API (when configured and ``use_api``) or the tenant's ``agents_file`` is used, in that order. ``wallclock`` is
    the moment the analysis is "as of" for keepalive and freshness checks (default: the system clock);
    ``generated_at`` is when the report was produced (default: the system clock). The source (and any API client)
    is always closed, even when an analysis fails. Raises :class:`ConfigError` for an unusable dispositions or
    agent inventory file (before reading any event).
    """
    try:
        return _analyze(tenant, source, options, wallclock, agents, generated_at)
    finally:
        _close(source)


def _analyze(
    tenant: TenantConfig,
    source: Any,
    options: AnalysisOptions,
    wallclock: datetime | None,
    agents: list[AgentInfo] | None,
    generated_at: datetime | None,
) -> AnalysisOutcome:
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
    ctx = _Context()

    # Context that does not depend on events (local files first: a usage error must not wait for the network) --
    dispositions = _load_dispositions(tenant, options) if "noise" in wanted else None
    ruleset = _load_ruleset(tenant, options, extra_findings)
    daemon_stats: dict[str, Any] | None = None
    api_client: Any = None
    if agents is None and options.agents_file:
        agents = load_agent_inventory(options.agents_file)
    if agents is None and options.use_api and tenant.wazuh_api is not None:
        agents, daemon_stats, api_client = _query_api(tenant, extra_findings, ctx)
    elif agents is None and tenant.agents_file:
        agents = load_agent_inventory(tenant.agents_file)
    ctx.inventory = agents is not None

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
        basis.now, basis.now_origin = options.now, options.now_origin
    elif basis.now is None:
        basis.now, basis.now_origin = wall, "wallclock"
    _window_notes(basis, options)
    needs_inventory = "silence" in wanted or "coverage" in wanted
    if ctx.api_failed:
        _mark(basis, NOT_EVALUATED_API)
    elif needs_inventory and not ctx.inventory:
        _mark(basis, NOT_EVALUATED_INVENTORY)
        _warn(basis, M("engine.skip.inventory" if _is_wazuh(basis) else "engine.skip.inventory_generic"))
    if ctx.stats_missing and "pipeline" in wanted:
        _mark(basis, NOT_EVALUATED_MANAGER_STATS)
    for note in ctx.notes:
        _warn(basis, note)

    # Analyses ----------------------------------------------------------------------------------------------
    findings: list[Finding] = list(extra_findings)
    suggestions: list[Any] = []
    if basis.events > 0:
        if noise_c is not None:
            dependents = ruleset.dependents if ruleset is not None else None
            noise = analyze_noise(noise_c, tenant=tenant, now=now, dependents=dependents)
            if noise.suggestions and _reiterable(source):
                noise = apply_backtest(noise, _backtest_events(source, noise.suggestions), tenant=tenant)
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
    if basis.events == 0:
        findings = _empty_input(findings, basis)

    # Suppressions ------------------------------------------------------------------------------------------
    emitted = None
    if options.emit_suppressions is not None:
        emitted = _emit(
            tenant, suggestions, ruleset, basis, options.emit_suppressions, now.date(), findings, options.overwrite
        )
        if emitted is not None and "noise" in sections:
            sections["noise"]["suppressions_file"] = str(emitted.paths[0]) if emitted.paths else None

    # Coverage of the run itself ----------------------------------------------------------------------------
    has_ruleset = ruleset is not None
    findings.extend(_unsupported_noise(wanted, sections, basis))
    findings = _link(findings)
    status = assess(findings, sections, wanted, basis, has_ruleset=has_ruleset, has_inventory=ctx.inventory)
    _explain_not_evaluated(status, wanted, sections, basis, tenant, has_ruleset)
    if basis.events > 0:
        idle = _nothing_assessed(status, wanted)
        if idle is not None:
            findings.append(idle)
            status = assess(findings, sections, wanted, basis, has_ruleset=has_ruleset, has_inventory=ctx.inventory)

    findings = _assign_tenant(findings, tenant.name)
    report = Report(
        tenant=tenant.name,
        generated_at=generated_at or (datetime.now(UTC) if wallclock is not None else wall),
        tool_version=__version__,
        data_basis=basis,
        findings=sort_findings(findings),
        sections=sections,
        assessment=status,
    )
    return AnalysisOutcome(report=report, suggestions=suggestions, emitted=emitted)


# ---- helpers --------------------------------------------------------------------------------------------------


def _close(source: Any) -> None:
    close = getattr(source, "close", None)
    if callable(close):
        try:
            close()
        except Exception as exc:  # closing is best effort: never mask the real outcome
            log.debug("closing the input failed: %s", type(exc).__name__)


def _reiterable(source: Any) -> bool:
    return not isinstance(source, Iterator)


def _backtest_events(source: Any, suggestions: Sequence[Any]) -> Iterable[Any]:
    """The backtest only replays the candidates' rules: use the source's fast rule filter when it has one."""
    rule_ids = {str(s.rule_id) for s in suggestions if getattr(s, "rule_id", None) is not None}
    fast = getattr(source, "iter_rules", None)
    events: Iterable[Any] = fast(rule_ids) if callable(fast) else source
    return events


def _mark(basis: DataBasis, name: str) -> None:
    if name not in basis.not_evaluated:
        basis.not_evaluated.append(name)


def _warn(basis: DataBasis, message: Message) -> None:
    if message not in basis.warnings:
        basis.warnings.append(message)


def _window_notes(basis: DataBasis, options: AnalysisOptions) -> None:
    """Explain events read but left out by --since / --now (a silent drop reads as "no data")."""
    count = max(0, int(basis.excluded_by_window or 0))
    if count == 0 or (options.since is None and options.until is None):
        return
    cutoff, until = iso(options.since), iso(options.until)
    if options.since is not None and options.until is not None:
        _warn(basis, M("engine.window.both", count=count, cutoff=cutoff, until=until))
    elif options.since is not None:
        _warn(basis, M("engine.window.since", count=count, cutoff=cutoff))
    else:
        _warn(basis, M("engine.window.until", count=count, until=until))
    newest = basis.excluded_newest
    if newest is not None:
        _warn(basis, M("engine.window.newest", newest=iso(newest)))
    if options.since_relative and options.now is None and options.now_origin == "flag":
        example = (newest or basis.end or datetime.now(UTC)).strftime("%Y-%m-%d")
        _warn(basis, M("engine.window.tip", example=example))


def _query_api(
    tenant: TenantConfig, findings: list[Finding], ctx: _Context
) -> tuple[list[AgentInfo] | None, dict[str, Any] | None, Any]:
    """Agent inventory + manager stats from the Wazuh API. Failures become assessment findings, never zeros.

    The two queries are independent: statistics that cannot be read (older manager, missing ``manager:read``)
    never discard the agent inventory."""
    from .ingest.wazuh_api import WazuhAPI
    from .net import RemoteError

    assert tenant.wazuh_api is not None
    api: Any = None
    try:
        api = WazuhAPI(tenant.wazuh_api)
        with api:
            agents = api.agents()
            try:
                stats = api.daemon_stats()
            except (RemoteError, OSError) as exc:
                stats = None
                ctx.stats_missing = True
                ctx.notes.append(M("engine.stats_failed", error=_error_text(exc)))
            if stats is None:
                ctx.stats_missing = True
            return agents, stats, api
    except (RemoteError, OSError) as exc:
        ctx.api_failed = True
        findings.append(
            Finding(
                kind="assessment.incomplete",
                domain="assessment",
                title=M("engine.api_failed.title"),
                severity=Severity.HIGH,
                subject="wazuh-api",
                reasons=[M("engine.api_failed", error=_error_text(exc))],
            )
        )
        return None, None, api


def _error_text(exc: BaseException) -> Message | str:
    """The translatable message of a RemoteError (never a raw exception text with URLs or tokens)."""
    message = getattr(exc, "message", None)
    if isinstance(message, (Message, str)):
        return message
    return getattr(exc, "strerror", None) or type(exc).__name__


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
    """The dispositions CSV (only when noise runs). An unusable file is a configuration error, never ignored:
    silently dropping configured dispositions would drop the true-positive vetoes."""
    path = options.dispositions or tenant.dispositions
    if not path:
        return None
    from .analysis.dispositions import Dispositions

    try:
        return Dispositions.load(path, tenant=tenant.name)
    except OSError as exc:
        raise ConfigError(f"cannot read the dispositions file {path}: {exc.strerror or type(exc).__name__}") from None
    except (ValueError, UnicodeError) as exc:
        raise ConfigError(f"invalid dispositions file {path}: {str(exc)[:200]}") from None


def _emit(
    tenant: TenantConfig,
    suggestions: Iterable[Any],
    ruleset: Any,
    basis: DataBasis,
    out_dir: Path,
    today: date,
    findings: list[Finding],
    overwrite: bool = False,
) -> Any:
    """Write review-ready Wazuh rules for ``tune`` suggestions. Refused for non-Wazuh-4 data."""
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
    # tune suggestions become rules; index-volume-only ones are explained in VALIDATION.md (never written as rules)
    tune = [
        s for s in suggestions if getattr(s, "verdict", None) == "tune" or getattr(s, "impact", "") == "index_volume"
    ]
    try:
        result = emit_suppressions(
            tune,
            ruleset=ruleset,
            id_range=tenant.suppression_id_range,
            out_dir=out_dir,
            now=today,
            profile="wazuh4",
            overwrite=overwrite,
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
    skipped = [message for _, message in getattr(result, "skipped", [])]
    if skipped:
        findings.append(
            Finding(
                kind="noise.emit_skipped",
                domain="noise",
                title=M("engine.emit_skipped.title", count=len(skipped)),
                severity=Severity.INFO,
                subject="emit-skipped",
                reasons=list(skipped),
            )
        )
    notes = [w for w in result.warnings if w not in skipped]  # older emitters also listed skips as warnings
    if notes:
        findings.append(
            Finding(
                kind="noise.emit_notes",
                domain="noise",
                title=M("engine.emit_notes.title", count=len(notes)),
                severity=Severity.INFO,
                subject="emit-notes",
                reasons=list(notes),
            )
        )
    return result


def _empty_input(findings: list[Finding], basis: DataBasis) -> list[Finding]:
    """Zero events: one assessment finding with a title that says so (and why, when a window dropped them)."""
    excluded = max(0, int(basis.excluded_by_window or 0))
    title = M("engine.no_input.window_title", count=excluded) if excluded else M("engine.no_input.title")
    reasons: list[Message | str] = [
        w for w in basis.warnings if isinstance(w, Message) and w.key.startswith("engine.window.")
    ]
    out: list[Finding] = []
    done = False
    for f in findings:
        if not done and f.kind == "assessment.incomplete" and f.subject == "basis":
            out.append(replace(f, title=title, reasons=[*reasons, *f.reasons], severity=Severity.HIGH))
            done = True
        else:
            out.append(f)
    if not done:
        out.append(
            Finding(
                kind="assessment.incomplete",
                domain="assessment",
                title=title,
                severity=Severity.HIGH,
                subject="no-input",
                reasons=reasons,
            )
        )
    return out


def _unsupported_noise(wanted: frozenset[str], sections: dict[str, dict[str, Any]], basis: DataBasis) -> list[Finding]:
    """Noise requested on alert-like data where NO event carries a rule id: a mapping problem, not "no noise"."""
    section = sections.get("noise")
    if "noise" not in wanted or section is None or basis.events <= 0:
        return []
    skipped = int(section.get("skipped_events") or 0)
    if skipped < basis.events or str(basis.input_kind) in ("archives", "indexer-archives"):
        return []
    return [
        Finding(
            kind="assessment.incomplete",
            domain="assessment",
            title=M("engine.noise_no_rule.title", count=basis.events),
            severity=Severity.MEDIUM,
            subject="noise:no-rule-id",
            recommendation=M("engine.noise_no_rule.rec"),
        )
    ]


def _link(findings: list[Finding]) -> list[Finding]:
    """Cross-domain de-duplication (one incident = one finding; the others go to ``related``)."""
    try:
        from .analysis.correlate import link_findings
    except ImportError:  # the correlation module is optional
        return findings
    try:
        return list(link_findings(findings))
    except Exception as exc:  # never lose a report over grouping: unlinked findings are more, not fewer
        log.warning("correlating findings failed (%s); findings are reported ungrouped", type(exc).__name__)
        return findings


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


def requested_domains(wanted: Collection[str]) -> list[str]:
    """Report domains covered by the requested analyses."""
    return [d for d, analyses in _DOMAIN_ANALYSES.items() if any(a in wanted for a in analyses)]


def assess(
    findings: Sequence[Finding],
    sections: dict[str, dict[str, Any]],
    wanted: frozenset[str],
    basis: DataBasis,
    *,
    has_ruleset: bool,
    has_inventory: bool = True,
) -> dict[str, str]:
    """Per-domain status: fail (high/critical finding), warn (medium), ok, or not_assessed (grey).

    Never green without the evidence: the pipeline domain is not "ok" when silence/coverage ran without an agent
    inventory (disconnected agents cannot be seen), and silence is at most "warn" when its key cap truncated it.
    """
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
        section = sections.get(domain, {})
        if section.get("status") == "not_assessed":  # e.g. noise still learning, or no alerts to analyze
            status[domain] = "not_assessed"
            continue
        ranks = [f.severity.rank for f in findings if f.domain == domain]
        if any(r >= Severity.HIGH.rank for r in ranks):
            status[domain] = "fail"
        elif any(r >= Severity.MEDIUM.rank for r in ranks):
            status[domain] = "warn"
        else:
            status[domain] = "ok"
        if (
            status[domain] == "ok"
            and domain == "pipeline"
            and not has_inventory
            and ("silence" in wanted or "coverage" in wanted)
        ):
            status[domain] = "not_assessed"
        if status[domain] == "ok" and domain == "silence" and _silence_truncated(section):
            status[domain] = "warn"
        if status[domain] == "ok" and section.get("status") in ("warn", "fail"):
            status[domain] = str(section["status"])  # the analyzer knows more than its findings (e.g. unjudged gaps)
    incomplete = [f for f in findings if f.domain == "assessment" and f.severity.rank >= Severity.MEDIUM.rank]
    status["assessment"] = "fail" if (incomplete or not basis.complete) else "ok"
    return status


def _is_wazuh(basis: DataBasis) -> bool:
    return str(basis.profile) in ("wazuh4", "wazuh5", "unknown", "mixed")


def _silence_truncated(section: dict[str, Any]) -> bool:
    fields_section = section.get("fields")
    fields_truncated = isinstance(fields_section, dict) and bool(fields_section.get("truncated"))
    return bool(section.get("cube_truncated")) or fields_truncated


def _explain_not_evaluated(
    status: dict[str, str],
    wanted: frozenset[str],
    sections: dict[str, dict[str, Any]],
    basis: DataBasis,
    tenant: TenantConfig,
    has_ruleset: bool,
) -> None:
    """List every requested domain that could not be assessed in the data basis, with the reason when known."""
    if basis.events <= 0:
        return  # the no-input finding already says it all
    history = days_between(basis.start, basis.end)
    for domain in requested_domains(wanted):
        if domain == "pipeline":
            continue  # its missing parts are listed by name (agent inventory, API, manager stats)
        if domain == "silence" and status.get(domain) == "warn" and _silence_truncated(sections.get("silence", {})):
            _warn(basis, M("engine.skip.silence_truncated"))
            continue
        if status.get(domain) != "not_assessed":
            continue
        _mark(basis, domain)
        section = sections.get(domain, {})
        if domain == "tuning" and not has_ruleset:
            _warn(basis, M("engine.skip.tuning" if _is_wazuh(basis) else "engine.skip.tuning_generic"))
        elif domain == "noise" and int(section.get("skipped_events") or 0) >= basis.events:
            archives = str(basis.input_kind) in ("archives", "indexer-archives")
            _warn(
                basis,
                M("engine.skip.noise_archives") if archives else M("engine.skip.noise_no_rule", count=basis.events),
            )
        elif domain == "noise" and section.get("learning"):
            _warn(basis, M("engine.skip.noise_learning", days=tenant.noise.min_history_days))
        elif domain in ("silence", "coverage") and history < tenant.silence.min_history_days:
            days = tenant.silence.min_history_days
            _warn(basis, M("engine.skip.learning", domain=M(f"domain.{domain}"), days=days))
        else:
            _warn(basis, M("engine.skip.domain", domain=M(f"domain.{domain}")))


def _nothing_assessed(status: dict[str, str], wanted: frozenset[str]) -> Finding | None:
    """One policy for every command: when NOTHING the user asked for could be assessed, the run is incomplete.

    The pipeline domain (input sanity checks) only counts when it is the only thing requested."""
    domains = requested_domains(wanted)
    primary = [d for d in domains if d != "pipeline"] or domains
    if not primary or any(status.get(d) != "not_assessed" for d in primary):
        return None
    return Finding(
        kind="assessment.incomplete",
        domain="assessment",
        title=M("engine.nothing_assessed.title"),
        severity=Severity.MEDIUM,
        subject="nothing-assessed",
        reasons=[M("engine.nothing_assessed.reason", domains=[M(f"domain.{d}") for d in primary])],
    )


def unassessed_kinds(report: Report) -> frozenset[str]:
    """Finding kinds this report could not re-check even though their domain ran (for the cron lifecycle): the
    agent-connectivity kinds when there was no usable inventory, and learning when the run was incomplete."""
    kinds: set[str] = set()
    missing = set(report.data_basis.not_evaluated)
    if missing & {NOT_EVALUATED_API, NOT_EVALUATED_INVENTORY}:
        kinds |= INVENTORY_KINDS
    if report.assessment.get("assessment") == "fail" or report.data_basis.events <= 0:
        kinds.add("assessment.learning")
    return frozenset(kinds)


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
