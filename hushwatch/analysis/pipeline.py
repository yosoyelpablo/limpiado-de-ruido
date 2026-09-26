"""Pipeline health: is the SIEM itself ingesting, and can this run's conclusions be trusted?

* **Input completeness** — partial failures (shard failures, timeouts, auth errors), truncation (caps hit),
  zero events, unparseable timestamps or lines: ``assessment.incomplete`` (never a false green).
* **Clock skew** — events stamped in the future (``DataBasis.future_timestamps``): ``pipeline.clock_skew``.
* **Freshness** — the data ends long before the wall clock (an old export): an informational
  ``assessment.incomplete`` finding, because silence is then relative to the end of the data.
* **Manager drops** — Wazuh ``GET /manager/daemons/stats`` (and the legacy flat ``/manager/stats/analysisd`` /
  ``remoted`` shapes and state files): analysisd events dropped (full queues / EPS limit), remoted messages
  discarded, queues near full: ``pipeline.manager_drops``. Parsed defensively: unknown shapes are "not assessed".
* **Ingest lag** — per source, event origin time vs arrival (Wazuh ``data.win.system.systemTime`` or
  ``predecoder.timestamp`` vs the manager ``timestamp``; ECS ``@timestamp`` vs ``event.ingested``), sampled with a
  bounded reservoir (:class:`LagCollector`). p95 > 15 min is ``pipeline.lag``; a source clock ahead of the manager,
  or an exact whole-hour offset (timezone misconfiguration), is ``pipeline.clock_skew``. When five or more sources show
  the same problem it is reported once (a pipeline-wide root cause when most sources do), listing every source past
  its tier SLA and every critical one first.
"""

from __future__ import annotations

import math
import random
import re
from array import array
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone, tzinfo
from typing import Any

from ..config import TenantConfig
from ..i18n import Entity, M, Message, register
from ..inventory import AgentInfo
from ..models import Confidence, DataBasis, Event, Finding, Severity, fingerprint, get_path, sort_findings
from ..timeutil import UTC, humanize, iso, parse_ts

__all__ = [
    "LAG_MIN_SAMPLES",
    "LAG_P95_THRESHOLD_S",
    "DaemonHealth",
    "LagCollector",
    "PipelineResult",
    "analyze_pipeline",
    "lag_seconds",
    "parse_daemon_stats",
]

# ---- tunables ---------------------------------------------------------------------------------------------------

LAG_P95_THRESHOLD_S = 900.0  # p95 origin->arrival delay above this is a finding
LAG_MIN_SAMPLES = 20  # fewer samples per source: not assessed
SKEW_AHEAD_S = 300.0  # median lag below -5 min: the source clock is ahead
TZ_TOLERANCE_S = 120.0  # |median - k x 15 min| within this, with a tight spread: timezone offset
# Timezone-less syslog headers: the offset between the device's zone and the manager's is read from the LOW end of
# the lag distribution (lag is never negative, so its minimum is the offset plus the fastest transport delay) and
# only for offsets of at least 30 minutes. Using the median would erase a real backlog: a forwarder that ships
# every 30 minutes has a median lag of ~15 minutes, which looks like a quarter-hour zone.
NAIVE_TZ_ANCHOR_Q = 0.01
NAIVE_TZ_MIN_OFFSET_S = 1800.0
MAX_LAG_ABS_S = 5 * 366 * 86400.0  # |lag| beyond 5 years is garbage (bad year inference, hostile values)
STALE_AFTER = timedelta(hours=24)  # data ending longer ago than this is an old export
FUTURE_HIGH_SHARE = 0.05
FUTURE_MEDIUM_SHARE = 0.001
BAD_INPUT_SHARE = 0.01  # unparseable timestamps / lines above this share make the analysis incomplete
QUEUE_HIGH = 0.9
DROP_HIGH_RATIO = 0.001  # lost / received above this (or unknown) makes drops HIGH; below, MEDIUM
QUEUE_WARN = 0.7
GROUP_MIN_SOURCES = 5  # a problem on >= this many sources and >= GROUP_MIN_SHARE of them is one root cause
GROUP_MIN_SHARE = 0.5
MAX_SOURCE_FINDINGS = 50  # sources listed in a grouped finding's evidence (beyond-SLA / critical ones always)
MAX_CRITICAL_LISTED = 1000
# Fallback when the tenant's ``sla`` mapping omits a tier (a partial override must never loosen a critical SLA).
DEFAULT_SLA: dict[str, timedelta] = {
    "critical": timedelta(hours=4),
    "standard": timedelta(hours=24),
    "low": timedelta(hours=72),
}
MAX_NAME_LEN = 256
MAX_TEXT_LEN = 200
MAX_STATS_ITEMS = 64
MAX_STATS_DEPTH = 6
MAX_STATS_LEAVES = 2000
MAX_COUNTER = 1e15  # counters above this are garbage

register(
    {
        # input completeness ----------------------------------------------------------------------------------
        "pipeline.basis.incomplete.title": {
            "en": "Analysis incomplete: part of the data could not be assessed",
            "es": "Análisis incompleto: parte de los datos no se pudo evaluar",
        },
        "pipeline.basis.partial": {
            "en": "Partial failures while reading the input: {count} (e.g. {examples}). Silence and coverage may "
            "show gaps that are not real, and noise volumes are undercounted.",
            "es": "Fallos parciales al leer la entrada: {count} (p. ej. {examples}). Silencio y cobertura pueden "
            "mostrar huecos que no son reales, y los volúmenes de ruido quedan subestimados.",
        },
        "pipeline.basis.truncated": {
            "en": "The input was capped (event or key limits reached): volumes are undercounted and some sources "
            "may look silent or missing.",
            "es": "La entrada se recortó (se alcanzaron límites de eventos o claves): los volúmenes quedan "
            "subestimados y algunas fuentes pueden parecer silenciosas o ausentes.",
        },
        "pipeline.basis.no_events": {
            "en": "No events were read: noise, silence and coverage could not be assessed.",
            "es": "No se leyó ningún evento: no se pudo evaluar ruido, silencio ni cobertura.",
        },
        "pipeline.basis.bad_timestamps": {
            "en": "{count} {count:plural:event|events} ({share:.1%}) had unparseable timestamps and "
            "{count:plural:was|were} left out of time-based analyses.",
            "es": "{count} {count:plural:evento|eventos} ({share:.1%}) {count:plural:tenía|tenían} marcas de "
            "tiempo ilegibles y {count:plural:quedó|quedaron} fuera de los análisis temporales.",
        },
        "pipeline.basis.malformed": {
            "en": "{count} lines or documents ({share:.1%}) could not be parsed.",
            "es": "{count} líneas o documentos ({share:.1%}) no se pudieron interpretar.",
        },
        "pipeline.basis.not_evaluated": {
            "en": "Not evaluated with this input: {analyses}.",
            "es": "No evaluado con esta entrada: {analyses}.",
        },
        "pipeline.join.0": {"en": "-", "es": "-"},
        "pipeline.join.1": {"en": "{a}", "es": "{a}"},
        "pipeline.join.2": {"en": "{a}; {b}", "es": "{a}; {b}"},
        "pipeline.join.3": {"en": "{a}; {b}; {c}", "es": "{a}; {b}; {c}"},
        "pipeline.basis.sampled": {
            "en": "The input is a sample: the absence of a source or event type cannot be proven from it.",
            "es": "La entrada es una muestra: con ella no se puede demostrar la ausencia de una fuente o tipo de "
            "evento.",
        },
        "pipeline.basis.recommendation": {
            "en": "Fix the input problems and run again before relying on the absence of findings.",
            "es": "Corrija los problemas de la entrada y vuelva a ejecutar antes de confiar en la ausencia de "
            "hallazgos.",
        },
        # clock skew / freshness -----------------------------------------------------------------------------
        "pipeline.skew.title": {
            "en": "{count} {count:plural:event has a timestamp|events have timestamps} in the future (clock skew)",
            "es": "{count} {count:plural:evento tiene una marca|eventos tienen marcas} de tiempo en el futuro "
            "(desfase de reloj)",
        },
        "pipeline.skew.reason": {
            "en": "{count} of {events} events ({share:.2%}) are more than 5 minutes ahead of the wall clock. A "
            "source clock (NTP) or timezone setting is wrong, and future events can hide a real silence.",
            "es": "{count} de {events} eventos ({share:.2%}) van más de 5 minutos por delante del reloj real. Un "
            "reloj (NTP) o una zona horaria de origen están mal configurados, y los eventos futuros pueden ocultar "
            "un silencio real.",
        },
        "pipeline.skew.recommendation": {
            "en": "Check NTP on the sources and the timezone of timestamps without offset (input naive_timezone).",
            "es": "Revise NTP en los orígenes y la zona horaria de las marcas sin desplazamiento (naive_timezone de "
            "la entrada).",
        },
        "pipeline.stale.title": {
            "en": "Analyzing an old export: the data ends {age} before now",
            "es": "Se analiza una exportación antigua: los datos terminan {age} antes de ahora",
        },
        "pipeline.stale.reason": {
            "en": "The newest event is from {end}. Silence is measured relative to the end of the data, not to "
            "the current time, so anything that broke afterwards is not visible in this report.",
            "es": "El evento más reciente es de {end}. El silencio se mide respecto del final de los datos, no de "
            "la hora actual, así que lo que se haya roto después no aparece en este informe.",
        },
        "pipeline.stale.recommendation": {
            "en": "Analyze current data (or the live indexer) to know the present state.",
            "es": "Analice datos actuales (o el indexador en vivo) para conocer el estado presente.",
        },
        # manager daemons ------------------------------------------------------------------------------------
        "pipeline.drops.title.analysisd": {
            "en": "wazuh-analysisd dropped {dropped} {dropped:plural:event|events}: detection never saw them",
            "es": "wazuh-analysisd descartó {dropped} {dropped:plural:evento|eventos}: la detección nunca los vio",
        },
        "pipeline.drops.title.remoted": {
            "en": "wazuh-remoted discarded {dropped} messages from agents",
            "es": "wazuh-remoted descartó {dropped} mensajes de los agentes",
        },
        "pipeline.drops.title.queue": {
            "en": "{daemon} queue '{queue}' is {usage:.0%} full: drops are imminent",
            "es": "La cola '{queue}' de {daemon} está llena al {usage:.0%}: los descartes son inminentes",
        },
        "pipeline.drops.title.eps": {
            "en": "{daemon} hit its EPS limit for {seconds} seconds",
            "es": "{daemon} alcanzó su límite de EPS durante {seconds} segundos",
        },
        "pipeline.drops.title.sent": {
            "en": "wazuh-remoted discarded {count} messages to agents (send queue full)",
            "es": "wazuh-remoted descartó {count} mensajes hacia los agentes (cola de envío llena)",
        },
        "pipeline.drops.reason.analysisd": {
            "en": "{dropped} {dropped:plural:event was|events were} dropped because the analysis queues were "
            "full or the EPS limit was reached{top}.",
            "es": "Se {dropped:plural:descartó|descartaron} {dropped} {dropped:plural:evento|eventos} porque "
            "las colas de análisis estaban llenas o se alcanzó el límite de EPS{top}.",
        },
        "pipeline.drops.reason.top": {"en": "; mostly from {sources}", "es": "; sobre todo de {sources}"},
        "pipeline.drops.reason.remoted": {
            "en": "{dropped} messages received from agents were discarded because the remoted queue was full.",
            "es": "Se descartaron {dropped} mensajes recibidos de los agentes porque la cola de remoted estaba llena.",
        },
        "pipeline.drops.reason.sent": {
            "en": "{count} messages to agents (configuration, active response) were discarded.",
            "es": "Se descartaron {count} mensajes hacia los agentes (configuración, respuesta activa).",
        },
        "pipeline.drops.reason.eps": {
            "en": "The EPS limit was exceeded for {seconds} seconds; events queue up and arrive late.",
            "es": "Se superó el límite de EPS durante {seconds} segundos; los eventos se encolan y llegan tarde.",
        },
        "pipeline.drops.reason.queue": {
            "en": "Queue '{queue}' is at {usage:.0%} of its capacity.",
            "es": "La cola '{queue}' está al {usage:.0%} de su capacidad.",
        },
        "pipeline.drops.reason.cumulative": {
            "en": "Counters are cumulative since the daemon started ({uptime}).",
            "es": "Los contadores son acumulados desde que arrancó el demonio ({uptime}).",
        },
        "pipeline.drops.recommendation.analysisd": {
            "en": "Raise the analysisd queue sizes or the EPS limit (<global><limits><eps>), add analysis threads, "
            "and find the agents flooding the manager.",
            "es": "Aumente los tamaños de cola de analysisd o el límite de EPS (<global><limits><eps>), agregue "
            "hilos de análisis y localice los agentes que saturan el manager.",
        },
        "pipeline.drops.recommendation.remoted": {
            "en": "Increase <remote><queue_size> in ossec.conf and the remoted worker_pool in internal_options.conf.",
            "es": "Aumente <remote><queue_size> en ossec.conf y el worker_pool de remoted en internal_options.conf.",
        },
        # ingest lag / per-source clocks ---------------------------------------------------------------------
        "pipeline.lag.title": {
            "en": "{host}: events arrive {p95} late (p95)",
            "es": "{host}: los eventos llegan con {p95} de retraso (p95)",
        },
        "pipeline.lag.title.global": {
            "en": "Ingest lag on {count} of {total} sources: p95 above 15 minutes",
            "es": "Retraso de ingesta en {count} de {total} orígenes: p95 superior a 15 minutos",
        },
        "pipeline.lag.reason": {
            "en": "Origin-to-arrival delay over {samples} sampled events: median {p50}, p95 {p95}, max {max}.",
            "es": "Demora entre origen y llegada en {samples} eventos muestreados: mediana {p50}, p95 {p95}, "
            "máximo {max}.",
        },
        "pipeline.lag.reason.global": {
            "en": "Most sources are late at the same time, which points to a shared backlog (manager queues, "
            "indexer, Filebeat/Logstash) rather than to the sources. Worst: {hosts}.",
            "es": "La mayoría de los orígenes llegan tarde a la vez, lo que apunta a un atasco compartido (colas "
            "del manager, indexador, Filebeat/Logstash) más que a los orígenes. Los peores: {hosts}.",
        },
        "pipeline.lag.reason.global_generic": {
            "en": "Most sources are late at the same time, which points to a shared backlog (collectors, forwarders, "
            "ingest pipeline, indexer) rather than to the sources. Worst: {hosts}.",
            "es": "La mayoría de los orígenes llegan tarde a la vez, lo que apunta a un atasco compartido "
            "(recolectores, reenviadores, canalización de ingesta, indexador) más que a los orígenes. Los peores: "
            "{hosts}.",
        },
        "pipeline.lag.reason.sources": {
            "en": "These sources are late on their own rather than all at once, which is typical of hosts that are "
            "often offline (laptops, VPN) or of an overloaded forwarder; they are reported together. Worst: {hosts}.",
            "es": "Estos orígenes llegan tarde cada uno por su cuenta y no todos a la vez, algo típico de equipos que "
            "suelen estar desconectados (portátiles, VPN) o de un reenviador sobrecargado; se informan juntos. Los "
            "peores: {hosts}.",
        },
        "pipeline.lag.reason.beyond_sla": {
            "en": "{count} of them arrive later than their tier SLA allows: {hosts}.",
            "es": "{count} de ellos llegan más tarde de lo que permite el SLA de su nivel: {hosts}.",
        },
        "pipeline.lag.reason.critical": {
            "en": "Critical-tier sources affected: {hosts}.",
            "es": "Orígenes de nivel crítico afectados: {hosts}.",
        },
        "pipeline.lag.reason.constant": {
            "en": "The delay is nearly constant, which suggests the source clock is behind rather than a backlog.",
            "es": "La demora es casi constante, lo que sugiere que el reloj del origen está atrasado más que un "
            "atasco.",
        },
        "pipeline.lag.recommendation": {
            "en": "Check the agent buffer, network and forwarders for this source; for scheduled rules make the "
            "look-back cover the p95 delay.",
            "es": "Revise el buffer del agente, la red y los reenviadores de este origen; en reglas programadas, "
            "haga que la ventana de búsqueda cubra la demora p95.",
        },
        "pipeline.clock.ahead.title": {
            "en": "{host}: source clock is about {offset} ahead of the manager",
            "es": "{host}: el reloj del origen va unos {offset} adelantado respecto del manager",
        },
        "pipeline.clock.ahead.title.global": {
            "en": "{count} of {total} sources look {offset} ahead: the manager clock is probably behind",
            "es": "{count} de {total} orígenes parecen ir {offset} adelantados: probablemente el reloj del manager "
            "está atrasado",
        },
        "pipeline.clock.ahead.title.sources": {
            "en": "{count} of {total} sources have clocks ahead of the manager (median {offset})",
            "es": "{count} de {total} orígenes tienen el reloj adelantado respecto del manager (mediana {offset})",
        },
        "pipeline.clock.reason.hosts": {
            "en": "Sources ahead ({count}): {hosts}.",
            "es": "Orígenes adelantados ({count}): {hosts}.",
        },
        "pipeline.clock.tz.title": {
            "en": "{host}: timestamps are offset by exactly {hours} h (timezone misconfiguration)",
            "es": "{host}: las marcas de tiempo están desplazadas exactamente {hours} h (zona horaria mal configurada)",
        },
        "pipeline.clock.tz.title.global": {
            "en": "{count} of {total} sources are offset by exactly {hours} h (timezone misconfiguration)",
            "es": "{count} de {total} orígenes están desplazados exactamente {hours} h (zona horaria mal configurada)",
        },
        "pipeline.clock.reason": {
            "en": "Median origin-to-arrival difference {p50} over {samples} sampled events (spread p25-p75 {iqr}). "
            "Wrong clocks corrupt time windows and correlation and make sources look silent or bursty.",
            "es": "Diferencia mediana entre origen y llegada {p50} en {samples} eventos muestreados (dispersión "
            "p25-p75 {iqr}). Los relojes erróneos corrompen ventanas temporales y correlaciones, y hacen que los "
            "orígenes parezcan silenciosos o en ráfagas.",
        },
        "pipeline.clock.recommendation": {
            "en": "Enable NTP on the source (or the manager) and set the timezone of timestamps without offset.",
            "es": "Active NTP en el origen (o en el manager) y configure la zona horaria de las marcas sin "
            "desplazamiento.",
        },
    }
)


# ---- ingest lag sampling -------------------------------------------------------------------------------------------

_TZ_SUFFIX = re.compile(r"(?:[Zz]|[+-]\d{2}:?\d{2})$")
_OFFSET = re.compile(r"([+-])(\d{2}):?(\d{2})$")
_OFFSET_CACHE: dict[str, tzinfo | None] = {}  # "+0300"-style suffix -> tzinfo (bounded)
_HALF_YEAR = timedelta(days=183)


def lag_seconds(event: Event) -> float | None:
    """Arrival minus origin time, in seconds (positive: the event arrived late; negative: its clock is ahead).

    * Wazuh Windows: ``data.win.system.systemTime`` (UTC, set by the Windows host) vs ``event.ts`` (manager).
    * Wazuh syslog: ``predecoder.timestamp`` vs ``event.ts``. A classic syslog header has no timezone and no year:
      it is read in the manager's UTC offset (from the raw ``timestamp`` field) and in the year closest to the
      arrival. Without that offset the sample is skipped, never guessed. The result then includes any timezone
      difference between the device and the manager; :class:`LagCollector` removes such a constant offset.
    * ECS: ``event.ingested`` vs ``@timestamp``.

    Returns None when the event carries no usable origin time.
    """
    measured = _lag(event)
    return None if measured is None else measured[0]


def _lag(event: Event) -> tuple[float, bool] | None:
    """(lag, naive): ``naive`` when the origin time had no timezone (classic syslog header)."""
    fields = event.fields
    if not fields:
        return None
    raw = _field(fields, "data.win.system.systemTime")
    if raw is not None:
        return _pair(_diff(event.ts, _parse(raw)), naive=False)
    raw = _field(fields, "predecoder.timestamp")
    if raw is not None:
        origin, naive = _syslog_origin(raw, fields, event.ts)
        return _pair(_diff(event.ts, origin), naive=naive)
    ingested = _field(fields, "event.ingested")
    if ingested is not None:
        return _pair(_diff(_parse(ingested), _parse(_field(fields, "@timestamp"))), naive=False)
    return None


def _pair(lag: float | None, *, naive: bool) -> tuple[float, bool] | None:
    return None if lag is None else (lag, naive)


def _has_origin(fields: Mapping[str, Any]) -> bool:
    """Cheap pre-check (flattened keys first; nested documents take the slow path)."""
    if "data.win.system.systemTime" in fields or "predecoder.timestamp" in fields:
        return True
    if "event.ingested" in fields:
        return "@timestamp" in fields
    if "data" in fields or "predecoder" in fields or "event" in fields:
        return (
            _field(fields, "data.win.system.systemTime") is not None
            or _field(fields, "predecoder.timestamp") is not None
            or (_field(fields, "event.ingested") is not None and _field(fields, "@timestamp") is not None)
        )
    return False


def _parse(value: Any) -> datetime | None:
    if value is None or isinstance(value, (bool, list, tuple, dict)):
        return None
    if isinstance(value, str):
        if len(value) > 64:
            return None
        if value[:4].isdigit() and "-" in value[4:5]:
            try:  # fast path (Python >= 3.11 reads Z, +0000 and 7-digit fractions); parse_ts is the reference
                parsed = datetime.fromisoformat(value)
            except ValueError:
                return parse_ts(value)
            return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)
    return parse_ts(value)


def _syslog_origin(raw: Any, fields: Mapping[str, Any], arrival: datetime) -> tuple[datetime | None, bool]:
    if not isinstance(raw, str) or not raw.strip() or len(raw) > 64:
        return None, True
    text = raw.strip()
    if _TZ_SUFFIX.search(text) and text[:4].isdigit():  # ISO-8601 with an explicit offset: unambiguous
        return parse_ts(text), False
    offset = _manager_offset(fields)
    if offset is None:
        return None, True
    year = _aware(arrival).astimezone(offset).year
    origin = parse_ts(text, naive_tz=offset, default_year=year)
    if origin is not None and abs(origin - arrival) <= _HALF_YEAR:
        return origin, True
    # no year in the header: around New Year the event belongs to the neighbouring year
    best = origin
    for candidate_year in (year - 1, year + 1):
        candidate = parse_ts(text, naive_tz=offset, default_year=candidate_year)
        if candidate is not None and (best is None or abs(candidate - arrival) < abs(best - arrival)):
            best = candidate
    return best, True


def _manager_offset(fields: Mapping[str, Any]) -> tzinfo | None:
    """UTC offset of the manager, read from the raw Wazuh ``timestamp`` (``...+0300``)."""
    raw = fields.get("timestamp")
    if not isinstance(raw, str) or len(raw) > 64:
        return None
    text = raw.strip()
    if text.endswith(("Z", "z")):
        return UTC
    # the offset is fully determined by this suffix ("+0300" or "+03:00"), so it is a safe cache key
    suffix = text[-6:] if text[-3:-2] == ":" else text[-5:]
    if suffix in _OFFSET_CACHE:
        return _OFFSET_CACHE[suffix]
    offset: tzinfo | None = None
    match = _OFFSET.fullmatch(suffix)
    if match is not None:
        hours, minutes = int(match.group(2)), int(match.group(3))
        if hours <= 23 and minutes <= 59:
            delta = timedelta(hours=hours, minutes=minutes)
            offset = timezone(-delta if match.group(1) == "-" else delta)
    if len(_OFFSET_CACHE) < 256:
        _OFFSET_CACHE[suffix] = offset
    return offset


def _diff(arrival: datetime | None, origin: datetime | None) -> float | None:
    if arrival is None or origin is None:
        return None
    try:
        value = (_aware(arrival) - _aware(origin)).total_seconds()
    except (OverflowError, ValueError):
        return None
    if not math.isfinite(value) or abs(value) > MAX_LAG_ABS_S:
        return None
    return value


class LagCollector:
    """Per-source (``Event.source``) uniform reservoir of lag samples (:func:`lag_seconds`).

    Memory is bounded (``per_agent`` samples for at most ``max_agents`` sources) and the timestamp parsing cost is
    paid only for events that enter the reservoir (about ``k·(1 + ln(n/k))`` per source), so the collector stays
    cheap on multi-GB inputs. Sampling is seeded, hence deterministic for a given input order.

    Samples from timezone-less syslog headers are remembered as such: in :meth:`samples` the zone difference between
    the device and the manager (a multiple of 15 minutes, at least 30, read from the fastest 1% of the samples) is
    removed from them, so it is neither reported as lag nor as a clock problem, while a backlog is kept. Sources with
    explicit time zones keep their offsets, because there an offset is a real misconfiguration.
    """

    def __init__(self, *, per_agent: int = 256, max_agents: int = 10_000, seed: int = 20260925) -> None:
        self.per_agent = max(1, per_agent)
        self.max_agents = max(1, max_agents)
        self._rng = random.Random(seed)
        self._reservoirs: dict[str, array[float]] = {}
        self._naive: dict[str, bytearray] = {}  # parallel to _reservoirs: 1 = timezone-less origin
        self._seen: dict[str, int] = {}
        self.events = 0  # events offered
        self.with_origin = 0  # events carrying an origin timestamp
        self.unparseable = 0  # sampled events whose origin time could not be used
        self.agents_overflow = 0  # events of sources beyond max_agents
        self.tz_normalized: dict[str, float] = {}  # source -> hours removed from its naive samples (last samples())

    def add(self, event: Event) -> None:
        """Offer one event."""
        self.events += 1
        source = event.source
        fields = event.fields
        if not isinstance(source, str) or not source or not fields or not _has_origin(fields):
            return
        self.with_origin += 1
        if len(source) > MAX_NAME_LEN:
            source = source[:MAX_NAME_LEN]
        reservoir = self._reservoirs.get(source)
        if reservoir is None:
            if len(self._reservoirs) >= self.max_agents:
                self.agents_overflow += 1
                return
            reservoir = self._reservoirs[source] = array("d")
            self._naive[source] = bytearray()
        flags = self._naive[source]
        seen = self._seen.get(source, 0) + 1
        self._seen[source] = seen
        slot = -1
        if len(reservoir) >= self.per_agent:
            slot = self._rng.randrange(seen)
            if slot >= self.per_agent:
                return
        measured = _lag(event)
        if measured is None:
            self.unparseable += 1
            return
        lag, naive = measured
        if slot < 0:
            reservoir.append(lag)
            flags.append(1 if naive else 0)
        else:
            reservoir[slot] = lag
            flags[slot] = 1 if naive else 0

    def samples(self) -> dict[str, list[float]]:
        """Lag samples (seconds) per source, with the timezone offset of timezone-less samples removed."""
        out: dict[str, list[float]] = {}
        self.tz_normalized = {}
        for source, values in self._reservoirs.items():
            if not values:
                continue
            flags = self._flags(self, source, len(values))
            naive = [v for v, flag in zip(values, flags, strict=True) if flag]
            offset = _naive_offset(naive)
            if offset:
                self.tz_normalized[source] = offset / 3600.0
            out[source] = [v - offset if flag else v for v, flag in zip(values, flags, strict=True)]
        return out

    @staticmethod
    def _flags(collector: LagCollector, source: str, length: int) -> bytearray:
        flags = collector._naive.get(source)
        return flags if flags is not None and len(flags) == length else bytearray(length)

    def stats(self) -> dict[str, int]:
        """Counters for the DataBasis / section."""
        return {
            "events": self.events,
            "with_origin": self.with_origin,
            "unparseable": self.unparseable,
            "sources": len(self._reservoirs),
            "sources_overflow": self.agents_overflow,
        }

    def merge(self, other: LagCollector) -> None:
        """Fold ``other`` in, keeping each source's reservoir an (approximately) uniform sample of both."""
        self.events += other.events
        self.with_origin += other.with_origin
        self.unparseable += other.unparseable
        self.agents_overflow += other.agents_overflow
        for source, theirs in other._reservoirs.items():
            n_theirs = other._seen.get(source, len(theirs))
            mine = self._reservoirs.get(source)
            if mine is None:
                if len(self._reservoirs) >= self.max_agents:
                    self.agents_overflow += n_theirs
                    continue
                self._reservoirs[source] = array("d", theirs[: self.per_agent])
                self._naive[source] = self._flags(other, source, len(theirs))[: self.per_agent]
                self._seen[source] = n_theirs
                continue
            n_mine = self._seen.get(source, len(mine))
            total = n_mine + n_theirs
            pool_a = list(zip(mine, self._flags(self, source, len(mine)), strict=True))
            pool_b = list(zip(theirs, self._flags(other, source, len(theirs)), strict=True))
            merged: array[float] = array("d")
            merged_flags = bytearray()
            while len(merged) < self.per_agent and (pool_a or pool_b):
                take_a = bool(pool_a) and (not pool_b or self._rng.random() * total < n_mine)
                pool = pool_a if take_a else pool_b
                value, flag = pool.pop(self._rng.randrange(len(pool)))
                merged.append(value)
                merged_flags.append(flag)
            self._reservoirs[source] = merged
            self._naive[source] = merged_flags
            self._seen[source] = total


def _naive_offset(values: Sequence[float]) -> float:
    """The timezone offset (a multiple of 15 min, at least 30 min) of timezone-less samples, or 0.0.

    Anchored on the 1st percentile, not the median: the fastest events carry the zone difference plus almost no
    transport delay, while a backlog only adds to the upper part of the distribution, so it is never mistaken for
    (and erased as) a zone difference."""
    if len(values) < LAG_MIN_SAMPLES:
        return 0.0
    anchor = _quantile(sorted(values), NAIVE_TZ_ANCHOR_Q)
    offset = round(anchor / 900.0) * 900.0
    if abs(offset) >= NAIVE_TZ_MIN_OFFSET_S and abs(anchor - offset) <= TZ_TOLERANCE_S:
        return offset
    return 0.0


# ---- manager daemon stats -----------------------------------------------------------------------------------------


@dataclass(slots=True)
class DaemonHealth:
    """Loss and saturation counters of one Wazuh manager daemon, normalized from any known stats shape."""

    daemon: str  # wazuh-analysisd | wazuh-remoted
    node: str | None = None
    uptime: str | None = None
    legacy: bool = False  # flat /manager/stats/<daemon> or state-file shape
    dropped: float = 0.0  # analysisd: events lost; remoted: received messages discarded
    dropped_breakdown: dict[str, float] = field(default_factory=dict)  # analysisd: source -> events lost
    discarded_sent: float = 0.0  # remoted: messages to agents discarded
    received: float | None = None  # cumulative events / messages received (denominator of the loss ratio)
    eps_seconds_over_limit: float = 0.0
    queues: dict[str, float] = field(default_factory=dict)  # queue -> usage fraction (0..1)

    @property
    def fullest_queue(self) -> tuple[str, float] | None:
        if not self.queues:
            return None
        return max(self.queues.items(), key=lambda item: (item[1], item[0]))


def parse_daemon_stats(stats: Any) -> list[DaemonHealth]:
    """Normalize Wazuh daemon statistics into :class:`DaemonHealth` items (analysisd and remoted only).

    Accepted shapes: the full API response (``{"data": {"affected_items": [...]}}``), its ``data`` or
    ``affected_items`` part, a list of daemon items (``{"name": "wazuh-analysisd", "metrics": {...}}``), a mapping
    keyed by daemon name, and the legacy flat shapes (``events_dropped``, ``*_queue_usage``; ``discarded_count``,
    ``queue_size``/``total_queue_size``), with numbers or numeric strings. Anything else — including negative,
    non-finite or absurd counters — is ignored, never trusted.
    """
    out: list[DaemonHealth] = []
    for hint, item in _stat_items(stats, 0):
        daemon = _daemon_kind(item, hint)
        if daemon == "analysisd":
            out.append(_parse_analysisd(item))
        elif daemon == "remoted":
            out.append(_parse_remoted(item))
    return out


def _stat_items(stats: Any, depth: int) -> list[tuple[str | None, Mapping[str, Any]]]:
    if depth > 4:
        return []
    if isinstance(stats, list):
        return [(None, item) for item in stats[:MAX_STATS_ITEMS] if isinstance(item, Mapping)]
    if not isinstance(stats, Mapping):
        return []
    data = stats.get("data")
    if isinstance(data, (Mapping, list)):
        inner = _stat_items(data, depth + 1)
        if inner:
            return inner
    affected = stats.get("affected_items")
    if isinstance(affected, list):
        return _stat_items(affected, depth + 1)
    if "metrics" in stats or "name" in stats or _legacy_kind(stats) is not None:
        return [(None, stats)]
    items: list[tuple[str | None, Mapping[str, Any]]] = []
    for key, value in list(stats.items())[:MAX_STATS_ITEMS]:
        if not isinstance(key, str) or not isinstance(value, Mapping):
            continue
        if _daemon_from_text(key) is not None:
            items.append((key, value))
        elif "metrics" in value or "name" in value:  # e.g. wazuh_api's "daemon-<n>" key for a nameless item
            items.append((None, value))
    return items


def _daemon_from_text(text: Any) -> str | None:
    if not isinstance(text, str) or len(text) > 64:
        return None
    lowered = text.casefold()
    if "analysisd" in lowered:
        return "analysisd"
    if "remoted" in lowered:
        return "remoted"
    return None


def _legacy_kind(item: Mapping[str, Any]) -> str | None:
    keys = [k for k in list(item)[:500] if isinstance(k, str)]
    if "events_dropped" in keys or any(k.endswith("_queue_usage") for k in keys):
        return "analysisd"
    if "discarded_count" in keys or "total_queue_size" in keys or "evt_count" in keys:
        return "remoted"
    return None


def _daemon_kind(item: Mapping[str, Any], hint: str | None) -> str | None:
    for text in (item.get("name"), hint):
        kind = _daemon_from_text(text)
        if kind is not None:
            return kind
    if isinstance(item.get("name"), str):
        return None  # another daemon (wazuh-db...)
    metrics = item.get("metrics")
    if isinstance(metrics, Mapping):
        if "eps" in metrics or "events" in metrics:
            return "analysisd"
        if "messages" in metrics:
            return "remoted"
        return None
    return _legacy_kind(item)


def _parse_analysisd(item: Mapping[str, Any]) -> DaemonHealth:
    health = DaemonHealth("wazuh-analysisd", node=_node(item), uptime=_uptime(item.get("uptime")))
    metrics = item.get("metrics")
    if isinstance(metrics, Mapping):
        eps = metrics.get("eps")
        eps_total = 0.0
        if isinstance(eps, Mapping):
            eps_total = _num0(eps.get("events_dropped")) + _num0(eps.get("events_dropped_not_eps"))
            health.eps_seconds_over_limit = _num0(eps.get("seconds_over_limit"))
        leaves: dict[str, float] = {}
        _numeric_leaves(_path(metrics, "events", "received_breakdown", "dropped_breakdown"), "", leaves, 0)
        # each lost event bumps both its per-source counter and one EPS counter: never add them up
        health.dropped = max(eps_total, sum(leaves.values()))
        top = sorted(((k, v) for k, v in leaves.items() if v > 0), key=lambda kv: (-kv[1], kv[0]))
        health.dropped_breakdown = dict(top[:10])
        health.received = _num(_path(metrics, "events", "received"))
        queues = metrics.get("queues")
        if isinstance(queues, Mapping):
            for name, queue in list(queues.items())[:MAX_STATS_ITEMS]:
                if isinstance(name, str) and len(name) <= 64 and isinstance(queue, Mapping):
                    usage = _usage(queue.get("usage"), queue.get("size"), count=False)
                    if usage is not None:
                        health.queues[name] = usage
        return health
    health.legacy = True
    health.dropped = _num0(item.get("events_dropped"))
    for key, value in list(item.items())[:500]:
        if isinstance(key, str) and key.endswith("_queue_usage") and len(key) <= 64:
            name = key[: -len("_queue_usage")]
            usage = _usage(value, item.get(f"{name}_queue_size"), count=False)
            if usage is not None:
                health.queues[name] = usage
    return health


def _parse_remoted(item: Mapping[str, Any]) -> DaemonHealth:
    health = DaemonHealth("wazuh-remoted", node=_node(item), uptime=_uptime(item.get("uptime")))
    metrics = item.get("metrics")
    if isinstance(metrics, Mapping):
        health.dropped = _num0(_path(metrics, "messages", "received_breakdown", "discarded"))
        health.discarded_sent = _num0(_path(metrics, "messages", "sent_breakdown", "discarded"))
        health.received = _num(_path(metrics, "messages", "received_breakdown", "event"))
        received = _path(metrics, "queues", "received")
        if isinstance(received, Mapping):
            usage = _usage(received.get("usage"), received.get("size"), count=True)
            if usage is not None:
                health.queues["received"] = usage
        return health
    health.legacy = True
    health.dropped = _num0(item.get("discarded_count"))
    usage = _usage(item.get("queue_size"), item.get("total_queue_size"), count=True)
    if usage is not None:
        health.queues["received"] = usage
    return health


def _path(node: Any, *keys: str) -> Any:
    for key in keys:
        if not isinstance(node, Mapping):
            return None
        node = node.get(key)
    return node


def _numeric_leaves(node: Any, prefix: str, out: dict[str, float], depth: int) -> None:
    if not isinstance(node, Mapping) or depth > MAX_STATS_DEPTH:
        return
    for key, value in list(node.items())[:MAX_STATS_ITEMS]:
        if len(out) >= MAX_STATS_LEAVES or not isinstance(key, str) or len(key) > 64:
            continue
        name = key[: -len("_breakdown")] if key.endswith("_breakdown") else key
        path = f"{prefix}.{name}" if prefix else name
        if isinstance(value, Mapping):
            _numeric_leaves(value, path, out, depth + 1)
        else:
            number = _num(value)
            if number is not None:
                out[path] = number


def _num(value: Any) -> float | None:
    """A finite, non-negative, plausible counter, or None (bools, NaN, inf, negatives, junk strings...)."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        try:
            number = float(value)
        except OverflowError:
            return None
    elif isinstance(value, str):
        text = value.strip().strip("'\"")
        if not text or len(text) > 32:
            return None
        try:
            number = float(text)
        except ValueError:
            return None
    else:
        return None
    if not math.isfinite(number) or number < 0 or number > MAX_COUNTER:
        return None
    return number


def _num0(value: Any) -> float:
    number = _num(value)
    return 0.0 if number is None else number


def _usage(usage: Any, size: Any, *, count: bool) -> float | None:
    """Queue usage as a fraction. ``count`` means ``usage`` is a number of queued items (remoted); otherwise it is a
    fraction (analysisd), tolerated as a percentage when in (1, 100]."""
    value = _num(usage)
    capacity = _num(size)
    if value is None:
        return None
    if count:
        if capacity is None or capacity <= 0:
            return None
        fraction = value / capacity
    elif value <= 1.0:
        fraction = value
    elif value <= 100.0:
        fraction = value / 100.0
    elif capacity is not None and capacity > 0 and value <= capacity:
        fraction = value / capacity
    else:
        return None
    return fraction if 0.0 <= fraction <= 1.0 else None


def _node(item: Mapping[str, Any]) -> str | None:
    for key in ("node_name", "node"):
        value = item.get(key)
        if isinstance(value, str) and 0 < len(value.strip()) <= 128:
            return value.strip()
    return None


def _uptime(value: Any) -> str | None:
    if isinstance(value, str) and 0 < len(value) <= 64:
        parsed = parse_ts(value)
        return iso(parsed) if parsed is not None else None
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        parsed = parse_ts(value)
        return iso(parsed) if parsed is not None else None
    return None


# ---- analysis ---------------------------------------------------------------------------------------------------


@dataclass(slots=True)
class PipelineResult:
    findings: list[Finding]
    section: dict[str, Any]


def analyze_pipeline(
    basis: DataBasis,
    *,
    tenant: TenantConfig,
    now: datetime,
    daemon_stats: dict[str, Any] | None = None,
    lag_samples: dict[str, list[float]] | None = None,
    agents: list[AgentInfo] | None = None,
) -> PipelineResult:
    """Assess input completeness, clock skew, freshness, Wazuh manager drops and ingest lag.

    ``now`` is the wall clock (used for freshness). ``daemon_stats`` is the Wazuh ``/manager/daemons/stats``
    response in any known shape (see :func:`parse_daemon_stats`); ``lag_samples`` comes from
    :meth:`LagCollector.samples`; ``agents`` (optional) only feeds the agent status counts of the section.
    Returns findings and ``sections["pipeline"]``.
    """
    wall = _aware(now)
    findings: list[Finding] = []
    checks: list[dict[str, Any]] = []
    for check in (_basis_check(basis), _skew_check(basis), _freshness_check(basis, wall)):
        finding, row = check
        checks.append(row)
        if finding is not None:
            findings.append(finding)
    wazuh = _is_wazuh(basis)
    daemon_findings, daemon_row = _daemon_check(daemon_stats)
    findings.extend(daemon_findings)
    if wazuh or daemon_stats is not None:  # a Wazuh manager check means nothing for Elastic / generic input
        checks.append(daemon_row)
    lag_findings, lag_row = _lag_check(lag_samples, tenant, wazuh=wazuh)
    findings.extend(lag_findings)
    checks.append(lag_row)
    for finding in findings:
        # fingerprints are tenant-scoped: recompute now that the tenant is known
        finding.tenant = tenant.name
        finding.fingerprint = fingerprint(tenant.name, finding.kind, finding.subject)

    own = [f for f in findings if f.domain == "pipeline"]
    ran = basis.events > 0 or daemon_row["status"] != "not_assessed" or lag_row["status"] != "not_assessed"
    if not ran:
        status = "not_assessed"
    elif any(f.severity.rank >= Severity.HIGH.rank for f in own):
        status = "fail"
    elif any(f.severity.rank >= Severity.MEDIUM.rank for f in own):
        status = "warn"
    else:
        status = "ok"
    section = {"status": status, "agents": _agent_counts(agents), "checks": checks}
    return PipelineResult(findings=sort_findings(findings), section=section)


def _basis_check(basis: DataBasis) -> tuple[Finding | None, dict[str, Any]]:
    reasons: list[Message | str] = []
    triggers: list[str] = []
    severity: Severity | None = None
    # translatable messages (ingest / indexer / API failures) or plain strings
    failures = [p if isinstance(p, Message) else _clip(str(p)) for p in basis.partial_failures]
    if failures:
        triggers.append("partial_failures")
        reasons.append(M("pipeline.basis.partial", count=len(failures), examples=_joined(failures[:3])))
        severity = Severity.HIGH
    if basis.truncated:
        triggers.append("truncated")
        reasons.append(M("pipeline.basis.truncated"))
        severity = Severity.HIGH
    if basis.events <= 0:
        triggers.append("no_events")
        reasons.append(M("pipeline.basis.no_events"))
        severity = Severity.HIGH
    events = max(0, basis.events)
    bad = max(0, basis.bad_timestamps)
    bad_share = bad / (events + bad) if bad else 0.0
    if bad_share >= BAD_INPUT_SHARE:
        triggers.append("bad_timestamps")
        reasons.append(M("pipeline.basis.bad_timestamps", count=bad, share=bad_share))
        severity = severity or Severity.MEDIUM
    malformed = max(0, basis.malformed)
    malformed_share = malformed / (events + malformed) if malformed else 0.0
    if malformed_share >= BAD_INPUT_SHARE:
        triggers.append("malformed")
        reasons.append(M("pipeline.basis.malformed", count=malformed, share=malformed_share))
        severity = severity or Severity.MEDIUM
    row: dict[str, Any] = {
        "check": "input_completeness",
        "status": "fail" if severity is Severity.HIGH else "warn" if severity is not None else "ok",
        "events": basis.events,
        "partial_failures": len(failures),
        "truncated": basis.truncated,
        "sampled": basis.sampled,
        "bad_timestamps": bad,
        "malformed": malformed,
        "not_evaluated": list(basis.not_evaluated),
        "input_kind": basis.input_kind,
    }
    if severity is None:
        return None, row
    if basis.not_evaluated:
        reasons.append(M("pipeline.basis.not_evaluated", analyses=", ".join(map(str, basis.not_evaluated))))
    if basis.sampled:
        reasons.append(M("pipeline.basis.sampled"))
    finding = Finding(
        kind="assessment.incomplete",
        domain="assessment",
        title=M("pipeline.basis.incomplete.title"),
        severity=severity,
        subject="basis",
        reasons=reasons,
        evidence={
            "triggers": triggers,
            "events": basis.events,
            "partial_failures": len(failures),
            "partial_failure_examples": failures[:5],
            "truncated": basis.truncated,
            "sampled": basis.sampled,
            "bad_timestamps": bad,
            "malformed": malformed,
            "not_evaluated": list(basis.not_evaluated),
        },
        recommendation=M("pipeline.basis.recommendation"),
        confidence=Confidence.HIGH,
    )
    return finding, row


def _joined(items: Sequence[Message | str]) -> Message:
    """Up to three messages (or texts) as one "a; b; c" message (rendered in the report's language)."""
    names = ("a", "b", "c")
    shown = list(items[:3])
    return M(f"pipeline.join.{len(shown)}", **dict(zip(names, shown, strict=False)))


def _skew_check(basis: DataBasis) -> tuple[Finding | None, dict[str, Any]]:
    future = max(0, basis.future_timestamps)
    share = future / basis.events if basis.events > 0 else (1.0 if future else 0.0)
    row: dict[str, Any] = {"check": "clock_skew", "future_timestamps": future, "share": round(share, 6)}
    if future == 0:
        row["status"] = "ok" if basis.events > 0 else "not_assessed"
        return None, row
    if share >= FUTURE_HIGH_SHARE:
        severity = Severity.HIGH
    elif share >= FUTURE_MEDIUM_SHARE:
        severity = Severity.MEDIUM
    else:
        severity = Severity.LOW
    row["status"] = "fail" if severity is Severity.HIGH else "warn"
    finding = Finding(
        kind="pipeline.clock_skew",
        domain="pipeline",
        title=M("pipeline.skew.title", count=future),
        severity=severity,
        subject="basis:future_timestamps",
        reasons=[M("pipeline.skew.reason", count=future, events=basis.events, share=min(share, 1.0))],
        evidence={"future_timestamps": future, "events": basis.events, "share": round(share, 6)},
        recommendation=M("pipeline.skew.recommendation"),
        confidence=Confidence.HIGH,
        score=float(future),
    )
    return finding, row


def _freshness_check(basis: DataBasis, wall: datetime) -> tuple[Finding | None, dict[str, Any]]:
    end = basis.now if isinstance(basis.now, datetime) else None
    row: dict[str, Any] = {
        "check": "freshness",
        "data_end": iso(_aware(end)) if end else None,
        "now_origin": basis.now_origin,
    }
    if end is None:
        row["status"] = "not_assessed"
        return None, row
    age = wall - _aware(end)
    row["age_hours"] = round(age.total_seconds() / 3600.0, 1)
    if basis.now_origin != "data" or age <= STALE_AFTER:
        row["status"] = "ok"
        return None, row
    row["status"] = "warn"
    finding = Finding(
        kind="assessment.incomplete",
        domain="assessment",
        title=M("pipeline.stale.title", age=humanize(age)),
        severity=Severity.INFO,
        subject="basis:stale",
        reasons=[M("pipeline.stale.reason", end=iso(_aware(end)) or "?")],
        evidence={"data_end": iso(_aware(end)), "age_hours": row["age_hours"], "now_origin": basis.now_origin},
        recommendation=M("pipeline.stale.recommendation"),
        confidence=Confidence.HIGH,
    )
    return finding, row


def _daemon_check(daemon_stats: Any) -> tuple[list[Finding], dict[str, Any]]:
    row: dict[str, Any] = {"check": "manager_daemons", "daemons": []}
    if daemon_stats is None:
        row["status"] = "not_assessed"
        row["reason"] = "no_stats"
        return [], row
    healths = parse_daemon_stats(daemon_stats)
    if not healths:
        row["status"] = "not_assessed"
        row["reason"] = "unrecognized_shape"
        return [], row
    findings: list[Finding] = []
    worst = "ok"
    seen: set[tuple[str, str | None]] = set()
    for health in healths:
        if (health.daemon, health.node) in seen:
            continue  # the same daemon twice (hostile or duplicated input): one subject, one finding
        seen.add((health.daemon, health.node))
        finding = _daemon_finding(health)
        fullest = health.fullest_queue
        state = "ok"
        if finding is not None:
            findings.append(finding)
            state = "fail" if finding.severity.rank >= Severity.HIGH.rank else "warn"
        elif fullest is not None and fullest[1] >= QUEUE_WARN:
            state = "warn"
        worst = max(worst, state, key=lambda s: ("ok", "warn", "fail").index(s))
        row["daemons"].append(
            {
                "daemon": health.daemon,
                "node": Entity("host", health.node) if health.node else None,
                "status": state,
                "dropped": int(health.dropped),
                "discarded_sent": int(health.discarded_sent),
                "eps_seconds_over_limit": int(health.eps_seconds_over_limit),
                "fullest_queue": {"queue": fullest[0], "usage": round(fullest[1], 4)} if fullest else None,
                "uptime": health.uptime,
                "legacy": health.legacy,
            }
        )
    row["status"] = worst
    return findings, row


def _daemon_finding(health: DaemonHealth) -> Finding | None:
    reasons: list[Message | str] = []
    title: Message | None = None
    severity: Severity | None = None
    analysisd = health.daemon == "wazuh-analysisd"
    dropped = int(health.dropped)
    fullest = health.fullest_queue
    ratio = health.dropped / (health.dropped + health.received) if health.received is not None and dropped else None
    if dropped > 0:
        severity = Severity.HIGH if ratio is None or ratio >= DROP_HIGH_RATIO else Severity.MEDIUM
        if analysisd:
            title = M("pipeline.drops.title.analysisd", dropped=dropped)
            top: Message | str = ""
            if health.dropped_breakdown:
                top = M("pipeline.drops.reason.top", sources=", ".join(list(health.dropped_breakdown)[:3]))
            reasons.append(M("pipeline.drops.reason.analysisd", dropped=dropped, top=top))
        else:
            title = M("pipeline.drops.title.remoted", dropped=dropped)
            reasons.append(M("pipeline.drops.reason.remoted", dropped=dropped))
    if fullest is not None and fullest[1] >= QUEUE_HIGH:
        reasons.append(M("pipeline.drops.reason.queue", queue=fullest[0], usage=fullest[1]))
        if title is None:
            title = M("pipeline.drops.title.queue", daemon=health.daemon, queue=fullest[0], usage=fullest[1])
            severity = Severity.MEDIUM
    seconds = int(health.eps_seconds_over_limit)
    if seconds > 0:
        reasons.append(M("pipeline.drops.reason.eps", seconds=seconds))
        if title is None:
            title = M("pipeline.drops.title.eps", daemon=health.daemon, seconds=seconds)
            severity = Severity.MEDIUM
    sent = int(health.discarded_sent)
    if sent > 0:
        reasons.append(M("pipeline.drops.reason.sent", count=sent))
        if title is None:
            title = M("pipeline.drops.title.sent", count=sent)
            severity = Severity.LOW
    if title is None or severity is None:
        return None
    if health.uptime and (dropped > 0 or sent > 0 or seconds > 0):
        reasons.append(M("pipeline.drops.reason.cumulative", uptime=health.uptime))
    subject = f"daemon:{health.daemon}" + (f"|node:{health.node}" if health.node else "")
    return Finding(
        kind="pipeline.manager_drops",
        domain="pipeline",
        title=title,
        severity=severity,
        subject=subject,
        reasons=reasons,
        evidence={
            "check": "manager_daemons",
            "daemon": health.daemon,
            "node": Entity("host", health.node) if health.node else None,
            "dropped": dropped,
            "dropped_breakdown": {k: int(v) for k, v in health.dropped_breakdown.items()},
            "discarded_sent": sent,
            "received": int(health.received) if health.received is not None else None,
            "loss_ratio": float(f"{ratio:.3g}") if ratio is not None else None,
            "eps_seconds_over_limit": seconds,
            "queues": {k: round(v, 4) for k, v in sorted(health.queues.items())},
            "uptime": health.uptime,
            "legacy_format": health.legacy,
        },
        recommendation=M(
            "pipeline.drops.recommendation.analysisd" if analysisd else "pipeline.drops.recommendation.remoted"
        ),
        confidence=Confidence.HIGH,
        score=float(dropped),
    )


# ---- lag ----------------------------------------------------------------------------------------------------------


@dataclass(slots=True)
class _LagProfile:
    source: str
    samples: int
    p25: float
    p50: float
    p75: float
    p95: float
    maximum: float
    kind: str  # ok | lag | ahead | tz_offset
    offset_hours: float = 0.0

    @property
    def entity(self) -> Entity:
        return Entity("host", self.source)


def _profile(source: str, values: Sequence[Any]) -> _LagProfile | None:
    clean = sorted(
        float(v)
        for v in values[:100_000]
        if isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v) and abs(v) <= MAX_LAG_ABS_S
    )
    if len(clean) < LAG_MIN_SAMPLES:
        return None
    p25, p50, p75, p95 = (_quantile(clean, q) for q in (0.25, 0.5, 0.75, 0.95))
    profile = _LagProfile(source, len(clean), p25, p50, p75, p95, clean[-1], "ok")
    nearest = round(p50 / 900.0) * 900.0  # every real UTC offset is a multiple of 15 minutes
    if abs(nearest) >= 3600.0 and abs(p50 - nearest) <= TZ_TOLERANCE_S and (p75 - p25) <= 2 * TZ_TOLERANCE_S:
        profile.kind = "tz_offset"
        profile.offset_hours = nearest / 3600.0
    elif p50 < -SKEW_AHEAD_S:
        profile.kind = "ahead"
    elif p95 > LAG_P95_THRESHOLD_S:
        profile.kind = "lag"
    return profile


def _is_wazuh(basis: DataBasis) -> bool:
    """Whether the input comes from Wazuh (Wazuh-specific checks and advice apply). Mixed or unknown input keeps
    them: it may be Wazuh."""
    return basis.profile in ("wazuh4", "wazuh5", "mixed", "unknown") or basis.input_kind == "mixed"


def _lag_check(lag_samples: Any, tenant: TenantConfig, *, wazuh: bool = True) -> tuple[list[Finding], dict[str, Any]]:
    row: dict[str, Any] = {"check": "ingest_lag", "threshold_seconds": LAG_P95_THRESHOLD_S}
    profiles: list[_LagProfile] = []
    if isinstance(lag_samples, Mapping):
        for source, values in lag_samples.items():
            if isinstance(source, str) and source and isinstance(values, (list, tuple, array)):
                profile = _profile(source[:MAX_NAME_LEN], values)
                if profile is not None:
                    profiles.append(profile)
    total = len(profiles)
    row["sources_assessed"] = total
    if total == 0:
        row["status"] = "not_assessed"
        return [], row
    profiles.sort(key=lambda p: (-p.p95, p.source))
    lagging = [p for p in profiles if p.kind == "lag"]
    ahead = [p for p in profiles if p.kind == "ahead"]
    offsets: dict[float, list[_LagProfile]] = {}
    for p in profiles:
        if p.kind == "tz_offset":
            offsets.setdefault(p.offset_hours, []).append(p)
    findings: list[Finding] = []
    findings.extend(_lag_findings(lagging, total, tenant, wazuh=wazuh))
    findings.extend(_ahead_findings(ahead, total))
    for hours, members in sorted(offsets.items()):
        findings.extend(_tz_findings(hours, members, total))
    row.update(
        {
            "status": "fail"
            if any(f.severity.rank >= Severity.HIGH.rank for f in findings)
            else "warn"
            if findings
            else "ok",
            "lagging": len(lagging),
            "clock_ahead": len(ahead),
            "tz_offset": sum(len(v) for v in offsets.values()),
            "worst": [
                {
                    "agent": p.entity,
                    "samples": p.samples,
                    "p50_seconds": round(p.p50, 1),
                    "p95_seconds": round(p.p95, 1),
                    "kind": p.kind,
                }
                for p in profiles[:10]
            ],
        }
    )
    return findings, row


def _is_global(count: int, total: int) -> bool:
    return count >= GROUP_MIN_SOURCES and count >= GROUP_MIN_SHARE * total


_TIER_RANK = {"critical": 0, "standard": 1, "low": 2}


def _tier_sla(tenant: TenantConfig, tier: str) -> timedelta:
    """The tier's SLA; a tier missing from a partial ``sla`` override falls back to its built-in default."""
    value = tenant.sla.get(tier) if isinstance(tenant.sla, Mapping) else None
    if isinstance(value, timedelta) and value.total_seconds() >= 0:
        return value
    return DEFAULT_SLA.get(tier, DEFAULT_SLA["standard"])


def _lag_findings(lagging: list[_LagProfile], total: int, tenant: TenantConfig, *, wazuh: bool) -> list[Finding]:
    if not lagging:
        return []

    def tier(p: _LagProfile) -> str:
        return tenant.tier_for(p.source)

    def beyond_sla(p: _LagProfile) -> bool:
        return p.p95 > _tier_sla(tenant, tier(p)).total_seconds()

    if len(lagging) >= GROUP_MIN_SOURCES:
        # One finding, not one per source: either a shared backlog (most sources late together) or many sources
        # that are late on their own (laptops on VPN, busy forwarders). Sources past their tier SLA and critical
        # ones come first in the evidence so a grouped finding never buries them.
        shared = _is_global(len(lagging), total)
        ordered = sorted(lagging, key=lambda p: (not beyond_sla(p), _TIER_RANK.get(tier(p), 1), -p.p95, p.source))
        late = [p.entity for p in ordered if beyond_sla(p)]
        critical = [p.entity for p in ordered if tier(p) == "critical"]
        reasons: list[Message | str] = [
            M(
                ("pipeline.lag.reason.global" if wazuh else "pipeline.lag.reason.global_generic")
                if shared
                else "pipeline.lag.reason.sources",
                hosts=[p.entity for p in ordered[:5]],
            )
        ]
        if late:
            reasons.append(M("pipeline.lag.reason.beyond_sla", count=len(late), hosts=late[:10]))
        if critical:
            reasons.append(M("pipeline.lag.reason.critical", hosts=critical[:MAX_CRITICAL_LISTED]))
        keep = max(MAX_SOURCE_FINDINGS, min(len(late) + len(critical), MAX_CRITICAL_LISTED))
        return [
            Finding(
                kind="pipeline.lag",
                domain="pipeline",
                title=M("pipeline.lag.title.global", count=len(lagging), total=total),
                severity=Severity.HIGH if late or (shared and len(lagging) == total) else Severity.MEDIUM,
                subject="lag:global" if shared else "lag:sources",
                reasons=reasons,
                evidence={
                    "sources": [_lag_evidence(p) for p in ordered[:keep]],
                    "sources_lagging": len(lagging),
                    "sources_assessed": total,
                    "sources_beyond_sla": late[:MAX_CRITICAL_LISTED],
                    "critical_sources": critical[:MAX_CRITICAL_LISTED],
                    "shared_backlog": shared,
                    "threshold_seconds": LAG_P95_THRESHOLD_S,
                },
                recommendation=M("pipeline.lag.recommendation"),
                confidence=Confidence.MEDIUM,
                score=float(len(lagging)),
            )
        ]
    findings: list[Finding] = []
    for p in lagging:
        reasons = [M("pipeline.lag.reason", samples=p.samples, p50=_dur(p.p50), p95=_dur(p.p95), max=_dur(p.maximum))]
        if p.p75 - p.p25 <= 2 * TZ_TOLERANCE_S and p.p50 > LAG_P95_THRESHOLD_S:
            reasons.append(M("pipeline.lag.reason.constant"))
        findings.append(
            Finding(
                kind="pipeline.lag",
                domain="pipeline",
                title=M("pipeline.lag.title", host=p.entity, p95=_dur(p.p95)),
                severity=Severity.HIGH if beyond_sla(p) else Severity.MEDIUM,
                subject=f"agent:{p.source}",
                reasons=reasons,
                evidence={**_lag_evidence(p), "threshold_seconds": LAG_P95_THRESHOLD_S},
                recommendation=M("pipeline.lag.recommendation"),
                confidence=Confidence.MEDIUM,
                score=p.p95,
            )
        )
    return findings


def _ahead_findings(ahead: list[_LagProfile], total: int) -> list[Finding]:
    if not ahead:
        return []
    ahead = sorted(ahead, key=lambda p: (p.p50, p.source))
    if len(ahead) >= GROUP_MIN_SOURCES:
        shared = _is_global(len(ahead), total)
        median = _quantile(sorted(-p.p50 for p in ahead), 0.5)
        return [
            Finding(
                kind="pipeline.clock_skew",
                domain="pipeline",
                title=M(
                    "pipeline.clock.ahead.title.global" if shared else "pipeline.clock.ahead.title.sources",
                    count=len(ahead),
                    total=total,
                    offset=_dur(median),
                ),
                severity=Severity.MEDIUM,
                subject="clock:ahead:global" if shared else "clock:ahead:sources",
                reasons=[
                    M("pipeline.clock.reason", p50=_dur(-median), samples=sum(p.samples for p in ahead), iqr="-"),
                    M("pipeline.clock.reason.hosts", hosts=[p.entity for p in ahead[:10]], count=len(ahead)),
                ],
                evidence={
                    "sources": [_lag_evidence(p) for p in ahead[:MAX_SOURCE_FINDINGS]],
                    "sources_ahead": len(ahead),
                    "sources_assessed": total,
                    "shared_cause": shared,
                },
                recommendation=M("pipeline.clock.recommendation"),
                confidence=Confidence.MEDIUM,
                score=float(len(ahead)),
            )
        ]
    return [
        Finding(
            kind="pipeline.clock_skew",
            domain="pipeline",
            title=M("pipeline.clock.ahead.title", host=p.entity, offset=_dur(-p.p50)),
            severity=Severity.MEDIUM,
            subject=f"agent:{p.source}",
            reasons=[M("pipeline.clock.reason", p50=_dur(p.p50), samples=p.samples, iqr=_dur(p.p75 - p.p25))],
            evidence=_lag_evidence(p),
            recommendation=M("pipeline.clock.recommendation"),
            confidence=Confidence.MEDIUM,
            score=-p.p50,
        )
        for p in ahead
    ]


def _tz_findings(hours: float, members: list[_LagProfile], total: int) -> list[Finding]:
    label = f"{hours:+g}"
    # sources sharing the exact same offset are one root cause (a device group, collector or manager setting)
    if len(members) >= GROUP_MIN_SOURCES:
        return [
            Finding(
                kind="pipeline.clock_skew",
                domain="pipeline",
                title=M("pipeline.clock.tz.title.global", count=len(members), total=total, hours=label),
                severity=Severity.MEDIUM,
                subject=f"clock:tz_offset:{label}",
                reasons=[
                    M(
                        "pipeline.clock.reason",
                        p50=_dur(hours * 3600.0),
                        samples=sum(p.samples for p in members),
                        iqr="-",
                    )
                ],
                evidence={
                    "offset_hours": hours,
                    "sources": [_lag_evidence(p) for p in members[:50]],
                    "sources_offset": len(members),
                    "sources_assessed": total,
                },
                recommendation=M("pipeline.clock.recommendation"),
                confidence=Confidence.HIGH,
                score=float(len(members)),
            )
        ]
    return [
        Finding(
            kind="pipeline.clock_skew",
            domain="pipeline",
            title=M("pipeline.clock.tz.title", host=p.entity, hours=label),
            severity=Severity.MEDIUM,
            subject=f"agent:{p.source}|tz_offset",
            reasons=[M("pipeline.clock.reason", p50=_dur(p.p50), samples=p.samples, iqr=_dur(p.p75 - p.p25))],
            evidence={**_lag_evidence(p), "offset_hours": hours},
            recommendation=M("pipeline.clock.recommendation"),
            confidence=Confidence.HIGH,
            score=abs(p.p50),
        )
        for p in members[:MAX_SOURCE_FINDINGS]
    ]


def _lag_evidence(p: _LagProfile) -> dict[str, Any]:
    return {
        "agent": p.entity,
        "samples": p.samples,
        "p25_seconds": round(p.p25, 1),
        "p50_seconds": round(p.p50, 1),
        "p75_seconds": round(p.p75, 1),
        "p95_seconds": round(p.p95, 1),
        "max_seconds": round(p.maximum, 1),
    }


# ---- helpers ------------------------------------------------------------------------------------------------------


def _agent_counts(agents: Sequence[AgentInfo] | None) -> dict[str, int]:
    if not agents:
        return {}
    counts: dict[str, int] = {"total": 0}
    for agent in agents:
        if not isinstance(agent, AgentInfo) or agent.is_manager:
            continue
        status = agent.status if isinstance(agent.status, str) and 0 < len(agent.status) <= 32 else "unknown"
        counts[status] = counts.get(status, 0) + 1
        counts["total"] += 1
    return counts


def _quantile(values: Sequence[float], q: float) -> float:
    """Linear-interpolation quantile of an already sorted, non-empty sequence."""
    pos = (len(values) - 1) * q
    lower = math.floor(pos)
    upper = min(lower + 1, len(values) - 1)
    return values[lower] + (values[upper] - values[lower]) * (pos - lower)


def _dur(seconds: float) -> str:
    """Signed, human-readable duration ("1h 5m", "-7m", "45s")."""
    if not math.isfinite(seconds):
        return "?"
    return humanize(timedelta(seconds=round(seconds)))


def _clip(text: str) -> str:
    cleaned = "".join(ch if ch.isprintable() else " " for ch in text[: MAX_TEXT_LEN * 2])
    return cleaned[:MAX_TEXT_LEN] + ("…" if len(cleaned) > MAX_TEXT_LEN else "")


def _field(fields: Mapping[str, Any], path: str) -> Any:
    value = fields.get(path)
    if value is None and path.split(".", 1)[0] in fields:
        value = get_path(fields, path)
    return value


def _aware(ts: datetime) -> datetime:
    return ts.replace(tzinfo=UTC) if ts.tzinfo is None else ts
