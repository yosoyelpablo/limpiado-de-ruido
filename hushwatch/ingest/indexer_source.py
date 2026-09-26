"""EventSource over a Wazuh indexer / OpenSearch / Elasticsearch index pattern.

Streams documents with :meth:`IndexerClient.stream` (PIT or scroll, always released), normalizes them with the
same profiles as file input and builds a :class:`DataBasis` per pass. Remote problems (shard failures, timeouts,
truncation, a connection or authentication failure in the middle of the pass) are folded into the basis so they
surface as an incomplete assessment, never as zeros and never as a crash.
"""

from __future__ import annotations

from collections.abc import Collection, Iterator
from datetime import datetime, timedelta
from itertools import chain
from typing import Any

from ..config import InputConfig, TenantConfig
from ..i18n import M, register
from ..models import DataBasis, Event
from ..net import RemoteError, safe_url
from ..timeutil import UTC, iso
from .opensearch import IndexerClient
from .profiles import bind, detect_profile

DETECT_SAMPLE = 50
FUTURE_TOLERANCE = timedelta(minutes=5)

register(
    {
        "indexer_source.alerts_only": {
            "en": "Input is an alerts index: it contains only events that matched a rule at or above the alert "
            "threshold, so silence here is alert silence. Point hushwatch at the archives index for full "
            "log-source silence detection.",
            "es": "La entrada es un índice de alertas: contiene solo eventos que dispararon una regla por encima del "
            "umbral, así que el silencio aquí es silencio de alertas. Use el índice de archives para detectar "
            "el silencio real de las fuentes de logs.",
        },
        "indexer_source.window": {
            "en": "Indexer query window: {start} to {end} (set --since / --now to change it).",
            "es": "Ventana consultada en el indexer: {start} a {end} (use --since / --now para cambiarla).",
        },
        "indexer_source.interrupted": {
            "en": "Reading the indexer stopped after {events} events: {error}",
            "es": "La lectura del indexer se detuvo tras {events} eventos: {error}",
        },
    }
)


class IndexerEventSource:
    """Re-iterable EventSource backed by an index pattern. Each iteration re-queries the indexer.

    The query window ends at ``options.until``, else ``options.now`` (``--now``: "as of"), else the wall clock; it
    starts at ``options.since`` or one baseline + window + a day before the end. A remote failure in the middle of
    a pass (connection lost, authentication, a lost PIT) ends the pass: the events read so far are kept and the
    failure is recorded in ``basis.partial_failures``, so the report is incomplete (exit 3), never silently short.
    """

    def __init__(
        self,
        cfg: InputConfig,
        *,
        tenant: TenantConfig,
        options: Any,
        client: IndexerClient | None = None,
        wallclock: datetime | None = None,
    ) -> None:
        self.cfg = cfg
        self.tenant = tenant
        self.client = client or IndexerClient(cfg)
        wall = wallclock or datetime.now(UTC)
        default_span = tenant.silence.baseline + tenant.silence.window + timedelta(days=1)
        self.end: datetime = getattr(options, "until", None) or getattr(options, "now", None) or wall
        self.start: datetime = getattr(options, "since", None) or (self.end - default_span)
        self.max_events: int | None = getattr(options, "max_events", None) or cfg.max_events
        requested = getattr(options, "profile", "auto")
        self.profile = cfg.profile if requested == "auto" else requested
        self._wall = wall
        self._resolved_profile: str | None = None
        self.basis = DataBasis(input_kind=self._input_kind(), profile=self.profile, sources=[self._label()])

    def close(self) -> None:
        """Release the HTTP client (and any open PIT/scroll)."""
        self.client.close()

    def _label(self) -> str:
        return f"{safe_url(self.cfg.url)}/{self.cfg.index}"

    def _input_kind(self) -> str:
        return "indexer-archives" if "archives" in self.cfg.index else "indexer-alerts"

    def _stream(self, query: dict[str, Any] | None = None) -> Iterator[dict[str, Any]]:
        return self.client.stream(
            self.cfg.index,
            start=self.start,
            end=self.end,
            time_field=self.cfg.time_field,
            query=query,
            max_docs=self.max_events,
        )

    def __iter__(self) -> Iterator[Event]:
        events = bad = future = 0
        start: datetime | None = None
        end: datetime | None = None
        now: datetime | None = None
        horizon = self._wall + FUTURE_TOLERANCE
        profile = self.profile
        failure: RemoteError | None = None
        try:
            docs = self._stream()
            head: list[dict[str, Any]] = []
            if profile == "auto":
                for doc in docs:
                    head.append(doc)
                    if len(head) >= DETECT_SAMPLE:
                        break
                profile = detect_profile(head) if head else "wazuh4"
            self._resolved_profile = profile
            normalize = bind(profile, input_cfg=self.cfg)
            for doc in chain(head, docs):
                event = normalize(doc)
                if event is None:
                    bad += 1
                    continue
                events += 1
                ts = event.ts
                start = ts if start is None or ts < start else start
                end = ts if end is None or ts > end else end
                if ts > horizon:
                    future += 1
                elif now is None or ts > now:
                    now = ts
                yield event
        except RemoteError as exc:  # never "fewer events" in silence: the pass is incomplete and says so
            failure = exc
        basis = DataBasis(
            input_kind=self._input_kind(),
            profile=profile if profile != "auto" else "unknown",
            sources=[self._label()],
            start=start,
            end=end,
            now=now or end,
            now_origin="data",
            events=events,
            bad_timestamps=bad,
            future_timestamps=future,
            warnings=[M("indexer_source.window", start=iso(self.start) or "?", end=iso(self.end) or "?")],
        )
        if basis.input_kind == "indexer-alerts":
            basis.warnings.append(M("indexer_source.alerts_only"))
        self.client.apply_to(basis)
        if failure is not None:
            message = failure.message
            if message not in basis.partial_failures:
                basis.partial_failures.append(M("indexer_source.interrupted", events=events, error=message))
        self.basis = basis

    def iter_rules(self, rule_ids: Collection[str]) -> Iterator[Event]:
        """Only the events of ``rule_ids`` (the backtest pass); ``basis`` is not touched.

        Wazuh 4.x documents are filtered by the indexer itself (``terms`` on ``rule.id``). Unlike a normal pass, a
        remote failure RAISES :class:`RemoteError`: a backtest over part of the data could approve a suppression
        that hides an alert it never saw, so the caller must treat the backtest as not done."""
        wanted = frozenset(str(r) for r in rule_ids)
        if not wanted:
            return
        profile = self._resolved_profile or (self.profile if self.profile != "auto" else None)
        query = {"terms": {"rule.id": sorted(wanted)}} if profile == "wazuh4" else None
        docs = self._stream(query)
        normalize = bind(profile or "wazuh4", input_cfg=self.cfg) if profile else None
        if normalize is None:
            head: list[dict[str, Any]] = []
            for doc in docs:
                head.append(doc)
                if len(head) >= DETECT_SAMPLE:
                    break
            normalize = bind(detect_profile(head) if head else "wazuh4", input_cfg=self.cfg)
            docs = chain(head, docs)
        for doc in docs:
            event = normalize(doc)
            if event is not None and event.rule_id in wanted:
                yield event
