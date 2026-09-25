"""EventSource over a Wazuh indexer / OpenSearch / Elasticsearch index pattern.

Streams documents with :meth:`IndexerClient.stream` (PIT or scroll, always released), normalizes them with the
same profiles as file input and builds a :class:`DataBasis` per complete pass. Remote problems (shard failures,
timeouts, truncation) are folded into the basis so they surface as an incomplete assessment, never as zeros.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import datetime, timedelta
from itertools import chain
from typing import Any

from ..config import InputConfig, TenantConfig
from ..i18n import M, register
from ..models import DataBasis, Event
from ..net import safe_url
from ..timeutil import UTC
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
            "en": "Indexer query window: {start} to {end} (set --since to change it).",
            "es": "Ventana consultada en el indexer: {start} a {end} (use --since para cambiarla).",
        },
    }
)


class IndexerEventSource:
    """Re-iterable EventSource backed by an index pattern. Each iteration re-queries the indexer."""

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
        self.end: datetime = getattr(options, "until", None) or wall
        self.start: datetime = getattr(options, "since", None) or (self.end - default_span)
        self.max_events: int | None = getattr(options, "max_events", None) or cfg.max_events
        requested = getattr(options, "profile", "auto")
        self.profile = cfg.profile if requested == "auto" else requested
        self._wall = wall
        self.basis = DataBasis(input_kind=self._input_kind(), profile=self.profile, sources=[self._label()])

    def close(self) -> None:
        """Release the HTTP client (and any open PIT/scroll)."""
        self.client.close()

    def _label(self) -> str:
        return f"{safe_url(self.cfg.url)}/{self.cfg.index}"

    def _input_kind(self) -> str:
        return "indexer-archives" if "archives" in self.cfg.index else "indexer-alerts"

    def __iter__(self) -> Iterator[Event]:
        docs = self.client.stream(
            self.cfg.index,
            start=self.start,
            end=self.end,
            time_field=self.cfg.time_field,
            max_docs=self.max_events,
        )
        profile = self.profile
        head: list[dict[str, Any]] = []
        if profile == "auto":
            for doc in docs:
                head.append(doc)
                if len(head) >= DETECT_SAMPLE:
                    break
            profile = detect_profile(head) if head else "wazuh4"
        normalize = bind(profile, input_cfg=self.cfg)
        events = bad = future = 0
        start: datetime | None = None
        end: datetime | None = None
        now: datetime | None = None
        horizon = self._wall + FUTURE_TOLERANCE
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
        basis = DataBasis(
            input_kind=self._input_kind(),
            profile=profile,
            sources=[self._label()],
            start=start,
            end=end,
            now=now or end,
            now_origin="data",
            events=events,
            bad_timestamps=bad,
            future_timestamps=future,
            warnings=[M("indexer_source.window", start=self.start.isoformat(), end=self.end.isoformat())],
        )
        if basis.input_kind == "indexer-alerts":
            basis.warnings.append(M("indexer_source.alerts_only"))
        self.client.apply_to(basis)
        self.basis = basis
