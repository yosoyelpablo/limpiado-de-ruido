"""Read-only client for the Wazuh indexer, OpenSearch 1-3 and Elasticsearch 7-9.

Design (see docs/architecture.md §3):

* **Engine detection** from ``GET /``: ``version.distribution == "opensearch"`` or the tagline
  ``The OpenSearch Project`` means OpenSearch. The Wazuh indexer runs OpenSearch 2.x with
  ``compatibility.override_main_response_version`` and reports ``7.10.2`` *without* a distribution, so the
  real version is read from ``GET /_nodes/_local``. ``X-elastic-product: Elasticsearch`` (or the
  ``You Know, for Search`` tagline) means Elasticsearch.
* **Streaming documents**: point-in-time + ``search_after`` only where a unique ``_shard_doc`` tiebreaker
  exists (Elasticsearch >= 7.12: ``POST /<idx>/_pit`` -> ``id``; OpenSearch >= 3.3:
  ``POST /<idx>/_search/point_in_time`` -> ``pit_id``). Without that tiebreaker ``search_after`` can skip
  documents that share a timestamp at page boundaries, and sorting on ``_id`` loads ``_id`` fielddata into
  the heap of (often small) Wazuh indexers, so OpenSearch < 3.3 - every Wazuh 4.x indexer - uses a scroll
  sorted by ``_doc``, which is complete and cheap. A PIT that cannot be opened (403: a read-only role
  without ``point_in_time/create``, or an unsupported endpoint) also falls back to scroll. The newest PIT /
  scroll id is always carried forward and always released in ``finally`` (also when the consumer stops
  early, and by :meth:`IndexerClient.close` for streams left suspended). A scroll requests an exact
  ``hits.total`` and checks it: ending short is a partial failure, overshooting (a looping server) an error.
* Response bodies are read with a size limit (``max_response_bytes``, decoded bytes) so a hostile or broken
  endpoint cannot exhaust memory.
* **Aggregations**: composite aggregation (``fixed_interval`` date histogram with epoch-ms keys + terms
  sources with ``missing_bucket: true``) paged with ``after_key``; ``_count``; ``_field_caps``.
* **Never a false green**: every response is checked for ``timed_out``, ``_shards.failed`` and skipped
  remote clusters. Problems are recorded in :attr:`IndexerClient.partial_failures` (safe English strings
  for ``DataBasis.partial_failures``) and :attr:`IndexerClient.failure_messages` (the same as i18n
  messages); a response where every shard failed raises :class:`~hushwatch.net.RemoteError`. Caps that
  cut results set :attr:`IndexerClient.truncated`.
* Credentials, API keys and PIT/scroll ids never appear in messages.
"""

from __future__ import annotations

import base64
import json
import re
import time
import weakref
from collections.abc import Callable, Generator, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import quote

import httpx

from ..config import InputConfig
from ..i18n import Entity, M, Message, register, render
from ..models import DataBasis
from ..net import (
    DEFAULT_MAX_RESPONSE_BYTES,
    RemoteError,
    backoff_delay,
    is_plain_http,
    loads_json,
    make_client,
    retry_after,
    safe_url,
    sanitize_message,
    sanitize_text,
    send_bounded,
    transport_error,
)

__all__ = ["EngineInfo", "IndexerClient", "parse_version"]

_UTC = timezone.utc
AGG_NAME = "hushwatch"
TIME_KEY = "ts"  # key of the date-histogram source in composite() bucket keys
MAX_PAGE_SIZE = 10_000  # index.max_result_window default; also keeps composite pages far below max_buckets
KEEP_ALIVE = "5m"
_FALLBACK_STATUSES = frozenset({400, 403, 404, 405, 406, 501})
_RETRY_STATUSES = frozenset({429, 502, 503, 504})
_MAX_RECORDED = 50
_BAD_INDEX_CHARS = re.compile(r"[\s/\\?#\"|\x00-\x1f\x7f]")
_HEADER_SAFE = re.compile(r"[!-~]{1,8192}")  # visible ASCII, no spaces / CR / LF
_SOURCE_NAME = re.compile(r"[A-Za-z0-9_.-]{1,64}")
_FIXED_INTERVAL = re.compile(r"[1-9]\d{0,5}(?:ms|s|m|h|d)")
_TIME_ZONE = re.compile(r"[A-Za-z0-9_+\-/:]{1,64}")
_VERSION_RE = re.compile(r"\s*v?(\d{1,6})(?:\.(\d{1,6}))?(?:\.(\d{1,6}))?(?!\d)")

register(
    {
        "indexer.err.no_url": {
            "en": "The indexer input has no 'url'.",
            "es": "La entrada de tipo indexer no tiene 'url'.",
        },
        "indexer.err.index": {
            "en": "Invalid index pattern {index}: use index names, '*' wildcards, '-' exclusions and commas "
            "only (no spaces, '/', '?', '#', and no name starting with '_').",
            "es": "Patrón de índice no válido {index}: use solo nombres de índice, comodines '*', exclusiones "
            "'-' y comas (sin espacios, '/', '?', '#' ni nombres que empiecen por '_').",
        },
        "indexer.err.api_key": {
            "en": "The indexer api_key contains characters that are not allowed in an HTTP header.",
            "es": "La api_key del indexer contiene caracteres no permitidos en una cabecera HTTP.",
        },
        "indexer.err.auth": {
            "en": "The indexer at {url} rejected the credentials (HTTP {status}) during '{op}' ({reason}). Check "
            "username/password or api_key for this input.",
            "es": "El indexer de {url} rechazó las credenciales (HTTP {status}) durante '{op}' ({reason}). "
            "Revise username/password o api_key de esta entrada.",
        },
        "indexer.err.forbidden": {
            "en": "The indexer user may not run '{op}' on {index} (HTTP 403: {reason}). Grant the 'read' and "
            "'view_index_metadata' index permissions on this pattern.",
            "es": "El usuario del indexer no puede ejecutar '{op}' sobre {index} (HTTP 403: {reason}). Concede "
            "los permisos de índice 'read' y 'view_index_metadata' sobre este patrón.",
        },
        "indexer.err.not_found": {
            "en": "'{op}' on {index} returned HTTP 404 ({reason}). Check the index pattern; wazuh-archives-* "
            "only exists when archives are enabled.",
            "es": "'{op}' sobre {index} devolvió HTTP 404 ({reason}). Revise el patrón de índice; "
            "wazuh-archives-* solo existe si los archives están activados.",
        },
        "indexer.err.rate_limited": {
            "en": "The indexer rejected '{op}' on {index} as overloaded (HTTP {status}) after {attempts} "
            "attempts. Run hushwatch off-peak or lower the page size.",
            "es": "El indexer rechazó '{op}' sobre {index} por sobrecarga (HTTP {status}) tras {attempts} "
            "intentos. Ejecute hushwatch fuera de las horas pico o reduzca el tamaño de página.",
        },
        "indexer.err.http": {
            "en": "The indexer returned HTTP {status} for '{op}' on {index} ({reason}).",
            "es": "El indexer devolvió HTTP {status} para '{op}' sobre {index} ({reason}).",
        },
        "indexer.err.protocol": {
            "en": "Unexpected response from the indexer for '{op}' on {index}: {reason}.",
            "es": "Respuesta inesperada del indexer para '{op}' sobre {index}: {reason}.",
        },
        "indexer.err.engine": {
            "en": "{url} does not look like OpenSearch, Elasticsearch or a Wazuh indexer.",
            "es": "{url} no parece un OpenSearch, un Elasticsearch ni un Wazuh indexer.",
        },
        "indexer.err.all_shards_failed": {
            "en": "Every shard failed for '{op}' on {index} ({reason}); no result is available.",
            "es": "Fallaron todos los shards en '{op}' sobre {index} ({reason}); no hay resultado disponible.",
        },
        "indexer.err.context_lost": {
            "en": "The search context on {url} expired or was lost during '{op}' (HTTP 404: {reason}); the "
            "document stream is incomplete. Re-run; pages must be consumed within {keep_alive}.",
            "es": "El contexto de búsqueda en {url} venció o se perdió durante '{op}' (HTTP 404: {reason}); "
            "la descarga de documentos está incompleta. Vuelva a ejecutarlo; cada página debe "
            "consumirse en menos de {keep_alive}.",
        },
        "indexer.partial.shards": {
            "en": "'{op}' on {index}: {failed} of {total} shards failed ({reason}); results are incomplete.",
            "es": "'{op}' sobre {index}: fallaron {failed} de {total} shards ({reason}); los resultados están "
            "incompletos.",
        },
        "indexer.partial.timed_out": {
            "en": "'{op}' on {index} timed out on the server; results are incomplete.",
            "es": "'{op}' sobre {index} agotó el tiempo en el servidor; los resultados están incompletos.",
        },
        "indexer.partial.clusters": {
            "en": "'{op}' on {index}: remote clusters skipped={skipped}, partial={partial}, failed={failed}; "
            "results are incomplete.",
            "es": "'{op}' sobre {index}: clústeres remotos omitidos={skipped}, parciales={partial}, "
            "fallidos={failed}; los resultados están incompletos.",
        },
        "indexer.partial.scroll_short": {
            "en": "The scroll over {index} ended after {seen} of the {total} matching documents; the document "
            "stream is incomplete.",
            "es": "El scroll sobre {index} terminó tras {seen} de los {total} documentos que coinciden; la "
            "descarga de documentos está incompleta.",
        },
        "indexer.err.closed": {
            "en": "The indexer client was closed while '{op}' on {index} was still running; the results are "
            "incomplete.",
            "es": "El cliente del indexer se cerró mientras '{op}' sobre {index} seguía en curso; los resultados "
            "están incompletos.",
        },
        "indexer.partial.after_key": {
            "en": "The composite aggregation on {index} repeated its paging key; paging stopped early and counts "
            "are incomplete.",
            "es": "La agregación composite sobre {index} repitió su clave de paginación; se detuvo antes de "
            "tiempo y los recuentos están incompletos.",
        },
        "indexer.partial.buckets": {
            "en": "The composite aggregation on {index} returned malformed buckets; they were ignored and counts "
            "are incomplete.",
            "es": "La agregación composite sobre {index} devolvió buckets mal formados; se ignoraron y los "
            "recuentos están incompletos.",
        },
        "indexer.partial.field_caps": {
            "en": "field_caps on {index}: {failed} indices failed ({reason}); the field list is incomplete.",
            "es": "field_caps sobre {index}: fallaron {failed} índices ({reason}); la lista de campos está incompleta.",
        },
        "indexer.partial.more": {
            "en": "Further partial failures from the indexer were not listed.",
            "es": "No se listan más fallos parciales del indexer.",
        },
        "indexer.warn.truncated": {
            "en": "'{op}' on {index} stopped at the configured limit of {limit}; results are truncated.",
            "es": "'{op}' sobre {index} se detuvo en el límite configurado de {limit}; los resultados están truncados.",
        },
        "indexer.warn.no_indices": {
            "en": "'{op}': the index pattern {index} matched no index; there is no data to analyse.",
            "es": "'{op}': el patrón de índice {index} no coincide con ningún índice; no hay datos que analizar.",
        },
        "indexer.note.fallback": {
            "en": "Point-in-time search is unavailable on {url} ({reason}); a scroll was used instead.",
            "es": "La búsqueda point-in-time no está disponible en {url} ({reason}); se usó un scroll en su lugar.",
        },
        "indexer.note.version_unknown": {
            "en": "The real engine version of {url} could not be read ({reason}); scroll is used for document "
            "streaming.",
            "es": "No se pudo leer la versión real del motor de {url} ({reason}); se usa scroll para descargar "
            "documentos.",
        },
        "indexer.note.close_failed": {
            "en": "Could not release the {what} context on {url} ({reason}); it expires by itself after {keep_alive}.",
            "es": "No se pudo liberar el contexto {what} en {url} ({reason}); vence solo tras {keep_alive}.",
        },
        "indexer.hint.ca": {
            "en": " (for a Wazuh indexer: the root-ca.pem created at install time, e.g. "
            "/etc/wazuh-indexer/certs/root-ca.pem)",
            "es": " (en un Wazuh indexer: el root-ca.pem generado en la instalación, p. ej. "
            "/etc/wazuh-indexer/certs/root-ca.pem)",
        },
        "indexer.reason.not_json": {"en": "the body is not valid JSON", "es": "el cuerpo no es JSON válido"},
        "indexer.reason.not_object": {
            "en": "the body is not a JSON object",
            "es": "el cuerpo no es un objeto JSON",
        },
        "indexer.reason.no_hits": {
            "en": "hits.hits is missing or not a list",
            "es": "hits.hits falta o no es una lista",
        },
        "indexer.reason.no_sort": {
            "en": "the last hit has no sort values",
            "es": "el último resultado no tiene valores de ordenación",
        },
        "indexer.reason.no_progress": {
            "en": "the page did not advance past the previous search_after position",
            "es": "la página no avanzó más allá de la posición search_after anterior",
        },
        "indexer.reason.scroll_loop": {
            "en": "the scroll repeated a page or returned more documents than its reported total",
            "es": "el scroll repitió una página o devolvió más documentos que su total indicado",
        },
        "indexer.reason.no_pit_id": {
            "en": "no point-in-time id was returned",
            "es": "no se devolvió un id de point-in-time",
        },
        "indexer.reason.no_scroll_id": {
            "en": "no scroll id was returned",
            "es": "no se devolvió un id de scroll",
        },
        "indexer.reason.no_aggregation": {
            "en": "the composite aggregation is missing from the response",
            "es": "falta la agregación composite en la respuesta",
        },
        "indexer.reason.bad_count": {
            "en": "the count is missing or not a number",
            "es": "el recuento falta o no es un número",
        },
        "indexer.reason.no_fields": {
            "en": "the 'fields' object is missing",
            "es": "falta el objeto 'fields'",
        },
        "indexer.reason.forbidden_info": {
            "en": "HTTP 403 on the cluster information endpoint",
            "es": "HTTP 403 en el endpoint de información del clúster",
        },
        "indexer.reason.unknown": {"en": "no reason given", "es": "sin motivo indicado"},
    }
)


def parse_version(text: object) -> tuple[int, ...]:
    """``"8.15.0-SNAPSHOT"`` -> ``(8, 15, 0)``; anything unparseable -> ``()``."""
    if not isinstance(text, str):
        return ()
    match = _VERSION_RE.match(text)
    if not match:
        return ()
    return tuple(int(group) for group in match.groups() if group is not None)


@dataclass(frozen=True, slots=True)
class EngineInfo:
    """What ``GET /`` (and, for masquerading OpenSearch, ``GET /_nodes/_local``) says about the backend.

    ``version`` is the REAL engine version, or ``()`` when unknown (Wazuh indexer compatibility mode without
    permission to read node info). ``reported_version`` is what ``GET /`` said (``7.10.2`` in compatibility
    mode).
    """

    kind: str  # "opensearch" | "elasticsearch"
    version: tuple[int, ...]
    wazuh_indexer: bool = False
    reported_version: str = ""
    compat_mode: bool = False  # GET / answered with the 7.10.2 compatibility version

    @property
    def version_known(self) -> bool:
        return bool(self.version)

    @property
    def supports_pit(self) -> bool:
        """The PIT API exists (ES >= 7.10, OpenSearch >= 2.4); unknown versions are assumed to have it."""
        if not self.version:
            return self.kind == "opensearch"
        return self.version >= ((7, 10) if self.kind == "elasticsearch" else (2, 4))

    @property
    def shard_doc_tiebreak(self) -> bool:
        """A unique ``_shard_doc`` tiebreaker is available for PIT searches (ES >= 7.12, OpenSearch >= 3.3)."""
        if not self.version:
            return False
        return self.version >= ((7, 12) if self.kind == "elasticsearch" else (3, 3))


class _PitUnavailable(Exception):
    """Internal: PIT could not be used before any document was produced (fall back to scroll)."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _as_int(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    if isinstance(value, str) and value.strip().isdigit() and len(value) < 20:
        return int(value)
    return None


def _iso_ms(ts: datetime, *, ceil: bool = False) -> str:
    """Aware datetime -> ``2026-09-25T10:00:00.123Z`` (ms precision; ``ceil`` rounds sub-ms up)."""
    if ts.tzinfo is None or ts.utcoffset() is None:
        raise ValueError("start/end must be timezone-aware datetimes (UTC)")
    utc = ts.astimezone(_UTC)
    if ceil and utc.microsecond % 1000:
        utc = utc + timedelta(microseconds=1000 - utc.microsecond % 1000)
    return utc.strftime("%Y-%m-%dT%H:%M:%S.") + f"{utc.microsecond // 1000:03d}Z"


def _exact_total(data: Mapping[str, Any]) -> int | None:
    """``hits.total`` when the engine reports it as exact (``relation: eq`` or a bare int), else None."""
    outer = data.get("hits")
    total = outer.get("total") if isinstance(outer, Mapping) else None
    if isinstance(total, Mapping):
        return _as_int(total.get("value")) if total.get("relation", "eq") == "eq" else None
    return _as_int(total)


def _no_shards(data: Mapping[str, Any]) -> bool:
    """True when the response says the search ran on zero shards (no index matched the pattern)."""
    shards = data.get("_shards")
    return isinstance(shards, Mapping) and _as_int(shards.get("total")) == 0 and not _as_int(shards.get("failed"))


def _page_marker(hits: Sequence[Mapping[str, Any]]) -> tuple[Any, ...]:
    """Identity of a page (first/last hit index + id + sort) to detect a server repeating the same page."""
    first, last = hits[0], hits[-1]
    return (
        len(hits),
        str(first.get("_index")),
        str(first.get("_id")),
        str(first.get("sort")),
        str(last.get("_index")),
        str(last.get("_id")),
        str(last.get("sort")),
    )


def _merge(target: list[Any], items: Sequence[Any]) -> None:
    for item in items:
        if item not in target:
            target.append(item)


def _clamp(value: int, low: int, high: int, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an int")
    return max(low, min(high, value))


def _index_path(index: str) -> str:
    """Validate an index pattern and percent-encode it for a URL path segment."""
    bad = not isinstance(index, str) or not index.strip() or bool(_BAD_INDEX_CHARS.search(index))
    if not bad:
        for part in index.split(","):
            name = part[1:] if part.startswith("-") else part
            if not name or set(name) <= {"."} or (name.startswith(("_", "+")) and name != "_all"):
                bad = True
                break
    if bad:
        shown = sanitize_text(index, limit=80) if isinstance(index, str) else repr(type(index))
        raise RemoteError(M("indexer.err.index", index=shown), kind="config")
    return quote(index, safe="*,-_.:")


def _build_query(
    time_field: str, start: datetime | None, end: datetime | None, query: Mapping[str, Any] | None
) -> dict[str, Any]:
    if not isinstance(time_field, str) or not time_field.strip():
        raise ValueError("time_field must be a non-empty string")
    filters: list[dict[str, Any]] = []
    bounds: dict[str, str] = {}
    # Both bounds round sub-millisecond instants UP: for millisecond data "t >= start" is exactly
    # "t >= ceil_ms(start)" (and likewise for "t < end"), and adjacent windows [a, b) + [b, c) then split at the
    # same instant, so no document is counted twice or lost at a window boundary.
    if start is not None:
        bounds["gte"] = _iso_ms(start, ceil=True)  # validates awareness before any comparison
    if end is not None:
        bounds["lt"] = _iso_ms(end, ceil=True)
    if start is not None and end is not None and start > end:
        raise ValueError("start must not be after end")
    if bounds:
        filters.append({"range": {time_field: {**bounds, "format": "strict_date_optional_time"}}})
    if query is not None:
        if not isinstance(query, Mapping):
            raise TypeError("query must be a mapping (an OpenSearch/Elasticsearch query clause)")
        clause = query.get("query") if set(query) == {"query"} else query  # tolerate {"query": {...}}
        if not isinstance(clause, Mapping):
            raise TypeError("query must be a mapping (an OpenSearch/Elasticsearch query clause)")
        if clause:
            filters.append(dict(clause))
    if not filters:
        return {"match_all": {}}
    return {"bool": {"filter": filters}}


def _source_param(fields: Sequence[str] | None, time_field: str) -> Any:
    if fields is None:
        return None
    if isinstance(fields, str):
        raise TypeError("fields must be a list of field names, not a string")
    cleaned: list[str] = []
    for name in fields:
        if not isinstance(name, str) or not name.strip():
            raise ValueError("field names must be non-empty strings")
        if name not in cleaned:
            cleaned.append(name)
    if not cleaned:
        return False
    if time_field not in cleaned:
        cleaned.append(time_field)  # consumers always need the event time
    return {"includes": cleaned}


class IndexerClient:
    """Read-only client for one indexer input (Wazuh indexer, OpenSearch, Elasticsearch).

    Build it from an :class:`~hushwatch.config.InputConfig`, or from explicit keyword arguments (which
    override the config). ``transport`` (an ``httpx.MockTransport``) and ``sleep`` are for tests.
    ``max_response_bytes`` bounds any single response body held in memory (default 256 MiB).
    Authentication: ``api_key`` (sent as ``Authorization: ApiKey <key>``) wins over username/password (HTTP
    basic).

    State the caller must fold into the report's DataBasis after using the client:

    * ``partial_failures`` (English strings) / ``failure_messages`` (i18n): shard failures, timeouts, skipped
      clusters, malformed aggregation pages. Their presence means results are INCOMPLETE, never zero.
    * ``truncated``: a ``max_docs`` / ``max_buckets`` cap cut results.
    * ``warnings``: TLS verification disabled or plain HTTP, empty index pattern, truncation.
    * ``notes``: informational (scroll fallback, unknown engine version, context release failures).
    * ``malformed``: hits whose ``_source`` was not an object (skipped).
    * ``last_mode``: ``"pit"`` or ``"scroll"`` for the last :meth:`stream`.
    """

    def __init__(
        self,
        cfg: InputConfig | None = None,
        *,
        url: str | None = None,
        username: str | None = None,
        password: str | None = None,
        api_key: str | None = None,
        ca_cert: str | None = None,
        verify_tls: bool | None = None,
        timeout: float | None = None,
        index: str | None = None,
        time_field: str | None = None,
        transport: httpx.BaseTransport | None = None,
        sleep: Callable[[float], None] | None = None,
        max_retries: int = 3,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
    ) -> None:
        base = cfg if cfg is not None else InputConfig(type="indexer")
        raw_url = url if url is not None else base.url
        if not raw_url:
            raise RemoteError(M("indexer.err.no_url"), kind="config")
        user = username if username is not None else base.username
        secret = password if password is not None else base.password
        key = api_key if api_key is not None else base.api_key
        verify = base.verify_tls if verify_tls is None else verify_tls
        self.index: str = index or base.index
        self.time_field: str = time_field or base.time_field
        self._timeout = float(timeout if timeout is not None else base.timeout)
        self._max_retries = max(0, int(max_retries))
        self._max_bytes = max(1024, int(max_response_bytes))
        self._last_attempts = 0
        self._sleep: Callable[[float], None] = sleep if sleep is not None else time.sleep
        headers: dict[str, str] = {}
        auth: httpx.Auth | None = None
        secrets: list[str | None] = []
        if key:
            if not _HEADER_SAFE.fullmatch(key):
                raise RemoteError(M("indexer.err.api_key"), kind="config")
            headers["Authorization"] = f"ApiKey {key}"
            secrets.append(key)
        elif user:
            auth = httpx.BasicAuth(user, secret or "")
            secrets.append(secret)
            secrets.append(base64.b64encode(f"{user}:{secret or ''}".encode()).decode("ascii"))
        self._static_secrets: tuple[str, ...] = tuple(s for s in secrets if s)
        self._client = make_client(
            raw_url,
            ca_cert=ca_cert if ca_cert is not None else base.ca_cert,
            verify_tls=verify,
            timeout=self._timeout,
            auth=auth,
            headers=headers,
            transport=transport,
        )
        self._url = safe_url(raw_url)
        self._shown = Entity("url", self._url)
        self.partial_failures: list[str] = []
        self.failure_messages: list[Message] = []
        self.warnings: list[Message] = []
        self.notes: list[Message] = []
        self.truncated = False
        self.malformed = 0
        self._malformed_applied = 0
        self.last_mode: str | None = None
        self._engine: EngineInfo | None = None
        self._recorded: set[str] = set()
        self._live_ids: set[str] = set()
        # Page generators of streams that are still suspended (PIT/scroll open): close() releases them.
        self._active: weakref.WeakSet[Generator[list[dict[str, Any]], None, None]] = weakref.WeakSet()
        self._closed = False
        if is_plain_http(self._url):
            self.warnings.append(M("net.warn.plain_http", url=self._shown))
        elif not verify:
            self.warnings.append(M("net.warn.tls_disabled", url=self._shown))

    # ---- lifecycle -------------------------------------------------------------------------------------------
    def apply_to(self, basis: DataBasis) -> None:
        """Fold partial failures (as translatable messages), warnings, truncation and malformed hits into ``basis``
        (idempotent)."""
        _merge(basis.partial_failures, self.failure_messages)
        _merge(basis.warnings, self.warnings)
        basis.truncated = basis.truncated or self.truncated
        basis.malformed += self.malformed - self._malformed_applied
        self._malformed_applied = self.malformed

    def close(self) -> None:
        """Release every PIT/scroll still held by an unfinished :meth:`stream`, then close the connection pool.

        A stream resumed after ``close()`` raises :class:`RemoteError` (kind ``partial``) instead of ending
        quietly with fewer documents.
        """
        if self._closed:
            return
        for pages in list(self._active):
            try:
                pages.close()  # runs the generator's ``finally``: DELETE of the newest PIT/scroll id
            except (RuntimeError, ValueError):  # pragma: no cover - generator running in another thread
                continue
        self._closed = True
        self._client.close()

    def __enter__(self) -> IndexerClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def __repr__(self) -> str:
        return f"IndexerClient(url={self._url!r}, index={self.index!r})"

    # ---- engine ----------------------------------------------------------------------------------------------
    def engine(self) -> EngineInfo:
        """Detect the backend (cached). Raises :class:`RemoteError` on auth/connection problems."""
        if self._engine is not None:
            return self._engine
        resp = self._send("GET", "/", op="info")
        product = resp.headers.get("x-elastic-product", "").strip().lower()
        if resp.status_code == 403:
            # A minimal read-only role may lack cluster:monitor/main; stay conservative (scroll streaming).
            kind = "elasticsearch" if product == "elasticsearch" else "opensearch"
            self._note(M("indexer.note.version_unknown", url=self._shown, reason=M("indexer.reason.forbidden_info")))
            self._engine = EngineInfo(kind=kind, version=())
            return self._engine
        body = self._json(resp, "info", None)
        version_obj = body.get("version")
        version_map: Mapping[str, Any] = version_obj if isinstance(version_obj, Mapping) else {}
        number = version_map.get("number")
        reported = number if isinstance(number, str) else ""
        distribution = str(version_map.get("distribution") or "").strip().lower()
        tagline = str(body.get("tagline") or "")
        cluster = str(body.get("cluster_name") or "").lower()
        if distribution == "opensearch" or tagline.startswith("The OpenSearch Project"):
            compat = distribution != "opensearch"
            version = self._real_opensearch_version() if compat else parse_version(reported)
            self._engine = EngineInfo(
                kind="opensearch",
                version=version,
                wazuh_indexer=compat or "wazuh" in cluster,
                reported_version=sanitize_text(reported, limit=40),
                compat_mode=compat,
            )
        elif product == "elasticsearch" or "you know, for search" in tagline.lower():
            self._engine = EngineInfo(
                kind="elasticsearch",
                version=parse_version(reported),
                reported_version=sanitize_text(reported, limit=40),
            )
        else:
            raise RemoteError(M("indexer.err.engine", url=self._shown), kind="protocol")
        return self._engine

    def _real_opensearch_version(self) -> tuple[int, ...]:
        try:
            resp = self._send("GET", "/_nodes/_local", op="nodes", params={"filter_path": "nodes.*.version"})
            body = self._json(resp, "nodes", None)
        except RemoteError as exc:
            if exc.kind in ("auth", "connection", "timeout", "tls", "config"):
                raise
            self._note(M("indexer.note.version_unknown", url=self._shown, reason=f"HTTP {exc.status or '?'}"))
            return ()
        nodes = body.get("nodes")
        versions = sorted(
            {parse_version(node.get("version")) for node in nodes.values() if isinstance(node, Mapping)}
            if isinstance(nodes, Mapping)
            else set()
        )
        versions = [v for v in versions if v]
        if not versions:
            self._note(M("indexer.note.version_unknown", url=self._shown, reason=M("indexer.reason.unknown")))
            return ()
        return versions[0]  # oldest node decides what the cluster supports

    # ---- documents -------------------------------------------------------------------------------------------
    def stream(
        self,
        index: str | None = None,
        *,
        start: datetime | None,
        end: datetime | None,
        time_field: str | None = None,
        fields: Sequence[str] | None = None,
        query: Mapping[str, Any] | None = None,
        page_size: int = 5000,
        max_docs: int | None = None,
    ) -> Generator[dict[str, Any], None, None]:
        """Stream the ``_source`` of every document in ``[start, end)`` (lazily, page by page).

        Each yielded dict is the document ``_source`` (only ``fields`` + the time field when ``fields`` is
        given; ``[]`` means no source) with ``_id`` and ``_index`` added. ``query`` is an extra filter clause
        (e.g. ``{"term": {"rule.id": "5710"}}``). ``max_docs`` caps the output and sets :attr:`truncated`
        when more documents existed. Order: by time with PIT, index order with scroll (consumers must not
        rely on it). Arguments are validated immediately; network I/O starts on iteration.
        Raises :class:`RemoteError` on HTTP/auth/connection errors (the PIT/scroll is released first).
        A consumer that stops early should ``close()`` the returned generator (or the client) so the server
        context is released at once instead of when the generator is garbage-collected.
        """
        label = self.index if index is None else index
        path = _index_path(label)
        field = time_field or self.time_field
        body_query = _build_query(field, start, end, query)
        source = _source_param(fields, field)
        size = _clamp(page_size, 1, MAX_PAGE_SIZE, "page_size")
        if max_docs is not None:
            if isinstance(max_docs, bool) or not isinstance(max_docs, int) or max_docs < 0:
                raise ValueError("max_docs must be a non-negative int or None")
            size = min(size, max_docs + 1)  # one extra hit tells whether the cap truncated anything
        return self._stream(path, label, field, body_query, source, size, max_docs)

    def _stream(
        self,
        path: str,
        label: str,
        field: str,
        body_query: dict[str, Any],
        source: Any,
        size: int,
        max_docs: int | None,
    ) -> Generator[dict[str, Any], None, None]:
        pages = self._pages(path, label, field, body_query, source, size)
        self._active.add(pages)
        remaining = max_docs
        try:
            for hits in pages:
                cut = False
                if remaining is not None:
                    if remaining <= 0:  # the cap was reached exactly at the end of the previous page
                        self._truncate("stream", label, max_docs)
                        return
                    if len(hits) > remaining:
                        hits = hits[:remaining]
                        cut = True
                    remaining -= len(hits)
                for hit in hits:
                    doc = self._doc(hit)
                    if doc is not None:
                        yield doc
                if cut:
                    self._truncate("stream", label, max_docs)
                    return
            if self._closed:  # close() ended the page generator: the stream is incomplete, not finished
                raise RemoteError(M("indexer.err.closed", op="stream", index=label), kind="partial")
        finally:
            pages.close()
            self._active.discard(pages)

    def _pages(
        self, path: str, label: str, field: str, body_query: dict[str, Any], source: Any, size: int
    ) -> Generator[list[dict[str, Any]], None, None]:
        engine = self.engine()
        if engine.shard_doc_tiebreak:
            try:
                yield from self._pit_pages(engine, path, label, field, body_query, source, size)
                return
            except _PitUnavailable as exc:
                self._note(M("indexer.note.fallback", url=self._shown, reason=exc.reason))
        yield from self._scroll_pages(path, label, body_query, source, size)

    def _pit_pages(
        self,
        engine: EngineInfo,
        path: str,
        label: str,
        field: str,
        body_query: dict[str, Any],
        source: Any,
        size: int,
    ) -> Generator[list[dict[str, Any]], None, None]:
        pit_id = self._open_pit(engine, path, label)
        stream_ids = [pit_id]
        self.last_mode = "pit"
        sort: list[Any] = [
            {field: {"order": "asc", "unmapped_type": "date"}},
            {"_shard_doc": "asc"},
        ]
        search_after: Any = None
        first = True
        try:
            while True:
                body: dict[str, Any] = {
                    "size": size,
                    "query": body_query,
                    "sort": sort,
                    "track_total_hits": False,
                    "pit": {"id": pit_id, "keep_alive": KEEP_ALIVE},
                }
                if source is not None:
                    body["_source"] = source
                if search_after is not None:
                    body["search_after"] = search_after
                resp = self._send("POST", "/_search", op="search", body=body)
                if first and resp.status_code in _FALLBACK_STATUSES:
                    raise _PitUnavailable(f"HTTP {resp.status_code}: {self._error_reason(resp)}")
                data = self._json(resp, "search", label)
                newer = data.get("pit_id")
                if isinstance(newer, str) and newer and newer != pit_id:
                    self._live_ids.add(newer)
                    stream_ids.append(newer)
                    pit_id = newer
                clean = self._check(data, "search", label)
                hits = self._hits(data, "search", label)
                if not hits:
                    return
                last_sort = hits[-1].get("sort")
                if not isinstance(last_sort, list) or not last_sort:
                    raise self._protocol("search", label, M("indexer.reason.no_sort"))
                if last_sort == search_after:  # no progress: stop instead of looping forever
                    raise self._protocol("search", label, M("indexer.reason.no_progress"))
                first = False
                yield hits
                if len(hits) < size and clean:
                    return
                search_after = last_sort
        finally:
            self._close_pit(engine, pit_id)
            self._live_ids.difference_update(stream_ids)

    def _open_pit(self, engine: EngineInfo, path: str, label: str) -> str:
        if engine.kind == "elasticsearch":
            endpoint, key = f"/{path}/_pit", "id"
        else:
            endpoint, key = f"/{path}/_search/point_in_time", "pit_id"
        resp = self._send("POST", endpoint, op="open_pit", params={"keep_alive": KEEP_ALIVE})
        if resp.status_code in _FALLBACK_STATUSES:
            raise _PitUnavailable(f"HTTP {resp.status_code}: {self._error_reason(resp)}")
        data = self._json(resp, "open_pit", label)
        pit_id = data.get(key) or data.get("pit_id") or data.get("id")
        if not isinstance(pit_id, str) or not pit_id:
            raise self._protocol("open_pit", label, M("indexer.reason.no_pit_id"))
        self._live_ids.add(pit_id)
        try:
            self._check(data, "open_pit", label)  # OpenSearch allows partial PIT creation by default
        except RemoteError:
            self._close_pit(engine, pit_id)
            raise
        return pit_id

    def _close_pit(self, engine: EngineInfo, pit_id: str) -> None:
        if engine.kind == "elasticsearch":
            self._release("DELETE", "/_pit", {"id": pit_id}, "PIT")
        else:
            self._release("DELETE", "/_search/point_in_time", {"pit_id": [pit_id]}, "PIT")

    def _scroll_pages(
        self, path: str, label: str, body_query: dict[str, Any], source: Any, size: int
    ) -> Generator[list[dict[str, Any]], None, None]:
        # An exact total (a scroll cannot disable it anyway) lets the stream prove it is complete: a scroll that
        # ends early is reported, one that returns more than the total (a looping server) is stopped.
        body: dict[str, Any] = {"size": size, "query": body_query, "sort": ["_doc"], "track_total_hits": True}
        if source is not None:
            body["_source"] = source
        resp = self._send("POST", f"/{path}/_search", op="scroll", params={"scroll": KEEP_ALIVE}, body=body)
        data = self._json(resp, "scroll", label)
        self.last_mode = "scroll"
        scroll_id = data.get("_scroll_id")
        scroll_id = scroll_id if isinstance(scroll_id, str) and scroll_id else None
        stream_ids = [scroll_id] if scroll_id else []
        self._live_ids.update(stream_ids)
        expected = _exact_total(data)
        seen = 0
        previous: tuple[Any, ...] | None = None
        try:
            while True:
                self._check(data, "scroll", label)
                before = self.malformed
                hits = self._hits(data, "scroll", label)
                seen += len(hits) + self.malformed - before
                if not hits:
                    if expected is not None and seen < expected:
                        self._record(M("indexer.partial.scroll_short", index=label, seen=seen, total=expected))
                    return
                if scroll_id is None:
                    raise self._protocol("scroll", label, M("indexer.reason.no_scroll_id"))
                marker = _page_marker(hits)
                if (expected is not None and seen > expected) or marker == previous:
                    raise self._protocol("scroll", label, M("indexer.reason.scroll_loop"))
                previous = marker
                yield hits
                # Never retry a scroll continuation: a retried page could silently skip a batch.
                resp = self._send(
                    "POST",
                    "/_search/scroll",
                    op="scroll_next",
                    body={"scroll": KEEP_ALIVE, "scroll_id": scroll_id},
                    retry=False,
                )
                data = self._json(resp, "scroll_next", label)
                newer = data.get("_scroll_id")
                if isinstance(newer, str) and newer and newer != scroll_id:
                    self._live_ids.add(newer)
                    stream_ids.append(newer)
                    scroll_id = newer
        finally:
            if scroll_id:
                self._release("DELETE", "/_search/scroll", {"scroll_id": [scroll_id]}, "scroll")
            self._live_ids.difference_update(stream_ids)

    def _release(self, method: str, path: str, body: dict[str, Any], what: str) -> None:
        """Best-effort release of a PIT/scroll context. Never raises (it runs in ``finally`` blocks)."""
        reason: str | None = None
        try:
            resp = self._send(method, path, op=f"close_{what.lower()}", body=body, retry=False)
            if resp.status_code >= 400 and resp.status_code != 404:  # 404: already expired
                reason = f"HTTP {resp.status_code}"
        except RemoteError as exc:
            reason = exc.kind
        except Exception as exc:  # cleanup must never mask the original error
            reason = type(exc).__name__
        finally:
            for value in body.values():
                for item in value if isinstance(value, list) else [value]:
                    self._live_ids.discard(str(item))
        if reason is not None:
            self._note(M("indexer.note.close_failed", what=what, url=self._shown, reason=reason, keep_alive=KEEP_ALIVE))

    def _doc(self, hit: dict[str, Any]) -> dict[str, Any] | None:
        source = hit.get("_source")
        if source is None:
            doc: dict[str, Any] = {}
        elif isinstance(source, dict):
            doc = source
        else:
            self.malformed += 1
            return None
        doc_id = hit.get("_id")
        if isinstance(doc_id, str):
            doc.setdefault("_id", doc_id)
        doc_index = hit.get("_index")
        if isinstance(doc_index, str):
            doc.setdefault("_index", doc_index)
        return doc

    def _hits(self, data: Mapping[str, Any], op: str, label: str) -> list[dict[str, Any]]:
        outer = data.get("hits")
        inner = outer.get("hits") if isinstance(outer, Mapping) else None
        if not isinstance(inner, list):
            raise self._protocol(op, label, M("indexer.reason.no_hits"))
        hits = [hit for hit in inner if isinstance(hit, dict)]
        self.malformed += len(inner) - len(hits)
        return hits

    # ---- aggregations ----------------------------------------------------------------------------------------
    def composite(
        self,
        index: str | None = None,
        *,
        sources: Sequence[tuple[str, str]],
        start: datetime | None,
        end: datetime | None,
        time_field: str | None = None,
        interval: str | None = "1h",
        time_zone: str = "UTC",
        query: Mapping[str, Any] | None = None,
        size: int = 1000,
        max_buckets: int | None = None,
    ) -> Generator[tuple[dict[str, Any], int], None, None]:
        """Yield ``(key, doc_count)`` for every composite bucket, paging with ``after_key``.

        The key has ``"ts"`` (bucket start, epoch milliseconds; omitted when ``interval`` is None) plus one
        entry per ``(name, field)`` terms source. Missing values are counted in buckets whose value is
        ``None`` (``missing_bucket: true``). ``interval`` is a fixed interval (``"1h"``, ``"15m"``, ``"1d"``);
        ``time_zone`` shifts bucket boundaries. ``max_buckets`` caps the output and sets :attr:`truncated`.
        """
        label = self.index if index is None else index
        path = _index_path(label)
        field = time_field or self.time_field
        body_query = _build_query(field, start, end, query)
        page = _clamp(size, 1, MAX_PAGE_SIZE, "size")
        if max_buckets is not None:
            if isinstance(max_buckets, bool) or not isinstance(max_buckets, int) or max_buckets < 0:
                raise ValueError("max_buckets must be a non-negative int or None")
            page = min(page, max_buckets + 1)
        comp_sources: list[dict[str, Any]] = []
        if interval is not None:
            if not isinstance(interval, str) or not _FIXED_INTERVAL.fullmatch(interval):
                raise ValueError("interval must be a fixed interval such as '1h', '15m' or '1d'")
            if not isinstance(time_zone, str) or not _TIME_ZONE.fullmatch(time_zone):
                raise ValueError("time_zone must be an IANA name or an offset such as '+01:00'")
            comp_sources.append(
                {TIME_KEY: {"date_histogram": {"field": field, "fixed_interval": interval, "time_zone": time_zone}}}
            )
        names: set[str] = {TIME_KEY} if interval is not None else set()
        for item in sources:
            if not isinstance(item, (tuple, list)) or len(item) != 2:
                raise ValueError("sources must be (name, field) pairs")
            name, source_field = item
            if not isinstance(name, str) or not _SOURCE_NAME.fullmatch(name) or name in names:
                raise ValueError(f"invalid or duplicate composite source name {name!r}")
            if not isinstance(source_field, str) or not source_field.strip():
                raise ValueError("composite source fields must be non-empty strings")
            names.add(name)
            comp_sources.append({name: {"terms": {"field": source_field, "missing_bucket": True}}})
        if not comp_sources:
            raise ValueError("composite() needs an interval or at least one terms source")
        return self._composite(path, label, body_query, comp_sources, page, max_buckets)

    def _composite(
        self,
        path: str,
        label: str,
        body_query: dict[str, Any],
        comp_sources: list[dict[str, Any]],
        page: int,
        max_buckets: int | None,
    ) -> Generator[tuple[dict[str, Any], int], None, None]:
        after: dict[str, Any] | None = None
        seen_after: set[str] = set()
        emitted = 0
        malformed_reported = False
        while True:
            composite: dict[str, Any] = {"size": page, "sources": comp_sources}
            if after is not None:
                composite["after"] = after
            body = {
                "size": 0,
                "track_total_hits": False,
                "query": body_query,
                "aggs": {AGG_NAME: {"composite": composite}},
            }
            resp = self._send("POST", f"/{path}/_search", op="composite", body=body)
            data = self._json(resp, "composite", label)
            self._check(data, "composite", label)
            aggs = data.get("aggregations")
            agg = aggs.get(AGG_NAME) if isinstance(aggs, Mapping) else None
            buckets = agg.get("buckets") if isinstance(agg, Mapping) else None
            if aggs is None and after is None and _no_shards(data):
                # The pattern matched no index (e.g. wazuh-archives-* with archives off): the engines then omit
                # "aggregations" entirely. _check() already recorded the "matched no index" warning.
                return
            if not isinstance(agg, Mapping) or not isinstance(buckets, list):
                raise self._protocol("composite", label, M("indexer.reason.no_aggregation"))
            for bucket in buckets:
                key = bucket.get("key") if isinstance(bucket, Mapping) else None
                count = _as_int(bucket.get("doc_count")) if isinstance(bucket, Mapping) else None
                if not isinstance(key, dict) or count is None or count < 0:
                    if not malformed_reported:
                        self._record(M("indexer.partial.buckets", index=label))
                        malformed_reported = True
                    continue
                if max_buckets is not None and emitted >= max_buckets:
                    self._truncate("composite", label, max_buckets)
                    return
                emitted += 1
                yield dict(key), count
            next_after = agg.get("after_key")
            if not buckets or not isinstance(next_after, dict) or not next_after:
                return
            marker = json.dumps(next_after, sort_keys=True, default=str)
            if marker in seen_after:  # a repeated/cycling paging key would loop forever
                self._record(M("indexer.partial.after_key", index=label))
                return
            seen_after.add(marker)
            after = next_after

    def count(
        self,
        index: str | None = None,
        *,
        query: Mapping[str, Any] | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
        time_field: str | None = None,
    ) -> int:
        """Number of documents matching ``query`` in ``[start, end)``.

        Shard failures are recorded in :attr:`partial_failures` (the count is then a lower bound); a
        response where every shard failed raises :class:`RemoteError` instead of returning 0.
        """
        label = self.index if index is None else index
        path = _index_path(label)
        body = {"query": _build_query(time_field or self.time_field, start, end, query)}
        resp = self._send("POST", f"/{path}/_count", op="count", body=body)
        data = self._json(resp, "count", label)
        self._check(data, "count", label)
        value = _as_int(data.get("count"))
        if value is None or value < 0:
            raise self._protocol("count", label, M("indexer.reason.bad_count"))
        return value

    def field_caps(self, index: str | None = None) -> dict[str, list[str]]:
        """Field name -> sorted mapped types across the matching indices (several types = mapping conflict).

        Metadata fields (``_id``...) and pure ``object`` parents are omitted.
        """
        label = self.index if index is None else index
        path = _index_path(label)
        resp = self._send("GET", f"/{path}/_field_caps", op="field_caps", params={"fields": "*"})
        data = self._json(resp, "field_caps", label)
        failed = _as_int(data.get("failed_indices"))
        if failed:
            reason = self._failure_reasons(
                [f.get("failure") for f in data.get("failures", []) if isinstance(f, Mapping)]
                if isinstance(data.get("failures"), list)
                else None
            )
            self._record(M("indexer.partial.field_caps", index=label, failed=failed, reason=reason))
        fields = data.get("fields")
        if not isinstance(fields, Mapping):
            raise self._protocol("field_caps", label, M("indexer.reason.no_fields"))
        indices = data.get("indices")
        if isinstance(indices, list) and not indices:
            self._warn(M("indexer.warn.no_indices", op="field_caps", index=label))
        out: dict[str, list[str]] = {}
        for name, types in fields.items():
            if not isinstance(name, str) or not name or name.startswith("_") or not isinstance(types, Mapping):
                continue
            kinds = sorted({t for t in types if isinstance(t, str) and t})
            if not kinds or kinds == ["object"]:
                continue
            out[name] = kinds
        return out

    # ---- HTTP plumbing ---------------------------------------------------------------------------------------
    def _secrets(self) -> tuple[str, ...]:
        return self._static_secrets + tuple(self._live_ids)

    def _send(
        self,
        method: str,
        path: str,
        *,
        op: str,
        params: Mapping[str, str] | None = None,
        body: Any = None,
        retry: bool = True,
    ) -> httpx.Response:
        if self._closed:
            raise RemoteError(M("indexer.err.closed", op=op, index="-"), kind="partial")
        attempts = self._max_retries + 1 if retry else 1
        attempt = 0
        while True:
            try:
                request = self._client.build_request(method, path, params=params, json=body)
                resp = send_bounded(self._client, request, max_bytes=self._max_bytes, url=self._url, op=op)
            except (httpx.HTTPError, httpx.InvalidURL) as exc:
                raise transport_error(
                    exc,
                    url=self._url,
                    op=op,
                    timeout=self._timeout,
                    hint=M("indexer.hint.ca"),
                    secrets=self._secrets(),
                ) from None
            attempt += 1
            self._last_attempts = attempt
            if resp.status_code in _RETRY_STATUSES and attempt < attempts:
                self._sleep(retry_after(resp) or backoff_delay(attempt - 1, cap=30.0))
                continue
            return resp

    def _json(self, resp: httpx.Response, op: str, index: str | None) -> dict[str, Any]:
        if not 200 <= resp.status_code < 300:
            raise self._http_error(resp, op, index)
        try:
            data = loads_json(resp.content)
        except ValueError:
            raise self._protocol(op, index, M("indexer.reason.not_json")) from None
        if not isinstance(data, dict):
            raise self._protocol(op, index, M("indexer.reason.not_object"))
        return data

    def _http_error(self, resp: httpx.Response, op: str, index: str | None) -> RemoteError:
        status = resp.status_code
        reason = self._error_reason(resp)
        label = index or "-"
        if status == 401:
            msg = M("indexer.err.auth", url=self._shown, status=status, op=op, reason=reason)
            return RemoteError(msg, kind="auth", status=status)
        if status == 403:
            return RemoteError(
                M("indexer.err.forbidden", op=op, index=label, reason=reason), kind="forbidden", status=status
            )
        if status == 404 and op in ("search", "scroll_next"):
            msg = M("indexer.err.context_lost", url=self._shown, op=op, reason=reason, keep_alive=KEEP_ALIVE)
            return RemoteError(msg, kind="partial", status=status)
        if status == 404:
            return RemoteError(
                M("indexer.err.not_found", op=op, index=label, reason=reason), kind="not_found", status=status
            )
        if status == 429:
            msg = M("indexer.err.rate_limited", op=op, index=label, status=status, attempts=self._last_attempts)
            return RemoteError(msg, kind="rate_limited", status=status)
        return RemoteError(
            M("indexer.err.http", status=status, op=op, index=label, reason=reason), kind="http", status=status
        )

    def _error_reason(self, resp: httpx.Response) -> str:
        """Short, sanitized reason from an OpenSearch/Elasticsearch error body (untrusted text)."""
        text: object = ""
        try:
            data = loads_json(resp.content)
        except ValueError:
            data = None
        if isinstance(data, Mapping):
            error = data.get("error")
            if isinstance(error, Mapping):
                roots = error.get("root_cause")
                first = roots[0] if isinstance(roots, list) and roots and isinstance(roots[0], Mapping) else error
                text = self._type_reason(first) or self._type_reason(error)
            elif isinstance(error, str):
                text = error
            elif isinstance(data.get("message"), str):
                text = data["message"]
        elif resp.content:
            text = resp.content[:1000].decode("utf-8", "replace")
        cleaned = sanitize_text(text, limit=300, secrets=self._secrets())
        return cleaned or sanitize_text(resp.reason_phrase or f"HTTP {resp.status_code}", limit=60)

    @staticmethod
    def _type_reason(obj: Mapping[str, Any]) -> str:
        kind, reason = obj.get("type"), obj.get("reason")
        parts = [str(p) for p in (kind, reason) if isinstance(p, (str, int, float)) and str(p)]
        return ": ".join(parts)

    def _failure_reasons(self, failures: object) -> str:
        """Up to three distinct ``type: reason`` strings from a ``failures`` list."""
        found: list[str] = []
        if isinstance(failures, list):
            for failure in failures:
                if not isinstance(failure, Mapping):
                    continue
                reason = failure.get("reason")
                if not isinstance(reason, Mapping):
                    reason = failure.get("error") if isinstance(failure.get("error"), Mapping) else failure
                text = self._type_reason(reason) if isinstance(reason, Mapping) else str(reason or "")
                text = sanitize_text(text, limit=160, secrets=self._secrets())
                if text and text not in found:
                    found.append(text)
                if len(found) >= 3:
                    break
        return "; ".join(found) if found else render(M("indexer.reason.unknown"), "en")

    def _check(self, data: Mapping[str, Any], op: str, label: str) -> bool:
        """Record timeouts, shard failures and skipped clusters. Returns True when the response is complete.

        Raises :class:`RemoteError` (kind ``partial``) when every shard failed: that is no data, not zero.
        """
        clean = True
        timed_out = data.get("timed_out")
        if timed_out is True or (timed_out is not None and not isinstance(timed_out, bool)):
            self._record(M("indexer.partial.timed_out", op=op, index=label))
            clean = False
        shards = data.get("_shards")
        if isinstance(shards, Mapping):
            raw_failed = shards.get("failed", 0)
            failed = _as_int(raw_failed)
            total = _as_int(shards.get("total"))
            successful = _as_int(shards.get("successful"))
            if failed is None or failed > 0:
                reason = self._failure_reasons(shards.get("failures"))
                if failed and total and successful == 0:
                    msg = M("indexer.err.all_shards_failed", op=op, index=label, reason=reason)
                    raise RemoteError(msg, kind="partial")
                shown_failed: object = failed if failed is not None else sanitize_text(raw_failed, limit=20)
                shown_total: object = total if total is not None else "?"
                self._record(
                    M(
                        "indexer.partial.shards",
                        op=op,
                        index=label,
                        failed=shown_failed,
                        total=shown_total,
                        reason=reason,
                    )
                )
                clean = False
            elif total == 0 and op in ("count", "composite", "search", "scroll", "open_pit"):
                self._warn(M("indexer.warn.no_indices", op=op, index=label))
        elif shards is not None:
            self._record(M("indexer.partial.shards", op=op, index=label, failed="?", total="?", reason="?"))
            clean = False
        clusters = data.get("_clusters")
        if isinstance(clusters, Mapping):
            skipped = _as_int(clusters.get("skipped")) or 0
            partial = _as_int(clusters.get("partial")) or 0
            failed_clusters = _as_int(clusters.get("failed")) or 0
            if skipped or partial or failed_clusters:
                self._record(
                    M(
                        "indexer.partial.clusters",
                        op=op,
                        index=label,
                        skipped=skipped,
                        partial=partial,
                        failed=failed_clusters,
                    )
                )
                clean = False
        return clean

    def _protocol(self, op: str, index: str | None, reason: Message) -> RemoteError:
        return RemoteError(M("indexer.err.protocol", op=op, index=index or "-", reason=reason), kind="protocol")

    # ---- bookkeeping -----------------------------------------------------------------------------------------
    def _record(self, msg: Message) -> None:
        if len(self.partial_failures) > _MAX_RECORDED:
            return
        text = sanitize_text(render(msg, "en"), limit=600, secrets=self._secrets())
        if text in self._recorded:
            return
        self._recorded.add(text)
        if len(self.partial_failures) == _MAX_RECORDED:
            msg = M("indexer.partial.more")
            text = render(msg, "en")
        self.partial_failures.append(text)
        self.failure_messages.append(sanitize_message(msg, limit=600, secrets=self._secrets()))

    def _warn(self, msg: Message) -> None:
        if msg not in self.warnings:
            self.warnings.append(msg)

    def _note(self, msg: Message) -> None:
        if msg not in self.notes and len(self.notes) < _MAX_RECORDED:
            self.notes.append(msg)

    def _truncate(self, op: str, label: str, limit: int | None) -> None:
        self.truncated = True
        self._warn(M("indexer.warn.truncated", op=op, index=label, limit=limit if limit is not None else 0))
