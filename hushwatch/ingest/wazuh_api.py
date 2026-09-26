"""Read-only client for the Wazuh server API (port 55000), Wazuh 4.x (5.x where the endpoints still exist).

* Authentication: ``POST /security/user/authenticate?raw=true`` with HTTP basic auth returns a JWT that is
  kept in memory only. Its ``exp`` claim is decoded (base64url, no signature check needed: we are the
  client) and the token is renewed about 60 s before it expires; the lifetime is taken as ``exp - nbf``
  (issuer clock) so clock skew between hushwatch and the manager cannot cause a login storm. A 401 triggers
  one re-login and one retry. ``DELETE /security/user/authenticate`` is NEVER called: it revokes every token
  of the user, which would log out a dashboard or integration sharing the account.
* Load: a client-side sliding-window limiter (``max_requests_per_minute``, default 240 < Wazuh's 300) and
  exponential backoff on HTTP 429 (the Wazuh limit window is one minute). The limiter slot is taken before
  the token is checked, so a limiter wait can never send an expired token. Bodies are read with a size cap.
* Compatibility: ``GET /agents`` asks for ``status_code`` (Wazuh >= 4.7); older managers reject that select
  field (error 1724) and the request is repeated with fewer fields.
* Errors: Wazuh error payloads (``title``/``detail``/``error`` code, ``data.failed_items``) are surfaced
  through safe messages; the password and the token never appear in them. Optional endpoints
  (``/rules``, ``/manager/daemons/stats``, logcollector stats, ``/manager/info``) return ``None``/``[]`` when
  the manager version or the user's RBAC does not offer them, with a note or warning explaining why.

Like :class:`~hushwatch.ingest.opensearch.IndexerClient`, the client exposes ``partial_failures``
(English strings), ``failure_messages`` (i18n), ``warnings`` and ``notes`` for the report's DataBasis.
"""

from __future__ import annotations

import base64
import math
import re
import time
from collections.abc import Callable, Iterable, Mapping
from datetime import datetime
from typing import Any

import httpx

from ..config import ApiConfig
from ..i18n import Entity, M, Message, register, render
from ..inventory import AgentInfo
from ..models import DataBasis
from ..net import (
    RateLimiter,
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
from ..timeutil import parse_ts

__all__ = ["AGENT_FIELDS", "LEGACY_AGENT_FIELDS", "WazuhAPI", "parse_agent", "platform_family", "token_ttl"]

AUTH_PATH = "/security/user/authenticate"
AGENT_FIELDS: tuple[str, ...] = (
    "id",
    "name",
    "ip",
    "status",
    "status_code",
    "lastKeepAlive",
    "dateAdd",
    "version",
    "os.name",
    "os.platform",
    "group",
    "node_name",
)
# Wazuh < 4.7 has no status_code and rejects the whole request (error 1724) when select names it.
LEGACY_AGENT_FIELDS: tuple[str, ...] = tuple(f for f in AGENT_FIELDS if f != "status_code")
SELECT_ERROR = "1724"  # Wazuh "Not a valid select field"
PAGE_SIZE = 500  # Wazuh's recommended maximum page size
DEFAULT_MAX_RESPONSE_BYTES = 64 * 1024 * 1024  # one API page (500 agents / rules) is far below this
MAX_TOKEN_RESPONSE_BYTES = 1024 * 1024
RULE_IDS_PER_REQUEST = 200  # keeps the query string short
REFRESH_MARGIN = 60.0  # renew the JWT this many seconds before it expires
DEFAULT_TTL = 300.0  # assumed lifetime when the token's claims cannot be read (Wazuh default is 900 s)
MAX_429_RETRIES = 6  # 1+2+4+8+16+32 s of backoff: covers Wazuh's one-minute rate-limit window
MAX_5XX_RETRIES = 2
MAX_PAGES = 100_000
_OPTIONAL_STATUSES = frozenset({400, 403, 404, 405, 501})
_JWT = re.compile(r"[A-Za-z0-9_-]{2,8192}\.[A-Za-z0-9_-]{2,16384}\.[A-Za-z0-9_-]{0,8192}")
_KNOWN_STATUSES = frozenset({"active", "disconnected", "pending", "never_connected"})
_LINUX_PLATFORMS = frozenset(
    {
        "linux",
        "ubuntu",
        "debian",
        "centos",
        "rhel",
        "redhat",
        "fedora",
        "amzn",
        "amazon",
        "sles",
        "sled",
        "suse",
        "opensuse",
        "opensuse-leap",
        "opensuse-tumbleweed",
        "ol",
        "oracle",
        "rocky",
        "almalinux",
        "alma",
        "arch",
        "alpine",
        "raspbian",
        "linuxmint",
        "kali",
        "gentoo",
        "slackware",
        "manjaro",
        "photon",
        "cloudlinux",
        "scientific",
        "xenserver",
        "nixos",
        "mariner",
        "azurelinux",
        "bottlerocket",
        "coreos",
    }
)

register(
    {
        "wazuh_api.err.no_url": {
            "en": "The Wazuh API configuration has no 'url'.",
            "es": "La configuración de la API de Wazuh no tiene 'url'.",
        },
        "wazuh_api.err.no_credentials": {
            "en": "The Wazuh API needs a username and a password (write them as ${{ENV_VAR}} references).",
            "es": "La API de Wazuh necesita usuario y contraseña (escríbelos como referencias ${{VARIABLE}}).",
        },
        "wazuh_api.err.login": {
            "en": "The Wazuh API at {url} rejected the login of {user} (HTTP {status}: {detail}). Check the API "
            "username and password; repeated failures block the source address for a while.",
            "es": "La API de Wazuh de {url} rechazó el inicio de sesión de {user} (HTTP {status}: {detail}). "
            "Revise el usuario y la contraseña de la API; los fallos repetidos bloquean temporalmente la "
            "dirección de origen.",
        },
        "wazuh_api.err.token": {
            "en": "The Wazuh API at {url} returned an invalid authentication token.",
            "es": "La API de Wazuh de {url} devolvió un token de autenticación no válido.",
        },
        "wazuh_api.err.unauthorized": {
            "en": "The Wazuh API rejected '{op}' for {user} even after logging in again (HTTP 401).",
            "es": "La API de Wazuh rechazó '{op}' para {user} incluso tras volver a iniciar sesión (HTTP 401).",
        },
        "wazuh_api.err.forbidden": {
            "en": "The Wazuh API user {user} may not call '{op}' (HTTP 403: {detail}). Grant the matching read "
            "permission in Wazuh RBAC.",
            "es": "El usuario {user} de la API de Wazuh no puede llamar a '{op}' (HTTP 403: {detail}). Concede "
            "el permiso de lectura correspondiente en el RBAC de Wazuh.",
        },
        "wazuh_api.err.rate_limited": {
            "en": "The Wazuh API kept answering HTTP 429 (request limit reached) to '{op}' after {attempts} "
            "attempts. Lower max_requests_per_minute or run hushwatch later.",
            "es": "La API de Wazuh siguió respondiendo HTTP 429 (límite de peticiones) a '{op}' tras {attempts} "
            "intentos. Reduzca max_requests_per_minute o ejecute hushwatch más tarde.",
        },
        "wazuh_api.err.http": {
            "en": "The Wazuh API returned HTTP {status} for '{op}' (error {code}: {detail}).",
            "es": "La API de Wazuh devolvió HTTP {status} para '{op}' (error {code}: {detail}).",
        },
        "wazuh_api.err.protocol": {
            "en": "Unexpected response from the Wazuh API for '{op}': {reason}.",
            "es": "Respuesta inesperada de la API de Wazuh para '{op}': {reason}.",
        },
        "wazuh_api.partial.failed_items": {
            "en": "'{op}': the Wazuh API could not process {count} {count:plural:item|items} ({errors}); "
            "results are incomplete.",
            "es": "'{op}': la API de Wazuh no pudo procesar {count} {count:plural:elemento|elementos} "
            "({errors}); los resultados están incompletos.",
        },
        "wazuh_api.partial.agents_incomplete": {
            "en": "'GET /agents' returned {seen} of {total} agents; the agent inventory is incomplete.",
            "es": "'GET /agents' devolvió {seen} de {total} agentes; el inventario de agentes está incompleto.",
        },
        "wazuh_api.partial.agents_malformed": {
            "en": "'GET /agents' returned {count} {count:plural:item|items} without a usable agent id; they "
            "are missing from the agent inventory.",
            "es": "'GET /agents' devolvió {count} {count:plural:elemento|elementos} sin un id de agente "
            "válido; faltan en el inventario de agentes.",
        },
        "wazuh_api.partial.stalled": {
            "en": "'{op}': the Wazuh API returned the same page again (it ignored the offset); listing "
            "stopped after {seen} {seen:plural:item|items} and may be incomplete.",
            "es": "'{op}': la API de Wazuh devolvió de nuevo la misma página (ignoró el offset); el listado "
            "se detuvo tras {seen} {seen:plural:elemento|elementos} y puede estar incompleto.",
        },
        "wazuh_api.partial.flagged": {
            "en": "'{op}': the Wazuh API marked the response as failed or partial (error {code}) without listing "
            "the failed items; results may be incomplete.",
            "es": "'{op}': la API de Wazuh marcó la respuesta como fallida o parcial (error {code}) sin detallar "
            "los elementos fallidos; los resultados pueden estar incompletos.",
        },
        "wazuh_api.partial.more": {
            "en": "Further partial failures from the Wazuh API were not listed.",
            "es": "No se listan más fallos parciales de la API de Wazuh.",
        },
        "wazuh_api.warn.forbidden": {
            "en": "The Wazuh API user {user} may not call '{op}' (HTTP 403: {detail}); the related checks were "
            "skipped.",
            "es": "El usuario {user} de la API de Wazuh no puede llamar a '{op}' (HTTP 403: {detail}); se "
            "omitieron las comprobaciones relacionadas.",
        },
        "wazuh_api.note.unavailable": {
            "en": "'{op}' is not available on this Wazuh API (HTTP {status}); the related checks were skipped.",
            "es": "'{op}' no está disponible en esta API de Wazuh (HTTP {status}); se omitieron las "
            "comprobaciones relacionadas.",
        },
        "wazuh_api.note.rules_unsupported": {
            "en": "GET /rules does not exist in Wazuh API {version}; rule metadata was not loaded from the API.",
            "es": "GET /rules no existe en la API de Wazuh {version}; los metadatos de reglas no se cargaron "
            "desde la API.",
        },
        "wazuh_api.note.select_fallback": {
            "en": "'{op}': this Wazuh API version does not know some requested fields (error 1724, e.g. "
            "status_code before 4.7); the request was repeated with fewer fields.",
            "es": "'{op}': esta versión de la API de Wazuh no conoce algunos campos pedidos (error 1724, p. ej. "
            "status_code antes de 4.7); la petición se repitió con menos campos.",
        },
        "wazuh_api.note.stalled": {
            "en": "'{op}': the Wazuh API returned the same page again (it ignored the offset); listing "
            "stopped after {seen} {seen:plural:item|items}.",
            "es": "'{op}': la API de Wazuh devolvió de nuevo la misma página (ignoró el offset); el listado "
            "se detuvo tras {seen} {seen:plural:elemento|elementos}.",
        },
        "wazuh_api.note.failed_items": {
            "en": "'{op}': {count} {count:plural:item was|items were} not returned ({errors}).",
            "es": "'{op}': no se {count:plural:devolvió|devolvieron} {count} "
            "{count:plural:elemento|elementos} ({errors}).",
        },
        "wazuh_api.hint.ca": {
            "en": " (for the Wazuh API: the CA of its certificate. The default self-signed "
            "/var/ossec/api/configuration/ssl/server.crt is only valid for the name 'localhost', so install a "
            "certificate issued for the manager's host name, e.g. signed by the Wazuh root-ca.pem)",
            "es": " (para la API de Wazuh: la CA de su certificado. El certificado autofirmado por defecto "
            "/var/ossec/api/configuration/ssl/server.crt solo es válido para el nombre 'localhost', así que "
            "instala un certificado emitido para el nombre del manager, p. ej. firmado por el root-ca.pem de "
            "Wazuh)",
        },
        "wazuh_api.reason.not_json": {"en": "the body is not valid JSON", "es": "el cuerpo no es JSON válido"},
        "wazuh_api.reason.not_object": {
            "en": "the body is not a JSON object",
            "es": "el cuerpo no es un objeto JSON",
        },
        "wazuh_api.reason.no_data": {
            "en": "the 'data' object is missing",
            "es": "falta el objeto 'data'",
        },
        "wazuh_api.reason.no_items": {
            "en": "data.affected_items is missing or not a list",
            "es": "data.affected_items falta o no es una lista",
        },
    }
)


# ---- parsing helpers (pure, unit-tested) ---------------------------------------------------------------------


def _num(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    number = float(value)
    return number if math.isfinite(number) else None


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


def _text(value: object, limit: int = 256) -> str:
    """A plain string field from the API (numbers accepted), truncated; anything else -> ''."""
    if isinstance(value, str):
        return value[:limit]
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return str(value)
    return ""


def token_ttl(token: str, now: float) -> float:
    """Seconds the JWT is valid for, from its claims (``exp - nbf``/``iat``; else ``exp - now``).

    Using the issuer's own ``nbf``/``iat`` makes the refresh schedule immune to clock skew between hushwatch
    and the manager. Unreadable claims give :data:`DEFAULT_TTL`. The result is clamped to [5 s, 24 h].
    """
    try:
        segment = token.split(".")[1]
        claims = loads_json(base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4)))
    except (ValueError, IndexError):  # binascii.Error is a ValueError
        return DEFAULT_TTL
    if not isinstance(claims, dict):
        return DEFAULT_TTL
    exp = _num(claims.get("exp"))
    issued = _num(claims.get("nbf"))
    if issued is None:
        issued = _num(claims.get("iat"))
    if exp is None:
        return DEFAULT_TTL
    if issued is not None and exp > issued:
        ttl = exp - issued
    elif exp > now:
        ttl = exp - now
    else:
        return DEFAULT_TTL
    return min(max(ttl, 5.0), 86400.0)


def _last_page(items: list[Any], total: int | None, offset: int) -> bool:
    """Stop paging on an empty page, once ``total_affected_items`` is reached, or - when the API gave no
    total - on a short page."""
    if not items:
        return True
    return offset >= total if total is not None else len(items) < PAGE_SIZE


def _api_time(value: object) -> datetime | None:
    """Wazuh API ISO-8601 time; sentinels (agent 000's 9999-12-31, epoch 0 for never-connected) -> None."""
    if not isinstance(value, str) or not value.strip():
        return None
    parsed = parse_ts(value)
    if parsed is None or parsed.year >= 9000 or parsed.year < 1990:
        return None
    return parsed


def platform_family(platform: str | None, os_name: str | None = None) -> str | None:
    """Normalize Wazuh ``os.platform`` / ``os.name`` to ``windows | linux | darwin | bsd | solaris | aix |
    hpux`` (unknown platforms are returned lower-cased; nothing known -> None)."""
    plat = (platform or "").strip().lower()
    name = (os_name or "").strip().lower()
    if plat == "windows" or "windows" in name:
        return "windows"
    if plat in ("darwin", "macos", "osx") or "macos" in name or "mac os" in name:
        return "darwin"
    if plat in _LINUX_PLATFORMS or "linux" in name:
        return "linux"
    if plat.endswith("bsd") or "bsd" in name:
        return "bsd"
    if plat in ("sunos", "solaris") or "solaris" in name or "sunos" in name:
        return "solaris"
    if plat == "aix" or name.startswith("aix"):
        return "aix"
    if plat in ("hp-ux", "hpux") or "hp-ux" in name:
        return "hpux"
    return plat[:32] or None


def _agent_id(value: object) -> str | None:
    """Wazuh agent ids are zero-padded decimal strings (``"001"``); ints are padded. Anything else -> None."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return f"{value:03d}" if 0 <= value < 10**9 else None
    if isinstance(value, str):
        text = value.strip()
        if text.isascii() and text.isdigit() and len(text) <= 9:
            return text.zfill(3)
    return None


def parse_agent(raw: object) -> AgentInfo | None:
    """One ``GET /agents`` item -> :class:`AgentInfo` (None when it has no usable id).

    Every field but ``id`` is optional (``never_connected`` agents lack os/version/keepalive). Agent ``000``
    is the manager itself: its ``lastKeepAlive`` sentinel (9999-12-31) becomes None and
    ``AgentInfo.is_manager`` flags it. ``platform`` is the normalized family (see :func:`platform_family`);
    the raw ``os.platform`` is kept in ``extra["os_platform"]``.
    """
    if not isinstance(raw, Mapping):
        return None
    agent_id = _agent_id(raw.get("id"))
    if agent_id is None:
        return None
    status_raw = _text(raw.get("status"), 64).strip().lower().replace(" ", "_")
    status = status_raw if status_raw in _KNOWN_STATUSES else "unknown"
    os_obj = raw.get("os")
    os_map: Mapping[str, Any] = os_obj if isinstance(os_obj, Mapping) else {}
    os_platform = _text(os_map.get("platform"), 64)
    os_name = _text(os_map.get("name"), 128) or None
    groups_raw = raw.get("group")
    if isinstance(groups_raw, list):
        groups = tuple(g[:128] for g in groups_raw if isinstance(g, str) and g)
    elif isinstance(groups_raw, str):
        groups = tuple(g.strip()[:128] for g in groups_raw.split(",") if g.strip())
    else:
        groups = ()
    extra: dict[str, str] = {}
    for key, value in (
        ("ip", _text(raw.get("ip"), 64)),
        ("status_code", _text(raw.get("status_code"), 8)),
        ("os_platform", os_platform),
    ):
        if value:
            extra[key] = value
    if status_raw and status == "unknown":
        extra["status_raw"] = status_raw
    return AgentInfo(
        id=agent_id,
        name=_text(raw.get("name")),
        status=status,
        last_keepalive=_api_time(raw.get("lastKeepAlive")),
        date_add=_api_time(raw.get("dateAdd")),
        platform=platform_family(os_platform, os_name),
        os_name=os_name,
        groups=groups,
        version=_text(raw.get("version"), 64) or None,
        node=_text(raw.get("node_name"), 128) or None,
        extra=extra,
    )


class WazuhAPI:
    """Read-only Wazuh server API client built from :class:`~hushwatch.config.ApiConfig`.

    ``transport`` (``httpx.MockTransport``), ``clock`` (seconds; wall clock for token expiry and the rate
    limiter) and ``sleep`` are injectable for tests. Use as a context manager or call :meth:`close`.
    """

    def __init__(
        self,
        cfg: ApiConfig,
        *,
        transport: httpx.BaseTransport | None = None,
        clock: Callable[[], float] | None = None,
        sleep: Callable[[float], None] | None = None,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
    ) -> None:
        if not cfg.url:
            raise RemoteError(M("wazuh_api.err.no_url"), kind="config")
        if not cfg.username:
            raise RemoteError(M("wazuh_api.err.no_credentials"), kind="config")
        self._user = cfg.username
        self._password = cfg.password or ""
        self._timeout = float(cfg.timeout)
        self._max_bytes = max(1024, int(max_response_bytes))
        self._client = make_client(
            cfg.url, ca_cert=cfg.ca_cert, verify_tls=cfg.verify_tls, timeout=self._timeout, transport=transport
        )
        self._url = safe_url(cfg.url)
        self._shown = Entity("url", self._url)
        self._user_entity = Entity("user", self._user)
        self._clock: Callable[[], float] = clock if clock is not None else time.time
        self._sleep: Callable[[float], None] = sleep if sleep is not None else time.sleep
        self._limiter = RateLimiter(
            cfg.max_requests_per_minute,
            clock=clock if clock is not None else time.monotonic,
            sleep=self._sleep,
        )
        self._basic = base64.b64encode(f"{self._user}:{self._password}".encode()).decode("ascii")
        self._token: str | None = None
        self._refresh_at = 0.0
        self._info: dict[str, Any] | None = None
        self._recorded: set[str] = set()
        self.partial_failures: list[str] = []
        self.failure_messages: list[Message] = []
        self.warnings: list[Message] = []
        self.notes: list[Message] = []
        self.malformed = 0  # agent items without a usable id
        self.logins = 0  # successful authentications (diagnostics / tests)
        if is_plain_http(self._url):
            self.warnings.append(M("net.warn.plain_http", url=self._shown))
        elif not cfg.verify_tls:
            self.warnings.append(M("net.warn.tls_disabled", url=self._shown))

    # ---- lifecycle -------------------------------------------------------------------------------------------
    def apply_to(self, basis: DataBasis) -> None:
        """Fold partial failures (as translatable messages) and warnings into ``basis`` (idempotent)."""
        for msg in self.failure_messages:
            if msg not in basis.partial_failures:
                basis.partial_failures.append(msg)
        for msg in self.warnings:
            if msg not in basis.warnings:
                basis.warnings.append(msg)

    def close(self) -> None:
        """Forget the token and close the connection pool. Deliberately does NOT call
        ``DELETE /security/user/authenticate`` (that would revoke every token of the user)."""
        self._token = None
        self._client.close()

    def __enter__(self) -> WazuhAPI:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def __repr__(self) -> str:
        return f"WazuhAPI(url={self._url!r})"

    # ---- public API ------------------------------------------------------------------------------------------
    def info(self) -> dict[str, Any]:
        """``GET /``: ``api_version``, ``revision``, ``hostname``, ``timestamp``... (cached)."""
        if self._info is None:
            payload = self._payload(self._request("GET", "/", op="GET /"), "GET /")
            self._info = self._data(payload, "GET /")
        return dict(self._info)

    def api_version(self) -> tuple[int, ...]:
        """The API version from :meth:`info` as a tuple (``(4, 14, 8)``); ``()`` when unknown."""
        version = self.info().get("api_version")
        if not isinstance(version, str):
            return ()
        match = re.match(r"\s*v?(\d{1,6})(?:\.(\d{1,6}))?(?:\.(\d{1,6}))?(?!\d)", version)
        return tuple(int(g) for g in match.groups() if g is not None) if match else ()

    def agents(self, *, include_manager: bool = True) -> list[AgentInfo]:
        """Every agent (``GET /agents`` paginated by 500, sorted by id), including ``never_connected`` ones.

        Agent ``000`` (the manager) is included and flagged by ``AgentInfo.is_manager`` unless
        ``include_manager`` is false. Items the API failed to return are recorded in ``partial_failures``.
        """
        op = "GET /agents"
        by_id: dict[str, AgentInfo] = {}
        offset = 0
        total: int | None = None
        malformed = 0
        stalled = False
        selects: tuple[tuple[str, ...] | None, ...] = (AGENT_FIELDS, LEGACY_AGENT_FIELDS, None)
        select_index = 0
        for _ in range(MAX_PAGES):
            params = {"offset": str(offset), "limit": str(PAGE_SIZE), "sort": "+id", "wait_for_complete": "true"}
            fields = selects[select_index]
            if fields is not None:
                params["select"] = ",".join(fields)
            resp = self._request("GET", "/agents", op=op, params=params)
            if (
                resp.status_code == 400
                and offset == 0
                and select_index + 1 < len(selects)
                and self._detail(resp)[0] == SELECT_ERROR
            ):
                select_index += 1  # older manager: ask again with fewer (or all default) fields
                self._note(M("wazuh_api.note.select_fallback", op=op))
                continue
            payload = self._payload(resp, op)
            data = self._data(payload, op)
            self._failed_items(data, op, partial=True, error_code=payload.get("error"))
            items = self._items(data, op)
            total = _as_int(data.get("total_affected_items"))
            added = 0
            for raw in items:
                agent = parse_agent(raw)
                if agent is None:
                    malformed += 1
                elif agent.id not in by_id:
                    by_id[agent.id] = agent
                    added += 1
            offset += len(items)
            if _last_page(items, total, offset):
                break
            if not added:  # a full page with nothing new: the server ignores offset, stop instead of looping
                stalled = True
                break
        self.malformed += malformed
        seen = len(by_id) + malformed  # unique agents: a server repeating pages must not look complete
        if total is not None and seen < total:
            self._record(M("wazuh_api.partial.agents_incomplete", seen=seen, total=total))
        elif stalled:
            self._record(M("wazuh_api.partial.stalled", op=op, seen=seen))
        if malformed:
            self._record(M("wazuh_api.partial.agents_malformed", count=malformed))
        agents = sorted(by_id.values(), key=lambda a: (len(a.id), a.id))
        return [a for a in agents if include_manager or not a.is_manager]

    def rules(self, rule_ids: Iterable[str | int] | None = None) -> list[dict[str, Any]]:
        """Rule metadata from ``GET /rules`` (Wazuh 4.x), paginated; optionally only ``rule_ids``.

        Returns ``[]`` (with a note) when the endpoint does not exist (404, Wazuh 5.x) or is not allowed
        (403, with a warning). Non-numeric ids are ignored. Requested ids the API did not return are listed in
        ``notes`` (e.g. rules renumbered after an upgrade).
        """
        op = "GET /rules"
        version = self._version_or_empty()
        if version and version[0] >= 5:
            self._note(M("wazuh_api.note.rules_unsupported", version=".".join(map(str, version))))
            return []
        chunks: list[list[str] | None]
        if rule_ids is None:
            chunks = [None]
        else:
            wanted: set[int] = set()
            for rule_id in rule_ids:
                text = str(rule_id).strip() if isinstance(rule_id, (str, int)) and not isinstance(rule_id, bool) else ""
                if text.isascii() and text.isdigit() and len(text) <= 9:
                    wanted.add(int(text))
            ordered = [str(r) for r in sorted(wanted)]
            if not ordered:
                return []
            chunks = [ordered[i : i + RULE_IDS_PER_REQUEST] for i in range(0, len(ordered), RULE_IDS_PER_REQUEST)]
        out: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()
        for chunk in chunks:
            offset = 0
            for _ in range(MAX_PAGES):
                params = {"offset": str(offset), "limit": str(PAGE_SIZE), "wait_for_complete": "true"}
                if chunk is not None:
                    params["rule_ids"] = ",".join(chunk)
                resp = self._request("GET", "/rules", op=op, params=params)
                if resp.status_code in _OPTIONAL_STATUSES:
                    self._unavailable(op, resp)
                    return []
                payload = self._payload(resp, op)
                data = self._data(payload, op)
                self._failed_items(data, op, partial=False, error_code=payload.get("error"))
                items = self._items(data, op)
                added = 0
                for item in items:
                    if not isinstance(item, Mapping):
                        continue
                    key = (str(item.get("id")), str(item.get("relative_dirname")) + "/" + str(item.get("filename")))
                    if key not in seen:
                        seen.add(key)
                        out.append(dict(item))
                        added += 1
                total = _as_int(data.get("total_affected_items"))
                offset += len(items)
                if _last_page(items, total, offset):
                    break
                if not added:  # a full page with nothing new: the server ignores offset
                    self._note(M("wazuh_api.note.stalled", op=op, seen=len(out)))
                    break
        return out

    def daemon_stats(self) -> dict[str, Any] | None:
        """``GET /manager/daemons/stats`` (Wazuh >= 4.4): daemon name -> statistics (``wazuh-analysisd``,
        ``wazuh-remoted``, ``wazuh-db``). None when unavailable (older manager, 400/404, RBAC)."""
        op = "GET /manager/daemons/stats"
        resp = self._request("GET", "/manager/daemons/stats", op=op)
        if resp.status_code in _OPTIONAL_STATUSES:
            self._unavailable(op, resp)
            return None
        payload = self._payload(resp, op)
        data = self._data(payload, op)
        self._failed_items(data, op, partial=True, error_code=payload.get("error"))
        out: dict[str, Any] = {}
        for position, item in enumerate(self._items(data, op)):
            if isinstance(item, Mapping):
                name = _text(item.get("name"), 64) or f"daemon-{position}"
                out[name] = dict(item)
        return out or None

    def logcollector_stats(self, agent_id: str | int) -> dict[str, Any] | None:
        """``GET /agents/{id}/stats/logcollector``: per-location event and drop counters of one agent.

        None when unavailable (agent not active, old version, RBAC); the reason goes to ``notes``/``warnings``.
        Raises ValueError for an id that is not a Wazuh agent id (never builds a path from arbitrary text).
        """
        normalized = _agent_id(agent_id)
        if normalized is None:
            raise ValueError("agent_id must be a numeric Wazuh agent id such as '001'")
        op = "GET /agents/{agent_id}/stats/logcollector"
        resp = self._request("GET", f"/agents/{normalized}/stats/logcollector", op=op)
        if resp.status_code in _OPTIONAL_STATUSES:
            self._unavailable(op, resp)
            return None
        payload = self._payload(resp, op)
        data = self._data(payload, op)
        self._failed_items(data, op, partial=False, error_code=payload.get("error"))
        items = self._items(data, op)
        first = items[0] if items else None
        return dict(first) if isinstance(first, Mapping) else None

    def manager_info(self) -> dict[str, Any] | None:
        """``GET /manager/info``: version, type, timezone, paths of the manager. None when unavailable."""
        op = "GET /manager/info"
        resp = self._request("GET", "/manager/info", op=op)
        if resp.status_code in _OPTIONAL_STATUSES:
            self._unavailable(op, resp)
            return None
        payload = self._payload(resp, op)
        data = self._data(payload, op)
        self._failed_items(data, op, partial=False, error_code=payload.get("error"))
        items = self._items(data, op)
        first = items[0] if items else None
        return dict(first) if isinstance(first, Mapping) else None

    # ---- authentication --------------------------------------------------------------------------------------
    def _authenticate(self) -> str:
        self._token = None
        op = f"POST {AUTH_PATH}"
        try:
            request = self._client.build_request("POST", AUTH_PATH, params={"raw": "true"})
            resp = send_bounded(
                self._client,
                request,
                max_bytes=min(self._max_bytes, MAX_TOKEN_RESPONSE_BYTES),
                url=self._url,
                op=op,
                auth=httpx.BasicAuth(self._user, self._password),
            )
        except (httpx.HTTPError, httpx.InvalidURL) as exc:
            raise self._transport_error(exc, op) from None
        if resp.status_code in (401, 403):
            _, detail = self._detail(resp)
            msg = M(
                "wazuh_api.err.login", url=self._shown, user=self._user_entity, status=resp.status_code, detail=detail
            )
            raise RemoteError(msg, kind="auth", status=resp.status_code)
        if resp.status_code == 429:
            raise RemoteError(M("wazuh_api.err.rate_limited", op=op, attempts=1), kind="rate_limited", status=429)
        if not 200 <= resp.status_code < 300:
            raise self._http_error(resp, op)
        token = self._parse_token(resp)
        now = self._clock()
        ttl = token_ttl(token, now)
        self._token = token
        self._refresh_at = now + ttl - min(REFRESH_MARGIN, max(1.0, ttl * 0.25))
        self.logins += 1
        return token

    def _parse_token(self, resp: httpx.Response) -> str:
        text = resp.content[:65536].decode("utf-8", "replace").strip()
        if text.startswith("{"):  # ?raw=true ignored: {"data": {"token": "..."}}
            try:
                payload = loads_json(text)
            except ValueError:
                payload = None
            data = payload.get("data") if isinstance(payload, Mapping) else None
            token = data.get("token") if isinstance(data, Mapping) else None
            text = token.strip() if isinstance(token, str) else ""
        text = text.strip('"')
        if not _JWT.fullmatch(text):
            raise RemoteError(M("wazuh_api.err.token", url=self._shown), kind="protocol")
        return text

    def _ensure_token(self) -> str:
        """The current JWT, logging in first when there is none or it is about to expire."""
        if self._token is None or self._clock() >= self._refresh_at:
            return self._authenticate()
        return self._token

    # ---- HTTP plumbing ---------------------------------------------------------------------------------------
    def _secrets(self) -> tuple[str, ...]:
        return tuple(s for s in (self._password, self._token, self._basic) if s)

    def _transport_error(self, exc: BaseException, op: str) -> RemoteError:
        return transport_error(
            exc, url=self._url, op=op, timeout=self._timeout, hint=M("wazuh_api.hint.ca"), secrets=self._secrets()
        )

    def _request(self, method: str, path: str, *, op: str, params: Mapping[str, str] | None = None) -> httpx.Response:
        reauthenticated = False
        throttled = 0
        server_errors = 0
        while True:
            # Wait for a rate-limit slot BEFORE picking the token: the wait can last up to a minute, and a token
            # checked before it could expire while we sleep (401, re-login, then possibly a second fatal 401).
            self._limiter.acquire()
            token = self._ensure_token()
            try:
                request = self._client.build_request(
                    method, path, params=params, headers={"Authorization": f"Bearer {token}"}
                )
                resp = send_bounded(self._client, request, max_bytes=self._max_bytes, url=self._url, op=op)
            except (httpx.HTTPError, httpx.InvalidURL) as exc:
                raise self._transport_error(exc, op) from None
            status = resp.status_code
            if status == 401:
                if reauthenticated:
                    msg = M("wazuh_api.err.unauthorized", op=op, user=self._user_entity)
                    raise RemoteError(msg, kind="auth", status=401)
                reauthenticated = True
                self._token = None  # log in again (token expired early or was revoked), then retry once
                continue
            if status == 429:
                if throttled >= MAX_429_RETRIES:
                    msg = M("wazuh_api.err.rate_limited", op=op, attempts=throttled + 1)
                    raise RemoteError(msg, kind="rate_limited", status=429)
                self._sleep(retry_after(resp) or backoff_delay(throttled, cap=60.0))
                throttled += 1
                continue
            if status in (502, 503, 504) and server_errors < MAX_5XX_RETRIES:
                self._sleep(backoff_delay(server_errors, base=2.0, cap=30.0))
                server_errors += 1
                continue
            return resp

    def _payload(self, resp: httpx.Response, op: str) -> dict[str, Any]:
        if not 200 <= resp.status_code < 300:
            raise self._http_error(resp, op)
        try:
            payload = loads_json(resp.content)
        except ValueError:
            raise self._protocol(op, M("wazuh_api.reason.not_json")) from None
        if not isinstance(payload, dict):
            raise self._protocol(op, M("wazuh_api.reason.not_object"))
        return payload

    def _data(self, payload: Mapping[str, Any], op: str) -> dict[str, Any]:
        data = payload.get("data")
        if not isinstance(data, Mapping):
            raise self._protocol(op, M("wazuh_api.reason.no_data"))
        return dict(data)

    def _items(self, data: Mapping[str, Any], op: str) -> list[Any]:
        items = data.get("affected_items")
        if not isinstance(items, list):  # missing is an error, never "zero items"
            raise self._protocol(op, M("wazuh_api.reason.no_items"))
        return items

    def _detail(self, resp: httpx.Response) -> tuple[str, str]:
        """(error code, "title: detail") from a Wazuh error body, sanitized (untrusted text)."""
        try:
            payload = loads_json(resp.content)
        except ValueError:
            payload = None
        code: object = "-"
        text: object = ""
        if isinstance(payload, Mapping):
            code = payload.get("error", "-")
            parts = [str(p) for p in (payload.get("title"), payload.get("detail")) if isinstance(p, str) and p]
            text = ": ".join(parts)
        elif resp.content:
            text = resp.content[:500].decode("utf-8", "replace")
        detail = sanitize_text(text, limit=300, secrets=self._secrets()) or resp.reason_phrase or "-"
        return sanitize_text(code, limit=20), detail

    def _http_error(self, resp: httpx.Response, op: str) -> RemoteError:
        status = resp.status_code
        code, detail = self._detail(resp)
        if status == 403:
            msg = M("wazuh_api.err.forbidden", user=self._user_entity, op=op, detail=detail)
            return RemoteError(msg, kind="forbidden", status=status)
        kind = "not_found" if status == 404 else "http"
        return RemoteError(
            M("wazuh_api.err.http", status=status, op=op, code=code, detail=detail), kind=kind, status=status
        )

    def _protocol(self, op: str, reason: Message) -> RemoteError:
        return RemoteError(M("wazuh_api.err.protocol", op=op, reason=reason), kind="protocol")

    def _failed_items(self, data: Mapping[str, Any], op: str, *, partial: bool, error_code: object = 0) -> None:
        """Surface ``data.failed_items`` (safe summary of up to three error codes/messages).

        ``error_code`` is the response's top-level ``error`` (0 complete, 1 failed, 2 partial): a response
        flagged 1/2 that lists no failed item is still reported, never taken as a complete result.
        """
        items = data.get("failed_items")
        count = _as_int(data.get("total_failed_items")) or 0
        if not isinstance(items, list) or not items:
            if count <= 0:
                flag = _as_int(error_code)
                if flag in (1, 2):
                    msg = M("wazuh_api.partial.flagged", op=op, code=flag)
                    if partial:
                        self._record(msg)
                    else:
                        self._note(msg)
                return
            items = []
        summaries: list[str] = []
        for item in items:
            error = item.get("error") if isinstance(item, Mapping) else None
            if not isinstance(error, Mapping):
                continue
            code = sanitize_text(error.get("code", "-"), limit=12)
            message = sanitize_text(error.get("message", ""), limit=160, secrets=self._secrets())
            summary = f"[{code}] {message}".strip()
            if summary not in summaries:
                summaries.append(summary)
            if len(summaries) >= 3:
                break
        count = max(count, len(items))
        errors = "; ".join(summaries) or "-"
        if partial:
            self._record(M("wazuh_api.partial.failed_items", op=op, count=count, errors=errors))
        else:
            self._note(M("wazuh_api.note.failed_items", op=op, count=count, errors=errors))

    def _unavailable(self, op: str, resp: httpx.Response) -> None:
        if resp.status_code == 403:
            _, detail = self._detail(resp)
            self._warn(M("wazuh_api.warn.forbidden", user=self._user_entity, op=op, detail=detail))
        else:
            self._note(M("wazuh_api.note.unavailable", op=op, status=resp.status_code))

    def _version_or_empty(self) -> tuple[int, ...]:
        try:
            return self.api_version()
        except RemoteError as exc:
            if exc.kind in ("auth", "connection", "timeout", "tls", "config", "rate_limited"):
                raise
            return ()

    # ---- bookkeeping -----------------------------------------------------------------------------------------
    def _record(self, msg: Message) -> None:
        if len(self.partial_failures) > 50:
            return
        text = sanitize_text(render(msg, "en"), limit=600, secrets=self._secrets())
        if text in self._recorded:
            return
        self._recorded.add(text)
        if len(self.partial_failures) == 50:
            msg = M("wazuh_api.partial.more")
            text = render(msg, "en")
        self.partial_failures.append(text)
        self.failure_messages.append(sanitize_message(msg, limit=600, secrets=self._secrets()))

    def _warn(self, msg: Message) -> None:
        if msg not in self.warnings:
            self.warnings.append(msg)

    def _note(self, msg: Message) -> None:
        if msg not in self.notes and len(self.notes) < 50:
            self.notes.append(msg)
