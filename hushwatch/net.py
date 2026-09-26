"""Shared HTTP/TLS helpers for the remote clients (Wazuh indexer / OpenSearch / Elasticsearch, Wazuh API).

Security rules implemented here, so every client gets them for free:

* TLS is verified against the system trust store plus an optional per-tenant CA file, through an explicit
  :class:`ssl.SSLContext` (httpx 0.28 deprecates passing a path to ``verify``). Verification is disabled only
  when the configuration says ``verify_tls: false``; callers record that as a report warning.
* Credentials never travel in URLs, redirects are not followed (so credentials never reach another host),
  and :class:`RemoteError` messages never contain passwords, tokens, API keys or full PIT/scroll ids.
* Server-provided text (error reasons) is treated as untrusted: control characters are removed, secrets are
  scrubbed, and the text is truncated before it reaches a message.
"""

from __future__ import annotations

import importlib
import json
import math
import os
import re
import ssl
import threading
import time
from collections import deque
from collections.abc import Callable, Iterable, Mapping
from typing import Any
from urllib.parse import quote, urlsplit, urlunsplit

import httpx

from . import __version__
from .i18n import Entity, EntityFormatter, M, Message, register, render

__all__ = [
    "DEFAULT_MAX_RESPONSE_BYTES",
    "ERROR_KINDS",
    "RateLimiter",
    "RemoteError",
    "backoff_delay",
    "build_ssl_context",
    "is_plain_http",
    "loads_json",
    "make_client",
    "redact_secret",
    "retry_after",
    "safe_url",
    "sanitize_text",
    "send_bounded",
    "transport_error",
    "validate_base_url",
]

# RemoteError.kind values. "config" maps to a usage/config error (exit 2); the others make the analysis
# incomplete (exit 3).
ERROR_KINDS: tuple[str, ...] = (
    "config",
    "tls",
    "auth",
    "forbidden",
    "not_found",
    "connection",
    "timeout",
    "rate_limited",
    "http",
    "protocol",
    "partial",
)

USER_AGENT = f"hushwatch/{__version__}"
CONNECT_TIMEOUT_CAP = 15.0  # seconds; the TCP/TLS connect phase never waits longer than this
# Largest (decoded) response body read into memory; bigger bodies are refused, not buffered.
DEFAULT_MAX_RESPONSE_BYTES = 256 * 1024 * 1024
_BODY_HEADERS = frozenset({"content-encoding", "content-length", "transfer-encoding"})

register(
    {
        "net.err.tls_verify": {
            "en": "TLS certificate verification failed for {url} ({reason}). Set ca_cert to the CA certificate "
            "that signed the server certificate{hint}. Do not disable verification.",
            "es": "Falló la verificación del certificado TLS de {url} ({reason}). Configure ca_cert con el "
            "certificado de la CA que firmó el certificado del servidor{hint}. No desactive la verificación.",
        },
        "net.err.tls_hostname": {
            "en": "The TLS certificate of {url} does not match its host name ({reason}). Use a host name or IP "
            "address listed in the certificate (subjectAltName) in the URL, or reissue the certificate.",
            "es": "El certificado TLS de {url} no corresponde a su nombre de host ({reason}). Use en la URL un "
            "nombre o IP incluido en el certificado (subjectAltName) o vuelva a emitir el certificado.",
        },
        "net.err.tls": {
            "en": "TLS handshake with {url} failed ({reason}). Check that the scheme (https/http) and port are "
            "correct.",
            "es": "Falló la negociación TLS con {url} ({reason}). Verifique que el esquema (https/http) y el "
            "puerto sean correctos.",
        },
        "net.err.connect": {
            "en": "Cannot connect to {url} ({reason}). Check the URL, the port, firewalls and that the service "
            "is running.",
            "es": "No se puede conectar con {url} ({reason}). Revise la URL, el puerto, los cortafuegos y que el "
            "servicio esté en marcha.",
        },
        "net.err.timeout": {
            "en": "The request '{op}' to {url} timed out after {seconds:.0f} s. Increase 'timeout' or narrow "
            "the time range.",
            "es": "La petición '{op}' a {url} superó el tiempo de espera ({seconds:.0f} s). Aumente 'timeout' o "
            "reduzca el intervalo de tiempo.",
        },
        "net.err.connection": {
            "en": "The connection to {url} failed during '{op}' ({reason}).",
            "es": "La conexión con {url} falló durante '{op}' ({reason}).",
        },
        "net.err.ca_file": {
            "en": "Cannot load the CA certificate {path} ({reason}). ca_cert must point to a readable PEM file "
            "or directory.",
            "es": "No se puede cargar el certificado de CA {path} ({reason}). ca_cert debe apuntar a un archivo "
            "PEM o directorio legible.",
        },
        "net.err.url": {
            "en": "Invalid service URL {url}: {reason}.",
            "es": "URL de servicio no válida {url}: {reason}.",
        },
        "net.err.url_credentials": {
            "en": "The URL {url} embeds credentials. Remove them from the URL and set username/password (as "
            "${{ENV_VAR}} references) instead.",
            "es": "La URL {url} incluye credenciales. Quítelas de la URL y use username/password (como "
            "referencias ${{VARIABLE}}) en su lugar.",
        },
        "net.err.timeout_value": {
            "en": "Invalid timeout {value}: it must be a positive number of seconds.",
            "es": "Tiempo de espera no válido {value}: debe ser un número positivo de segundos.",
        },
        "net.err.connect_timeout": {
            "en": "Cannot connect to {url}: no answer within {seconds:.0f} s. Check the URL, the port, firewalls "
            "and that the service is running.",
            "es": "No se puede conectar con {url}: sin respuesta en {seconds:.0f} s. Revise la URL, el puerto, los "
            "cortafuegos y que el servicio esté en marcha.",
        },
        "net.err.too_large": {
            "en": "The response of {url} to '{op}' exceeded the {limit:.0f} MiB safety limit and was discarded; "
            "the results are incomplete. Request smaller pages (e.g. a lower page_size).",
            "es": "La respuesta de {url} a '{op}' superó el límite de seguridad de {limit:.0f} MiB y se descartó; "
            "los resultados están incompletos. Pida páginas más pequeñas (p. ej. un page_size menor).",
        },
        "net.warn.tls_disabled": {
            "en": "TLS certificate verification is DISABLED for {url} (verify_tls: false). Traffic and "
            "credentials can be intercepted; set ca_cert instead.",
            "es": "La verificación de certificados TLS está DESACTIVADA para {url} (verify_tls: false). El "
            "tráfico y las credenciales pueden interceptarse; configure ca_cert en su lugar.",
        },
        "net.warn.plain_http": {
            "en": "{url} is reached over plain HTTP: credentials, tokens and security data cross the network "
            "unencrypted. Use https.",
            "es": "Se accede a {url} por HTTP sin cifrar: credenciales, tokens y datos de seguridad viajan por la "
            "red en claro. Use https.",
        },
        "net.reason.scheme": {
            "en": "the scheme must be http or https",
            "es": "el esquema debe ser http o https",
        },
        "net.reason.host": {"en": "the host is missing", "es": "falta el host"},
        "net.reason.query": {
            "en": "query strings and fragments are not allowed in a base URL",
            "es": "no se admiten parámetros de consulta ni fragmentos en una URL base",
        },
        "net.reason.port": {"en": "the port is not valid", "es": "el puerto no es válido"},
    }
)


class RemoteError(Exception):
    """A remote service failed in a way the caller must report (never silently treat as "no data").

    ``str(error)`` is a safe English message: it never contains passwords, tokens, API keys or full
    PIT/scroll ids. ``message`` is the i18n :class:`Message` (render it with :meth:`render` for Spanish or with
    a redacting entity formatter). ``kind`` is one of :data:`ERROR_KINDS`; ``status`` is the HTTP status when
    there was one.
    """

    def __init__(self, message: Message | str, *, kind: str = "http", status: int | None = None) -> None:
        self.message: Message | str = message
        self.kind = kind if kind in ERROR_KINDS else "http"
        self.status = status
        super().__init__(render(message, "en"))

    def render(self, lang: str = "en", entity: EntityFormatter | None = None) -> str:
        """Render the message in ``lang`` (optionally pseudonymizing entities)."""
        if entity is None:
            return render(self.message, lang)
        return render(self.message, lang, entity)


# ---- secrets and untrusted text ------------------------------------------------------------------------------

_JWT_LIKE = re.compile(r"eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*")
# Credential-looking value after an auth scheme word: needs a digit or base64 symbol, so prose survives.
_BEARER = re.compile(r"(?i)\b(bearer|basic|apikey)\s+(?=[A-Za-z0-9+/=._~-]*[0-9+/=])[A-Za-z0-9+/=._~-]{12,}")
# C0/C1 controls, zero-width, bidi overrides and line/paragraph separators (terminal / report spoofing).
_UNSAFE_CHARS = re.compile("[\x00-\x1f\x7f-\x9f\u200b-\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069\ufeff]+")
_MAX_SCRUB_INPUT = 65536


def redact_secret(secret: str | None, *, keep: int = 4) -> str:
    """Show a secret-ish handle (token, PIT/scroll id) without revealing it: ``"FGlu…(412 chars)"``.

    Short values are fully masked. Never use this for passwords (use ``"***"``).
    """
    if not secret:
        return ""
    keep = max(0, keep)
    if len(secret) <= max(12, keep * 3):
        return "***"
    return f"{secret[:keep]}…({len(secret)} chars)"


def _secret_forms(secret: str) -> set[str]:
    """The literal secret plus the JSON-escaped and percent-encoded spellings a server may echo."""
    forms = {secret, json.dumps(secret)[1:-1], json.dumps(secret, ensure_ascii=False)[1:-1], quote(secret, safe="")}
    return {form for form in forms if len(form) >= 3}


def sanitize_text(value: object, *, limit: int = 300, secrets: Iterable[str | None] = ()) -> str:
    """Make server-provided text safe for a message: scrub secrets, strip control characters, truncate.

    ``secrets`` are exact values (password, API key, token, PIT/scroll ids) replaced by ``***`` wherever they
    occur (also JSON-escaped or percent-encoded). Nothing of a secret survives: no prefix, no length.
    JWT-looking strings and ``Bearer``/``Basic``/``ApiKey`` credentials are always masked.
    """
    text = value if isinstance(value, str) else repr(value)
    text = text[:_MAX_SCRUB_INPUT]
    forms: set[str] = set()
    for secret in secrets:
        if secret:
            forms |= _secret_forms(secret)
    for form in sorted(forms, key=len, reverse=True):
        if form in text:
            text = text.replace(form, "***")
    text = _JWT_LIKE.sub("eyJ…[token]", text)
    text = _BEARER.sub(lambda m: f"{m.group(1)} ***", text)
    text = _UNSAFE_CHARS.sub(" ", text)
    text = " ".join(text.split())
    if len(text) > limit:
        text = text[: max(0, limit - 1)].rstrip() + "…"
    return text


def sanitize_message(msg: Message, *, limit: int = 300, secrets: Iterable[str | None] = ()) -> Message:
    """``msg`` with every text parameter made safe like :func:`sanitize_text` (nested messages and entity values
    too), for messages built from server-provided text that end up in a report (``DataBasis.partial_failures``)."""
    known = tuple(secret for secret in secrets if secret)

    def clean(value: Any, depth: int) -> Any:
        if isinstance(value, str):
            return sanitize_text(value, limit=limit, secrets=known)
        if isinstance(value, Entity):
            return Entity(value.kind, sanitize_text(value.value, limit=limit, secrets=known))
        if isinstance(value, Message):
            if depth > 8:
                return sanitize_text(render(value, "en"), limit=limit, secrets=known)
            return Message(value.key, {str(k): clean(v, depth + 1) for k, v in value.params.items()}, value.default)
        if isinstance(value, (list, tuple)):
            return [clean(item, depth + 1) for item in list(value)[:50]]
        return value

    cleaned = clean(msg, 0)
    return cleaned if isinstance(cleaned, Message) else msg


def safe_url(url: str | httpx.URL | None) -> str:
    """``scheme://host:port/path`` without credentials, query string or fragment (for messages)."""
    if url is None:
        return ""
    try:
        parts = urlsplit(str(url))
        port = parts.port
    except ValueError:
        return "<invalid url>"
    host = parts.hostname or ""
    if ":" in host:
        host = f"[{host}]"
    netloc = f"{host}:{port}" if port is not None else host
    return urlunsplit((parts.scheme, netloc, parts.path.rstrip("/"), "", ""))


def validate_base_url(url: str) -> str:
    """Validate a service base URL (http/https, host, no credentials/query) and return it without a trailing
    slash. Raises :class:`RemoteError` (kind ``config``)."""
    shown = Entity("url", safe_url(url))
    try:
        parts = urlsplit(url.strip())
        port = parts.port
    except (ValueError, AttributeError):
        raise RemoteError(M("net.err.url", url=shown, reason=M("net.reason.port")), kind="config") from None
    if parts.scheme.lower() not in ("http", "https"):
        raise RemoteError(M("net.err.url", url=shown, reason=M("net.reason.scheme")), kind="config")
    if parts.username is not None or parts.password is not None or "@" in parts.netloc:
        raise RemoteError(M("net.err.url_credentials", url=shown), kind="config")
    if not parts.hostname:
        raise RemoteError(M("net.err.url", url=shown, reason=M("net.reason.host")), kind="config")
    if parts.query or parts.fragment:
        raise RemoteError(M("net.err.url", url=shown, reason=M("net.reason.query")), kind="config")
    del port  # parsed only to validate it
    return urlunsplit((parts.scheme.lower(), parts.netloc, parts.path.rstrip("/"), "", ""))


# ---- TLS -----------------------------------------------------------------------------------------------------


def build_ssl_context(ca_cert: str | None, verify: bool) -> ssl.SSLContext | bool:
    """TLS settings for httpx: an :class:`ssl.SSLContext` trusting the system store plus ``ca_cert``.

    Returns ``False`` only when ``verify`` is explicitly false (``verify_tls: false`` in the config); the
    caller must surface that as a warning. ``ca_cert`` may be a PEM file or a directory of hashed certs.
    When a private CA is configured, Python 3.13's ``VERIFY_X509_STRICT`` flag is cleared because installer
    generated certificates (Wazuh's included) often lack extensions it requires; chain and host name
    verification stay on. Raises :class:`RemoteError` (kind ``config``) when the CA cannot be loaded.
    """
    if not verify:
        return False
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    if ctx.cert_store_stats().get("x509_ca", 0) == 0:
        _load_certifi(ctx)  # system store unavailable or lazily loaded (capath): add the certifi bundle
    if ca_cert:
        path = os.path.expanduser(ca_cert)
        try:
            if os.path.isdir(path):
                ctx.load_verify_locations(capath=path)
            else:
                ctx.load_verify_locations(cafile=path)
        except (OSError, ssl.SSLError, ValueError) as exc:
            reason = sanitize_text(getattr(exc, "strerror", None) or getattr(exc, "reason", None) or exc, limit=120)
            raise RemoteError(
                M("net.err.ca_file", path=Entity("file", ca_cert), reason=reason), kind="config"
            ) from None
        strict = getattr(ssl, "VERIFY_X509_STRICT", 0)
        if strict:
            ctx.verify_flags &= ~strict
    return ctx


def _load_certifi(ctx: ssl.SSLContext) -> None:
    try:
        certifi = importlib.import_module("certifi")
        where = certifi.where()
        if isinstance(where, str):
            ctx.load_verify_locations(cafile=where)
    except (ImportError, OSError, ssl.SSLError, AttributeError):  # pragma: no cover - best effort
        return


def make_client(
    base_url: str,
    *,
    ca_cert: str | None,
    verify_tls: bool,
    timeout: float,
    auth: httpx.Auth | tuple[str, str] | None = None,
    headers: Mapping[str, str] | None = None,
    transport: httpx.BaseTransport | None = None,
) -> httpx.Client:
    """Build an :class:`httpx.Client` for a SIEM endpoint with safe defaults.

    TLS through :func:`build_ssl_context` (never a path string), no redirects (credentials never follow a
    redirect to another host), a bounded connect timeout, JSON ``Accept`` and a hushwatch User-Agent.
    ``transport`` is for tests (``httpx.MockTransport``); environment proxies are ignored when it is set.
    """
    url = validate_base_url(base_url)
    if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or not math.isfinite(timeout) or timeout <= 0:
        raise RemoteError(M("net.err.timeout_value", value=str(timeout)), kind="config")
    verify: ssl.SSLContext | bool = True
    if url.startswith("https://"):
        verify = build_ssl_context(ca_cert, verify_tls)
    merged = {"Accept": "application/json", "User-Agent": USER_AGENT}
    if headers:
        merged.update(headers)
    return httpx.Client(
        base_url=url,
        verify=verify,
        timeout=httpx.Timeout(float(timeout), connect=min(float(timeout), CONNECT_TIMEOUT_CAP)),
        auth=auth,
        headers=merged,
        transport=transport,
        follow_redirects=False,
    )


def is_plain_http(url: str) -> bool:
    """True for an ``http://`` URL (no TLS: callers record :data:`net.warn.plain_http` as a report warning)."""
    return url.strip().lower().startswith("http://")


def send_bounded(
    client: httpx.Client,
    request: httpx.Request,
    *,
    max_bytes: int,
    url: str,
    op: str,
    auth: httpx.Auth | None = None,
) -> httpx.Response:
    """Send ``request`` and read its body into memory, refusing bodies larger than ``max_bytes``.

    The limit applies to the DECODED body (so a gzip bomb is caught too) and is enforced while streaming,
    before anything bigger is buffered. A declared ``Content-Length`` above the limit is refused without
    reading. Raises :class:`RemoteError` (kind ``protocol``) when the limit is exceeded; transport failures
    propagate as ``httpx`` exceptions (map them with :func:`transport_error`). The returned response is fully
    read (``.content`` works; it no longer carries ``Content-Encoding``).
    """
    response = client.send(request, stream=True, auth=httpx.USE_CLIENT_DEFAULT if auth is None else auth)
    try:
        declared = response.headers.get("content-length", "").strip()
        if declared.isdigit() and int(declared) > max_bytes:
            raise _too_large(url, op, max_bytes)
        buffer = bytearray()
        for chunk in response.iter_bytes():
            buffer += chunk
            if len(buffer) > max_bytes:
                raise _too_large(url, op, max_bytes)
    finally:
        response.close()
    headers = [(k, v) for k, v in response.headers.multi_items() if k.lower() not in _BODY_HEADERS]
    extensions = {k: v for k, v in response.extensions.items() if k in ("http_version", "reason_phrase")}
    return httpx.Response(
        response.status_code, headers=headers, content=bytes(buffer), request=request, extensions=extensions
    )


def _too_large(url: str, op: str, max_bytes: int) -> RemoteError:
    limit = max_bytes / (1024 * 1024)
    return RemoteError(M("net.err.too_large", url=Entity("url", safe_url(url)), op=op, limit=limit), kind="protocol")


# ---- errors --------------------------------------------------------------------------------------------------


def _ssl_error_in(exc: BaseException) -> ssl.SSLError | None:
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen and len(seen) < 16:
        if isinstance(current, ssl.SSLError):
            return current
        seen.add(id(current))
        current = current.__cause__ or current.__context__
    return None


def transport_error(
    exc: BaseException,
    *,
    url: str,
    op: str = "request",
    timeout: float | None = None,
    hint: Message | str = "",
    secrets: Iterable[str | None] = (),
) -> RemoteError:
    """Translate a transport-level failure (DNS, TCP, TLS, timeout) into an actionable :class:`RemoteError`.

    TLS verification failures recommend ``ca_cert`` (``hint`` adds a service-specific location), never
    disabling verification.
    """
    shown = Entity("url", safe_url(url))
    if isinstance(exc, httpx.ConnectTimeout):  # host unreachable / filtered: a bigger read timeout won't help
        seconds = min(float(timeout or 0.0), CONNECT_TIMEOUT_CAP)
        return RemoteError(M("net.err.connect_timeout", url=shown, seconds=seconds), kind="timeout")
    if isinstance(exc, httpx.TimeoutException):
        return RemoteError(M("net.err.timeout", url=shown, op=op, seconds=float(timeout or 0.0)), kind="timeout")
    ssl_exc = _ssl_error_in(exc)
    reason = sanitize_text(str(ssl_exc or exc) or type(exc).__name__, limit=200, secrets=secrets)
    lowered = reason.lower()
    if ssl_exc is not None or "certificate_verify_failed" in lowered or "[ssl" in lowered:
        if "hostname mismatch" in lowered or "ip address mismatch" in lowered or "doesn't match" in lowered:
            return RemoteError(M("net.err.tls_hostname", url=shown, reason=reason), kind="tls")
        if "certificate_verify_failed" in lowered or "certificate verify failed" in lowered:
            return RemoteError(M("net.err.tls_verify", url=shown, reason=reason, hint=hint), kind="tls")
        return RemoteError(M("net.err.tls", url=shown, reason=reason), kind="tls")
    if isinstance(exc, httpx.ConnectError):
        return RemoteError(M("net.err.connect", url=shown, reason=reason), kind="connection")
    return RemoteError(M("net.err.connection", url=shown, op=op, reason=reason), kind="connection")


def retry_after(response: httpx.Response, *, cap: float = 120.0) -> float | None:
    """Seconds from a ``Retry-After`` header (numeric form only), clamped to ``[0, cap]``."""
    value = response.headers.get("retry-after")
    if not value:
        return None
    try:
        seconds = float(value.strip())
    except ValueError:
        return None
    if not math.isfinite(seconds):
        return None
    return min(max(seconds, 0.0), cap)


def backoff_delay(attempt: int, *, base: float = 1.0, cap: float = 60.0) -> float:
    """Exponential backoff: ``base * 2**attempt`` capped at ``cap`` (attempt 0 -> base)."""
    return float(min(cap, base * (2 ** min(max(attempt, 0), 16))))


# ---- JSON ----------------------------------------------------------------------------------------------------


def _orjson_loads() -> Callable[[bytes], Any] | None:
    try:
        module = importlib.import_module("orjson")
    except ImportError:
        return None
    loads = getattr(module, "loads", None)
    return loads if callable(loads) else None


_FAST_LOADS = _orjson_loads()


def loads_json(content: bytes | str) -> Any:
    """Parse JSON (orjson when installed). Raises ValueError on invalid, too deep or oversized input."""
    try:
        if _FAST_LOADS is not None:
            return _FAST_LOADS(content if isinstance(content, bytes) else content.encode("utf-8", "surrogatepass"))
        return json.loads(content)
    except RecursionError:
        raise ValueError("JSON nested too deeply") from None
    except (TypeError, UnicodeDecodeError) as exc:
        raise ValueError(f"invalid JSON: {type(exc).__name__}") from None


# ---- rate limiting -------------------------------------------------------------------------------------------


class RateLimiter:
    """Sliding-window limiter: at most ``max_per_minute`` calls in any ``period`` seconds (0 disables it).

    ``clock`` and ``sleep`` are injectable for tests. :meth:`acquire` blocks (sleeps) until a slot is free and
    returns the seconds waited. It never loops forever, even with a clock that does not advance.
    """

    def __init__(
        self,
        max_per_minute: int,
        *,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        period: float = 60.0,
    ) -> None:
        self.max_per_minute = max(0, int(max_per_minute))
        self.period = float(period)
        self._clock = clock
        self._sleep = sleep
        self._stamps: deque[float] = deque()
        self._lock = threading.Lock()

    def _purge(self, now: float) -> None:
        while self._stamps and now - self._stamps[0] >= self.period:
            self._stamps.popleft()

    def acquire(self) -> float:
        """Take one slot, sleeping first if the window is full. Returns the seconds slept."""
        if self.max_per_minute <= 0:
            return 0.0
        with self._lock:
            now = self._clock()
            self._purge(now)
            waited = 0.0
            if len(self._stamps) >= self.max_per_minute:
                waited = max(0.0, self.period - (now - self._stamps[0]))
                if waited > 0:
                    self._sleep(waited)
                now = max(self._clock(), self._stamps[0] + self.period)
                self._purge(now)
            self._stamps.append(now)
            return waited
