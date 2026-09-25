"""Notifications: one digest per tenant per run (generic JSON webhook or Slack), plus a run heartbeat.

The digest carries only what changed (:class:`hushwatch.state.RunOutcome` transitions) and, by default,
counts, fingerprints and kinds: entity values (hosts, users, IPs...) are sent only when the target opts in with
``include_entities: true``; otherwise they are pseudonymized with the tenant redactor (or replaced by
``[kind]`` placeholders). Slack text is escaped (``& < >``), mentions (``@channel``/``@here``/``<!...>``) and
links cannot be injected by log values, and messages are truncated to Slack's limits.

Sending never raises: every failure is a :class:`SendResult` with ``ok=False`` and an error that names only the
target's scheme and host. Webhook URLs are secrets (a Slack webhook URL *is* the credential), so their path,
query and user info never appear in errors or logs. There are no retries; undelivered notifications are handed
back to the state store (:meth:`hushwatch.state.StateStore.mark_undelivered`) and go out with the next run.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import logging
import re
import secrets
import threading
import time
from collections import OrderedDict
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any

import httpx

from . import __version__
from .config import NotifyConfig
from .i18n import LANGS, Entity, EntityFormatter, M, Message, entity_formatter, register, render
from .models import Finding, Severity, iter_entities
from .redact import Redactor
from .state import ACCEPTANCE_EXPIRED, TRANSITION_TYPES, RunOutcome, Transition
from .timeutil import UTC, iso

log = logging.getLogger("hushwatch.notify")

NOTIFY_SCHEMA_VERSION = "1.0"
TOOL = "hushwatch"

MAX_TRANSITIONS = 500  # per webhook digest
SLACK_MAX_ITEMS = 20  # transitions listed in a Slack message (the rest are counted)
SLACK_TEXT_LIMIT = 3000  # section block text limit
_TITLE_LIMIT = 300
_DETAIL_LIMIT = 300
_ENTITIES_PER_ITEM = 20
_RESPONSE_READ_LIMIT = 4096

register(
    {
        "notify.headline": {"en": "hushwatch · {tenant}: {changes}", "es": "hushwatch · {tenant}: {changes}"},
        "notify.headline.none": {"en": "hushwatch · {tenant}: no changes", "es": "hushwatch · {tenant}: sin cambios"},
        "notify.count.opened": {"en": "opened: {n}", "es": "abiertos: {n}"},
        "notify.count.regressed": {"en": "regressed: {n}", "es": "reabiertos: {n}"},
        "notify.count.escalated": {"en": "more severe: {n}", "es": "más graves: {n}"},
        "notify.count.acceptance_expired": {"en": "acceptances expired: {n}", "es": "aceptaciones caducadas: {n}"},
        "notify.count.flapping": {"en": "flapping: {n}", "es": "intermitentes: {n}"},
        "notify.count.reminder": {"en": "still open: {n}", "es": "siguen abiertos: {n}"},
        "notify.count.resolved": {"en": "resolved: {n}", "es": "resueltos: {n}"},
        "notify.type.opened": {"en": "Opened", "es": "Abierto"},
        "notify.type.regressed": {"en": "Regressed", "es": "Reabierto"},
        "notify.type.escalated": {"en": "More severe", "es": "Más grave"},
        "notify.type.acceptance_expired": {"en": "Acceptance expired", "es": "Aceptación caducada"},
        "notify.type.flapping": {"en": "Flapping", "es": "Intermitente"},
        "notify.type.reminder": {"en": "Still open", "es": "Sigue abierto"},
        "notify.type.resolved": {"en": "Resolved", "es": "Resuelto"},
        "notify.slack.line": {
            "en": "{icon} *{severity}* · {label}: {title}",
            "es": "{icon} *{severity}* · {label}: {title}",
        },
        "notify.slack.context": {
            "en": "run {run_at} · open findings: {open} (critical: {critical})",
            "es": "ejecución {run_at} · hallazgos abiertos: {open} (críticos: {critical})",
        },
        "notify.slack.more": {
            "en": "…plus {n} more (see the full report)",
            "es": "…y {n} más (consulte el informe completo)",
        },
        "notify.slack.omitted": {
            "en": "changes not shown (severity below {severity}): {n}",
            "es": "cambios no mostrados (severidad inferior a {severity}): {n}",
        },
        "notify.heartbeat.ok": {
            "en": "hushwatch · {tenant}: run completed ({at})",
            "es": "hushwatch · {tenant}: ejecución completada ({at})",
        },
        "notify.heartbeat.fail": {
            "en": "hushwatch · {tenant}: run FAILED or incomplete ({at})",
            "es": "hushwatch · {tenant}: la ejecución FALLÓ o quedó incompleta ({at})",
        },
        "notify.error.no_url": {
            "en": "the notification target has no URL configured",
            "es": "el destino de notificación no tiene URL configurada",
        },
        "notify.error.bad_url": {
            "en": "the notification URL is invalid or does not use http(s)",
            "es": "la URL de notificación no es válida o no usa http(s)",
        },
        "notify.error.slack_https": {
            "en": "Slack webhook URLs must use https",
            "es": "las URL de webhook de Slack deben usar https",
        },
        "notify.error.unknown_type": {
            "en": "unknown notification type '{type}' (use webhook or slack)",
            "es": "tipo de notificación desconocido '{type}' (use webhook o slack)",
        },
        "notify.error.header": {
            "en": "custom header '{name}' is invalid (the name must be a token and the value a single line)",
            "es": "la cabecera personalizada '{name}' no es válida (el nombre debe ser un token y el valor una sola "
            "línea)",
        },
        "notify.error.entities": {
            "en": "{target}: the payload carries entity values but this target has include_entities: false",
            "es": "{target}: el contenido incluye valores de entidades pero este destino tiene include_entities: false",
        },
        "notify.error.payload": {
            "en": "the notification payload could not be encoded ({reason})",
            "es": "no se pudo codificar el contenido de la notificación ({reason})",
        },
        "notify.error.timeout": {
            "en": "{target}: no answer within {seconds:g} s",
            "es": "{target}: sin respuesta en {seconds:g} s",
        },
        "notify.error.connect": {
            "en": "{target}: connection failed ({reason})",
            "es": "{target}: falló la conexión ({reason})",
        },
        "notify.error.tls": {
            "en": "{target}: TLS error ({reason})",
            "es": "{target}: error de TLS ({reason})",
        },
        "notify.error.transport": {
            "en": "{target}: request failed ({reason})",
            "es": "{target}: falló la petición ({reason})",
        },
        "notify.error.http": {
            "en": "{target}: HTTP {status} ({body})",
            "es": "{target}: HTTP {status} ({body})",
        },
        "notify.error.http_nobody": {"en": "{target}: HTTP {status}", "es": "{target}: HTTP {status}"},
        "notify.error.redirect": {
            "en": "{target}: HTTP {status} redirect not followed; configure the final URL",
            "es": "{target}: no se sigue la redirección HTTP {status}; configure la URL final",
        },
        "notify.error.unexpected": {
            "en": "{target}: unexpected error ({reason})",
            "es": "{target}: error inesperado ({reason})",
        },
        "notify.skipped.empty": {
            "en": "nothing at or above {severity} severity to notify",
            "es": "nada que notificar con severidad {severity} o superior",
        },
        "notify.skipped.duplicate": {
            "en": "the digest of this run was already delivered to this target",
            "es": "el resumen de esta ejecución ya se entregó a este destino",
        },
        "notify.skipped.heartbeat": {
            "en": "Slack only receives failing heartbeats (use a webhook for a dead-man switch)",
            "es": "Slack solo recibe los latidos fallidos (use un webhook como interruptor de hombre muerto)",
        },
    }
)


@dataclass(frozen=True, slots=True)
class SendResult:
    """Outcome of one delivery attempt. ``error`` is safe to log: no URL path/query/credentials, no headers."""

    ok: bool
    sent: bool = False
    status_code: int | None = None
    target: str = ""  # scheme://host[:port] only
    error: str | None = None  # English
    message: Message | None = None  # the error / skip reason, for rendering in another language
    transitions: int = 0  # transitions delivered (after the min_severity filter)
    fingerprints: tuple[str, ...] = ()  # hand these to StateStore.mark_undelivered when ok is False


# ---- payloads ------------------------------------------------------------------------------------------------


def build_payload(
    tenant: str,
    outcome: RunOutcome,
    findings_by_fp: Mapping[str, Finding],
    *,
    lang: str = "en",
    include_entities: bool = False,
    redactor: Redactor | None = None,
    max_transitions: int = MAX_TRANSITIONS,
) -> dict[str, Any]:
    """Build the versioned digest for one run (JSON-serializable).

    Shape (``schema_version`` 1.0)::

        {"schema_version": "1.0", "type": "digest", "tool": {"name", "version"}, "tenant", "run_id", "run_at",
         "lang", "include_entities", "summary", "counts": {..., "transitions": {type: n}},
         "transitions": [{"type", "fingerprint", "kind", "domain", "severity", "status", "title", "flapping",
                          "first_seen", "opened_at", "resolved_at", ["detail"], ["confidence"],
                          ["acceptance": {"id", "expires"}], ["previous_severity"], ["subject"],
                          ["entities": [{"kind", "value"}]]}],
         "truncated": int}

    Titles are rendered in ``lang``. Entity values appear raw only with ``include_entities``; otherwise they are
    ``redactor`` tokens (and free text is passed through ``redactor.text``), or ``[kind]`` placeholders without
    a redactor. In both cases every entity value known from the findings is also masked where a module forgot to
    wrap it, and URLs in free text are cut to their origin. Credentials in URLs never leave, even with
    ``include_entities``. ``subject`` and ``entities`` are present only with ``include_entities`` or a redactor.
    Resolved findings are absent from the run: their title comes from the state summary (placeholders, never
    values).
    """
    lang = lang if lang in LANGS else "en"
    known = _known_entities(findings_by_fp.values(), outcome.transitions)
    fmt, scrub = _entity_policy(include_entities, redactor, known)
    chosen = _select(outcome.transitions, max(0, max_transitions))
    items = [_item(t, findings_by_fp.get(t.fingerprint), lang, fmt, scrub, include_entities, redactor) for t in chosen]
    counts: dict[str, Any] = {str(k): int(v) for k, v in outcome.counts.items()}
    counts["transitions"] = outcome.transition_counts
    return {
        "schema_version": NOTIFY_SCHEMA_VERSION,
        "type": "digest",
        "tool": {"name": TOOL, "version": __version__},
        "tenant": _clean(tenant, 128),
        "run_id": outcome.run_id,
        "run_at": iso(outcome.run_at),
        "lang": lang,
        "include_entities": bool(include_entities),
        "summary": _headline(tenant, items, lang),
        "counts": counts,
        "transitions": items,
        "truncated": len(outcome.transitions) - len(chosen),
    }


def build_heartbeat(
    tenant: str,
    *,
    now: datetime,
    ok: bool,
    detail: Message | str = "",
    run_id: str | None = None,
    counts: Mapping[str, int] | None = None,
    lang: str = "en",
    include_entities: bool = False,
    redactor: Redactor | None = None,
) -> dict[str, Any]:
    """Build the heartbeat payload sent after every run (a dead-man switch for the cron job itself).

    URLs in ``detail`` are always cut to ``scheme://host`` (their user info, path and query may be secrets)."""
    lang = lang if lang in LANGS else "en"
    fmt, scrub = _entity_policy(include_entities, redactor, list(iter_entities(detail)))
    text = render(detail, lang, fmt) if isinstance(detail, Message) else str(detail)
    text = _url_origins(text[: _DETAIL_LIMIT * 4])  # an error detail may quote a URL with credentials or a token
    at = iso(now.astimezone(UTC)) if now.tzinfo is not None else iso(now.replace(tzinfo=UTC))
    key = "notify.heartbeat.ok" if ok else "notify.heartbeat.fail"
    return {
        "schema_version": NOTIFY_SCHEMA_VERSION,
        "type": "heartbeat",
        "tool": {"name": TOOL, "version": __version__},
        "tenant": _clean(tenant, 128),
        "run_id": run_id,
        "at": at,
        "ok": bool(ok),
        "status": "ok" if ok else "fail",
        "lang": lang,
        "include_entities": bool(include_entities),
        "summary": _clean(render(M(key, tenant=tenant, at=at or ""), lang), _TITLE_LIMIT),
        "detail": _bounded(text, scrub, _DETAIL_LIMIT) if text else "",
        "counts": {str(k): int(v) for k, v in (counts or {}).items() if isinstance(v, int)},
    }


# ---- delivery ------------------------------------------------------------------------------------------------


def send(
    notify_cfg: NotifyConfig,
    payload: Mapping[str, Any],
    *,
    transport: httpx.BaseTransport | None = None,
    timeout: float = 10.0,
) -> SendResult:
    """Deliver one payload (digest or heartbeat) to one target. Never raises.

    * ``webhook``: POST of the JSON payload with the configured custom headers.
    * ``slack``: an incoming-webhook message (``text`` + ``blocks``), escaped for Slack, one message per call.

    Digest transitions below ``notify_cfg.min_severity`` are dropped (an unknown value falls back to ``info``:
    never hide by misconfiguration); when nothing is left, nothing is sent (``ok=True, sent=False``). A digest
    already delivered to the same target for the same tenant and run is not sent twice. Redirects are not
    followed and there are no retries.
    """
    target = _safe_target(notify_cfg.url)
    try:
        return _send(notify_cfg, payload, transport, timeout, target)
    except Exception as exc:  # a notifier must never break the run
        return _failure(
            M("notify.error.unexpected", target=_target_entity(target), reason=type(exc).__name__),
            target,
            _digest_fingerprints(notify_cfg, payload),
        )


def send_heartbeat(
    notify_cfg: NotifyConfig,
    tenant: str,
    *,
    now: datetime,
    ok: bool,
    detail: Message | str = "",
    run_id: str | None = None,
    counts: Mapping[str, int] | None = None,
    lang: str = "en",
    redactor: Redactor | None = None,
    transport: httpx.BaseTransport | None = None,
    timeout: float = 10.0,
    slack_always: bool = False,
) -> SendResult:
    """Send the run heartbeat. Webhooks get one every run; Slack only failing ones (unless ``slack_always``),
    because an "all good" message every few minutes teaches a channel to ignore the tool."""
    target = _safe_target(notify_cfg.url)
    if notify_cfg.type == "slack" and ok and not slack_always:
        return SendResult(ok=True, sent=False, target=target, message=M("notify.skipped.heartbeat"))
    try:
        payload = build_heartbeat(
            tenant,
            now=now,
            ok=ok,
            detail=detail,
            run_id=run_id,
            counts=counts,
            lang=lang,
            include_entities=notify_cfg.include_entities,
            redactor=redactor,
        )
    except Exception as exc:  # never raise out of a notifier
        return _failure(M("notify.error.payload", reason=type(exc).__name__), target)
    return send(notify_cfg, payload, transport=transport, timeout=timeout)


def _send(
    cfg: NotifyConfig,
    payload: Mapping[str, Any],
    transport: httpx.BaseTransport | None,
    timeout: float,
    target: str,
) -> SendResult:
    shown = _target_entity(target)
    lang = str(payload.get("lang") or "en")
    lang = lang if lang in LANGS else "en"
    kind = payload.get("type")
    min_sev = _min_severity(cfg.min_severity)
    items: list[dict[str, Any]] = []
    omitted = 0
    if kind == "digest":
        items, omitted = _filter(payload.get("transitions"), min_sev)
    elif kind != "heartbeat":
        return _failure(M("notify.error.payload", reason="unknown payload type"), target)
    # every failure hands back the digest's fingerprints (at-least-once, whatever went wrong, including a
    # misconfigured target: the notifications go out once the configuration is fixed)
    fingerprints = tuple(str(i.get("fingerprint") or "") for i in items)

    if cfg.type not in ("webhook", "slack"):
        return _failure(M("notify.error.unknown_type", type=_clean(str(cfg.type), 32)), target, fingerprints)
    raw_url = (cfg.url or "").strip()
    if not raw_url:
        return _failure(M("notify.error.no_url"), target, fingerprints)
    try:
        url = httpx.URL(raw_url)
    except (httpx.InvalidURL, ValueError, TypeError):
        return _failure(M("notify.error.bad_url"), target, fingerprints)
    if url.scheme not in ("http", "https") or not url.host:
        return _failure(M("notify.error.bad_url"), target, fingerprints)
    if cfg.type == "slack" and url.scheme != "https":
        return _failure(M("notify.error.slack_https"), target, fingerprints)
    headers = {"Content-Type": "application/json; charset=utf-8", "User-Agent": f"{TOOL}/{__version__}"}
    for name, value in (cfg.headers or {}).items():
        if (
            not _HEADER_NAME.match(str(name))
            or not isinstance(value, str)
            or _HEADER_BAD_VALUE.search(value)
            or not value.isascii()
        ):
            return _failure(M("notify.error.header", name=_clean(str(name), 64)), target, fingerprints)
        headers[str(name)] = value
    if payload.get("include_entities") and not cfg.include_entities:
        return _failure(M("notify.error.entities", target=shown), target, fingerprints)
    if kind == "digest" and not items:
        return SendResult(
            ok=True, sent=False, target=target, message=M("notify.skipped.empty", severity=_sev_label(min_sev))
        )

    dedupe_key: tuple[str, str, str] | None = None
    if kind == "digest":
        run_id = str(payload.get("run_id") or "")
        if run_id:
            dedupe_key = (
                hashlib.sha256(raw_url.encode("utf-8", "replace")).hexdigest(),
                str(payload.get("tenant")),
                run_id,
            )
            if _already_sent(dedupe_key):
                return SendResult(ok=True, sent=False, target=target, message=M("notify.skipped.duplicate"))
        if cfg.type == "slack":
            body: dict[str, Any] = _slack_digest(payload, items, omitted, min_sev, lang)
        else:
            body = dict(payload)
            body["transitions"] = items
            body["summary"] = _headline(str(payload.get("tenant") or ""), items, lang)
            body["min_severity"] = min_sev.value
            body["omitted"] = omitted
    else:
        body = _slack_heartbeat(payload, lang) if cfg.type == "slack" else dict(payload)

    try:
        content = json.dumps(body, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode(
            "utf-8", "replace"
        )
    except (TypeError, ValueError) as exc:
        return _failure(M("notify.error.payload", reason=type(exc).__name__), target, fingerprints)

    secrets_ = _url_secrets(raw_url, url) + _header_secrets(cfg.headers or {})
    seconds = max(0.1, float(timeout))
    try:
        with (
            httpx.Client(transport=transport, timeout=httpx.Timeout(seconds), follow_redirects=False) as client,
            client.stream("POST", url, content=content, headers=headers) as response,
        ):
            status = response.status_code
            # the body only matters for an error message; bounded in size AND time (a trickling server
            # must not hold the run hostage: per-read timeouts alone allow hours)
            snippet = b"" if 200 <= status < 400 else _read_limited(response, _RESPONSE_READ_LIMIT, seconds)
    except httpx.TimeoutException:
        return _failure(M("notify.error.timeout", target=shown, seconds=timeout), target, fingerprints)
    except httpx.ConnectError as exc:
        reason = _scrub(str(exc), secrets_)
        key = "notify.error.tls" if _looks_tls(str(exc)) else "notify.error.connect"
        return _failure(M(key, target=shown, reason=reason or type(exc).__name__), target, fingerprints)
    except (httpx.HTTPError, httpx.InvalidURL, OSError) as exc:
        reason = _scrub(str(exc), secrets_) or type(exc).__name__
        return _failure(M("notify.error.transport", target=shown, reason=reason), target, fingerprints)

    if 200 <= status < 300:
        if dedupe_key is not None:
            _remember_sent(dedupe_key)
        return SendResult(
            ok=True, sent=True, status_code=status, target=target, transitions=len(items), fingerprints=fingerprints
        )
    if 300 <= status < 400:
        return _failure(M("notify.error.redirect", target=shown, status=status), target, fingerprints, status)
    # scrub secrets on the raw text FIRST (removing characters first could split a secret and leak a part)
    body_text = _truncate(_RESPONSE_SAFE.sub("", _scrub(snippet.decode("utf-8", "replace"), secrets_, None)), 120)
    body_text = body_text.strip()
    if body_text:
        message = M("notify.error.http", target=shown, status=status, body=body_text)
    else:
        message = M("notify.error.http_nobody", target=shown, status=status)
    return _failure(message, target, fingerprints, status)


def _digest_fingerprints(cfg: NotifyConfig, payload: Any) -> tuple[str, ...]:
    """Fingerprints a digest would carry to ``cfg`` (for hand-back after an unexpected error). Never raises."""
    try:
        if not isinstance(payload, Mapping) or payload.get("type") != "digest":
            return ()
        items, _ = _filter(payload.get("transitions"), _min_severity(cfg.min_severity))
        return tuple(str(i.get("fingerprint") or "") for i in items)
    except Exception:  # pragma: no cover - defensive: this runs inside an error handler
        return ()


# ---- Slack ---------------------------------------------------------------------------------------------------

_SLACK_ICONS = {
    "resolved": ":white_check_mark:",
    "critical": ":red_circle:",
    "high": ":large_orange_circle:",
    "medium": ":large_yellow_circle:",
    "low": ":large_blue_circle:",
    "info": ":white_circle:",
}
_MENTION = re.compile(r"(?i)([@!])(channel|here|everyone|group|subteam)\b")
_SCHEME = re.compile(r"(?i)\b([a-z][a-z0-9+.-]{0,15}):(//)")
# host names / e-mail domains Slack would auto-link without a scheme ("evil-sso.example", "README.md"): labels
# joined by dots, the last one starting with a letter and at least two characters long (not "4.8.0", not "e.g")
_DOMAINISH = re.compile(r"(?<![\w-])(?:[\w-]+\.)+[^\W\d_][\w-]+(?![\w-])")


def slack_escape(text: str, limit: int = SLACK_TEXT_LIMIT, *, defang: bool = True) -> str:
    """Escape untrusted text for Slack mrkdwn.

    ``&``, ``<`` and ``>`` become entities (so ``<!channel>``, ``<@U123>`` and ``<http://x|label>`` are shown,
    not interpreted), bare ``@channel``/``@here``/``@everyone`` get a zero-width space, URL schemes are defanged
    (``http[:]//``) and, with ``defang`` (default), so are the dots of host names and e-mail domains
    (``evil[.]example``): Slack auto-links those even without a scheme, which would turn an attacker-chosen
    user or host name into a clickable phishing link in the SOC channel. Control and bidi-override characters
    are removed and the result is truncated to ``limit`` characters. ``*``/``_``/``~`` are left alone (Slack
    has no escape for them; at worst they change the emphasis of one line).
    """
    out = _clean(text, None)
    out = out.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    out = _MENTION.sub(lambda m: m.group(1) + "\u200b" + m.group(2), out)
    out = _SCHEME.sub(lambda m: m.group(1) + "[:]" + m.group(2), out)
    if defang:
        out = _DOMAINISH.sub(lambda m: m.group(0).replace(".", "[.]"), out)
    return _truncate(out, limit)


def _slack_code(text: str) -> str:
    """Our own identifiers (kind, fingerprint) as inline code: never auto-linked, so no defanging."""
    return "`" + slack_escape(text.replace("`", "'"), 128, defang=False) + "`"


def _slack_digest(
    payload: Mapping[str, Any], items: list[dict[str, Any]], omitted: int, min_sev: Severity, lang: str
) -> dict[str, Any]:
    tenant = str(payload.get("tenant") or "")
    headline = slack_escape(_headline(tenant, items, lang), 1000)
    blocks: list[dict[str, Any]] = [{"type": "section", "text": {"type": "mrkdwn", "text": "*" + headline + "*"}}]
    for item in items[:SLACK_MAX_ITEMS]:
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": _slack_line(item, lang)}})
    notes: list[str] = []
    if len(items) > SLACK_MAX_ITEMS:
        notes.append(render(M("notify.slack.more", n=len(items) - SLACK_MAX_ITEMS), lang))
    if omitted:
        notes.append(render(M("notify.slack.omitted", n=omitted, severity=_sev_label(min_sev)), lang))
    counts = payload.get("counts") if isinstance(payload.get("counts"), Mapping) else {}
    assert isinstance(counts, Mapping)
    notes.append(
        render(
            M(
                "notify.slack.context",
                run_at=str(payload.get("run_at") or ""),
                open=_int(counts.get("open")),
                critical=_int(counts.get("open.critical")),
            ),
            lang,
        )
    )
    blocks.append({"type": "context", "elements": [{"type": "mrkdwn", "text": slack_escape(" · ".join(notes))}]})
    return {
        "text": headline,
        "blocks": blocks,
        "unfurl_links": False,
        "unfurl_media": False,
        "link_names": False,
    }


def _slack_line(item: Mapping[str, Any], lang: str) -> str:
    kind = str(item.get("type") or "")
    severity = str(item.get("severity") or "info")
    icon = _SLACK_ICONS["resolved"] if kind == "resolved" else _SLACK_ICONS.get(severity, _SLACK_ICONS["info"])
    label = render(M("notify.type." + kind), lang) if kind in TRANSITION_TYPES else kind
    head = render(
        M(
            "notify.slack.line",
            icon=icon,
            severity=slack_escape(render(M("severity." + severity), lang).upper(), 32),
            label=slack_escape(label, 64),
            title=slack_escape(str(item.get("title") or ""), _TITLE_LIMIT + 50),
        ),
        lang,
    )
    tail = [_slack_code(str(item.get("kind") or "")), _slack_code(str(item.get("fingerprint") or ""))]
    tail = [t for t in tail if t != "``"]
    if item.get("detail"):
        tail.append(slack_escape(str(item["detail"]), _DETAIL_LIMIT + 50))
    return _truncate(head + "\n" + " · ".join(tail), SLACK_TEXT_LIMIT)


def _slack_heartbeat(payload: Mapping[str, Any], lang: str) -> dict[str, Any]:
    ok = bool(payload.get("ok"))
    summary = slack_escape(str(payload.get("summary") or ""), 1000)
    icon = ":white_check_mark:" if ok else ":red_circle:"
    text = icon + " " + summary
    detail = str(payload.get("detail") or "")
    if detail:
        text += "\n" + slack_escape(detail, _DETAIL_LIMIT + 50)
    return {
        "text": summary,
        "blocks": [{"type": "section", "text": {"type": "mrkdwn", "text": _truncate(text, SLACK_TEXT_LIMIT)}}],
        "unfurl_links": False,
        "unfurl_media": False,
        "link_names": False,
    }


# ---- helpers -------------------------------------------------------------------------------------------------

_CONTROL = re.compile("[\x00-\x1f\x7f-\x9f\u200b-\u200f\u2028\u2029\u202a-\u202e\u2060-\u2069\ufeff]")
_HEADER_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}$")
_HEADER_BAD_VALUE = re.compile(r"[\x00-\x08\x0a-\x1f\x7f]")
_RESPONSE_SAFE = re.compile(r"[^A-Za-z0-9 _.,:;()/-]")
# scheme, user info (up to the LAST '@' before the path: passwords may contain '@'), host[:port], rest
_URL_PARTS = re.compile(r"(?i)\b([a-z][a-z0-9+.-]{1,15})://(?:([^\s/?#]*)@)?([^\s/?#@]+)([^\s]*)")
_LEARN_MAX_LEN = 512
_LEARN_MAX_VALUES = 5000
_TLS_HINTS = ("ssl", "tls", "certificate", "handshake")
_SENT_LOCK = threading.Lock()
_SENT: OrderedDict[tuple[str, str, str], None] = OrderedDict()
_SENT_MAX = 4096


def _entity_policy(
    include_entities: bool, redactor: Redactor | None, known: Iterable[Entity] = ()
) -> tuple[EntityFormatter, Callable[[str], str]]:
    """How entities and free text are rendered: raw (opt-in), redactor tokens, or ``[kind]`` placeholders.

    ``known`` entity values are also masked in free text (a plain-string parameter a module forgot to wrap)."""
    if include_entities:
        return (lambda e: e.value), _strip_userinfo
    if redactor is not None:
        redactor.learn((e.kind, e.value) for e in known if len(e.value) <= _LEARN_MAX_LEN)
        return entity_formatter(redactor), lambda text: redactor.text(_url_origins(text))
    return (lambda e: "[" + e.kind + "]"), _PlaceholderScrubber(known)


class _PlaceholderScrubber:
    """Free-text scrubber without a redactor: known entity values become ``[kind]``; URLs are cut to their origin;
    IPs, e-mails, ``DOMAIN\\user`` and home directories are masked with a one-off random key (unlinkable)."""

    def __init__(self, known: Iterable[Entity]) -> None:
        kinds: dict[str, str] = {}
        for entity in known:
            value = entity.value
            if 3 <= len(value) <= _LEARN_MAX_LEN and value not in kinds:
                kinds[value] = re.sub(r"[^a-z_]", "", entity.kind.lower())[:16] or "val"
        self._kinds = kinds
        ordered = sorted(kinds, key=len, reverse=True)
        self._pattern = re.compile("|".join(re.escape(v) for v in ordered)) if ordered else None
        self._redactor = Redactor(secrets.token_bytes(32))

    def __call__(self, text: str) -> str:
        out = text
        if self._pattern is not None:
            out = self._pattern.sub(lambda m: "[" + self._kinds[m.group(0)] + "]", out)
        return self._redactor.text(_url_origins(out))


def _known_entities(findings: Iterable[Finding], transitions: Iterable[Transition]) -> list[Entity]:
    """Entity values of the digest's findings and transitions (bounded), for masking unwrapped occurrences."""
    out: list[Entity] = []
    sources: list[Any] = [[f.title, f.reasons, f.evidence, f.recommendation] for f in findings]
    sources += [[t.summary, t.detail] for t in transitions]
    for source in sources:
        for entity in iter_entities(source):
            out.append(entity)
            if len(out) >= _LEARN_MAX_VALUES:
                return out
    return out


def _url_origins(text: str) -> str:
    """``https://user:pw@host:9200/path?token=x`` -> ``https://host:9200/…`` in free text."""
    return _URL_PARTS.sub(lambda m: m.group(1) + "://" + m.group(3) + ("/…" if m.group(4) else ""), text)


def _strip_userinfo(text: str) -> str:
    """Drop ``user:password@`` from URLs in free text (credentials are never entities)."""
    return _URL_PARTS.sub(lambda m: m.group(1) + "://" + m.group(3) + m.group(4), text)


def _header_secrets(headers: Mapping[str, Any]) -> list[str]:
    """Custom header values (and their long parts: the token of ``Bearer <token>``) are secrets."""
    out: list[str] = []
    for value in headers.values():
        if isinstance(value, str):
            out.append(value)
            out += [part for part in re.split(r"[\s,;=]+", value) if len(part) >= 8]
    return out


def _item(
    t: Transition,
    finding: Finding | None,
    lang: str,
    fmt: EntityFormatter,
    scrub: Callable[[str], str],
    include_entities: bool,
    redactor: Redactor | None,
) -> dict[str, Any]:
    source: Message | str = finding.title if finding is not None else t.summary
    title = render(source, lang, fmt) if isinstance(source, Message) else source
    item: dict[str, Any] = {
        "type": t.type,
        "fingerprint": t.fingerprint or None,
        "kind": t.kind or None,
        "domain": t.domain or None,
        "severity": t.severity.value,
        "status": t.status or None,
        "title": _bounded(title, scrub, _TITLE_LIMIT),
        "flapping": bool(t.flapping),
        "first_seen": iso(t.first_seen),
        "opened_at": iso(t.opened_at),
        "resolved_at": iso(t.resolved_at),
    }
    if t.detail is not None:
        item["detail"] = _bounded(render(t.detail, lang, fmt), scrub, _DETAIL_LIMIT)
    if t.type == ACCEPTANCE_EXPIRED and t.accept_id:
        item["acceptance"] = {"id": t.accept_id, "expires": iso(t.accept_expires)}
    if t.previous_severity is not None:
        item["previous_severity"] = t.previous_severity.value
    if finding is not None:
        item["confidence"] = finding.confidence.value
        if include_entities or redactor is not None:
            item["subject"] = _clean(_entity_value(finding.subject, "val", include_entities, redactor), 512)
            seen: set[tuple[str, str]] = set()
            entities: list[dict[str, str]] = []
            for entity in iter_entities([finding.title, finding.reasons, finding.evidence, finding.recommendation]):
                ident = (entity.kind, entity.value)
                if ident in seen:
                    continue
                seen.add(ident)
                value = _entity_value(entity.value, entity.kind, include_entities, redactor)
                entities.append({"kind": _clean(entity.kind, 16), "value": _clean(value, 256)})
                if len(entities) >= _ENTITIES_PER_ITEM:
                    break
            item["entities"] = entities
    return item


def _entity_value(value: str, kind: str, include_entities: bool, redactor: Redactor | None) -> str:
    if include_entities:
        return _strip_userinfo(value)  # opted in to entity values, never to the credentials inside a URL
    if redactor is None:
        return value
    return redactor.token(value, kind)


def _select(transitions: list[Transition], limit: int) -> list[Transition]:
    """Keep the ``limit`` most important transitions (severity first), in their original order."""
    if len(transitions) <= limit:
        return list(transitions)
    order = {t: i for i, t in enumerate(TRANSITION_TYPES)}
    ranked = sorted(
        range(len(transitions)),
        key=lambda i: (-transitions[i].severity.rank, order.get(transitions[i].type, 99), i),
    )
    keep = sorted(ranked[:limit])
    return [transitions[i] for i in keep]


def _headline(tenant: str, items: Iterable[Mapping[str, Any]], lang: str) -> str:
    counts = dict.fromkeys(TRANSITION_TYPES, 0)
    for item in items:
        kind = item.get("type")
        if isinstance(kind, str) and kind in counts:
            counts[kind] += 1
    parts = [render(M("notify.count." + kind, n=n), lang) for kind, n in counts.items() if n]
    name = _clean(tenant, 128)
    if not parts:
        return render(M("notify.headline.none", tenant=name), lang)
    return render(M("notify.headline", tenant=name, changes=" · ".join(parts)), lang)


def _filter(raw: Any, min_sev: Severity) -> tuple[list[dict[str, Any]], int]:
    if not isinstance(raw, list):
        return [], 0
    kept: list[dict[str, Any]] = []
    total = 0
    for item in raw:
        if not isinstance(item, Mapping):
            continue
        total += 1
        if _severity_rank(item.get("severity")) >= min_sev.rank:
            kept.append(dict(item))
    return kept, total - len(kept)


def _severity_rank(value: Any) -> int:
    try:
        return Severity(str(value)).rank
    except ValueError:
        return Severity.CRITICAL.rank  # unknown severities are never filtered out


def _min_severity(value: Any) -> Severity:
    try:
        return Severity(str(value).strip().lower())
    except ValueError:
        log.warning("notify: unknown min_severity %r; sending every severity", value)
        return Severity.INFO


def _sev_label(severity: Severity) -> Message:
    return M("severity." + severity.value)


def _int(value: Any) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def _clean(text: str, limit: int | None) -> str:
    """One line of text: control, line-break, invisible and bidi characters and lone surrogates become spaces;
    truncated to ``limit``."""
    out = _CONTROL.sub(" ", text.encode("utf-8", "replace").decode("utf-8", "replace"))
    return out if limit is None else _truncate(out, limit)


def _bounded(text: str, scrub: Callable[[str], str], limit: int) -> str:
    """Scrub then shorten. Only a generous prefix is scrubbed (bounded work on hostile megabyte values): a value
    cut at that boundary lies far beyond the displayed ``limit`` characters, so nothing shown escapes scrubbing."""
    return _clean(scrub(_clean(text[: limit * 4], None)), limit)


def _truncate(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: max(0, limit - 1)] + "…"


def _safe_target(url: str | None) -> str:
    """``scheme://host[:port]`` of a URL: never its path, query or credentials."""
    try:
        parsed = httpx.URL((url or "").strip())
    except (httpx.InvalidURL, ValueError, TypeError):
        return "<invalid url>"
    if not parsed.scheme or not parsed.host:
        return "<invalid url>"
    host = parsed.host if ":" not in parsed.host else "[" + parsed.host + "]"
    port = f":{parsed.port}" if parsed.port is not None else ""
    return _clean(f"{parsed.scheme}://{host}{port}", 200)


def _target_entity(target: str) -> Entity:
    return Entity("url", target)


def _url_secrets(raw: str, url: httpx.URL) -> list[str]:
    """Every fragment of a webhook URL that may carry a secret (the whole URL, path, query, user info)."""
    parts = [raw, str(url)]
    with contextlib.suppress(Exception):
        parts += [url.path, url.raw_path.decode("ascii", "replace"), url.query.decode("ascii", "replace")]
        parts += [url.userinfo.decode("ascii", "replace"), url.username, url.password or ""]
        parts += [seg for seg in url.path.split("/") if len(seg) >= 4]
        parts += [v for _, v in url.params.multi_items()]
    return [p for p in parts if p]


def _scrub(text: str, secrets_: Iterable[str], limit: int | None = 160) -> str:
    """Remove URL secrets and header values from an error text; any other URL is cut to its origin."""
    out = text
    for secret in sorted({s for s in secrets_ if len(s) >= 4}, key=len, reverse=True):
        out = out.replace(secret, "***")
    out = _URL_PARTS.sub(lambda m: m.group(1) + "://" + m.group(3) + "/***", out)
    return _clean(out, limit).strip()


def _looks_tls(text: str) -> bool:
    lowered = text.lower()
    return any(hint in lowered for hint in _TLS_HINTS)


def _read_limited(response: httpx.Response, limit: int, seconds: float) -> bytes:
    """At most ``limit`` bytes of the body, and no more than about ``seconds`` spent reading it."""
    deadline = time.monotonic() + seconds
    buf = bytearray()
    for chunk in response.iter_bytes():
        buf.extend(chunk)
        if len(buf) >= limit or time.monotonic() >= deadline:
            break
    return bytes(buf[:limit])


def _failure(
    message: Message, target: str, fingerprints: tuple[str, ...] = (), status: int | None = None
) -> SendResult:
    text = render(message, "en")
    log.warning("notify: %s", text)
    return SendResult(
        ok=False, sent=False, status_code=status, target=target, error=text, message=message, fingerprints=fingerprints
    )


def _already_sent(key: tuple[str, str, str]) -> bool:
    with _SENT_LOCK:
        return key in _SENT


def _remember_sent(key: tuple[str, str, str]) -> None:
    with _SENT_LOCK:
        _SENT[key] = None
        _SENT.move_to_end(key)
        while len(_SENT) > _SENT_MAX:
            _SENT.popitem(last=False)


__all__ = [
    "NOTIFY_SCHEMA_VERSION",
    "SendResult",
    "build_heartbeat",
    "build_payload",
    "send",
    "send_heartbeat",
    "slack_escape",
]
