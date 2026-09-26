"""Tests for hushwatch.notify: digest payload, redaction, Slack escaping, webhook delivery, safe failures."""

from __future__ import annotations

import json
import uuid
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import httpx
import pytest

from hushwatch.config import NotifyConfig
from hushwatch.i18n import Entity, M, register
from hushwatch.models import Finding, Severity
from hushwatch.notify import (
    NOTIFY_SCHEMA_VERSION,
    SLACK_TEXT_LIMIT,
    build_heartbeat,
    build_payload,
    send,
    send_heartbeat,
    slack_escape,
)
from hushwatch.redact import Redactor
from hushwatch.state import RunOutcome, StateStore, Transition

UTC = timezone.utc
T0 = datetime(2026, 9, 1, 12, 0, tzinfo=UTC)
TENANT = "acme"
SLACK_SECRET = "FAKE-webhook-path"
SLACK_URL = f"https://hooks.slack.example/services/FAKE/FAKE/{SLACK_SECRET}"
HOOK_URL = "https://hooks.example.com/hushwatch/9f8e7d6c5b4a?token=FAKE-test-token"
RAW_VALUES = ("srv-web-01.example", "198.51.100.23", "alice", "dc01.corp.example", "203.0.113.9")

register(
    {
        "test.notify.silent": {
            "en": "{host} stopped sending {channel} events",
            "es": "{host} dejó de enviar eventos {channel}",
        },
        "test.notify.login": {
            "en": "{user} failed to log in from {ip} ({raw})",
            "es": "{user} no pudo iniciar sesión desde {ip} ({raw})",
        },
        "test.notify.hostile": {"en": "rule fired for {user}", "es": "regla disparada para {user}"},
    }
)


def silent_finding(host: str = "srv-web-01.example", severity: Severity = Severity.CRITICAL) -> Finding:
    return Finding(
        kind="silence.silent",
        domain="silence",
        title=M("test.notify.silent", host=Entity("host", host), channel="Security"),
        severity=severity,
        subject=f"agent:{host}|ls:Security",
        tenant=TENANT,
        evidence={"agent": Entity("host", host), "last_ip": Entity("ip", "198.51.100.23")},
    )


def login_finding(severity: Severity = Severity.MEDIUM) -> Finding:
    return Finding(
        kind="noise.investigate",
        domain="noise",
        title=M(
            "test.notify.login",
            user=Entity("user", "alice"),
            ip=Entity("ip", "203.0.113.9"),
            raw="seen via 198.51.100.23 by alice@corp.example",  # plain-string param: scrubbed as free text
        ),
        severity=severity,
        subject="rule:5710|srcip:203.0.113.9",
        tenant=TENANT,
    )


def transition(
    finding: Finding, kind: str = "opened", *, status: str = "open", summary: Any = None, **extra: Any
) -> Transition:
    return Transition(
        type=kind,
        fingerprint=finding.fingerprint,
        kind=finding.kind,
        domain=finding.domain,
        severity=finding.severity,
        status=status,
        summary=summary if summary is not None else finding.kind,
        first_seen=T0 - timedelta(hours=2),
        opened_at=T0 - timedelta(hours=1),
        **extra,
    )


def outcome_of(*transitions: Transition, counts: dict[str, int] | None = None) -> RunOutcome:
    return RunOutcome(
        run_id="20260901T120000Z-" + uuid.uuid4().hex[:8],  # unique: a digest is delivered once per run
        tenant=TENANT,
        run_at=T0,
        transitions=list(transitions),
        counts=counts or {"findings": 2, "open": 2, "open.critical": 1},
    )


def by_fp(*findings: Finding) -> dict[str, Finding]:
    return {f.fingerprint: f for f in findings}


class Recorder:
    """httpx.MockTransport handler that records requests."""

    def __init__(self, response: Callable[[httpx.Request], httpx.Response] | None = None) -> None:
        self.requests: list[httpx.Request] = []
        self._response = response or (lambda request: httpx.Response(200, text="ok"))

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return self._response(request)

    @property
    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self)

    def body(self, index: int = -1) -> Any:
        return json.loads(self.requests[index].content)


def webhook(**kwargs: Any) -> NotifyConfig:
    return NotifyConfig(type="webhook", url=kwargs.pop("url", HOOK_URL), **kwargs)


def slack(**kwargs: Any) -> NotifyConfig:
    return NotifyConfig(type="slack", url=kwargs.pop("url", SLACK_URL), **kwargs)


def all_texts(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [t for v in value.values() for t in all_texts(v)]
    if isinstance(value, list):
        return [t for v in value for t in all_texts(v)]
    return []


# ---- payload -----------------------------------------------------------------------------------------------------


def test_payload_schema() -> None:
    silent, login = silent_finding(), login_finding()
    payload = build_payload(
        TENANT, outcome_of(transition(silent), transition(login, "reminder")), by_fp(silent, login), lang="en"
    )
    assert payload["schema_version"] == NOTIFY_SCHEMA_VERSION
    assert payload["type"] == "digest"
    assert payload["tool"]["name"] == "hushwatch" and payload["tool"]["version"]
    assert payload["tenant"] == TENANT and payload["run_at"] == "2026-09-01T12:00:00Z"
    assert payload["run_id"].startswith("20260901T120000Z-")
    assert payload["counts"]["open"] == 2 and payload["counts"]["transitions"]["opened"] == 1
    assert payload["counts"]["transitions"]["reminder"] == 1 and payload["truncated"] == 0
    first = payload["transitions"][0]
    for key in ("type", "fingerprint", "kind", "domain", "severity", "status", "title", "flapping", "opened_at"):
        assert key in first
    assert first["fingerprint"] == silent.fingerprint and first["kind"] == "silence.silent"
    assert first["domain"] == "silence" and first["severity"] == "critical" and first["confidence"] == "medium"
    assert payload["summary"] == "hushwatch · acme: opened: 1 · still open: 1"
    json.dumps(payload, allow_nan=False)  # serializable as is


def test_payload_without_entities_and_without_redactor_has_no_raw_values() -> None:
    silent, login = silent_finding(), login_finding()
    payload = build_payload(TENANT, outcome_of(transition(silent), transition(login)), by_fp(silent, login))
    text = json.dumps(payload, ensure_ascii=False)
    for raw in RAW_VALUES:
        assert raw not in text, raw
    assert payload["transitions"][0]["title"] == "[host] stopped sending Security events"
    assert "subject" not in payload["transitions"][0] and "entities" not in payload["transitions"][0]


def test_payload_with_redactor_uses_stable_tokens() -> None:
    silent, login = silent_finding(), login_finding()
    redactor = Redactor(b"k" * 32)
    payload = build_payload(
        TENANT, outcome_of(transition(silent), transition(login)), by_fp(silent, login), redactor=redactor
    )
    text = json.dumps(payload, ensure_ascii=False)
    for raw in RAW_VALUES:
        assert raw not in text, raw
    host_token = redactor.token("srv-web-01.example", "host")
    item = payload["transitions"][0]
    assert item["title"] == f"{host_token} stopped sending Security events"
    assert {"kind": "host", "value": host_token} in item["entities"]
    assert item["subject"] == redactor.token(silent.subject, "val")
    login_item = payload["transitions"][1]
    assert redactor.token("alice", "user") in login_item["title"]


def test_payload_with_entities_opt_in_has_raw_values() -> None:
    silent = silent_finding()
    payload = build_payload(TENANT, outcome_of(transition(silent)), by_fp(silent), include_entities=True)
    item = payload["transitions"][0]
    assert item["title"] == "srv-web-01.example stopped sending Security events"
    assert item["subject"] == silent.subject
    assert {"kind": "ip", "value": "198.51.100.23"} in item["entities"]
    assert payload["include_entities"] is True


def test_payload_in_spanish() -> None:
    silent = silent_finding()
    payload = build_payload(TENANT, outcome_of(transition(silent)), by_fp(silent), lang="es")
    assert payload["transitions"][0]["title"] == "[host] dejó de enviar eventos Security"
    assert payload["summary"] == "hushwatch · acme: abiertos: 1"
    assert build_payload(TENANT, outcome_of(), {}, lang="xx")["lang"] == "en"


def test_resolved_finding_uses_state_summary(tmp_path: Path) -> None:
    silent = silent_finding()
    with StateStore(tmp_path / "s.sqlite3") as store:
        store.record_run(TENANT, [silent], now=T0)
        store.record_run(TENANT, [], now=T0 + timedelta(hours=1))
        outcome = store.record_run(TENANT, [], now=T0 + timedelta(hours=2))
    assert [t.type for t in outcome.transitions] == ["resolved"]
    payload = build_payload(TENANT, outcome, {}, lang="es", include_entities=True)
    item = payload["transitions"][0]
    assert item["title"] == "[host] dejó de enviar eventos [channel]"
    assert item["status"] == "resolved" and item["resolved_at"] == "2026-09-01T14:00:00Z"
    assert "entities" not in item


def test_acceptance_expired_payload(tmp_path: Path) -> None:
    from hushwatch.state import AcceptEntry, AcceptList

    silent = silent_finding()
    entry = AcceptEntry(owner="alice", reason="lab", expires=T0 - timedelta(hours=1), fingerprint=silent.fingerprint)
    with StateStore(tmp_path / "s.sqlite3") as store:
        outcome = store.record_run(TENANT, [silent], now=T0, accept=AcceptList([entry]))
    (item,) = build_payload(TENANT, outcome, by_fp(silent))["transitions"]
    assert item["type"] == "acceptance_expired"
    assert item["acceptance"]["id"] == entry.id and item["acceptance"]["expires"] == "2026-09-01T11:00:00Z"
    assert "alice" not in json.dumps(item) and "[user]" in item["detail"]


def test_truncation_keeps_the_most_severe() -> None:
    lows = [silent_finding(f"ws-{i:02d}.corp.example", Severity.LOW) for i in range(8)]
    crit = silent_finding("dc01.corp.example", Severity.CRITICAL)
    transitions = [transition(f) for f in lows] + [transition(crit, "resolved", status="resolved")]
    payload = build_payload(TENANT, outcome_of(*transitions), by_fp(*lows, crit), max_transitions=3)
    assert len(payload["transitions"]) == 3 and payload["truncated"] == 6
    assert crit.fingerprint in [t["fingerprint"] for t in payload["transitions"]]


def test_hostile_values_are_serializable_and_bounded() -> None:
    hostile = "\ud800\x00\x1b[2J<script>" + "A" * 1_000_000
    finding = Finding(
        kind="noise.investigate", domain="noise", title=M("test.notify.hostile", user=Entity("user", hostile)),
        severity=Severity.HIGH, subject=hostile, tenant=TENANT,
    )  # fmt: skip
    for include in (True, False):
        payload = build_payload(TENANT, outcome_of(transition(finding)), by_fp(finding), include_entities=include)
        text = json.dumps(payload, ensure_ascii=False, allow_nan=False)
        text.encode("utf-8")  # no lone surrogates left
        item = payload["transitions"][0]
        assert len(item["title"]) <= 300 and "\x00" not in item["title"] and "\x1b" not in item["title"]
        assert len(text) < 5000


def test_learned_entities_are_caught_in_free_text() -> None:
    finding = Finding(
        kind="pipeline.agent_no_data",
        domain="pipeline",
        title=M("test.notify.hostile", user="dc01.corp.example"),  # module bug: not wrapped in Entity
        severity=Severity.HIGH,
        subject="agent:dc01.corp.example",
        tenant=TENANT,
        evidence={"agent": Entity("host", "dc01.corp.example")},  # ...but known from the evidence
    )
    redactor = Redactor(b"k" * 32)
    payload = build_payload(TENANT, outcome_of(transition(finding)), by_fp(finding), redactor=redactor)
    assert "dc01.corp.example" not in json.dumps(payload)
    assert redactor.token("dc01.corp.example", "host") in payload["transitions"][0]["title"]


def test_plain_string_title_is_scrubbed_without_redactor() -> None:
    finding = Finding(
        kind="pipeline.lag", domain="pipeline", title="ingest lag on 198.51.100.23 for alice@corp.example",
        severity=Severity.HIGH, subject="agent:x", tenant=TENANT,
    )  # fmt: skip
    payload = build_payload(TENANT, outcome_of(transition(finding)), by_fp(finding))
    title = payload["transitions"][0]["title"]
    assert "198.51.100.23" not in title and "alice@corp.example" not in title and title.startswith("ingest lag on")


# ---- Slack -------------------------------------------------------------------------------------------------------

HOSTILE_TITLES = [
    "<!channel> urgent",
    "<!here|here> <!everyone>",
    "<http://evil.example/login|click here to fix>",
    "<@U12345678> and <#C12345678>",
    "Tom & Jerry <b>",
    "@channel @here @everyone",
    "<!date^1392734382^{date}|x>",
    "*bold* _it_ ~s~ `code` ```block```",
    "line1\nline2\r\n\u202eevil\u2066",
    "https://evil.example/path and ftp://files.example",
]


@pytest.mark.parametrize("title", HOSTILE_TITLES)
def test_slack_escape_neutralizes(title: str) -> None:
    escaped = slack_escape(title)
    assert "<" not in escaped and ">" not in escaped
    assert "@channel" not in escaped and "@here" not in escaped and "@everyone" not in escaped
    assert "://" not in escaped
    assert "\n" not in escaped and "\u202e" not in escaped and "\u2066" not in escaped
    # every & in the output starts an entity we produced
    assert escaped.replace("&amp;", "").replace("&lt;", "").replace("&gt;", "").count("&") == 0


def test_slack_escape_specifics() -> None:
    assert slack_escape("a & b < c > d") == "a &amp; b &lt; c &gt; d"
    assert slack_escape("&lt;") == "&amp;lt;"  # pre-escaped input cannot smuggle a raw '<'
    assert slack_escape("see http://evil.example") == "see http[:]//evil[.]example"
    assert slack_escape("x" * 5000, 100).endswith("…") and len(slack_escape("x" * 5000, 100)) == 100


def test_slack_message_with_hostile_titles() -> None:
    findings = [
        Finding(
            kind="noise.investigate",
            domain="noise",
            title=M("test.notify.hostile", user=Entity("user", t)),
            severity=Severity.HIGH,
            subject=f"s{i}",
            tenant=TENANT,
        )
        for i, t in enumerate(HOSTILE_TITLES)
    ]
    payload = build_payload(
        TENANT, outcome_of(*[transition(f) for f in findings]), by_fp(*findings), include_entities=True
    )
    rec = Recorder()
    result = send(slack(include_entities=True), payload, transport=rec.transport)
    assert result.ok and result.sent and result.transitions == len(HOSTILE_TITLES)
    body = rec.body()
    texts = all_texts(body)
    joined = "\n".join(texts)
    for text in texts:
        assert "<" not in text and ">" not in text, text
    assert "&lt;!channel&gt;" not in joined or "<!channel>" not in joined
    assert "<!" not in joined and "<http" not in joined and "<@" not in joined
    assert "@here" not in joined and "@channel" not in joined and "@everyone" not in joined
    assert "Tom &amp; Jerry &lt;b&gt;" in joined
    assert "http://" not in joined and "https://" not in joined
    assert body["unfurl_links"] is False and body["unfurl_media"] is False and body["link_names"] is False
    assert all(len(t) <= SLACK_TEXT_LIMIT for t in texts)


def test_slack_message_limits_with_many_long_transitions() -> None:
    findings = [silent_finding(f"ws-{i:03d}.corp.example" + "x" * 5000) for i in range(60)]
    payload = build_payload(TENANT, outcome_of(*[transition(f) for f in findings]), by_fp(*findings))
    rec = Recorder()
    assert send(slack(), payload, transport=rec.transport).ok
    body = rec.body()
    assert len(body["blocks"]) <= 50
    assert all(len(t) <= SLACK_TEXT_LIMIT for t in all_texts(body))
    assert "…plus 40 more (see the full report)" in json.dumps(body, ensure_ascii=False)
    assert len(rec.requests) == 1  # one digest per tenant per run


def test_slack_digest_in_spanish_and_min_severity_note() -> None:
    crit, medium = silent_finding(), login_finding(Severity.MEDIUM)
    payload = build_payload(TENANT, outcome_of(transition(crit), transition(medium)), by_fp(crit, medium), lang="es")
    rec = Recorder()
    result = send(slack(min_severity="high"), payload, transport=rec.transport)
    assert result.ok and result.transitions == 1
    text = json.dumps(rec.body(), ensure_ascii=False)
    assert "CRÍTICA" in text and "Abierto" in text and "abiertos: 1" in text
    assert "cambios no mostrados (severidad inferior a alta): 1" in text


# ---- webhook delivery ------------------------------------------------------------------------------------------


def test_webhook_post_json_with_custom_headers_and_min_severity() -> None:
    crit, medium, low = (
        silent_finding(),
        login_finding(Severity.MEDIUM),
        silent_finding("ws-01.corp.example", Severity.LOW),
    )
    payload = build_payload(
        TENANT, outcome_of(transition(crit), transition(medium), transition(low)), by_fp(crit, medium, low)
    )
    rec = Recorder()
    cfg = webhook(headers={"Authorization": "Bearer t0k3n-value", "X-Tenant": "acme"}, min_severity="medium")
    result = send(cfg, payload, transport=rec.transport)
    assert result.ok and result.sent and result.status_code == 200 and result.error is None
    assert result.target == "https://hooks.example.com"
    assert result.fingerprints == (crit.fingerprint, medium.fingerprint)
    (request,) = rec.requests
    assert request.method == "POST" and request.url == httpx.URL(HOOK_URL)
    assert request.headers["authorization"] == "Bearer t0k3n-value" and request.headers["x-tenant"] == "acme"
    assert request.headers["content-type"].startswith("application/json")
    assert request.headers["user-agent"].startswith("hushwatch/")
    body = rec.body()
    assert body["schema_version"] == NOTIFY_SCHEMA_VERSION and body["type"] == "digest"
    assert [t["severity"] for t in body["transitions"]] == ["critical", "medium"]
    assert body["omitted"] == 1 and body["min_severity"] == "medium"
    assert body["summary"] == "hushwatch · acme: opened: 2"


def test_nothing_at_or_above_min_severity_sends_nothing() -> None:
    low = silent_finding(severity=Severity.LOW)
    payload = build_payload(TENANT, outcome_of(transition(low)), by_fp(low))
    rec = Recorder()
    result = send(webhook(min_severity="high"), payload, transport=rec.transport)
    assert result.ok and not result.sent and rec.requests == []
    assert build_payload(TENANT, outcome_of(), {})["transitions"] == []
    assert send(webhook(), build_payload(TENANT, outcome_of(), {}), transport=rec.transport).sent is False
    assert rec.requests == []


def test_unknown_min_severity_sends_everything() -> None:
    info = silent_finding(severity=Severity.INFO)
    payload = build_payload(TENANT, outcome_of(transition(info)), by_fp(info))
    rec = Recorder()
    assert send(webhook(min_severity="verbose"), payload, transport=rec.transport).sent


def test_digest_sent_once_per_run_and_target() -> None:
    crit = silent_finding()
    payload = build_payload(TENANT, outcome_of(transition(crit)), by_fp(crit))
    payload["run_id"] = "20260901T120000Z-dedupe01"
    rec = Recorder()
    cfg = webhook(url="https://hooks.example.com/dedupe")
    assert send(cfg, payload, transport=rec.transport).sent
    second = send(cfg, payload, transport=rec.transport)
    assert second.ok and not second.sent and len(rec.requests) == 1
    other_target = webhook(url="https://hooks.example.com/other")
    assert send(other_target, payload, transport=rec.transport).sent


def test_failed_delivery_can_be_retried_next_time() -> None:
    crit = silent_finding()
    payload = build_payload(TENANT, outcome_of(transition(crit)), by_fp(crit))
    payload["run_id"] = "20260901T120000Z-retry001"
    cfg = webhook(url="https://hooks.example.com/retry")
    failing = Recorder(lambda r: httpx.Response(503, text="maintenance"))
    first = send(cfg, payload, transport=failing.transport)
    assert not first.ok and first.status_code == 503 and first.fingerprints == (crit.fingerprint,)
    ok = Recorder()
    assert send(cfg, payload, transport=ok.transport).sent


def test_entities_payload_refused_for_target_without_opt_in() -> None:
    crit = silent_finding()
    payload = build_payload(TENANT, outcome_of(transition(crit)), by_fp(crit), include_entities=True)
    rec = Recorder()
    result = send(slack(include_entities=False), payload, transport=rec.transport)
    assert not result.ok and rec.requests == [] and "include_entities" in (result.error or "")


# ---- failures never raise and never leak the URL ----------------------------------------------------------------


def _raise(exc: Exception) -> Callable[[httpx.Request], httpx.Response]:
    def handler(request: httpx.Request) -> httpx.Response:
        raise exc

    return handler


def _assert_no_secret(error: str | None) -> None:
    assert error
    for secret in (SLACK_SECRET, "/services/", "T00000000", "B00000000", "s3cr3tT0ken", "9f8e7d6c5b4a", "token="):
        assert secret not in error, (secret, error)


@pytest.mark.parametrize("url", [SLACK_URL, HOOK_URL])
@pytest.mark.parametrize(
    ("exc_factory", "expected"),
    [
        (lambda u: httpx.ConnectError(f"[Errno 111] Connection refused while connecting to {u}"), "connection failed"),
        (lambda u: httpx.ConnectError(f"[SSL: CERTIFICATE_VERIFY_FAILED] for {u}"), "TLS error"),
        (lambda u: httpx.ReadTimeout(f"timed out reading {u}"), "no answer within 10 s"),
        (lambda u: httpx.RemoteProtocolError(f"peer closed connection for {u}"), "request failed"),
        (lambda u: OSError(f"network unreachable {u}"), "request failed"),
        (lambda u: RuntimeError(f"boom {u}"), "unexpected error (RuntimeError)"),
    ],
)
def test_network_errors_return_safe_results(url: str, exc_factory: Callable[[str], Exception], expected: str) -> None:
    crit = silent_finding()
    payload = build_payload(TENANT, outcome_of(transition(crit)), by_fp(crit))
    cfg = slack(url=url) if "slack" in url else webhook(url=url)
    result = send(cfg, payload, transport=httpx.MockTransport(_raise(exc_factory(url))))
    assert not result.ok and not result.sent
    assert expected in (result.error or "")
    _assert_no_secret(result.error)
    assert result.target in (result.error or "") or expected.startswith("unexpected")
    # every failure hands the fingerprints back (regression: unexpected errors used to lose them)
    assert result.fingerprints == (crit.fingerprint,)


def test_http_error_body_echoing_the_url_is_scrubbed() -> None:
    crit = silent_finding()
    payload = build_payload(TENANT, outcome_of(transition(crit)), by_fp(crit))
    rec = Recorder(lambda r: httpx.Response(404, text=f"no_service: {r.url} (token {SLACK_SECRET})"))
    result = send(slack(), payload, transport=rec.transport)
    assert not result.ok and result.status_code == 404 and "HTTP 404" in (result.error or "")
    assert "no_service" in (result.error or "")
    _assert_no_secret(result.error)


def test_redirects_are_not_followed() -> None:
    crit = silent_finding()
    payload = build_payload(TENANT, outcome_of(transition(crit)), by_fp(crit))
    rec = Recorder(lambda r: httpx.Response(302, headers={"Location": "https://attacker.example/collect"}))
    result = send(webhook(), payload, transport=rec.transport)
    assert not result.ok and result.status_code == 302 and len(rec.requests) == 1
    assert "redirect" in (result.error or "")


@pytest.mark.parametrize(
    ("cfg", "expected"),
    [
        (NotifyConfig(type="webhook", url=""), "no URL configured"),
        (NotifyConfig(type="webhook", url="ftp://files.example/drop"), "invalid or does not use http(s)"),
        (NotifyConfig(type="webhook", url="file:///etc/passwd"), "invalid or does not use http(s)"),
        (NotifyConfig(type="webhook", url="hooks.example.com/no-scheme/FAKE-test-token"), "invalid"),
        (
            NotifyConfig(type="slack", url="http://hooks.slack.example/services/FAKE/FAKE/" + SLACK_SECRET),
            "must use https",
        ),
        (NotifyConfig(type="teams", url=HOOK_URL), "unknown notification type"),
        (NotifyConfig(type="webhook", url=HOOK_URL, headers={"X-Bad": "v\r\nX-Injected: 1"}), "custom header 'X-Bad'"),
        (NotifyConfig(type="webhook", url=HOOK_URL, headers={"Bad Name": "v"}), "custom header"),
        (NotifyConfig(type="webhook", url=HOOK_URL, headers={"X-Owner": "José"}), "custom header 'X-Owner'"),
    ],
)
def test_invalid_configuration_is_reported_not_raised(cfg: NotifyConfig, expected: str) -> None:
    crit = silent_finding()
    payload = build_payload(TENANT, outcome_of(transition(crit)), by_fp(crit))
    rec = Recorder()
    result = send(cfg, payload, transport=rec.transport)
    assert not result.ok and rec.requests == []
    assert expected in (result.error or "")
    _assert_no_secret(result.error)
    assert "X-Injected" not in (result.error or "")
    assert result.fingerprints == (crit.fingerprint,)  # handed back: sent once the configuration is fixed


def test_malformed_payloads_never_raise() -> None:
    rec = Recorder()
    assert not send(webhook(), {"type": "weird"}, transport=rec.transport).ok
    assert send(webhook(), {"type": "digest", "transitions": "nope"}, transport=rec.transport).sent is False
    nan = {"type": "digest", "transitions": [{"severity": "high"}], "counts": {"x": float("nan")}}
    result = send(webhook(), nan, transport=rec.transport)
    assert not result.ok and "could not be encoded" in (result.error or "")
    assert rec.requests == []


def test_header_token_echoed_by_the_server_is_scrubbed() -> None:
    crit = silent_finding()
    payload = build_payload(TENANT, outcome_of(transition(crit)), by_fp(crit))
    rec = Recorder(lambda r: httpx.Response(401, text="invalid token t0k3n-value-123 for this workspace"))
    result = send(webhook(headers={"Authorization": "Bearer t0k3n-value-123"}), payload, transport=rec.transport)
    assert not result.ok and "HTTP 401" in (result.error or "") and "invalid token" in (result.error or "")
    assert "t0k3n-value-123" not in (result.error or "")


class _Trickle(httpx.SyncByteStream):
    def __init__(self) -> None:
        self.chunks = 0

    def __iter__(self) -> Any:
        import time

        for _ in range(4096):
            self.chunks += 1
            time.sleep(0.01)
            yield b"x"


def test_trickling_error_body_is_bounded_in_time() -> None:
    # regression: per-read timeouts let a server trickling one byte at a time hold the run for hours
    stream = _Trickle()
    crit = silent_finding()
    payload = build_payload(TENANT, outcome_of(transition(crit)), by_fp(crit))
    result = send(
        webhook(),
        payload,
        transport=httpx.MockTransport(lambda r: httpx.Response(500, stream=stream)),
        timeout=0.2,
    )
    assert not result.ok and result.status_code == 500
    assert stream.chunks < 100


def test_success_body_is_not_read() -> None:
    stream = _Trickle()
    crit = silent_finding()
    payload = build_payload(TENANT, outcome_of(transition(crit)), by_fp(crit))
    result = send(webhook(), payload, transport=httpx.MockTransport(lambda r: httpx.Response(200, stream=stream)))
    assert result.ok and result.sent and stream.chunks == 0


# ---- heartbeat ---------------------------------------------------------------------------------------------------


def test_heartbeat_to_webhook_every_run() -> None:
    rec = Recorder()
    result = send_heartbeat(
        webhook(),
        TENANT,
        now=T0,
        ok=False,
        detail="indexer https://svc:FAKE-test-password-1@198.51.100.7:9200/_search failed",
        run_id="r1",
        counts={"open": 3},
        transport=rec.transport,
    )
    assert result.ok and result.sent
    body = rec.body()
    assert body["type"] == "heartbeat" and body["ok"] is False and body["status"] == "fail"
    assert body["tenant"] == TENANT and body["at"] == "2026-09-01T12:00:00Z" and body["counts"] == {"open": 3}
    assert "FAKE-test-password-1" not in body["detail"] and "198.51.100.7" not in body["detail"]
    assert body["summary"] == "hushwatch · acme: run FAILED or incomplete (2026-09-01T12:00:00Z)"
    assert send_heartbeat(webhook(), TENANT, now=T0, ok=True, transport=rec.transport).sent


def test_slack_heartbeat_only_when_failing() -> None:
    rec = Recorder()
    quiet = send_heartbeat(slack(), TENANT, now=T0, ok=True, transport=rec.transport)
    assert quiet.ok and not quiet.sent and rec.requests == []
    loud = send_heartbeat(
        slack(), TENANT, now=T0, ok=False, detail="<!channel> auth failed", lang="es", transport=rec.transport
    )
    assert loud.ok and loud.sent
    body = rec.body()
    joined = "\n".join(all_texts(body))
    assert "FALLÓ" in joined and "<" not in joined
    forced = send_heartbeat(slack(), TENANT, now=T0, ok=True, slack_always=True, transport=rec.transport)
    assert forced.sent


@pytest.mark.parametrize("include", [False, True])
@pytest.mark.parametrize("with_redactor", [False, True])
def test_heartbeat_detail_never_carries_url_credentials(include: bool, with_redactor: bool) -> None:
    # regression: a password with a '!' or an api_key in the query string reached the webhook
    detail = "indexer https://svc:p4ss!w0rd@indexer.corp.example:9200/_search?api_key=ABCDEF123 failed"
    redactor = Redactor(b"k" * 32) if with_redactor else None
    body = build_heartbeat(TENANT, now=T0, ok=False, detail=detail, include_entities=include, redactor=redactor)
    for secret in ("p4ss", "w0rd", "ABCDEF123", "api_key", "_search", "svc:"):
        assert secret not in body["detail"], (secret, body["detail"])
    assert body["detail"].startswith("indexer https://") and body["detail"].endswith(" failed")


def test_titles_never_carry_url_credentials() -> None:
    finding = Finding(
        kind="noise.investigate", domain="noise", severity=Severity.HIGH, subject="x", tenant=TENANT,
        title=M("test.notify.hostile", user="https://bob:FAKE-test-password-2@203.0.113.9/x?sig=FAKE-signature"),
    )  # fmt: skip
    for include in (True, False):
        payload = build_payload(TENANT, outcome_of(transition(finding)), by_fp(finding), include_entities=include)
        title = payload["transitions"][0]["title"]
        assert "FAKE-test-password-2" not in title and "bob:" not in title, title
        assert ("FAKE-signature" in title) is include  # opted in: the URL itself is data, only credentials go


def test_url_entities_lose_their_credentials_even_with_include_entities() -> None:
    finding = Finding(
        kind="noise.investigate", domain="noise", severity=Severity.HIGH, tenant=TENANT,
        subject="url:https://bob:FAKE-test-password-2@203.0.113.9/login",
        title=M("test.notify.hostile", user=Entity("url", "https://bob:FAKE-test-password-2@203.0.113.9/login")),
    )  # fmt: skip
    payload = build_payload(TENANT, outcome_of(transition(finding)), by_fp(finding), include_entities=True)
    text = json.dumps(payload)
    assert "FAKE-test-password-2" not in text and "https://203.0.113.9/login" in text


def test_unwrapped_value_known_from_evidence_is_masked_without_redactor() -> None:
    # regression: without a redactor, a hostname a module forgot to wrap reached the webhook in clear
    finding = Finding(
        kind="pipeline.agent_no_data",
        domain="pipeline",
        title=M("test.notify.hostile", user="dc01.corp.example"),
        severity=Severity.HIGH,
        subject="agent:dc01.corp.example",
        tenant=TENANT,
        evidence={"agent": Entity("host", "dc01.corp.example")},
    )
    payload = build_payload(TENANT, outcome_of(transition(finding)), by_fp(finding))
    assert "dc01.corp.example" not in json.dumps(payload)
    assert payload["transitions"][0]["title"] == "rule fired for [host]"


def test_heartbeat_detail_message_is_redacted() -> None:
    detail = M("test.notify.silent", host=Entity("host", "srv-web-01.example"), channel="Security")
    plain = build_heartbeat(TENANT, now=T0, ok=True, detail=detail)
    assert plain["detail"] == "[host] stopped sending Security events"
    raw = build_heartbeat(TENANT, now=T0, ok=True, detail=detail, include_entities=True)
    assert "srv-web-01.example" in raw["detail"]


def test_slack_defangs_bare_domains_and_emails() -> None:
    # regression: attacker-chosen names like "reset-sso.example" were auto-linked by Slack (phishing in the SOC)
    finding = Finding(
        kind="noise.investigate", domain="noise", severity=Severity.HIGH, subject="x", tenant=TENANT,
        title=M("test.notify.hostile", user=Entity("user", "log in at reset-sso.example or mail it@evil.example")),
    )  # fmt: skip
    payload = build_payload(TENANT, outcome_of(transition(finding)), by_fp(finding), include_entities=True)
    rec = Recorder()
    assert send(slack(include_entities=True), payload, transport=rec.transport).sent
    joined = "\n".join(all_texts(rec.body()))
    assert "reset-sso[.]example" in joined and "it@evil[.]example" in joined
    assert "reset-sso.example" not in joined and "evil.example" not in joined
    assert f"`{finding.kind}`" in joined  # our own identifiers stay readable (code spans are never linked)
    assert slack_escape("version 4.8.0, 1.5h, e.g. this") == "version 4.8.0, 1.5h, e.g. this"


def test_escalation_is_delivered_past_the_severity_filter(tmp_path: Path) -> None:
    low = silent_finding(severity=Severity.LOW)
    with StateStore(tmp_path / "s.sqlite3") as store:
        opened = store.record_run(TENANT, [low], now=T0)
        rec = Recorder()
        assert not send(
            webhook(min_severity="high"), build_payload(TENANT, opened, by_fp(low)), transport=rec.transport
        ).sent
        crit = silent_finding(severity=Severity.CRITICAL)
        escalated = store.record_run(TENANT, [crit], now=T0 + timedelta(hours=1))
    payload = build_payload(TENANT, escalated, by_fp(crit), lang="es")
    result = send(webhook(min_severity="high"), payload, transport=rec.transport)
    assert result.sent
    (item,) = rec.body()["transitions"]
    assert item["type"] == "escalated" and item["severity"] == "critical" and item["previous_severity"] == "low"
    assert rec.body()["summary"] == "hushwatch · acme: más graves: 1"
    slack_rec = Recorder()
    assert send(slack(), build_payload(TENANT, escalated, by_fp(crit)), transport=slack_rec.transport).sent
    assert "More severe" in json.dumps(slack_rec.body())


# ---- integration with the state store ----------------------------------------------------------------------------


def test_undelivered_digest_is_resent_next_run(tmp_path: Path) -> None:
    crit = silent_finding()
    with StateStore(tmp_path / "s.sqlite3") as store:
        outcome = store.record_run(TENANT, [crit], now=T0)
        payload = build_payload(TENANT, outcome, by_fp(crit))
        failed = send(webhook(), payload, transport=httpx.MockTransport(_raise(httpx.ConnectError("refused"))))
        assert not failed.ok
        store.mark_undelivered(TENANT, outcome.run_id, failed.fingerprints)
        again = store.record_run(TENANT, [crit], now=T0 + timedelta(minutes=15))
        assert [t.type for t in again.transitions] == ["opened"]
        rec = Recorder()
        delivered = send(webhook(), build_payload(TENANT, again, by_fp(crit)), transport=rec.transport)
        assert delivered.sent
        assert store.record_run(TENANT, [crit], now=T0 + timedelta(minutes=30)).transitions == []
