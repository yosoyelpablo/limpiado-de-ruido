"""Tests for hushwatch.net: TLS context, client factory, safe errors, secret scrubbing, rate limiter."""

from __future__ import annotations

import shutil
import ssl
import subprocess
from pathlib import Path
from typing import Any, ClassVar

import httpx
import pytest

from hushwatch import i18n
from hushwatch.net import (
    RateLimiter,
    RemoteError,
    backoff_delay,
    build_ssl_context,
    is_plain_http,
    loads_json,
    make_client,
    redact_secret,
    retry_after,
    safe_url,
    sanitize_text,
    send_bounded,
    transport_error,
    validate_base_url,
)

PASSWORD = "Tr0ub4dor&3-not-real"
JWT = "eyJhbGciOiJFUzUxMiJ9.eyJpc3MiOiJ3YXp1aCIsImV4cCI6MTcwMDAwMDkwMH0.c2lnbmF0dXJlLW5vdC1yZWFs"


class FakeClock:
    def __init__(self, now: float = 1000.0, *, advance_on_sleep: bool = True) -> None:
        self.now = now
        self.sleeps: list[float] = []
        self.advance_on_sleep = advance_on_sleep

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        if self.advance_on_sleep:
            self.now += seconds


def _openssl_ca(tmp_path: Path) -> Path:
    """Generate a throwaway self-signed CA with the openssl CLI (test skipped when unavailable)."""
    if shutil.which("openssl") is None:
        pytest.skip("openssl CLI not available")
    key = tmp_path / "ca.key"
    cert = tmp_path / "root-ca.pem"
    result = subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(key),
            "-out",
            str(cert),
            "-days",
            "2",
            "-subj",
            "/CN=hushwatch-test-ca.example",
        ],
        capture_output=True,
        check=False,
        timeout=60,
    )
    if result.returncode != 0:
        pytest.skip("openssl could not generate a test CA")
    return cert


# ---- TLS -------------------------------------------------------------------------------------------------------


def test_verify_false_only_when_explicit() -> None:
    assert build_ssl_context(None, False) is False
    assert build_ssl_context("/nonexistent/ca.pem", False) is False  # explicit opt-out ignores the CA


def test_default_context_verifies_chain_and_hostname() -> None:
    ctx = build_ssl_context(None, True)
    assert isinstance(ctx, ssl.SSLContext)
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.check_hostname is True
    assert ctx.minimum_version >= ssl.TLSVersion.TLSv1_2


def test_context_loads_real_ca_file(tmp_path: Path) -> None:
    ca = _openssl_ca(tmp_path)
    ctx = build_ssl_context(str(ca), True)
    assert isinstance(ctx, ssl.SSLContext)
    subjects = [dict(item[0] for item in cert["subject"]) for cert in ctx.get_ca_certs()]  # type: ignore[misc]
    assert {"commonName": "hushwatch-test-ca.example"} in subjects
    assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname
    assert not ctx.verify_flags & getattr(ssl, "VERIFY_X509_STRICT", 0)


def test_context_ca_file_with_monkeypatched_loader(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ca = tmp_path / "root-ca.pem"
    ca.write_text("placeholder")
    calls: list[dict[str, Any]] = []

    def fake_load(self: ssl.SSLContext, cafile: Any = None, capath: Any = None, cadata: Any = None) -> None:
        calls.append({"cafile": cafile, "capath": capath})

    monkeypatch.setattr(ssl.SSLContext, "load_verify_locations", fake_load)
    ctx = build_ssl_context(str(ca), True)
    assert isinstance(ctx, ssl.SSLContext)
    assert {"cafile": str(ca), "capath": None} in calls


def test_context_ca_directory_uses_capath(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[dict[str, Any]] = []

    def fake_load(self: ssl.SSLContext, cafile: Any = None, capath: Any = None, cadata: Any = None) -> None:
        calls.append({"cafile": cafile, "capath": capath})

    monkeypatch.setattr(ssl.SSLContext, "load_verify_locations", fake_load)
    build_ssl_context(str(tmp_path), True)
    assert {"cafile": None, "capath": str(tmp_path)} in calls


def test_missing_ca_file_is_a_config_error(tmp_path: Path) -> None:
    missing = tmp_path / "nope" / "root-ca.pem"
    with pytest.raises(RemoteError) as info:
        build_ssl_context(str(missing), True)
    assert info.value.kind == "config"
    assert "root-ca.pem" in str(info.value)
    assert "No se puede cargar" in info.value.render("es")


def test_garbage_ca_file_is_a_config_error(tmp_path: Path) -> None:
    bad = tmp_path / "bad.pem"
    bad.write_text("-----BEGIN CERTIFICATE-----\nnot a certificate\n-----END CERTIFICATE-----\n")
    with pytest.raises(RemoteError) as info:
        build_ssl_context(str(bad), True)
    assert info.value.kind == "config"


# ---- client factory --------------------------------------------------------------------------------------------


class _RecordingClient:
    last_kwargs: ClassVar[dict[str, Any]] = {}

    def __init__(self, **kwargs: Any) -> None:
        type(self).last_kwargs = kwargs


def test_make_client_passes_ssl_context_never_a_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ca = _openssl_ca(tmp_path)
    monkeypatch.setattr(httpx, "Client", _RecordingClient)  # the module hushwatch.net calls at runtime
    make_client("https://indexer.example:9200", ca_cert=str(ca), verify_tls=True, timeout=30)
    kwargs = _RecordingClient.last_kwargs
    assert isinstance(kwargs["verify"], ssl.SSLContext)
    assert kwargs["follow_redirects"] is False
    assert kwargs["base_url"] == "https://indexer.example:9200"
    assert kwargs["timeout"].connect == 15.0 and kwargs["timeout"].read == 30.0


def test_make_client_verify_false_and_plain_http(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(httpx, "Client", _RecordingClient)
    make_client("https://indexer.example:9200", ca_cert=None, verify_tls=False, timeout=5)
    assert _RecordingClient.last_kwargs["verify"] is False
    make_client("http://10.0.0.5:9200/", ca_cert="/nonexistent.pem", verify_tls=True, timeout=5)
    assert _RecordingClient.last_kwargs["verify"] is True  # no TLS on plain http: the CA is irrelevant
    assert _RecordingClient.last_kwargs["base_url"] == "http://10.0.0.5:9200"


def test_make_client_sends_safe_default_headers_and_no_redirects() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(302, headers={"Location": "https://evil.example/steal"})

    client = make_client(
        "https://indexer.example:9200/prefix",
        ca_cert=None,
        verify_tls=True,
        timeout=5,
        auth=("alice", PASSWORD),
        transport=httpx.MockTransport(handler),
    )
    resp = client.get("/_search")
    assert resp.status_code == 302  # not followed: credentials never go to another host
    assert len(seen) == 1
    assert str(seen[0].url) == "https://indexer.example:9200/prefix/_search"
    assert seen[0].headers["user-agent"].startswith("hushwatch/")
    assert seen[0].headers["accept"] == "application/json"


@pytest.mark.parametrize(
    "url",
    [
        f"https://alice:{PASSWORD}@indexer.example:9200",
        "https://alice@indexer.example:9200",
    ],
)
def test_credentials_in_url_rejected_without_echoing_them(url: str) -> None:
    with pytest.raises(RemoteError) as info:
        make_client(url, ca_cert=None, verify_tls=True, timeout=5)
    assert info.value.kind == "config"
    assert PASSWORD not in str(info.value)
    assert "alice" not in str(info.value)
    assert PASSWORD not in info.value.render("es")


@pytest.mark.parametrize(
    "url",
    [
        "ftp://indexer.example",
        "indexer.example:9200",
        "https://",
        "https://indexer.example:99999",
        "https://h.example/?a=1",
    ],
)
def test_invalid_urls_rejected(url: str) -> None:
    with pytest.raises(RemoteError) as info:
        validate_base_url(url)
    assert info.value.kind == "config"


@pytest.mark.parametrize("timeout", [0, -1, float("nan"), float("inf"), True])
def test_invalid_timeout_rejected(timeout: Any) -> None:
    with pytest.raises(RemoteError) as info:
        make_client("https://indexer.example", ca_cert=None, verify_tls=True, timeout=timeout)
    assert info.value.kind == "config"


# ---- safe errors / secrets ---------------------------------------------------------------------------------------


def test_remote_error_renders_in_both_languages() -> None:
    err = RemoteError(i18n.M("net.err.connect", url=i18n.Entity("url", "https://dc01.corp.example"), reason="refused"))
    assert "Cannot connect to https://dc01.corp.example" in str(err)
    assert "No se puede conectar con https://dc01.corp.example" in err.render("es")
    redacted = err.render("en", lambda e: f"<{e.kind}>")
    assert "<url>" in redacted and "dc01" not in redacted
    assert RemoteError("x", kind="bogus").kind == "http"


def test_redact_secret() -> None:
    assert redact_secret(None) == ""
    assert redact_secret("") == ""
    assert redact_secret("short") == "***"
    long_id = "FGluY2x1ZGVfY29udGV4dF91dWlkDXF1ZXJ5QW5kRmV0Y2gBAAAAAAAAAAEWYm9o"
    shown = redact_secret(long_id)
    assert shown.startswith("FGlu") and str(len(long_id)) in shown
    assert long_id not in shown and long_id[4:20] not in shown


def test_sanitize_text_scrubs_secrets_controls_and_truncates() -> None:
    pit = "46ToAwMDaWR5BXV1aWQyKwZub2RlXzMAAAAAAAAAACoBYwADaWR4BXV1aWQxAgZub2RlXzEAAAAAAAAAAAEBYQADaWR5"
    raw = (
        f"bad pit [{pit}] password={PASSWORD} token {JWT} Authorization: Bearer abcDEF123456ghiJKL=\n"
        "\x1b[31mred\x1b[0m \u202eevil\u202c tail"
    )
    text = sanitize_text(raw, limit=1000, secrets=[pit, PASSWORD, None, ""])
    assert pit not in text and PASSWORD not in text and JWT not in text
    assert "abcDEF123456ghiJKL" not in text
    assert "\x1b" not in text and "\u202e" not in text and "\n" not in text
    assert "Bearer ***" in text
    assert len(sanitize_text("x" * 5000, limit=50)) == 50
    # scrubbing happens before truncation: a secret straddling the cut leaks no prefix
    cut = sanitize_text("a" * 40 + pit, limit=60, secrets=[pit])
    assert pit[4:30] not in cut


def test_sanitize_text_keeps_prose_after_auth_words() -> None:
    assert sanitize_text("basic authentication failed for user") == "basic authentication failed for user"


def test_safe_url_strips_credentials_query_and_fragment() -> None:
    assert safe_url(f"https://alice:{PASSWORD}@indexer.example:9200/es/?pit=abc#x") == "https://indexer.example:9200/es"
    assert safe_url("https://[2001:db8::1]:55000") == "https://[2001:db8::1]:55000"
    assert safe_url(None) == ""
    assert safe_url("https://h.example:bad") == "<invalid url>"


# ---- transport errors ------------------------------------------------------------------------------------------


def _chained_tls_error() -> httpx.ConnectError:
    inner = ssl.SSLCertVerificationError(
        1, "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: self-signed certificate in certificate chain"
    )
    try:
        try:
            raise inner
        except ssl.SSLError as exc:
            raise httpx.ConnectError(str(exc)) from exc
    except httpx.ConnectError as outer:
        return outer


def test_tls_verification_failure_recommends_ca_cert_not_disabling() -> None:
    err = transport_error(
        _chained_tls_error(), url="https://indexer.example:9200", op="info", hint=" (Wazuh: root-ca.pem)"
    )
    assert err.kind == "tls"
    text = str(err)
    assert "ca_cert" in text and "root-ca.pem" in text and "Do not disable verification" in text
    assert "verify_tls: false" not in text
    assert "ca_cert" in err.render("es") and "No desactive la verificación" in err.render("es")  # usted register


def test_tls_hostname_mismatch_and_wrong_protocol() -> None:
    mismatch = httpx.ConnectError(
        "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: Hostname mismatch, certificate is not valid "
        "for 'indexer.example'. (_ssl.c:1006)"
    )
    err = transport_error(mismatch, url="https://indexer.example:9200")
    assert err.kind == "tls" and "subjectAltName" in str(err)
    wrong = httpx.ConnectError("[SSL: WRONG_VERSION_NUMBER] wrong version number (_ssl.c:1006)")
    err = transport_error(wrong, url="https://indexer.example:9200")
    assert err.kind == "tls" and "https/http" in str(err)


def test_connect_timeout_and_protocol_errors() -> None:
    err = transport_error(httpx.ConnectError("[Errno 111] Connection refused"), url="https://10.0.0.5:9200")
    assert err.kind == "connection" and "Cannot connect" in str(err)
    err = transport_error(httpx.ReadTimeout("timed out"), url="https://10.0.0.5:9200", op="search", timeout=60)
    assert err.kind == "timeout" and "60" in str(err) and "search" in str(err)
    err = transport_error(httpx.RemoteProtocolError("peer closed"), url="https://10.0.0.5:9200", op="scroll")
    assert err.kind == "connection"


def test_transport_error_scrubs_secrets() -> None:
    err = transport_error(httpx.ConnectError(f"proxy said {PASSWORD}"), url="https://h.example", secrets=[PASSWORD])
    assert PASSWORD not in str(err)


# ---- small helpers -----------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("header", "expected"),
    [("3", 3.0), ("0.5", 0.5), ("-4", 0.0), ("100000", 120.0), ("nan", None), ("inf", None), ("Wed, 21 Oct", None)],
)
def test_retry_after(header: str, expected: float | None) -> None:
    assert retry_after(httpx.Response(429, headers={"Retry-After": header})) == expected
    assert retry_after(httpx.Response(429)) is None


def test_backoff_delay() -> None:
    assert [backoff_delay(i, cap=30) for i in range(7)] == [1, 2, 4, 8, 16, 30, 30]
    assert backoff_delay(10_000) == 60.0
    assert backoff_delay(-3) == 1.0


def test_loads_json_rejects_hostile_input() -> None:
    assert loads_json(b'{"a": [1, 2]}') == {"a": [1, 2]}
    for bad in (b"{", b"\xff\xfe", b"[" * 200_000, b"1" * 10_000, "{'a': 1}"):
        with pytest.raises(ValueError):
            loads_json(bad)


# ---- rate limiter ----------------------------------------------------------------------------------------------


def test_rate_limiter_sliding_window() -> None:
    clock = FakeClock()
    limiter = RateLimiter(3, clock=clock, sleep=clock.sleep)
    assert [limiter.acquire() for _ in range(3)] == [0.0, 0.0, 0.0]
    clock.now += 10
    waited = limiter.acquire()
    assert waited == pytest.approx(50.0)
    assert clock.sleeps == [pytest.approx(50.0)]
    clock.now += 61
    assert limiter.acquire() == 0.0


def test_rate_limiter_disabled_and_stuck_clock() -> None:
    clock = FakeClock()
    disabled = RateLimiter(0, clock=clock, sleep=clock.sleep)
    assert all(disabled.acquire() == 0.0 for _ in range(1000))
    assert clock.sleeps == []
    stuck = FakeClock(advance_on_sleep=False)
    limiter = RateLimiter(1, clock=stuck, sleep=stuck.sleep)
    limiter.acquire()
    limiter.acquire()  # must not loop forever when the clock does not move
    limiter.acquire()
    assert len(stuck.sleeps) == 2


def test_every_net_message_has_spanish() -> None:
    catalog = i18n.keys()  # the registered message keys (a function, not dict.keys)
    keys = [k for k in catalog if k.startswith("net.")]
    assert keys
    for key in keys:
        assert i18n.render(i18n.M(key), "es") != i18n.render(i18n.M(key), "en") or key.endswith(".host")


# ---- review regressions ----------------------------------------------------------------------------------------


def test_scrubbed_secret_leaves_no_prefix_or_length() -> None:
    """Regression: secrets longer than 12 chars were replaced by '<first 4 chars>...(N chars)', leaking part of
    the password (and its length) into error messages."""
    err = transport_error(httpx.ConnectError(f"proxy said {PASSWORD}"), url="https://h.example", secrets=[PASSWORD])
    text = str(err)
    assert PASSWORD[:4] not in text and str(len(PASSWORD)) not in text and "***" in text
    assert sanitize_text(f"pw={PASSWORD}", secrets=[PASSWORD]) == "pw=***"


def test_secret_is_scrubbed_in_escaped_spellings() -> None:
    tricky = 'p"a\\ss w/rd+\u00f1'
    for spelling in ('p\\"a\\\\ss w/rd+\\u00f1', 'p\\"a\\\\ss w/rd+\u00f1', "p%22a%5Css%20w%2Frd%2B%C3%B1"):
        cleaned = sanitize_text(f"echo [{spelling}]", secrets=[tricky])
        assert cleaned == "echo [***]", spelling


def test_connect_timeout_is_not_blamed_on_the_read_timeout() -> None:
    err = transport_error(httpx.ConnectTimeout("timed out"), url="https://10.0.0.5:9200", op="info", timeout=60)
    assert err.kind == "timeout"
    assert "Cannot connect" in str(err) and "15 s" in str(err) and "narrow the time range" not in str(err)
    assert "No se puede conectar" in err.render("es")


def test_is_plain_http() -> None:
    assert is_plain_http("http://10.0.0.5:9200") and is_plain_http(" HTTP://h.example")
    assert not is_plain_http("https://h.example")


def _bounded(handler: Any, limit: int, **kwargs: Any) -> httpx.Response:
    client = make_client(
        "https://indexer.example:9200", ca_cert=None, verify_tls=True, timeout=5, transport=httpx.MockTransport(handler)
    )
    request = client.build_request("GET", "/x")
    return send_bounded(client, request, max_bytes=limit, url="https://indexer.example:9200", op="test", **kwargs)


def test_send_bounded_returns_a_fully_read_decoded_response() -> None:
    import gzip

    body = b'{"ok": true}'

    def handler(request: httpx.Request) -> httpx.Response:
        headers = {"Content-Encoding": "gzip", "X-elastic-product": "Elasticsearch"}
        return httpx.Response(201, content=gzip.compress(body), headers=headers, extensions={"reason_phrase": b"Made"})

    resp = _bounded(handler, 1024)
    assert resp.status_code == 201 and resp.content == body and resp.json() == {"ok": True}
    assert resp.headers["x-elastic-product"] == "Elasticsearch" and "content-encoding" not in resp.headers
    assert resp.reason_phrase == "Made"


def test_send_bounded_uses_the_given_auth() -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers.get("authorization", ""))
        return httpx.Response(200, content=b"token")

    _bounded(handler, 1024, auth=httpx.BasicAuth("alice", PASSWORD))
    assert seen and seen[0].startswith("Basic ")


@pytest.mark.parametrize("shape", ["declared", "chunked", "gzip-bomb"])
def test_send_bounded_refuses_bodies_over_the_limit(shape: str) -> None:
    import gzip

    limit = 10_000
    big = b"0" * (limit * 50)
    reads: list[int] = []

    def chunks() -> Any:
        for i in range(0, len(big), 1000):
            reads.append(i)
            yield big[i : i + 1000]

    def handler(request: httpx.Request) -> httpx.Response:
        if shape == "declared":
            return httpx.Response(200, content=big)
        if shape == "chunked":
            return httpx.Response(200, content=chunks())
        return httpx.Response(200, content=gzip.compress(big), headers={"Content-Encoding": "gzip"})

    with pytest.raises(RemoteError) as info:
        _bounded(handler, limit)
    assert info.value.kind == "protocol" and "test" in str(info.value)
    if shape == "chunked":
        assert len(reads) <= limit // 1000 + 2  # stopped while streaming, not after buffering everything
