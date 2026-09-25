"""Tests for hushwatch.ingest.wazuh_api (httpx.MockTransport only, fake clock, no network)."""

from __future__ import annotations

import base64
import json
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

import httpx
import pytest

from hushwatch import i18n
from hushwatch.config import ApiConfig
from hushwatch.ingest.wazuh_api import (
    AGENT_FIELDS,
    DEFAULT_TTL,
    LEGACY_AGENT_FIELDS,
    WazuhAPI,
    parse_agent,
    platform_family,
    token_ttl,
)
from hushwatch.net import RemoteError

UTC = timezone.utc
USER = "hushwatch_ro"
PASSWORD = "Api-S3cret-not-real!"
AUTH = "/security/user/authenticate"

Handler = Callable[[httpx.Request], httpx.Response]


def b64url(data: dict[str, Any]) -> str:
    return base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip("=")


def make_jwt(*, exp: float | None, nbf: float | None, serial: int = 0) -> str:
    claims: dict[str, Any] = {"iss": "wazuh", "aud": "Wazuh API REST", "sub": USER, "run_as": False, "rbac_roles": [1]}
    if exp is not None:
        claims["exp"] = exp
    if nbf is not None:
        claims["nbf"] = nbf
    return f"{b64url({'alg': 'ES512', 'typ': 'JWT'})}.{b64url(claims)}.c2lnbmF0dXJl{serial:04d}"


class FakeClock:
    def __init__(self, now: float = 1_000_000.0) -> None:
        self.now = now
        self.sleeps: list[float] = []

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


def ok(data: dict[str, Any], *, error: int = 0) -> Handler:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"data": data, "message": "ok", "error": error})

    return handler


def status(code: int, body: Any = None, headers: dict[str, str] | None = None) -> Handler:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            code, json=body if body is not None else {"title": "Error", "detail": "x"}, headers=headers
        )

    return handler


class FakeWazuh:
    """Minimal Wazuh API: token issuance/validation plus canned responses per (method, path)."""

    def __init__(self, clock: FakeClock, *, ttl: int = 900, token_skew: float = 0.0) -> None:
        self.clock = clock
        self.ttl = ttl
        self.token_skew = token_skew  # manager clock minus our clock
        self.valid: set[str] = set()
        self.issued: list[str] = []
        self.calls: list[httpx.Request] = []
        self.routes: dict[tuple[str, str], list[Handler]] = {}
        self.login_response: Handler | None = None

    def on(self, method: str, path: str, *handlers: Handler) -> FakeWazuh:
        self.routes.setdefault((method, path), []).extend(handlers)
        return self

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(request)
        if request.url.path == AUTH:
            assert request.method == "POST", "only POST may touch the authenticate endpoint"
            assert request.url.params.get("raw") == "true"
            if self.login_response is not None:
                return self.login_response(request)
            expected = "Basic " + base64.b64encode(f"{USER}:{PASSWORD}".encode()).decode()
            if request.headers.get("authorization") != expected:
                return httpx.Response(
                    401, json={"title": "Unauthorized", "detail": "Invalid credentials", "error": 6000}
                )
            issued_at = self.clock() + self.token_skew
            token = make_jwt(exp=issued_at + self.ttl, nbf=issued_at, serial=len(self.issued))
            self.issued.append(token)
            self.valid.add(token)
            return httpx.Response(200, text=token, headers={"Content-Type": "text/plain"})
        auth = request.headers.get("authorization", "")
        if not auth.startswith("Bearer ") or auth[7:] not in self.valid:
            return httpx.Response(401, json={"title": "Unauthorized", "detail": "No authorization token provided"})
        queue = self.routes.get((request.method, request.url.path))
        if not queue:
            raise AssertionError(f"unexpected request {request.method} {request.url}")
        handler = queue.pop(0) if len(queue) > 1 else queue[0]
        return handler(request)

    def calls_to(self, method: str, path: str) -> list[httpx.Request]:
        return [c for c in self.calls if c.method == method and c.url.path == path]

    def logins(self) -> int:
        return len(self.calls_to("POST", AUTH))


def api(server: FakeWazuh, clock: FakeClock, **cfg: Any) -> WazuhAPI:
    config = ApiConfig(url="https://wazuh-manager.example:55000", username=USER, password=PASSWORD, **cfg)
    return WazuhAPI(config, transport=httpx.MockTransport(server), clock=clock, sleep=clock.sleep)


INFO = {"title": "Wazuh API REST", "api_version": "4.14.8", "revision": 41408, "hostname": "wazuh-manager.example"}


# ---- authentication ------------------------------------------------------------------------------------------


def test_login_with_basic_auth_then_bearer_and_never_delete() -> None:
    clock = FakeClock()
    server = FakeWazuh(clock).on("GET", "/", ok(INFO))
    client = api(server, clock)
    assert client.info()["api_version"] == "4.14.8"
    assert client.api_version() == (4, 14, 8)
    client.info()  # cached
    assert server.logins() == 1
    get = server.calls_to("GET", "/")
    assert len(get) == 1 and get[0].headers["authorization"] == f"Bearer {server.issued[0]}"
    client.close()
    assert not [c for c in server.calls if c.method == "DELETE"]


def test_jwt_refreshed_about_60s_before_expiry() -> None:
    clock = FakeClock()
    server = FakeWazuh(clock, ttl=900).on("GET", "/manager/info", ok({"affected_items": [{"version": "v4.14.8"}]}))
    client = api(server, clock)
    client.manager_info()
    start = clock.now
    clock.now = start + 830  # 70 s before expiry: keep the token
    client.manager_info()
    assert server.logins() == 1
    clock.now = start + 845  # 55 s before expiry: renew first, never send a token about to expire
    client.manager_info()
    assert server.logins() == 2
    last = server.calls_to("GET", "/manager/info")[-1]
    assert last.headers["authorization"] == f"Bearer {server.issued[1]}"
    assert client.logins == 2


def test_clock_skew_does_not_cause_a_login_storm() -> None:
    clock = FakeClock()
    server = FakeWazuh(clock, token_skew=-7200).on("GET", "/manager/info", ok({"affected_items": [{}]}))
    client = api(server, clock)
    for _ in range(5):
        client.manager_info()
    assert server.logins() == 1  # exp is 2 h "in the past" by our clock, but exp - nbf = 900 s


def test_token_ttl_rules() -> None:
    now = 5000.0
    assert token_ttl(make_jwt(exp=1900, nbf=1000), now) == 900
    assert token_ttl(make_jwt(exp=now + 600, nbf=None), now) == 600
    assert token_ttl(make_jwt(exp=None, nbf=1000), now) == DEFAULT_TTL
    assert token_ttl(make_jwt(exp=10, nbf=None), now) == DEFAULT_TTL
    assert token_ttl(make_jwt(exp=1001, nbf=1000), now) == 5.0  # clamped
    assert token_ttl("not-a-jwt", now) == DEFAULT_TTL
    assert token_ttl("a.!!!.c", now) == DEFAULT_TTL
    assert token_ttl(f"a.{b64url({'exp': 'soon'})}.c", now) == DEFAULT_TTL
    assert token_ttl("a." + base64.urlsafe_b64encode(b"[1,2]").decode() + ".c", now) == DEFAULT_TTL


def test_short_ttl_uses_proportional_margin() -> None:
    clock = FakeClock()
    server = FakeWazuh(clock, ttl=30).on("GET", "/manager/info", ok({"affected_items": [{}]}))
    client = api(server, clock)
    client.manager_info()
    clock.now += 20  # margin is min(60, 30/4) = 7.5 s -> still valid
    client.manager_info()
    assert server.logins() == 1
    clock.now += 3
    client.manager_info()
    assert server.logins() == 2


def test_401_triggers_one_reauth_and_retry() -> None:
    clock = FakeClock()
    server = FakeWazuh(clock).on("GET", "/manager/info", ok({"affected_items": [{"version": "v4.14.8"}]}))
    client = api(server, clock)
    client.manager_info()
    server.valid.clear()  # e.g. security config changed: every token revoked
    assert client.manager_info() == {"version": "v4.14.8"}
    assert server.logins() == 2


def test_persistent_401_raises_auth_error_without_secrets() -> None:
    clock = FakeClock()
    server = FakeWazuh(clock).on("GET", "/agents", status(401, {"title": "Unauthorized", "detail": "Invalid token"}))
    client = api(server, clock)
    with pytest.raises(RemoteError) as info:
        client.agents()
    err = info.value
    assert err.kind == "auth" and err.status == 401
    assert server.logins() == 2  # exactly one re-login, no loop
    for text in (str(err), err.render("es")):
        assert PASSWORD not in text
        assert all(token not in text for token in server.issued)
    assert USER in str(err)


def test_login_failure_message_has_user_but_no_password() -> None:
    clock = FakeClock()
    server = FakeWazuh(clock)
    config = ApiConfig(url="https://wazuh-manager.example:55000", username=USER, password="wrong-" + PASSWORD)
    client = WazuhAPI(config, transport=httpx.MockTransport(server), clock=clock, sleep=clock.sleep)
    with pytest.raises(RemoteError) as info:
        client.info()
    err = info.value
    assert err.kind == "auth" and err.status == 401
    assert "Invalid credentials" in str(err) and USER in str(err)
    assert PASSWORD not in str(err) and PASSWORD not in err.render("es")
    assert PASSWORD not in repr(client)
    assert server.logins() == 1


def test_invalid_token_body_is_rejected_without_echo() -> None:
    clock = FakeClock()
    server = FakeWazuh(clock)
    server.login_response = lambda request: httpx.Response(200, text="<html>captive portal secret-abc</html>")
    with pytest.raises(RemoteError) as info:
        api(server, clock).info()
    assert info.value.kind == "protocol" and "secret-abc" not in str(info.value)


def test_json_token_response_is_accepted() -> None:
    clock = FakeClock()
    server = FakeWazuh(clock).on("GET", "/", ok(INFO))
    token = make_jwt(exp=clock.now + 900, nbf=clock.now)
    server.valid.add(token)
    server.login_response = lambda request: httpx.Response(200, json={"data": {"token": token}, "error": 0})
    assert api(server, clock).info()["api_version"] == "4.14.8"


def test_login_rate_limited_or_server_error() -> None:
    clock = FakeClock()
    server = FakeWazuh(clock)
    server.login_response = status(429, {"title": "Too Many Requests"})
    with pytest.raises(RemoteError) as info:
        api(server, clock).info()
    assert info.value.kind == "rate_limited"
    server.login_response = status(500, {"title": "Internal Error", "detail": "db locked", "error": 1000})
    with pytest.raises(RemoteError) as info:
        api(server, clock).info()
    assert info.value.kind == "http" and "db locked" in str(info.value)


# ---- rate limiting / backoff -----------------------------------------------------------------------------------


def test_429_backoff_then_success() -> None:
    clock = FakeClock()
    limited = {"title": "Too Many Requests", "detail": "Maximum number of requests per minute reached", "error": 6001}
    server = FakeWazuh(clock).on(
        "GET",
        "/manager/info",
        status(429, limited),
        status(429, limited),
        status(429, limited, {"Retry-After": "7"}),
        ok({"affected_items": [{"version": "v4.14.8"}]}),
    )
    client = api(server, clock)
    assert client.manager_info() == {"version": "v4.14.8"}
    assert clock.sleeps == [1.0, 2.0, 7.0]


def test_429_gives_up_after_bounded_attempts() -> None:
    clock = FakeClock()
    server = FakeWazuh(clock).on("GET", "/agents", status(429, {"title": "Too Many Requests"}))
    with pytest.raises(RemoteError) as info:
        api(server, clock).agents()
    assert info.value.kind == "rate_limited"
    assert len(server.calls_to("GET", "/agents")) == 7
    assert clock.sleeps == [1.0, 2.0, 4.0, 8.0, 16.0, 32.0]
    assert "max_requests_per_minute" in str(info.value)


def test_client_side_rate_limit() -> None:
    clock = FakeClock()
    server = FakeWazuh(clock).on("GET", "/manager/info", ok({"affected_items": [{}]}))
    client = api(server, clock, max_requests_per_minute=2)
    for _ in range(3):
        client.manager_info()
    assert clock.sleeps == [pytest.approx(60.0)]


def test_transient_5xx_retried_twice() -> None:
    clock = FakeClock()
    server = FakeWazuh(clock).on(
        "GET", "/manager/info", status(503), status(502), ok({"affected_items": [{"type": "server"}]})
    )
    assert api(server, clock).manager_info() == {"type": "server"}
    assert clock.sleeps == [2.0, 4.0]


# ---- agents ----------------------------------------------------------------------------------------------------

MANAGER = {
    "id": "000",
    "name": "wazuh-manager.example",
    "ip": "127.0.0.1",
    "status": "active",
    "status_code": 0,
    "lastKeepAlive": "9999-12-31T23:59:59Z",
    "dateAdd": "2026-01-10T08:00:00Z",
    "version": "Wazuh v4.14.8",
    "os": {"name": "Ubuntu", "platform": "ubuntu"},
    "node_name": "node01",
}
NEVER = {"id": "002", "name": "laptop-07.corp.example", "status": "never_connected", "dateAdd": "2026-09-01T09:00:00Z"}


def _agent(n: int) -> dict[str, Any]:
    windows = n % 2 == 0
    return {
        "id": f"{n:03d}",
        "name": f"{'ws' if windows else 'srv-web'}-{n:02d}.corp.example",
        "ip": f"10.0.{n // 250}.{n % 250 + 1}",
        "status": "active" if n % 5 else "disconnected",
        "status_code": 0 if n % 5 else 1,
        "lastKeepAlive": "2026-09-25T09:59:10Z",
        "dateAdd": "2026-02-01T10:00:00Z",
        "version": "Wazuh v4.14.8",
        "os": {"name": "Microsoft Windows 11 Pro", "platform": "windows"}
        if windows
        else {"name": "Red Hat Enterprise Linux", "platform": "rhel"},
        "group": ["default", "windows" if windows else "linux"],
        "node_name": "node01",
    }


def _agents_page(request: httpx.Request, everyone: list[dict[str, Any]]) -> httpx.Response:
    offset, limit = int(request.url.params["offset"]), int(request.url.params["limit"])
    data = {
        "affected_items": everyone[offset : offset + limit],
        "total_affected_items": len(everyone),
        "total_failed_items": 0,
        "failed_items": [],
    }
    return httpx.Response(200, json={"data": data, "message": "ok", "error": 0})


def test_agents_paginates_and_handles_manager_and_never_connected() -> None:
    everyone = [MANAGER, _agent(1), NEVER, *[_agent(n) for n in range(3, 1203)]]
    clock = FakeClock()
    server = FakeWazuh(clock).on("GET", "/agents", lambda r: _agents_page(r, everyone))
    client = api(server, clock)
    agents = client.agents()
    calls = server.calls_to("GET", "/agents")
    assert [c.url.params["offset"] for c in calls] == ["0", "500", "1000"]
    assert {c.url.params["limit"] for c in calls} == {"500"}
    assert calls[0].url.params["select"] == ",".join(AGENT_FIELDS)
    assert calls[0].url.params["select"] == (
        "id,name,ip,status,status_code,lastKeepAlive,dateAdd,version,os.name,os.platform,group,node_name"
    )
    assert calls[0].url.params["sort"] == "+id"
    assert len(agents) == 1203 and client.partial_failures == []
    by_id = {a.id: a for a in agents}
    manager = by_id["000"]
    assert manager.is_manager and manager.last_keepalive is None and manager.groups == ()
    assert manager.platform == "linux" and manager.extra["os_platform"] == "ubuntu"
    never = by_id["002"]
    assert never.status == "never_connected" and never.last_keepalive is None and never.platform is None
    assert never.date_add == datetime(2026, 9, 1, 9, 0, tzinfo=UTC)
    first = by_id["001"]
    assert first.status == "active" and first.platform == "linux" and first.groups == ("default", "linux")
    assert first.last_keepalive == datetime(2026, 9, 25, 9, 59, 10, tzinfo=UTC)
    assert first.extra["ip"] == "10.0.0.2" and first.node == "node01" and first.version == "Wazuh v4.14.8"
    assert by_id["004"].platform == "windows"
    assert by_id["005"].status == "disconnected"
    assert [a.id for a in client.agents(include_manager=False)][:2] == ["001", "002"]


def test_agents_failed_items_are_partial_failures() -> None:
    clock = FakeClock()
    data = {
        "affected_items": [_agent(1)],
        "total_affected_items": 1,
        "failed_items": [
            {"error": {"code": 1701, "message": "Agent does not exist", "remediation": "-"}, "id": ["099"]}
        ],
        "total_failed_items": 1,
    }
    server = FakeWazuh(clock).on("GET", "/agents", ok(data, error=2))
    client = api(server, clock)
    assert len(client.agents()) == 1
    assert len(client.partial_failures) == 1
    assert "[1701] Agent does not exist" in client.partial_failures[0]
    assert "no pudo procesar" in i18n.render(client.failure_messages[0], "es")


def test_agents_short_listing_is_reported_incomplete() -> None:
    clock = FakeClock()
    server = FakeWazuh(clock).on(
        "GET",
        "/agents",
        ok({"affected_items": [_agent(1)], "total_affected_items": 3}),
        ok({"affected_items": [], "total_affected_items": 3}),
    )
    client = api(server, clock)
    assert len(client.agents()) == 1
    assert client.failure_messages[0].key == "wazuh_api.partial.agents_incomplete"


def test_agents_hostile_items_are_counted_not_fatal() -> None:
    clock = FakeClock()
    items = [
        "junk",
        {"name": "no-id.example"},
        {"id": "../../etc", "name": "x"},
        {"id": True},
        {
            "id": 7,
            "name": ["not", "a", "string"],
            "status": {"x": 1},
            "os": "linux",
            "group": "default,web",
            "lastKeepAlive": 12,
        },
        _agent(1),
        _agent(1),
    ]
    server = FakeWazuh(clock).on("GET", "/agents", ok({"affected_items": items, "total_affected_items": len(items)}))
    client = api(server, clock)
    agents = client.agents()
    assert client.malformed == 4
    assert [a.id for a in agents] == ["001", "007"]  # duplicates collapsed, sorted
    odd = agents[1]
    assert odd.name == "" and odd.status == "unknown" and odd.groups == ("default", "web") and odd.platform is None


def test_agents_error_payload_surfaced() -> None:
    clock = FakeClock()
    body = {
        "title": "Bad Request",
        "detail": "Invalid field found {'bogus'}",
        "remediation": "Check the docs",
        "error": 1724,
    }
    server = FakeWazuh(clock).on("GET", "/agents", status(400, body))
    with pytest.raises(RemoteError) as info:
        api(server, clock).agents()
    assert info.value.kind == "http" and "1724" in str(info.value) and "Invalid field" in str(info.value)


def test_agents_forbidden_names_the_permission_problem() -> None:
    clock = FakeClock()
    server = FakeWazuh(clock).on(
        "GET", "/agents", status(403, {"title": "Permission Denied", "detail": "agent:read", "error": 4000})
    )
    with pytest.raises(RemoteError) as info:
        api(server, clock).agents()
    assert info.value.kind == "forbidden" and "RBAC" in str(info.value) and USER in str(info.value)


def test_parse_agent_units() -> None:
    assert parse_agent(None) is None
    assert parse_agent({"id": 5}).id == "005"  # type: ignore[union-attr]
    assert parse_agent({"id": "1234"}).id == "1234"  # type: ignore[union-attr]
    assert parse_agent({"id": "\uff11\uff12"}) is None  # non-ASCII (fullwidth) digits
    agent = parse_agent({"id": "003", "status": "Never connected", "lastKeepAlive": "1970-01-01T00:00:00Z"})
    assert agent is not None and agent.status == "never_connected" and agent.last_keepalive is None
    weird = parse_agent({"id": "004", "status": "exploded"})
    assert weird is not None and weird.status == "unknown" and weird.extra["status_raw"] == "exploded"


@pytest.mark.parametrize(
    ("platform", "name", "expected"),
    [
        ("windows", "Microsoft Windows Server 2022", "windows"),
        (None, "Microsoft Windows 10 Pro", "windows"),
        ("darwin", "macOS", "darwin"),
        ("ubuntu", "Ubuntu", "linux"),
        ("amzn", "Amazon Linux", "linux"),
        ("rocky", None, "linux"),
        ("freebsd", "FreeBSD", "bsd"),
        ("sunos", "SunOS", "solaris"),
        ("aix", "AIX", "aix"),
        ("hp-ux", "HP-UX", "hpux"),
        ("zos", None, "zos"),
        (None, None, None),
    ],
)
def test_platform_family(platform: str | None, name: str | None, expected: str | None) -> None:
    assert platform_family(platform, name) == expected


# ---- rules / stats / info --------------------------------------------------------------------------------------


def _rules_page(request: httpx.Request) -> httpx.Response:
    wanted = request.url.params.get("rule_ids")
    rules = [{"id": n, "level": 5, "description": f"rule {n}", "groups": ["syslog"]} for n in range(1, 1101)]
    if wanted:
        rules = [r for r in rules if str(r["id"]) in wanted.split(",")]
    offset, limit = int(request.url.params["offset"]), int(request.url.params["limit"])
    data = {"affected_items": rules[offset : offset + limit], "total_affected_items": len(rules)}
    return httpx.Response(200, json={"data": data, "error": 0})


def test_rules_paginated() -> None:
    clock = FakeClock()
    server = FakeWazuh(clock).on("GET", "/", ok(INFO)).on("GET", "/rules", _rules_page)
    rules = api(server, clock).rules()
    assert len(rules) == 1100
    assert [c.url.params["offset"] for c in server.calls_to("GET", "/rules")] == ["0", "500", "1000"]


def test_rules_by_id_filters_hostile_ids_and_chunks() -> None:
    clock = FakeClock()
    server = FakeWazuh(clock).on("GET", "/", ok(INFO)).on("GET", "/rules", _rules_page)
    ids = [str(n) for n in range(1, 451)] + ["5710 OR 1=1", "../x", "", "-5", True, 7]
    rules = api(server, clock).rules(ids)  # type: ignore[arg-type]
    assert len(rules) == 450
    calls = server.calls_to("GET", "/rules")
    assert len(calls) == 3  # 200 + 200 + 50 ids per request
    for call in calls:
        assert all(part.isdigit() for part in call.url.params["rule_ids"].split(","))
    assert api(server, clock).rules(["abc"]) == []


def test_rules_tolerates_404_and_skips_5x() -> None:
    clock = FakeClock()
    server = FakeWazuh(clock).on("GET", "/", ok(INFO)).on("GET", "/rules", status(404, {"title": "Not Found"}))
    client = api(server, clock)
    assert client.rules() == []
    assert client.notes[0].key == "wazuh_api.note.unavailable"
    assert client.partial_failures == []
    v5 = FakeWazuh(clock).on("GET", "/", ok({**INFO, "api_version": "5.0.0"}))
    client5 = api(v5, clock)
    assert client5.rules() == []
    assert not v5.calls_to("GET", "/rules")
    assert "5.0.0" in i18n.render(client5.notes[0])


def test_rules_forbidden_is_a_warning() -> None:
    clock = FakeClock()
    server = (
        FakeWazuh(clock)
        .on("GET", "/", ok(INFO))
        .on("GET", "/rules", status(403, {"title": "Permission Denied", "detail": "rules:read"}))
    )
    client = api(server, clock)
    assert client.rules() == []
    assert client.warnings[0].key == "wazuh_api.warn.forbidden"


def test_rules_missing_ids_are_notes() -> None:
    clock = FakeClock()
    data = {
        "affected_items": [],
        "total_affected_items": 0,
        "failed_items": [{"error": {"code": 1208, "message": "The requested rule does not exist"}, "id": [999999]}],
        "total_failed_items": 1,
    }
    server = FakeWazuh(clock).on("GET", "/", ok(INFO)).on("GET", "/rules", ok(data, error=1))
    client = api(server, clock)
    assert client.rules(["999999"]) == []
    assert client.partial_failures == [] and "1208" in i18n.render(client.notes[0])


def test_daemon_stats() -> None:
    clock = FakeClock()
    items = [
        {"name": "wazuh-analysisd", "uptime": "2026-09-25T00:00:00+00:00", "metrics": {"events": {"received": 10}}},
        {"name": "wazuh-remoted", "metrics": {"queues": {"received": {"size": 131072, "usage": 0.1}}}},
    ]
    server = FakeWazuh(clock).on(
        "GET", "/manager/daemons/stats", ok({"affected_items": items, "total_affected_items": 2})
    )
    stats = api(server, clock).daemon_stats()
    assert stats is not None and set(stats) == {"wazuh-analysisd", "wazuh-remoted"}


@pytest.mark.parametrize("code", [400, 404])
def test_daemon_stats_unavailable_returns_none(code: int) -> None:
    clock = FakeClock()
    server = FakeWazuh(clock).on("GET", "/manager/daemons/stats", status(code, {"title": "Not Found"}))
    client = api(server, clock)
    assert client.daemon_stats() is None
    assert client.notes and client.partial_failures == []


def test_logcollector_stats() -> None:
    clock = FakeClock()
    body = {
        "global": {
            "start": "2026-09-25T00:00:00Z",
            "files": [{"location": "Security", "events": 42, "targets": [{"name": "agent", "drops": 0}]}],
        }
    }
    server = FakeWazuh(clock).on(
        "GET", "/agents/001/stats/logcollector", ok({"affected_items": [body], "total_affected_items": 1})
    )
    client = api(server, clock)
    assert client.logcollector_stats(1) == body
    assert client.logcollector_stats("001") == body


def test_logcollector_stats_inactive_agent_is_none_with_note() -> None:
    clock = FakeClock()
    data = {
        "affected_items": [],
        "total_affected_items": 0,
        "failed_items": [
            {"error": {"code": 1707, "message": "Cannot send request, agent is not active"}, "id": ["003"]}
        ],
        "total_failed_items": 1,
    }
    server = FakeWazuh(clock).on("GET", "/agents/003/stats/logcollector", ok(data, error=1))
    client = api(server, clock)
    assert client.logcollector_stats("003") is None
    assert "1707" in i18n.render(client.notes[0])


@pytest.mark.parametrize("bad", ["../../security/user/authenticate", "1;2", "", "abc", -1, True, None, "0" * 20])
def test_logcollector_stats_rejects_bad_ids_without_request(bad: Any) -> None:
    clock = FakeClock()
    server = FakeWazuh(clock)
    with pytest.raises(ValueError):
        api(server, clock).logcollector_stats(bad)
    assert server.calls == []


def test_manager_info() -> None:
    clock = FakeClock()
    item = {"version": "v4.14.8", "type": "server", "tz_offset": "+0000", "tz_name": "UTC"}
    server = FakeWazuh(clock).on("GET", "/manager/info", ok({"affected_items": [item], "total_affected_items": 1}))
    assert api(server, clock).manager_info() == item
    missing = FakeWazuh(clock).on("GET", "/manager/info", status(404))
    assert api(missing, clock).manager_info() is None


# ---- errors / hostile servers ----------------------------------------------------------------------------------


def test_error_details_are_sanitized_and_token_scrubbed() -> None:
    clock = FakeClock()
    server = FakeWazuh(clock)

    def echo_token(request: httpx.Request) -> httpx.Response:
        token = request.headers["authorization"][7:]
        detail = f"bad token {token} \x1b[31m\u202e {PASSWORD} " + "x" * 3000
        return httpx.Response(500, json={"title": "Internal Error", "detail": detail, "error": 1000})

    server.on("GET", "/agents", echo_token)
    with pytest.raises(RemoteError) as info:
        api(server, clock).agents()
    text = str(info.value)
    assert server.issued[0] not in text and PASSWORD not in text
    assert "\x1b" not in text and "\u202e" not in text and len(text) < 600


def test_protocol_errors() -> None:
    clock = FakeClock()
    for handler in (
        lambda r: httpx.Response(200, content=b"<html>"),
        lambda r: httpx.Response(200, json=[1, 2]),
        lambda r: httpx.Response(200, json={"error": 0}),
        lambda r: httpx.Response(200, json={"data": {"affected_items": "x"}, "error": 0}),
    ):
        server = FakeWazuh(clock).on("GET", "/agents", handler)
        with pytest.raises(RemoteError) as info:
            api(server, clock).agents()
        assert info.value.kind == "protocol"


def test_tls_failure_suggests_ca_cert() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: self-signed certificate")

    config = ApiConfig(url="https://wazuh-manager.example:55000", username=USER, password=PASSWORD)
    with pytest.raises(RemoteError) as info:
        WazuhAPI(config, transport=httpx.MockTransport(handler)).info()
    assert info.value.kind == "tls" and "ca_cert" in str(info.value) and "server.crt" in str(info.value)


def test_config_errors_and_tls_warning() -> None:
    with pytest.raises(RemoteError) as info:
        WazuhAPI(ApiConfig(url="https://wazuh-manager.example:55000"))
    assert info.value.kind == "config"
    with pytest.raises(RemoteError):
        WazuhAPI(ApiConfig(url="", username=USER, password=PASSWORD))
    client = WazuhAPI(
        ApiConfig(url="https://wazuh-manager.example:55000", username=USER, password=PASSWORD, verify_tls=False),
        transport=httpx.MockTransport(FakeWazuh(FakeClock())),
    )
    assert [w.key for w in client.warnings] == ["net.warn.tls_disabled"]


def test_context_manager_forgets_token() -> None:
    clock = FakeClock()
    server = FakeWazuh(clock).on("GET", "/", ok(INFO))
    with api(server, clock) as client:
        client.info()
    assert client._token is None
    assert not [c for c in server.calls if c.method == "DELETE"]


def test_every_wazuh_api_message_has_spanish() -> None:
    catalog = i18n.keys()  # the registered message keys (a function, not dict.keys)
    keys = [k for k in catalog if k.startswith("wazuh_api.")]
    assert len(keys) > 15
    for key in keys:
        assert i18n.render(i18n.M(key), "es") != i18n.render(i18n.M(key), "en")


def test_pagination_without_total_continues_while_pages_are_full() -> None:
    clock = FakeClock()
    first = [_agent(n) for n in range(1, 501)]
    second = [_agent(n) for n in range(501, 511)]
    server = FakeWazuh(clock).on("GET", "/agents", ok({"affected_items": first}), ok({"affected_items": second}))
    client = api(server, clock)
    assert len(client.agents()) == 510
    assert [c.url.params["offset"] for c in server.calls_to("GET", "/agents")] == ["0", "500"]


def test_missing_affected_items_is_an_error_not_zero_agents() -> None:
    clock = FakeClock()
    server = FakeWazuh(clock).on("GET", "/agents", ok({"total_affected_items": 12}))
    with pytest.raises(RemoteError) as info:
        api(server, clock).agents()
    assert info.value.kind == "protocol"


def test_unparseable_agents_are_a_partial_failure() -> None:
    clock = FakeClock()
    server = FakeWazuh(clock).on(
        "GET", "/agents", ok({"affected_items": [{"name": "x"}, _agent(1)], "total_affected_items": 2})
    )
    client = api(server, clock)
    assert len(client.agents()) == 1
    assert [m.key for m in client.failure_messages] == ["wazuh_api.partial.agents_malformed"]


def test_apply_to_folds_failures_and_warnings() -> None:
    from hushwatch.models import DataBasis

    clock = FakeClock()
    data = {
        "affected_items": [_agent(1)],
        "total_affected_items": 1,
        "failed_items": [{"error": {"code": 1701, "message": "Agent does not exist"}, "id": ["099"]}],
        "total_failed_items": 1,
    }
    server = FakeWazuh(clock).on("GET", "/agents", ok(data, error=2))
    client = api(server, clock, verify_tls=False)
    client.agents()
    basis = DataBasis()
    client.apply_to(basis)
    client.apply_to(basis)
    assert len(basis.partial_failures) == 1 and len(basis.warnings) == 1


# ---- review regressions ----------------------------------------------------------------------------------------


class ExpiringWazuh(FakeWazuh):
    """Like FakeWazuh, but tokens past their ``exp`` (manager clock) are rejected like the real API does."""

    expired_rejections = 0

    def __call__(self, request: httpx.Request) -> httpx.Response:
        auth = request.headers.get("authorization", "")
        if request.url.path != AUTH and auth.startswith("Bearer "):
            segment = auth[7:].split(".")[1]
            claims = json.loads(base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4)))
            if claims["exp"] <= self.clock() + self.token_skew:
                self.calls.append(request)
                self.expired_rejections += 1
                return httpx.Response(401, json={"title": "Unauthorized", "detail": "Token expired"})
        return super().__call__(request)


def test_rate_limit_wait_never_sends_an_expired_token() -> None:
    """Regression: the token was checked BEFORE a limiter wait of up to 60 s, so a short-lived token expired
    during the wait, the retry waited again and the second 401 aborted the call."""
    clock = FakeClock()
    server = ExpiringWazuh(clock, ttl=30)
    server.on("GET", "/manager/info", ok({"affected_items": [{"type": "server"}]}))
    client = api(server, clock, max_requests_per_minute=1)
    for _ in range(3):
        assert client.manager_info() == {"type": "server"}
    assert server.expired_rejections == 0  # every request carried a token that was valid when sent
    assert server.logins() == 3  # one fresh login after each 60 s limiter wait (TTL 30 s)
    assert clock.sleeps == [pytest.approx(60.0), pytest.approx(60.0)]


def _old_manager_agents(accepted: set[str] | None) -> Handler:
    """GET /agents of a manager that rejects unknown select fields with error 1724 (Wazuh < 4.7)."""

    def handler(request: httpx.Request) -> httpx.Response:
        select = request.url.params.get("select")
        if select is not None and (accepted is None or not set(select.split(",")) <= accepted):
            body = {"title": "Bad Request", "detail": "Not a valid select field", "error": 1724}
            return httpx.Response(400, json=body)
        agent = {k: v for k, v in _agent(1).items() if k != "status_code"}
        data = {"affected_items": [MANAGER, agent], "total_affected_items": 2}
        return httpx.Response(200, json={"data": data, "error": 0})

    return handler


def test_agents_on_wazuh_before_4_7_retries_without_status_code() -> None:
    """Regression: select=...status_code... made GET /agents fail (HTTP 400, error 1724) on Wazuh 4.0-4.6."""
    clock = FakeClock()
    server = FakeWazuh(clock).on("GET", "/agents", _old_manager_agents(set(LEGACY_AGENT_FIELDS)))
    client = api(server, clock)
    agents = client.agents()
    assert [a.id for a in agents] == ["000", "001"] and client.partial_failures == []
    selects = [c.url.params.get("select") for c in server.calls_to("GET", "/agents")]
    assert selects == [",".join(AGENT_FIELDS), ",".join(LEGACY_AGENT_FIELDS)]
    assert "status_code" not in LEGACY_AGENT_FIELDS
    assert [n.key for n in client.notes] == ["wazuh_api.note.select_fallback"]


def test_agents_select_fallback_ends_with_default_fields() -> None:
    clock = FakeClock()
    server = FakeWazuh(clock).on("GET", "/agents", _old_manager_agents(None))
    agents = api(server, clock).agents()
    assert len(agents) == 2
    assert [c.url.params.get("select") for c in server.calls_to("GET", "/agents")][-1] is None


def test_other_400_errors_are_not_retried_as_select_problems() -> None:
    clock = FakeClock()
    body = {"title": "Bad Request", "detail": "Invalid offset", "error": 1400}
    server = FakeWazuh(clock).on("GET", "/agents", status(400, body))
    with pytest.raises(RemoteError):
        api(server, clock).agents()
    assert len(server.calls_to("GET", "/agents")) == 1


@pytest.mark.parametrize("flag", [1, 2])
def test_response_flagged_failed_without_items_is_not_a_complete_result(flag: int) -> None:
    """Regression: {"error": 1, "data": {"affected_items": []}} was read as "zero agents"."""
    clock = FakeClock()
    server = FakeWazuh(clock).on("GET", "/agents", ok({"affected_items": [], "total_affected_items": 0}, error=flag))
    client = api(server, clock)
    assert client.agents() == []
    assert [m.key for m in client.failure_messages] == ["wazuh_api.partial.flagged"]
    assert "marc\u00f3 la respuesta" in i18n.render(client.failure_messages[0], "es")


def test_server_ignoring_offset_with_total_is_incomplete_not_complete() -> None:
    """Regression: offset counted items, so a server repeating page 1 looked like a complete inventory."""
    clock = FakeClock()
    first = [_agent(n) for n in range(1, 501)]
    server = FakeWazuh(clock).on("GET", "/agents", ok({"affected_items": first, "total_affected_items": 1200}))
    client = api(server, clock)
    assert len(client.agents()) == 500
    assert len(server.calls_to("GET", "/agents")) == 2  # stops at the first page that adds nothing
    assert [m.key for m in client.failure_messages] == ["wazuh_api.partial.agents_incomplete"]
    assert "500 of 1,200" in client.partial_failures[0]


def test_server_ignoring_offset_without_total_stops() -> None:
    clock = FakeClock()
    first = [_agent(n) for n in range(1, 501)]
    server = FakeWazuh(clock).on("GET", "/agents", ok({"affected_items": first}))
    client = api(server, clock)
    assert len(client.agents()) == 500
    assert len(server.calls_to("GET", "/agents")) == 2
    assert [m.key for m in client.failure_messages] == ["wazuh_api.partial.stalled"]


def test_rules_server_ignoring_offset_is_deduplicated_and_stops() -> None:
    clock = FakeClock()
    rules = [{"id": n, "filename": "0010-rules_config.xml", "relative_dirname": "ruleset/rules"} for n in range(500)]
    server = FakeWazuh(clock).on("GET", "/", ok(INFO)).on("GET", "/rules", ok({"affected_items": rules}))
    client = api(server, clock)
    assert len(client.rules()) == 500
    assert len(server.calls_to("GET", "/rules")) == 2
    assert [n.key for n in client.notes] == ["wazuh_api.note.stalled"]


def test_oversized_api_response_is_refused() -> None:
    clock = FakeClock()
    huge = {"affected_items": [{"pad": "x" * 4096}] * 64, "total_affected_items": 64}
    server = FakeWazuh(clock).on("GET", "/manager/info", ok(huge))
    config = ApiConfig(url="https://wazuh-manager.example:55000", username=USER, password=PASSWORD)
    client = WazuhAPI(
        config, transport=httpx.MockTransport(server), clock=clock, sleep=clock.sleep, max_response_bytes=64 * 1024
    )
    with pytest.raises(RemoteError) as info:
        client.manager_info()
    assert info.value.kind == "protocol" and "MiB" in str(info.value)


def test_plain_http_api_is_a_warning() -> None:
    config = ApiConfig(url="http://wazuh-manager.example:55000", username=USER, password=PASSWORD)
    client = WazuhAPI(config, transport=httpx.MockTransport(FakeWazuh(FakeClock())))
    assert [w.key for w in client.warnings] == ["net.warn.plain_http"]


def test_default_certificate_hint_explains_localhost_only() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: self-signed certificate")

    config = ApiConfig(url="https://wazuh-manager.example:55000", username=USER, password=PASSWORD)
    with pytest.raises(RemoteError) as info:
        WazuhAPI(config, transport=httpx.MockTransport(handler)).info()
    assert "localhost" in str(info.value) and "localhost" in info.value.render("es")
    assert "verify_tls: false" not in str(info.value)
