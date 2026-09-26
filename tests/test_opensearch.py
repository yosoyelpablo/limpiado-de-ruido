"""Tests for hushwatch.ingest.opensearch (httpx.MockTransport only, no network)."""

from __future__ import annotations

import base64
import json
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
import pytest

from hushwatch import i18n
from hushwatch.config import InputConfig
from hushwatch.ingest.opensearch import EngineInfo, IndexerClient, parse_version
from hushwatch.net import RemoteError

UTC = timezone.utc
START = datetime(2026, 9, 20, tzinfo=UTC)
END = datetime(2026, 9, 21, tzinfo=UTC)
PASSWORD = "FAKE-test-indexer-password!"
INDEX = "wazuh-alerts-*"
OS_TAGLINE = "The OpenSearch Project: https://opensearch.org/"

Handler = Callable[[httpx.Request], httpx.Response]


def respond(status: int = 200, body: Any = None, headers: dict[str, str] | None = None) -> Handler:
    """A factory producing a fresh response per request (responses are single-use in httpx)."""

    def handler(request: httpx.Request) -> httpx.Response:
        if isinstance(body, (bytes, str)):
            return httpx.Response(status, content=body, headers=headers)
        return httpx.Response(status, json=body if body is not None else {}, headers=headers)

    return handler


class Router:
    """Queue of canned responses per (method, path); the last one repeats."""

    def __init__(self) -> None:
        self.routes: dict[tuple[str, str], list[Handler]] = {}
        self.calls: list[httpx.Request] = []

    def on(self, method: str, path: str, *handlers: Handler) -> Router:
        self.routes.setdefault((method, path), []).extend(handlers)
        return self

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(request)
        queue = self.routes.get((request.method, request.url.path))
        if not queue:
            raise AssertionError(f"unexpected request {request.method} {request.url}")
        handler = queue.pop(0) if len(queue) > 1 else queue[0]
        return handler(request)

    def calls_to(self, method: str, path: str) -> list[httpx.Request]:
        return [c for c in self.calls if c.method == method and c.url.path == path]

    def bodies(self, method: str, path: str) -> list[Any]:
        return [json.loads(c.content) for c in self.calls_to(method, path)]


def os_root(number: str = "2.19.3", *, distribution: bool = True, cluster: str = "opensearch") -> Handler:
    version: dict[str, Any] = {"number": number, "build_type": "tar", "lucene_version": "9.12.1"}
    if distribution:
        version["distribution"] = "opensearch"
    return respond(200, {"name": "node-1", "cluster_name": cluster, "version": version, "tagline": OS_TAGLINE})


def es_root(number: str = "8.15.0", *, header: bool = True, tagline: bool = True) -> Handler:
    body: dict[str, Any] = {
        "name": "es01",
        "cluster_name": "siem",
        "version": {"number": number, "build_flavor": "default"},
    }
    if tagline:
        body["tagline"] = "You Know, for Search"
    return respond(200, body, {"X-elastic-product": "Elasticsearch"} if header else None)


def alert(n: int, agent: str = "srv-web-01.example") -> dict[str, Any]:
    return {
        "_index": "wazuh-alerts-4.x-2026.09.20",
        "_id": f"doc-{n}",
        "_source": {
            "timestamp": f"2026-09-20T10:00:{n % 60:02d}.000+0000",
            "rule": {"id": "5710", "level": 5},
            "agent": {"name": agent},
            "data": {"srcip": "192.0.2.10"},
        },
        "sort": [1789898400000 + n, n],
    }


def page(hits: list[dict[str, Any]], **extra: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "took": 3,
        "timed_out": False,
        "_shards": {"total": 3, "successful": 3, "skipped": 0, "failed": 0},
        "hits": {"hits": hits},
    }
    body.update(extra)
    return body


def client(router: Router, **kwargs: Any) -> IndexerClient:
    kwargs.setdefault("url", "https://indexer.example:9200")
    kwargs.setdefault("username", "hushwatch_ro")
    kwargs.setdefault("password", PASSWORD)
    sleeps: list[float] = kwargs.pop("sleeps", [])
    return IndexerClient(transport=httpx.MockTransport(router), sleep=sleeps.append, **kwargs)


# ---- engine detection ------------------------------------------------------------------------------------------


def test_engine_opensearch_2x() -> None:
    router = Router().on("GET", "/", os_root("2.19.3"))
    info = client(router).engine()
    assert info == EngineInfo(kind="opensearch", version=(2, 19, 3), reported_version="2.19.3")
    assert info.supports_pit and not info.shard_doc_tiebreak and not info.wazuh_indexer


def test_engine_wazuh_indexer_masquerade_reads_real_version() -> None:
    router = (
        Router()
        .on("GET", "/", os_root("7.10.2", distribution=False, cluster="wazuh-cluster"))
        .on(
            "GET", "/_nodes/_local", respond(200, {"nodes": {"a1": {"version": "2.19.3"}, "b2": {"version": "2.19.1"}}})
        )
    )
    info = client(router).engine()
    assert info.kind == "opensearch" and info.wazuh_indexer and info.compat_mode
    assert info.version == (2, 19, 1)  # the oldest node decides
    assert info.reported_version == "7.10.2"
    assert router.calls_to("GET", "/_nodes/_local")[0].url.params["filter_path"] == "nodes.*.version"


def test_engine_masquerade_without_node_permission_is_conservative() -> None:
    router = (
        Router()
        .on("GET", "/", os_root("7.10.2", distribution=False, cluster="wazuh-cluster"))
        .on(
            "GET", "/_nodes/_local", respond(403, {"error": {"type": "security_exception", "reason": "no permissions"}})
        )
    )
    idx = client(router)
    info = idx.engine()
    assert info.kind == "opensearch" and info.version == () and info.wazuh_indexer
    assert not info.shard_doc_tiebreak
    assert any(n.key == "indexer.note.version_unknown" for n in idx.notes)


def test_engine_elasticsearch_by_header_only() -> None:
    router = Router().on("GET", "/", es_root("8.15.0", tagline=False))
    info = client(router).engine()
    assert info.kind == "elasticsearch" and info.version == (8, 15, 0)
    assert info.shard_doc_tiebreak and not info.wazuh_indexer


def test_engine_old_elasticsearch_by_tagline() -> None:
    router = Router().on("GET", "/", es_root("7.9.3", header=False))
    info = client(router).engine()
    assert info.kind == "elasticsearch" and info.version == (7, 9, 3)
    assert not info.supports_pit and not info.shard_doc_tiebreak


def test_engine_unknown_product_raises() -> None:
    router = Router().on("GET", "/", respond(200, {"hello": "world"}))
    with pytest.raises(RemoteError) as info:
        client(router).engine()
    assert info.value.kind == "protocol"


def test_engine_forbidden_root_falls_back() -> None:
    router = Router().on("GET", "/", respond(403, {"error": "forbidden"}, {"X-elastic-product": "Elasticsearch"}))
    idx = client(router)
    assert idx.engine() == EngineInfo(kind="elasticsearch", version=())
    router2 = Router().on("GET", "/", respond(403, {"error": "forbidden"}))
    assert client(router2).engine().kind == "opensearch"


def test_engine_is_cached() -> None:
    router = Router().on("GET", "/", os_root())
    idx = client(router)
    idx.engine()
    idx.engine()
    assert len(router.calls_to("GET", "/")) == 1


def test_parse_version() -> None:
    assert parse_version("8.15.0-SNAPSHOT") == (8, 15, 0)
    assert parse_version("v3.3") == (3, 3)
    assert parse_version("garbage") == ()
    assert parse_version(None) == ()
    assert parse_version("9" * 50) == ()


# ---- PIT streaming ---------------------------------------------------------------------------------------------


def test_pit_flow_elasticsearch_rotates_ids_and_closes_latest() -> None:
    router = (
        Router()
        .on("GET", "/", es_root())
        .on(
            "POST",
            "/wazuh-alerts-*/_pit",
            respond(200, {"id": "pit-A-0123456789abcdef", "_shards": {"total": 3, "successful": 3, "failed": 0}}),
        )
        .on(
            "POST",
            "/_search",
            respond(200, page([alert(1), alert(2)], pit_id="pit-B-0123456789abcdef")),
            respond(200, page([alert(3)], pit_id="pit-C-0123456789abcdef")),
        )
        .on("DELETE", "/_pit", respond(200, {"succeeded": True, "num_freed": 3}))
    )
    idx = client(router)
    docs = list(idx.stream(INDEX, start=START, end=END, fields=["rule.id", "agent.name"], page_size=2))
    assert [d["_id"] for d in docs] == ["doc-1", "doc-2", "doc-3"]
    assert docs[0]["_index"] == "wazuh-alerts-4.x-2026.09.20"
    assert idx.last_mode == "pit"
    create = router.calls_to("POST", "/wazuh-alerts-*/_pit")[0]
    assert create.url.params["keep_alive"] == "5m"
    first, second = router.bodies("POST", "/_search")
    assert first["pit"] == {"id": "pit-A-0123456789abcdef", "keep_alive": "5m"}
    assert second["pit"]["id"] == "pit-B-0123456789abcdef"  # always the newest id
    assert "search_after" not in first and second["search_after"] == alert(2)["sort"]
    assert first["track_total_hits"] is False
    assert first["sort"] == [{"timestamp": {"order": "asc", "unmapped_type": "date"}}, {"_shard_doc": "asc"}]
    assert first["_source"] == {"includes": ["rule.id", "agent.name", "timestamp"]}
    assert first["query"] == {
        "bool": {
            "filter": [
                {
                    "range": {
                        "timestamp": {
                            "gte": "2026-09-20T00:00:00.000Z",
                            "lt": "2026-09-21T00:00:00.000Z",
                            "format": "strict_date_optional_time",
                        }
                    }
                }
            ]
        }
    }
    assert router.bodies("DELETE", "/_pit") == [{"id": "pit-C-0123456789abcdef"}]
    assert idx.partial_failures == [] and not idx.truncated


def test_pit_flow_opensearch_3x() -> None:
    router = (
        Router()
        .on("GET", "/", os_root("3.3.0"))
        .on(
            "POST",
            "/wazuh-alerts-*/_search/point_in_time",
            respond(
                200,
                {
                    "pit_id": "os-pit-1-abcdefghijkl",
                    "_shards": {"total": 1, "successful": 1, "failed": 0},
                    "creation_time": 1,
                },
            ),
        )
        .on(
            "POST",
            "/_search",
            respond(200, page([alert(1), alert(2)], pit_id="os-pit-2-abcdefghijkl")),
            respond(200, page([], pit_id="os-pit-3-abcdefghijkl")),
        )
        .on("DELETE", "/_search/point_in_time", respond(200, {"pits": [{"successful": True}]}))
    )
    idx = client(router)
    docs = list(idx.stream(INDEX, start=START, end=END, page_size=2, query={"term": {"rule.id": "5710"}}))
    assert len(docs) == 2
    bodies = router.bodies("POST", "/_search")
    assert [b["pit"]["id"] for b in bodies] == ["os-pit-1-abcdefghijkl", "os-pit-2-abcdefghijkl"]
    assert "_source" not in bodies[0]  # fields=None: full documents
    assert bodies[0]["query"]["bool"]["filter"][1] == {"term": {"rule.id": "5710"}}
    assert router.bodies("DELETE", "/_search/point_in_time") == [{"pit_id": ["os-pit-3-abcdefghijkl"]}]
    assert all(c.url.path == "/_search" for c in router.calls_to("POST", "/_search"))  # never index in path


def test_pit_short_clean_page_ends_stream_without_extra_request() -> None:
    router = (
        Router()
        .on("GET", "/", os_root("3.3.0"))
        .on("POST", "/wazuh-alerts-*/_search/point_in_time", respond(200, {"pit_id": "pit-000000000001"}))
        .on("POST", "/_search", respond(200, page([alert(1)])))
        .on("DELETE", "/_search/point_in_time", respond(200, {}))
    )
    assert len(list(client(router).stream(INDEX, start=START, end=END, page_size=10))) == 1
    assert len(router.calls_to("POST", "/_search")) == 1


def test_pit_closed_on_error_with_latest_id_and_no_id_in_message() -> None:
    latest = "pit-LATEST-0123456789abcdefghij"
    router = (
        Router()
        .on("GET", "/", es_root())
        .on("POST", "/wazuh-alerts-*/_pit", respond(200, {"id": "pit-FIRST-0123456789abcdef"}))
        .on(
            "POST",
            "/_search",
            respond(200, page([alert(1), alert(2)], pit_id=latest)),
            respond(
                500,
                {
                    "error": {
                        "type": "search_context_missing_exception",
                        "reason": f"No search context found for id [{latest}]",
                    }
                },
            ),
        )
        .on("DELETE", "/_pit", respond(200, {}))
    )
    idx = client(router, sleeps=[])
    got: list[dict[str, Any]] = []
    with pytest.raises(RemoteError) as info:
        for doc in idx.stream(INDEX, start=START, end=END, page_size=2):
            got.append(doc)
    assert len(got) == 2
    assert info.value.kind == "http" and info.value.status == 500
    assert latest not in str(info.value) and latest[4:24] not in str(info.value)
    assert router.bodies("DELETE", "/_pit") == [{"id": latest}]


def test_pit_closed_when_consumer_stops_early() -> None:
    router = (
        Router()
        .on("GET", "/", es_root())
        .on("POST", "/wazuh-alerts-*/_pit", respond(200, {"id": "pit-early-0123456789"}))
        .on("POST", "/_search", respond(200, page([alert(1), alert(2)], pit_id="pit-early-0123456789")))
        .on("DELETE", "/_pit", respond(200, {}))
    )
    stream = client(router).stream(INDEX, start=START, end=END, page_size=2)
    next(stream)
    stream.close()
    assert router.bodies("DELETE", "/_pit") == [{"id": "pit-early-0123456789"}]


def test_pit_close_failure_never_masks_the_original_error() -> None:
    router = (
        Router()
        .on("GET", "/", es_root())
        .on("POST", "/wazuh-alerts-*/_pit", respond(200, {"id": "pit-x-0123456789abc"}))
        .on("POST", "/_search", respond(401, "Unauthorized"))
        .on("DELETE", "/_pit", respond(500, {"error": "boom"}))
    )
    idx = client(router)
    with pytest.raises(RemoteError) as info:
        list(idx.stream(INDEX, start=START, end=END))
    assert info.value.kind == "auth"
    assert any(n.key == "indexer.note.close_failed" for n in idx.notes)


def test_pit_create_forbidden_falls_back_to_scroll() -> None:
    router = (
        Router()
        .on("GET", "/", os_root("3.3.0"))
        .on(
            "POST",
            "/wazuh-alerts-*/_search/point_in_time",
            respond(
                403,
                {
                    "error": {
                        "root_cause": [
                            {
                                "type": "security_exception",
                                "reason": "no permissions for [indices:data/read/point_in_time/create]",
                            }
                        ]
                    }
                },
            ),
        )
        .on(
            "POST",
            "/wazuh-alerts-*/_search",
            respond(200, page([alert(1), alert(2)], _scroll_id="scroll-1-abcdefghijkl")),
        )
        .on(
            "POST",
            "/_search/scroll",
            respond(200, page([alert(3)], _scroll_id="scroll-2-abcdefghijkl")),
            respond(200, page([], _scroll_id="scroll-3-abcdefghijkl")),
        )
        .on("DELETE", "/_search/scroll", respond(200, {"succeeded": True}))
    )
    idx = client(router)
    docs = list(idx.stream(INDEX, start=START, end=END, page_size=2, fields=["agent.name"]))
    assert [d["_id"] for d in docs] == ["doc-1", "doc-2", "doc-3"]
    assert idx.last_mode == "scroll"
    initial = router.calls_to("POST", "/wazuh-alerts-*/_search")[0]
    assert initial.url.params["scroll"] == "5m"
    initial_body = json.loads(initial.content)
    # an exact total lets the scroll prove it is complete (a scroll cannot disable it anyway)
    assert initial_body["sort"] == ["_doc"] and initial_body["track_total_hits"] is True
    assert initial_body["_source"] == {"includes": ["agent.name", "timestamp"]}
    assert [b["scroll_id"] for b in router.bodies("POST", "/_search/scroll")] == [
        "scroll-1-abcdefghijkl",
        "scroll-2-abcdefghijkl",
    ]
    assert router.bodies("DELETE", "/_search/scroll") == [{"scroll_id": ["scroll-3-abcdefghijkl"]}]
    fallback = [n for n in idx.notes if n.key == "indexer.note.fallback"]
    assert fallback and "point_in_time/create" in i18n.render(fallback[0])
    assert idx.partial_failures == []


def test_pit_first_page_rejected_closes_pit_and_uses_scroll() -> None:
    router = (
        Router()
        .on("GET", "/", es_root("8.15.0"))
        .on("POST", "/wazuh-alerts-*/_pit", respond(200, {"id": "pit-bad-0123456789ab"}))
        .on(
            "POST",
            "/_search",
            respond(400, {"error": {"type": "illegal_argument_exception", "reason": "unsupported sort [_shard_doc]"}}),
        )
        .on("DELETE", "/_pit", respond(200, {}))
        .on("POST", "/wazuh-alerts-*/_search", respond(200, page([alert(1)], _scroll_id="scroll-a-0123456789")))
        .on("POST", "/_search/scroll", respond(200, page([], _scroll_id="scroll-a-0123456789")))
        .on("DELETE", "/_search/scroll", respond(200, {}))
    )
    idx = client(router)
    assert len(list(idx.stream(INDEX, start=START, end=END))) == 1
    assert router.bodies("DELETE", "/_pit") == [{"id": "pit-bad-0123456789ab"}]
    assert idx.last_mode == "scroll"


def test_wazuh_4x_indexer_streams_with_scroll_directly() -> None:
    router = (
        Router()
        .on("GET", "/", os_root("7.10.2", distribution=False, cluster="wazuh-cluster"))
        .on("GET", "/_nodes/_local", respond(200, {"nodes": {"n": {"version": "2.19.3"}}}))
        .on("POST", "/wazuh-alerts-*/_search", respond(200, page([alert(1)], _scroll_id="scroll-w-0123456789")))
        .on("POST", "/_search/scroll", respond(200, page([], _scroll_id="scroll-w-0123456789")))
        .on("DELETE", "/_search/scroll", respond(200, {}))
    )
    idx = client(router)
    assert len(list(idx.stream(start=START, end=END))) == 1
    assert not router.calls_to("POST", "/wazuh-alerts-*/_search/point_in_time")
    assert idx.last_mode == "scroll" and idx.notes == []


def test_scroll_error_mid_stream_clears_scroll() -> None:
    router = (
        Router()
        .on("GET", "/", os_root("2.19.3"))
        .on("POST", "/wazuh-alerts-*/_search", respond(200, page([alert(1)], _scroll_id="scroll-e-0123456789")))
        .on("POST", "/_search/scroll", respond(429, {"error": "too many requests"}))
        .on("DELETE", "/_search/scroll", respond(200, {}))
    )
    sleeps: list[float] = []
    idx = client(router, sleeps=sleeps)
    with pytest.raises(RemoteError) as info:
        list(idx.stream(INDEX, start=START, end=END))
    assert info.value.kind == "rate_limited"
    assert len(router.calls_to("POST", "/_search/scroll")) == 1  # scroll pages are never retried
    assert sleeps == []
    assert router.bodies("DELETE", "/_search/scroll") == [{"scroll_id": ["scroll-e-0123456789"]}]


# ---- partial results are never zero ----------------------------------------------------------------------------


def _shard_failure_page(hits: list[dict[str, Any]], **extra: Any) -> dict[str, Any]:
    return page(
        hits,
        _shards={
            "total": 3,
            "successful": 1,
            "skipped": 0,
            "failed": 2,
            "failures": [
                {
                    "shard": 0,
                    "index": "wazuh-alerts-4.x-2026.09.20",
                    "node": "n1",
                    "reason": {"type": "node_disconnected_exception", "reason": "node left"},
                },
                {
                    "shard": 1,
                    "index": "wazuh-alerts-4.x-2026.09.20",
                    "node": "n1",
                    "reason": {"type": "node_disconnected_exception", "reason": "node left"},
                },
            ],
        },
        **extra,
    )


def test_shard_failures_recorded_once_and_documents_still_flow() -> None:
    router = (
        Router()
        .on("GET", "/", os_root("2.19.3"))
        .on(
            "POST",
            "/wazuh-alerts-*/_search",
            respond(200, _shard_failure_page([alert(1)], _scroll_id="scroll-s-0123456789")),
        )
        .on(
            "POST",
            "/_search/scroll",
            respond(200, _shard_failure_page([alert(2)], _scroll_id="scroll-s-0123456789")),
            respond(200, _shard_failure_page([], _scroll_id="scroll-s-0123456789")),
        )
        .on("DELETE", "/_search/scroll", respond(200, {}))
    )
    idx = client(router)
    assert len(list(idx.stream(INDEX, start=START, end=END))) == 2
    assert len(idx.partial_failures) == 1  # deduplicated across pages
    text = idx.partial_failures[0]
    assert "2 of 3 shards failed" in text and "node_disconnected_exception" in text and INDEX in text
    assert "scroll-s-0123456789" not in text
    assert idx.failure_messages[0].key == "indexer.partial.shards"
    assert "fallaron 2 de 3 shards" in i18n.render(idx.failure_messages[0], "es")


def test_timed_out_and_skipped_clusters_recorded() -> None:
    router = (
        Router()
        .on("GET", "/", os_root("2.19.3"))
        .on(
            "POST",
            "/wazuh-alerts-*/_search",
            respond(
                200,
                {
                    **page([alert(1)], _scroll_id="scroll-t-0123456789"),
                    "timed_out": True,
                    "_clusters": {"total": 2, "successful": 1, "skipped": 1},
                },
            ),
        )
        .on("POST", "/_search/scroll", respond(200, page([])))
        .on("DELETE", "/_search/scroll", respond(200, {}))
    )
    idx = client(router)
    list(idx.stream(INDEX, start=START, end=END))
    keys = [m.key for m in idx.failure_messages]
    assert "indexer.partial.timed_out" in keys and "indexer.partial.clusters" in keys


def test_unparseable_shard_status_is_not_treated_as_success() -> None:
    router = (
        Router()
        .on("GET", "/", os_root("2.19.3"))
        .on(
            "POST",
            "/wazuh-alerts-*/_count",
            respond(
                200, {"count": 5, "_shards": {"total": 3, "successful": 3, "failed": "lots"}, "timed_out": "maybe"}
            ),
        )
    )
    idx = client(router)
    assert idx.count(INDEX, start=START, end=END) == 5
    keys = [m.key for m in idx.failure_messages]
    assert "indexer.partial.shards" in keys and "indexer.partial.timed_out" in keys


def test_every_shard_failed_raises_instead_of_zero() -> None:
    all_failed = {
        "count": 0,
        "_shards": {
            "total": 3,
            "successful": 0,
            "failed": 3,
            "failures": [{"reason": {"type": "circuit_breaking_exception", "reason": "data too large"}}],
        },
    }
    router = Router().on("POST", "/wazuh-alerts-*/_count", respond(200, all_failed))
    with pytest.raises(RemoteError) as info:
        client(router).count(INDEX, start=START, end=END)
    assert info.value.kind == "partial" and "circuit_breaking_exception" in str(info.value)


def test_max_docs_truncates_and_reports() -> None:
    router = (
        Router()
        .on("GET", "/", os_root("2.19.3"))
        .on(
            "POST",
            "/wazuh-alerts-*/_search",
            respond(200, page([alert(i) for i in range(4)], _scroll_id="scroll-m-0123456789")),
        )
        .on("DELETE", "/_search/scroll", respond(200, {}))
    )
    idx = client(router)
    docs = list(idx.stream(INDEX, start=START, end=END, max_docs=3))
    assert len(docs) == 3 and idx.truncated
    assert json.loads(router.calls_to("POST", "/wazuh-alerts-*/_search")[0].content)["size"] == 4
    assert any(w.key == "indexer.warn.truncated" for w in idx.warnings)
    assert router.bodies("DELETE", "/_search/scroll")


def test_max_docs_equal_to_available_is_not_truncation() -> None:
    router = (
        Router()
        .on("GET", "/", os_root("2.19.3"))
        .on(
            "POST",
            "/wazuh-alerts-*/_search",
            respond(200, page([alert(i) for i in range(3)], _scroll_id="scroll-q-0123456789")),
        )
        .on("POST", "/_search/scroll", respond(200, page([], _scroll_id="scroll-q-0123456789")))
        .on("DELETE", "/_search/scroll", respond(200, {}))
    )
    idx = client(router)
    assert len(list(idx.stream(INDEX, start=START, end=END, max_docs=3))) == 3
    assert not idx.truncated


def test_hostile_hits_are_skipped_or_rejected() -> None:
    weird: list[Any] = [alert(1), {"_id": "x", "_source": "not-a-dict"}, "garbage", {"_id": "y"}]
    router = (
        Router()
        .on("GET", "/", os_root("2.19.3"))
        .on("POST", "/wazuh-alerts-*/_search", respond(200, page(weird, _scroll_id="scroll-h-0123456789")))
        .on("POST", "/_search/scroll", respond(200, {"hits": {"hits": "nope"}}))
        .on("DELETE", "/_search/scroll", respond(200, {}))
    )
    idx = client(router)
    docs: list[dict[str, Any]] = []
    with pytest.raises(RemoteError) as info:
        for doc in idx.stream(INDEX, start=START, end=END):
            docs.append(doc)
    assert info.value.kind == "protocol"
    assert [d["_id"] for d in docs] == ["doc-1", "y"]  # a hit without _source yields metadata only
    assert idx.malformed == 2


def test_non_json_and_non_object_bodies_are_protocol_errors() -> None:
    for body in (b"<html>proxy error</html>", b"[1,2,3]"):
        router = Router().on("POST", "/wazuh-alerts-*/_count", respond(200, body))
        with pytest.raises(RemoteError) as info:
            client(router).count(INDEX)
        assert info.value.kind == "protocol"


# ---- composite aggregation -------------------------------------------------------------------------------------


def _agg(buckets: list[dict[str, Any]], after_key: dict[str, Any] | None, **extra: Any) -> dict[str, Any]:
    agg: dict[str, Any] = {"buckets": buckets}
    if after_key is not None:
        agg["after_key"] = after_key
    body = {
        "timed_out": False,
        "_shards": {"total": 3, "successful": 3, "failed": 0},
        "hits": {"hits": []},
        "aggregations": {"hushwatch": agg},
    }
    body.update(extra)
    return body


H0 = 1789869600000  # 2026-09-20T00:00:00Z in epoch ms


def test_composite_pages_with_after_key_and_counts_missing_values() -> None:
    router = Router().on(
        "POST",
        "/wazuh-alerts-*/_search",
        respond(
            200,
            _agg(
                [
                    {"key": {"ts": H0, "agent": "srv-web-01.example", "channel": "Security"}, "doc_count": 40},
                    {"key": {"ts": H0, "agent": "srv-web-01.example", "channel": None}, "doc_count": 3},
                ],
                {"ts": H0, "agent": "srv-web-01.example", "channel": "zzz-opaque"},
            ),
        ),
        respond(
            200,
            _agg(
                [{"key": {"ts": H0 + 3600000, "agent": None, "channel": None}, "doc_count": 7}],
                {"ts": H0 + 3600000, "agent": None, "channel": None},
            ),
        ),
        respond(200, _agg([], None)),
    )
    idx = client(router)
    rows = list(
        idx.composite(
            INDEX,
            sources=[("agent", "agent.name"), ("channel", "data.win.system.channel")],
            start=START,
            end=END,
            interval="1h",
            time_zone="Europe/Madrid",
            size=2,
        )
    )
    assert rows == [
        ({"ts": H0, "agent": "srv-web-01.example", "channel": "Security"}, 40),
        ({"ts": H0, "agent": "srv-web-01.example", "channel": None}, 3),
        ({"ts": H0 + 3600000, "agent": None, "channel": None}, 7),
    ]
    bodies = router.bodies("POST", "/wazuh-alerts-*/_search")
    assert len(bodies) == 3
    comp = bodies[0]["aggs"]["hushwatch"]["composite"]
    assert bodies[0]["size"] == 0 and bodies[0]["track_total_hits"] is False
    assert comp["size"] == 2 and "after" not in comp
    assert comp["sources"] == [
        {"ts": {"date_histogram": {"field": "timestamp", "fixed_interval": "1h", "time_zone": "Europe/Madrid"}}},
        {"agent": {"terms": {"field": "agent.name", "missing_bucket": True}}},
        {"channel": {"terms": {"field": "data.win.system.channel", "missing_bucket": True}}},
    ]
    # after_key is passed back verbatim (it is not always the last bucket's key)
    assert bodies[1]["aggs"]["hushwatch"]["composite"]["after"] == {
        "ts": H0,
        "agent": "srv-web-01.example",
        "channel": "zzz-opaque",
    }
    assert bodies[2]["aggs"]["hushwatch"]["composite"]["after"] == {"ts": H0 + 3600000, "agent": None, "channel": None}
    assert idx.partial_failures == [] and not idx.truncated


def test_composite_max_buckets_truncates() -> None:
    buckets = [{"key": {"ts": H0 + i * 3600000}, "doc_count": 1} for i in range(3)]
    router = Router().on("POST", "/wazuh-alerts-*/_search", respond(200, _agg(buckets, {"ts": H0 + 2 * 3600000})))
    idx = client(router)
    rows = list(idx.composite(INDEX, sources=[], start=START, end=END, max_buckets=2, size=1000))
    assert len(rows) == 2 and idx.truncated
    assert router.bodies("POST", "/wazuh-alerts-*/_search")[0]["aggs"]["hushwatch"]["composite"]["size"] == 3


def test_composite_repeated_after_key_stops_and_reports() -> None:
    same = _agg([{"key": {"ts": H0}, "doc_count": 1}], {"ts": H0})
    router = Router().on("POST", "/wazuh-alerts-*/_search", respond(200, same))
    idx = client(router)
    rows = list(idx.composite(INDEX, sources=[], start=START, end=END))
    assert len(rows) == 2 and len(router.calls) == 2
    assert [m.key for m in idx.failure_messages] == ["indexer.partial.after_key"]


def test_composite_records_shard_failures_and_malformed_buckets() -> None:
    buckets: list[Any] = [
        {"key": {"ts": H0}, "doc_count": 5},
        {"key": "bad", "doc_count": 1},
        {"key": {"ts": H0}, "doc_count": -3},
        "x",
    ]
    body = _agg(
        buckets,
        None,
        _shards={
            "total": 3,
            "successful": 2,
            "failed": 1,
            "failures": [{"reason": {"type": "exception", "reason": "boom"}}],
        },
    )
    router = Router().on("POST", "/wazuh-alerts-*/_search", respond(200, body))
    idx = client(router)
    assert list(idx.composite(INDEX, sources=[], start=START, end=END)) == [({"ts": H0}, 5)]
    assert {m.key for m in idx.failure_messages} == {"indexer.partial.shards", "indexer.partial.buckets"}


def test_composite_missing_aggregation_is_protocol_error() -> None:
    router = Router().on("POST", "/wazuh-alerts-*/_search", respond(200, {"hits": {"hits": []}}))
    with pytest.raises(RemoteError) as info:
        list(client(router).composite(INDEX, sources=[], start=START, end=END))
    assert info.value.kind == "protocol"


@pytest.mark.parametrize(
    "kwargs",
    [
        {"sources": [("ts", "agent.name")]},
        {"sources": [("a", "x"), ("a", "y")]},
        {"sources": [("bad name", "x")]},
        {"sources": [("a", "")]},
        {"sources": ["agent.name"]},
        {"sources": [], "interval": "1w"},
        {"sources": [], "interval": "1M"},
        {"sources": [], "interval": None},
        {"sources": [], "time_zone": "UTC; DROP"},
        {"sources": [], "max_buckets": -1},
    ],
)
def test_composite_argument_validation(kwargs: dict[str, Any]) -> None:
    idx = client(Router())
    with pytest.raises(ValueError):
        idx.composite(INDEX, start=START, end=END, **kwargs)


# ---- count / field_caps ------------------------------------------------------------------------------------------


def test_count_body_and_empty_pattern_warning() -> None:
    router = Router().on(
        "POST",
        "/wazuh-archives-*/_count",
        respond(200, {"count": 12, "_shards": {"total": 3, "successful": 3, "failed": 0}}),
        respond(200, {"count": 0, "_shards": {"total": 0, "successful": 0, "failed": 0}}),
    )
    idx = client(router)
    assert idx.count("wazuh-archives-*", query={"term": {"agent.id": "001"}}, start=START, end=END) == 12
    body = router.bodies("POST", "/wazuh-archives-*/_count")[0]
    assert body["query"]["bool"]["filter"][1] == {"term": {"agent.id": "001"}}
    assert idx.count("wazuh-archives-*") == 0
    assert any(w.key == "indexer.warn.no_indices" for w in idx.warnings)


def test_count_rejects_bad_count() -> None:
    router = Router().on("POST", "/wazuh-alerts-*/_count", respond(200, {"count": "many"}))
    with pytest.raises(RemoteError):
        client(router).count(INDEX)


def test_field_caps_types_conflicts_and_failures() -> None:
    body = {
        "indices": ["wazuh-alerts-4.x-2026.09.20", "wazuh-alerts-4.x-2026.09.21"],
        "fields": {
            "_id": {"_id": {"type": "_id"}},
            "agent": {"object": {"type": "object"}},
            "agent.name": {"keyword": {"type": "keyword", "searchable": True, "aggregatable": True}},
            "data.srcport": {"keyword": {"type": "keyword"}, "long": {"type": "long"}},
            "timestamp": {"date": {"type": "date"}},
        },
        "failed_indices": 1,
        "failures": [{"indices": ["x"], "failure": {"error": {"type": "index_closed_exception", "reason": "closed"}}}],
    }
    router = Router().on("GET", "/wazuh-alerts-*/_field_caps", respond(200, body))
    idx = client(router)
    caps = idx.field_caps(INDEX)
    assert caps == {"agent.name": ["keyword"], "data.srcport": ["keyword", "long"], "timestamp": ["date"]}
    assert router.calls[0].url.params["fields"] == "*"
    assert "index_closed_exception" in idx.partial_failures[0]


# ---- auth, TLS, retries ------------------------------------------------------------------------------------------


def test_basic_auth_error_never_contains_password() -> None:
    router = Router().on(
        "GET",
        "/",
        respond(
            401,
            {
                "error": {
                    "root_cause": [
                        {
                            "type": "security_exception",
                            "reason": f"unable to authenticate user [hushwatch_ro] pw {PASSWORD}",
                        }
                    ]
                }
            },
        ),
    )
    idx = client(router)
    with pytest.raises(RemoteError) as info:
        idx.engine()
    err = info.value
    assert err.kind == "auth" and err.status == 401
    for rendered in (str(err), err.render("es"), repr(idx)):
        assert PASSWORD not in rendered
    assert "username/password" in str(err)
    sent = router.calls[0].headers["authorization"]
    assert base64.b64decode(sent.split()[1]).decode() == f"hushwatch_ro:{PASSWORD}"


def test_api_key_header_and_scrubbing() -> None:
    key = "RkFLRS1rZXktaWQ6RkFLRS10ZXN0LWFwaS1rZXk="
    router = Router().on("GET", "/", respond(403, {"error": f"api key {key} lacks privileges"}))
    idx = client(router, username=None, password=None, api_key=key)
    idx.engine()  # 403 on GET / is tolerated
    assert router.calls[0].headers["authorization"] == f"ApiKey {key}"
    router2 = Router().on("POST", "/wazuh-alerts-*/_count", respond(403, {"error": f"api key {key} lacks privileges"}))
    with pytest.raises(RemoteError) as info:
        client(router2, username=None, password=None, api_key=key).count(INDEX)
    assert info.value.kind == "forbidden" and key not in str(info.value)
    assert "view_index_metadata" in str(info.value)


def test_api_key_with_header_injection_rejected() -> None:
    with pytest.raises(RemoteError) as info:
        client(Router(), api_key="abc\r\nX-Evil: 1")
    assert info.value.kind == "config" and "X-Evil" not in str(info.value)


def test_tls_verification_failure_suggests_wazuh_root_ca() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError(
            "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: "
            "self-signed certificate in certificate chain (_ssl.c:1006)"
        )

    idx = IndexerClient(url="https://indexer.example:9200", transport=httpx.MockTransport(handler))
    with pytest.raises(RemoteError) as info:
        idx.engine()
    assert info.value.kind == "tls"
    assert "ca_cert" in str(info.value) and "root-ca.pem" in str(info.value)
    assert "root-ca.pem" in info.value.render("es")


def test_timeout_is_reported() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("read timed out")

    idx = IndexerClient(url="https://indexer.example:9200", timeout=12, transport=httpx.MockTransport(handler))
    with pytest.raises(RemoteError) as info:
        idx.count(INDEX)
    assert info.value.kind == "timeout" and "12" in str(info.value)


def test_429_is_retried_with_backoff() -> None:
    router = Router().on(
        "POST",
        "/wazuh-alerts-*/_count",
        respond(429, {"error": {"type": "es_rejected_execution_exception", "reason": "queue full"}}),
        respond(503, {"error": "unavailable"}, {"Retry-After": "7"}),
        respond(200, {"count": 3, "_shards": {"total": 1, "successful": 1, "failed": 0}}),
    )
    sleeps: list[float] = []
    assert client(router, sleeps=sleeps).count(INDEX) == 3
    assert sleeps == [1.0, 7.0]


def test_429_exhaustion_raises_rate_limited() -> None:
    router = Router().on("POST", "/wazuh-alerts-*/_count", respond(429, {"error": "busy"}))
    sleeps: list[float] = []
    with pytest.raises(RemoteError) as info:
        client(router, sleeps=sleeps, max_retries=2).count(INDEX)
    assert info.value.kind == "rate_limited" and len(router.calls) == 3 and sleeps == [1.0, 2.0]
    assert "3 attempts" in str(info.value)


def test_error_reason_is_sanitized() -> None:
    hostile = "boom \x1b[2J\u202e" + "A" * 5000
    router = Router().on(
        "POST", "/wazuh-alerts-*/_count", respond(500, {"error": {"type": "exception", "reason": hostile}})
    )
    with pytest.raises(RemoteError) as info:
        client(router, sleeps=[]).count(INDEX)
    text = str(info.value)
    assert "\x1b" not in text and "\u202e" not in text and len(text) < 700


def test_verify_tls_false_is_a_warning() -> None:
    idx = client(Router(), verify_tls=False)
    assert [w.key for w in idx.warnings] == ["net.warn.tls_disabled"]


# ---- input validation --------------------------------------------------------------------------------------------


@pytest.mark.parametrize("index", ["", " ", "../x", "a/b", "a b", "a?b", "a#b", "_cat", "..", "a,,b", "+x", "x\n"])
def test_bad_index_patterns_rejected(index: str) -> None:
    with pytest.raises(RemoteError) as info:
        client(Router()).stream(index, start=START, end=END)
    assert info.value.kind == "config"


def test_index_pattern_encoding() -> None:
    router = Router().on("POST", "/wazuh-alerts-*,-wazuh-alerts-old*/_count", respond(200, {"count": 1}))
    assert client(router).count("wazuh-alerts-*,-wazuh-alerts-old*") == 1


def test_time_arguments_validated() -> None:
    idx = client(Router())
    with pytest.raises(ValueError):
        idx.stream(INDEX, start=datetime(2026, 9, 20), end=END)  # naive
    with pytest.raises(ValueError):
        idx.stream(INDEX, start=END, end=START)
    with pytest.raises(TypeError):
        idx.stream(INDEX, start=START, end=END, fields="agent.name")  # a str is a Sequence[str]: rejected
    with pytest.raises(ValueError):
        idx.stream(INDEX, start=START, end=END, max_docs=-1)


def test_sub_millisecond_bounds_and_query_unwrapping() -> None:
    router = Router().on("POST", "/wazuh-alerts-*/_count", respond(200, {"count": 1}))
    idx = client(router)
    idx.count(
        INDEX,
        start=START + timedelta(microseconds=1500),
        end=END + timedelta(microseconds=1),
        query={"query": {"term": {"rule.id": "5710"}}},
    )
    flt = router.bodies("POST", "/wazuh-alerts-*/_count")[0]["query"]["bool"]["filter"]
    # ms data: "t >= 00:00:00.0015" is "t >= .002"; flooring would admit the .001 document that precedes start
    assert flt[0]["range"]["timestamp"]["gte"] == "2026-09-20T00:00:00.002Z"
    assert flt[0]["range"]["timestamp"]["lt"] == "2026-09-21T00:00:00.001Z"  # rounded up: nothing lost
    assert flt[1] == {"term": {"rule.id": "5710"}}


@pytest.mark.parametrize("micros", [0, 1, 999, 1000, 1500, 999_999])
def test_adjacent_windows_share_one_boundary(micros: int) -> None:
    """Regression: [a, b) and [b, c) must split at the same instant (no double count, no gap) for any b."""
    router = Router().on("POST", "/wazuh-alerts-*/_count", respond(200, {"count": 1}))
    idx = client(router)
    boundary = START + timedelta(hours=5, microseconds=micros)
    idx.count(INDEX, start=START, end=boundary)
    idx.count(INDEX, start=boundary, end=END)
    first, second = (
        b["query"]["bool"]["filter"][0]["range"]["timestamp"] for b in router.bodies("POST", "/wazuh-alerts-*/_count")
    )
    assert first["lt"] == second["gte"]


def test_from_input_config_and_overrides() -> None:
    cfg = InputConfig(
        type="indexer",
        url="https://indexer.example:9200",
        index="wazuh-archives-*",
        time_field="@timestamp",
        username="hushwatch_ro",
        password=PASSWORD,
    )
    router = Router().on("POST", "/wazuh-archives-*/_count", respond(200, {"count": 2}))
    idx = IndexerClient(cfg, transport=httpx.MockTransport(router))
    assert idx.count(start=START) == 2
    assert "@timestamp" in router.bodies("POST", "/wazuh-archives-*/_count")[0]["query"]["bool"]["filter"][0]["range"]
    assert PASSWORD not in repr(idx)
    with pytest.raises(RemoteError) as info:
        IndexerClient(InputConfig(type="indexer"))
    assert info.value.kind == "config"


def test_every_indexer_message_has_spanish() -> None:
    catalog = i18n.keys()  # the registered message keys (a function, not dict.keys)
    keys = [k for k in catalog if k.startswith("indexer.")]
    assert len(keys) > 20
    for key in keys:
        assert i18n.render(i18n.M(key), "es") != i18n.render(i18n.M(key), "en")


# ---- loop guards / expired contexts ------------------------------------------------------------------------------


def test_pit_without_progress_stops_instead_of_looping() -> None:
    stuck = page([alert(1), alert(2)], pit_id="pit-stuck-0123456789")
    router = (
        Router()
        .on("GET", "/", es_root())
        .on("POST", "/wazuh-alerts-*/_pit", respond(200, {"id": "pit-stuck-0123456789"}))
        .on("POST", "/_search", respond(200, stuck))
        .on("DELETE", "/_pit", respond(200, {}))
    )
    with pytest.raises(RemoteError) as info:
        list(client(router).stream(INDEX, start=START, end=END, page_size=2))
    assert info.value.kind == "protocol"
    assert len(router.calls_to("POST", "/_search")) == 2
    assert router.bodies("DELETE", "/_pit") == [{"id": "pit-stuck-0123456789"}]


def test_composite_cycling_after_keys_stop() -> None:
    router = Router().on(
        "POST",
        "/wazuh-alerts-*/_search",
        respond(200, _agg([{"key": {"ts": H0}, "doc_count": 1}], {"ts": H0})),
        respond(200, _agg([{"key": {"ts": H0 + 1}, "doc_count": 1}], {"ts": H0 + 1})),
        respond(200, _agg([{"key": {"ts": H0}, "doc_count": 1}], {"ts": H0})),
    )
    idx = client(router)
    assert len(list(idx.composite(INDEX, sources=[], start=START, end=END))) == 3
    assert len(router.calls) == 3
    assert [m.key for m in idx.failure_messages] == ["indexer.partial.after_key"]


def test_expired_scroll_context_is_reported_as_incomplete() -> None:
    router = (
        Router()
        .on("GET", "/", os_root("2.19.3"))
        .on("POST", "/wazuh-alerts-*/_search", respond(200, page([alert(1)], _scroll_id="scroll-x-0123456789")))
        .on(
            "POST",
            "/_search/scroll",
            respond(
                404,
                {
                    "error": {
                        "type": "search_context_missing_exception",
                        "reason": "No search context found for id [scroll-x-0123456789]",
                    }
                },
            ),
        )
        .on("DELETE", "/_search/scroll", respond(404, {}))
    )
    idx = client(router)
    with pytest.raises(RemoteError) as info:
        list(idx.stream(INDEX, start=START, end=END))
    err = info.value
    assert err.kind == "partial" and "expired" in str(err) and "5m" in str(err)
    assert "scroll-x-0123456789" not in str(err)
    assert idx.notes == []  # 404 on release: the context was already gone


def test_apply_to_folds_state_into_data_basis_idempotently() -> None:
    from hushwatch.models import DataBasis

    router = (
        Router()
        .on("GET", "/", os_root("2.19.3"))
        .on(
            "POST",
            "/wazuh-alerts-*/_search",
            respond(
                200,
                _shard_failure_page([alert(1), alert(2), {"_id": "z", "_source": 5}], _scroll_id="scroll-b-0123456789"),
            ),
        )
        .on("DELETE", "/_search/scroll", respond(200, {}))
    )
    idx = client(router, verify_tls=False)
    assert len(list(idx.stream(INDEX, start=START, end=END, max_docs=1))) == 1
    basis = DataBasis()
    idx.apply_to(basis)
    idx.apply_to(basis)
    assert len(basis.partial_failures) == 1 and basis.truncated
    assert {getattr(w, "key", None) for w in basis.warnings} == {"net.warn.tls_disabled", "indexer.warn.truncated"}
    assert not basis.complete


# ---- review regressions: cleanup, completeness, size limits ----------------------------------------------------


def test_close_releases_a_suspended_pit_and_a_resumed_stream_fails_loudly() -> None:
    router = (
        Router()
        .on("GET", "/", es_root())
        .on("POST", "/wazuh-alerts-*/_pit", respond(200, {"id": "pit-susp-0123456789"}))
        .on("POST", "/_search", respond(200, page([alert(1), alert(2)], pit_id="pit-susp-9876543210")))
        .on("DELETE", "/_pit", respond(200, {}))
    )
    idx = client(router)
    stream = idx.stream(INDEX, start=START, end=END, page_size=2)
    assert next(stream)["_id"] == "doc-1"
    idx.close()  # the consumer kept the iterator alive: close() must still release the newest PIT id
    assert router.bodies("DELETE", "/_pit") == [{"id": "pit-susp-9876543210"}]
    assert next(stream)["_id"] == "doc-2"  # the page already fetched is still delivered...
    with pytest.raises(RemoteError) as info:
        next(stream)  # ...but the stream never ends quietly as if it were complete
    assert info.value.kind == "partial"
    with pytest.raises(RemoteError):
        idx.count(INDEX)
    idx.close()  # idempotent
    assert len(router.bodies("DELETE", "/_pit")) == 1


def test_close_releases_a_suspended_scroll() -> None:
    router = (
        Router()
        .on("GET", "/", os_root("2.19.3"))
        .on("POST", "/wazuh-alerts-*/_search", respond(200, page([alert(1)], _scroll_id="scroll-susp-0123456789")))
        .on("DELETE", "/_search/scroll", respond(200, {}))
    )
    idx = client(router)
    stream = idx.stream(INDEX, start=START, end=END)
    next(stream)
    with idx:
        pass
    assert router.bodies("DELETE", "/_search/scroll") == [{"scroll_id": ["scroll-susp-0123456789"]}]


def _scroll_page(hits: list[dict[str, Any]], total: int | None, scroll_id: str) -> dict[str, Any]:
    body = page(hits, _scroll_id=scroll_id)
    if total is not None:
        body["hits"]["total"] = {"value": total, "relation": "eq"}
    return body


def test_endless_scroll_repeating_a_page_is_stopped() -> None:
    same = [alert(1), alert(2)]
    router = (
        Router()
        .on("GET", "/", os_root("2.19.3"))
        .on("POST", "/wazuh-alerts-*/_search", respond(200, _scroll_page(same, None, "scroll-loop-0123456789")))
        .on("POST", "/_search/scroll", respond(200, _scroll_page(same, None, "scroll-loop-0123456789")))
        .on("DELETE", "/_search/scroll", respond(200, {}))
    )
    with pytest.raises(RemoteError) as info:
        list(client(router).stream(INDEX, start=START, end=END, page_size=2))
    assert info.value.kind == "protocol"
    assert len(router.calls_to("POST", "/_search/scroll")) == 1
    assert router.bodies("DELETE", "/_search/scroll")


def test_scroll_returning_more_than_its_total_is_stopped() -> None:
    router = (
        Router()
        .on("GET", "/", os_root("2.19.3"))
        .on(
            "POST",
            "/wazuh-alerts-*/_search",
            respond(200, _scroll_page([alert(1), alert(2)], 3, "scroll-over-0123456789")),
        )
        .on(
            "POST",
            "/_search/scroll",
            respond(200, _scroll_page([alert(3), alert(4)], None, "scroll-over-0123456789")),
            respond(200, _scroll_page([alert(5), alert(6)], None, "scroll-over-0123456789")),
        )
        .on("DELETE", "/_search/scroll", respond(200, {}))
    )
    got: list[dict[str, Any]] = []
    with pytest.raises(RemoteError) as info:
        for doc in client(router).stream(INDEX, start=START, end=END, page_size=2):
            got.append(doc)
    assert info.value.kind == "protocol" and len(got) == 2


def test_scroll_ending_short_of_its_total_is_a_partial_failure() -> None:
    router = (
        Router()
        .on("GET", "/", os_root("2.19.3"))
        .on("POST", "/wazuh-alerts-*/_search", respond(200, _scroll_page([alert(1)], 5, "scroll-short-0123456789")))
        .on("POST", "/_search/scroll", respond(200, _scroll_page([], None, "scroll-short-0123456789")))
        .on("DELETE", "/_search/scroll", respond(200, {}))
    )
    idx = client(router)
    assert len(list(idx.stream(INDEX, start=START, end=END))) == 1
    assert [m.key for m in idx.failure_messages] == ["indexer.partial.scroll_short"]
    assert "1 of the 5" in idx.partial_failures[0]
    assert "1 de los 5" in i18n.render(idx.failure_messages[0], "es")


def test_scroll_matching_its_total_is_clean_even_with_malformed_hits() -> None:
    router = (
        Router()
        .on("GET", "/", os_root("2.19.3"))
        .on(
            "POST",
            "/wazuh-alerts-*/_search",
            respond(200, _scroll_page([alert(1), "junk", alert(2)], 3, "scroll-ok-0123456789")),  # type: ignore[list-item]
        )
        .on("POST", "/_search/scroll", respond(200, _scroll_page([], None, "scroll-ok-0123456789")))
        .on("DELETE", "/_search/scroll", respond(200, {}))
    )
    idx = client(router)
    assert len(list(idx.stream(INDEX, start=START, end=END))) == 2
    assert idx.partial_failures == [] and idx.malformed == 1


def test_composite_on_a_pattern_matching_no_index_is_empty_with_a_warning() -> None:
    no_shards = {
        "took": 0,
        "timed_out": False,
        "_shards": {"total": 0, "successful": 0, "skipped": 0, "failed": 0},
        "hits": {"total": {"value": 0, "relation": "eq"}, "max_score": 0.0, "hits": []},
    }
    router = Router().on("POST", "/wazuh-archives-*/_search", respond(200, no_shards))
    idx = client(router)
    assert list(idx.composite("wazuh-archives-*", sources=[], start=START, end=END)) == []
    assert [w.key for w in idx.warnings] == ["indexer.warn.no_indices"]
    assert idx.partial_failures == []


@pytest.mark.parametrize("shape", ["content-length", "chunked", "gzip"])
def test_oversized_response_is_refused_not_buffered(shape: str) -> None:
    import gzip

    limit = 64 * 1024
    big = b'{"count": 1, "pad": "' + b"x" * (limit * 4) + b'"}'

    def handler(request: httpx.Request) -> httpx.Response:
        if shape == "chunked":
            return httpx.Response(200, content=iter([big[i : i + 4096] for i in range(0, len(big), 4096)]))
        if shape == "gzip":
            return httpx.Response(200, content=gzip.compress(big), headers={"Content-Encoding": "gzip"})
        return httpx.Response(200, content=big)

    idx = IndexerClient(
        url="https://indexer.example:9200", transport=httpx.MockTransport(handler), max_response_bytes=limit
    )
    with pytest.raises(RemoteError) as info:
        idx.count(INDEX)
    assert info.value.kind == "protocol" and "MiB" in str(info.value) and "MiB" in info.value.render("es")


def test_gzip_response_within_the_limit_is_decoded() -> None:
    import gzip

    body = json.dumps({"count": 7, "_shards": {"total": 1, "successful": 1, "failed": 0}}).encode()

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=gzip.compress(body), headers={"Content-Encoding": "gzip"})

    idx = IndexerClient(url="https://indexer.example:9200", transport=httpx.MockTransport(handler))
    assert idx.count(INDEX) == 7


def test_plain_http_is_a_warning() -> None:
    idx = client(Router(), url="http://10.0.0.5:9200")
    assert [w.key for w in idx.warnings] == ["net.warn.plain_http"]
