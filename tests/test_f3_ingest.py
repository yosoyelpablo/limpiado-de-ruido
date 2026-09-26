"""Regression tests for the ingest fixes of the system review (F3): the cheap backtest pass (``iter_rules``),
files skipped in input directories, events excluded by the time window, translatable partial failures and the
Wazuh 4 fast normalization path.

Synthetic data only (``*.example`` hosts, RFC 1918 / 5737 addresses).
"""

from __future__ import annotations

import gzip
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import httpx
import pytest

from hushwatch.config import ApiConfig, InputConfig, TenantConfig
from hushwatch.i18n import Entity, M, Message, render
from hushwatch.ingest import files as files_mod
from hushwatch.ingest import open_files, rule_line_filter
from hushwatch.ingest import profiles as profiles_mod
from hushwatch.models import DataBasis
from hushwatch.net import sanitize_message

UTC = timezone.utc
TENANT = TenantConfig(name="acme")
FIXTURES = Path(__file__).parent / "fixtures" / "ingest"
START = datetime(2026, 9, 1, tzinfo=UTC)


def alert(i: int, rule_id: str, *, level: int = 5, agent: str = "srv-web-01.example", **extra: Any) -> dict[str, Any]:
    ts = (START + timedelta(minutes=7 * i)).strftime("%Y-%m-%dT%H:%M:%S.000+0000")
    doc: dict[str, Any] = {
        "timestamp": ts,
        "rule": {"level": level, "description": "synthetic", "id": rule_id, "groups": ["syslog"]},
        "agent": {"id": "001", "name": agent},
        "manager": {"name": "wazuh-manager"},
        "id": f"{1788000000 + i}.{i * 331}",
        "decoder": {"name": "sshd"},
        "data": {"srcip": f"10.0.{i % 7}.{i % 200}", "srcport": str(40000 + i)},
        "location": "/var/log/auth.log",
    }
    doc.update(extra)
    return doc


def write_ndjson(path: Path, docs: list[dict[str, Any]], gz: bool = False) -> Path:
    data = b"".join(json.dumps(d, separators=(",", ":")).encode() + b"\n" for d in docs)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(gzip.compress(data) if gz else data)
    return path


def mixed_docs(n: int = 600, seed: int = 3) -> list[dict[str, Any]]:
    rng = random.Random(seed)
    rules = ["550", "5501", "5502", "5710", "60106", "31115"]
    return [alert(i, rng.choice(rules)) for i in range(n)]


def snapshot(events: Any) -> list[tuple[Any, ...]]:
    return [(e.ts, e.rule_id, e.event_id, e.source, tuple(sorted(e.fields.items()))) for e in events]


# ---- iter_rules: the backtest pass reads only what it needs -------------------------------------------------------


@pytest.mark.parametrize("gz", [False, True])
def test_iter_rules_yields_exactly_the_full_pass_events_of_those_rules(tmp_path: Path, gz: bool) -> None:
    path = write_ndjson(tmp_path / "alerts.json", mixed_docs(), gz=gz)
    source = open_files([path], tenant=TENANT)
    wanted = {"550", "60106"}
    full = snapshot(e for e in source if e.rule_id in wanted)
    basis = source.basis
    fast = snapshot(source.iter_rules(wanted))
    assert full and fast == full
    assert source.basis is basis  # the second pass never rewrites the data basis
    # "550" must not match "5501"/"5502" (substring pitfalls), and nothing else leaks in
    assert {row[1] for row in fast} == wanted


def test_iter_rules_honours_the_time_window_and_auto_profile(tmp_path: Path) -> None:
    path = write_ndjson(tmp_path / "alerts.json", mixed_docs())
    since, until = START + timedelta(hours=10), START + timedelta(hours=40)
    source = open_files([path], tenant=TENANT, since=since, until=until)
    full = snapshot(e for e in source if e.rule_id == "5710")
    assert full and all(since <= row[0] < until for row in full)
    assert snapshot(source.iter_rules(["5710"])) == full


def test_iter_rules_with_max_events_follows_the_full_pass(tmp_path: Path) -> None:
    path = write_ndjson(tmp_path / "alerts.json", mixed_docs())
    source = open_files([path], tenant=TENANT, max_events=100)
    full = snapshot(e for e in source if e.rule_id == "5710")
    basis = source.basis
    assert snapshot(source.iter_rules({"5710"})) == full
    assert source.basis is basis


def test_iter_rules_reads_generic_numeric_rule_ids(tmp_path: Path) -> None:
    docs = [
        {"@timestamp": (START + timedelta(minutes=i)).isoformat(), "host": "h1.example", "signature_id": sid}
        for i, sid in enumerate([5710, 57101, 15710, 5710.0, "5710", [5710, 1]])
    ]
    path = write_ndjson(tmp_path / "export.ndjson", docs)
    cfg = InputConfig(path=str(path), profile="generic", mapping={"rule_id": "signature_id", "source": "host"})
    source = open_files([path], tenant=TENANT, profile="generic", input_cfg=cfg)
    full = snapshot(e for e in source if e.rule_id == "5710")
    assert len(full) == 4  # 5710, 5710.0, "5710", [5710, ...]
    assert snapshot(source.iter_rules({"5710"})) == full


def test_iter_rules_parses_every_line_for_ids_json_could_escape(tmp_path: Path) -> None:
    docs = [alert(i, 'rule "a"/b') for i in range(5)] + [alert(9, "5710")]
    path = write_ndjson(tmp_path / "alerts.json", docs)
    source = open_files([path], tenant=TENANT)
    assert rule_line_filter(['rule "a"/b']) is None
    assert len(list(source.iter_rules(['rule "a"/b']))) == 5


def test_rule_line_filter_is_a_superset_test() -> None:
    keep = rule_line_filter({"550", "5710"})
    assert keep is not None
    assert keep(b'{"rule":{"id":"550","level":7}}\n')
    assert keep(b'{"rule":{"id": "5710"}}\n')
    assert keep(b'{"rule_id": 5710, "x": 1}\n') and keep(b'{"ids":[550]}\n') and keep(b'{"id":550.0}\n')
    assert not keep(b'{"rule":{"id":"5501"},"id":"1788000550.5501"}\n')
    assert not keep(b'{"rule":{"id":"15710"},"data":{"srcport":"57101"}}\n')
    strings_only = rule_line_filter({"5710"}, numbers=False)
    assert strings_only is not None and not strings_only(b'{"rule_id": 5710}\n')


def test_iter_rules_skips_unparsed_lines_cheaply(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = write_ndjson(tmp_path / "alerts.json", mixed_docs(900))
    source = open_files([path], tenant=TENANT, profile="wazuh4")
    parsed = 0
    real = files_mod._loads

    def counting(data: bytes) -> Any:
        nonlocal parsed
        parsed += 1
        return real(data)

    monkeypatch.setattr(files_mod, "_loads", counting)
    events = list(source.iter_rules({"31115"}))
    assert events and parsed == len(events)  # only the lines of the wanted rule were JSON-decoded


# ---- directories: nothing is skipped silently ----------------------------------------------------------------------


def test_directories_read_json_logs_whatever_their_extension_and_list_the_rest(tmp_path: Path) -> None:
    base = tmp_path / "exports"
    write_ndjson(base / "a.json", [alert(0, "5710")])
    write_ndjson(base / "b.jsonl", [alert(1, "5710")])
    write_ndjson(base / "c.ndjson", [alert(2, "5710")])
    write_ndjson(base / "d.log", [alert(3, "5710")])  # NDJSON with a .log name: sniffed and read
    write_ndjson(base / "e", [alert(4, "5710")])  # no extension
    write_ndjson(base / "f.log.gz", [alert(5, "5710")], gz=True)
    (base / "notes.txt").write_text("not events\n", encoding="utf-8")
    (base / "g.bin").write_bytes(bytes(range(256)))
    (base / ".hidden.json").write_text("{}", encoding="utf-8")
    source = open_files([base], tenant=TENANT)
    assert len(list(source)) == 6
    skipped = sorted(Path(p).name for p in source.basis.skipped_files)
    assert skipped == ["g.bin", "notes.txt"]  # hidden files are never data and are not listed
    warning = next(w for w in source.basis.warnings if isinstance(w, Message) and w.key == "ingest.warn.skipped_files")
    assert warning.params["count"] == 2
    assert "2 file(s)" in render(warning) and "2 archivo(s)" in render(warning, "es")


def test_wazuh_plain_text_and_checksum_twins_are_skipped_silently(tmp_path: Path) -> None:
    day = tmp_path / "alerts" / "2026" / "Sep"
    write_ndjson(day / "ossec-alerts-02.json.gz", [alert(0, "5710")], gz=True)
    (day / "ossec-alerts-02.log.gz").write_bytes(gzip.compress(b"** Alert 1788.1: - syslog,sshd\n"))
    (day / "ossec-alerts-02.json.sum").write_text("sha1 abc\n", encoding="utf-8")
    (day / "ossec-alerts-03.log").write_text("** Alert 1789.1: - syslog\n", encoding="utf-8")  # no JSON twin
    source = open_files([tmp_path / "alerts"], tenant=TENANT)
    assert len(list(source)) == 1
    assert [Path(p).name for p in source.basis.skipped_files] == ["ossec-alerts-03.log"]


def test_glob_matches_are_sniffed_too(tmp_path: Path) -> None:
    write_ndjson(tmp_path / "x.log", [alert(0, "5710")])
    (tmp_path / "y.log").write_text("plain text\n", encoding="utf-8")
    source = open_files([str(tmp_path / "*.log")], tenant=TENANT)
    assert len(list(source)) == 1
    assert [Path(p).name for p in source.basis.skipped_files] == ["y.log"]


# ---- time window: excluded events are counted -----------------------------------------------------------------------


def test_events_outside_since_until_are_counted_in_the_basis(tmp_path: Path) -> None:
    path = write_ndjson(tmp_path / "alerts.json", [alert(i, "5710") for i in range(100)])
    since = START + timedelta(minutes=7 * 30)
    until = START + timedelta(minutes=7 * 80)
    source = open_files([path], tenant=TENANT, since=since, until=until)
    events = list(source)
    assert len(events) == 50
    assert source.basis.events == 50 and source.basis.excluded_by_window == 50
    assert source.basis.excluded_newest == START + timedelta(minutes=7 * 99)  # the newest event left out
    unbounded = open_files([path], tenant=TENANT)
    list(unbounded)
    assert unbounded.basis.excluded_by_window == 0


# ---- partial failures are translatable ---------------------------------------------------------------------------


def test_file_partial_failures_are_messages_in_both_languages(tmp_path: Path) -> None:
    path = tmp_path / "alerts.json.bz2"
    path.write_bytes(b"BZh91AY&SY" + bytes(64))
    source = open_files([path], tenant=TENANT)
    list(source)
    [failure] = source.basis.partial_failures
    assert isinstance(failure, Message) and failure.key == "ingest.failure"
    assert render(failure).startswith(f"{path}: unsupported compression (bzip2)")
    assert "compresión no soportada" in render(failure, "es")
    assert isinstance(failure.params["file"], Entity)  # a path: pseudonymized with --redact


def test_indexer_and_api_fold_translatable_failures_into_the_basis() -> None:
    from hushwatch.ingest.opensearch import IndexerClient
    from hushwatch.ingest.wazuh_api import WazuhAPI

    idx = IndexerClient(
        InputConfig(type="indexer", url="https://indexer.example:9200", username="hw", password="S3cretPass!"),
        transport=httpx.MockTransport(lambda request: httpx.Response(500)),
    )
    idx._record(M("indexer.partial.shards", op="search", index="wazuh-*", failed=2, total=3, reason="x S3cretPass!"))
    basis = DataBasis()
    idx.apply_to(basis)
    idx.apply_to(basis)  # idempotent
    [failure] = basis.partial_failures
    assert isinstance(failure, Message) and failure.key == "indexer.partial.shards"
    assert "S3cretPass!" not in render(failure) and "***" in render(failure)
    assert "fallaron 2 de 3 shards" in render(failure, "es")
    api = WazuhAPI(
        ApiConfig(url="https://manager.example:55000", username="wazuh", password="S3cretPass!"),
        transport=httpx.MockTransport(lambda request: httpx.Response(500)),
    )
    api._record(M("wazuh_api.partial.flagged", op="agents S3cretPass!", code=1))
    api.apply_to(basis)
    assert len(basis.partial_failures) == 2 and isinstance(basis.partial_failures[1], Message)
    assert "S3cretPass!" not in render(basis.partial_failures[1])


def test_sanitize_message_cleans_nested_params_and_entities() -> None:
    msg = M(
        "x.outer",
        reason=M("x.inner", detail="token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig\x07 secret123"),
        host=Entity("host", "h1‮.example"),
        items=["a secret123", 3],
        count=4,
    )
    clean = sanitize_message(msg, secrets=["secret123"])
    assert clean.params["count"] == 4
    inner = clean.params["reason"].params["detail"]
    assert "secret123" not in inner and "eyJ…[token]" in inner and "\x07" not in inner
    assert clean.params["host"] == Entity("host", "h1 .example")
    assert clean.params["items"] == ["a ***", 3]


# ---- the Wazuh 4 fast path equals the extractor path ---------------------------------------------------------------


def _slow_wazuh4(doc: dict[str, Any]) -> Any:
    _, mapper = profiles_mod._MAPPERS["wazuh4"]
    ctx = profiles_mod._Ctx(profiles_mod.zone(None), None, {})
    return mapper(profiles_mod._W4_EXTRACTOR.extract(profiles_mod._Doc(doc)), ctx)


def _fixture_docs() -> list[dict[str, Any]]:
    docs: list[dict[str, Any]] = []
    for name in ("wazuh4_alerts.json", "wazuh4_archives.json"):
        for line in (FIXTURES / name).read_text(encoding="utf-8").splitlines():
            if line.strip():
                try:
                    value = json.loads(line)
                except ValueError:
                    continue
                if isinstance(value, dict):
                    docs.append(value)
    return docs


def test_wazuh4_flat_fast_path_normalizes_exactly_like_the_extractor() -> None:
    docs = _fixture_docs() + mixed_docs(50)
    docs.append(alert(1, "5710", agent={"id": "000", "name": "wazuh-manager"}, predecoder={"hostname": "fw.example"},
                      location="10.10.0.1"))  # fmt: skip
    docs.append(alert(2, "5710", **{"rule": {"id": "5710", "level": "7", "mitre": {"id": ["T1110"]}}}))
    docs.append({"timestamp": "2026-09-01T00:00:00.000+0000", "rule.id": "5710", "agent.name": "flat.example"})
    fast = profiles_mod.bind("wazuh4")
    assert len(docs) > 50
    for doc in docs:
        a, b = fast(doc), _slow_wazuh4(doc)
        if a is None or b is None:
            assert a is b is None
            continue
        a.fields, b.fields = {}, {}
        assert a == b, doc
