"""Tests for hushwatch.ingest (file sources): formats, layouts, DataBasis accounting, hostile input, streaming."""

from __future__ import annotations

import gzip
import json
import os
import random
import shutil
import time
import tracemalloc
from collections.abc import Iterable
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from hushwatch.config import InputConfig, TenantConfig
from hushwatch.i18n import M, render
from hushwatch.i18n import keys as message_keys
from hushwatch.ingest import EventSource, FileEventSource, IngestError, ReadStats, iter_documents, open_files
from hushwatch.ingest import files as files_mod
from hushwatch.ingest.files import rotated_date
from hushwatch.models import Event, flatten

UTC = timezone.utc
FIXTURES = Path(__file__).parent / "fixtures" / "ingest"
TENANT = TenantConfig()


def _alert(ts: str, rule_id: str = "5710", agent: str = "srv-web-01.example", level: int = 5, **extra: Any) -> dict:
    doc: dict[str, Any] = {
        "timestamp": ts,
        "rule": {"level": level, "description": "synthetic rule", "id": rule_id, "groups": ["syslog", "sshd"]},
        "agent": {"id": "001", "name": agent, "ip": "10.0.0.20"},
        "manager": {"name": "wazuh-manager"},
        "id": f"{ts}.{rule_id}",
        "decoder": {"name": "sshd"},
        "data": {"srcip": "10.0.0.5", "srcuser": "alice"},
        "location": "/var/log/auth.log",
    }
    doc.update(extra)
    return doc


def _archive(ts: str, agent: str = "srv-web-01.example") -> dict:
    doc = _alert(ts, agent=agent)
    del doc["rule"]
    doc["full_log"] = "Sep 10 10:00:00 srv-web-01 CRON[1]: session opened"
    return doc


def _ndjson(docs: Iterable[dict]) -> bytes:
    return b"".join(json.dumps(d, separators=(",", ":")).encode() + b"\n" for d in docs)


def _write(path: Path, data: bytes, gz: bool = False) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(gzip.compress(data) if gz else data)
    return path


def _keys(messages: Iterable[Any]) -> list[str]:
    return [getattr(m, "key", str(m)) for m in messages]


def _open(paths: Any, **kwargs: Any) -> FileEventSource:
    kwargs.setdefault("tenant", TENANT)
    return open_files(paths, **kwargs)


# ---- fixtures and DataBasis -----------------------------------------------------------------------------------


def test_wazuh_alerts_fixture_basis() -> None:
    source = _open([FIXTURES / "wazuh4_alerts.json"])
    assert isinstance(source, EventSource)
    events = list(source)
    assert [e.rule_id for e in events] == ["5710", "60106", "92052", "4101", "550"]
    basis = source.basis
    assert basis.input_kind == "alerts"
    assert basis.profile == "wazuh4"
    assert basis.events == 5 and basis.malformed == 0 and basis.bad_timestamps == 0
    assert basis.sources == [str(FIXTURES / "wazuh4_alerts.json")]
    assert basis.start == datetime(2026, 9, 10, 10, 15, 32, 481000, tzinfo=UTC)
    assert basis.end == datetime(2026, 9, 10, 10, 45, 12, 4000, tzinfo=UTC)
    assert basis.now == basis.end and basis.now_origin == "data"
    assert not basis.truncated and not basis.partial_failures and basis.complete
    assert "ingest.warn.alerts_only_wazuh" in _keys(basis.warnings)
    for lang in ("en", "es"):
        text = render(basis.warnings[0], lang)
        assert "log_alert_level" in text and "logall_json" in text


def test_archives_fixture_is_full_fidelity() -> None:
    source = _open(FIXTURES / "wazuh4_archives.json")
    events = list(source)
    assert len(events) == 3
    assert sum(e.rule_id is None for e in events) == 2
    assert source.basis.input_kind == "archives"
    assert "ingest.warn.alerts_only_wazuh" not in _keys(source.basis.warnings)


def test_alerts_plus_archives_is_mixed_with_warning() -> None:
    source = _open([FIXTURES / "wazuh4_alerts.json", FIXTURES / "wazuh4_archives.json"])
    assert len(list(source)) == 8
    assert source.basis.input_kind == "mixed"
    assert "ingest.warn.mixed_kinds" in _keys(source.basis.warnings)


def test_archives_filename_hint_wins(tmp_path: Path) -> None:
    path = _write(tmp_path / "archives.json", _ndjson([_alert("2026-09-10T10:00:00.000+0000")]))
    source = _open(path)
    list(source)
    assert source.basis.input_kind == "archives"


def test_ecs_alerts_fixture() -> None:
    source = _open(FIXTURES / "ecs_alerts.ndjson")
    events = list(source)
    assert [e.severity for e in events] == [7, 10]
    assert source.basis.profile == "ecs" and source.basis.input_kind == "alerts"
    assert "ingest.warn.alerts_only" in _keys(source.basis.warnings)
    assert "ingest.warn.alerts_only_wazuh" not in _keys(source.basis.warnings)


def test_generic_csv_with_mapping_from_tenant_inputs() -> None:
    path = str(FIXTURES / "generic_export.csv")
    cfg = InputConfig(
        path=path,
        profile="generic",
        naive_timezone="Europe/Madrid",
        mapping={"ts": "when", "source": "box", "rule_id": "sig", "rule_name": "sig_name", "severity": "sev"},
    )
    source = _open(path, profile="generic", tenant=TenantConfig(inputs=[cfg]))  # input_cfg found by path
    events = list(source)
    assert [e.ts.hour for e in events] == [8, 9, 10]  # CEST -> UTC
    assert events[2].rule_name == "Login failure; bad password"  # quoted delimiter inside a field
    assert events[2].severity == 8
    assert events[0].fields["client"] == "10.0.2.10"  # CSV values stay strings
    assert events[0].entities["user"] == "svc_backup"  # heuristic "account" column
    assert source.basis.profile == "generic" and source.basis.input_kind == "alerts"


def test_generic_mapping_unknown_keys_warn(tmp_path: Path) -> None:
    path = _write(tmp_path / "x.csv", b"when,host\n2026-09-10T10:00:00Z,srv-web-01.example\n")
    cfg = InputConfig(mapping={"ts": "when", "colour": "host"})
    source = _open(path, profile="generic", input_cfg=cfg)
    assert len(list(source)) == 1
    warning = next(w for w in source.basis.warnings if getattr(w, "key", "") == "ingest.warn.mapping_unknown")
    assert "colour" in render(warning, "es")


def test_tsv_and_crlf_and_semicolon(tmp_path: Path) -> None:
    tsv = _write(tmp_path / "a.tsv", b"time\thost\trule_id\r\n2026-09-10T10:00:00Z\tsrv-web-01.example\tR1\r\n")
    semi = _write(tmp_path / "b.csv", b"time;host;rule_id\n2026-09-10T11:00:00Z;srv-db-01.example;R2\n")
    events = list(_open([tsv, semi], profile="generic"))
    assert [(e.source, e.rule_id) for e in events] == [("srv-web-01.example", "R1"), ("srv-db-01.example", "R2")]


def test_csv_bad_rows_are_counted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(files_mod, "MAX_CSV_LINE_CHARS", 64)
    data = (
        "time,host\n"
        "2026-09-10T10:00:00Z,srv-web-01.example\n"
        f"2026-09-10T10:01:00Z,{'x' * 500}\n"  # over-long line
        ",\n"  # empty row: skipped silently
        "2026-09-10T10:02:00Z,srv-web-01.example,extra,columns\n"
        "not a date,srv-web-01.example\n"
    )
    source = _open(_write(tmp_path / "r.csv", data.encode()), profile="generic")
    assert len(list(source)) == 2
    assert source.basis.malformed == 1
    assert source.basis.bad_timestamps == 1


# ---- compression, encodings, layouts --------------------------------------------------------------------------


def test_gzip_detected_by_magic_bytes(tmp_path: Path) -> None:
    docs = [_alert(f"2026-09-10T10:0{i}:00.000+0000") for i in range(5)]
    plain = _write(tmp_path / "plain.json", _ndjson(docs))
    gz = _write(tmp_path / "packed.json.gz", _ndjson(docs), gz=True)
    disguised = _write(tmp_path / "disguised.json", _ndjson(docs), gz=True)  # gzip without .gz suffix
    expected = [e.ts for e in _open(plain)]
    assert [e.ts for e in _open(gz)] == expected
    assert [e.ts for e in _open(disguised)] == expected


def test_csv_gz(tmp_path: Path) -> None:
    path = _write(tmp_path / "x.csv.gz", b"time,host\n2026-09-10T10:00:00Z,srv-web-01.example\n", gz=True)
    assert [e.source for e in _open(path, profile="generic")] == ["srv-web-01.example"]


def test_bom_tolerated_everywhere(tmp_path: Path) -> None:
    bom = b"\xef\xbb\xbf"
    ndjson = _write(tmp_path / "a.json", bom + _ndjson([_alert("2026-09-10T10:00:00.000+0000")]))
    array = _write(tmp_path / "b.json", bom + json.dumps([_alert("2026-09-10T10:01:00.000+0000")]).encode())
    csv_file = _write(tmp_path / "c.csv", bom + b"time,host\n2026-09-10T10:02:00Z,srv-web-01.example\n")
    # a BOM in the middle of a concatenation (cat a.json b.json) is tolerated too
    concat = _write(tmp_path / "d.json", ndjson.read_bytes() + ndjson.read_bytes())
    source = _open([ndjson, array, concat])
    assert len(list(source)) == 4 and source.basis.malformed == 0
    csv_source = _open(csv_file, profile="generic")
    assert [e.source for e in csv_source] == ["srv-web-01.example"]


def test_utf16_with_bom(tmp_path: Path) -> None:
    text = _ndjson([_alert("2026-09-10T10:00:00.000+0000", agent="srv-ñandú-01")]).decode()
    path = _write(tmp_path / "u16.json", text.encode("utf-16"))
    csv_path = _write(tmp_path / "u16.csv", "time,host\n2026-09-10T10:00:00Z,srv-web-01\n".encode("utf-16"))
    assert [e.source for e in _open(path)] == ["srv-ñandú-01"]
    assert [e.source for e in _open(csv_path, profile="generic")] == ["srv-web-01"]


def test_rotated_layout_order_links_and_pruning(tmp_path: Path) -> None:
    root = tmp_path / "logs" / "alerts"
    for day in (1, 2, 3, 4, 5):
        docs = [_alert(f"2026-09-{day:02d}T{h:02d}:00:00.000+0000") for h in (0, 12)]
        _write(root / "2026" / "Sep" / f"ossec-alerts-{day:02d}.json.gz", _ndjson(docs), gz=True)
        _write(root / "2026" / "Sep" / f"ossec-alerts-{day:02d}.json.sum", b"checksum")
        _write(root / "2026" / "Sep" / f"ossec-alerts-{day:02d}.log.gz", b"plain text alerts", gz=True)
    _write(root / "2026" / "Aug" / "ossec-alerts-31.json.gz", _ndjson([_alert("2026-08-31T10:00:00.000+0000")]), True)
    today = _write(root / "2026" / "Sep" / "ossec-alerts-06.json", _ndjson([_alert("2026-09-06T01:00:00.000+0000")]))
    os.link(today, root / "alerts.json")  # Wazuh's live alerts.json is a link to today's file
    _write(root / ".hidden.json", b"garbage\n")

    source = _open(root)
    names = [Path(p).name for p in source.files]
    assert names == [
        "ossec-alerts-31.json.gz",
        *[f"ossec-alerts-{d:02d}.json.gz" for d in (1, 2, 3, 4, 5)],
        "alerts.json",  # same inode as ossec-alerts-06.json: read once
    ]
    events = list(source)
    assert len(events) == 12
    assert [e.ts for e in events] == sorted(e.ts for e in events)  # chronological, not Apr/Aug/Dec...
    assert source.basis.malformed == 0

    # --since prunes rotated files by their path date without opening them
    (root / "2026" / "Aug" / "ossec-alerts-31.json.gz").write_bytes(b"\x1f\x8bcorrupt")
    pruned = _open(root, since=datetime(2026, 9, 4, 0, 0, tzinfo=UTC))
    assert [Path(p).name for p in pruned.files] == [
        "ossec-alerts-03.json.gz",  # kept: a manager at UTC-12 writes events up to Sep 4 12:00 UTC into it
        "ossec-alerts-04.json.gz",
        "ossec-alerts-05.json.gz",
        "alerts.json",
    ]
    events = list(pruned)
    assert all(e.ts >= datetime(2026, 9, 4, tzinfo=UTC) for e in events)
    assert len(events) == 5
    assert not pruned.basis.partial_failures


def test_rotated_date_parser() -> None:
    assert rotated_date("/var/ossec/logs/alerts/2026/Sep/ossec-alerts-25.json.gz") == datetime(2026, 9, 25).date()
    assert rotated_date("/var/ossec/logs/archives/2026/Feb/ossec-archive-01.json") == datetime(2026, 2, 1).date()
    assert rotated_date("alerts/2026/Feb/ossec-alerts-30.json") is None  # impossible date
    assert rotated_date("alerts/2026/Sept/ossec-alerts-01.json") is None
    assert rotated_date("ossec-alerts-01.json") is None


def test_uncompressed_sibling_wins_over_gz(tmp_path: Path) -> None:
    docs = _ndjson([_alert("2026-09-10T10:00:00.000+0000")])
    _write(tmp_path / "d" / "ossec-alerts-10.json", docs)
    _write(tmp_path / "d" / "ossec-alerts-10.json.gz", docs[: len(docs) // 2], gz=True)  # mid-compression
    source = _open(tmp_path / "d")
    assert [Path(p).name for p in source.files] == ["ossec-alerts-10.json"]
    assert len(list(source)) == 1 and not source.basis.partial_failures


def test_glob_and_single_path_string(tmp_path: Path) -> None:
    for i in range(3):
        _write(tmp_path / f"part{i}.json", _ndjson([_alert(f"2026-09-10T10:0{i}:00.000+0000")]))
    _write(tmp_path / "notes.txt", b"not data")
    source = _open(str(tmp_path / "part*.json"))
    assert len(list(source)) == 3
    assert len(list(_open(str(tmp_path / "*")))) == 3  # glob results are filtered to data files
    assert len(list(_open(str(tmp_path / "part0.json")))) == 1  # a bare string is one path, not characters


def test_explicit_file_with_any_extension(tmp_path: Path) -> None:
    path = _write(tmp_path / "export.txt", _ndjson([_alert("2026-09-10T10:00:00.000+0000")]))
    assert len(list(_open(path))) == 1


# ---- malformed input ------------------------------------------------------------------------------------------


def test_malformed_lines_counted_partial_last_line_tolerated(tmp_path: Path) -> None:
    good = _ndjson([_alert("2026-09-10T10:00:00.000+0000"), _alert("2026-09-10T10:01:00.000+0000")])
    data = (
        good
        + b"\n   \n"  # blank lines: ignored
        + b"{not json}\n"
        + b"[1, 2, 3]\n"  # valid JSON, not an object
        + b'"just a string"\n'
        + good
        + b'{"timestamp":"2026-09-10T10:02:00.000+0000","rule":{"id":"57'  # writer is mid-line
    )
    source = _open(_write(tmp_path / "alerts.json", data))
    assert len(list(source)) == 4
    assert source.basis.malformed == 3
    assert source.basis.events == 4


def test_overlong_line_is_skipped_with_bounded_memory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(files_mod, "MAX_LINE_BYTES", 4096)
    huge = json.dumps(_alert("2026-09-10T10:00:00.000+0000", full_log="x" * 50_000)).encode()
    data = _ndjson([_alert("2026-09-10T09:00:00.000+0000")]) + huge + b"\n" + _ndjson([_alert("2026-09-10T11:00:00Z")])
    source = _open(_write(tmp_path / "alerts.json", data))
    assert [e.ts.hour for e in source] == [9, 11]
    assert source.basis.malformed == 1


def test_hostile_json_lines(tmp_path: Path) -> None:
    deep = b"[" * 100_000 + b"]" * 100_000
    lines = [
        deep,
        b'{"timestamp":"2026-09-10T10:00:00Z","rule":{"id":"1","level":NaN},"agent":{"id":"001","name":"a"}}',
        b'{"timestamp":"2026-09-10T10:00:01Z","rule":{"id":"2","level":1e999},"agent":{"id":"001","name":"b"}}',
        b'{"timestamp":"2026-09-10T10:00:02Z","rule":{"id":"3","level":' + b"9" * 5000 + b'},"agent":{"id":"1"}}',
        # invalid UTF-8 in an attacker-controlled value must not drop the event
        b'{"timestamp":"2026-09-10T10:00:03Z","rule":{"id":"4","level":5},"agent":{"id":"001","name":"c\xff\xfe"}}',
        # lone surrogate escape: would crash every UTF-8 writer downstream if kept
        b'{"timestamp":"2026-09-10T10:00:04Z","rule":{"id":"5","level":5},"data":{"srcuser":"x\\ud800y"},'
        b'"agent":{"id":"001","name":"d"}}',
        b'{"timestamp":"2026-09-10T10:00:05Z","rule":{"id":"6","level":5},"agent":{"id":"001","name":"e"},'
        b'"data":{"srcuser":"\\u0000\\u001b[31m<script>"}}',
    ]
    source = _open(_write(tmp_path / "alerts.json", b"\n".join(lines) + b"\n"), profile="wazuh4")
    events = {e.rule_id: e for e in source}
    assert sorted(events) == ["1", "2", "4", "5", "6"]
    assert source.basis.malformed == 2  # deep nesting + beyond the int digit limit
    assert events["1"].severity is None and events["2"].severity is None
    assert events["4"].source == "c\ufffd\ufffd"
    user = events["5"].entities["user"]
    user.encode("utf-8")  # scrubbed: encodable
    assert user.startswith("x") and user.endswith("y")
    assert events["6"].entities["user"] == "\x00\x1b[31m<script>"  # kept raw: escaping is the sinks' job


def test_non_string_keys_and_weird_documents(tmp_path: Path) -> None:
    lines = [
        b"{}",
        b'{"timestamp": null}',
        b'{"timestamp": {"$date": "2026-09-10"}}',
        b'{"": "", "timestamp": "2026-09-10T10:00:00Z", "rule": []}',
    ]
    source = _open(_write(tmp_path / "w.json", b"\n".join(lines) + b"\n"), profile="wazuh4")
    events = list(source)
    assert len(events) == 1 and events[0].rule_id is None
    assert source.basis.bad_timestamps == 3
    assert source.basis.malformed == 0


def test_unparseable_timestamps_counted_and_explained(tmp_path: Path) -> None:
    docs = [{"when": "yesterday-ish", "host": "srv-web-01.example"} for _ in range(4)]
    source = _open(_write(tmp_path / "g.json", _ndjson(docs)), profile="generic")
    assert list(source) == []
    assert source.basis.bad_timestamps == 4 and source.basis.events == 0
    assert "ingest.warn.no_timestamp" in _keys(source.basis.warnings)


def test_future_timestamps_counted_but_do_not_move_now(tmp_path: Path) -> None:
    docs = [
        _alert("2026-09-10T10:00:00.000+0000"),
        _alert("2026-09-10T11:00:00.000+0000"),
        _alert("2099-01-01T00:00:00.000+0000"),  # clock-skewed source
    ]
    source = _open(_write(tmp_path / "alerts.json", _ndjson(docs)))
    events = list(source)
    assert len(events) == 3  # still yielded
    assert source.basis.future_timestamps == 1
    assert source.basis.end == datetime(2099, 1, 1, tzinfo=UTC)
    assert source.basis.now == datetime(2026, 9, 10, 11, 0, tzinfo=UTC)


def test_future_relative_to_injected_clock(tmp_path: Path) -> None:
    docs = [_alert("2026-09-10T10:00:00.000+0000"), _alert("2026-09-10T10:04:00.000+0000")]
    path = _write(tmp_path / "alerts.json", _ndjson(docs))
    wall = datetime(2026, 9, 10, 9, 58, tzinfo=UTC)
    source = FileEventSource([path], tenant=TENANT, clock=lambda: wall)
    list(source)
    assert source.basis.future_timestamps == 1  # 10:04 > 09:58 + 5 min; 10:00 is within the skew allowance
    assert source.basis.now == datetime(2026, 9, 10, 10, 0, tzinfo=UTC)


# ---- JSON arrays and documents --------------------------------------------------------------------------------


def test_json_array_and_non_object_items(tmp_path: Path) -> None:
    docs: list[Any] = [_alert("2026-09-10T10:00:00.000+0000"), 42, "x", _alert("2026-09-10T10:01:00.000+0000")]
    source = _open(_write(tmp_path / "arr.json", json.dumps(docs, indent=2).encode()))
    assert len(list(source)) == 2
    assert source.basis.malformed == 2


def test_big_json_array_rejected_clearly(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(files_mod, "MAX_JSON_DOCUMENT_BYTES", 2048)
    big = _write(tmp_path / "big.json", json.dumps([_alert(f"2026-09-10T10:{i:02d}:00Z") for i in range(40)]).encode())
    small = _write(tmp_path / "small.json", _ndjson([_alert("2026-09-10T11:00:00.000+0000")]))
    source = _open([big, small])
    assert len(list(source)) == 1  # the other input is still analyzed
    assert source.basis.partial_failures == [f"{big}: JSON array too large"]
    assert not source.basis.complete
    warning = next(w for w in source.basis.warnings if getattr(w, "key", "") == "ingest.warn.array_too_large")
    assert "jq -c" in render(warning, "en") and "NDJSON" in render(warning, "es")


def test_invalid_json_array_is_a_partial_failure(tmp_path: Path) -> None:
    path = _write(tmp_path / "broken.json", b'[{"timestamp": "2026-09-10T10:00:00Z"}, {"broken": ')
    source = _open(path)
    assert list(source) == []
    assert source.basis.malformed == 1
    assert source.basis.partial_failures == [f"{path}: invalid JSON array"]


def test_pretty_printed_documents_and_search_response(tmp_path: Path) -> None:
    pretty = _write(
        tmp_path / "pretty.json",
        (json.dumps(_alert("2026-09-10T10:00:00.000+0000"), indent=2) + "\n").encode() * 2,
    )
    response = {
        "took": 3,
        "timed_out": False,
        "_shards": {"total": 1, "successful": 1, "failed": 0},
        "hits": {
            "total": {"value": 2},
            "hits": [
                {"_index": "wazuh-alerts-4.x-2026.09.10", "_id": "h1", "_source": _alert("2026-09-10T10:05:00Z")},
                {"_index": "wazuh-alerts-4.x-2026.09.10", "_id": "h2", "_source": _alert("2026-09-10T10:06:00Z")},
                "junk",
            ],
        },
    }
    saved = _write(tmp_path / "response.json", json.dumps(response, indent=2).encode())
    assert len(list(_open(pretty))) == 2
    source = _open(saved)
    events = list(source)
    assert [e.event_id for e in events] == ["2026-09-10T10:05:00Z.5710", "2026-09-10T10:06:00Z.5710"]
    assert [e.fields["_id"] for e in events] == ["h1", "h2"]
    assert source.basis.malformed == 1


def test_archives_index_hits_are_archives(tmp_path: Path) -> None:
    hits = [{"_index": "wazuh-archives-4.x-2026.09.10", "_id": "a1", "_source": _alert("2026-09-10T10:05:00.000+0000")}]
    source = _open(_write(tmp_path / "export.ndjson", _ndjson(hits)))
    assert [e.event_id for e in source] == ["2026-09-10T10:05:00.000+0000.5710"]
    assert source.basis.input_kind == "archives"


def test_array_first_line_in_ndjson_falls_back(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    data = b"[1, 2, 3]\n" + _ndjson([_alert("2026-09-10T10:01:00.000+0000")] * 3)
    source = _open(_write(tmp_path / "alerts.json", data))
    assert len(list(source)) == 3
    assert source.basis.malformed == 1 and not source.basis.partial_failures
    monkeypatch.setattr(files_mod, "MAX_JSON_DOCUMENT_BYTES", 64)  # a big NDJSON file must not be rejected
    big = _open(_write(tmp_path / "big.json", data))
    assert len(list(big)) == 3 and not big.basis.partial_failures


def test_pretty_guess_falls_back_to_ndjson(tmp_path: Path) -> None:
    data = b'{"timestamp": "2026-09-10T10:00:00Z", "broken\n' + _ndjson([_alert("2026-09-10T10:01:00.000+0000")])
    source = _open(_write(tmp_path / "alerts.json", data))
    assert len(list(source)) == 1
    assert source.basis.malformed == 1
    assert not source.basis.partial_failures


# ---- compressed data problems ---------------------------------------------------------------------------------


def test_truncated_gzip_keeps_events_and_reports_failure(tmp_path: Path) -> None:
    docs = [_alert(f"2026-09-10T{h:02d}:00:00.000+0000", full_log=os.urandom(2000).hex()) for h in range(20)]
    blob = gzip.compress(_ndjson(docs))
    path = _write(tmp_path / "cut.json.gz", blob[: len(blob) // 2])
    source = _open(path)
    events = list(source)
    assert 0 < len(events) < 20
    assert source.basis.partial_failures == [f"{path}: truncated compressed data"]
    assert "ingest.warn.read_error" in _keys(source.basis.warnings)


def test_corrupt_gzip_is_a_partial_failure(tmp_path: Path) -> None:
    path = _write(tmp_path / "bad.json.gz", b"\x1f\x8b\x08\x00" + os.urandom(64))
    source = _open(path)
    assert list(source) == []
    assert len(source.basis.partial_failures) == 1
    assert "compressed" in source.basis.partial_failures[0]


@pytest.mark.parametrize(
    ("magic", "name"),
    [(b"BZh91AY&SY", "bzip2"), (b"\xfd7zXZ\x00\x00", "xz"), (b"\x28\xb5\x2f\xfd\x00", "zstd"), (b"PK\x03\x04", "zip")],
)
def test_other_compressions_are_reported_not_parsed(tmp_path: Path, magic: bytes, name: str) -> None:
    path = _write(tmp_path / f"alerts.json.{name}", magic + os.urandom(256))
    source = _open(path)
    assert list(source) == []
    assert source.basis.partial_failures == [f"{path}: {name} compressed"]
    assert source.basis.malformed == 0
    warning = next(w for w in source.basis.warnings if getattr(w, "key", "") == "ingest.warn.read_error")
    assert "gzip" in render(warning, "en") and "gzip" in render(warning, "es")


def test_field_explosion_is_capped_and_reported(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(files_mod, "MAX_FIELDS_PER_EVENT", 50)
    doc = _alert("2026-09-10T10:00:00.000+0000")
    doc["data"]["json"] = {f"k{i}": i for i in range(500)}  # attacker-controlled JSON log keys
    doc["zz_last"] = "tail"
    source = _open(_write(tmp_path / "alerts.json", _ndjson([doc, _alert("2026-09-10T10:01:00.000+0000")])))
    first, second = list(source)
    assert 50 <= len(first.fields) <= 80
    assert first.fields["agent.name"] == "srv-web-01.example" and first.fields["data.srcip"] == "10.0.0.5"
    assert first.fields["rule.id"] == "5710"
    assert second.fields == flatten(_alert("2026-09-10T10:01:00.000+0000"))
    warning = next(w for w in source.basis.warnings if getattr(w, "key", "") == "ingest.warn.fields_capped")
    assert warning.params["count"] == 1


@pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0, reason="root can read anything")
def test_unreadable_file_is_a_partial_failure(tmp_path: Path) -> None:
    path = _write(tmp_path / "secret.json", _ndjson([_alert("2026-09-10T10:00:00.000+0000")]))
    path.chmod(0)
    try:
        source = _open(path)
        assert list(source) == []
        assert source.basis.partial_failures == [f"{path}: permission denied"]
    finally:
        path.chmod(0o600)


def test_file_deleted_after_open_is_a_partial_failure(tmp_path: Path) -> None:
    path = _write(tmp_path / "gone.json", _ndjson([_alert("2026-09-10T10:00:00.000+0000")]))
    source = _open(path)
    path.unlink()
    assert list(source) == []
    assert len(source.basis.partial_failures) == 1


# ---- argument validation --------------------------------------------------------------------------------------


def test_usage_errors_raise_ingest_error(tmp_path: Path) -> None:
    good = _write(tmp_path / "a.json", _ndjson([_alert("2026-09-10T10:00:00.000+0000")]))
    with pytest.raises(IngestError, match="not found"):
        _open(tmp_path / "missing.json")
    with pytest.raises(IngestError, match="no data files match"):
        _open(str(tmp_path / "nothing-*.json"))
    with pytest.raises(IngestError, match="unknown profile"):
        _open(good, profile="splunk")
    with pytest.raises(IngestError, match="max_events"):
        _open(good, max_events=-1)
    with pytest.raises(IngestError, match="since"):
        _open(good, since=datetime(2026, 9, 2, tzinfo=UTC), until=datetime(2026, 9, 1, tzinfo=UTC))
    with pytest.raises(IngestError, match="timezone"):
        _open(good, input_cfg=InputConfig(naive_timezone="Mars/Olympus"))
    with pytest.raises(IngestError):
        _open([])
    assert issubclass(IngestError, ValueError)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs FIFOs")
def test_pipes_are_rejected(tmp_path: Path) -> None:
    fifo = tmp_path / "pipe"
    os.mkfifo(fifo)
    with pytest.raises(IngestError, match="not a regular file"):
        _open(fifo)


def test_empty_directory_is_reported(tmp_path: Path) -> None:
    (tmp_path / "empty").mkdir()
    _write(tmp_path / "empty" / "readme.md", b"# nothing")
    source = _open(tmp_path / "empty")
    assert list(source) == []
    assert source.basis.partial_failures == [f"{tmp_path / 'empty'}: no data files"]
    assert "ingest.warn.no_files" in _keys(source.basis.warnings)


def test_empty_file_yields_nothing(tmp_path: Path) -> None:
    source = _open(_write(tmp_path / "empty.json", b""))
    assert list(source) == []
    assert source.basis.events == 0 and source.basis.input_kind == "unknown" and not source.basis.partial_failures


# ---- time filtering, truncation, re-iteration ----------------------------------------------------------------


def test_since_until_filter(tmp_path: Path) -> None:
    docs = [_alert(f"2026-09-10T{h:02d}:00:00.000+0000") for h in range(10)]
    path = _write(tmp_path / "alerts.json", _ndjson(docs))
    source = _open(path, since=datetime(2026, 9, 10, 3, tzinfo=UTC), until=datetime(2026, 9, 10, 6))  # naive = UTC
    assert [e.ts.hour for e in source] == [3, 4, 5]
    assert source.basis.start == datetime(2026, 9, 10, 3, tzinfo=UTC)
    outside = _open(path, since=datetime(2026, 9, 11, tzinfo=UTC))
    assert list(outside) == []
    warning = next(w for w in outside.basis.warnings if getattr(w, "key", "") == "ingest.warn.out_of_range")
    assert "10" in render(warning, "en")


def test_max_events_truncation(tmp_path: Path) -> None:
    docs = [_alert(f"2026-09-10T{h:02d}:00:00.000+0000") for h in range(10)]
    path = _write(tmp_path / "alerts.json", _ndjson(docs))
    source = _open(path, max_events=4)
    assert len(list(source)) == 4
    assert source.basis.truncated and source.basis.events == 4 and not source.basis.complete
    assert "ingest.warn.truncated" in _keys(source.basis.warnings)
    exact = _open(path, max_events=10)
    assert len(list(exact)) == 10 and not exact.basis.truncated  # nothing was left unread


def test_reiteration_does_not_double_count(tmp_path: Path) -> None:
    source = _open([FIXTURES / "wazuh4_alerts.json", FIXTURES / "wazuh4_archives.json"])
    first = list(source)
    basis_one = source.basis
    second = list(source)
    assert first == second
    assert source.basis is not basis_one
    assert source.basis.events == basis_one.events == 8
    assert source.basis.warnings == basis_one.warnings
    assert source.basis.partial_failures == basis_one.partial_failures


def test_abandoned_pass_keeps_previous_basis(tmp_path: Path) -> None:
    source = _open(FIXTURES / "wazuh4_alerts.json")
    list(source)
    complete = source.basis
    iterator = iter(source)
    next(iterator)
    del iterator
    assert source.basis is complete


def test_second_pass_sees_the_same_snapshot_of_a_live_file(tmp_path: Path) -> None:
    path = _write(tmp_path / "alerts.json", _ndjson([_alert("2026-09-10T10:00:00.000+0000")] * 3))
    source = _open(path)
    assert len(list(source)) == 3
    with path.open("ab") as handle:  # analysisd keeps appending
        handle.write(_ndjson([_alert("2026-09-10T10:01:00.000+0000")] * 5))
    assert len(list(source)) == 3
    assert source.basis.events == 3


# ---- misc API -------------------------------------------------------------------------------------------------


def test_iter_documents_labels_and_stats(tmp_path: Path) -> None:
    a = _write(tmp_path / "a.json", _ndjson([{"x": 1}]) + b"oops\n")
    b = _write(tmp_path / "b.json", _ndjson([{"y": 2}, {"z": 3}]))
    stats = ReadStats()
    pairs = list(iter_documents([a, b], stats=stats))
    assert pairs == [({"x": 1}, str(a)), ({"y": 2}, str(b)), ({"z": 3}, str(b))]
    assert stats.malformed == 1
    with pytest.raises(IngestError):
        iter_documents(tmp_path / "missing.json")


def test_projection_through_open_files(tmp_path: Path) -> None:
    path = _write(tmp_path / "alerts.json", _ndjson([_alert("2026-09-10T10:00:00.000+0000", full_log="big")]))
    projected = next(iter(_open(path, project=["decoder.name"])))
    assert projected.fields["decoder.name"] == "sshd"
    assert projected.fields["data.srcip"] == "10.0.0.5"  # core key
    assert "full_log" not in projected.fields and "manager.name" not in projected.fields
    lean = next(iter(_open(path, keep_fields=False)))
    assert "manager.name" not in lean.fields and "full_log" not in lean.fields
    assert lean.fields["agent.name"] == "srv-web-01.example"


def test_progress_reports_bytes(tmp_path: Path) -> None:
    a = _write(tmp_path / "a.json", _ndjson([_alert("2026-09-10T10:00:00.000+0000")] * 50))
    b = _write(tmp_path / "b.json.gz", _ndjson([_alert("2026-09-10T11:00:00.000+0000")] * 50), gz=True)
    calls: list[tuple[int, int]] = []
    source = _open([a, b], on_progress=lambda done, total: calls.append((done, total)))
    list(source)
    total = a.stat().st_size + b.stat().st_size
    assert calls and all(t == total for _, t in calls)
    assert [d for d, _ in calls] == sorted(d for d, _ in calls)
    assert calls[-1][0] == total


def test_forced_profile_and_mixed_profiles(tmp_path: Path) -> None:
    ecs = FIXTURES / "ecs_alerts.ndjson"
    source = _open([FIXTURES / "wazuh4_alerts.json", ecs])
    list(source)
    assert source.basis.profile == "mixed"
    forced = _open(ecs, profile="generic")
    events = list(forced)
    assert forced.basis.profile == "generic"
    assert events[0].ts == datetime(2026, 9, 10, 11, 0, 5, 123000, tzinfo=UTC)  # generic reads @timestamp first


def test_wazuh5_input_warns(tmp_path: Path) -> None:
    doc = {
        "@timestamp": "2026-09-10T12:00:00Z",
        "wazuh": {"agent": {"name": "srv-web-01.example"}},
        "agent": {"name": "srv-web-01.example"},
        "event": {"original": "x", "dataset": "sshd"},
    }
    source = _open(_write(tmp_path / "w5.json", _ndjson([doc])))
    assert len(list(source)) == 1
    assert source.basis.profile == "wazuh5"
    assert "ingest.warn.wazuh5" in _keys(source.basis.warnings)


def test_syslog_year_rollover_from_mtime(tmp_path: Path) -> None:
    path = _write(tmp_path / "syslog.csv", b"time,host\nDec 31 23:59:00,srv-web-01\nJan  1 00:01:00,srv-web-01\n")
    stamp = datetime(2026, 1, 1, 0, 5, tzinfo=UTC).timestamp()
    os.utime(path, (stamp, stamp))
    events = list(_open(path, profile="generic"))
    assert [e.ts for e in events] == [
        datetime(2025, 12, 31, 23, 59, tzinfo=UTC),
        datetime(2026, 1, 1, 0, 1, tzinfo=UTC),
    ]


def test_warnings_render_in_both_languages(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(files_mod, "MAX_JSON_DOCUMENT_BYTES", 16)
    big = _write(tmp_path / "big.json", json.dumps([_alert("2026-09-10T10:00:00Z")]).encode())
    cut = _write(tmp_path / "cut.json.gz", gzip.compress(_ndjson([_alert("2026-09-10T10:00:00Z")] * 50))[:60])
    source = _open([big, cut, FIXTURES / "wazuh4_alerts.json"], max_events=1)
    list(source)
    assert len(source.basis.warnings) >= 4
    for message in source.basis.warnings:
        english, spanish = render(message, "en"), render(message, "es")
        assert english and spanish and english != spanish
        assert "{" not in english and "{" not in spanish


def test_every_ingest_message_is_translated() -> None:
    keys = [key for key in message_keys() if key.startswith("ingest.")]
    assert len(keys) >= 15
    for key in keys:
        english = render(M(key), "en")
        spanish = render(M(key), "es")
        assert english and spanish and english != spanish, key


# ---- performance ----------------------------------------------------------------------------------------------


def _generate(path: Path, count: int, seed: int = 7) -> None:
    rng = random.Random(seed)
    agents = [f"srv-{i:03d}.example" for i in range(40)]
    rules = [("5710", 5), ("5715", 3), ("60106", 3), ("550", 7), ("4101", 5)]
    start = datetime(2026, 9, 1, tzinfo=UTC)
    with path.open("w", encoding="utf-8") as handle:
        for i in range(count):
            rule_id, level = rules[rng.randrange(len(rules))]
            ts = start + timedelta(seconds=i * 20 + rng.randrange(20))
            doc = _alert(
                ts.strftime("%Y-%m-%dT%H:%M:%S.") + f"{rng.randrange(1000):03d}+0000",
                rule_id=rule_id,
                agent=rng.choice(agents),
                level=level,
                full_log=f"Sep  1 00:00:00 host sshd[{rng.randrange(99999)}]: Invalid user u{rng.randrange(50)}",
            )
            doc["data"]["srcip"] = f"10.{rng.randrange(256)}.{rng.randrange(256)}.{rng.randrange(1, 255)}"
            handle.write(json.dumps(doc, separators=(",", ":")) + "\n")


def _time_pass(path: Path) -> tuple[float, int]:
    begin = time.perf_counter()
    count = sum(1 for _ in _open(path))
    return time.perf_counter() - begin, count


def test_fifty_thousand_events_stream_quickly(tmp_path: Path) -> None:
    small, large = tmp_path / "small.json", tmp_path / "large.json"
    _generate(small, 10_000)
    _generate(large, 50_000)
    small_time, small_count = _time_pass(small)
    large_time, large_count = _time_pass(large)
    assert (small_count, large_count) == (10_000, 50_000)
    assert large_time < 15.0, f"50k events took {large_time:.1f}s"
    # linear, not quadratic: 5x the data must take well under 25x the time
    assert large_time < 12 * max(small_time, 0.05), (small_time, large_time)


def _peak_memory(path: Path) -> int:
    tracemalloc.start()
    try:
        count = 0
        for event in _open(path):
            assert isinstance(event, Event)
            count += 1
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert count > 0
    return peak


def test_streaming_memory_is_bounded(tmp_path: Path) -> None:
    peaks: dict[str, int] = {}
    for name, count in (("small", 1_500), ("large", 6_000)):
        path = tmp_path / f"{name}.json"
        _generate(path, count)
        gz = tmp_path / f"{name}.json.gz"
        with path.open("rb") as src, gzip.open(gz, "wb") as dst:
            shutil.copyfileobj(src, dst)
        peaks[name] = _peak_memory(path)
        peaks[name + ".gz"] = _peak_memory(gz)
    # constant, not proportional to the input: 4x the data must not need noticeably more memory
    assert peaks["large"] < peaks["small"] * 1.5 + 256 * 1024, peaks
    assert peaks["large.gz"] < peaks["small.gz"] * 1.5 + 256 * 1024, peaks
    assert max(peaks.values()) < 16 * 1024 * 1024, peaks


# ---- regressions (review) -------------------------------------------------------------------------------------


def test_alert_files_named_archive_are_still_alerts(tmp_path: Path) -> None:
    # an archived copy of ALERTS must keep the alerts-only caveat: calling it "archives" is a false green
    path = _write(tmp_path / "wazuh-alerts-archive-2025.json", _ndjson([_alert("2026-09-10T10:00:00.000+0000")]))
    source = _open(path)
    list(source)
    assert source.basis.input_kind == "alerts"
    assert "ingest.warn.alerts_only_wazuh" in _keys(source.basis.warnings)
    rotated = _write(
        tmp_path / "archives" / "2026" / "Sep" / "ossec-archive-10.json", _ndjson([_archive("2026-09-10T10:00:00Z")])
    )
    archived = _open(rotated)
    list(archived)
    assert archived.basis.input_kind == "archives"


def test_wazuh_export_without_rule_id_column_is_alerts(tmp_path: Path) -> None:
    # dashboard CSV export whose columns omit rule.id: the rows still carry rule.level / rule.description
    data = (
        b"timestamp,agent.id,agent.name,manager.name,rule.level,rule.description,location\n"
        + b"2026-09-10T10:00:00.000+0000,001,srv-web-01.example,wazuh-manager,5,sshd failure,/var/log/auth.log\n" * 3
    )
    source = _open(_write(tmp_path / "export.csv", data))
    events = list(source)
    assert source.basis.profile == "wazuh4" and len(events) == 3
    assert source.basis.input_kind == "alerts"
    assert "ingest.warn.alerts_only_wazuh" in _keys(source.basis.warnings)


def test_alerts_mixed_with_unknown_kind_still_warn(tmp_path: Path) -> None:
    alerts = _write(tmp_path / "a.json", _ndjson([_alert("2026-09-10T10:00:00.000+0000")]))
    other = _write(tmp_path / "g.csv", b"time,host\n2026-09-10T10:00:00Z,srv-web-01.example\n")
    source = _open([alerts, other])
    list(source)
    assert source.basis.input_kind == "mixed"
    assert "ingest.warn.partly_alerts" in _keys(source.basis.warnings)


def test_size_split_rotated_files_are_dated_ordered_and_pruned(tmp_path: Path) -> None:
    month = tmp_path / "alerts" / "2026" / "Sep"
    _write(month / "ossec-alerts-09.json.gz", _ndjson([_alert("2026-09-09T10:00:00.000+0000")]), gz=True)
    _write(month / "ossec-alerts-10.json.gz", _ndjson([_alert("2026-09-10T01:00:00.000+0000")]), gz=True)
    _write(month / "ossec-alerts-10-001.json.gz", _ndjson([_alert("2026-09-10T02:00:00.000+0000")]), gz=True)
    _write(month / "ossec-alerts-10-002.json", _ndjson([_alert("2026-09-10T03:00:00.000+0000")]))
    assert rotated_date(month / "ossec-alerts-10-002.json") == datetime(2026, 9, 10).date()
    source = _open(tmp_path / "alerts")
    assert [Path(p).name for p in source.files] == [
        "ossec-alerts-09.json.gz",
        "ossec-alerts-10.json.gz",  # written first, although "-001" sorts before "." as text
        "ossec-alerts-10-001.json.gz",
        "ossec-alerts-10-002.json",
    ]
    assert [e.ts.hour for e in source] == [10, 1, 2, 3]
    pruned = _open(tmp_path / "alerts", until=datetime(2026, 9, 5, tzinfo=UTC))
    assert pruned.files == []


def test_big_pretty_printed_document_is_a_reported_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(files_mod, "MAX_JSON_DOCUMENT_BYTES", 4096)
    doc = (json.dumps(_alert("2026-09-10T10:00:00.000+0000"), indent=2) + "\n").encode()
    big = _write(tmp_path / "pretty.json", doc * 40)
    small = _write(tmp_path / "small.json", _ndjson([_alert("2026-09-10T11:00:00.000+0000")]))
    source = _open([big, small])
    assert len(list(source)) == 1
    assert source.basis.partial_failures == [f"{big}: JSON document too large"]
    assert source.basis.malformed == 0  # its lines are not NDJSON garbage
    assert not source.basis.complete


def test_broken_pretty_document_does_not_hide_the_rest_of_the_file(tmp_path: Path) -> None:
    good = (json.dumps(_alert("2026-09-10T10:00:00.000+0000"), indent=2) + "\n").encode()
    broken = b'{\n  "timestamp": "2026-09-10T10:00:00Z",\n  "rule": \n}\n'
    source = _open(_write(tmp_path / "pretty.json", good * 3 + broken + good * 20 + broken))
    assert len(list(source)) == 23
    assert source.basis.malformed == 2
    first_broken = _open(_write(tmp_path / "first.json", broken + good * 2))
    assert len(list(first_broken)) == 2 and first_broken.basis.malformed == 1


def test_majority_of_future_events_uses_the_newest_event_as_now(tmp_path: Path) -> None:
    wall = datetime(2026, 9, 10, 12, 0, tzinfo=UTC)
    stamps = [
        wall - timedelta(hours=2),
        wall + timedelta(hours=1),
        wall + timedelta(hours=2),
        wall + timedelta(hours=3),
    ]
    path = _write(tmp_path / "alerts.json", _ndjson([_alert(t.strftime("%Y-%m-%dT%H:%M:%S.000+0000")) for t in stamps]))
    source = FileEventSource([path], tenant=TENANT, clock=lambda: wall)
    list(source)
    assert source.basis.future_timestamps == 3
    assert source.basis.now == source.basis.end == wall + timedelta(hours=3)
    assert "ingest.warn.future_majority" in _keys(source.basis.warnings)
    minority = FileEventSource([path], tenant=TENANT, clock=lambda: wall + timedelta(hours=2, minutes=30))
    list(minority)
    assert minority.basis.now == wall + timedelta(hours=2) and minority.basis.future_timestamps == 1
    assert "ingest.warn.future_majority" not in _keys(minority.basis.warnings)


def test_live_file_relinked_between_passes_is_reported_not_misread(tmp_path: Path) -> None:
    day1 = _write(tmp_path / "ossec-alerts-24.json", _ndjson([_alert("2026-09-24T23:00:00.000+0000")] * 20))
    live = tmp_path / "alerts.json"
    os.link(day1, live)
    source = _open(live)
    assert len(list(source)) == 20
    # midnight: analysisd re-links alerts.json to the new day's file
    day2 = _write(tmp_path / "ossec-alerts-25.json", _ndjson([_alert("2026-09-25T00:00:01.000+0000")] * 40))
    live.unlink()
    os.link(day2, live)
    assert list(source) == []  # the second pass must not silently analyze another day's events
    assert source.basis.partial_failures == [f"{live}: file replaced while being analyzed"]
    assert not source.basis.complete


def test_file_truncated_between_passes_is_reported(tmp_path: Path) -> None:
    path = _write(tmp_path / "app.json", _ndjson([_alert("2026-09-24T23:00:00.000+0000")] * 20))
    source = _open(path)
    assert len(list(source)) == 20
    with path.open("r+b") as handle:  # logrotate copytruncate
        handle.truncate(0)
        handle.write(_ndjson([_alert("2026-09-25T01:00:00.000+0000")]))
    assert list(source) == []
    assert source.basis.partial_failures == [f"{path}: file truncated while being analyzed"]


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs FIFOs")
def test_path_swapped_for_a_fifo_does_not_block(tmp_path: Path) -> None:
    path = _write(tmp_path / "x.json", _ndjson([_alert("2026-09-24T23:00:00.000+0000")]))
    source = _open(path)
    path.unlink()
    os.mkfifo(path)  # opening a FIFO for reading blocks until a writer appears: must not hang the run
    assert list(source) == []
    assert source.basis.partial_failures == [f"{path}: no longer a regular file"]


def test_unstatable_directory_entry_is_reported(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _write(tmp_path / "d" / "a.json", _ndjson([_alert("2026-09-10T10:00:00.000+0000")]))
    locked = _write(tmp_path / "d" / "b.json", _ndjson([_alert("2026-09-10T11:00:00.000+0000")]))
    os.symlink(tmp_path / "missing.json", tmp_path / "d" / "c.json")  # dangling link: no data, not an error
    real_stat = os.stat

    def fake_stat(path: Any, *args: Any, **kwargs: Any) -> os.stat_result:
        if os.fspath(path) == str(locked):
            raise PermissionError(13, "Permission denied", str(locked))
        return real_stat(path, *args, **kwargs)

    monkeypatch.setattr(files_mod.os, "stat", fake_stat)
    source = _open(tmp_path / "d")
    assert len(list(source)) == 1
    assert source.basis.partial_failures == [f"{locked}: permission denied"]


def test_year_rollover_only_for_generic_data(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = _write(tmp_path / "alerts.json", _ndjson([_alert("2026-09-10T10:00:00.000+0000")] * 3))
    stamp = datetime(2020, 1, 1, tzinfo=UTC).timestamp()  # stale mtime: every event is "after" it
    os.utime(path, (stamp, stamp))

    def boom(*args: Any, **kwargs: Any) -> Event:
        raise AssertionError("ISO timestamps carry their year: no second normalization")

    monkeypatch.setattr(FileEventSource, "_year_rollover", boom)
    source = _open(path)
    assert len(list(source)) == 3 and source.basis.malformed == 0


def test_timestamps_without_offset_read_as_utc_are_flagged(tmp_path: Path) -> None:
    # Wazuh dashboard CSV export: browser-local time without an offset
    data = (
        b"timestamp,rule.id,rule.level,agent.name,agent.id,location\n"
        b'"Sep 10, 2026 @ 10:15:32.481",5710,5,srv-web-01.example,001,/var/log/auth.log\n'
    )
    path = _write(tmp_path / "export.csv", data)
    source = _open(path)
    assert [e.ts.hour for e in source] == [10]
    warning = next(w for w in source.basis.warnings if getattr(w, "key", "") == "ingest.warn.naive_utc")
    assert warning.params["count"] == 1 and "naive_timezone" in render(warning, "es")
    configured = _open(path, input_cfg=InputConfig(naive_timezone="Europe/Madrid"))
    assert [e.ts.hour for e in configured] == [8]
    assert "ingest.warn.naive_utc" not in _keys(configured.basis.warnings)
    wazuh = _open(FIXTURES / "wazuh4_alerts.json")  # "+0000" offsets: nothing to flag
    list(wazuh)
    assert "ingest.warn.naive_utc" not in _keys(wazuh.basis.warnings)


def test_ecs_alert_documents_without_rule_id_are_alerts(tmp_path: Path) -> None:
    # e.g. Elastic Defend endpoint alerts: event.kind "alert" but no rule.id - not full-fidelity raw events
    doc = {
        "@timestamp": "2026-09-10T11:00:00Z",
        "event": {"kind": "alert", "module": "endpoint", "dataset": "endpoint.alerts"},
        "host": {"name": "wks-01.corp.example"},
    }
    raw = {"@timestamp": "2026-09-10T11:00:00Z", "event": {"kind": "event", "dataset": "system.auth"}}
    for keep in (True, False):
        alerts = _open(_write(tmp_path / "endpoint.ndjson", _ndjson([doc] * 2)), keep_fields=keep)
        list(alerts)
        assert alerts.basis.profile == "ecs" and alerts.basis.input_kind == "alerts"
    events = _open(_write(tmp_path / "raw.ndjson", _ndjson([raw] * 2)))
    list(events)
    assert events.basis.input_kind == "archives"
