"""Tests for hushwatch.ingest.profiles: normalization of Wazuh 4/5, ECS and generic documents."""

from __future__ import annotations

import json
import random
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from hushwatch.config import InputConfig, TenantConfig
from hushwatch.ingest import detect_profile, normalize
from hushwatch.ingest.profiles import (
    _EMPTY_TEXT,
    MAX_ENTITY_CHARS,
    MAX_LIST_ITEMS,
    bind,
    canonical_mapping_key,
    fast_flatten,
    parse_time,
    unwrap_hit,
    zone,
)
from hushwatch.models import flatten, is_empty
from hushwatch.tuning import Condition

UTC = timezone.utc
FIXTURES = Path(__file__).parent / "fixtures" / "ingest"
TENANT = TenantConfig()


def _lines(name: str) -> list[dict[str, Any]]:
    return [json.loads(line) for line in (FIXTURES / name).read_text(encoding="utf-8").splitlines() if line.strip()]


@pytest.fixture(scope="module")
def alerts() -> list[dict[str, Any]]:
    return _lines("wazuh4_alerts.json")


@pytest.fixture(scope="module")
def ecs_alerts() -> list[dict[str, Any]]:
    return _lines("ecs_alerts.ndjson")


def _norm(doc: dict[str, Any], profile: str = "wazuh4", **kwargs: Any) -> Any:
    event = normalize(doc, profile, tenant=TENANT, **kwargs)
    assert event is not None
    return event


# ---- wazuh4 ---------------------------------------------------------------------------------------------------


def test_wazuh4_sshd_from_agent(alerts: list[dict[str, Any]]) -> None:
    event = _norm(alerts[0])
    assert event.ts == datetime(2026, 9, 10, 10, 15, 32, 481000, tzinfo=UTC)
    assert event.rule_id == "5710"
    assert event.rule_name == "sshd: Attempt to login using a non-existent user"
    assert event.severity == 5
    assert event.source == "srv-web-01.example"
    assert event.log_source == "/var/log/auth.log"
    assert event.entities == {"src_ip": "203.0.113.7", "user": "admin", "host": "srv-web-01.example"}
    assert event.tags == ("T1110.001", "T1021.004")
    assert event.mitre_tactics == ("Credential Access", "Lateral Movement")
    assert event.rule_groups == ("syslog", "sshd", "authentication_failed", "invalid_login")
    assert event.event_id == "1789035332.1234567"
    assert event.event_code is None
    assert event.os_platform == "linux"
    # fields = flatten(doc): original dotted paths, lists of scalars kept as lists
    assert event.fields == flatten(alerts[0])
    assert event.fields["data.srcip"] == "203.0.113.7"
    assert event.fields["rule.pci_dss"] == ["10.2.4", "10.2.5", "10.6.1"]
    assert Condition("data.srcip", "203.0.113.7").matches(event)
    assert Condition("agent.name", "srv-web-01.example").matches(event)


def test_wazuh4_windows_logon_60106(alerts: list[dict[str, Any]]) -> None:
    event = _norm(alerts[1])
    assert event.ts == datetime(2026, 9, 10, 10, 20, 11, 302000, tzinfo=UTC)  # +0200 offset converted
    assert event.rule_id == "60106"
    assert event.severity == 3
    assert event.source == "dc01.corp.example"
    assert event.log_source == "Security"  # data.win.system.channel wins over location "EventChannel"
    assert event.event_code == "4624"
    assert event.os_platform == "windows"
    assert event.entities["user"] == "svc_backup"  # targetUserName before the machine-account subject
    assert event.entities["src_ip"] == "10.0.0.5"  # Windows ipAddress feeds src_ip
    assert event.fields["location"] == "EventChannel"
    # the Wazuh eventchannel backslash quirk is preserved verbatim (conditions must match the raw value)
    assert event.fields["data.win.eventdata.processName"] == "C:\\\\Windows\\\\System32\\\\services.exe"


def test_wazuh4_sysmon_process_creation(alerts: list[dict[str, Any]]) -> None:
    event = _norm(alerts[2])
    assert event.log_source == "Microsoft-Windows-Sysmon/Operational"
    assert event.event_code == "1"
    assert event.entities["process"] == "C:\\\\Windows\\\\System32\\\\cmd.exe"
    assert event.entities["parent_process"] == "C:\\\\Program Files\\\\Example\\\\agent.exe"
    assert event.entities["command_line"] == "cmd.exe /c whoami"
    assert event.entities["user"] == "CORP\\\\alice"
    assert event.tags == ("T1059.003",)
    assert event.mitre_tactics == ("Execution",)
    assert event.os_platform == "windows"


def test_wazuh4_manager_syslog_device(alerts: list[dict[str, Any]]) -> None:
    event = _norm(alerts[3])
    # agent 000 = the manager; the firewall is the syslog header hostname
    assert event.source == "fw-edge-01"
    assert event.entities["host"] == "fw-edge-01"
    assert event.log_source == "syslog"
    assert event.os_platform == "network"
    assert event.entities["src_ip"] == "203.0.113.50"
    assert event.entities["dst_ip"] == "10.20.0.15"
    assert event.fields["agent.name"] == "wazuh-manager"  # original values stay available for conditions
    assert event.fields["location"] == "10.10.0.1"
    assert Condition("predecoder.hostname", "fw-edge-01").matches(event)


def test_wazuh4_manager_syslog_without_hostname_keeps_sender(alerts: list[dict[str, Any]]) -> None:
    doc = json.loads(json.dumps(alerts[3]))
    del doc["predecoder"]["hostname"]
    event = _norm(doc)
    assert event.source == "wazuh-manager"
    assert event.log_source == "10.10.0.1"  # the only device identity left


def test_wazuh4_manager_local_file(alerts: list[dict[str, Any]]) -> None:
    doc = json.loads(json.dumps(alerts[0]))
    doc["agent"] = {"id": "000", "name": "wazuh-manager"}
    event = _norm(doc)
    assert event.source == "srv-web-01"  # predecoder.hostname for agent 000
    assert event.log_source == "/var/log/auth.log"
    assert event.os_platform == "linux"


def test_wazuh4_fim_syscheck(alerts: list[dict[str, Any]]) -> None:
    event = _norm(alerts[4])
    assert event.rule_id == "550"
    assert event.severity == 7
    assert event.log_source == "syscheck"
    assert event.entities["file"] == "/etc/hosts"
    assert "syscheck" in event.rule_groups
    assert event.os_platform == "linux"
    assert event.fields["syscheck.changed_attributes"] == ["size", "mtime", "md5", "sha1", "sha256"]


def test_wazuh4_archives_document_without_rule() -> None:
    doc = _lines("wazuh4_archives.json")[0]
    event = _norm(doc)
    assert event.rule_id is None and event.rule_name is None and event.severity is None
    assert event.rule_groups == () and event.tags == () and event.mitre_tactics == ()
    assert event.source == "srv-web-01.example"
    assert event.entities["user"] == "root"


def test_wazuh4_location_with_agent_prefix_is_stripped() -> None:
    doc = {"timestamp": "2026-09-10T10:00:00.000+0000", "agent": {"id": "004", "name": "srv-app-02.example"}}
    doc["location"] = "(srv-app-02.example) any->/var/log/secure"
    assert _norm(doc).log_source == "/var/log/secure"


def test_wazuh4_flat_dashboard_export_shape() -> None:
    doc = {
        "timestamp": "Sep 10, 2026 @ 10:15:32.481",
        "rule.id": "5710",
        "rule.level": "5",
        "rule.description": "sshd: Attempt to login using a non-existent user",
        "rule.groups": "syslog, sshd, authentication_failed",
        "rule.mitre.id": "T1110.001, T1021.004",
        "agent.name": "srv-web-01.example",
        "agent.id": "001",
        "data.srcip": "203.0.113.7",
        "location": "/var/log/auth.log",
    }
    assert detect_profile([doc]) == "wazuh4"
    event = _norm(doc, input_cfg=InputConfig(naive_timezone="Europe/Madrid"))
    assert event.ts == datetime(2026, 9, 10, 8, 15, 32, 481000, tzinfo=UTC)  # CEST (UTC+2)
    assert event.severity == 5
    assert event.rule_groups == ("syslog", "sshd", "authentication_failed")
    assert event.tags == ("T1110.001", "T1021.004")
    assert event.entities["src_ip"] == "203.0.113.7"
    assert Condition("data.srcip", "203.0.113.7").matches(event)


def test_wazuh4_indexer_hit_is_unwrapped() -> None:
    hit = {
        "_index": "wazuh-alerts-4.x-2026.09.10",
        "_id": "abc123",
        "_source": {"timestamp": "2026-09-10T10:00:00.000+0000", "rule": {"id": "5710", "level": 5}},
    }
    event = _norm(hit)
    assert event.rule_id == "5710"
    assert event.event_id == "abc123"
    assert event.fields["_index"] == "wazuh-alerts-4.x-2026.09.10"
    assert "_source" in hit and "_id" not in hit["_source"]  # input untouched


def test_normalize_does_not_mutate_input(alerts: list[dict[str, Any]]) -> None:
    doc = json.loads(json.dumps(alerts[1]))
    snapshot = json.dumps(doc, sort_keys=True)
    _norm(doc)
    _norm(doc, project=["data.win.eventdata"])
    assert json.dumps(doc, sort_keys=True) == snapshot


@pytest.mark.parametrize(
    ("level", "expected"),
    [
        (5, 5),
        ("7", 7),
        (7.9, 7),
        (999, 16),
        (-3, 0),
        ("abc", None),
        (float("nan"), None),
        (float("inf"), None),
        (True, None),
        ([12], 12),
        ({"x": 1}, None),
        ("1" * 500, None),
    ],
)
def test_wazuh4_level_is_sanitized(level: Any, expected: int | None) -> None:
    doc = {"timestamp": "2026-09-10T10:00:00Z", "rule": {"id": "1", "level": level}}
    assert _norm(doc).severity == expected


@pytest.mark.parametrize(
    "value",
    [
        None,
        "",
        "not a date",
        "9999-12-31T23:59:59-05:00",  # overflows when converted to UTC
        "0001-01-01T00:00:00+01:00",
        {"nested": "dict"},
        True,
        12,  # too small to be an epoch
        "2026-13-45T99:99:99Z",
        "Sep 10 10:00:00",  # year-less syslog without a default year
    ],
)
def test_unparseable_timestamp_returns_none(value: Any) -> None:
    doc = {"timestamp": value, "rule": {"id": "5710", "level": 5}, "agent": {"id": "001", "name": "srv-web-01"}}
    assert normalize(doc, "wazuh4", tenant=TENANT) is None


def test_timestamp_formats() -> None:
    assert parse_time("2026-09-10T10:15:32.481+0300") == datetime(2026, 9, 10, 7, 15, 32, 481000, tzinfo=UTC)
    assert parse_time("2026-09-10T10:15:32.9690001Z") == datetime(2026, 9, 10, 10, 15, 32, 969000, tzinfo=UTC)
    assert parse_time(1789035332) == datetime.fromtimestamp(1789035332, tz=UTC)
    assert parse_time(1789035332123) == datetime.fromtimestamp(1789035332.123, tz=UTC)
    assert parse_time("Sep 10 10:00:00", default_year=2026) == datetime(2026, 9, 10, 10, 0, tzinfo=UTC)
    assert parse_time("2026-09-10 10:00:00", zone("America/Sao_Paulo")) == datetime(2026, 9, 10, 13, 0, tzinfo=UTC)
    assert parse_time(["2026-09-10T10:00:00Z"]) == datetime(2026, 9, 10, 10, 0, tzinfo=UTC)
    assert parse_time("Sep 10, 2026 @ 10:15:32") == datetime(2026, 9, 10, 10, 15, 32, tzinfo=UTC)


def test_syslog_year_from_default_year() -> None:
    doc = {"ts": "Dec 31 23:59:59", "host": "srv-web-01.example"}
    event = _norm(doc, "generic", default_year=2025)
    assert event.ts == datetime(2025, 12, 31, 23, 59, 59, tzinfo=UTC)


def test_hostile_shapes_never_raise() -> None:
    long_cmd = "A" * (MAX_ENTITY_CHARS * 3)
    doc = {
        "timestamp": "2026-09-10T10:00:00Z",
        "rule": {
            "id": {"not": "a string"},
            "level": [None, "x"],
            "groups": ["ok", {"x": 1}, ["nested", ["deeper"]], None, 3, "ok", "a,b"],
            "mitre": {"id": "t1110.001, attack.T1059, T12, garbage", "tactic": 42},
        },
        "agent": ["srv-web-01.example"],
        "predecoder": "not an object",
        "data": {
            "srcip": {"ip": "203.0.113.7"},
            "dstuser": "-",
            "srcuser": "(NULL)",
            "win": {"eventdata": {"commandLine": long_cmd, "targetUserName": ["svc_backup", "other"]}},
        },
        "location": 12345,
        "id": float("nan"),
    }
    event = _norm(doc)
    assert event.rule_id is None
    assert event.severity is None
    assert event.rule_groups == ("ok", "nested", "deeper", "3", "a", "b")
    assert event.tags == ("T1110.001", "T1059")
    assert event.mitre_tactics == ("42",)
    assert event.source is None  # agent is a list of scalars, not an object
    assert "src_ip" not in event.entities
    assert event.entities["user"] == "svc_backup"  # empty-ish "-" / "(NULL)" skipped, list -> first
    assert len(event.entities["command_line"]) == MAX_ENTITY_CHARS
    assert event.fields["data.win.eventdata.commandLine"] == long_cmd  # fields keep the raw value
    assert event.log_source == "12345"
    assert event.event_id is None


def test_list_caps_bound_hostile_documents() -> None:
    doc = {
        "timestamp": "2026-09-10T10:00:00Z",
        "rule": {"id": "1", "groups": [f"g{i}" for i in range(10_000)], "mitre": {"id": ["T1110"] * 5000}},
    }
    event = _norm(doc)
    assert len(event.rule_groups) == MAX_LIST_ITEMS
    assert event.tags == ("T1110",)


def test_deep_nesting_does_not_crash_detection() -> None:
    deep: dict[str, Any] = {}
    node = deep
    for _ in range(200):
        node["rule"] = {}
        node = node["rule"]
    assert detect_profile([deep]) == "generic"


def test_empty_text_matches_models_is_empty() -> None:
    for text in _EMPTY_TEXT:
        assert is_empty(text) and is_empty(f"  {text} ")
    for text in ("x", "0", "false", "none", "Unknown"):
        assert is_empty(text) == (text in _EMPTY_TEXT)


# ---- ecs ------------------------------------------------------------------------------------------------------


def test_ecs_alert_with_flat_kibana_keys(ecs_alerts: list[dict[str, Any]]) -> None:
    event = _norm(ecs_alerts[0], "ecs")
    assert event.ts == datetime(2026, 9, 10, 11, 0, 3, tzinfo=UTC)  # event.ingested wins over @timestamp
    assert event.rule_id == "0a1b2c3d-0000-4000-8000-000000000001"
    assert event.rule_name == "Multiple Logon Failure from the same Source Address"
    assert event.severity == 7
    assert event.source == "dc01.corp.example"
    assert event.log_source == "system.security"
    assert event.event_code == "4625"
    assert event.event_id == "5f0c6a4e0e2d4c0f9d3b0a1b2c3d4e5f"
    assert event.tags == ("T1110", "T1110.001")
    assert event.mitre_tactics == ("Credential Access",)
    assert event.rule_groups == ("Domain: Endpoint", "OS: Windows", "Tactic: Credential Access")
    assert event.entities == {"src_ip": "198.51.100.23", "user": "alice", "host": "dc01.corp.example"}
    assert event.os_platform == "windows"
    assert event.fields["kibana.alert.workflow_reason"] == "false_positive"


def test_ecs_nested_alert_and_process(ecs_alerts: list[dict[str, Any]]) -> None:
    flat = ecs_alerts[1]
    nested: dict[str, Any] = {}
    for key, value in flat.items():
        node = nested
        parts = key.split(".")
        for part in parts[:-1]:
            node = node.setdefault(part, {})
        node[parts[-1]] = value
    for doc in (flat, nested):
        event = _norm(doc, "ecs")
        assert event.severity == 10
        assert event.tags == ("T1059", "T1059.001")
        assert event.mitre_tactics == ("Execution",)
        assert event.entities["process"].endswith("powershell.exe")
        assert event.entities["parent_process"] == "C:\\Windows\\explorer.exe"
        assert event.entities["command_line"] == "powershell.exe -enc AAAA"
        assert event.log_source == "windows.sysmon_operational"
        assert event.rule_groups == ("process",)


@pytest.mark.parametrize(
    ("fields", "expected"),
    [
        ({"kibana.alert.severity": "low"}, 3),
        ({"kibana.alert.severity": "Medium"}, 7),
        ({"kibana.alert.severity": "high"}, 10),
        ({"kibana.alert.severity": "critical"}, 13),
        ({"kibana.alert.risk_score": 21}, 3),
        ({"kibana.alert.risk_score": 99}, 13),
        ({"event.severity": 73}, 10),
        ({"event.severity": 5}, 5),
        ({"event.severity": "critical"}, 13),
        ({"event.severity": -1}, None),
        ({}, None),
    ],
)
def test_ecs_severity_normalization(fields: dict[str, Any], expected: int | None) -> None:
    doc = {"@timestamp": "2026-09-10T11:00:00Z", "event": {"kind": "alert"}, **fields}
    assert _norm(doc, "ecs").severity == expected


def test_ecs_raw_event_platform_and_entities() -> None:
    doc = {
        "@timestamp": "2026-09-10T11:00:00Z",
        "host": {"name": "srv-web-01.example", "os": {"platform": "ubuntu"}},
        "event": {"dataset": "system.auth", "category": ["authentication"]},
        "source": {"ip": "203.0.113.7"},
        "user": {"name": "alice"},
        "url": {"full": "https://www.example.com/login"},
        "dns": {"question": {"name": "www.example.com"}},
    }
    event = _norm(doc, "ecs")
    assert event.rule_id is None
    assert event.os_platform == "linux"
    assert event.entities["url"] == "https://www.example.com/login"
    assert event.entities["domain"] == "www.example.com"


# ---- wazuh5 ---------------------------------------------------------------------------------------------------


def test_wazuh5_best_effort() -> None:
    doc = {
        "@timestamp": "2026-09-10T12:00:00Z",
        "event": {"original": "Sep 10 12:00:00 srv-web-01 sshd[1]: Failed password", "dataset": "sshd"},
        "wazuh": {"agent": {"name": "srv-web-01.example"}, "integration": {"name": "linux"}},
        "agent": {"name": "srv-web-01.example", "id": "001"},
        "rule": {
            "id": "7f2c9a8e-1111-4222-8333-944455556666",
            "title": "SSH authentication failure",
            "level": "high",
            "tags": ["attack.credential-access", "attack.t1110.001"],
        },
        "source": {"ip": "203.0.113.7"},
    }
    assert detect_profile([doc]) == "wazuh5"
    event = _norm(doc, "wazuh5")
    assert event.rule_id == "7f2c9a8e-1111-4222-8333-944455556666"
    assert event.rule_name == "SSH authentication failure"
    assert event.severity == 10
    assert event.source == "srv-web-01.example"
    assert event.log_source == "sshd"
    assert event.tags == ("T1110.001",)
    assert event.mitre_tactics == ("credential-access",)
    assert event.entities["src_ip"] == "203.0.113.7"


# ---- generic --------------------------------------------------------------------------------------------------


def test_generic_mapping_with_alternatives_and_naive_timezone() -> None:
    cfg = InputConfig(
        profile="generic",
        naive_timezone="Europe/Madrid",
        mapping={
            "ts": "when",
            "source": "box",
            "rule_id": "sig",
            "rule_name": "sig_name",
            "severity": "sev",
            "src_ip": "client|src",
            "entities.user": "Account",
            "tags": "techniques",
        },
    )
    doc = {
        "when": "2026-01-15 10:00:00",
        "box": "srv-db-01.example",
        "sig": "S-100",
        "sig_name": "Backup job failed",
        "sev": "medium",
        "src": "10.0.2.10",
        "account": "svc_backup",
        "techniques": "attack.t1078, T1110",
    }
    event = _norm(doc, "generic", input_cfg=cfg)
    assert event.ts == datetime(2026, 1, 15, 9, 0, tzinfo=UTC)  # CET (UTC+1) in winter
    assert event.source == "srv-db-01.example"
    assert event.rule_id == "S-100"
    assert event.severity == 7
    assert event.entities == {"src_ip": "10.0.2.10", "user": "svc_backup", "host": "srv-db-01.example"}
    assert event.tags == ("T1078", "T1110")


def test_generic_explicit_mapping_has_no_heuristic_fallback() -> None:
    cfg = InputConfig(mapping={"ts": "when", "source": "missing_column"})
    doc = {"when": "2026-09-10T10:00:00Z", "host": "srv-web-01.example"}
    event = _norm(doc, "generic", input_cfg=cfg)
    assert event.source is None


def test_generic_heuristics_without_mapping() -> None:
    doc = {
        "Timestamp": "2026-09-10T10:00:00Z",
        "Hostname": "srv-web-01.example",
        "Severity": "high",
        "Rule_ID": "R1",
        "src_ip": "192.0.2.10",
        "Channel": "Security",
        "EventID": "4625",
    }
    event = _norm(doc, "generic")
    assert event.ts == datetime(2026, 9, 10, 10, 0, tzinfo=UTC)
    assert event.source == "srv-web-01.example"
    assert event.severity == 10
    assert event.rule_id == "R1"
    assert event.log_source == "Security"
    assert event.os_platform == "windows"
    assert event.event_code == "4625"
    assert event.entities["src_ip"] == "192.0.2.10"


def test_generic_without_timestamp_is_none() -> None:
    assert normalize({"host": "srv-web-01.example", "msg": "no time here"}, "generic", tenant=TENANT) is None


def test_canonical_mapping_keys() -> None:
    assert canonical_mapping_key("timestamp") == "ts"
    assert canonical_mapping_key("entities.user") == "user"
    assert canonical_mapping_key("Entity.SRC_IP") == "src_ip"
    assert canonical_mapping_key("level") == "severity"
    assert canonical_mapping_key("entities.bogus") is None
    assert canonical_mapping_key("colour") is None


# ---- detection ------------------------------------------------------------------------------------------------


def test_detect_profile(alerts: list[dict[str, Any]], ecs_alerts: list[dict[str, Any]]) -> None:
    assert detect_profile(alerts) == "wazuh4"
    assert detect_profile(_lines("wazuh4_archives.json")) == "wazuh4"
    assert detect_profile(ecs_alerts) == "ecs"
    assert detect_profile([{"time": "2026-09-10T10:00:00Z", "msg": "x"}]) == "generic"
    assert detect_profile([]) == "generic"
    assert detect_profile(["not a doc", 3]) == "generic"  # type: ignore[list-item]
    # majority wins; junk documents do not flip the verdict
    assert detect_profile([*alerts, {"x": 1}, {"y": 2}]) == "wazuh4"
    hits = [{"_index": "wazuh-alerts-4.x-2026.09.10", "_id": str(i), "_source": doc} for i, doc in enumerate(alerts)]
    assert detect_profile(hits) == "wazuh4"


def test_normalize_auto_and_unknown_profile(alerts: list[dict[str, Any]]) -> None:
    assert _norm(alerts[0], "auto").rule_id == "5710"
    with pytest.raises(ValueError, match="unknown profile"):
        normalize(alerts[0], "splunk", tenant=TENANT)
    with pytest.raises(ValueError, match="unknown timezone"):
        normalize({"ts": "2026-09-10 10:00:00"}, "generic", input_cfg=InputConfig(naive_timezone="Mars/Olympus"))
    with pytest.raises(TypeError):
        normalize(["not", "a", "mapping"], "wazuh4")  # type: ignore[arg-type]


# ---- projection and flatten -----------------------------------------------------------------------------------


def test_projection_keeps_core_keys(alerts: list[dict[str, Any]]) -> None:
    event = _norm(alerts[0], project=["data.srcport", "does.not.exist"])
    assert event.fields["data.srcport"] == "51234"
    for key in ("timestamp", "rule.id", "rule.level", "agent.name", "agent.id", "location", "data.srcip"):
        assert key in event.fields
    assert "full_log" not in event.fields and "rule.pci_dss" not in event.fields
    assert "does.not.exist" not in event.fields
    assert Condition("data.srcip", "203.0.113.7").matches(event)
    assert event.fields["rule.groups"] == ["syslog", "sshd", "authentication_failed", "invalid_login"]


def test_projection_of_a_subtree(alerts: list[dict[str, Any]]) -> None:
    event = _norm(alerts[1], project=["data.win.eventdata"])
    assert event.fields["data.win.eventdata.logonType"] == "3"
    assert event.fields["data.win.eventdata.targetDomainName"] == "CORP"
    assert "data.win.system.message" not in event.fields
    assert event.fields["data.win.system.channel"] == "Security"  # core key


def test_projection_empty_and_generic_tracks_used_columns() -> None:
    cfg = InputConfig(mapping={"ts": "When", "source": "Box"})
    doc = {"When": "2026-09-10T10:00:00Z", "Box": "srv-db-01.example", "Noise": "x", "Account": "alice"}
    event = _norm(doc, "generic", input_cfg=cfg, project=())
    # "Account" feeds the user entity (heuristic), so it is kept; "Noise" is not
    assert event.fields == {"When": "2026-09-10T10:00:00Z", "Box": "srv-db-01.example", "Account": "alice"}
    heuristic = _norm({"time": "2026-09-10T10:00:00Z", "User": "alice", "Other": 1}, "generic", project=())
    assert heuristic.fields == {"time": "2026-09-10T10:00:00Z", "User": "alice"}


def test_fast_flatten_matches_models_flatten(alerts: list[dict[str, Any]], ecs_alerts: list[dict[str, Any]]) -> None:
    rng = random.Random(1234)

    def build(depth: int) -> Any:
        roll = rng.random()
        if depth > 3 or roll < 0.35:
            return rng.choice(["x", "", 0, 1.5, True, None, [], ["a", "b"], [1, {"k": 2}]])
        if roll < 0.55:
            return [build(depth + 1) for _ in range(rng.randint(0, 3))]
        if roll < 0.75:
            return [{f"k{rng.randint(0, 3)}": build(depth + 1)} for _ in range(rng.randint(1, 3))]
        return {f"f{rng.randint(0, 5)}.{rng.randint(0, 2)}": build(depth + 1) for _ in range(rng.randint(0, 4))}

    samples: list[dict[str, Any]] = [*alerts, *ecs_alerts, {}, {"a": {}}, {"a": [{}]}]
    samples += [{f"top{i}": build(0) for i in range(5)} for _ in range(300)]
    for doc in samples:
        assert fast_flatten(doc) == flatten(doc)


def test_bind_is_cached_and_equivalent(alerts: list[dict[str, Any]]) -> None:
    bound = bind("wazuh4", default_year=2026)
    assert bound is bind("wazuh4", default_year=2026)
    for doc in alerts:
        assert bound(doc) == normalize(doc, "wazuh4", default_year=2026)
    with pytest.raises(ValueError):
        bind("nope")


def test_unwrap_hit_requires_hit_markers() -> None:
    assert unwrap_hit({"_source": {"a": 1}}) == {"_source": {"a": 1}}  # no _id/_index: a normal field
    assert unwrap_hit({"_id": "x", "_source": {"a": 1}}) == {"a": 1, "_id": "x"}
    assert unwrap_hit({"_id": "x", "_source": {"a": 1, "_id": "inner"}})["_id"] == "inner"


# ---- regressions (review) -------------------------------------------------------------------------------------


def test_elastic7_siem_signal_is_an_alert() -> None:
    # Elasticsearch 7.x .siem-signals-* documents keep the rule under signal.*, not kibana.alert.*
    doc = {
        "@timestamp": "2026-09-10T11:00:05.123Z",
        "ecs": {"version": "1.12.0"},
        "event": {"kind": "signal"},
        "host": {"name": "dc01.corp.example"},
        "signal": {
            "status": "closed",
            "original_time": "2026-09-10T11:00:00Z",
            "original_event": {"code": "4625", "dataset": "system.security"},
            "rule": {
                "id": "0a1b2c3d-0000-4000-8000-000000000009",
                "name": "Multiple Logon Failure",
                "severity": "high",
                "risk_score": 73,
                "threat": [
                    {
                        "tactic": {"name": "Credential Access"},
                        "technique": [{"id": "T1110", "subtechnique": [{"id": "T1110.001"}]}],
                    }
                ],
            },
        },
    }
    assert detect_profile([doc]) == "ecs"
    event = _norm(doc, "ecs")
    assert event.rule_id == "0a1b2c3d-0000-4000-8000-000000000009"
    assert event.rule_name == "Multiple Logon Failure"
    assert event.severity == 10
    assert event.tags == ("T1110", "T1110.001")
    assert event.mitre_tactics == ("Credential Access",)
    assert event.event_code == "4625" and event.log_source == "system.security"
    projected = _norm(doc, "ecs", project=())
    assert projected.fields["signal.status"] == "closed"  # disposition evidence survives projection
    assert _norm({**doc, "signal": {"rule": {"id": "x", "risk_score": 99}}}, "ecs").severity == 13


@pytest.mark.parametrize(
    ("column", "value"),
    [
        ("priority", "1"),  # Suricata / Snort: 1 is the HIGHEST priority
        ("Level", "1"),  # Windows event Level: 1 = Critical
        ("severity", "0"),  # syslog severity: 0 = emergency
        ("severity", "2"),
    ],
)
def test_generic_unmapped_numeric_severity_is_not_guessed(column: str, value: str) -> None:
    # an inverted scale read as a Wazuh level would make a critical event look low and tunable;
    # unknown severity blocks tuning instead
    event = _norm({"time": "2026-09-10T10:00:00Z", "host": "srv-web-01.example", column: value}, "generic")
    assert event.severity is None


def test_generic_severity_names_and_explicit_mapping_still_work() -> None:
    assert _norm({"time": "2026-09-10T10:00:00Z", "priority": "High"}, "generic").severity == 10
    assert _norm({"time": "2026-09-10T10:00:00Z", "Level": "Critical"}, "generic").severity == 13
    assert _norm({"time": "2026-09-10T10:00:00Z", "rule.level": "12"}, "generic").severity == 12
    mapped = InputConfig(mapping={"ts": "time", "severity": "sev"})
    assert _norm({"time": "2026-09-10T10:00:00Z", "sev": "8"}, "generic", input_cfg=mapped).severity == 8


def test_timestamp_lacks_offset() -> None:
    from hushwatch.ingest.profiles import timestamp_lacks_offset

    assert not timestamp_lacks_offset({"timestamp": "2026-09-10T10:15:32.481+0000"}, "wazuh4")
    assert timestamp_lacks_offset({"timestamp": "Sep 10, 2026 @ 10:15:32.481", "rule.id": "1"}, "wazuh4")
    assert not timestamp_lacks_offset({"@timestamp": "2026-09-10T10:00:00Z"}, "ecs")
    assert not timestamp_lacks_offset({"time": 1789035332}, "generic")  # epoch: absolute
    assert timestamp_lacks_offset({"time": "Sep 10 10:00:00"}, "generic")
    cfg = InputConfig(mapping={"ts": "when"})
    assert timestamp_lacks_offset({"when": "2026-09-10 10:00:00"}, "generic", input_cfg=cfg)
    assert not timestamp_lacks_offset({"when": "2026-09-10T10:00:00-03:00"}, "generic", input_cfg=cfg)
    assert not timestamp_lacks_offset({"nothing": "here"}, "generic")
