"""Tests for the demo / ground-truth generator (hushwatch.demo).

One full-size dataset (default arguments) is generated once per module and scanned once: every alert is checked
against the Wazuh 4.x alerts.json shape and projected into a compact record that the scenario tests query. Small
datasets (10 days, low scale) cover determinism and argument handling quickly.
"""

from __future__ import annotations

import csv
import ipaddress
import json
import os
import re
import statistics
import subprocess
import sys
import time
from collections import Counter, defaultdict
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from itertools import pairwise
from pathlib import Path
from typing import Any, NamedTuple
from xml.etree import ElementTree as ET
from zoneinfo import ZoneInfo

import pytest

from hushwatch import demo
from hushwatch.config import load_config
from hushwatch.i18n import Entity, has, render
from hushwatch.models import iter_entities

UTC = timezone.utc
TZ = ZoneInfo(demo.TIMEZONE)
TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}\+0000$")
ID_RE = re.compile(r"^(\d{10})\.(\d+)$")
IPV4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
SYSTIME_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{7}Z$")
SYSLOG_TS_RE = re.compile(r"^[A-Z][a-z]{2} [ \d]\d \d{2}:\d{2}:\d{2}$")
ALLOWED_NETS = [
    ipaddress.ip_network(n)
    for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
] + [ipaddress.ip_network("127.0.0.1/32")]
SYSMON = "Microsoft-Windows-Sysmon/Operational"
SYSLOG_DECODERS = {"sshd", "pam", "sudo", "edgefw"}


class A(NamedTuple):
    """Compact projection of one alert."""

    ms: int
    rule: str
    level: int
    agent_id: str
    agent: str
    hostname: str | None
    location: str
    channel: str | None
    code: str | None
    srcip: str | None
    srcuser: str | None
    dstuser: str | None
    target_user: str | None
    ip_address: str | None
    dest_ip: str | None
    logon_type: str | None
    command: str | None
    has_dstport: bool
    fim_path: str | None
    alert_id: str
    frequency: int | None
    previous_lines: int


@dataclass
class Dataset:
    manifest: demo.DemoManifest
    elapsed: float
    alerts: list[A]
    problems: list[str] = field(default_factory=list)
    docs_by_rule: dict[str, dict[str, Any]] = field(default_factory=dict)  # one sample document per rule
    fim_chain_breaks: int = 0

    def where(self, **conditions: Any) -> list[A]:
        return [a for a in self.alerts if all(getattr(a, k) == v for k, v in conditions.items())]

    @property
    def now_ms(self) -> int:
        return int(self.manifest.now.timestamp() * 1000)


def _ms(ts: datetime) -> int:
    return int(ts.timestamp() * 1000)


def _local(ms: int) -> datetime:
    return datetime.fromtimestamp(ms / 1000, tz=UTC).astimezone(TZ)


def _parse_ts(text: str) -> int:
    return _ms(datetime.strptime(text, "%Y-%m-%dT%H:%M:%S.%f%z"))


def _ip_ok(text: str) -> bool:
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return True  # not an IP (e.g. a version number): other tests cover names
    return any(address in net for net in ALLOWED_NETS)


def _scan(path: Path) -> tuple[list[A], list[str], dict[str, dict[str, Any]], int]:
    alerts: list[A] = []
    problems: list[str] = []
    samples: dict[str, dict[str, Any]] = {}
    fired: Counter[str] = Counter()
    fim_after: dict[tuple[str, str], str] = {}
    fim_breaks = 0
    offset = 0
    last_ms = -1

    def problem(msg: str) -> None:
        if len(problems) < 50:
            problems.append(msg)

    with path.open("rb") as handle:
        for number, raw in enumerate(handle, start=1):
            line_offset = offset
            offset += len(raw)
            text = raw.decode("utf-8")
            doc = json.loads(text)
            keys = list(doc)
            if keys[:5] != ["timestamp", "rule", "agent", "manager", "id"] or keys[-1] != "location":
                problem(f"line {number}: key order {keys}")
            ts = doc["timestamp"]
            if not TS_RE.match(ts):
                problem(f"line {number}: timestamp {ts!r}")
            ms = _parse_ts(ts)
            if ms < last_ms:
                problem(f"line {number}: not sorted")
            last_ms = ms
            match = ID_RE.match(doc["id"])
            if not match or int(match.group(1)) != ms // 1000 or int(match.group(2)) != line_offset:
                problem(f"line {number}: id {doc['id']!r} (offset {line_offset})")
            rule = doc["rule"]
            if list(rule)[:3] != ["level", "description", "id"]:
                problem(f"line {number}: rule key order {list(rule)}")
            if not isinstance(rule["id"], str) or not rule["id"].isdigit():
                problem(f"line {number}: rule.id {rule['id']!r}")
            if not isinstance(rule["level"], int) or not 3 <= rule["level"] <= 16:
                problem(f"line {number}: rule.level {rule['level']!r}")
            fired[rule["id"]] += 1
            if rule.get("firedtimes") != fired[rule["id"]]:
                problem(f"line {number}: firedtimes {rule.get('firedtimes')} != {fired[rule['id']]}")
            if not isinstance(rule.get("mail"), bool) or rule["mail"] != (rule["level"] >= 12):
                problem(f"line {number}: mail {rule.get('mail')!r}")
            if not rule.get("groups") or not all(isinstance(g, str) for g in rule["groups"]):
                problem(f"line {number}: groups {rule.get('groups')!r}")
            if any(
                g.startswith(("pci_dss_", "gdpr_", "hipaa_", "nist_800_53_", "tsc_", "gpg13_")) for g in rule["groups"]
            ):
                problem(f"line {number}: compliance group left in rule.groups")
            mitre = rule.get("mitre")
            if mitre is not None and (
                list(mitre) != ["id", "tactic", "technique"] or not mitre["id"] or not mitre["tactic"]
            ):
                problem(f"line {number}: mitre {mitre!r}")
            agent = doc["agent"]
            if not re.fullmatch(r"\d{3}", agent.get("id", "")) or not agent.get("name"):
                problem(f"line {number}: agent {agent!r}")
            if agent["id"] == "000" and "ip" in agent:
                problem(f"line {number}: manager with agent.ip")
            if doc["manager"] != {"name": demo.MANAGER_NAME}:
                problem(f"line {number}: manager {doc['manager']!r}")
            decoder = doc["decoder"]["name"]
            data = doc.get("data", {})
            win = data.get("win")
            if decoder == "windows_eventchannel":
                system = win["system"]
                if "full_log" in doc or doc["location"] != "EventChannel" or "predecoder" in doc:
                    problem(f"line {number}: eventchannel doc shape")
                if not SYSTIME_RE.match(system["systemTime"]) or not system["eventID"].isdigit():
                    problem(f"line {number}: win.system {system!r}")
                if system["computer"] != f"{agent['name']}.corp.example":
                    problem(f"line {number}: computer {system['computer']!r}")
                for value in win["eventdata"].values():
                    if "\\" in value and "\\\\" not in value:
                        problem(f"line {number}: single backslash in eventdata {value!r}")
            elif decoder in SYSLOG_DECODERS:
                pre = doc.get("predecoder", {})
                if not doc.get("full_log") or not SYSLOG_TS_RE.match(pre.get("timestamp", "")):
                    problem(f"line {number}: syslog shape")
                if not doc["full_log"].startswith(f"{pre['timestamp']} {pre['hostname']} {pre['program_name']}"):
                    problem(f"line {number}: full_log header {doc['full_log'][:60]!r}")
                if doc["decoder"].get("parent") != decoder:
                    problem(f"line {number}: decoder parent")
            elif decoder in ("web-accesslog", "syscheck_integrity_changed"):
                if not doc.get("full_log"):
                    problem(f"line {number}: missing full_log")
            elif decoder != "sca":
                problem(f"line {number}: unexpected decoder {decoder}")
            if "frequency" in rule and not isinstance(doc.get("previous_output"), str):
                problem(f"line {number}: correlation alert without previous_output")
            for ip in IPV4_RE.findall(text):
                if not _ip_ok(ip):
                    problem(f"line {number}: non-documentation public IP {ip}")
            syscheck = doc.get("syscheck")
            if syscheck:
                key = (agent["name"], syscheck["path"])
                if key in fim_after and fim_after[key] != syscheck["md5_before"]:
                    fim_breaks += 1
                fim_after[key] = syscheck["md5_after"]
            samples.setdefault(rule["id"], doc)
            eventdata = win["eventdata"] if win else {}
            alerts.append(
                A(
                    ms=ms,
                    rule=rule["id"],
                    level=rule["level"],
                    agent_id=agent["id"],
                    agent=agent["name"],
                    hostname=doc.get("predecoder", {}).get("hostname"),
                    location=doc["location"],
                    channel=win["system"]["channel"] if win else None,
                    code=win["system"]["eventID"] if win else None,
                    srcip=data.get("srcip"),
                    srcuser=data.get("srcuser"),
                    dstuser=data.get("dstuser"),
                    target_user=eventdata.get("targetUserName"),
                    ip_address=eventdata.get("ipAddress"),
                    dest_ip=eventdata.get("destinationIp"),
                    logon_type=eventdata.get("logonType"),
                    command=eventdata.get("commandLine"),
                    has_dstport="dstport" in data,
                    fim_path=syscheck["path"] if syscheck else None,
                    alert_id=doc["id"],
                    frequency=rule.get("frequency"),
                    previous_lines=len(doc["previous_output"].split("\n")) if "previous_output" in doc else 0,
                )
            )
    return alerts, problems, samples, fim_breaks


@pytest.fixture(scope="module")
def full(tmp_path_factory: pytest.TempPathFactory) -> Dataset:
    out = tmp_path_factory.mktemp("demo-full")
    started = time.perf_counter()
    manifest = demo.generate(out)
    elapsed = time.perf_counter() - started
    alerts, problems, samples, fim_breaks = _scan(manifest.alerts_path)
    return Dataset(manifest, elapsed, alerts, problems, samples, fim_breaks)


def _small(out: Path, **kwargs: Any) -> demo.DemoManifest:
    params: dict[str, Any] = {"days": 10, "scale": 0.1, "agents": 28}
    params.update(kwargs)
    return demo.generate(out, **params)


def _files(root: Path) -> dict[str, bytes]:
    return {p.relative_to(root).as_posix(): p.read_bytes() for p in sorted(root.rglob("*")) if p.is_file()}


# ---- volume, speed, schema -------------------------------------------------------------------------------------


def test_generation_is_fast_and_sized_like_the_spec(full: Dataset) -> None:
    assert full.elapsed < 20.0, f"generation took {full.elapsed:.1f}s (budget ~15s)"
    assert 100_000 <= full.manifest.alerts <= 250_000
    assert len(full.alerts) == full.manifest.alerts
    assert sum(full.manifest.rule_counts.values()) == full.manifest.alerts


def test_every_alert_has_the_wazuh_4x_alerts_json_shape(full: Dataset) -> None:
    assert full.problems == []


def test_window_bounds_and_clock(full: Dataset) -> None:
    manifest = full.manifest
    assert manifest.now == demo.DEFAULT_NOW
    assert manifest.start == demo.DEFAULT_NOW - timedelta(days=21)
    assert full.alerts[0].ms >= _ms(manifest.start)
    assert full.alerts[-1].ms < full.now_ms
    # "now" for files is the max event timestamp: always-on sources reach the last minutes of the window
    assert full.now_ms - full.alerts[-1].ms < 5 * 60_000


def test_realistic_sample_documents(full: Dataset) -> None:
    sshd = full.docs_by_rule["5710"]
    assert sshd["decoder"] == {"parent": "sshd", "name": "sshd"}
    assert sshd["rule"]["mitre"]["id"] == ["T1110.001", "T1021.004"]
    assert sshd["rule"]["groups"] == ["syslog", "sshd", "authentication_failed", "invalid_login"]
    assert sshd["rule"]["pci_dss"] == ["10.2.4", "10.2.5", "10.6.1"]
    assert set(sshd["data"]) == {"srcip", "srcport", "srcuser"}
    assert "Invalid user " in sshd["full_log"]
    logon = full.docs_by_rule["60106"]
    assert logon["data"]["win"]["system"]["providerName"] == "Microsoft-Windows-Security-Auditing"
    assert logon["rule"]["mitre"]["tactic"][:2] == ["Defense Evasion", "Persistence"]
    correlated = full.docs_by_rule["5712"]
    assert correlated["rule"]["frequency"] == 8 and correlated["rule"]["level"] == 10
    assert list(correlated["rule"]).index("frequency") < list(correlated["rule"]).index("firedtimes")
    fim = full.docs_by_rule["550"]
    assert fim["location"] == "syscheck" and fim["syscheck"]["event"] == "modified"
    sca = full.docs_by_rule["19004"]
    assert sca["rule"]["description"].startswith("SCA summary: CIS ")
    assert "$(" not in sca["rule"]["description"]
    assert full.fim_chain_breaks == 0  # md5_before of a change is the md5_after of the previous one


def test_privacy_only_documentation_addresses_and_example_names(full: Dataset) -> None:
    out = full.manifest.out_dir
    for path in sorted(out.rglob("*")):
        if not path.is_file() or path.name == demo.ALERTS_FILE:
            continue  # alerts were checked line by line during the scan
        text = path.read_text(encoding="utf-8")
        assert all(_ip_ok(ip) for ip in IPV4_RE.findall(text)), path.name
        assert not re.search(r"[\w.+-]+@[\w-]+\.[\w.-]+", text), path.name
        assert not re.search(r"\b[\w-]+\.(?:com|net|org|io|local|lan)\b", text, re.IGNORECASE), path.name
    fqdns = {a.agent for a in full.alerts} | {h for h in (a.hostname for a in full.alerts) if h}
    assert all("." not in name for name in fqdns)
    sample_text = json.dumps(full.docs_by_rule)
    assert set(re.findall(r"[\w-]+\.corp\.\w+", sample_text)) <= {
        f"{name}.corp.example" for name in full.manifest.agent_names
    }


# ---- determinism ---------------------------------------------------------------------------------------------


def test_same_seed_gives_identical_bytes(tmp_path: Path) -> None:
    first = _small(tmp_path / "one")
    second = _small(tmp_path / "two")
    assert _files(tmp_path / "one") == _files(tmp_path / "two")
    assert first.to_dict() == second.to_dict()


def test_identical_bytes_across_processes_and_hash_seeds(tmp_path: Path) -> None:
    _small(tmp_path / "here")
    code = (
        "import sys; from pathlib import Path; from hushwatch import demo; "
        "demo.generate(Path(sys.argv[1]), days=10, scale=0.1, agents=28)"
    )
    env = {**os.environ, "PYTHONHASHSEED": "12345"}
    subprocess.run([sys.executable, "-c", code, str(tmp_path / "there")], check=True, env=env, timeout=120)
    assert _files(tmp_path / "here") == _files(tmp_path / "there")


def test_different_seed_changes_the_alerts(tmp_path: Path) -> None:
    _small(tmp_path / "one", seed=7)
    _small(tmp_path / "two", seed=8)
    assert (tmp_path / "one" / "alerts.json").read_bytes() != (tmp_path / "two" / "alerts.json").read_bytes()


def test_default_now_is_fixed_not_wallclock(tmp_path: Path) -> None:
    manifest = _small(tmp_path)
    assert manifest.now == demo.DEFAULT_NOW
    time.sleep(1.1)
    again = _small(tmp_path / "later")
    assert again.now == demo.DEFAULT_NOW
    assert (tmp_path / "alerts.json").read_bytes() == (tmp_path / "later" / "alerts.json").read_bytes()


def test_custom_now_and_days(tmp_path: Path) -> None:
    now = datetime(2026, 3, 2, 18, 30, 45, 123456, tzinfo=timezone(timedelta(hours=-3)))
    manifest = _small(tmp_path, now=now, days=12)
    expected = now.astimezone(UTC).replace(microsecond=0)
    assert manifest.now == expected
    assert manifest.start == expected - timedelta(days=12)
    first = json.loads(manifest.alerts_path.open(encoding="utf-8").readline())
    assert _parse_ts(first["timestamp"]) >= _ms(manifest.start)
    last = manifest.alerts_path.read_text(encoding="utf-8").rstrip("\n").rsplit("\n", 1)[-1]
    assert _parse_ts(json.loads(last)["timestamp"]) < _ms(expected)
    assert manifest.holiday is not None and manifest.start.date() <= manifest.holiday <= expected.date()


def test_scale_changes_background_but_never_the_planted_scenarios(tmp_path: Path) -> None:
    low = _small(tmp_path / "low", scale=0.1)
    high = _small(tmp_path / "high", scale=0.3)
    assert high.alerts > low.alerts
    for background_rule in ("5501", "67027"):  # cron sessions, process creation: pure background
        assert high.rule_counts[background_rule] > 2.4 * low.rule_counts[background_rule]
    for sid in ("a", "b", "c", "d", "e", "f", "g", "i"):
        assert low.scenario(sid).count == high.scenario(sid).count, sid
        assert low.scenario(sid).start == high.scenario(sid).start, sid


def test_agents_parameter_sets_the_laptop_count(tmp_path: Path) -> None:
    manifest = _small(tmp_path, agents=30)
    laptops = [n for n in manifest.agent_names if n.startswith("lap-")]
    assert laptops == [f"lap-{i:03d}" for i in range(1, 11)]
    tiny = _small(tmp_path / "tiny", agents=1)
    assert sum(n.startswith("lap-") for n in tiny.agent_names) == 8  # lap-007 (beacon) always exists


@pytest.mark.parametrize(
    "kwargs",
    [
        {"days": 9},
        {"days": 91},
        {"days": 10.5},
        {"scale": 0},
        {"scale": True},
        {"scale": 25},
        {"agents": 0},
        {"agents": 501},
        {"seed": "7"},
        {"seed": True},
        {"now": datetime(2026, 1, 1, 12, 0)},
    ],
)
def test_invalid_arguments_are_rejected(tmp_path: Path, kwargs: dict[str, Any]) -> None:
    with pytest.raises(ValueError):
        demo.generate(tmp_path, **kwargs)
    assert not (tmp_path / demo.ALERTS_FILE).exists()


def test_now_at_night_during_the_backup_job(tmp_path: Path) -> None:
    now = datetime(2026, 6, 9, 3, 50, tzinfo=TZ)  # a Tuesday, 03:50 local: backup running, laptops off
    manifest = _small(tmp_path, now=now)
    alerts = {}
    with manifest.alerts_path.open(encoding="utf-8") as handle:
        for line in handle:
            doc = json.loads(line)
            alerts[doc["id"]] = _parse_ts(doc["timestamp"])
    with manifest.dispositions_path.open(encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            closed = _ms(datetime.strptime(row["closed_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC))
            assert closed <= _ms(manifest.now)
            if row["alert_id"]:
                assert closed >= alerts[row["alert_id"]]
    raw = json.loads(manifest.agents_path.read_text(encoding="utf-8"))
    for item in raw["data"]["affected_items"]:
        if item["name"].startswith("lap-"):
            assert item["status"] == "disconnected"
        if "lastKeepAlive" in item and not item["lastKeepAlive"].startswith("9999"):
            assert item["lastKeepAlive"] <= manifest.now.strftime("%Y-%m-%dT%H:%M:%SZ")
    assert manifest.scenario("m").details["events_outside_on_hours"] == 0


def test_a_failed_write_leaves_no_partial_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls = {"n": 0}
    original = demo._account

    def boom(*args: Any) -> None:
        calls["n"] += 1
        if calls["n"] == 500:
            raise RuntimeError("disk full")
        original(*args)

    monkeypatch.setattr(demo, "_account", boom)
    with pytest.raises(RuntimeError, match="disk full"):
        _small(tmp_path)
    assert not (tmp_path / "alerts.json").exists()
    assert not list(tmp_path.glob("*.partial"))


def test_large_fleets_get_valid_unique_addresses() -> None:
    fleet = demo._fleet(480)
    addresses = [a.ip for a in fleet if a.ip]
    assert len(addresses) == len(set(addresses))
    for address in addresses:
        assert ipaddress.ip_address(address).is_private
    assert fleet[-4].name == "lap-480" and fleet[-4].owner == "xavier19"


def test_output_directory_is_created_and_regeneration_is_idempotent(tmp_path: Path) -> None:
    target = tmp_path / "a" / "b" / "c"
    _small(target)
    before = _files(target)
    _small(target)
    assert _files(target) == before
    assert not list(target.glob("*.partial"))


# ---- manifest --------------------------------------------------------------------------------------------------


def test_manifest_exposes_paths_and_ground_truth(full: Dataset) -> None:
    manifest = full.manifest
    for path in (manifest.alerts_path, manifest.agents_path, manifest.dispositions_path, manifest.config_path):
        assert path.is_file()
    assert manifest.rules_dir.is_dir() and (manifest.rules_dir / "local_rules.xml").is_file()
    assert manifest.manifest_path.is_file()
    ids = [s.id for s in manifest.ground_truth]
    assert len(ids) == len(set(ids))
    expected_ids = set("abcdefghijklmnoqrs") | {"p1", "p2", "p3", "t1", "t2", "t3", "t4", "t5"}
    assert set(ids) == expected_ids
    assert manifest.scenarios is manifest.ground_truth
    assert manifest.scenario("trap.ssh_brute_force").id == "d"
    with pytest.raises(KeyError):
        manifest.scenario("nope")
    for scenario in manifest.ground_truth:
        assert scenario.category in ("noise_safe", "noise_trap", "silence", "coverage", "pipeline", "tuning")
        assert scenario.title and scenario.key
        assert scenario.count == sum(n for _, n in scenario.counts) or not scenario.counts


def test_manifest_round_trip(full: Dataset) -> None:
    loaded = demo.load_manifest(full.manifest.manifest_path)
    assert loaded.to_dict() == full.manifest.to_dict()
    assert demo.load_manifest(full.manifest.out_dir).alerts_path == full.manifest.alerts_path
    raw = json.loads(full.manifest.manifest_path.read_text(encoding="utf-8"))
    assert raw["schema"] == demo.DEMO_SCHEMA
    assert raw["files"]["alerts"] == "alerts.json"  # relative: the directory can be moved


def test_manifest_counts_match_the_alerts(full: Dataset) -> None:
    by_rule = Counter(a.rule for a in full.alerts)
    assert dict(by_rule) == full.manifest.rule_counts
    checks = {
        "a": lambda a: a.agent == "srv-backup-01" and a.target_user == "svc_backup",
        "b": lambda a: a.srcip == demo.SCANNER_IP,
        "d": lambda a: a.srcip == demo.BRUTE_FORCE_IP,
        "e": lambda a: a.ip_address == demo.SPRAY_IP,
        "f": lambda a: a.dest_ip == demo.BEACON_IP,
        "g": lambda a: a.srcip == demo.SLOW_BURN_IP,
        "h": lambda a: a.rule == "92601",
        "s": lambda a: a.command is not None and "-Enc " in a.command,
    }
    for sid, predicate in checks.items():
        scenario = full.manifest.scenario(sid)
        selected = [a for a in full.alerts if predicate(a)]
        assert len(selected) == scenario.count, sid
        assert dict(Counter(a.rule for a in selected)) == dict(scenario.counts), sid
        assert scenario.start is not None and scenario.end is not None
        assert _ms(scenario.start) == selected[0].ms and _ms(scenario.end) == selected[-1].ms, sid


def test_load_manifest_rejects_foreign_files(tmp_path: Path) -> None:
    (tmp_path / "manifest.json").write_text(json.dumps({"schema": "other"}), encoding="utf-8")
    with pytest.raises(ValueError):
        demo.load_manifest(tmp_path)
    (tmp_path / "manifest.json").write_text(json.dumps({"schema": demo.DEMO_SCHEMA}), encoding="utf-8")
    with pytest.raises(ValueError):
        demo.load_manifest(tmp_path / "manifest.json")
    with pytest.raises(OSError):
        demo.load_manifest(tmp_path / "missing.json")
    with pytest.raises(ValueError):
        demo.PlantedScenario.from_dict({"id": "x"})


def test_load_manifest_refuses_paths_outside_its_directory(full: Dataset, tmp_path: Path) -> None:
    raw = json.loads(full.manifest.manifest_path.read_text(encoding="utf-8"))
    raw["files"]["alerts"] = "../../../etc/passwd"
    (tmp_path / "manifest.json").write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(ValueError, match="outside"):
        demo.load_manifest(tmp_path)


def test_scenario_messages_are_translated_and_wrap_entities(full: Dataset) -> None:
    for scenario in full.manifest.ground_truth:
        message = scenario.message()
        assert has(message.key), message.key
        english, spanish = render(message, "en"), render(message, "es")
        assert "{" not in english and "{" not in spanish, scenario.id
        assert english != spanish, scenario.id
        for entity in iter_entities(message):
            assert entity.kind in ("host", "user", "ip", "file")
            assert entity.value in english
    masked = render(full.manifest.scenario("d").message(), "en", lambda e: f"<{e.kind}>")
    assert demo.BRUTE_FORCE_IP not in masked and "<ip>" in masked
    summary = render(full.manifest.summary(), "es")
    assert "alertas" in summary and "semilla 7" in summary
    assert isinstance(full.manifest.scenario("a").message().params["user"], Entity)


# ---- planted noise scenarios -------------------------------------------------------------------------------------


def test_a_svc_backup_nightly_logons(full: Dataset) -> None:
    planted = [a for a in full.alerts if a.target_user == "svc_backup"]
    assert planted and all(a.agent == "srv-backup-01" and a.rule == "60106" and a.logon_type == "4" for a in planted)
    assert all(0 <= _local(a.ms).hour < 5 for a in planted)
    nights = {_local(a.ms).date() for a in planted}
    assert len(nights) >= full.manifest.days - 1  # every night of the window
    share = len(planted) / full.manifest.rule_counts["60106"]
    assert share >= 0.25
    assert full.manifest.scenario("a").review_required is False


def test_b_internal_scanner_every_night_on_every_web_server(full: Dataset) -> None:
    planted = [a for a in full.alerts if a.srcip == demo.SCANNER_IP]
    assert {a.rule for a in planted} == {"5710"}
    assert {a.agent for a in planted} == {f"srv-web-{i:02d}" for i in range(1, 7)}
    assert len({_local(a.ms).date() for a in planted}) >= full.manifest.days - 1
    per_agent: dict[str, list[int]] = defaultdict(list)
    for a in planted:
        per_agent[a.agent].append(a.ms)
    gaps = [b - a for times in per_agent.values() for a, b in pairwise(times)]
    assert min(gaps) >= 20_000  # never 8 attempts within 120 s: 5712 cannot fire for the scanner
    assert planted[0].ms - _ms(full.manifest.start) < 2 * 86_400_000
    assert len(planted) / full.manifest.rule_counts["5710"] >= 0.25
    scenario = full.manifest.scenario("b")
    assert scenario.review_required is True and "5712" in scenario.details["dependents"]


def test_c_fim_noise_on_application_logs(full: Dataset) -> None:
    planted = [a for a in full.alerts if a.fim_path and a.fim_path.startswith("/var/log/app/")]
    assert {a.agent for a in planted} == {"srv-db-01", "srv-db-02", "srv-db-03"}
    assert {a.rule for a in planted} == {"550"}
    assert len({_local(a.ms).date() for a in planted}) >= full.manifest.days
    assert len(planted) / full.manifest.rule_counts["550"] > 0.9


def test_d_brute_force_from_new_external_ip_with_correlation_alerts(full: Dataset) -> None:
    planted = [a for a in full.alerts if a.srcip == demo.BRUTE_FORCE_IP]
    assert {a.agent for a in planted} == {"srv-web-02"}
    assert planted[0].ms >= full.now_ms - 48 * 3_600_000
    frequency = [a for a in planted if a.rule == "5712"]
    assert len(frequency) >= 20
    assert all(a.level == 10 and a.frequency == 8 and a.previous_lines == 7 for a in frequency)
    assert Counter(a.rule for a in planted)["5710"] > 500
    # the only 5712 alerts in the whole dataset come from the planted brute force
    assert {a.srcip for a in full.alerts if a.rule == "5712"} == {demo.BRUTE_FORCE_IP}
    assert full.manifest.scenario("d").must_not_hide


def test_e_password_spray_low_and_slow(full: Dataset) -> None:
    planted = [a for a in full.alerts if a.ip_address == demo.SPRAY_IP]
    assert {a.agent for a in planted} == {"dc01"} and {a.rule for a in planted} == {"60122"}
    assert planted[0].ms >= full.now_ms - 72 * 3_600_000
    assert len({a.target_user for a in planted}) >= 30
    gaps = [b.ms - a.ms for a, b in pairwise(planted)]
    assert min(gaps) >= 35_000
    assert "60204" not in full.manifest.rule_counts  # too slow for the frequency rule: only breadth gives it away


def test_f_beacon_every_five_minutes_while_the_laptop_is_on(full: Dataset) -> None:
    planted = [a for a in full.alerts if a.dest_ip == demo.BEACON_IP]
    assert {a.agent for a in planted} == {"lap-007"} and {a.rule for a in planted} == {"92150"}
    assert planted[0].ms >= full.now_ms - 6 * 86_400_000
    gaps = [b.ms - a.ms for a, b in pairwise(planted) if b.ms - a.ms < 3_600_000]
    assert abs(statistics.median(gaps) - 300_000) <= 5_000
    assert all(295_000 <= g <= 305_000 for g in gaps)
    assert all(_local(a.ms).weekday() < 5 and 7 <= _local(a.ms).hour < 20 for a in planted)
    assert full.manifest.scenario("f").details["share_of_rule"] >= 0.2


def test_g_slow_burn_internal_host_with_a_level_12_alert(full: Dataset) -> None:
    planted = [a for a in full.alerts if a.srcip == demo.SLOW_BURN_IP]
    assert {a.agent for a in planted} == {"srv-web-03"}
    probes = [a for a in planted if a.rule == "31101"]
    assert len({_local(a.ms).date() for a in probes}) >= full.manifest.days
    critical = [a for a in planted if a.rule == "31106"]
    assert len(critical) == 2 and all(a.level == 12 for a in critical)
    assert [a for a in full.alerts if a.rule == "31106"] == critical
    assert len(probes) / full.manifest.rule_counts["31101"] >= 0.25
    holiday = full.manifest.holiday
    assert all(_local(a.ms).date() != holiday for a in critical)


def test_h_noisy_level_12_rule(full: Dataset) -> None:
    planted = [a for a in full.alerts if a.rule == "92601"]
    assert all(a.level == 12 for a in planted)
    assert len(planted) / full.manifest.days >= 40
    assert {a.agent for a in planted} == {"dc01", "dc02", "srv-app-02", "srv-app-03"}


def test_s_macro_powershell_hidden_in_noisy_process_rules(full: Dataset) -> None:
    scenario = full.manifest.scenario("s")
    planted = [a for a in full.alerts if a.command == dict(scenario.conditions)["data.win.eventdata.commandLine"]]
    assert [a.rule for a in planted] == ["67027", "92001"] and {a.agent for a in planted} == {"lap-003"}
    assert full.now_ms - 3 * 86_400_000 < planted[0].ms < full.now_ms - 3_600_000
    # the same interpreter runs from scheduled tasks all the time: a tune keyed on its image alone hides the attack
    scheduled = [a for a in full.alerts if a.rule == "92001" and a.command and "-File C:\\\\Scripts" in a.command]
    assert len(scheduled) > 1000
    assert scenario.must_not_hide and "noise.tune" in scenario.forbidden_kinds


def test_benign_candidates_never_share_an_entity_with_high_level_alerts(full: Dataset) -> None:
    high = [a for a in full.alerts if a.level >= 10]
    assert not [a for a in high if a.agent == "srv-backup-01" or a.agent.startswith("srv-db-")]
    assert not [a for a in high if a.srcip == demo.SCANNER_IP or a.target_user == "svc_backup"]


def test_background_never_reuses_planted_addresses(full: Dataset) -> None:
    for ip, sid in (
        (demo.BRUTE_FORCE_IP, "d"),
        (demo.SPRAY_IP, "e"),
        (demo.BEACON_IP, "f"),
        (demo.SLOW_BURN_IP, "g"),
        (demo.SCANNER_IP, "b"),
    ):
        uses = [a for a in full.alerts if ip in (a.srcip, a.ip_address, a.dest_ip)]
        assert len(uses) == full.manifest.scenario(sid).count, ip


# ---- planted silence / coverage / pipeline scenarios ---------------------------------------------------------------


def test_i_dc02_silent_after_audit_log_cleared(full: Dataset) -> None:
    dc02 = full.where(agent="dc02")
    silence_start = full.now_ms - 30 * 3_600_000
    assert dc02[-1].ms < silence_start
    cleared = [a for a in dc02 if a.code == "1102"]
    assert len(cleared) == 1 and cleared[0].rule == "63103" and cleared[0].level == 12
    assert 19 * 60_000 <= silence_start - cleared[0].ms <= 21 * 60_000
    assert dc02[-1].ms - cleared[0].ms < 21 * 60_000  # dc02 still sent events after the clear, then nothing
    assert full.manifest.scenario("i").details["also_expected"] == ["pipeline.agent_no_data"]


def test_j_sysmon_channel_stops_while_security_continues(full: Dataset) -> None:
    host = full.where(agent="srv-backup-01")
    stop = full.now_ms - 48 * 3_600_000
    sysmon = [a for a in host if a.channel == SYSMON]
    assert sysmon and sysmon[-1].ms < stop
    days_with_sysmon = {_local(a.ms).date() for a in sysmon}
    assert len(days_with_sysmon) >= full.manifest.days - 3
    assert sum(1 for a in host if a.channel == "Security" and a.ms >= stop) > 50


def test_k_firewall_field_lost_after_firmware_upgrade(full: Dataset) -> None:
    fw = [a for a in full.alerts if a.hostname == "fw-edge-01"]
    assert {(a.agent_id, a.agent, a.location) for a in fw} == {("000", demo.MANAGER_NAME, demo.FIREWALL_IP)}
    upgrade = _ms(full.manifest.scenario("k").start or full.manifest.now)
    assert full.now_ms - 4 * 86_400_000 - 86_400_000 < upgrade <= full.now_ms - 3 * 86_400_000
    before = [a for a in fw if a.ms < upgrade]
    after = [a for a in fw if a.ms >= upgrade]
    assert len(before) >= 100 and len(after) >= 100
    assert all(a.has_dstport for a in before) and not any(a.has_dstport for a in after)


def test_l_heartbeat_rule_goes_dark_on_one_agent(full: Dataset) -> None:
    stop = full.now_ms - 7 * 86_400_000
    sca = [a for a in full.alerts if a.rule == "19004"]
    db02 = [a for a in sca if a.agent == "srv-db-02"]
    assert db02 and db02[-1].ms < stop
    per_day = len([a for a in db02 if a.ms < stop]) / ((stop - _ms(full.manifest.start)) / 86_400_000)
    assert 1.5 <= per_day <= 2.5
    still = {a.agent for a in sca if a.ms >= stop}
    # srv-legacy-01 keeps its heartbeat until it disconnects (5 days ago)
    assert still == {f"srv-web-{i:02d}" for i in range(1, 7)} | {"srv-db-01", "srv-db-03", "srv-legacy-01"}
    assert set(full.manifest.scenario("l").details["rule_still_fires_on"]) == still
    assert full.where(agent="srv-db-02")[-1].ms > full.now_ms - 3_600_000  # the agent itself stays alive


def test_r_rule_stops_matching_everywhere_while_sources_stay_alive(full: Dataset) -> None:
    change = _ms(full.manifest.scenario("r").start or full.manifest.now)
    assert not [a for a in full.alerts if a.rule == "5502" and a.ms >= change]
    assert len([a for a in full.alerts if a.rule == "5502"]) > 1000
    linux = {f"srv-web-{i:02d}" for i in range(1, 7)} | {"srv-db-01", "srv-db-02", "srv-db-03", demo.MANAGER_NAME}
    assert {a.agent for a in full.alerts if a.rule == "5501" and a.ms >= change} == linux


def test_m_laptops_only_send_during_business_hours(full: Dataset) -> None:
    holiday = full.manifest.holiday
    laptops = [a for a in full.alerts if a.agent.startswith("lap-")]
    assert laptops
    for a in laptops:
        local = _local(a.ms)
        assert local.weekday() < 5 and local.date() != holiday, a
        assert (local.hour, local.minute) >= (7, 45) and local.hour < 19, a
    assert full.manifest.scenario("m").details["events_outside_on_hours"] == 0
    business_days = {_local(a.ms).date() for a in laptops}
    assert holiday is not None and holiday not in business_days
    per_laptop = Counter(a.agent for a in laptops)
    assert len(per_laptop) == 20 and min(per_laptop.values()) > 100


def test_n_o_coverage_gaps(full: Dataset) -> None:
    windows = {a.agent for a in full.alerts if a.channel}
    sysmon_hosts = {a.agent for a in full.alerts if a.channel == SYSMON}
    assert windows - sysmon_hosts == {"srv-app-01"}
    assert full.where(agent="srv-app-01", channel="Security")
    codes: dict[str, set[str]] = defaultdict(set)
    for a in full.alerts:
        if a.channel == "Security" and a.code:
            codes[a.agent].add(a.code)
    assert "4624" in codes["srv-app-02"] and "4688" not in codes["srv-app-02"]
    assert {h for h, c in codes.items() if "4688" not in c} == {"srv-app-02"}


def test_pipeline_inventory(full: Dataset) -> None:
    raw = json.loads(full.manifest.agents_path.read_text(encoding="utf-8"))
    items = {item["name"]: item for item in raw["data"]["affected_items"]}
    assert raw["error"] == 0 and raw["data"]["total_affected_items"] == len(items)
    assert (
        items[demo.MANAGER_NAME]["lastKeepAlive"] == "9999-12-31T23:59:59Z" and "group" not in items[demo.MANAGER_NAME]
    )
    assert items["srv-legacy-01"]["status"] == "disconnected"
    assert items["srv-new-01"]["status"] == "never_connected" and "lastKeepAlive" not in items["srv-new-01"]
    assert items["srv-mon-01"]["status"] == "active"
    assert not full.where(agent="srv-mon-01") and not full.where(agent="srv-new-01")
    assert items["dc02"]["status"] == "active"  # tampering: the agent is alive, its logs are not
    legacy_last = full.where(agent="srv-legacy-01")[-1].ms
    assert legacy_last < full.now_ms - 5 * 86_400_000
    assert set(items) == set(full.manifest.agent_names)
    agents = {a.name: a for a in demo.load_demo_agents(full.manifest.agents_path)}
    assert agents[demo.MANAGER_NAME].last_keepalive is None and agents[demo.MANAGER_NAME].is_manager
    assert agents["dc01"].platform == "windows" and "domain-controllers" in agents["dc01"].groups
    assert agents["srv-new-01"].last_keepalive is None and agents["srv-new-01"].platform is None
    keepalive = agents["dc02"].last_keepalive
    assert keepalive is not None and keepalive > full.manifest.now - timedelta(minutes=2)


def test_load_demo_agents_tolerates_junk(tmp_path: Path) -> None:
    path = tmp_path / "agents.json"
    path.write_text(json.dumps({"data": {"affected_items": [{"id": "001"}, "x", {"id": "002", "name": "n"}]}}))
    assert [a.name for a in demo.load_demo_agents(path)] == ["n"]
    path.write_text("[]")
    assert demo.load_demo_agents(path) == []
    path.write_text(json.dumps({"data": ["x"]}))
    assert demo.load_demo_agents(path) == []
    path.write_text(json.dumps({"data": {"affected_items": [{"id": "003", "name": "h", "group": "web", "os": "x"}]}}))
    (agent,) = demo.load_demo_agents(path)
    assert agent.groups == () and agent.platform is None and agent.status == "unknown"


# ---- ruleset, local rules and consistency with the alerts --------------------------------------------------------


def _load_rules(rules_dir: Path) -> dict[str, tuple[str, ET.Element]]:
    rules: dict[str, tuple[str, ET.Element]] = {}
    for path in sorted(rules_dir.glob("*.xml")):
        root = ET.fromstring(f"<root>{path.read_text(encoding='utf-8')}</root>")
        for rule in root.iter("rule"):
            assert rule.get("id") not in rules, f"duplicate id {rule.get('id')}"
            rules[str(rule.get("id"))] = (path.name, rule)
    return rules


def test_ruleset_files_parse_and_cover_every_alert(full: Dataset) -> None:
    rules = _load_rules(full.manifest.rules_dir)
    for rule_id, count in full.manifest.rule_counts.items():
        assert count > 0
        file_name, element = rules[rule_id]
        assert file_name != "local_rules.xml"
        assert int(str(element.get("level"))) == full.docs_by_rule[rule_id]["rule"]["level"] >= 3
        assert (element.findtext("description") or "").split("$(")[0] in full.docs_by_rule[rule_id]["rule"][
            "description"
        ]
    assert rules["5712"][1].findtext("if_matched_sid") == "5710"
    assert rules["5712"][1].find("same_srcip") is not None
    assert rules["60204"][1].get("frequency") == "$MS_FREQ"
    security = (full.manifest.rules_dir / "0580-win-security_rules.xml").read_text(encoding="utf-8")
    assert '<var name="MS_FREQ">8</var>' in security
    assert all(int(rid) < 100000 for rid, (name, _) in rules.items() if name != "local_rules.xml")
    assert "NOT the official Wazuh ruleset" in security


def test_local_rules_hold_the_planted_tuning_debt(full: Dataset) -> None:
    rules = _load_rules(full.manifest.rules_dir)
    local = {rid: el for rid, (name, el) in rules.items() if name == "local_rules.xml"}
    assert set(local) == {"100010", "100011", "100020", "100030", "100040"}
    whole = local["100010"]
    assert whole.get("level") == "0" and [c.tag for c in whole] == ["if_sid", "description"]
    user_el = local["100011"].find("user")
    assert user_el is not None and user_el.text == "test" and user_el.get("type") is None
    field_el = local["100020"].find("field")
    assert field_el is not None and field_el.text == "svc_" and field_el.get("type") is None
    expired = re.search(r"expires (\d{4}-\d{2}-\d{2})", local["100030"].findtext("description") or "")
    current = re.search(r"expires (\d{4}-\d{2}-\d{2})", local["100040"].findtext("description") or "")
    assert expired and current
    assert date.fromisoformat(expired.group(1)) < full.manifest.now.date() < date.fromisoformat(current.group(1))
    for sid, rule_id in (("t1", "100010"), ("t2", "100011"), ("t3", "100020"), ("t4", "100030"), ("t5", "100040")):
        assert full.manifest.scenario(sid).rule_ids == (rule_id,)


def test_alerts_are_consistent_with_the_local_rules(full: Dataset) -> None:
    # 100010 mutes 5716 entirely (so 5720 can never fire); 100011 mutes 5710 users containing "test";
    # 100020 mutes 60122 users containing "svc_"; 100030/100040 would demote svc_legacy / svc_deploy logons.
    assert not [a for a in full.alerts if a.rule in ("5716", "5720")]
    assert not [a for a in full.alerts if a.rule == "5710" and "test" in (a.srcuser or "").lower()]
    assert not [a for a in full.alerts if a.rule == "60122" and "svc_" in (a.target_user or "").lower()]
    assert not [a for a in full.alerts if a.target_user in ("svc_legacy", "svc_deploy")]
    assert not {"100010", "100011", "100020", "100030", "100040"} & set(full.manifest.rule_counts)


# ---- dispositions and config ---------------------------------------------------------------------------------------


def test_dispositions_reference_real_alerts(full: Dataset) -> None:
    with full.manifest.dispositions_path.open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert rows and list(rows[0]) == [
        "alert_id",
        "rule_id",
        "field",
        "value",
        "verdict",
        "closed_at",
        "analyst",
        "comment",
    ]
    by_id = {a.alert_id: a for a in full.alerts}
    ids = [row["alert_id"] for row in rows if row["alert_id"]]
    assert len(ids) == len(set(ids))  # one verdict per alert
    verdicts: dict[str, Counter[str]] = defaultdict(Counter)
    for row in rows:
        assert row["verdict"] in ("fp", "btp", "tp", "untriaged")
        assert not row["comment"].startswith(("=", "+", "-", "@"))
        closed = datetime.strptime(row["closed_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
        assert closed <= full.manifest.now
        if row["alert_id"]:
            alert = by_id[row["alert_id"]]
            assert alert.rule == row["rule_id"]
            assert closed.timestamp() * 1000 >= alert.ms - 1000
            key = (
                "a"
                if alert.target_user == "svc_backup"
                else "b"
                if alert.srcip == demo.SCANNER_IP
                else "e"
                if alert.ip_address == demo.SPRAY_IP
                else "other"
            )
            verdicts[key][row["verdict"]] += 1
        else:
            assert (row["rule_id"], row["field"], row["value"], row["verdict"]) == (
                "60122",
                "data.win.eventdata.ipAddress",
                demo.SPRAY_IP,
                "tp",
            )
    assert "other" not in verdicts
    for key in ("a", "b"):
        assert verdicts[key]["fp"] + verdicts[key]["btp"] >= 10  # enough for a Wilson lower bound
        assert verdicts[key]["tp"] == 0
    assert verdicts["e"]["tp"] == 1
    assert full.manifest.scenario("a").details["dispositions"] == dict(verdicts["a"])


def test_config_parses_and_describes_the_demo_tenant(full: Dataset) -> None:
    tenant = load_config(full.manifest.config_path).tenant()
    assert tenant.name == demo.TENANT_NAME
    assert tenant.timezone == "America/Argentina/Buenos_Aires"
    assert tenant.triage_level == 7
    assert tenant.tier_for("dc01") == "critical" and tenant.tier_for("fw-edge-01") == "critical"
    assert tenant.tier_for("lap-003") == "low" and tenant.tier_for("srv-web-01") == "standard"
    assert tenant.is_trusted("user", "svc_backup") and tenant.is_trusted("data.srcip", demo.SCANNER_IP)
    assert tenant.is_internal(demo.SLOW_BURN_IP) and not tenant.is_internal(demo.BRUTE_FORCE_IP)
    holiday = full.manifest.holiday
    assert holiday is not None and tenant.in_calendar(holiday)
    assert full.manifest.start.date() < holiday < full.manifest.now.date()
    assert [i.path for i in tenant.inputs] == ["alerts.json"] and tenant.inputs[0].type == "file"
    assert tenant.ruleset_dirs == ["rules"] and tenant.dispositions == "dispositions.csv"
    names = {e.name: e for e in tenant.expectations}
    assert names["windows servers"].match == {"platform": "windows", "name": "srv-*"}
    assert set(names["windows servers"].log_sources) == {"Security", SYSMON}


def _iter_scenarios(manifest: demo.DemoManifest) -> Iterator[demo.PlantedScenario]:
    yield from manifest.ground_truth


def test_attack_scenarios_are_flagged_must_not_hide_and_forbid_tune(full: Dataset) -> None:
    for scenario in _iter_scenarios(full.manifest):
        if scenario.category == "noise_trap":
            assert scenario.must_not_hide and "noise.tune" in scenario.forbidden_kinds, scenario.id
            assert "tune" not in scenario.allowed_verdicts
        if scenario.category == "noise_safe":
            assert not scenario.must_not_hide
