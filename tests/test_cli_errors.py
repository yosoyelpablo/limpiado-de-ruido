"""Regression tests: CLI error handling and exit codes, cron mode (``check``), fleet, doctor,
engine honesty (never a false green) and the indexer event source. Synthetic data only; no network (HTTP clients
and the Wazuh API are replaced by fakes)."""

from __future__ import annotations

import csv
import json
import logging
import os
import re
import stat
import sys
import types
from collections.abc import Iterator, Sequence
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, ClassVar

import pytest
import yaml
from typer.testing import CliRunner, Result

import hushwatch.cli as cli
import hushwatch.config as hw_config
import hushwatch.ingest.indexer_source as hw_indexer_source
import hushwatch.ingest.wazuh_api as hw_wazuh_api
import hushwatch.notify as hw_notify
from hushwatch.cli import app
from hushwatch.config import InputConfig, TenantConfig, parse_config
from hushwatch.engine import AnalysisOptions, analyze, assess, merge_basis
from hushwatch.i18n import M, Message, render
from hushwatch.ingest.indexer_source import IndexerEventSource
from hushwatch.inventory import AgentInfo
from hushwatch.models import DataBasis, Finding
from hushwatch.net import RemoteError
from hushwatch.state import STATE_FILENAME, StateStore

UTC = timezone.utc
START = datetime(2026, 9, 1, tzinfo=UTC)
DAYS = 10
END = START + timedelta(days=DAYS)
NOW = "2026-09-11T00:00:00Z"
HOSTS = ("web-1.example", "web-2.example", "web-3.example")
ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
RUNNER = CliRunner(
    env={"HUSHWATCH_CONFIG": None, "HUSHWATCH_REDACT_KEY": None, "COLUMNS": "400", "LINES": "50", "TERM": "xterm"}
)


# ---- helpers ---------------------------------------------------------------------------------------------------------


def run(*args: object, env: dict[str, str] | None = None) -> Result:
    """Invoke the CLI; a traceback (an exception other than a clean exit) is never a valid outcome."""
    result = RUNNER.invoke(app, [str(a) for a in args], env=env)
    if result.exception is not None and not isinstance(result.exception, SystemExit):
        raise AssertionError(f"hushwatch {' '.join(map(str, args))} crashed") from result.exception
    return result


def text(value: str) -> str:
    return ANSI.sub("", value)


def mode(path: Path) -> int:
    return stat.S_IMODE(os.lstat(path).st_mode)


def alert_docs(hosts: Sequence[str] = HOSTS, *, start: datetime = START, days: int = DAYS) -> list[dict[str, Any]]:
    """Steady sshd 'authentication success' alerts (level 3) from ``hosts``."""
    docs = []
    n = 0
    for hour in range(days * 24):
        for idx, host in enumerate(hosts, 1):
            for k in range(3):
                n += 1
                ts = start + timedelta(hours=hour, minutes=7 * k + idx)
                docs.append(
                    {
                        "timestamp": ts.strftime("%Y-%m-%dT%H:%M:%S.000+0000"),
                        "rule": {"level": 3, "description": "sshd: authentication success.", "id": "5715",
                                 "groups": ["syslog", "sshd", "authentication_success"]},
                        "agent": {"id": f"{idx:03d}", "name": host, "ip": f"10.0.0.{10 + idx}"},
                        "manager": {"name": "wazuh-manager"},
                        "id": f"{int(ts.timestamp())}.{n}",
                        "decoder": {"name": "sshd"},
                        "data": {"srcip": "10.0.0.9", "dstuser": "alice"},
                        "location": "/var/log/auth.log",
                    }
                )  # fmt: skip
    return docs


def write_alerts(path: Path, docs: list[dict[str, Any]]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(d) + "\n" for d in docs), encoding="utf-8")
    return path


def write_config(path: Path, raw: dict[str, Any]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")
    os.chmod(path, 0o600)
    return path


def private_dir(path: Path) -> Path:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path, 0o700)
    return path


def agents_json(path: Path, *, extra: Sequence[dict[str, Any]] = ()) -> Path:
    items = [
        {"id": f"{i:03d}", "name": host, "status": "active", "lastKeepAlive": END.strftime("%Y-%m-%dT%H:%M:%SZ"),
         "os": {"platform": "ubuntu", "name": "Ubuntu"}, "group": ["default"]}
        for i, host in enumerate(HOSTS, 1)
    ]  # fmt: skip
    path.write_text(json.dumps({"data": {"affected_items": [*items, *extra], "total_affected_items": 4}}), "utf-8")
    return path


GONE_AGENT = {
    "id": "009",
    "name": "gone-1.example",
    "status": "disconnected",
    "lastKeepAlive": (START - timedelta(days=5)).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "os": {"platform": "ubuntu", "name": "Ubuntu"},
    "group": ["default"],
}


class FrozenClock(datetime):
    """Replacement for ``hushwatch.cli.datetime`` so cron-mode runs are dated deterministically."""

    current: datetime = END + timedelta(minutes=5)

    @classmethod
    def now(cls, tz: Any = None) -> datetime:  # type: ignore[override]
        return cls.current if tz is None else cls.current.astimezone(tz)


class Recorder:
    """Fake notify.send / notify.send_heartbeat that record what would have been delivered."""

    def __init__(self, *, ok: bool = True) -> None:
        self.ok = ok
        self.digests: list[dict[str, Any]] = []
        self.beats: list[dict[str, Any]] = []

    def send(self, target: Any, payload: dict[str, Any], **_: Any) -> hw_notify.SendResult:
        self.digests.append(payload)
        fps = tuple(str(t["fingerprint"]) for t in payload["transitions"])
        if self.ok:
            return hw_notify.SendResult(ok=True, sent=True, status_code=200, target="https://hooks.example",
                                        fingerprints=fps)  # fmt: skip
        return hw_notify.SendResult(ok=False, target="https://hooks.example", error="HTTP 500",
                                    message=M("notify.error.http_nobody", target="https://hooks.example", status=500),
                                    fingerprints=fps)  # fmt: skip

    def heartbeat(self, target: Any, tenant: str, **kwargs: Any) -> hw_notify.SendResult:
        self.beats.append({"tenant": tenant, **kwargs})
        if self.ok:
            return hw_notify.SendResult(ok=True, sent=True, status_code=200, target="https://hooks.example")
        timeout = M("notify.error.timeout", target="https://hooks.example", seconds=10)
        return hw_notify.SendResult(ok=False, target="https://hooks.example", error="timeout", message=timeout)

    def install(self, monkeypatch: pytest.MonkeyPatch) -> Recorder:
        monkeypatch.setattr(hw_notify, "send", self.send)
        monkeypatch.setattr(hw_notify, "send_heartbeat", self.heartbeat)
        return self

    def transitions(self) -> list[dict[str, Any]]:
        return [t for digest in self.digests for t in digest["transitions"]]


class FakeAPI:
    """Stand-in for :class:`hushwatch.ingest.wazuh_api.WazuhAPI` (no network)."""

    up = True
    stats_fail = False
    agents_list: ClassVar[list[AgentInfo]] = []

    def __init__(self, cfg: Any, **_: Any) -> None:
        self.cfg = cfg

    def __enter__(self) -> FakeAPI:
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def close(self) -> None:
        return None

    def apply_to(self, basis: DataBasis) -> None:
        return None

    def agents(self) -> list[AgentInfo]:
        if not FakeAPI.up:
            raise RemoteError(M("test.f1.api_down", "Wazuh API: connection refused"), kind="connection")
        return list(FakeAPI.agents_list)

    def info(self) -> dict[str, Any]:
        return {"api_version": "4.14.0"}

    def daemon_stats(self) -> dict[str, Any] | None:
        if FakeAPI.stats_fail:
            raise RemoteError(M("test.f1.forbidden", "manager:read denied"), kind="forbidden", status=403)
        return None


# ---- fixtures --------------------------------------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _isolated(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv("HUSHWATCH_CONFIG", raising=False)
    monkeypatch.delenv("HUSHWATCH_REDACT_KEY", raising=False)
    monkeypatch.setattr(hw_config, "DEFAULT_STATE_DIR", tmp_path / "default-state" / "hushwatch")
    FakeAPI.up, FakeAPI.stats_fail = True, False


@pytest.fixture(scope="module")
def alerts(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return write_alerts(tmp_path_factory.mktemp("alerts") / "alerts.json", alert_docs())


@pytest.fixture()
def clock(monkeypatch: pytest.MonkeyPatch) -> type[FrozenClock]:
    monkeypatch.setattr(cli, "datetime", FrozenClock)
    FrozenClock.current = END + timedelta(minutes=5)
    return FrozenClock


@pytest.fixture()
def fake_api(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> type[FakeAPI]:
    from hushwatch.ingest.wazuh_api import parse_agent

    raw = json.loads(agents_json(tmp_path / "agents-for-api.json", extra=[GONE_AGENT]).read_text("utf-8"))
    FakeAPI.agents_list = [a for a in (parse_agent(i) for i in raw["data"]["affected_items"]) if a is not None]
    monkeypatch.setattr(hw_wazuh_api, "WazuhAPI", FakeAPI)
    return FakeAPI


def _tenant_body(tmp_path: Path, alerts: Path, **extra: Any) -> dict[str, Any]:
    return {
        "timezone": "UTC",
        "state_dir": str(private_dir(tmp_path / "state")),
        "inputs": [{"type": "file", "path": str(alerts), "profile": "wazuh4"}],
        "notify": [{"type": "webhook", "url": "https://hooks.example/hushwatch"}],
        **extra,
    }


# ---- check: dry run, failed runs, delivery accounting ----------------------------------------------------------------


def test_dry_run_leaves_every_change_pending_and_a_failed_run_leaves_a_trace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, clock: type[FrozenClock]
) -> None:
    body = _tenant_body(tmp_path, tmp_path / "missing" / "alerts.json")
    cfg = write_config(tmp_path / "c.yml", {"tenants": {"acme": body}})
    recorder = Recorder().install(monkeypatch)

    dry = run("check", "-c", cfg, "--dry-run")
    assert dry.exit_code == 3
    assert "acme: input not found" in text(dry.stderr)
    assert "not sent (dry run" in text(dry.stdout)
    assert recorder.digests == [] and recorder.beats == []
    with StateStore(tmp_path / "state" / STATE_FILENAME) as store:
        beat = store.last_heartbeat("acme")
        assert beat is not None and not beat.ok and "input not found" in beat.detail
        last = store.last_run("acme")
        assert last is not None and last.counts["findings"] == 1  # an incomplete run is recorded
        assert [s.kind for s in store.open_findings("acme")] == ["assessment.incomplete"]

    clock.current += timedelta(minutes=5)
    real = run("check", "-c", cfg)
    assert real.exit_code == 3
    # what the dry run found is announced by the next real run (a dry run never swallows a notification)
    assert [(t["type"], t["kind"]) for t in recorder.transitions()] == [("opened", "assessment.incomplete")]
    assert len(recorder.beats) == 1 and recorder.beats[0]["ok"] is False
    detail = recorder.beats[0]["detail"]
    assert "input not found" in (render(detail) if isinstance(detail, Message) else str(detail))


def test_check_counts_delivered_notifications_and_fails_when_a_target_fails(
    tmp_path: Path, alerts: Path, monkeypatch: pytest.MonkeyPatch, clock: type[FrozenClock]
) -> None:
    cfg = write_config(tmp_path / "c.yml", {"tenants": {"acme": _tenant_body(tmp_path, alerts)}})
    clock.current = END + timedelta(days=3)  # the feed stopped 3 days ago: silence opens at once
    Recorder(ok=False).install(monkeypatch)
    result = run("check", "-c", cfg)
    assert result.exit_code == 3
    stderr = text(result.stderr)
    assert stderr.count("notification not delivered") == 1  # one line per failure, never repeated by a logger
    assert stderr.count("heartbeat not delivered") == 1
    match = re.search(r"(\d+) of (\d+) notifications? delivered", text(result.stdout))
    assert match and match.group(1) == "0" and int(match.group(2)) > 0
    # handed back: the next run sends them again
    ok = Recorder().install(monkeypatch)
    clock.current += timedelta(minutes=5)
    again = run("check", "-c", cfg)
    assert again.exit_code in (0, 1)
    assert len(ok.transitions()) >= int(match.group(2))


def test_check_fail_on_and_critical_heartbeat_counts(
    tmp_path: Path, alerts: Path, monkeypatch: pytest.MonkeyPatch, clock: type[FrozenClock]
) -> None:
    cfg = write_config(tmp_path / "c.yml", {"tenants": {"acme": _tenant_body(tmp_path, alerts)}})
    clock.current = END + timedelta(days=3)
    recorder = Recorder().install(monkeypatch)
    plain = run("check", "-c", cfg)
    assert plain.exit_code == 0
    clock.current += timedelta(minutes=5)
    strict = run("check", "-c", cfg, "--fail-on", "medium")
    assert strict.exit_code == 1
    assert all("open.critical" in beat["counts"] for beat in recorder.beats)


def test_an_api_outage_never_resolves_agent_findings(
    tmp_path: Path, alerts: Path, monkeypatch: pytest.MonkeyPatch, clock: type[FrozenClock], fake_api: type[FakeAPI]
) -> None:
    body = _tenant_body(tmp_path, alerts, wazuh_api={"url": "https://manager.example:55000", "username": "u",
                                                     "password": "p"})  # fmt: skip
    cfg = write_config(tmp_path / "c.yml", {"tenants": {"acme": body}})
    recorder = Recorder().install(monkeypatch)
    for _ in range(2):  # API up: the disconnected agent opens (hysteresis: two runs)
        assert run("check", "-c", cfg).exit_code == 0
        clock.current += timedelta(minutes=5)
    opened = [t for t in recorder.transitions() if t["kind"] == "pipeline.agent_disconnected"]
    assert [t["type"] for t in opened] == ["opened"]
    recorder.digests.clear()
    fake_api.up = False
    for _ in range(3):  # API down: incomplete runs, and absence proves nothing
        result = run("check", "-c", cfg)
        assert result.exit_code == 3
        clock.current += timedelta(minutes=5)
    assert not [t for t in recorder.transitions() if t["type"] == "resolved"]
    with StateStore(tmp_path / "state" / STATE_FILENAME) as store:
        assert "pipeline.agent_disconnected" in {s.kind for s in store.open_findings("acme")}


def test_check_without_any_inventory_never_resolves_agent_findings(
    tmp_path: Path, alerts: Path, monkeypatch: pytest.MonkeyPatch, clock: type[FrozenClock]
) -> None:
    body = _tenant_body(tmp_path, alerts, agents_file=str(agents_json(tmp_path / "a.json", extra=[GONE_AGENT])))
    cfg = write_config(tmp_path / "c.yml", {"tenants": {"acme": body}})
    recorder = Recorder().install(monkeypatch)
    for _ in range(2):
        run("check", "-c", cfg)
        clock.current += timedelta(minutes=5)
    assert any(t["kind"] == "pipeline.agent_disconnected" for t in recorder.transitions())
    body.pop("agents_file")  # the inventory is gone (e.g. --no-api): agent checks cannot run
    write_config(tmp_path / "c.yml", {"tenants": {"acme": body}})
    recorder.digests.clear()
    for _ in range(3):
        run("check", "-c", cfg)
        clock.current += timedelta(minutes=5)
    assert not [t for t in recorder.transitions() if t["kind"] == "pipeline.agent_disconnected"]


def test_daemon_stats_failure_keeps_the_agent_inventory(tmp_path: Path, alerts: Path, fake_api: type[FakeAPI]) -> None:
    fake_api.stats_fail = True
    tenant = parse_config(
        {"tenants": {"acme": {"wazuh_api": {"url": "https://manager.example:55000"}, "timezone": "UTC"}}}, {}
    ).tenant()
    from hushwatch.engine import open_sources

    opts = AnalysisOptions(now=END + timedelta(minutes=5), now_origin="wallclock")
    report = analyze(tenant, open_sources(tenant, paths=[str(alerts)], options=opts), options=opts,
                     wallclock=END + timedelta(minutes=5)).report  # fmt: skip
    assert "wazuh-manager-stats" in report.data_basis.not_evaluated
    assert "wazuh-api" not in report.data_basis.not_evaluated
    assert not [f for f in report.findings if f.subject == "wazuh-api"]
    assert any(f.kind == "pipeline.agent_disconnected" for f in report.findings)


# ---- one tenant's outage never stops the others ----------------------------------------------------------------------


class _DownClient:
    def __init__(self, cfg: Any, **_: Any) -> None:
        raise RemoteError(M("test.f1.refused", "indexer: connection refused"), kind="connection")


def _two_tenants(tmp_path: Path, alerts: Path) -> Path:
    down = {"timezone": "UTC", "state_dir": str(private_dir(tmp_path / "s-down")),
            "inputs": [{"type": "indexer", "url": "https://idx.example:9200"}]}  # fmt: skip
    up = _tenant_body(tmp_path, alerts, notify=[])
    return write_config(tmp_path / "two.yml", {"tenants": {"down": down, "up": up}})


def test_check_and_fleet_continue_after_a_tenant_outage(
    tmp_path: Path, alerts: Path, monkeypatch: pytest.MonkeyPatch, clock: type[FrozenClock]
) -> None:
    monkeypatch.setattr(hw_indexer_source, "IndexerClient", _DownClient)
    cfg = _two_tenants(tmp_path, alerts)
    result = run("check", "-c", cfg)
    assert result.exit_code == 3
    assert "down: indexer: connection refused" in text(result.stderr)
    assert re.search(r"^up: \d+ finding", text(result.stdout), re.MULTILINE)
    with StateStore(tmp_path / "s-down" / STATE_FILENAME) as store:
        beat = store.last_heartbeat("down")
        assert beat is not None and not beat.ok and "connection refused" in beat.detail

    fleet = run("fleet", "-c", cfg, "-f", "json", "--data-now")
    assert fleet.exit_code == 3
    rows = {row["tenant"]: row for row in json.loads(fleet.stdout)["tenants"]}
    assert rows["down"]["incomplete"] and not rows["up"]["incomplete"]


def test_indexer_failure_in_the_middle_of_a_pass_is_partial_not_a_crash() -> None:
    class FakeClient:
        def __init__(self, docs: list[dict[str, Any]], fail_after: int | None) -> None:
            self.docs, self.fail_after = docs, fail_after
            self.calls: list[tuple[Any, Any, Any]] = []

        def stream(self, index: str, *, start: Any, end: Any, time_field: str, query: Any = None,
                   max_docs: Any = None) -> Iterator[dict[str, Any]]:  # fmt: skip
            self.calls.append((start, end, query))
            for i, doc in enumerate(self.docs):
                if self.fail_after is not None and i == self.fail_after:
                    raise RemoteError(M("test.f1.auth", "indexer: HTTP 401"), kind="auth", status=401)
                yield doc

        def apply_to(self, basis: DataBasis) -> None:
            return None

        def close(self) -> None:
            return None

    now = END - timedelta(hours=1)
    docs = alert_docs(days=1, start=END - timedelta(days=1))[:10]
    client = FakeClient(docs, fail_after=4)
    cfg = InputConfig(type="indexer", url="https://idx.example:9200", profile="wazuh4")
    source = IndexerEventSource(cfg, tenant=TenantConfig(), options=AnalysisOptions(now=now), client=client)  # type: ignore[arg-type]
    events = list(source)
    assert len(events) == 4
    assert source.basis.events == 4 and not source.basis.complete
    assert "401" in render(source.basis.partial_failures[0])
    assert client.calls[0][1] == now  # the window ends at --now, not at the wall clock
    window = next(w for w in source.basis.warnings if isinstance(w, Message) and w.key == "indexer_source.window")
    assert window.params["end"] == now.strftime("%Y-%m-%dT%H:%M:%SZ")
    # the backtest pass must never run on part of the data: there the failure propagates
    with pytest.raises(RemoteError):
        list(source.iter_rules({"5715"}))
    whole = IndexerEventSource(cfg, tenant=TenantConfig(), options=AnalysisOptions(now=now),
                               client=FakeClient(docs, fail_after=None))  # type: ignore[arg-type]  # fmt: skip
    assert len(list(whole.iter_rules({"5715"}))) == 10
    assert whole.client.calls[-1][2] == {"terms": {"rule.id": ["5715"]}}  # type: ignore[attr-defined]


# ---- errors: one clean line, the documented exit code ----------------------------------------------------------------


def test_unexpected_errors_are_one_clean_line(alerts: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("exploded near https://hooks.example/services/FAKE-webhook-path?token=FAKE-test-token")

    monkeypatch.setattr(cli, "analyze", boom)
    result = run("report", alerts, "--now", NOW)
    assert result.exit_code == 3
    stderr = text(result.stderr)
    assert "unexpected RuntimeError" in stderr and "use -v for details" in stderr
    assert "Traceback" not in stderr and "FAKE-webhook-path" not in stderr
    verbose = run("report", alerts, "--now", NOW, "-v")
    assert verbose.exit_code == 3 and "Traceback" in verbose.stderr and "FAKE-webhook-path" not in verbose.stderr
    spanish = run("report", alerts, "--now", NOW, "--lang", "es")
    assert "fallo inesperado: RuntimeError" in text(spanish.stderr) and "use -v para ver los detalles" in text(
        spanish.stderr
    )


def test_main_never_shows_a_traceback(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    from hushwatch.config import ConfigError

    for exc, code in ((ValueError("bad"), 3), (ConfigError("broken config"), 2)):

        def fail(exc: Exception = exc) -> None:
            raise exc

        monkeypatch.setattr(cli, "app", fail)
        monkeypatch.setattr(sys, "argv", ["hushwatch", "report"])
        with pytest.raises(SystemExit) as caught:
            cli.main()
        assert caught.value.code == code
        assert "Traceback" not in capsys.readouterr().err


def test_file_arguments_are_validated_before_the_analysis(
    tmp_path: Path, alerts: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def never(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("the analysis must not start")

    monkeypatch.setattr(cli, "analyze", never)
    link = tmp_path / "link.html"
    victim = tmp_path / "victim.txt"
    victim.write_text("precious", encoding="utf-8")
    link.symlink_to(victim)
    emit = tmp_path / "emit"
    emit.mkdir()
    (emit / "hushwatch_local_rules.xml").write_text("<group/>", encoding="utf-8")
    cases = [
        (["-o", tmp_path], "is a directory"),
        (["-o", link], "symbolic link"),
        (["--emit-suppressions", emit], "--force"),
        (["--dispositions", tmp_path / "nope.csv"], "file not found"),
        (["--agents", tmp_path / "nope.json"], "file not found"),
        (["--since", "2026-09-12", "--now", NOW], "must be earlier"),
    ]
    for extra, message in cases:
        result = run("report", alerts, "--now", NOW, *extra) if "--now" not in extra else run("report", alerts, *extra)
        assert result.exit_code == 2, (extra, result.stderr)
        assert message in text(result.stderr).replace("\n", " "), (extra, result.stderr)
    assert victim.read_text(encoding="utf-8") == "precious"


def test_reports_are_written_atomically_and_privately(tmp_path: Path, alerts: Path) -> None:
    out = tmp_path / "new" / "deeper" / "report.md"
    result = run("report", alerts, "--now", NOW, "-f", "md", "-o", out)
    assert result.exit_code in (0, 3)
    assert mode(out) == 0o600 and mode(out.parent) == 0o700 and mode(out.parent.parent) == 0o700
    assert [p.name for p in out.parent.iterdir()] == ["report.md"]  # no temporary file left behind


def test_force_lets_an_existing_suppression_directory_be_reused(tmp_path: Path, alerts: Path) -> None:
    emit = tmp_path / "emit"
    emit.mkdir()
    (emit / "hushwatch_local_rules.xml").write_text("<group/>", encoding="utf-8")
    refused = run("noise", alerts, "--now", NOW, "--emit-suppressions", emit)
    assert refused.exit_code == 2 and "--force" in text(refused.stderr).replace("\n", " ")
    forced = run("noise", alerts, "--now", NOW, "--emit-suppressions", emit, "--force", "-f", "json")
    assert forced.exit_code != 2


def test_a_redaction_key_problem_is_a_config_error(tmp_path: Path, alerts: Path) -> None:
    state = private_dir(tmp_path / "state")
    (state / "keys").mkdir()
    os.chmod(state / "keys", 0o777)
    cfg = write_config(tmp_path / "c.yml", {"tenants": {"acme": {"state_dir": str(state)}}})
    result = run("report", alerts, "-c", cfg, "--now", NOW, "--redact")
    assert result.exit_code == 2
    assert "other users" in text(result.stderr).replace("\n", " ")


def test_verbose_logging_never_prints_webhook_secrets() -> None:
    records: list[str] = []

    class ListHandler(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(self.format(record))

    handler = ListHandler()
    root = logging.getLogger()
    root.addHandler(handler)
    try:
        cli._setup_logging(True)
        assert not logging.getLogger("httpx").isEnabledFor(logging.INFO)
        assert not logging.getLogger("httpcore").isEnabledFor(logging.DEBUG)
        logging.getLogger("hushwatch.test").warning(
            "HTTP Request: POST %s",
            "https://hooks.slack.example/services/FAKE0/FAKE1/FAKE-webhook-path?token=FAKE-test-token",
        )
    finally:
        root.removeHandler(handler)
        root.setLevel(logging.WARNING)
    assert records and "hooks.slack.example" in records[-1]
    assert "FAKE0" not in records[-1] and "FAKE-test-token" not in records[-1]


def test_cli_messages_follow_lang(tmp_path: Path) -> None:
    result = run("report", "--lang", "es")
    assert result.exit_code == 2 and "no hay entrada" in text(result.stderr)
    doctor = run("doctor", "--lang", "es")
    assert "cómo corregirlo" in text(doctor.stdout) and "controles:" in text(doctor.stdout)


def test_help_documents_redaction_keys_force_and_agents() -> None:
    out = " ".join(text(run("report", "--help").stdout).split())
    for word in ("keys/", "HUSHWATCH_REDACT_KEY", "--force", "--agents", "GET /agents"):
        assert word in out, word


# ---- --since / --now -------------------------------------------------------------------------------------------------


def test_relative_since_counts_back_from_now(alerts: Path) -> None:
    result = run("report", alerts, "--now", NOW, "--since", "3d", "-f", "json")
    report = json.loads(result.stdout)
    assert report["data_basis"]["events"] > 0  # anchored to --now, not to today's wall clock
    assert report["data_basis"]["start"] >= "2026-09-08T00:00:00Z"
    assert report["data_basis"]["now"] == NOW and report["data_basis"]["now_origin"] == "flag"


def test_naive_now_is_read_in_the_tenant_timezone(tmp_path: Path, alerts: Path) -> None:
    cfg = write_config(tmp_path / "c.yml", {"tenants": {"acme": {"timezone": "America/Argentina/Buenos_Aires"}}})
    result = run("report", alerts, "-c", cfg, "--now", "2026-09-10T21:00:00", "-f", "json")
    assert json.loads(result.stdout)["data_basis"]["now"] == NOW  # 21:00 in Buenos Aires (UTC-3)


def test_excluded_events_are_explained(monkeypatch: pytest.MonkeyPatch) -> None:
    class Stub:
        def __init__(self) -> None:
            self.basis = DataBasis()

        def __iter__(self) -> Iterator[Any]:
            self.basis = DataBasis(input_kind="alerts", profile="wazuh4", excluded_by_window=42,
                                   excluded_newest=START + timedelta(days=3))  # fmt: skip
            return iter(())

    since = END - timedelta(days=7)
    options = AnalysisOptions(since=since, since_relative=True, use_api=False)
    report = analyze(TenantConfig(), Stub(), options=options).report
    keys = [w.key for w in report.data_basis.warnings if isinstance(w, Message)]
    assert {"engine.window.since", "engine.window.newest", "engine.window.tip"} <= set(keys)
    titles = [render(f.title) for f in report.findings if f.domain == "assessment"]
    assert any("all 42 events read were outside it" in t for t in titles)
    tip = next(w for w in report.data_basis.warnings if isinstance(w, Message) and w.key == "engine.window.tip")
    assert "--now 2026-09-04" in render(tip)


# ---- engine honesty --------------------------------------------------------------------------------------------------


def test_the_pipeline_is_not_green_without_an_agent_inventory(tmp_path: Path, alerts: Path) -> None:
    bare = json.loads(run("report", alerts, "--now", NOW, "-f", "json").stdout)
    assert bare["assessment"]["pipeline"] == "not_assessed"
    assert "agent-inventory" in bare["data_basis"]["not_evaluated"]
    assert any("--agents" in (w["text"] if isinstance(w, dict) else w) for w in bare["data_basis"]["warnings"])
    agents = agents_json(tmp_path / "agents.json")
    full = json.loads(run("report", alerts, "--now", NOW, "--agents", agents, "-f", "json").stdout)
    assert full["assessment"]["pipeline"] != "not_assessed"
    assert "agent-inventory" not in full["data_basis"]["not_evaluated"]
    noise_only = json.loads(run("noise", alerts, "--now", NOW, "-f", "json").stdout)
    assert noise_only["assessment"]["pipeline"] != "not_assessed"  # input checks only: no agents needed


def test_silence_truncation_is_never_green() -> None:
    basis = DataBasis(events=10)
    wanted = frozenset({"silence", "fields"})
    assert assess([], {"silence": {"status": "ok"}}, wanted, basis, has_ruleset=False)["silence"] == "ok"
    truncated = {"silence": {"status": "ok", "cube_truncated": True}}
    assert assess([], truncated, wanted, basis, has_ruleset=False)["silence"] == "warn"
    fields = {"silence": {"status": "ok", "fields": {"truncated": True}}}
    assert assess([], fields, wanted, basis, has_ruleset=False)["silence"] == "warn"


def test_generic_data_without_rule_ids_is_incomplete_with_a_mapping_hint(tmp_path: Path) -> None:
    path = tmp_path / "export.csv"
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["timestamp", "host", "message"])
        for hour in range(DAYS * 24):
            for i, host in enumerate(("mail-01", "web-01")):
                writer.writerow(
                    [(START + timedelta(hours=hour, minutes=7 * i)).strftime("%Y-%m-%dT%H:%M:%SZ"), host, "ok"]
                )
    result = run("report", path, "--now", NOW, "-f", "json")
    report = json.loads(result.stdout)
    assert result.exit_code == 3
    assert "noise" in report["data_basis"]["not_evaluated"]
    finding = next(f for f in report["findings"] if f["subject"] == "noise:no-rule-id")
    assert "mapping" in json.dumps(finding["recommendation"])
    warnings_text = json.dumps(report["data_basis"]["warnings"])
    assert "rule id" in warnings_text and "/var/ossec" not in warnings_text  # no Wazuh advice for generic data


def test_a_run_where_nothing_could_be_assessed_exits_3(tmp_path: Path) -> None:
    short = write_alerts(tmp_path / "short.json", alert_docs(days=3))
    result = run("noise", short, "--now", "2026-09-04T00:00:00Z", "-f", "json")
    report = json.loads(result.stdout)
    assert report["assessment"]["noise"] == "not_assessed"
    assert result.exit_code == 3
    assert any(f["subject"] == "nothing-assessed" for f in report["findings"])


def test_an_empty_input_says_so(tmp_path: Path) -> None:
    empty = tmp_path / "alerts.json"
    empty.write_text("", encoding="utf-8")
    report = json.loads(run("report", empty, "-f", "json").stdout)
    titles = [f["title"]["text"] if isinstance(f["title"], dict) else f["title"] for f in report["findings"]]
    assert any(t.startswith("No input events") for t in titles)
    assert not any("part of the data" in t for t in titles)


def test_merge_basis_keeps_the_alerts_caveat_and_drops_duplicates() -> None:
    warning = M("indexer_source.alerts_only")
    a = DataBasis(input_kind="alerts", profile="wazuh4", events=5, warnings=[warning], excluded_by_window=2)
    b = DataBasis(input_kind="indexer-alerts", profile="wazuh4", events=7, warnings=[warning, M("x.other")],
                  partial_failures=["shard 3 failed", "shard 3 failed"], excluded_by_window=3)  # fmt: skip
    empty = DataBasis(input_kind="unknown", profile="unknown")
    merged = merge_basis([a, b, empty])
    assert merged.input_kind == "alerts" and merged.profile == "wazuh4"
    assert merged.warnings == [warning, M("x.other")]
    assert merged.partial_failures == ["shard 3 failed"]
    assert merged.events == 12 and merged.excluded_by_window == 5
    archives = merge_basis(
        [DataBasis(input_kind="archives", events=1), DataBasis(input_kind="indexer-archives", events=1)]
    )
    assert archives.input_kind == "archives"
    assert merge_basis([a, DataBasis(input_kind="archives", events=1)]).input_kind == "mixed"


def test_emit_findings_count_only_the_suggestions_not_written(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import hushwatch.wazuh.emitter as emitter
    from hushwatch.engine import _emit

    skip, note = (
        M("wazuh.emit.skip.duplicate", fingerprint="abc", rule="5710", other="def"),
        M("wazuh.emit.warn.nothing"),
    )

    received: list[str] = []

    def fake(suggestions: list[Any], **kwargs: Any) -> Any:
        assert kwargs["overwrite"] is True
        received.extend(s.fingerprint for s in suggestions)
        return emitter.EmitResult(paths=[tmp_path / "x.xml"], skipped=[("abc", skip)], warnings=[skip, note])

    monkeypatch.setattr(emitter, "emit_suppressions", fake)
    findings: list[Finding] = []
    basis = DataBasis(profile="wazuh4", events=1)
    suggestions = [
        types.SimpleNamespace(fingerprint="tune", verdict="tune", impact="analyst"),
        types.SimpleNamespace(fingerprint="volume", verdict="watch", impact="index_volume"),
        types.SimpleNamespace(fingerprint="risky", verdict="investigate", impact=""),
    ]
    _emit(TenantConfig(), suggestions, None, basis, tmp_path, END.date(), findings, overwrite=True)
    assert received == ["tune", "volume"]  # index-volume suggestions are explained in VALIDATION.md
    by_kind = {f.kind: f for f in findings}
    assert by_kind["noise.emit_skipped"].reasons == [skip]
    assert "1 tuning suggestion was" in render(by_kind["noise.emit_skipped"].title)
    assert by_kind["noise.emit_notes"].reasons == [note]


def test_cross_domain_links_are_applied_and_survive_tenant_stamping(
    alerts: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    linked: list[tuple[tuple[str, str], tuple[str, str]]] = []

    def link_findings(findings: list[Finding]) -> list[Finding]:
        if len(findings) >= 2:
            parent, child = findings[0], findings[1]
            parent.related = [*parent.related, child.fingerprint]
            linked.append(((parent.kind, parent.subject), (child.kind, child.subject)))
        return findings

    fake = types.ModuleType("hushwatch.analysis.correlate")
    fake.link_findings = link_findings  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "hushwatch.analysis.correlate", fake)
    late = "2026-09-14T00:00:00Z"  # three days after the data ends: several findings to link
    report = json.loads(run("report", alerts, "--now", late, "-f", "json").stdout)
    assert linked, "link_findings was not called"
    (parent_key, child_key) = linked[0]
    by_key = {(f["kind"], f["subject"]): f for f in report["findings"]}
    # the link points at the child's FINAL (tenant-stamped) fingerprint
    assert by_key[child_key]["fingerprint"] in by_key[parent_key]["related"]
    monkeypatch.setitem(sys.modules, "hushwatch.analysis.correlate", None)  # module absent: tolerated
    assert run("report", alerts, "--now", NOW, "-f", "json").exit_code in (0, 3)


def test_the_backtest_replays_only_the_candidate_rules() -> None:
    from hushwatch.engine import _backtest_events

    class WithFilter:
        def __init__(self) -> None:
            self.asked: set[str] = set()

        def iter_rules(self, rule_ids: set[str]) -> Iterator[Any]:
            self.asked = set(rule_ids)
            return iter(())

        def __iter__(self) -> Iterator[Any]:
            raise AssertionError("the whole input must not be re-read")

    source = WithFilter()
    suggestions = [types.SimpleNamespace(rule_id="5710"), types.SimpleNamespace(rule_id="60106")]
    assert list(_backtest_events(source, suggestions)) == []
    assert source.asked == {"5710", "60106"}
    plain = [1, 2]
    assert _backtest_events(plain, suggestions) is plain


# ---- fleet and doctor ------------------------------------------------------------------------------------------------


def test_fleet_measures_live_inputs_against_the_system_clock(
    tmp_path: Path, alerts: Path, clock: type[FrozenClock]
) -> None:
    clock.current = END + timedelta(days=5)
    cfg = write_config(tmp_path / "f.yml", {"tenants": {"web": _tenant_body(tmp_path, alerts, notify=[])}})
    live = json.loads(run("fleet", "-c", cfg, "-f", "json").stdout)["tenants"][0]
    exported = json.loads(run("fleet", "-c", cfg, "-f", "json", "--data-now").stdout)["tenants"][0]
    assert live["findings"]["critical"] + live["findings"]["high"] > 0  # the feed stopped five days ago
    assert exported["findings"]["critical"] + exported["findings"]["high"] == 0


def test_doctor_lists_unset_variables_and_insecure_connections(
    tmp_path: Path, alerts: Path, fake_api: type[FakeAPI]
) -> None:
    raw = {
        "tenants": {
            "acme": {
                "inputs": [{"type": "indexer", "url": "https://idx.example:9200", "password": "${ACME_IDX_PW}"}],
                "notify": [{"type": "slack", "url": "${ACME_SLACK}"}],
            },
            "globex": {
                "inputs": [{"type": "file", "path": str(alerts)}],
                "wazuh_api": {"url": "http://manager.example:55000", "username": "u", "password": "${GLOBEX_PW}",
                              "verify_tls": False},
                "state_dir": str(private_dir(tmp_path / "state")),
            },
        }
    }  # fmt: skip
    cfg = write_config(tmp_path / "c.yml", raw)
    everything = run("doctor", "-c", cfg, env={"GLOBEX_PW": "x"})
    out = text(everything.stdout)
    assert everything.exit_code == 1
    assert "export ACME_IDX_PW=..." in out and "export ACME_SLACK=..." in out
    assert "plain http" in out and "DISABLED" in out
    only_globex = run("doctor", "-c", cfg, "-t", "globex", env={"GLOBEX_PW": "x"})
    assert only_globex.exit_code == 0, only_globex.stdout  # acme's unset variables do not block globex
    report = run("report", alerts, "-c", cfg, "-t", "globex", "--now", NOW, "--no-api", env={"GLOBEX_PW": "x"})
    assert report.exit_code in (0, 3)
    blocked = run("report", alerts, "-c", cfg, "-t", "acme", "--now", NOW)
    assert blocked.exit_code == 2 and "ACME_IDX_PW" in text(blocked.stderr)


def test_doctor_reports_a_legacy_state_database(tmp_path: Path) -> None:
    legacy = tmp_path / "state"
    with StateStore(tmp_path / "x.sqlite3") as store:
        store.record_run("acme", [], now=END)
    os.rename(tmp_path / "x.sqlite3", legacy)
    cfg = write_config(tmp_path / "c.yml", {"tenants": {"acme": {"state_dir": str(legacy)}}})
    out = text(run("doctor", "-c", cfg).stdout)
    assert re.search(r"state dir\s+│\s+WARN", out) and "older hushwatch" in out.replace("\n", " ")


def test_redact_migrates_a_legacy_state_database_instead_of_failing(tmp_path: Path, alerts: Path) -> None:
    legacy = tmp_path / "state"
    with StateStore(tmp_path / "x.sqlite3") as store:
        store.record_run("acme", [], now=END)
    os.rename(tmp_path / "x.sqlite3", legacy)  # what the old `check` left at the state_dir path
    cfg = write_config(tmp_path / "c.yml", {"tenants": {"acme": {"state_dir": str(legacy)}}})
    result = run("report", alerts, "-c", cfg, "--now", NOW, "--redact", "-f", "json")
    assert result.exit_code in (0, 3), result.stderr
    assert json.loads(result.stdout)["redacted"] is True
    assert legacy.is_dir() and (legacy / STATE_FILENAME).is_file() and (legacy / "keys").is_dir()


def test_a_section_that_says_warn_is_never_reported_ok() -> None:
    basis = DataBasis(events=10)
    status = assess([], {"coverage": {"status": "warn"}}, frozenset({"coverage"}), basis, has_ruleset=False)
    assert status["coverage"] == "warn"
