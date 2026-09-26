"""CLI and engine integration tests: ``typer.testing.CliRunner`` against :data:`hushwatch.cli.app`.

Data:

* One module-scoped demo dataset from :func:`hushwatch.demo.generate`, reused by every test that needs realistic
  data. A full-size demo takes ~30 s to *analyze* per CLI invocation, so it is generated at the smallest supported
  size (``days=10, scale=0.05``): every planted scenario is still there (planted events are never scaled) and one
  analysis takes ~5 s. ``hushwatch demo`` itself is run with the generator patched to the same size.
* Tiny synthetic Wazuh 4.x alert files (RFC 1918 addresses, ``*.example`` names) for exit-code edge cases.

Isolation: ``HUSHWATCH_CONFIG`` / ``HUSHWATCH_REDACT_KEY`` are removed and the default state directory is
redirected to a temporary directory, so nothing touches ``~/.local/state``.

Every documented CLI/engine bug has a regression test here (no xfail left).
"""

from __future__ import annotations

import json
import os
import re
import stat
from collections import Counter
from collections.abc import Iterator, Sequence
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from xml.etree import ElementTree as ET

import pytest
import yaml
from typer.testing import CliRunner, Result

import hushwatch
import hushwatch.cli as cli
import hushwatch.config as hw_config
import hushwatch.demo as hw_demo
import hushwatch.notify as hw_notify
from hushwatch.cli import app
from hushwatch.demo import DemoManifest
from hushwatch.models import Severity
from hushwatch.state import STATE_FILENAME, StateStore

UTC = timezone.utc
REPO = Path(__file__).resolve().parents[1]
DEMO_KWARGS: dict[str, Any] = {"days": 10, "scale": 0.05}
COMMANDS = ("report", "noise", "silence", "audit", "demo", "check", "fleet", "doctor", "version")
FAIL_ON_LEVELS = ("none", "info", "low", "medium", "high", "critical")
SYNTH_START = datetime(2026, 9, 1, tzinfo=UTC)
SYNTH_NOW = "2026-09-11T00:00:00Z"
ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")

RUNNER = CliRunner(
    env={"HUSHWATCH_CONFIG": None, "HUSHWATCH_REDACT_KEY": None, "COLUMNS": "400", "LINES": "50", "TERM": "xterm"}
)


# ---- helpers ------------------------------------------------------------------------------------------------------


def run(*args: object, allow_crash: bool = False) -> Result:
    """Invoke the CLI. An exception other than a clean exit is re-raised (a traceback is never a valid outcome)."""
    result = RUNNER.invoke(app, [str(a) for a in args])
    if not allow_crash and crashed(result):
        raise AssertionError(f"hushwatch {' '.join(map(str, args))} crashed") from result.exception
    return result


def crashed(result: Result) -> bool:
    return result.exception is not None and not isinstance(result.exception, SystemExit)


def text(value: str) -> str:
    return ANSI.sub("", value)


def mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def expected_exit(report: dict[str, Any], fail_on: str) -> int:
    """The documented contract: 3 incomplete analysis, 1 findings at/above --fail-on, else 0."""
    if report["assessment"]["assessment"] == "fail":
        return 3
    if fail_on == "none":
        return 0
    threshold = Severity(fail_on).rank
    return int(any(Severity(f["severity"]).rank >= threshold for f in report["findings"]))


def write_config(path: Path, raw: dict[str, Any]) -> Path:
    path.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")
    os.chmod(path, 0o600)
    return path


def private_dir(path: Path) -> Path:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path, 0o700)
    return path


def synthetic_alerts(path: Path, hosts: Sequence[str], *, days: int = 10, per_hour: int = 3) -> Path:
    """Steady sshd 'authentication success' alerts (level 3) from ``hosts``: a healthy, fully assessable input."""
    docs = []
    n = 0
    for hour in range(days * 24):
        for idx, host in enumerate(hosts, 1):
            for k in range(per_hour):
                n += 1
                ts = SYNTH_START + timedelta(hours=hour, minutes=7 * k + idx)
                stamp = f"{ts:%b %d %H:%M:%S}"
                docs.append(
                    {
                        "timestamp": ts.strftime("%Y-%m-%dT%H:%M:%S.000+0000"),
                        "rule": {
                            "level": 3,
                            "description": "sshd: authentication success.",
                            "id": "5715",
                            "firedtimes": n,
                            "mail": False,
                            "groups": ["syslog", "sshd", "authentication_success"],
                        },
                        "agent": {"id": f"{idx:03d}", "name": host, "ip": f"10.0.0.{10 + idx}"},
                        "manager": {"name": "wazuh-manager"},
                        "id": f"{int(ts.timestamp())}.{n}",
                        "full_log": f"{stamp} {host} sshd[1]: Accepted publickey for alice from 10.0.0.9 port 22",
                        "predecoder": {"program_name": "sshd", "timestamp": stamp, "hostname": host},
                        "decoder": {"parent": "sshd", "name": "sshd"},
                        "data": {"srcip": "10.0.0.9", "dstuser": "alice"},
                        "location": "/var/log/auth.log",
                    }
                )
    docs.sort(key=lambda d: d["timestamp"])
    path.write_text("".join(json.dumps(d) + "\n" for d in docs), encoding="utf-8")
    return path


class FrozenClock(datetime):
    """Replacement for ``hushwatch.cli.datetime`` so cron-mode runs are dated deterministically."""

    current: datetime = SYNTH_START

    @classmethod
    def now(cls, tz: Any = None) -> datetime:  # type: ignore[override]
        return cls.current if tz is None else cls.current.astimezone(tz)


class Leaks:
    """Raw hostnames and IPs sampled from the demo alerts, and a whole-token search for them in rendered output."""

    def __init__(self, hosts: set[str], ips: set[str]) -> None:
        self.hosts, self.ips = hosts, ips
        alt_hosts = "|".join(re.escape(h) for h in sorted(hosts, key=len, reverse=True))
        alt_ips = "|".join(re.escape(i) for i in sorted(ips, key=len, reverse=True))
        self._hosts = re.compile(rf"(?<![A-Za-z0-9_-])(?:{alt_hosts})(?![A-Za-z0-9_-])", re.IGNORECASE)
        self._ips = re.compile(rf"(?<![\d.])(?:{alt_ips})(?!\d)")

    def find(self, output: str) -> set[str]:
        return {m.group(0) for m in self._hosts.finditer(output)} | {m.group(0) for m in self._ips.finditer(output)}


# ---- module fixtures ----------------------------------------------------------------------------------------------


@pytest.fixture(scope="module", autouse=True)
def _isolated_environment(tmp_path_factory: pytest.TempPathFactory) -> Iterator[None]:
    with pytest.MonkeyPatch.context() as mp:
        mp.delenv("HUSHWATCH_CONFIG", raising=False)
        mp.delenv("HUSHWATCH_REDACT_KEY", raising=False)
        mp.setattr(hw_config, "DEFAULT_STATE_DIR", tmp_path_factory.mktemp("default-state") / "hushwatch")
        yield


@pytest.fixture(scope="module")
def demo(tmp_path_factory: pytest.TempPathFactory) -> DemoManifest:
    return hw_demo.generate(tmp_path_factory.mktemp("demo"), **DEMO_KWARGS)


@pytest.fixture(scope="module")
def demo_config(demo: DemoManifest, tmp_path_factory: pytest.TempPathFactory) -> Path:
    """The demo tenant config with absolute paths (the shipped one is relative to the demo directory)."""
    raw = yaml.safe_load(demo.config_path.read_text(encoding="utf-8"))
    body = raw["tenants"][demo.tenant]
    body["inputs"][0]["path"] = str(demo.alerts_path)
    body["ruleset_dirs"] = [str(demo.rules_dir)]
    body["dispositions"] = str(demo.dispositions_path)
    body["agents_file"] = str(demo.agents_path)  # agent inventory: the pipeline domain can be assessed
    base = tmp_path_factory.mktemp("demo-config")
    body["state_dir"] = str(private_dir(base / "state"))
    return write_config(base / "hushwatch.yml", raw)


@pytest.fixture(scope="module")
def report_args(demo: DemoManifest, demo_config: Path) -> list[str]:
    """``hushwatch report`` on the demo alerts, pinned to the dataset's 'now' so results never drift."""
    return ["report", str(demo.alerts_path), "-c", str(demo_config), "--now", demo.now.isoformat()]


@pytest.fixture(scope="module")
def leaks(demo: DemoManifest) -> Leaks:
    hosts: set[str] = set()
    ips: set[str] = set()
    with demo.alerts_path.open(encoding="utf-8") as handle:
        for line in handle:
            doc = json.loads(line)
            hosts.add(doc["agent"]["name"])
            if doc["agent"].get("ip"):
                ips.add(doc["agent"]["ip"])
            if doc.get("predecoder", {}).get("hostname"):
                hosts.add(doc["predecoder"]["hostname"])
            data = doc.get("data", {})
            eventdata = data.get("win", {}).get("eventdata", {})
            for value in (data.get("srcip"), data.get("dstip"), eventdata.get("ipAddress"), eventdata.get("sourceIp")):
                if value and re.fullmatch(r"\d+\.\d+\.\d+\.\d+", value):
                    ips.add(value)
    assert len(hosts) >= 20 and len(ips) >= 20
    return Leaks(hosts, ips)


@pytest.fixture(scope="module")
def json_report(
    report_args: list[str], tmp_path_factory: pytest.TempPathFactory
) -> tuple[Result, Path, dict[str, Any]]:
    """One full ``report -f json -o FILE --fail-on critical`` run; its findings drive the exit-code expectations."""
    out = tmp_path_factory.mktemp("json-report") / "nested" / "report.json"
    result = run(*report_args, "-f", "json", "-o", out, "--fail-on", "critical")
    return result, out, json.loads(out.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def small_alerts(tmp_path_factory: pytest.TempPathFactory) -> Path:
    base = tmp_path_factory.mktemp("synthetic")
    return synthetic_alerts(base / "alerts.json", ["web-1.example", "web-2.example", "web-3.example"])


@pytest.fixture(scope="module")
def other_alerts(tmp_path_factory: pytest.TempPathFactory) -> Path:
    base = tmp_path_factory.mktemp("synthetic-other")
    return synthetic_alerts(base / "alerts.json", ["db-1.example", "db-2.example"], per_hour=2)


@pytest.fixture(scope="module")
def small_report(small_alerts: Path) -> dict[str, Any]:
    result = run("report", small_alerts, "--now", SYNTH_NOW, "-f", "json")
    report = json.loads(result.stdout)
    assert result.exit_code == expected_exit(report, "none") == 0
    return report


@pytest.fixture()
def frozen_clock(monkeypatch: pytest.MonkeyPatch) -> type[FrozenClock]:
    monkeypatch.setattr(cli, "datetime", FrozenClock)
    return FrozenClock


# ---- version / help -----------------------------------------------------------------------------------------------


def test_exercises_the_repository_package() -> None:
    assert Path(hushwatch.__file__).resolve().is_relative_to(REPO)


@pytest.mark.parametrize("args", [["--version"], ["version"]])
def test_version(args: list[str]) -> None:
    result = run(*args)
    assert result.exit_code == 0
    assert text(result.stdout).strip() == f"hushwatch {hushwatch.__version__}"


def test_help_lists_every_command() -> None:
    result = run("--help")
    assert result.exit_code == 0
    out = text(result.stdout)
    assert "SIEM hygiene" in out
    for command in COMMANDS:
        assert re.search(rf"^\s+{command}\s", out, re.MULTILINE), command


def test_no_arguments_prints_usage_and_exits_2() -> None:
    result = run()
    assert result.exit_code == 2
    assert "Usage" in text(result.stderr)
    assert "report" in text(result.stderr)


@pytest.mark.parametrize("command", COMMANDS)
def test_command_help(command: str) -> None:
    result = run(command, "--help")
    assert result.exit_code == 0
    assert f"hushwatch {command}" in text(result.stdout)


def test_report_help_documents_common_options() -> None:
    out = text(run("report", "--help").stdout)
    for option in ("--format", "--output", "--lang", "--redact", "--fail-on", "--since", "--now", "--dispositions",
                   "--ruleset", "--emit-suppressions", "--config", "--tenant", "--profile"):  # fmt: skip
        assert option in out, option
    for value in ("console", "html", "md", "json", "none", "critical"):
        assert value in out


# ---- demo ---------------------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("lang", "extra", "html_name", "heading", "exit_code"),
    [
        ("en", [], "report.html", "SIEM hygiene report", 0),
        # the demo plants log clearing before dc02 goes dark: a critical silence.tampering finding
        ("es", ["--fail-on", "critical"], "report.es.html", "Informe de higiene del SIEM", 1),
    ],
)
def test_demo_command_writes_html_report_and_suppressions(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    lang: str,
    extra: list[str],
    html_name: str,
    heading: str,
    exit_code: int,
) -> None:
    real_generate = hw_demo.generate

    def small_generate(out_dir: Path, *, seed: int = 7) -> DemoManifest:
        return real_generate(out_dir, seed=seed, **DEMO_KWARGS)

    opened: list[Any] = []
    monkeypatch.setattr(hw_demo, "generate", small_generate)
    monkeypatch.setattr("webbrowser.open", lambda *a, **k: opened.append(a) or True)
    out_dir = tmp_path / "hushwatch-demo"
    result = run("demo", "--out", out_dir, "--no-open", "--lang", lang, *extra)

    assert result.exit_code == exit_code
    assert opened == []  # --no-open
    stdout = text(result.stdout)
    assert heading in stdout
    html_path = out_dir / html_name
    label = "HTML report" if lang == "en" else "Informe HTML"
    assert f"{label}: {html_path}" in stdout.replace("\n", "")
    assert ("Generating a synthetic" if lang == "en" else "Generando un conjunto") in text(result.stderr)
    assert html_path.is_file() and mode(html_path) == 0o600
    assert mode(out_dir / "hushwatch.yml") == 0o600  # the demo config is private like any other config
    html = html_path.read_text(encoding="utf-8")
    assert html.lstrip().lower().startswith("<!doctype html")
    assert f'<html lang="{lang}"' in html
    assert "Content-Security-Policy" in html
    for name in ("alerts.json", "manifest.json", "hushwatch.yml", "agents.json", "dispositions.csv"):
        assert (out_dir / name).is_file(), name
    suppressions = out_dir / "suppressions"
    rules_xml = suppressions / "hushwatch_local_rules.xml"
    written = rules_xml.is_file()
    # the rules line is printed exactly when a rule file was written (the small demo may have no safe candidate)
    assert (("Suggested Wazuh rules" if lang == "en" else "Reglas de Wazuh sugeridas") in stdout) == written
    if written:
        assert mode(suppressions) == 0o700
        for name in ("hushwatch_local_rules.xml", "hushwatch_suppressions.json", "VALIDATION.md"):
            assert mode(suppressions / name) == 0o600, name
        assert sum(1 for _ in ET.parse(rules_xml).getroot().iter("rule")) >= 1
    # running the demo again replaces its own files (no "pass --force" dead end)
    again = run("demo", "--out", out_dir, "--no-open", "--lang", lang, *extra)
    assert again.exit_code == exit_code


# ---- report: every format, files and stdout -----------------------------------------------------------------------


def test_report_json_to_file(json_report: tuple[Result, Path, dict[str, Any]], demo: DemoManifest) -> None:
    result, path, report = json_report
    assert result.exit_code == expected_exit(report, "critical") == 1
    assert result.stdout == ""
    assert f"report written to {path}" in text(result.stderr)
    assert mode(path) == 0o600
    assert report["document"] == "hushwatch.report"
    assert report["tenant"] == demo.tenant
    assert report["lang"] == "en"
    assert report["redacted"] is False
    assert report["assessment"]["assessment"] == "ok"
    assert set(report["assessment"]) >= {"noise", "silence", "pipeline", "coverage", "tuning", "assessment"}
    assert report["data_basis"]["events"] == demo.alerts
    assert report["data_basis"]["now_origin"] == "flag"
    assert report["summary"]["findings"] == len(report["findings"]) > 0
    kinds = {(f["kind"], f["subject"]) for f in report["findings"]}
    assert ("silence.tampering", "agent:dc02") in kinds
    assert any(kind.startswith("noise.") for kind, _ in kinds)
    assert any(kind == "tuning.risky_suppression" for kind, _ in kinds)
    # the analysis ran with the tenant's configured ruleset and dispositions
    assert report["assessment"]["tuning"] != "not_assessed"


@pytest.mark.parametrize(
    ("fmt", "lang", "fail_on", "marker"),
    [
        ("md", "en", "none", "# hushwatch · SIEM hygiene report"),
        ("html", "es", "high", '<html lang="es"'),
        ("console", "es", "medium", "# hushwatch · Informe de higiene del SIEM"),  # console + -o writes Markdown
    ],
)
def test_report_formats_to_file(
    report_args: list[str],
    json_report: tuple[Result, Path, dict[str, Any]],
    tmp_path: Path,
    fmt: str,
    lang: str,
    fail_on: str,
    marker: str,
) -> None:
    out = tmp_path / f"report.{fmt}"
    result = run(*report_args, "-f", fmt, "-o", out, "--lang", lang, "--fail-on", fail_on)
    assert result.exit_code == expected_exit(json_report[2], fail_on)
    assert result.stdout == ""
    written = "report written to" if lang == "en" else "informe escrito en"
    assert f"{written} {out}" in text(result.stderr)
    if fmt == "console":  # a console report written to a file is Markdown, and the message says so
        assert "Markdown" in text(result.stderr)
    assert mode(out) == 0o600
    body = out.read_text(encoding="utf-8")
    assert marker in body
    assert "dc02" in body  # not redacted
    if fmt == "html":
        assert "Content-Security-Policy" in body


@pytest.mark.parametrize("fmt", ["json", "md", "html", "console"])
def test_report_stdout_with_redact_never_prints_raw_hosts_or_ips(
    report_args: list[str], leaks: Leaks, fmt: str
) -> None:
    result = run(*report_args, "-f", fmt, "--redact")
    assert result.exit_code == 0
    out = result.stdout
    assert len(out) > 1000
    assert leaks.find(out) == set()
    assert leaks.find(result.stderr) == set()
    if fmt == "json":
        report = json.loads(out)
        assert report["redacted"] is True
        assert any("host-" in f["title"]["text"] for f in report["findings"] if isinstance(f["title"], dict))
    elif fmt == "html":
        assert "<html" in out
    elif fmt == "md":
        assert out.startswith("# hushwatch")
    else:
        assert "Data basis" in text(out)


def test_redaction_sample_is_meaningful(json_report: tuple[Result, Path, dict[str, Any]], leaks: Leaks) -> None:
    """Sanity check of the leak detector: the unredacted report does contain many of the sampled values."""
    found = leaks.find(json_report[1].read_text(encoding="utf-8"))
    assert len(found & leaks.hosts) >= 5
    assert len(found & leaks.ips) >= 3


def test_report_console_to_stdout(small_alerts: Path) -> None:
    result = run("report", small_alerts, "--now", SYNTH_NOW)
    assert result.exit_code == 0
    out = text(result.stdout)
    assert "SIEM hygiene report" in out
    assert "Data basis" in out
    assert "web-1.example" in out or "10.0.0.9" in out


def test_report_json_to_stdout_in_spanish(small_alerts: Path) -> None:
    result = run("report", small_alerts, "--now", SYNTH_NOW, "-f", "json", "--lang", "es")
    report = json.loads(result.stdout)
    assert report["lang"] == "es"
    assert result.exit_code == 0
    assert re.match(r"(La r|R)egla 5715\b", report["findings"][0]["title"]["text"])


# ---- --fail-on and exit codes --------------------------------------------------------------------------------------


def test_small_input_discriminates_fail_on_levels(small_report: dict[str, Any]) -> None:
    codes = {level: expected_exit(small_report, level) for level in FAIL_ON_LEVELS}
    assert 0 in codes.values() and 1 in codes.values(), codes


@pytest.mark.parametrize("fail_on", FAIL_ON_LEVELS)
def test_fail_on_semantics(small_alerts: Path, small_report: dict[str, Any], fail_on: str) -> None:
    result = run("report", small_alerts, "--now", SYNTH_NOW, "-f", "json", "--fail-on", fail_on)
    assert result.exit_code == expected_exit(small_report, fail_on)


def test_missing_input_path_exits_2(tmp_path: Path) -> None:
    missing = tmp_path / "nope" / "alerts.json"
    result = run("report", missing)
    assert result.exit_code == 2
    assert "input not found" in text(result.stderr)
    assert result.stdout == ""


@pytest.mark.parametrize("via_env", [False, True])
def test_config_typo_exits_2(tmp_path: Path, small_alerts: Path, via_env: bool) -> None:
    cfg = tmp_path / "typo.yml"
    cfg.write_text("tenants:\n  acme:\n    timezon: UTC\n", encoding="utf-8")
    if via_env:
        result = RUNNER.invoke(app, ["report", str(small_alerts)], env={"HUSHWATCH_CONFIG": str(cfg)})
    else:
        result = run("report", small_alerts, "-c", cfg)
    assert not crashed(result)
    assert result.exit_code == 2
    assert "unknown key 'timezon' (did you mean 'timezone'?)" in text(result.stderr)


@pytest.mark.parametrize("fail_on", ["none", "info"])
def test_empty_alerts_file_exits_3(tmp_path: Path, fail_on: str) -> None:
    empty = tmp_path / "alerts.json"
    empty.write_text("", encoding="utf-8")
    result = run("report", empty, "-f", "json", "--fail-on", fail_on)
    assert result.exit_code == 3  # incomplete analysis wins over --fail-on
    report = json.loads(result.stdout)
    assert report["assessment"]["assessment"] == "fail"
    assert report["incomplete"] is True
    assert report["data_basis"]["events"] == 0
    assert all(status == "not_assessed" for d, status in report["assessment"].items() if d != "assessment")


@pytest.mark.parametrize("command", ["report", "noise"])
def test_redact_with_emit_suppressions_exits_2(tmp_path: Path, small_alerts: Path, command: str) -> None:
    out_dir = tmp_path / "suppressions"
    result = run(command, small_alerts, "--redact", "--emit-suppressions", out_dir)
    assert result.exit_code == 2
    assert "--redact cannot be combined with --emit-suppressions" in text(result.stderr).replace("\n", " ")
    assert not out_dir.exists()


@pytest.mark.parametrize(
    ("args", "message"),
    [
        (["report"], "no input"),
        (["report", "{alerts}", "--since", "garbage"], "--since"),
        (["report", "{alerts}", "--now", "garbage"], "--now"),
        (["report", "{alerts}", "--profile", "bogus"], "unknown profile"),
        (["report", "{alerts}", "-f", "xml"], "Invalid value"),
        (["report", "{alerts}", "--fail-on", "bogus"], "Invalid value"),
        (["report", "{alerts}", "-t", "nope"], "unknown tenant"),
        (["audit"], "Missing argument"),
    ],
)
def test_usage_errors_exit_2(small_alerts: Path, args: list[str], message: str) -> None:
    result = run(*(a.format(alerts=small_alerts) for a in args))
    assert result.exit_code == 2
    assert message in text(result.stderr)


def test_multi_tenant_config_requires_tenant(tmp_path: Path, small_alerts: Path) -> None:
    cfg = write_config(tmp_path / "two.yml", {"tenants": {"acme": {}, "globex": {}}})
    result = run("report", small_alerts, "-c", cfg)
    assert result.exit_code == 2
    assert "choose one with --tenant" in text(result.stderr).replace("\n", " ")
    assert run("report", small_alerts, "-c", cfg, "-t", "globex", "--now", SYNTH_NOW).exit_code == 0


def test_output_file_is_private_even_when_it_already_exists(tmp_path: Path, small_alerts: Path) -> None:
    out = tmp_path / "report.json"
    out.write_text("old", encoding="utf-8")
    os.chmod(out, 0o644)
    result = run("report", small_alerts, "--now", SYNTH_NOW, "-f", "json", "-o", out)
    assert result.exit_code == 0
    assert json.loads(out.read_text(encoding="utf-8"))["document"] == "hushwatch.report"
    assert mode(out) == 0o600


@pytest.mark.parametrize("problem", ["missing", "bad_header"])
def test_bad_dispositions_file_is_a_usage_error(tmp_path: Path, small_alerts: Path, problem: str) -> None:
    csv_path = tmp_path / "dispositions.csv"
    if problem == "bad_header":
        csv_path.write_text("foo,bar\n1,2\n", encoding="utf-8")
    result = run("report", small_alerts, "--dispositions", csv_path, allow_crash=True)
    assert not crashed(result), repr(result.exception)
    assert result.exit_code == 2


# ---- audit --------------------------------------------------------------------------------------------------------


@pytest.fixture(scope="module")
def audit_report(demo: DemoManifest) -> dict[str, Any]:
    result = run("audit", demo.rules_dir, "-f", "json")
    report = json.loads(result.stdout)
    assert result.exit_code == expected_exit(report, "none") == 0
    return report


def test_audit_flags_the_planted_tuning_debt(audit_report: dict[str, Any], demo: DemoManifest) -> None:
    section = audit_report["sections"]["tuning"]
    assert section["rules_parsed"] > 0 and section["risky"] >= 3
    assert audit_report["assessment"]["tuning"] == "fail"
    assert {d for d, s in audit_report["assessment"].items() if s != "not_assessed"} == {"tuning", "assessment"}
    found = {(f["kind"], f["subject"].split("|")[0]) for f in audit_report["findings"]}
    for scenario in demo.ground_truth:
        if scenario.category != "tuning":
            continue
        for rule in scenario.rule_ids:
            if scenario.expected_kinds:
                assert any((kind, f"rule:{rule}") in found for kind in scenario.expected_kinds), scenario.key
            else:  # the safe control suppression must not be flagged
                assert all(subject != f"rule:{rule}" for _, subject in found), scenario.key


@pytest.mark.parametrize("fail_on", FAIL_ON_LEVELS)
def test_audit_fail_on(demo: DemoManifest, audit_report: dict[str, Any], fail_on: str) -> None:
    result = run("audit", demo.rules_dir, "--fail-on", fail_on)
    assert result.exit_code == expected_exit(audit_report, fail_on)
    assert "Tuning debt" in text(result.stdout)


def test_audit_missing_ruleset_exits_2(tmp_path: Path) -> None:
    result = run("audit", tmp_path / "no-rules")
    assert result.exit_code == 2
    assert "ruleset path not found" in text(result.stderr)


# ---- noise / silence ----------------------------------------------------------------------------------------------


def test_noise_emit_suppressions(demo: DemoManifest, demo_config: Path, tmp_path: Path) -> None:
    out_dir = tmp_path / "suppressions"
    result = run(
        "noise", demo.alerts_path, "-c", demo_config, "--now", demo.now.isoformat(),
        "--emit-suppressions", out_dir, "-f", "json",
    )  # fmt: skip
    report = json.loads(result.stdout)
    assert result.exit_code == expected_exit(report, "none") == 0
    assert set(report["sections"]) == {"noise", "pipeline"}
    assert {d for d, s in report["assessment"].items() if s != "not_assessed"} == {"noise", "pipeline", "assessment"}
    assert {f["domain"] for f in report["findings"]} <= {"noise", "pipeline", "assessment"}

    rules_xml = out_dir / "hushwatch_local_rules.xml"
    tunes = [f for f in report["findings"] if f["kind"] == "noise.tune"]
    if not tunes:  # the small demo may hold no safe candidate: then nothing is written, and the report says so
        assert report["sections"]["noise"]["suppressions_file"] is None
        assert not rules_xml.exists()
        return
    assert report["sections"]["noise"]["suppressions_file"] == str(rules_xml)
    assert mode(out_dir) == 0o700
    for path in out_dir.iterdir():
        assert mode(path) == 0o600, path.name
    xml_text = rules_xml.read_text(encoding="utf-8")
    assert "real values" in xml_text  # local-only header
    root = ET.fromstring(xml_text)
    assert root.tag == "group" and "hushwatch" in root.get("name", "")
    rules = list(root.iter("rule"))
    spec = json.loads((out_dir / "hushwatch_suppressions.json").read_text(encoding="utf-8"))
    assert len(rules) == len(spec["suppressions"]) >= 1
    low, high = spec["id_range"]
    assert all(low <= int(rule.get("id", "0")) <= high for rule in rules)
    assert all(rule.get("level") == "3" for rule in rules)  # demote, never drop

    assert len(tunes) >= len(spec["suppressions"])
    parents = {s["parent_rule"] for s in spec["suppressions"]}
    safe = {r for sc in demo.ground_truth if sc.category == "noise_safe" for r in sc.rule_ids}
    traps = {r for sc in demo.ground_truth if sc.must_not_hide for r in sc.rule_ids}
    assert not parents & (traps - safe), "a suppression targets a rule that only fires for a planted attack"


def test_silence(demo: DemoManifest, demo_config: Path, tmp_path: Path) -> None:
    out = tmp_path / "silence.md"
    result = run(
        "silence", demo.alerts_path, "-c", demo_config, "--now", demo.now.isoformat(),
        "--fail-on", "critical", "-f", "json",
    )  # fmt: skip
    report = json.loads(result.stdout)
    assert result.exit_code == expected_exit(report, "critical") == 1
    assert set(report["sections"]) == {"silence", "coverage", "pipeline"}
    assert report["assessment"]["noise"] == "not_assessed"
    assert report["assessment"]["tuning"] == "not_assessed"
    domains = Counter(f["domain"] for f in report["findings"])
    assert set(domains) <= {"silence", "coverage", "pipeline", "assessment"}
    assert domains["silence"] > 0 and domains["coverage"] > 0
    subjects = {(f["kind"], f["subject"]) for f in report["findings"]}
    assert ("silence.tampering", "agent:dc02") in subjects
    assert any(k == "silence.field_lost" and "fw-edge-01" in s for k, s in subjects)

    result = run("silence", demo.alerts_path, "-c", demo_config, "--now", demo.now.isoformat(), "-f", "md", "-o", out)
    assert result.exit_code == 0 and mode(out) == 0o600
    assert "# hushwatch" in out.read_text(encoding="utf-8")


# ---- check (cron mode) --------------------------------------------------------------------------------------------


_SUMMARY = re.compile(
    r"(?P<tenant>\S+): (?P<findings>\d+) findings?, (?P<opened>\d+) opened, (?P<resolved>\d+) resolved, "
    r"(?:(?P<delivered>\d+) of (?P<sent>\d+) notifications? delivered"
    r"|(?P<dry>\d+) notifications? not sent \(dry run: the next run sends them\)"
    r"|(?P<none>\d+) changes?, no notification target configured)"
)


def _summary(output: str) -> dict[str, Any]:
    match = _SUMMARY.fullmatch(text(output).strip())
    assert match, output
    groups = match.groupdict()
    parsed: dict[str, Any] = {k: int(groups[k]) for k in ("findings", "opened", "resolved")}
    parsed["notifications"] = int(groups["sent"] or groups["dry"] or groups["none"])
    parsed["delivered"] = int(groups["delivered"]) if groups["delivered"] is not None else None
    parsed["tenant"], parsed["dry_run"] = match["tenant"], groups["dry"] is not None
    return parsed


def _check_config(tmp_path: Path, alerts: Path, state_dir: Path, **tenant: Any) -> Path:
    body = {
        "timezone": "UTC",
        "state_dir": str(state_dir),
        "inputs": [{"type": "file", "path": str(alerts), "profile": "wazuh4"}],
        "notify": [{"type": "webhook", "url": "https://hooks.example/hushwatch"}],
        **tenant,
    }
    return write_config(tmp_path / "check.yml", {"tenants": {"acme": body}})


def test_check_twice_dry_run(
    demo_config: Path, demo: DemoManifest, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, frozen_clock: Any
) -> None:
    def no_network(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("--dry-run must not send notifications")

    monkeypatch.setattr(hw_notify, "send", no_network)
    monkeypatch.setattr(hw_notify, "send_heartbeat", no_network)
    raw = yaml.safe_load(demo_config.read_text(encoding="utf-8"))
    body = raw["tenants"][demo.tenant]
    state_dir = private_dir(tmp_path / "state")
    body["state_dir"] = str(state_dir)
    body["notify"] = [{"type": "webhook", "url": "https://hooks.example/hushwatch"}]
    cfg = write_config(tmp_path / "check.yml", raw)

    frozen_clock.current = demo.now + timedelta(hours=1)
    first = run("check", "-c", cfg, "--dry-run")
    frozen_clock.current += timedelta(minutes=5)  # the next cron run
    second = run("check", "-c", cfg, "--dry-run")

    assert first.exit_code == second.exit_code == 0
    one, two = _summary(first.stdout), _summary(second.stdout)
    assert one["tenant"] == two["tenant"] == demo.tenant
    assert one["dry_run"] and two["dry_run"]
    assert two["findings"] == one["findings"] > 0
    # hysteresis: only critical / immediate kinds open on the first run, the rest on the second; what the first
    # dry run would have sent is still pending (a dry run never swallows a notification), so the second run
    # announces every open finding
    assert 0 < one["opened"] < one["findings"]
    assert one["notifications"] == one["opened"]
    assert two["opened"] == two["notifications"] == two["findings"]
    assert two["resolved"] == 0

    db = state_dir / STATE_FILENAME
    assert db.is_file() and mode(db) == 0o600
    with StateStore(state_dir) as store:
        last = store.last_run(demo.tenant)
        assert last is not None and last.run_at == frozen_clock.current
        assert last.counts["open"] == two["findings"]
        assert last.counts["pending"] == 0
        beat = store.last_heartbeat(demo.tenant)
        assert beat is not None and beat.ok and beat.at == frozen_clock.current


def test_check_sends_notifications_without_dry_run(
    tmp_path: Path, small_alerts: Path, monkeypatch: pytest.MonkeyPatch, frozen_clock: Any
) -> None:
    sent: list[tuple[str, Any]] = []

    def fake_send(target: Any, payload: Any, **kwargs: Any) -> hw_notify.SendResult:
        sent.append(("send", payload))
        return hw_notify.SendResult(ok=True, sent=True, status_code=200)

    def fake_heartbeat(target: Any, tenant: str, **kwargs: Any) -> hw_notify.SendResult:
        sent.append(("heartbeat", tenant))
        return hw_notify.SendResult(ok=True, sent=True, status_code=200)

    monkeypatch.setattr(hw_notify, "send", fake_send)
    monkeypatch.setattr(hw_notify, "send_heartbeat", fake_heartbeat)
    cfg = _check_config(tmp_path, small_alerts, private_dir(tmp_path / "state"))
    frozen_clock.current = datetime(2026, 9, 11, tzinfo=UTC)
    result = run("check", "-c", cfg)
    assert result.exit_code == 0
    summary = _summary(result.stdout)
    assert summary["tenant"] == "acme" and not summary["dry_run"]
    assert [kind for kind, _ in sent] == ["send", "heartbeat"]
    assert sent[1][1] == "acme"


def test_check_tenant_without_inputs_exits_2(tmp_path: Path) -> None:
    cfg = write_config(tmp_path / "cfg.yml", {"tenants": {"acme": {"state_dir": str(private_dir(tmp_path / "s"))}}})
    result = run("check", "-c", cfg, "--dry-run")
    assert result.exit_code == 2
    assert "no inputs configured" in text(result.stderr)


def test_check_creates_a_missing_state_dir(tmp_path: Path, small_alerts: Path, frozen_clock: Any) -> None:
    state_dir = tmp_path / "fresh" / "state"
    cfg = _check_config(tmp_path, small_alerts, state_dir)
    frozen_clock.current = datetime(2026, 9, 11, tzinfo=UTC)
    result = run("check", "-c", cfg, "--dry-run", allow_crash=True)
    assert not crashed(result), repr(result.exception)
    assert result.exit_code == 0
    assert state_dir.is_dir()
    assert (state_dir / STATE_FILENAME).is_file()


def test_check_invalid_accept_file_is_a_config_error(tmp_path: Path, small_alerts: Path, frozen_clock: Any) -> None:
    state_dir = private_dir(tmp_path / "state")
    accept = state_dir / "hushwatch-accept.yml"
    accept.write_text(
        "version: 1\naccept:\n  - kind: silence.silent\n    subject: 'agent:*'\n    owner: soc\n    reason: lab\n",
        encoding="utf-8",
    )  # no 'expires': invalid
    os.chmod(accept, 0o600)
    cfg = _check_config(tmp_path, small_alerts, state_dir)
    frozen_clock.current = datetime(2026, 9, 11, tzinfo=UTC)
    result = run("check", "-c", cfg, "--dry-run", allow_crash=True)
    assert not crashed(result), repr(result.exception)
    assert result.exit_code == 2
    assert "expires" in text(result.stderr)


@pytest.mark.parametrize("command", ["check", "doctor"])
def test_unknown_tenant_is_a_usage_error(tmp_path: Path, small_alerts: Path, command: str) -> None:
    cfg = _check_config(tmp_path, small_alerts, private_dir(tmp_path / "state"))
    result = run(command, "-c", cfg, "-t", "nope", allow_crash=True)
    assert not crashed(result), repr(result.exception)
    assert result.exit_code == 2
    assert "unknown tenant" in text(result.stderr)


# ---- fleet --------------------------------------------------------------------------------------------------------


def _fleet_config(tmp_path: Path, tenants: dict[str, Any]) -> Path:
    raw = {"defaults": {"timezone": "UTC", "state_dir": str(private_dir(tmp_path / "state"))}, "tenants": tenants}
    return write_config(tmp_path / "fleet.yml", raw)


def _file_input(path: Path) -> dict[str, Any]:
    return {"inputs": [{"type": "file", "path": str(path), "profile": "wazuh4"}]}


def test_fleet_two_tenants_json_redacted(
    tmp_path: Path, demo: DemoManifest, demo_config: Path, other_alerts: Path, leaks: Leaks
) -> None:
    demo_body = yaml.safe_load(demo_config.read_text(encoding="utf-8"))["tenants"][demo.tenant]
    demo_body.pop("state_dir")
    cfg = _fleet_config(tmp_path, {"alpha": demo_body, "bravo": _file_input(other_alerts)})
    out = tmp_path / "fleet.json"
    # the synthetic exports are old: measure each tenant as of its own newest event
    result = run("fleet", "-c", cfg, "-f", "json", "-o", out, "--redact", "--data-now")
    assert result.exit_code == 0
    stderr = text(result.stderr)
    assert "analyzing alpha" in stderr and "analyzing bravo" in stderr
    assert mode(out) == 0o600
    body = out.read_text(encoding="utf-8")
    doc = json.loads(body)
    assert doc["document"] == "hushwatch.fleet"
    rows = {row["tenant"]: row for row in doc["tenants"]}
    assert list(rows) == ["alpha", "bravo"]  # ordered by critical findings first
    assert rows["alpha"]["events"] == demo.alerts
    assert rows["alpha"]["findings"]["critical"] >= 1
    assert rows["bravo"]["findings"]["critical"] == rows["bravo"]["findings"]["high"] == 0
    assert all(not row["incomplete"] for row in rows.values())
    assert leaks.find(body) == set()
    assert "db-1.example" not in body


def test_fleet_console_table(tmp_path: Path, small_alerts: Path, other_alerts: Path) -> None:
    cfg = _fleet_config(tmp_path, {"web": _file_input(small_alerts), "db": _file_input(other_alerts), "idle": {}})
    result = run("fleet", "-c", cfg, "--data-now")
    assert result.exit_code == 0
    out = text(result.stdout)
    assert "Fleet summary" in out
    assert re.search(r"^web\s", out, re.MULTILINE) and re.search(r"^db\s", out, re.MULTILINE)
    assert "idle: no inputs configured, skipped" in text(result.stderr)


def test_fleet_exit_3_when_a_tenant_has_no_events(tmp_path: Path, small_alerts: Path) -> None:
    empty = tmp_path / "empty.json"
    empty.write_text("", encoding="utf-8")
    cfg = _fleet_config(tmp_path, {"web": _file_input(small_alerts), "void": _file_input(empty)})
    result = run("fleet", "-c", cfg, "-f", "md", "--data-now")
    assert result.exit_code == 3
    assert "void" in result.stdout and "web" in result.stdout


def test_fleet_without_analyzable_tenants_exits_2(tmp_path: Path) -> None:
    cfg = _fleet_config(tmp_path, {"idle": {}})
    result = run("fleet", "-c", cfg)
    assert result.exit_code == 2
    assert "no tenant could be analyzed" in text(result.stderr)


def test_fleet_tenant_with_missing_input_is_not_a_green_run(tmp_path: Path, small_alerts: Path) -> None:
    cfg = _fleet_config(tmp_path, {"web": _file_input(small_alerts), "lost": _file_input(tmp_path / "missing.json")})
    result = run("fleet", "-c", cfg, "-f", "json", "--data-now")
    assert "lost: input not found" in text(result.stderr)
    assert result.exit_code == 3
    rows = {row["tenant"]: row for row in json.loads(result.stdout)["tenants"]}
    assert set(rows) == {"web", "lost"}  # the failed tenant has its own (incomplete) row
    assert rows["lost"]["incomplete"] and not rows["web"]["incomplete"]


# ---- doctor -------------------------------------------------------------------------------------------------------


def test_doctor_with_the_demo_config(demo: DemoManifest, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(demo.out_dir)  # the demo config uses paths relative to its directory
    result = run("doctor", "-c", demo.config_path)
    assert result.exit_code == 0
    out = text(result.stdout)
    assert "hushwatch doctor" in out
    for header in ("tenant", "check", "status", "detail", "how to fix"):
        assert header in out
    rows = {line for line in out.splitlines() if line.startswith("│ demo")}
    assert any("file input" in r and " OK " in r and "wazuh4" in r for r in rows), rows
    assert any("ruleset" in r and " OK " in r for r in rows), rows
    assert any("state dir" in r and " OK " in r for r in rows), rows
    assert re.search(r"\d+ checks?: 0 failed", out)


def test_doctor_resolves_config_relative_paths_from_any_directory(
    demo: DemoManifest, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)  # the demo config's relative paths are relative to the config file, not the cwd
    result = run("doctor", "-c", demo.config_path)
    assert result.exit_code == 0, result.stdout
    out = text(result.stdout)
    assert str(demo.alerts_path) in out.replace("\n", "")  # shown resolved (absolute)
    assert re.search(r"\d+ checks?: 0 failed", out)


def test_doctor_fails_when_an_input_is_not_reachable(tmp_path: Path) -> None:
    cfg = _check_config(tmp_path, tmp_path / "gone" / "alerts.json", private_dir(tmp_path / "state"))
    result = run("doctor", "-c", cfg)
    assert result.exit_code == 1
    out = text(result.stdout)
    assert any("file input" in line and "FAIL" in line for line in out.splitlines())
    assert "not found" in out
    assert re.search(r"\d+ checks?: [1-9]\d* failed", out)


def test_doctor_config_permissions(demo_config: Path) -> None:
    os.chmod(demo_config, 0o644)
    try:
        loose = text(run("doctor", "-c", demo_config).stdout)
    finally:
        os.chmod(demo_config, 0o600)
    assert "config permissions" in loose and "WARN" in loose
    strict = text(run("doctor", "-c", demo_config).stdout)
    assert "config permissions" not in strict
