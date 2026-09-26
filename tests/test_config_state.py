"""Regression tests: configuration loading, the state directory and lifecycle, redaction keys,
heartbeats and notification failure reporting. Synthetic data only."""

from __future__ import annotations

import logging
import os
import stat
import time
import warnings
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest
import yaml

from hushwatch.config import ConfigError, NotifyConfig, load_config, parse_config
from hushwatch.i18n import render
from hushwatch.models import Finding, Severity
from hushwatch.notify import build_heartbeat, send
from hushwatch.redact import RedactKeyError, Redactor, key_filename
from hushwatch.state import STATE_FILENAME, StateError, StateStore, prepare_state_dir, state_dir_problem

UTC = timezone.utc
T0 = datetime(2026, 9, 1, 12, 0, tzinfo=UTC)
HOUR = timedelta(hours=1)
TENANT = "acme"


def _mode(path: Path) -> int:
    return stat.S_IMODE(os.stat(path).st_mode)


def private(path: Path, want: int = 0o600) -> bool:
    """Owner-only permissions; Windows has ACLs, not POSIX mode bits, so there is nothing to compare."""
    return os.name != "posix" or _mode(path) == want


def _write(path: Path, raw: object, mode: int = 0o600) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(raw if isinstance(raw, str) else yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")
    os.chmod(path, mode)
    return path


def _finding(kind: str, subject: str, severity: Severity = Severity.HIGH, related: list[str] | None = None) -> Finding:
    domain = kind.split(".", 1)[0]
    return Finding(
        kind=kind,
        domain=domain,
        title=f"{kind} {subject}",
        severity=severity,
        subject=subject,
        tenant=TENANT,
        related=list(related or []),
    )


# ---- configuration: paths, environment, validation -----------------------------------------------------------------


def test_relative_paths_resolve_against_the_config_file_directory(tmp_path: Path) -> None:
    cfg_path = _write(
        tmp_path / "etc" / "hushwatch.yml",
        {
            "tenants": {
                "acme": {
                    "inputs": [
                        {"type": "file", "path": "logs/*.json"},
                        {"type": "indexer", "url": "https://idx.example:9200", "ca_cert": "ca.pem"},
                    ],
                    "ruleset_dirs": ["rules", "/abs/rules"],
                    "dispositions": "dispositions.csv",
                    "state_dir": "state",
                    "agents_file": "agents.json",
                    "wazuh_api": {"url": "https://manager.example:55000", "ca_cert": "../api-ca.pem"},
                }
            }
        },
    )
    tenant = load_config(cfg_path, environ={}).tenant()
    base = tmp_path / "etc"
    assert tenant.inputs[0].path == str(base / "logs" / "*.json")
    assert tenant.inputs[1].ca_cert == str(base / "ca.pem")
    assert tenant.ruleset_dirs == [str(base / "rules"), "/abs/rules"]
    assert tenant.dispositions == str(base / "dispositions.csv")
    assert tenant.state_dir == str(base / "state")
    assert tenant.agents_file == str(base / "agents.json")
    assert tenant.wazuh_api is not None and tenant.wazuh_api.ca_cert == str(tmp_path / "api-ca.pem")


def test_a_missing_environment_variable_only_blocks_its_tenant() -> None:
    raw = {
        "tenants": {
            "acme": {"notify": [{"type": "slack", "url": "${ACME_SLACK}"}]},
            "globex": {"inputs": [{"type": "indexer", "url": "https://idx.example", "password": "${GLOBEX_PW}"}]},
        }
    }
    cfg = parse_config(raw, {"ACME_SLACK": "https://hooks.slack.example/services/T/B/SECRETVALUE"})
    assert cfg.tenant("acme").notify[0].url.endswith("SECRETVALUE")
    with pytest.raises(ConfigError, match="GLOBEX_PW") as caught:
        cfg.tenant("globex")
    assert "tenants.globex.inputs[0].password" in str(caught.value)  # the list index is kept
    assert "SECRETVALUE" not in str(caught.value)
    assert cfg.select(None) == ["acme", "globex"]
    assert cfg.env_error("acme") is None
    with pytest.raises(ConfigError, match="did you mean 'globex'"):
        cfg.select("globx")


def test_config_errors_are_all_reported_where_they_were_written() -> None:
    raw = {
        "defaults": {"noise": {"min_shar": 0.3}},
        "tenants": {"acme": {"timezon": "UTC", "notify": [{"type": "webhook", "ulr": "https://x"}]}},
    }
    with pytest.raises(ConfigError) as caught:
        parse_config(raw, {})
    message = str(caught.value)
    assert "3 problems" in message
    assert "defaults.noise: unknown key 'min_shar' (did you mean 'min_share'?)" in message
    assert "tenants.acme: unknown key 'timezon' (did you mean 'timezone'?)" in message
    assert "tenants.acme.notify[0]: unknown key 'ulr' (did you mean 'url'?)" in message


def test_a_bad_value_inherited_from_defaults_is_reported_under_defaults() -> None:
    raw = {"defaults": {"noise": {"min_share": "lots"}}, "tenants": {"acme": {"noise": {"persistence": 0.5}}}}
    with pytest.raises(ConfigError, match=r"defaults\.noise\.min_share: expected a number"):
        parse_config(raw, {})


def test_criticality_tiers_are_validated_and_unknown_trusted_fields_warned() -> None:
    with pytest.raises(ConfigError, match=r"unknown tier 'crtical' \(did you mean 'critical'\?\)"):
        parse_config({"tenants": {"a": {"criticality": {"crtical": ["dc*"]}}}}, {})
    with pytest.warns(UserWarning, match=r"'usr' is not a known field \(did you mean 'user'\?\)"):
        cfg = parse_config({"tenants": {"a": {"trusted_entities": {"usr": ["svc_x"], "data.srcip": ["10.0.0.5"]}}}}, {})
    assert cfg.tenant("a").is_trusted("data.srcip", "10.0.0.5")
    with warnings.catch_warnings():
        warnings.simplefilter("error")  # canonical names and dotted paths are silent
        parse_config({"tenants": {"a": {"trusted_entities": {"user": ["x"], "data.win.eventdata.image": ["y"]}}}}, {})


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions")
def test_literal_credentials_are_found_in_the_parsed_tree(tmp_path: Path) -> None:
    text = """\
tenants:
  acme:
    inputs:
      - type: indexer
        url: https://idx.example:9200
        username: reader
        password: "${IDX_PASSWORD}"
      - {type: indexer, url: "https://idx2.example:9200", password: FAKE-literal-password}
    notify:
      - {type: slack, url: "https://hooks.slack.example/services/FAKE/FAKE/FAKE-webhook-path"}
      - {type: webhook, url: "https://hooks.example/hushwatch"}
      - type: webhook
        url: "${HOOK}"
        headers: {Authorization: "Bearer FAKE-test-token", X-Env: "${TAG}"}
"""
    loose = _write(tmp_path / "loose.yml", text, 0o644)
    env = {"IDX_PASSWORD": "x", "HOOK": "https://h.example/x", "TAG": "t"}
    with pytest.warns(UserWarning, match="literal credentials") as caught:
        cfg = load_config(loose, environ=env)
    assert cfg.literal_secrets == [
        "tenants.acme.inputs[1].password",
        "tenants.acme.notify[0].url",
        "tenants.acme.notify[2].headers.Authorization",
    ]
    shown = str(caught[0].message)
    assert "FAKE-literal-password" not in shown and "FAKE-webhook-path" not in shown and "Bearer" not in shown
    private = _write(tmp_path / "private.yml", text, 0o600)
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        load_config(private, environ=env)  # a private file holding literals is the user's choice: no warning
    only_refs = _write(
        tmp_path / "refs.yml", 'tenants:\n  a:\n    wazuh_api: {url: https://m, password: "${P}"}\n', 0o644
    )
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        assert load_config(only_refs, environ={"P": "p"}).literal_secrets == []


def test_yaml_alias_bombs_are_refused_quickly(tmp_path: Path) -> None:
    lines = ['a0: &a0 ["lol","lol","lol","lol","lol","lol","lol","lol","lol"]']
    for i in range(1, 12):
        lines.append(f"a{i}: &a{i} [" + ",".join([f"*a{i - 1}"] * 9) + "]")
    bomb = _write(tmp_path / "bomb.yml", "\n".join(lines) + "\ntenants: {}\n")
    started = time.monotonic()
    with pytest.raises(ConfigError, match="aliases"):
        load_config(bomb, environ={})
    assert time.monotonic() - started < 5


def test_yaml_errors_give_the_position_never_the_text(tmp_path: Path) -> None:
    bad = _write(
        tmp_path / "bad.yml",
        'tenants:\n  acme:\n    notify:\n      - url: "https://hooks.slack.example/services/FAKE/FAKE/FAKE-webhook-path\n'
        "    bad: [\n",
    )
    with pytest.raises(ConfigError) as caught:
        load_config(bad, environ={})
    message = str(caught.value)
    assert "FAKE-webhook-path" not in message and "hooks.slack" not in message
    assert "line" in message and "column" in message and "<unicode string>" not in message


# ---- state directory ----------------------------------------------------------------------------------------------


def test_a_missing_path_without_suffix_is_a_state_directory(tmp_path: Path) -> None:
    target = tmp_path / "fresh" / "state"
    with StateStore(target) as store:
        assert store.path == target / STATE_FILENAME
        store.record_run(TENANT, [], now=T0)
    assert target.is_dir() and private(target, 0o700)
    assert (target / STATE_FILENAME).is_file()


def test_a_database_created_at_the_directory_path_is_migrated(tmp_path: Path) -> None:
    legacy = tmp_path / "legacy.sqlite3"
    with StateStore(legacy) as store:
        store.record_run(TENANT, [_finding("silence.silent", "agent:web-1")], now=T0)
    state_dir = tmp_path / "state"
    os.rename(legacy, state_dir)  # what the old `check` left behind: the database AT the state_dir path
    for suffix in ("-wal", "-shm"):
        if Path(str(legacy) + suffix).exists():
            os.rename(str(legacy) + suffix, str(state_dir) + suffix)
    problem = state_dir_problem(state_dir)
    assert problem is not None and problem[0] == "warn"
    assert prepare_state_dir(state_dir) == state_dir
    assert state_dir.is_dir() and private(state_dir, 0o700)
    assert state_dir_problem(state_dir) is None
    with StateStore(state_dir / STATE_FILENAME) as store:
        last = store.last_run(TENANT)
        assert last is not None and last.run_at == T0  # history kept


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions")
def test_prepare_state_dir_refuses_other_files_and_shared_directories(tmp_path: Path) -> None:
    plain = tmp_path / "notes"
    plain.write_text("hello", encoding="utf-8")
    with pytest.raises(StateError, match="not a directory"):
        prepare_state_dir(plain)
    assert state_dir_problem(plain) is not None and state_dir_problem(plain)[0] == "fail"  # type: ignore[index]
    shared = tmp_path / "shared"
    shared.mkdir()
    os.chmod(shared, 0o777)
    with pytest.raises(StateError, match="other users"):
        prepare_state_dir(shared)
    created = prepare_state_dir(tmp_path / "a" / "b")
    assert private(tmp_path / "a", 0o700) and private(created, 0o700)


# ---- lifecycle: explained findings and kinds a run could not re-check --------------------------------------------


def test_explained_findings_are_never_resolved_while_their_explanation_is_present(tmp_path: Path) -> None:
    child = _finding("silence.silent", "agent:dc02|ls:Security")
    parent = _finding("silence.tampering", "agent:dc02", Severity.CRITICAL, related=[child.fingerprint])
    with StateStore(tmp_path / "s.sqlite3") as store:
        assert [t.type for t in store.record_run(TENANT, [child], now=T0).transitions] == ["opened"]
        for i in range(1, 4):  # the parent now explains the child: grouped, still there
            outcome = store.record_run(TENANT, [parent], now=T0 + i * HOUR)
            assert all(t.fingerprint != child.fingerprint for t in outcome.transitions if t.type == "resolved")
            assert outcome.counts["explained"] == 1
        state = store.get(TENANT, child.fingerprint)
        assert state is not None and state.status == "open"
        store.record_run(TENANT, [], now=T0 + 4 * HOUR)
        resolved = store.record_run(TENANT, [], now=T0 + 5 * HOUR).resolved
        assert {t.fingerprint for t in resolved} == {child.fingerprint, parent.fingerprint}


def test_kinds_a_run_could_not_recheck_are_left_open(tmp_path: Path) -> None:
    gone = _finding("pipeline.agent_disconnected", "agent:gone-1")
    with StateStore(tmp_path / "s.sqlite3") as store:
        store.record_run(TENANT, [gone], now=T0)
        store.record_run(TENANT, [gone], now=T0 + HOUR)
        for i in range(2, 6):
            outcome = store.record_run(
                TENANT, [], now=T0 + i * HOUR, assessed={"pipeline"}, unassessed_kinds={"pipeline.agent_disconnected"}
            )
            assert outcome.resolved == [] and outcome.counts["not_assessed"] == 1
        state = store.get(TENANT, gone.fingerprint)
        assert state is not None and state.status == "open"


# ---- redaction keys -----------------------------------------------------------------------------------------------


def test_tenants_with_similar_names_never_share_a_redaction_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("HUSHWATCH_REDACT_KEY", raising=False)
    state = tmp_path / "state"
    names = ("cliente/norte", "cliente_norte", "cliente norte")
    tokens = {name: Redactor.for_tenant(name, state).token("dc01", "host") for name in names}
    assert len(set(tokens.values())) == 3
    keys = state / "keys"
    files = sorted(p.name for p in keys.iterdir())
    assert files == sorted(key_filename(n) for n in names) and len(set(files)) == 3
    assert private(keys, 0o700) and private(state, 0o700)
    assert all(private(keys / f) and (keys / f).stat().st_size == 32 for f in files)
    again = Redactor.for_tenant("cliente/norte", state).token("dc01", "host")
    assert again == tokens["cliente/norte"]  # stable across runs


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions")
def test_unsafe_redaction_keys_are_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("HUSHWATCH_REDACT_KEY", raising=False)
    state = tmp_path / "state"
    Redactor.for_tenant(TENANT, state)
    key = state / "keys" / key_filename(TENANT)
    os.chmod(key, 0o644)
    with pytest.raises(RedactKeyError, match="not a private key file"):
        Redactor.for_tenant(TENANT, state)
    os.chmod(key, 0o600)
    key.write_bytes(b"short")
    with pytest.raises(RedactKeyError):
        Redactor.for_tenant(TENANT, state)
    key.unlink()
    victim = tmp_path / "victim.bin"
    victim.write_bytes(b"x" * 32)
    os.chmod(victim, 0o600)
    key.symlink_to(victim)
    with pytest.raises(RedactKeyError):
        Redactor.for_tenant(TENANT, state)
    shared = tmp_path / "shared"
    (shared / "keys").mkdir(parents=True)
    os.chmod(shared / "keys", 0o777)
    with pytest.raises(RedactKeyError, match="other users") as caught:
        Redactor.for_tenant(TENANT, shared)
    assert "otros usuarios" in caught.value.render("es").lower()


def test_a_key_of_the_previous_layout_is_adopted_for_plain_names(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("HUSHWATCH_REDACT_KEY", raising=False)
    keys = tmp_path / "keys"
    keys.mkdir(mode=0o700)
    legacy = keys / "acme.key"
    legacy.write_bytes(b"k" * 32)
    os.chmod(legacy, 0o600)
    redactor = Redactor.for_tenant("acme", tmp_path)
    assert redactor.token("dc01", "host") == Redactor(b"k" * 32).token("dc01", "host")
    assert (keys / key_filename("acme")).is_file() and not legacy.exists()


# ---- heartbeats and notification failures ------------------------------------------------------------------------


def test_heartbeat_status_says_when_critical_findings_are_open() -> None:
    quiet = build_heartbeat(TENANT, now=T0, ok=True, counts={"open": 3, "open.critical": 0})
    assert quiet["status"] == "ok"
    loud = build_heartbeat(TENANT, now=T0, ok=True, counts={"open": 3, "open.critical": 2})
    assert loud["ok"] is True and loud["status"] == "critical" and "2 critical" in loud["summary"]
    assert (
        "2 hallazgos críticos abiertos"
        in build_heartbeat(TENANT, now=T0, ok=True, counts={"open.critical": 2}, lang="es")["summary"]
    )
    failed = build_heartbeat(TENANT, now=T0, ok=False, detail="input not found", counts={"open.critical": 2})
    assert failed["status"] == "fail" and failed["detail"] == "input not found"


def test_a_failed_delivery_is_reported_once_by_the_caller(caplog: pytest.LogCaptureFixture) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500)

    caplog.set_level(logging.DEBUG, logger="hushwatch")
    payload = build_heartbeat(TENANT, now=T0, ok=True)
    result = send(
        NotifyConfig(type="webhook", url="https://hooks.example/p/SECRET"),
        payload,
        transport=httpx.MockTransport(handler),
    )
    assert not result.ok and result.message is not None
    assert "SECRET" not in render(result.message) and "SECRET" not in (result.error or "")
    assert not [r for r in caplog.records if r.levelno >= logging.WARNING]  # the CLI prints the one line
