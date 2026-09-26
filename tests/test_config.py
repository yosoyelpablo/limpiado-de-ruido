"""Configuration loading: the documented examples must load, secrets never leak, mistakes are clear errors."""

from __future__ import annotations

import re
from datetime import timedelta
from pathlib import Path

import pytest

from hushwatch.config import ApiConfig, ConfigError, InputConfig, NotifyConfig, load_config, parse_config

ROOT = Path(__file__).resolve().parents[1]
ENV = {
    "ACME_WAZUH_API_USER": "api-reader",
    "ACME_WAZUH_API_PASSWORD": "FAKE-test-api-pass",
    "ACME_WEBHOOK_URL": "https://hooks.example/abc",
    "GLOBEX_INDEXER_USER": "idx-reader",
    "GLOBEX_INDEXER_PASSWORD": "FAKE-test-idx-pass",
    "GLOBEX_SLACK_WEBHOOK": "https://hooks.slack.example/services/T0/B0/XYZ",
}


def test_example_config_loads_with_typed_sections() -> None:
    cfg = load_config(ROOT / "examples" / "hushwatch.yml", environ=ENV)
    acme = cfg.tenant("acme")
    assert isinstance(acme.wazuh_api, ApiConfig)
    assert acme.wazuh_api.url.startswith("https://")
    assert acme.wazuh_api.password == ENV["ACME_WAZUH_API_PASSWORD"]
    assert all(isinstance(i, InputConfig) for i in acme.inputs)
    assert all(isinstance(n, NotifyConfig) for n in acme.notify)
    globex = cfg.tenant("globex")
    assert globex.timezone == "Europe/Madrid"  # tenant overrides defaults
    assert globex.inputs[0].type == "indexer"
    assert globex.criticality == acme.criticality  # inherited
    assert acme.sla["critical"] == timedelta(hours=4)


def test_readme_config_snippet_loads() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    block = re.search(r"```yaml\n(defaults:.*?)```", readme, re.S)
    assert block, "README must contain the configuration example"
    import yaml

    raw = yaml.safe_load(block.group(1))
    env = {k: "x" for k in re.findall(r"\$\{([A-Z_]+)\}", block.group(1))}
    cfg = parse_config(raw, env)
    tenant = cfg.tenant("acme")
    assert isinstance(tenant.wazuh_api, ApiConfig)
    assert tenant.inputs[0].type == "indexer"


def test_secrets_never_in_repr() -> None:
    cfg = load_config(ROOT / "examples" / "hushwatch.yml", environ=ENV)
    for tenant in cfg.tenants.values():
        text = repr(tenant)
        for secret in ("FAKE-test-api-pass", "FAKE-test-idx-pass", "hooks.slack.example/services", "hooks.example/abc"):
            assert secret not in text


def test_missing_env_var_names_the_variable_not_a_value() -> None:
    cfg = load_config(
        ROOT / "examples" / "hushwatch.yml", environ={k: v for k, v in ENV.items() if "API_PASSWORD" not in k}
    )
    with pytest.raises(ConfigError, match="ACME_WAZUH_API_PASSWORD") as caught:
        cfg.tenant("acme")
    assert "FAKE-test" not in str(caught.value)
    assert cfg.tenant("globex").inputs[0].password == ENV["GLOBEX_INDEXER_PASSWORD"]  # other tenants still work


@pytest.mark.parametrize(
    ("tenant", "message"),
    [
        ({"triage_levl": 3}, "unknown key 'triage_levl' \\(did you mean 'triage_level'\\?\\)"),
        ({"timezone": "Mars/Olympus"}, "unknown timezone"),
        ({"internal_networks": ["10.0.0.0/33"]}, "invalid network"),
        ({"suppression_id_range": [1, 5]}, "100000-120000"),
        ({"inputs": [{"type": "file"}]}, "needs 'path'"),
        ({"inputs": [{"type": "kafka", "path": "x"}]}, "file or indexer"),
        ({"inputs": [{"type": "file", "path": "x", "max_events": "lots"}]}, "expected a number"),
        ({"wazuh_api": {"url": "https://m", "bogus": 1}}, "tenants.t.wazuh_api: unknown key 'bogus'"),
        ({"criticality": {"crtical": ["dc*"]}}, "unknown tier 'crtical' \\(did you mean 'critical'\\?\\)"),
        ({"wazuh_api": {"username": "u"}}, "missing required key\\(s\\) url"),
        ({"state_dir": ["x"]}, "expected a string"),
        ({"sla": {"platinum": "1h"}}, "unknown sla tier"),
        ({"notify": [{"type": "slack", "url": "https://x", "min_severity": "loud"}]}, "min_severity"),
        ({"silence": {"baseline": "fortnight"}}, "invalid duration"),
    ],
)
def test_config_mistakes_are_clear_errors(tenant: dict[str, object], message: str) -> None:
    with pytest.raises(ConfigError, match=message):
        parse_config({"tenants": {"t": tenant}}, {})


def test_partial_sla_override_keeps_other_tiers() -> None:
    t = parse_config({"defaults": {"sla": {"standard": "12h"}}}, {}).tenant()
    assert t.sla["standard"] == timedelta(hours=12)
    assert t.sla_for("critical") == timedelta(hours=4)
    assert t.sla_for("low") == timedelta(hours=72)


def test_helpers() -> None:
    t = parse_config(
        {"defaults": {"trusted_entities": {"data.srcip": ["10.20.0.15"], "user": ["svc_*"]},
                      "criticality": {"critical": ["dc*"], "low": ["lap-*"]}}},
        {},
    ).tenant()  # fmt: skip
    assert t.is_trusted("src_ip", "10.20.0.15") and t.is_trusted("data.win.eventdata.subjectUserName", "SVC_backup")
    assert not t.is_trusted("user", "alice")
    assert t.tier_for("DC01") == "critical" and t.tier_for("lap-003") == "low" and t.tier_for("srv") == "standard"
    assert t.is_internal("::ffff:10.0.0.5") and not t.is_internal("203.0.113.5") and not t.is_internal("nope")
