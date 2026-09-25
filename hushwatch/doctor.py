"""``hushwatch doctor``: check that every configured tenant can actually be analyzed, and say how to fix it.

Most tools are abandoned at the "cannot connect" step. Each check prints OK / WARN / FAIL with the exact fix,
and steers users away from disabling TLS verification (the usual shortcut with Wazuh's self-signed certs).
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.text import Text

from .config import Config, InputConfig, TenantConfig
from .timeutil import UTC, humanize


@dataclass(slots=True)
class Check:
    tenant: str
    name: str
    status: str  # ok | warn | fail
    detail: str
    fix: str = ""


def run_doctor(cfg: Config, tenants: list[TenantConfig], *, console: Console) -> bool:
    """Run every check, print a table, return True when nothing FAILED."""
    checks: list[Check] = []
    checks.extend(_config_checks(cfg))
    for tenant in tenants:
        checks.extend(_tenant_checks(tenant))
    table = Table(title="hushwatch doctor", show_lines=False, expand=True)
    table.add_column("tenant", no_wrap=True)
    table.add_column("check", no_wrap=True)
    table.add_column("status", no_wrap=True)
    table.add_column("detail")
    table.add_column("how to fix")
    colors = {"ok": "green", "warn": "yellow", "fail": "red"}
    for c in checks:
        table.add_row(
            Text(c.tenant),
            Text(c.name),
            Text(c.status.upper(), style=f"bold {colors[c.status]}"),
            Text(c.detail),
            Text(c.fix),
        )
    console.print(table)
    failed = sum(c.status == "fail" for c in checks)
    warned = sum(c.status == "warn" for c in checks)
    console.print(Text(f"{len(checks)} checks: {failed} failed, {warned} warnings"))
    return failed == 0


def _config_checks(cfg: Config) -> list[Check]:
    if cfg.path is None:
        return [
            Check(
                "-",
                "config",
                "warn",
                "no config file: using built-in defaults (tenant 'default')",
                "copy examples/hushwatch.yml and pass --config or set HUSHWATCH_CONFIG",
            )
        ]
    out: list[Check] = []
    try:
        mode = cfg.path.stat().st_mode
    except OSError as exc:
        return [Check("-", "config", "fail", f"cannot stat {cfg.path}: {exc.strerror}")]
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        out.append(
            Check(
                "-",
                "config permissions",
                "warn",
                f"{cfg.path} is accessible by group/others (mode {stat.S_IMODE(mode):o})",
                f"chmod 600 {cfg.path}",
            )
        )
    else:
        out.append(Check("-", "config", "ok", f"{cfg.path} ({len(cfg.tenants)} tenant(s))"))
    return out


def _tenant_checks(tenant: TenantConfig) -> list[Check]:
    checks: list[Check] = []
    if not tenant.inputs:
        checks.append(
            Check(
                tenant.name,
                "inputs",
                "warn",
                "no inputs configured (only CLI paths will work)",
                "add an 'inputs' entry (type: file or indexer)",
            )
        )
    for item in tenant.inputs:
        if item.type == "file":
            checks.append(_file_check(tenant, item))
        else:
            checks.extend(_indexer_checks(tenant, item))
    if tenant.wazuh_api is not None:
        checks.extend(_api_checks(tenant))
    for rs_dir in tenant.ruleset_dirs:
        checks.append(_ruleset_check(tenant, rs_dir))
    checks.append(_state_check(tenant))
    for target in tenant.notify:
        if not target.url.startswith("https://"):
            checks.append(
                Check(tenant.name, f"notify {target.type}", "warn", "webhook URL is not https", "use an https URL")
            )
        else:
            checks.append(Check(tenant.name, f"notify {target.type}", "ok", "https webhook configured (not sent)"))
    return checks


def _file_check(tenant: TenantConfig, item: InputConfig) -> Check:
    from .ingest import IngestError, detect_profile, iter_documents

    path = item.path or ""
    try:
        docs = []
        for doc, _label in iter_documents([path]):
            docs.append(doc)
            if len(docs) >= 50:
                break
    except (IngestError, OSError) as exc:
        return Check(
            tenant.name,
            "file input",
            "fail",
            f"{path}: {exc}",
            "check the path; run hushwatch as a user in the 'wazuh' group to read /var/ossec/logs",
        )
    if not docs:
        return Check(tenant.name, "file input", "fail", f"{path}: no readable events", "point to alerts.json")
    profile = detect_profile(docs) if item.profile == "auto" else item.profile
    has_rule = sum(1 for d in docs if isinstance(d.get("rule"), dict))
    kind = "alerts" if has_rule == len(docs) else ("archives" if has_rule == 0 else "mixed")
    hint = (
        ""
        if kind != "alerts"
        else "for full log-source silence detection also enable logall_json and analyze archives.json"
    )
    return Check(tenant.name, "file input", "ok", f"{path}: profile {profile}, {kind}", hint)


def _indexer_checks(tenant: TenantConfig, item: InputConfig) -> list[Check]:
    from .ingest.opensearch import IndexerClient
    from .net import RemoteError

    name = f"indexer {item.index}"
    fix_tls = "set ca_cert to your indexer root CA (Wazuh: /etc/wazuh-indexer/certs/root-ca.pem); do not disable TLS"
    checks: list[Check] = []
    if not item.verify_tls:
        checks.append(Check(tenant.name, name, "warn", "TLS verification is DISABLED for this input", fix_tls))
    try:
        with IndexerClient(item) as client:
            info = client.engine()
            version = ".".join(str(v) for v in info.version) if info.version else "?"
            checks.append(
                Check(
                    tenant.name,
                    name,
                    "ok",
                    f"{info.kind} {version}{' (Wazuh indexer)' if info.wazuh_indexer else ''}",
                )
            )
            caps = client.field_caps(item.index)
            if item.time_field not in caps:
                checks.append(
                    Check(
                        tenant.name,
                        name,
                        "fail",
                        f"time field {item.time_field!r} not found in {item.index}",
                        "set time_field (Wazuh alerts: 'timestamp'; ECS: '@timestamp')",
                    )
                )
            end = datetime.now(UTC)
            count = client.count(item.index, query=None, start=end - timedelta(hours=24), end=end)
            status = "ok" if count > 0 else "warn"
            checks.append(
                Check(
                    tenant.name,
                    name,
                    status,
                    f"{count} documents in the last 24h",
                    "" if count else "check the index pattern and that data is still arriving",
                )
            )
            if "archives" not in item.index:
                checks.append(
                    Check(
                        tenant.name,
                        name,
                        "ok",
                        "alerts index: silence findings will be alert-level",
                        "add a wazuh-archives-* input for full log-source silence detection",
                    )
                )
    except RemoteError as exc:
        fix = fix_tls if getattr(exc, "kind", "") == "tls" else "check url, credentials (read-only role) and network"
        checks.append(Check(tenant.name, name, "fail", str(exc), fix))
    return checks


def _api_checks(tenant: TenantConfig) -> list[Check]:
    from .ingest.wazuh_api import WazuhAPI
    from .net import RemoteError

    api_cfg = tenant.wazuh_api
    assert api_cfg is not None
    try:
        with WazuhAPI(api_cfg) as api:
            info = api.info()
            agents = api.agents()
            stats = api.daemon_stats()
    except RemoteError as exc:
        fix = (
            "set ca_cert (the default Wazuh API cert is only valid for 'localhost')"
            if getattr(exc, "kind", "") == "tls"
            else "check url (port 55000), credentials and RBAC (agents:read, rules:read, manager:read)"
        )
        return [Check(tenant.name, "wazuh api", "fail", str(exc), fix)]
    version = str(info.get("api_version", "?")) if isinstance(info, dict) else "?"
    by_status: dict[str, int] = {}
    stale = 0
    now = datetime.now(UTC)
    for agent in agents:
        by_status[agent.status] = by_status.get(agent.status, 0) + 1
        if agent.last_keepalive and now - agent.last_keepalive > timedelta(days=1) and not agent.is_manager:
            stale += 1
    summary = ", ".join(f"{k}: {v}" for k, v in sorted(by_status.items()))
    checks = [Check(tenant.name, "wazuh api", "ok", f"API {version}; {len(agents)} agents ({summary})")]
    if stale:
        checks.append(
            Check(
                tenant.name,
                "wazuh api",
                "warn",
                f"{stale} agent(s) without keepalive for more than {humanize(timedelta(days=1))}",
                "run 'hushwatch report' to see which and since when",
            )
        )
    if stats is None:
        checks.append(
            Check(
                tenant.name,
                "wazuh api",
                "warn",
                "manager daemon stats unavailable (event drop checks will be skipped)",
                "grant manager:read, or upgrade to a Wazuh version with /manager/daemons/stats",
            )
        )
    return checks


def _ruleset_check(tenant: TenantConfig, rs_dir: str) -> Check:
    from .wazuh.ruleset import load_ruleset

    if not Path(rs_dir).exists():
        return Check(tenant.name, "ruleset", "fail", f"{rs_dir} not found", "fix ruleset_dirs")
    rs = load_ruleset([rs_dir])
    status = "warn" if rs.errors else "ok"
    detail = f"{rs_dir}: {len(rs.rules)} rules, {len(rs.errors)} parse problem(s)"
    return Check(tenant.name, "ruleset", status, detail, "see 'hushwatch audit' for details" if rs.errors else "")


def _state_check(tenant: TenantConfig) -> Check:
    state_dir = tenant.resolved_state_dir()
    target = state_dir if state_dir.exists() else state_dir.parent
    if not target.exists():
        return Check(tenant.name, "state dir", "ok", f"{state_dir} will be created (mode 0700)")
    if not os.access(target, os.W_OK):
        return Check(tenant.name, "state dir", "fail", f"{target} is not writable", "set state_dir to a writable path")
    return Check(tenant.name, "state dir", "ok", str(state_dir))
