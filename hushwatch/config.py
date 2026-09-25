"""Configuration: one YAML file, ``defaults`` inherited by N ``tenants`` (MSSP-ready).

Secrets are never accepted on the command line. In YAML they are written as ``${ENV_VAR}`` references and
expanded at load time; a missing variable is an error that names the variable, never its value.
"""

from __future__ import annotations

import fnmatch
import functools
import ipaddress
import os
import re
import stat
import warnings
from collections.abc import Mapping
from dataclasses import dataclass, field, fields, is_dataclass
from datetime import date, timedelta
from pathlib import Path
from typing import Any, TypeVar, get_type_hints
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import yaml

from .timeutil import parse_duration

CONFIG_ENV = "HUSHWATCH_CONFIG"
DEFAULT_STATE_DIR = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state")) / "hushwatch"

_ENV_REF = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")

# MITRE ATT&CK tactics (names and shortnames, v18/v19) where tuning needs explicit evidence (dispositions).
DEFAULT_SENSITIVE_TACTICS: tuple[str, ...] = (
    "credential access",
    "credential-access",
    "lateral movement",
    "lateral-movement",
    "command and control",
    "command-and-control",
    "exfiltration",
    "impact",
    "defense evasion",
    "defense-evasion",
    "stealth",
    "defense impairment",
    "defense-impairment",
    "privilege escalation",
    "privilege-escalation",
    "persistence",
)


DEFAULT_SLA: dict[str, timedelta] = {
    "critical": timedelta(hours=4),
    "standard": timedelta(hours=24),
    "low": timedelta(hours=72),
}


class ConfigError(ValueError):
    """Invalid or incomplete configuration (maps to exit code 2)."""


@dataclass(slots=True)
class NoiseSettings:
    min_history_days: int = 7  # below this: LEARNING, no tuning verdicts
    min_share: float = 0.2  # a candidate condition must explain >= this share of its rule's volume
    persistence: float = 0.8  # candidate present on >= this fraction of days
    novelty_fraction: float = 0.25  # candidate must be first seen within this leading fraction of the window
    burst_factor: float = 5.0  # a day >= factor x median daily volume => BURST (investigate, never tune)
    cluster_gap: timedelta = timedelta(minutes=15)  # session gap for dedup clusters
    co_occurrence_window: timedelta = timedelta(hours=24)
    minutes_per_alert: tuple[float, float] = (1.0, 5.0)  # range for the (upper-bound) time estimate
    min_dispositions: int = 10  # before an FP-rate lower bound is used
    disposition_confidence: float = 0.95
    top_rules: int = 25
    max_candidates_per_rule: int = 5
    heavy_hitters: int = 64  # Space-Saving capacity per (rule, field)
    sensitive_tactics: tuple[str, ...] = DEFAULT_SENSITIVE_TACTICS
    allow_rule_wide: bool = False  # never propose muting a whole rule unless explicitly allowed
    # usernames treated as service accounts (may anchor a scoped suggestion); fnmatch globs, case-insensitive
    # (machine accounts "HOST$" are deliberately NOT here: in failed logons they are attacker-chosen)
    service_account_patterns: tuple[str, ...] = ("svc_*", "svc-*", "svc.*", "service_*", "sa_*", "*_svc")


@dataclass(slots=True)
class SilenceSettings:
    baseline: timedelta = timedelta(days=14)
    window: timedelta = timedelta(hours=24)  # DROP evaluation window
    ingest_lag: timedelta = timedelta(minutes=15)  # the most recent slice is excluded (late data)
    alarm_budget: float = 0.05  # expected false SILENT/DROP findings per run, across all keys
    drop_ratio: float = 0.3  # observed/expected must be below this (effect size) for DROP
    min_history_days: int = 7
    global_fraction: float = 0.3  # >= this share of ALWAYS-ON sources silent together => one PIPELINE finding
    heartbeat_rule_days: float = 0.9  # a rule firing on >= 90% of days is a heartbeat (can "go dark")
    field_presence_before: float = 0.95
    field_presence_after: float = 0.05
    field_min_events: int = 100
    peer_coverage: float = 0.9  # flag hosts missing a log source >= this share of their peers send
    max_keys: int = 50_000


@dataclass(slots=True)
class InputConfig:
    type: str = "file"  # file | indexer
    path: str | None = None  # file/dir/glob (type=file)
    profile: str = "auto"  # auto | wazuh4 | wazuh5 | ecs | generic
    url: str | None = None  # indexer base URL (type=indexer)
    index: str = "wazuh-alerts-*"
    time_field: str = "timestamp"
    username: str | None = None
    password: str | None = field(default=None, repr=False)
    api_key: str | None = field(default=None, repr=False)
    ca_cert: str | None = None
    verify_tls: bool = True
    timeout: float = 60.0
    max_events: int | None = None  # cap for raw document streaming (noise); reported as truncation
    naive_timezone: str | None = None  # timezone of timestamps that carry no offset
    mapping: dict[str, str] = field(default_factory=dict)  # generic profile: our field -> source dotted path


@dataclass(slots=True)
class ApiConfig:
    url: str
    username: str | None = None
    password: str | None = field(default=None, repr=False)
    ca_cert: str | None = None
    verify_tls: bool = True
    timeout: float = 30.0
    max_requests_per_minute: int = 240


@dataclass(slots=True)
class NotifyConfig:
    type: str = "webhook"  # webhook | slack
    url: str = field(default="", repr=False)  # webhook URLs are secrets (Slack)
    include_entities: bool = False  # webhooks carry counts and ids, not usernames/IPs, unless opted in
    min_severity: str = "medium"
    headers: dict[str, str] = field(default_factory=dict, repr=False)


@dataclass(slots=True)
class Expectation:
    """Telemetry contract: hosts matching ``match`` must send ``log_sources``."""

    name: str
    log_sources: list[str]
    match: dict[str, Any] = field(default_factory=dict)  # platform, groups, name (glob)
    min_events_per_day: int = 1


@dataclass(slots=True)
class CalendarEntry:
    start: date
    end: date  # inclusive
    reason: str = ""


@dataclass(slots=True)
class TenantConfig:
    name: str = "default"
    timezone: str = "UTC"
    triage_level: int = 7  # alerts at/above this level reach analysts
    high_level: int = 10  # "high" alerts (co-occurrence checks, never-tune threshold)
    max_tunable_level: int = 9  # rules above this level are never proposed for tuning
    internal_networks: list[str] = field(
        default_factory=lambda: [
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "127.0.0.0/8",
            "fc00::/7",
            "fe80::/10",
            "::1/128",
        ]
    )
    trusted_entities: dict[str, list[str]] = field(default_factory=dict)  # field -> known-benign values
    criticality: dict[str, list[str]] = field(default_factory=dict)  # tier -> agent name globs
    sla: dict[str, timedelta] = field(default_factory=lambda: dict(DEFAULT_SLA))
    expectations: list[Expectation] = field(default_factory=list)
    calendar: list[CalendarEntry] = field(default_factory=list)
    inputs: list[InputConfig] = field(default_factory=list)
    wazuh_api: ApiConfig | None = None
    ruleset_dirs: list[str] = field(default_factory=list)
    suppression_id_range: tuple[int, int] = (100100, 119999)
    dispositions: str | None = None
    notify: list[NotifyConfig] = field(default_factory=list)
    state_dir: str | None = None
    noise: NoiseSettings = field(default_factory=NoiseSettings)
    silence: SilenceSettings = field(default_factory=SilenceSettings)

    # ---- helpers -----------------------------------------------------------------------------------------
    @property
    def tz(self) -> ZoneInfo:
        return ZoneInfo(self.timezone)

    def tier_for(self, agent: str | None) -> str:
        if agent:
            lowered = agent.lower()
            for tier in ("critical", "low"):
                for pattern in self.criticality.get(tier, []):
                    if fnmatch.fnmatch(lowered, pattern.lower()):
                        return tier
        return "standard"

    def is_internal(self, ip: str | None) -> bool:
        if not ip:
            return False
        try:
            address = ipaddress.ip_address(ip.strip().split("%", 1)[0])  # drop IPv6 zone ids (fe80::1%eth0)
        except ValueError:
            return False
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
            address = address.ipv4_mapped  # ::ffff:10.0.0.5 (Windows Kerberos events) is 10.0.0.5
        return any(address in network for network in _networks(tuple(self.internal_networks)))

    def is_trusted(self, field_name: str, value: str | None) -> bool:
        """True when ``value`` is a configured known-benign entity for ``field_name``.

        ``trusted_entities`` keys may be canonical names (``user``, ``src_ip``, ``host``) or source paths
        (``data.srcip``, ``data.win.eventdata.subjectUserName``, ``agent.name``...); both spellings match.
        """
        if value is None:
            return False
        lowered = value.lower()
        for key in _trust_aliases(field_name):
            for pattern in self.trusted_entities.get(key, []):
                if fnmatch.fnmatchcase(lowered, pattern.lower()):
                    return True
        return False

    def sla_for(self, tier: str) -> timedelta:
        return self.sla.get(tier) or DEFAULT_SLA.get(tier, DEFAULT_SLA["standard"])

    def in_calendar(self, day: date) -> bool:
        return any(entry.start <= day <= entry.end for entry in self.calendar)

    def resolved_state_dir(self) -> Path:
        return Path(self.state_dir).expanduser() if self.state_dir else DEFAULT_STATE_DIR


@dataclass(slots=True)
class Config:
    tenants: dict[str, TenantConfig]
    path: Path | None = None

    def tenant(self, name: str | None = None) -> TenantConfig:
        if name is None:
            if len(self.tenants) == 1:
                return next(iter(self.tenants.values()))
            raise ConfigError(f"several tenants configured, choose one with --tenant: {', '.join(self.tenants)}")
        try:
            return self.tenants[name]
        except KeyError:
            raise ConfigError(f"unknown tenant {name!r}; configured: {', '.join(self.tenants)}") from None


_TRUST_GROUPS: tuple[frozenset[str], ...] = (
    frozenset(
        {
            "user",
            "data.srcuser",
            "data.dstuser",
            "data.win.eventdata.subjectUserName",
            "data.win.eventdata.targetUserName",
            "user.name",
            "source.user.name",
        }
    ),
    frozenset({"src_ip", "srcip", "data.srcip", "source.ip", "client.ip"}),
    frozenset({"dst_ip", "dstip", "data.dstip", "destination.ip"}),
    frozenset({"host", "agent", "agent.name", "host.name", "predecoder.hostname"}),
    frozenset({"process", "data.win.eventdata.image", "process.executable"}),
)


@functools.lru_cache(maxsize=256)
def _trust_aliases(field_name: str) -> tuple[str, ...]:
    for group in _TRUST_GROUPS:
        if field_name in group:
            return (field_name, *sorted(group - {field_name}))
    return (field_name,)


@functools.lru_cache(maxsize=64)
def _networks(nets: tuple[str, ...]) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    return tuple(ipaddress.ip_network(n, strict=False) for n in nets)


# ---- loading -------------------------------------------------------------------------------------------------


def load_config(path: str | Path | None = None, *, environ: Mapping[str, str] | None = None) -> Config:
    """Load ``path`` (or ``$HUSHWATCH_CONFIG``). Returns a single ``default`` tenant when no file is given."""
    env = os.environ if environ is None else environ
    if path is None:
        path = env.get(CONFIG_ENV)
    if path is None:
        return Config(tenants={"default": TenantConfig()})
    cfg_path = Path(path).expanduser()
    try:
        text = cfg_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"cannot read config {cfg_path}: {exc.strerror}") from None
    _warn_if_exposed(cfg_path, text)
    try:
        raw = yaml.safe_load(text) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid YAML in {cfg_path}: {exc}") from None
    if not isinstance(raw, dict):
        raise ConfigError(f"{cfg_path}: top level must be a mapping")
    return parse_config(raw, env, cfg_path)


def parse_config(raw: Mapping[str, Any], environ: Mapping[str, str], path: Path | None = None) -> Config:
    unknown = set(raw) - {"defaults", "tenants"}
    if unknown:
        raise ConfigError(f"unknown top-level keys: {', '.join(sorted(unknown))} (expected defaults, tenants)")
    defaults = raw.get("defaults") or {}
    tenants_raw = raw.get("tenants") or {"default": {}}
    if not isinstance(defaults, dict) or not isinstance(tenants_raw, dict):
        raise ConfigError("'defaults' and 'tenants' must be mappings")
    tenants: dict[str, TenantConfig] = {}
    for name, body in tenants_raw.items():
        merged = _deep_merge(defaults, body or {})
        merged = _expand_env(merged, environ, f"tenants.{name}")
        merged["name"] = str(name)
        tenants[str(name)] = _build(TenantConfig, merged, f"tenants.{name}")
        _validate_tenant(tenants[str(name)])
    return Config(tenants=tenants, path=path)


def _validate_tenant(tenant: TenantConfig) -> None:
    for tier, default in DEFAULT_SLA.items():  # a partial `sla:` override keeps the other tiers' defaults
        tenant.sla.setdefault(tier, default)
    unknown_tiers = set(tenant.sla) - set(DEFAULT_SLA)
    if unknown_tiers:
        raise ConfigError(f"tenant {tenant.name}: unknown sla tier(s) {', '.join(sorted(unknown_tiers))}")
    try:
        ZoneInfo(tenant.timezone)
    except (ZoneInfoNotFoundError, ValueError):
        raise ConfigError(f"tenant {tenant.name}: unknown timezone {tenant.timezone!r} (use IANA names)") from None
    for net in tenant.internal_networks:
        try:
            ipaddress.ip_network(net, strict=False)
        except ValueError:
            raise ConfigError(f"tenant {tenant.name}: invalid network {net!r}") from None
    low, high = tenant.suppression_id_range
    if not (100000 <= low <= high <= 120000):
        raise ConfigError(f"tenant {tenant.name}: suppression_id_range must be inside 100000-120000")
    for item in tenant.inputs:
        if item.type not in ("file", "indexer"):
            raise ConfigError(f"tenant {tenant.name}: input type must be file or indexer, got {item.type!r}")
        if item.type == "file" and not item.path:
            raise ConfigError(f"tenant {tenant.name}: file input needs 'path'")
        if item.type == "indexer" and not item.url:
            raise ConfigError(f"tenant {tenant.name}: indexer input needs 'url'")
        if item.url and item.url.startswith("http://") and (item.password or item.api_key):
            warnings.warn(f"tenant {tenant.name}: credentials sent over plain http to {item.url}", stacklevel=2)
    for n in tenant.notify:
        if n.type not in ("webhook", "slack"):
            raise ConfigError(f"tenant {tenant.name}: notify type must be webhook or slack")
        if n.min_severity not in ("info", "low", "medium", "high", "critical"):
            raise ConfigError(f"tenant {tenant.name}: notify min_severity must be info|low|medium|high|critical")


def _deep_merge(base: Mapping[str, Any], override: Mapping[str, Any]) -> dict[str, Any]:
    out = dict(base)
    for key, value in override.items():
        if isinstance(value, Mapping) and isinstance(out.get(key), Mapping):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = value
    return out


def _expand_env(value: Any, environ: Mapping[str, str], where: str) -> Any:
    if isinstance(value, str):

        def repl(match: re.Match[str]) -> str:
            var, default = match.group(1), match.group(2)
            if var in environ:
                return environ[var]
            if default is not None:
                return default
            raise ConfigError(f"{where}: environment variable {var} is not set")

        return _ENV_REF.sub(repl, value)
    if isinstance(value, list):
        return [_expand_env(v, environ, where) for v in value]
    if isinstance(value, Mapping):
        return {k: _expand_env(v, environ, f"{where}.{k}") for k, v in value.items()}
    return value


T = TypeVar("T")


def _build(cls: type[T], data: Any, where: str) -> T:
    if not isinstance(data, Mapping):
        raise ConfigError(f"{where}: expected a mapping")
    hints = get_type_hints(cls)
    names = {f.name for f in fields(cls)}  # type: ignore[arg-type]
    unknown = set(data) - names
    if unknown:
        raise ConfigError(f"{where}: unknown keys {', '.join(sorted(map(str, unknown)))}")
    kwargs = {key: _coerce(hints[key], value, f"{where}.{key}") for key, value in data.items()}
    try:
        return cls(**kwargs)
    except TypeError as exc:
        raise ConfigError(f"{where}: {exc}") from None


def _coerce(hint: Any, value: Any, where: str) -> Any:
    origin = getattr(hint, "__origin__", None)
    args: tuple[Any, ...] = tuple(getattr(hint, "__args__", ()))
    if value is None:
        return None
    if hint is timedelta:
        try:
            return parse_duration(value)
        except ValueError as exc:
            raise ConfigError(f"{where}: {exc}") from None
    if hint is date:
        if isinstance(value, date):
            return value
        try:
            return date.fromisoformat(str(value))
        except ValueError:
            raise ConfigError(f"{where}: invalid date {value!r} (YYYY-MM-DD)") from None
    if is_dataclass(hint):
        return _build(hint, value, where)  # type: ignore[arg-type]
    if origin is list:
        if not isinstance(value, list):
            raise ConfigError(f"{where}: expected a list")
        return [_coerce(args[0], v, f"{where}[{i}]") for i, v in enumerate(value)] if args else list(value)
    if origin is tuple:
        if not isinstance(value, (list, tuple)):
            raise ConfigError(f"{where}: expected a list")
        if len(args) == 2 and args[1] is Ellipsis:
            return tuple(_coerce(args[0], v, where) for v in value)
        if len(value) != len(args):
            raise ConfigError(f"{where}: expected {len(args)} items")
        return tuple(_coerce(a, v, where) for a, v in zip(args, value, strict=True))
    if origin is dict:
        if not isinstance(value, Mapping):
            raise ConfigError(f"{where}: expected a mapping")
        return {str(k): _coerce(args[1], v, f"{where}.{k}") if args else v for k, v in value.items()}
    if origin is not None and type(None) in args:  # Optional[X] / X | None
        inner = [a for a in args if a is not type(None)]
        return _coerce(inner[0], value, where) if len(inner) == 1 else value
    if hint is bool:
        if not isinstance(value, bool):
            raise ConfigError(f"{where}: expected true/false")
        return value
    if hint in (int, float):
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ConfigError(f"{where}: expected a number")
        return hint(value)
    if hint is str:
        return str(value)
    return value


def _warn_if_exposed(path: Path, text: str) -> None:
    """Warn when a config holding literal secrets is readable by group/others."""
    try:
        mode = path.stat().st_mode
    except OSError:
        return
    literal_secret = re.search(r"(?im)^\s*(password|api_key)\s*:\s*(?!\$\{)\S+", text)
    if literal_secret and mode & (stat.S_IRGRP | stat.S_IROTH):
        warnings.warn(
            f"{path} contains literal credentials and is readable by other users; use ${{ENV_VAR}} "
            f"references or chmod 600",
            stacklevel=3,
        )
