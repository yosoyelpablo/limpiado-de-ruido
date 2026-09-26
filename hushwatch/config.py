"""Configuration: one YAML file, ``defaults`` inherited by N ``tenants`` (MSSP-ready).

Secrets are never accepted on the command line. In YAML they are written as ``${ENV_VAR}`` references and
expanded at load time. A missing variable only blocks the tenant(s) that use it: :meth:`Config.tenant` raises an
error that names the variable (never a value), so one customer's unset secret never stops the others.

Relative paths in the file (``inputs[].path``, ``ruleset_dirs``, ``dispositions``, ``state_dir``, ``ca_cert``,
``agents_file``) are resolved against the directory of the config file, not the current directory, so a cron
job and an interactive shell see the same files.

The YAML is parsed with a safe loader that refuses aliases (``*name``): a few hundred bytes of nested aliases
expand to gigabytes. Errors quote the line and column, never the offending text (it may hold a secret).
"""

from __future__ import annotations

import difflib
import fnmatch
import functools
import ipaddress
import os
import re
import stat
import warnings
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, fields, is_dataclass
from datetime import date, timedelta
from pathlib import Path
from types import UnionType
from typing import Any, TypeVar, Union, get_args, get_origin, get_type_hints
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import yaml

from .timeutil import parse_duration

CONFIG_ENV = "HUSHWATCH_CONFIG"
DEFAULT_STATE_DIR = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state")) / "hushwatch"

_ENV_REF = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")

CRITICALITY_TIERS: tuple[str, ...] = ("critical", "standard", "low")
# canonical entity names accepted as trusted_entities keys (dotted source paths such as data.srcip are accepted too)
TRUSTED_ENTITY_NAMES: tuple[str, ...] = (
    "user",
    "src_ip",
    "srcip",
    "dst_ip",
    "dstip",
    "host",
    "agent",
    "process",
    "parent_process",
    "command_line",
    "file",
    "url",
    "domain",
)
# keys whose literal (non-${ENV}) string values are credentials
_SECRET_KEYS = frozenset({"password", "api_key", "token", "secret"})

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
    min_noisy_alerts: int = 50  # a rule is called "noisy" only with at least this many alerts...
    min_noisy_per_day: float = 5.0  # ...and this many per day
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
    agents_file: str | None = None  # JSON export of the Wazuh API ``GET /agents`` (agent inventory without the API)
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
    """A loaded configuration.

    ``missing_env`` maps a tenant to the ``(variable, where)`` pairs its settings reference but the environment
    does not define; :meth:`tenant` refuses such a tenant (the placeholders are never used as values).
    ``literal_secrets`` lists where the file holds credentials written literally instead of ``${ENV_VAR}``.
    """

    tenants: dict[str, TenantConfig]
    path: Path | None = None
    missing_env: dict[str, list[tuple[str, str]]] = field(default_factory=dict)
    literal_secrets: list[str] = field(default_factory=list)

    def tenant(self, name: str | None = None) -> TenantConfig:
        """The tenant ``name`` (the only one when ``name`` is None), ready to use."""
        if name is None:
            if len(self.tenants) == 1:
                name = next(iter(self.tenants))
            else:
                raise ConfigError(f"several tenants configured, choose one with --tenant: {', '.join(self.tenants)}")
        if name not in self.tenants:
            hint = _did_you_mean(name, list(self.tenants))
            raise ConfigError(f"unknown tenant {name!r}{hint}; configured: {', '.join(self.tenants)}")
        error = self.env_error(name)
        if error is not None:
            raise error
        return self.tenants[name]

    def select(self, name: str | None = None) -> list[str]:
        """Tenant names to process: ``[name]`` (validated) or every configured tenant."""
        if name is None:
            return list(self.tenants)
        if name not in self.tenants:
            hint = _did_you_mean(name, list(self.tenants))
            raise ConfigError(f"unknown tenant {name!r}{hint}; configured: {', '.join(self.tenants)}")
        return [name]

    def env_error(self, name: str) -> ConfigError | None:
        """The error for a tenant whose settings reference unset environment variables (None when usable)."""
        missing = self.missing_env.get(name)
        if not missing:
            return None
        variables = sorted({var for var, _ in missing})
        places = ", ".join(sorted({where for _, where in missing})[:5])
        return ConfigError(
            f"tenant {name}: environment variable(s) {', '.join(variables)} not set (used in {places}); "
            f"export them before running hushwatch"
        )


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

# where each path-like setting lives, for resolution against the config file's directory
_PATH_FIELDS: tuple[str, ...] = ("dispositions", "state_dir", "agents_file")


class _StrictLoader(yaml.SafeLoader):
    """``yaml.SafeLoader`` that refuses aliases: nested aliases ("billion laughs") expand exponentially."""

    def compose_node(self, parent: Any, index: Any) -> Any:
        if self.check_event(yaml.AliasEvent):
            event = self.peek_event()  # type: ignore[no-untyped-call]
            raise yaml.composer.ComposerError(None, None, _ALIAS_PROBLEM, event.start_mark)
        return super().compose_node(parent, index)


_ALIAS_PROBLEM = "YAML aliases (*name) are not supported; put shared settings under defaults"


class YamlError(ConfigError):
    """Unparseable YAML. ``detail`` names the position and the problem, never the offending text."""

    def __init__(self, source: str, detail: str) -> None:
        self.detail = detail
        super().__init__(f"invalid YAML in {source}: {detail}")


def safe_yaml_load(text: str, *, source: str = "config") -> Any:
    """Parse YAML text safely (no aliases, no Python tags). Errors name only the position, never the text."""
    try:
        return yaml.load(text, Loader=_StrictLoader)  # noqa: S506 - _StrictLoader is a SafeLoader subclass
    except yaml.YAMLError as exc:
        position = _yaml_position(exc)
        raise YamlError(source, f"{position}: {_yaml_problem(exc)}" if position else _yaml_problem(exc)) from None
    except (ValueError, TypeError, OverflowError, RecursionError) as exc:  # e.g. an impossible date 2026-13-40
        problem = _CONTROL.sub(" ", re.sub(r"'[^']*'|\"[^\"]*\"", "'…'", str(exc)))[:120]
        raise YamlError(source, f"{type(exc).__name__}: {problem}" if problem else type(exc).__name__) from None


def _yaml_position(exc: yaml.YAMLError) -> str:
    mark = getattr(exc, "problem_mark", None) or getattr(exc, "context_mark", None)
    line, column = getattr(mark, "line", None), getattr(mark, "column", None)
    if isinstance(line, int) and isinstance(column, int):
        return f"line {line + 1}, column {column + 1}"
    return ""


def _yaml_problem(exc: yaml.YAMLError) -> str:
    """PyYAML's problem description with any quoted text removed (it may quote part of a secret)."""
    problem = str(getattr(exc, "problem", None) or "syntax error")
    problem = re.sub(r"'[^']*'|\"[^\"]*\"|`[^`]*`", "'…'", problem)
    return _CONTROL.sub(" ", problem)[:160]


_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


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
        raise ConfigError(f"cannot read config {cfg_path}: {exc.strerror or type(exc).__name__}") from None
    except UnicodeDecodeError:
        raise ConfigError(f"cannot read config {cfg_path}: not UTF-8 text") from None
    raw = safe_yaml_load(text, source=str(cfg_path)) or {}
    if not isinstance(raw, dict):
        raise ConfigError(f"{cfg_path}: top level must be a mapping")
    cfg = parse_config(raw, env, cfg_path)
    _warn_if_exposed(cfg_path, cfg.literal_secrets)
    return cfg


def parse_config(raw: Mapping[str, Any], environ: Mapping[str, str], path: Path | None = None) -> Config:
    """Validate and build every tenant of a parsed config. Every structural problem is reported at once."""
    problems: list[str] = []
    for key in raw:
        if key not in ("defaults", "tenants"):
            problems.append(f"unknown top-level key {key!r}{_did_you_mean(str(key), ['defaults', 'tenants'])}")
    defaults = raw.get("defaults") or {}
    tenants_raw = raw.get("tenants") or {"default": {}}
    if not isinstance(defaults, Mapping) or not isinstance(tenants_raw, Mapping):
        raise ConfigError("'defaults' and 'tenants' must be mappings")
    _check_keys(TenantConfig, defaults, "defaults", problems)
    for name, body in tenants_raw.items():
        if body is not None and not isinstance(body, Mapping):
            problems.append(f"tenants.{name}: expected a mapping")
            continue
        _check_keys(TenantConfig, body or {}, f"tenants.{name}", problems)
    if problems:
        raise ConfigError(_join(problems))

    base = path.expanduser().absolute().parent if path is not None else None
    literal = _literal_secrets(raw)
    tenants: dict[str, TenantConfig] = {}
    missing_env: dict[str, list[tuple[str, str]]] = {}
    for name, body in tenants_raw.items():
        where = f"tenants.{name}"
        merged = _deep_merge(defaults, body or {})
        missing: list[tuple[str, str]] = []
        merged = _expand_env(merged, environ, where, missing)
        merged["name"] = str(name)
        local: list[str] = []
        tenant = _build(TenantConfig, merged, where, local)
        if tenant is not None and not local:
            _validate_tenant(tenant, local)
        problems.extend(_attribute(p, where, body or {}, defaults) for p in local)
        if tenant is None or local:
            continue
        if base is not None:
            _resolve_paths(tenant, base)
        tenants[str(name)] = tenant
        if missing:
            missing_env[str(name)] = missing
    if problems:
        raise ConfigError(_join(problems))
    return Config(tenants=tenants, path=path, missing_env=missing_env, literal_secrets=literal)


def _join(problems: Sequence[str]) -> str:
    unique = list(dict.fromkeys(problems))
    if len(unique) == 1:
        return unique[0]
    return f"{len(unique)} problems in the configuration:\n" + "\n".join(f"  - {p}" for p in unique)


def _did_you_mean(value: str, choices: Sequence[str]) -> str:
    close = difflib.get_close_matches(value, list(choices), n=1, cutoff=0.6)
    return f" (did you mean {close[0]!r}?)" if close else ""


def _attribute(problem: str, where: str, body: Mapping[str, Any], defaults: Mapping[str, Any]) -> str:
    """Rewrite ``tenants.x.a.b: ...`` as ``defaults.a.b: ...`` when the offending value came from ``defaults``."""
    if not problem.startswith(where + "."):
        return problem
    rest = problem[len(where) + 1 :]
    parts = re.split(r"[.\[:]", rest, maxsplit=2)
    first = parts[0]
    second = parts[1] if len(parts) > 1 else None
    in_body = first in body
    if (
        in_body
        and second is not None
        and isinstance(body.get(first), Mapping)
        and isinstance(defaults.get(first), Mapping)
    ):
        in_body = second in body[first] or second not in defaults[first]
    if not in_body and first in defaults:
        return "defaults." + rest
    return problem


def _check_keys(cls: type[Any], data: Any, where: str, problems: list[str]) -> None:
    """Report unknown keys (with a did-you-mean hint) in ``data`` and its nested settings, at their real path."""
    if not isinstance(data, Mapping):
        return
    hints = get_type_hints(cls)
    names = [f.name for f in fields(cls)]
    for key, value in data.items():
        if key not in names:
            problems.append(f"{where}: unknown key {key!r}{_did_you_mean(str(key), names)}")
            continue
        inner, is_list = _dataclass_of(hints[key])
        if inner is None:
            continue
        if is_list and isinstance(value, list):
            for i, item in enumerate(value):
                _check_keys(inner, item, f"{where}.{key}[{i}]", problems)
        elif not is_list:
            _check_keys(inner, value, f"{where}.{key}", problems)


def _dataclass_of(hint: Any) -> tuple[type[Any] | None, bool]:
    origin = get_origin(hint)
    args = [a for a in get_args(hint) if a is not type(None)]
    if origin in (Union, UnionType) and len(args) == 1:
        return _dataclass_of(args[0])
    if origin is list and args and isinstance(args[0], type) and is_dataclass(args[0]):
        return args[0], True
    if isinstance(hint, type) and is_dataclass(hint):
        return hint, False
    return None, False


def _validate_tenant(tenant: TenantConfig, problems: list[str]) -> None:
    where = f"tenants.{tenant.name}"
    for tier, default in DEFAULT_SLA.items():  # a partial `sla:` override keeps the other tiers' defaults
        tenant.sla.setdefault(tier, default)
    for tier in sorted(set(tenant.sla) - set(DEFAULT_SLA)):
        problems.append(f"{where}.sla: unknown sla tier {tier!r}{_did_you_mean(tier, CRITICALITY_TIERS)}")
    for tier in sorted(set(tenant.criticality) - set(CRITICALITY_TIERS)):
        problems.append(
            f"{where}.criticality: unknown tier {tier!r}{_did_you_mean(tier, CRITICALITY_TIERS)} "
            f"(tiers: {', '.join(CRITICALITY_TIERS)})"
        )
    for key in sorted(tenant.trusted_entities):
        if "." not in key and key not in TRUSTED_ENTITY_NAMES:
            warnings.warn(
                f"{where}.trusted_entities: {key!r} is not a known field{_did_you_mean(key, TRUSTED_ENTITY_NAMES)}; "
                f"use a canonical name ({', '.join(TRUSTED_ENTITY_NAMES[:6])}...) or a dotted source path such as "
                f"data.srcip; entries under it will never match",
                stacklevel=2,
            )
    try:
        ZoneInfo(tenant.timezone)
    except (ZoneInfoNotFoundError, ValueError):
        problems.append(f"{where}.timezone: unknown timezone {tenant.timezone!r} (use IANA names)")
    for net in tenant.internal_networks:
        try:
            ipaddress.ip_network(net, strict=False)
        except ValueError:
            problems.append(f"{where}.internal_networks: invalid network {net!r}")
    low, high = tenant.suppression_id_range
    if not (100000 <= low <= high <= 120000):
        problems.append(f"{where}.suppression_id_range: must be inside 100000-120000")
    for i, item in enumerate(tenant.inputs):
        at = f"{where}.inputs[{i}]"
        if item.type not in ("file", "indexer"):
            problems.append(f"{at}: input type must be file or indexer, got {item.type!r}")
        if item.type == "file" and not item.path:
            problems.append(f"{at}: file input needs 'path'")
        if item.type == "indexer" and not item.url:
            problems.append(f"{at}: indexer input needs 'url'")
        if item.url and item.url.startswith("http://") and (item.password or item.api_key):
            warnings.warn(f"{at}: credentials sent over plain http to {_origin(item.url)}", stacklevel=2)
    api = tenant.wazuh_api
    if api is not None and api.url.startswith("http://") and (api.password or api.username):
        warnings.warn(f"{where}.wazuh_api: credentials sent over plain http to {_origin(api.url)}", stacklevel=2)
    for i, n in enumerate(tenant.notify):
        at = f"{where}.notify[{i}]"
        if n.type not in ("webhook", "slack"):
            problems.append(f"{at}: notify type must be webhook or slack")
        if n.min_severity not in ("info", "low", "medium", "high", "critical"):
            problems.append(f"{at}: notify min_severity must be info|low|medium|high|critical")


def _origin(url: str) -> str:
    """``scheme://host[:port]`` of a URL (never its user info, path or query)."""
    match = re.match(r"(?i)^([a-z][a-z0-9+.-]*://)(?:[^@/?#]*@)?([^/?#]*)", url.strip())
    return (match.group(1) + match.group(2)) if match else "?"


def _resolve_paths(tenant: TenantConfig, base: Path) -> None:
    """Make relative paths absolute against ``base`` (the config file's directory)."""
    for name in _PATH_FIELDS:
        setattr(tenant, name, _resolve(getattr(tenant, name), base))
    tenant.ruleset_dirs = [_resolve(p, base) or p for p in tenant.ruleset_dirs]
    for item in tenant.inputs:
        item.path = _resolve(item.path, base)
        item.ca_cert = _resolve(item.ca_cert, base)
    if tenant.wazuh_api is not None:
        tenant.wazuh_api.ca_cert = _resolve(tenant.wazuh_api.ca_cert, base)


def _resolve(value: str | None, base: Path) -> str | None:
    if not value or "${" in value:  # unset environment variable: the tenant is unusable anyway
        return value
    expanded = os.path.expanduser(value)
    if os.path.isabs(expanded):
        return expanded
    return os.path.normpath(os.path.join(str(base), expanded))


def _deep_merge(base: Mapping[str, Any], override: Mapping[str, Any]) -> dict[str, Any]:
    out = dict(base)
    for key, value in override.items():
        if isinstance(value, Mapping) and isinstance(out.get(key), Mapping):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = value
    return out


def _expand_env(value: Any, environ: Mapping[str, str], where: str, missing: list[tuple[str, str]]) -> Any:
    """Expand ``${VAR}`` / ``${VAR:-default}``. An unset variable is recorded in ``missing`` (with its setting's
    path) and left as the literal ``${VAR}`` placeholder: the tenant is refused later, only if it is used."""
    if isinstance(value, str):

        def repl(match: re.Match[str]) -> str:
            var, default = match.group(1), match.group(2)
            if var in environ:
                return environ[var]
            if default is not None:
                return default
            missing.append((var, where))
            return match.group(0)

        return _ENV_REF.sub(repl, value)
    if isinstance(value, list):
        return [_expand_env(v, environ, f"{where}[{i}]", missing) for i, v in enumerate(value)]
    if isinstance(value, Mapping):
        return {k: _expand_env(v, environ, f"{where}.{k}", missing) for k, v in value.items()}
    return value


T = TypeVar("T")


def _build(cls: type[T], data: Any, where: str, problems: list[str]) -> T | None:
    """Build dataclass ``cls`` from ``data``; problems are appended (every field is checked) and None returned."""
    if not isinstance(data, Mapping):
        problems.append(f"{where}: expected a mapping")
        return None
    hints = get_type_hints(cls)
    names = [f.name for f in fields(cls)]  # type: ignore[arg-type]
    before = len(problems)
    kwargs: dict[str, Any] = {}
    for key, value in data.items():
        if key not in names:
            problems.append(f"{where}: unknown key {key!r}{_did_you_mean(str(key), names)}")
            continue
        try:
            kwargs[key] = _coerce(hints[key], value, f"{where}.{key}", problems)
        except _Reported:
            continue
        except ConfigError as exc:
            problems.append(str(exc))
    if len(problems) > before:
        return None
    try:
        return cls(**kwargs)
    except TypeError as exc:
        problems.append(f"{where}: {_missing_argument(exc)}")
        return None


def _missing_argument(exc: TypeError) -> str:
    match = re.search(r"missing \d+ required (?:positional |keyword-only )?arguments?: (.+)$", str(exc))
    if match:
        return "missing required key(s) " + match.group(1).replace("'", "")
    return "invalid settings"


def _coerce(hint: Any, value: Any, where: str, problems: list[str]) -> Any:
    origin = get_origin(hint)
    args: tuple[Any, ...] = tuple(get_args(hint))
    if value is None:
        return None
    if origin in (Union, UnionType):  # Optional[X] / X | None (UnionType has no __origin__: use get_origin)
        inner = [a for a in args if a is not type(None)]
        if len(inner) != 1:
            raise ConfigError(f"{where}: unsupported type")
        return _coerce(inner[0], value, where, problems)
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
            raise ConfigError(f"{where}: invalid date (YYYY-MM-DD)") from None
    if is_dataclass(hint):
        built = _build(hint, value, where, problems)  # type: ignore[arg-type]
        if built is None:
            raise _Reported()
        return built
    if origin is list:
        if not isinstance(value, list):
            raise ConfigError(f"{where}: expected a list")
        if not args:
            return list(value)
        out = []
        failed = False
        for i, v in enumerate(value):
            try:
                out.append(_coerce(args[0], v, f"{where}[{i}]", problems))
            except _Reported:
                failed = True
            except ConfigError as exc:
                problems.append(str(exc))
                failed = True
        if failed:
            raise _Reported()
        return out
    if origin is tuple:
        if not isinstance(value, (list, tuple)):
            raise ConfigError(f"{where}: expected a list")
        if len(args) == 2 and args[1] is Ellipsis:
            return tuple(_coerce(args[0], v, f"{where}[{i}]", problems) for i, v in enumerate(value))
        if len(value) != len(args):
            raise ConfigError(f"{where}: expected {len(args)} items")
        return tuple(_coerce(a, v, f"{where}[{i}]", problems) for i, (a, v) in enumerate(zip(args, value, strict=True)))
    if origin is dict:
        if not isinstance(value, Mapping):
            raise ConfigError(f"{where}: expected a mapping")
        return {str(k): _coerce(args[1], v, f"{where}.{k}", problems) if args else v for k, v in value.items()}
    if hint is bool:
        if not isinstance(value, bool):
            raise ConfigError(f"{where}: expected true/false")
        return value
    if hint in (int, float):
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ConfigError(f"{where}: expected a number")
        return hint(value)
    if hint is str:
        if isinstance(value, bool) or not isinstance(value, (str, int, float)):
            raise ConfigError(f"{where}: expected a string")
        return str(value)
    return value


class _Reported(ConfigError):
    """A nested problem already appended to the problem list (nothing more to add)."""

    def __init__(self) -> None:
        super().__init__("")


def _literal_secrets(raw: Mapping[str, Any]) -> list[str]:
    """Where the RAW (unexpanded) config holds literal credentials: secret keys, header values, and webhook URLs
    that carry a secret (Slack webhooks, tokens in the query or user info, long random path segments).

    Works on the parsed tree, so block style, flow mappings (``{password: x}``) and quoting all look the same; a
    value that references ``${VAR}`` is not literal."""
    found: list[str] = []

    def literal(value: Any) -> bool:
        return (
            isinstance(value, (str, int, float))
            and not isinstance(value, bool)
            and "${" not in str(value)
            and bool(str(value).strip())
        )

    def walk(node: Any, where: str, key: str | None, parent: Any) -> None:
        if isinstance(node, Mapping):
            for k, v in node.items():
                walk(v, f"{where}.{k}" if where else str(k), str(k), node)
        elif isinstance(node, list):
            for i, v in enumerate(node):
                walk(v, f"{where}[{i}]", key, parent)
        elif key is not None and literal(node):
            in_headers = where.rsplit(".", 2)[-2:-1] == ["headers"]
            if (
                key.lower() in _SECRET_KEYS
                or in_headers
                or (
                    key == "url"
                    and "notify[" in where
                    and isinstance(parent, Mapping)
                    and _secret_url(str(node), str(parent.get("type") or "webhook"))
                )
            ):
                found.append(where)

    walk(raw, "", None, None)
    return found


_TOKEN_SEGMENT = re.compile(r"[A-Za-z0-9_-]{20,}")


def _secret_url(url: str, kind: str) -> bool:
    """A webhook URL that is itself a credential: Slack incoming webhooks, or a token in it."""
    if kind == "slack" or "hooks.slack.com" in url:
        return True
    rest = url.split("://", 1)[-1]
    authority, _, path = rest.partition("/")
    return "@" in authority or "?" in url or any(_TOKEN_SEGMENT.fullmatch(seg) for seg in path.split("/"))


def _warn_if_exposed(path: Path, literal: Sequence[str]) -> None:
    """Warn when a config holding literal credentials is readable by group/others."""
    if not literal or os.name != "posix":  # (Windows ACLs are not mode bits)
        return
    try:
        mode = path.stat().st_mode
    except OSError:
        return
    if mode & (stat.S_IRGRP | stat.S_IROTH):
        shown = ", ".join(literal[:5]) + (f" (+{len(literal) - 5} more)" if len(literal) > 5 else "")
        warnings.warn(
            f"{path} contains literal credentials ({shown}) and is readable by other users; use ${{ENV_VAR}} "
            f"references or chmod 600",
            stacklevel=3,
        )
