"""Anchor fields and the hard safety gates of the noise engine (architecture §5.2, §5.4).

A tuning candidate is a rule plus one to three exact-match conditions on ORIGINAL dotted field paths. Only a
value that identifies a HOST can stand alone; everything else narrows a host scope. Which fields may carry a
condition, and how, depends on the field's *role*:

======================  =====================================================================================
role                    rule
======================  =====================================================================================
``host``                the event's host (agent name, or the syslog hostname for agent ``000``; the manager's
                        own name is never a scope): stable anchor
``source``              log-source type (log file, decoder, provider, dataset). Constant for most rules, so a
                        condition on it alone would mute the rule everywhere: only paired with a host. A
                        ``location`` that names the sending device (syslog sender address, ``host->path``) is a
                        host-like anchor with every host safeguard (exposure share, co-occurrence, new hosts)
``ip``                  the event's source IP: stable anchor when internal (``tenant.is_internal``); a public
                        IP is attacker-controlled (only paired with a host) and routes to "restrict exposure"
``peer_ip``             other IPs (destination, logon source): only paired with a host
``user``                only paired with a host (a scope on an account follows its credentials everywhere);
                        trusted when configured or a service account by name, never a machine account (``X$``,
                        creatable by any domain user). Usernames in FAILED logons are attacker-chosen. A target
                        account is pinned together with its logon type (``companion``)
``process``             full image paths only paired with a host; interpreters, living-off-the-land binaries
                        and generic parents (:data:`GENERIC_PROCESS_PATTERNS`) never; bare names are
                        attacker-controlled
``file``                FIM paths (``syscheck.path``): anchor, verdict ``fix_at_source``
``attacker``            command lines, URLs, user agents, file names, DNS names: only paired with a host
``context``             companion fields (``logonType``): only pinned next to the field they qualify
======================  =====================================================================================

Process-creation rules (Sysmon 1, Security 4688, auditd execve; :data:`PROCESS_GROUPS`) are as sensitive as a
sensitive ATT&CK tactic: they need a trusted internal anchor plus FP dispositions.

Anchor field paths per profile (:data:`ANCHOR_FIELDS`):

* ``wazuh4`` — ``agent.name``, ``predecoder.hostname`` (host); ``location`` (skipping static component
  locations such as ``EventChannel``), ``decoder.name``, ``data.win.system.providerName`` (source);
  ``data.srcip`` (ip); ``data.dstip``, ``data.src_ip``, ``data.dest_ip``, ``data.win.eventdata.ipAddress``,
  ``…sourceIp``, ``…destinationIp`` (peer_ip); ``data.srcuser``, ``data.dstuser``,
  ``data.win.eventdata.subjectUserName``, ``…targetUserName`` (user, with ``…logonType`` as companion);
  ``data.win.eventdata.image``, ``…parentImage``, ``…newProcessName``, ``…parentProcessName`` (process);
  ``syscheck.path`` (file); ``…commandLine``, ``…parentCommandLine``, ``data.url``, ``…targetFilename``,
  ``…queryName`` (attacker).
* ``ecs`` (also used for ``wazuh5``) — ``host.name``; ``event.dataset``; ``source.ip``; ``destination.ip``;
  ``user.name``; ``process.executable``, ``process.parent.executable``; ``file.path`` (anchor only in FIM
  events); ``process.command_line``, ``url.original``, ``url.full``, ``user_agent.original``, ``file.name``,
  ``dns.question.name``.
* ``generic`` — derived from ``InputConfig.mapping`` (our field name → source path).

The gates themselves are pure functions over :class:`CandidateFacts` so they can be tested in isolation.
Low severity and regularity are NEVER used as evidence of benignity; regularity towards a public address is
evidence of beaconing.
"""

from __future__ import annotations

import bisect
import fnmatch
import functools
import ipaddress
import re
import socket
import statistics
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import date, datetime, timezone, tzinfo
from typing import Any

from ..config import NoiseSettings, TenantConfig
from ..i18n import Entity, M, Message, register
from ..models import get_path, is_empty
from .dispositions import DispositionCounts
from .sketches import SpaceSavingEntry, hash64

# ---- roles ------------------------------------------------------------------------------------------------------
ROLE_HOST = "host"
ROLE_SOURCE = "source"
ROLE_IP = "ip"
ROLE_PEER_IP = "peer_ip"
ROLE_USER = "user"
ROLE_PROCESS = "process"
ROLE_FILE = "file"
ROLE_ATTACKER = "attacker"
ROLE_CONTEXT = "context"  # pinned together with another condition (e.g. the logon type of a logon), never alone

IP_ROLES = frozenset({ROLE_IP, ROLE_PEER_IP})

# ---- tunables that are not (yet) in NoiseSettings ----------------------------------------------------------------
MAX_VALUE_LEN = 1024  # longer values are never condition candidates (and are not sketched)
MAX_LIST_VALUES = 8  # distinct scalar values taken from a list-valued field
MIN_CANDIDATE_EVENTS = 10  # a condition set must (at least) cover this many alerts to be worth tuning
NARROW_RATIO = 0.8  # replace a host-wide condition by narrower host+X conditions covering >= this share of it
FP_EVIDENCE_MIN = 0.8  # Wilson lower bound of the FP rate needed to tune a sensitive-tactic rule
AGGREGATE_DUP_RATIO = 0.9  # duplicate ratio (1 - clusters/alerts) from which aggregation is suggested
BEACON_MIN_ACTIVE_HOURS = 12  # a beacon-like address is active in at least this many distinct hours...
BEACON_MIN_COVERAGE = 0.75  # ...covering at least this share of the hours between its first and last hour,
BEACON_MIN_RUN_HOURS = 4.0  # ...or in unbroken runs of this many consecutive hours on average (a beacon that only
# runs while a laptop is on, or during business hours, is still regular: 10 consecutive hours every day)
PERIODIC_MIN_SHARE = 0.6  # regularity (share of gaps within ~±10% of the usual gap) that makes activity periodic
MIN_NOISY_ALERTS = 50  # a rule is called "noisy" only from this many alerts in the window...
MIN_NOISY_PER_DAY = 5.0  # ...and this many per day (NoiseSettings.min_noisy_alerts / min_noisy_per_day override)
TP_LOOKBACK_DAYS = 90
EXPOSURE_SHARE = 0.5  # a host-wide scope whose alerts mostly come from public addresses is exposure, not noise
DEFAULT_SERVICE_ACCOUNT_PATTERNS: tuple[str, ...] = (
    "svc_*",
    "svc-*",
    "svc.*",
    "svc[0-9]*",
    "service_*",
    "service-*",
    "service.*",
)

# Wazuh static component locations: identical for every event of their kind, never a useful scope.
STATIC_LOCATIONS = frozenset(
    {
        "EventChannel",
        "WinEvtLog",
        "syscheck",
        "rootcheck",
        "sca",
        "syscollector",
        "vulnerability-detector",
        "osquery",
        "aws-s3",
        "ciscat",
        "wazuh-modulesd",
        "journald",
        "macos",
    }
)

FAILURE_GROUPS = frozenset(
    {
        "authentication_failed",
        "authentication_failures",
        "invalid_login",
        "win_authentication_failed",
        "login_denied",
    }
)
FIM_GROUPS = frozenset({"syscheck", "syscheck_file", "syscheck_entry_modified", "syscheck_entry_added", "fim"})
CHECK_GROUPS = frozenset({"rootcheck", "sca"})
# Process-creation rules (Sysmon event 1, Security 4688, auditd execve). Execution is where attacks happen; a
# scope on these rules needs the same evidence as a sensitive ATT&CK tactic (trusted anchor + FP dispositions).
PROCESS_GROUPS = frozenset(
    {
        "sysmon_event1",
        "sysmon_event_1",
        "sysmon_eid1_detections",
        "sysmon_process_creation",
        "sysmon_process-create",
        "process_creation",
        "windows_process_creation",
        "audit_command",
    }
)

# Interpreters, living-off-the-land binaries and generic parent processes (basenames, lowercase fnmatch globs).
# Their image path says nothing about WHO runs them or WHY: PowerShell started by a Word macro and PowerShell
# started by a scheduled task share the same image, and svchost / explorer are the parents of most services,
# scheduled tasks and user-launched programs. Such a value is never a condition, alone or paired with a host.
GENERIC_PROCESS_PATTERNS: tuple[str, ...] = (
    "powershell.exe",
    "powershell_ise.exe",
    "pwsh.exe",
    "pwsh",
    "cmd.exe",
    "command.com",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "certutil.exe",
    "bitsadmin.exe",
    "msiexec.exe",
    "msbuild.exe",
    "installutil.exe",
    "regasm.exe",
    "regsvcs.exe",
    "cmstp.exe",
    "odbcconf.exe",
    "mavinject.exe",
    "msdt.exe",
    "hh.exe",
    "forfiles.exe",
    "pcalua.exe",
    "control.exe",
    "wmic.exe",
    "wmiprvse.exe",
    "wsmprovhost.exe",
    "winrshost.exe",
    "schtasks.exe",
    "at.exe",
    "sc.exe",
    "net.exe",
    "net1.exe",
    "reg.exe",
    "curl.exe",
    "wget.exe",
    "ftp.exe",
    "bash.exe",
    "wsl.exe",
    "svchost.exe",
    "services.exe",
    "explorer.exe",
    "taskeng.exe",
    "taskhost.exe",
    "taskhostw.exe",
    "dllhost.exe",
    "conhost.exe",
    "runtimebroker.exe",
    "userinit.exe",
    "winlogon.exe",
    "mmc.exe",
    "python*",
    "py.exe",
    "pyw.exe",
    "perl*",
    "ruby*",
    "php*",
    "node",
    "node.exe",
    "java",
    "java.exe",
    "javaw.exe",
    "osascript",
    "sh",
    "bash",
    "dash",
    "zsh",
    "ksh",
    "csh",
    "tcsh",
    "fish",
    "busybox",
    "env",
    "sudo",
    "su",
    "nohup",
    "xargs",
    "cron",
    "crond",
    "systemd",
    "init",
    "sshd",
    "curl",
    "wget",
    "nc",
    "ncat",
    "netcat",
    "socat",
    "awk",
    "gawk",
    "openssl",
)
_GENERIC_EXACT = frozenset(p for p in GENERIC_PROCESS_PATTERNS if not any(ch in p for ch in "*?["))
_GENERIC_GLOBS = tuple(p for p in GENERIC_PROCESS_PATTERNS if any(ch in p for ch in "*?["))
_SYSMON_PROVIDERS = frozenset({"microsoft-windows-sysmon", "sysmon"})
_SYSMON_CHANNEL = "microsoft-windows-sysmon/operational"

# Principals and addresses too generic to link two alerts (co-occurrence would taint everything).
_GENERIC_USERS = frozenset(
    {
        "-",
        "system",
        "nt authority\\system",
        "nt authority\\\\system",
        "local service",
        "network service",
        "localsystem",
        "anonymous logon",
        "anonymous",
        "n/a",
        "unknown",
    }
)
_GENERIC_IPS = frozenset({"127.0.0.1", "::1", "0.0.0.0", "::", "-", "localhost"})  # noqa: S104 (values, not a bind)

_FULL_PATH = re.compile(r"^(?:[A-Za-z]:[\\/]|\\\\|/)")
_VOLATILE = re.compile(
    r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}|0x[0-9A-Fa-f]+|[0-9A-Fa-f]{12,}|\d{3,}"
)
_FREE_TEXT_CHARS = 2048


@dataclass(frozen=True, slots=True)
class AnchorField:
    """One field the noise engine sketches."""

    path: str
    role: str
    entity: str | None  # i18n Entity kind for values of this field (None: not an entity, e.g. decoder names)
    direction: str = ""  # "src" | "dst" for IP fields (co-occurrence looks at actors, not targets)
    hours: bool = False  # keep an active-hours bitset (beacon detection)
    free_text: bool = False  # normalize volatile tokens before fingerprinting
    failure_sensitive: bool = False  # attacker-chosen in failed logons
    companion: str | None = None  # context field pinned with this one whenever the event carries it


def _f(path: str, role: str, entity: str | None, **kw: Any) -> AnchorField:
    return AnchorField(path, role, entity, **kw)


_WAZUH4_FIELDS: tuple[AnchorField, ...] = (
    _f("agent.name", ROLE_HOST, "host"),
    _f("predecoder.hostname", ROLE_HOST, "host"),
    _f("location", ROLE_SOURCE, None),
    _f("decoder.name", ROLE_SOURCE, None),
    _f("data.win.system.providerName", ROLE_SOURCE, None),
    _f("data.srcip", ROLE_IP, "ip", direction="src", hours=True),
    _f("data.dstip", ROLE_PEER_IP, "ip", direction="dst", hours=True),
    _f("data.src_ip", ROLE_PEER_IP, "ip", direction="src", hours=True),
    _f("data.dest_ip", ROLE_PEER_IP, "ip", direction="dst", hours=True),
    _f("data.win.eventdata.ipAddress", ROLE_PEER_IP, "ip", direction="src", hours=True),
    _f("data.win.eventdata.sourceIp", ROLE_PEER_IP, "ip", direction="src", hours=True),
    _f("data.win.eventdata.destinationIp", ROLE_PEER_IP, "ip", direction="dst", hours=True),
    _f("data.srcuser", ROLE_USER, "user", failure_sensitive=True),
    _f("data.dstuser", ROLE_USER, "user", failure_sensitive=True),
    _f("data.win.eventdata.subjectUserName", ROLE_USER, "user"),
    # a logon scope pins the logon type: svc_backup's nightly batch logons (type 4) must not hide an RDP (type 10)
    # or network (type 3) logon with the same, possibly stolen, credentials
    _f(
        "data.win.eventdata.targetUserName",
        ROLE_USER,
        "user",
        failure_sensitive=True,
        companion="data.win.eventdata.logonType",
    ),
    _f("data.win.eventdata.image", ROLE_PROCESS, "file"),
    _f("data.win.eventdata.parentImage", ROLE_PROCESS, "file"),
    _f("data.win.eventdata.newProcessName", ROLE_PROCESS, "file"),  # Security 4688
    _f("data.win.eventdata.parentProcessName", ROLE_PROCESS, "file"),
    _f("syscheck.path", ROLE_FILE, "file"),
    _f("data.win.eventdata.commandLine", ROLE_ATTACKER, "cmd", free_text=True),
    _f("data.win.eventdata.parentCommandLine", ROLE_ATTACKER, "cmd", free_text=True),
    _f("data.url", ROLE_ATTACKER, "url", free_text=True),
    _f("data.win.eventdata.targetFilename", ROLE_ATTACKER, "file", free_text=True),
    _f("data.win.eventdata.queryName", ROLE_ATTACKER, "domain"),
)

_ECS_FIELDS: tuple[AnchorField, ...] = (
    _f("host.name", ROLE_HOST, "host"),
    _f("agent.name", ROLE_HOST, "host"),
    _f("event.dataset", ROLE_SOURCE, None),
    _f("source.ip", ROLE_IP, "ip", direction="src", hours=True),
    _f("destination.ip", ROLE_PEER_IP, "ip", direction="dst", hours=True),
    _f("user.name", ROLE_USER, "user", failure_sensitive=True),
    _f("process.executable", ROLE_PROCESS, "file"),
    _f("process.parent.executable", ROLE_PROCESS, "file"),
    _f("file.path", ROLE_FILE, "file"),
    _f("process.command_line", ROLE_ATTACKER, "cmd", free_text=True),
    _f("url.original", ROLE_ATTACKER, "url", free_text=True),
    _f("url.full", ROLE_ATTACKER, "url", free_text=True),
    _f("user_agent.original", ROLE_ATTACKER, "val", free_text=True),
    _f("file.name", ROLE_ATTACKER, "file"),
    _f("dns.question.name", ROLE_ATTACKER, "domain"),
)

ANCHOR_FIELDS: dict[str, tuple[AnchorField, ...]] = {
    "wazuh4": _WAZUH4_FIELDS,
    "ecs": _ECS_FIELDS,
    "wazuh5": _ECS_FIELDS,
}

# generic profile: our canonical field -> role
_GENERIC_ROLES: dict[str, tuple[str, str | None, dict[str, Any]]] = {
    "host": (ROLE_HOST, "host", {}),
    "source": (ROLE_HOST, "host", {}),
    "log_source": (ROLE_SOURCE, None, {}),
    "src_ip": (ROLE_IP, "ip", {"direction": "src", "hours": True}),
    "dst_ip": (ROLE_PEER_IP, "ip", {"direction": "dst", "hours": True}),
    "user": (ROLE_USER, "user", {"failure_sensitive": True}),
    "process": (ROLE_PROCESS, "file", {}),
    "parent_process": (ROLE_PROCESS, "file", {}),
    "file": (ROLE_ATTACKER, "file", {}),
    "command_line": (ROLE_ATTACKER, "cmd", {"free_text": True}),
    "url": (ROLE_ATTACKER, "url", {"free_text": True}),
}


class AnchorSpec:
    """Fields sketched for one profile plus how to find the event's host (lookup plan precomputed)."""

    __slots__ = ("ecs_context", "fields", "host_paths", "host_plan", "plan", "profile", "wazuh_host")

    def __init__(self, profile: str, fields: tuple[AnchorField, ...], host_paths: tuple[str, ...]) -> None:
        self.profile = profile
        self.fields = fields
        self.host_paths = host_paths
        self.plan: tuple[tuple[AnchorField, str, str], ...] = tuple((f, f.path, _head(f.path)) for f in fields)
        self.host_plan: tuple[tuple[str, str], ...] = tuple((p, _head(p)) for p in host_paths)
        self.ecs_context = profile != "wazuh4"  # event.outcome / event.module only exist outside Wazuh 4.x
        self.wazuh_host = "predecoder.hostname" in host_paths

    def by_path(self) -> dict[str, AnchorField]:
        return {f.path: f for f in self.fields}


def _head(path: str) -> str:
    return path.split(".", 1)[0]


def spec_for(profile: str, tenant: TenantConfig | None = None) -> AnchorSpec:
    """Anchor spec for a profile (``auto``/unknown profiles get the union of wazuh4 and ecs)."""
    if profile == "wazuh4":
        return AnchorSpec("wazuh4", _WAZUH4_FIELDS, ("agent.name", "predecoder.hostname"))
    if profile in ("ecs", "wazuh5"):
        return AnchorSpec(profile, _ECS_FIELDS, ("host.name", "agent.name"))
    if profile == "generic":
        return _generic_spec(tenant)
    seen: dict[str, AnchorField] = {}
    for item in (*_WAZUH4_FIELDS, *_ECS_FIELDS):
        seen.setdefault(item.path, item)
    return AnchorSpec(profile or "auto", tuple(seen.values()), ("agent.name", "predecoder.hostname", "host.name"))


def _generic_spec(tenant: TenantConfig | None) -> AnchorSpec:
    fields_: dict[str, AnchorField] = {}
    hosts: list[str] = []
    for item in tenant.inputs if tenant is not None else ():
        for ours, path in sorted(item.mapping.items()):
            if ours not in _GENERIC_ROLES or not path or path in fields_:
                continue
            role, entity, extra = _GENERIC_ROLES[ours]
            fields_[path] = AnchorField(path, role, entity, **extra)
            if role == ROLE_HOST:
                hosts.append(path)
    return AnchorSpec("generic", tuple(fields_.values()), tuple(hosts))


# context fields pinned as companions (never sketched on their own)
COMPANION_FIELDS: dict[str, AnchorField] = {
    "data.win.eventdata.logonType": _f("data.win.eventdata.logonType", ROLE_CONTEXT, None),
}


def all_fields(tenant: TenantConfig | None = None) -> dict[str, AnchorField]:
    """Every known anchor field by path (used to classify stored candidates whatever profile produced them)."""
    out: dict[str, AnchorField] = {}
    for spec in (spec_for("wazuh4"), spec_for("ecs"), _generic_spec(tenant)):
        for item in spec.fields:
            out.setdefault(item.path, item)
    for path, item in COMPANION_FIELDS.items():
        out.setdefault(path, item)
    return out


def companion_value(fields: Mapping[str, Any], path: str) -> str | None:
    """The single, usable value of a companion field (None when absent, empty, multi-valued or too long)."""
    values = scalar_values(_get(fields, path))
    if len(values) != 1 or len(values[0]) > MAX_VALUE_LEN:
        return None
    return values[0]


def detect_profile(fields: Mapping[str, Any]) -> str:
    """Cheap per-event profile guess for collectors created with profile ``auto``."""
    if _get(fields, "decoder.name") is not None or _get(fields, "rule.level") is not None:
        return "wazuh4"
    if _get(fields, "location") is not None and _get(fields, "agent.id") is not None:
        return "wazuh4"
    if (
        _get(fields, "ecs.version") is not None
        or _get(fields, "event.dataset") is not None
        or _get(fields, "host.name") is not None
        or _get(fields, "kibana.alert.rule.uuid") is not None
    ):
        return "ecs"
    return "auto"


FIXED_PROFILES = frozenset({"wazuh4", "ecs", "wazuh5", "generic"})


class SpecResolver:
    """Anchor spec per event: fixed for a known profile, detected per event for ``auto``."""

    __slots__ = ("_fixed", "_specs", "_tenant", "counts")

    def __init__(self, profile: str, tenant: TenantConfig | None = None) -> None:
        self._tenant = tenant
        self._specs: dict[str, AnchorSpec] = {}
        self._fixed = spec_for(profile, tenant) if profile in FIXED_PROFILES else None
        self.counts: dict[str, int] = {}

    def for_fields(self, fields: Mapping[str, Any]) -> AnchorSpec:
        if self._fixed is not None:
            return self._fixed
        detected = detect_profile(fields)
        self.counts[detected] = self.counts.get(detected, 0) + 1
        spec = self._specs.get(detected)
        if spec is None:
            spec = self._specs[detected] = spec_for(detected, self._tenant)
        return spec


class DayIndex:
    """Epoch seconds -> tenant-local calendar day (``date.toordinal()``), cached per 15-minute bucket (every
    modern UTC offset is a multiple of 15 minutes, so a bucket never straddles a local midnight)."""

    __slots__ = ("_cache", "_tz")

    def __init__(self, tz: tzinfo) -> None:
        self._tz = tz
        self._cache: dict[int, int] = {}

    def day(self, epoch: float) -> int:
        bucket = int(epoch // 900)
        cached = self._cache.get(bucket)
        if cached is not None:
            return cached
        if len(self._cache) > 200_000:
            self._cache.clear()
        try:
            day = datetime.fromtimestamp(bucket * 900, tz=self._tz).date().toordinal()
        except (OverflowError, OSError, ValueError):
            day = _EPOCH_ORDINAL + (bucket * 900) // 86400
        self._cache[bucket] = day
        return day

    def start_of(self, day: int) -> float:
        """Epoch seconds of local midnight starting ``day``."""
        local = datetime.combine(date.fromordinal(day), datetime.min.time(), tzinfo=self._tz)
        return local.timestamp()


_EPOCH_ORDINAL = date(1970, 1, 1).toordinal()


# ---- value extraction --------------------------------------------------------------------------------------------
_EMPTY_TOKENS = frozenset(("", "-", "null", "NULL", "(NULL)", "None", "N/A", "n/a", "unknown"))  # models.is_empty
_GROUP_FLAGS: dict[tuple[str, ...], tuple[bool, bool, bool, bool]] = {}


def _get(fields: Mapping[str, Any], path: str, head: str | None = None) -> Any:
    """``models.get_path`` semantics, fast for flattened documents (the common case)."""
    value = fields.get(path)
    if value is not None:
        return value
    if head is None:
        head = _head(path)
    if head == path or head not in fields:
        return None
    return get_path(fields, path)


def field_value(fields: Mapping[str, Any], path: str) -> Any:
    """Value of an ORIGINAL dotted path in a flattened or nested document (``models.get_path`` semantics)."""
    return _get(fields, path)


def scalar_values(raw: Any) -> tuple[str, ...]:
    """String values of a field as ``Condition.matches`` compares them (``str(value)``); lists are exploded.
    Values that carry no information (``models.is_empty``) are dropped."""
    if raw.__class__ is str:
        if raw in _EMPTY_TOKENS or ((raw[:1].isspace() or raw[-1:].isspace()) and raw.strip() in _EMPTY_TOKENS):
            return ()
        return (raw,)
    if raw is None or isinstance(raw, bool):
        return ()
    if isinstance(raw, str):
        return () if is_empty(raw) else (str(raw),)
    if isinstance(raw, (int, float)):
        return (str(raw),)
    if isinstance(raw, (list, tuple)):
        out: list[str] = []
        for item in raw:
            if isinstance(item, bool) or not isinstance(item, (str, int, float)):
                continue
            text = str(item)
            if not is_empty(text) and text not in out:
                out.append(text)
                if len(out) >= MAX_LIST_VALUES:
                    break
        return tuple(out)
    return ()


def _group_flags(groups: tuple[str, ...]) -> tuple[bool, bool, bool, bool]:
    """(failure, fim, check, process creation) from rule groups, cached per distinct groups tuple."""
    try:
        cached = _GROUP_FLAGS.get(groups)
    except TypeError:  # unhashable junk inside the tuple
        cached = None
        groups = tuple(str(x) for x in groups)
    if cached is not None:
        return cached
    lowered = {str(x).lower() for x in groups}
    flags = (
        bool(lowered & FAILURE_GROUPS),
        bool(lowered & FIM_GROUPS),
        bool(lowered & CHECK_GROUPS),
        bool(lowered & PROCESS_GROUPS),
    )
    if len(_GROUP_FLAGS) >= 4096:
        _GROUP_FLAGS.clear()
    _GROUP_FLAGS[groups] = flags
    return flags


@dataclass(slots=True)
class Extracted:
    """Anchor values of one event (spec order), its host, and context flags."""

    values: list[tuple[AnchorField, str]]
    host: tuple[AnchorField, str] | None
    failure: bool
    fim: bool
    check: bool
    process: bool = False  # a process-creation event (Sysmon 1, Security 4688, auditd execve)


def extract(spec: AnchorSpec, fields: Mapping[str, Any], rule_groups: Iterable[str] = ()) -> Extracted:
    """Pull the sketched values out of an event's fields."""
    groups = rule_groups if isinstance(rule_groups, tuple) else tuple(rule_groups)
    if not groups:
        raw_groups = _get(fields, "rule.groups", "rule")
        if isinstance(raw_groups, (list, tuple)):
            groups = tuple(str(x) for x in raw_groups[: MAX_LIST_VALUES * 8])
    failure, fim, check, process = _group_flags(groups) if groups else (False, False, False, False)
    if spec.ecs_context:
        if not failure:
            outcome = _get(fields, "event.outcome", "event")
            failure = isinstance(outcome, str) and outcome.lower() == "failure"
        if not fim:
            module = _get(fields, "event.module", "event") or _get(fields, "event.dataset", "event")
            fim = isinstance(module, str) and module.lower().startswith(("file_integrity", "fim"))
    if not process:
        process = is_process_creation(fields, ecs=spec.ecs_context)

    manager_event = spec.wazuh_host and str(_get(fields, "agent.id", "agent")) == "000"
    host_field, host_value = _host_of(spec, fields, manager_event)
    host_lower = host_value.lower() if host_value is not None else None
    # agent 000 is the manager: its name is not the device that sent the log (syslog relayed to the manager), so
    # "agent.name = <manager>" would mute every device behind it
    skip_agent = manager_event
    values: list[tuple[AnchorField, str]] = []
    host: tuple[AnchorField, str] | None = None
    for item, path, head in spec.plan:
        if item.role == ROLE_HOST:
            if path == host_field and host_value is not None:
                host = (item, host_value)
                values.append(host)
                continue
            if skip_agent and path == "agent.name":
                continue  # agent 000: the manager's name is not the device
            raw = _get(fields, path, head)
            if raw is None:
                continue
            for value in scalar_values(raw):
                if len(value) <= MAX_VALUE_LEN and value.lower() != host_lower:
                    values.append((item, value))
            continue
        raw = _get(fields, path, head)
        if raw is None:
            continue
        for value in scalar_values(raw):
            if len(value) > MAX_VALUE_LEN or (path == "location" and value in STATIC_LOCATIONS):
                continue
            entry = (item, value)
            values.append(entry)
            if host is None and path == host_field and value == host_value:
                host = entry  # a syslog sender without a hostname header: the sender is the device
    return Extracted(values, host, failure, fim, check, process)


def _host_of(spec: AnchorSpec, fields: Mapping[str, Any], manager_event: bool = False) -> tuple[str | None, str | None]:
    if not spec.host_plan:
        return None, None
    if manager_event:
        # the device is the syslog header's hostname; without it, the sender address in "location" (never the
        # manager's own name)
        pre = scalar_values(_get(fields, "predecoder.hostname", "predecoder"))
        if pre and len(pre[0]) <= MAX_VALUE_LEN:
            return "predecoder.hostname", pre[0]
        loc = scalar_values(_get(fields, "location"))
        if len(loc) == 1 and len(loc[0]) <= MAX_VALUE_LEN and is_sender_location(loc[0]):
            return "location", loc[0]
        return None, None
    for path, head in spec.host_plan:
        found = scalar_values(_get(fields, path, head))
        if found and len(found[0]) <= MAX_VALUE_LEN:
            return path, found[0]
    return None, None


def is_sender_location(value: str) -> bool:
    """A Wazuh ``location`` that names the sending device: a syslog sender address or ``host->path``."""
    if "->" in value:
        return True
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _lower_values(raw: Any) -> list[str]:
    return [v.strip().lower() for v in scalar_values(raw)]


def is_process_creation(fields: Mapping[str, Any], *, ecs: bool = False) -> bool:
    """A process-creation event: Sysmon event 1, Windows Security 4688, or ECS ``event.category: process`` with
    ``event.type: start`` (rule groups are checked separately, see :data:`PROCESS_GROUPS`)."""
    codes = _lower_values(_get(fields, "data.win.system.eventID", "data"))
    if codes:
        if "4688" in codes:
            return True
        if "1" in codes:
            provider = _lower_values(_get(fields, "data.win.system.providerName", "data"))
            channel = _lower_values(_get(fields, "data.win.system.channel", "data"))
            if any(p in _SYSMON_PROVIDERS for p in provider) or _SYSMON_CHANNEL in channel:
                return True
    if ecs:
        categories = _lower_values(_get(fields, "event.category", "event"))
        if "process" in categories and "start" in _lower_values(_get(fields, "event.type", "event")):
            return True
        code = _lower_values(_get(fields, "event.code", "event"))
        if "4688" in code:
            return True
        if "1" in code and any("sysmon" in p for p in _lower_values(_get(fields, "event.provider", "event"))):
            return True
    return False


def process_basename(value: str) -> str:
    """Lowercase executable name of a path or command line (``C:\\\\Windows\\\\cmd.exe /c x`` -> ``cmd.exe``)."""
    text = value.strip()
    if text[:1] in ('"', "'"):
        text = text[1:].split(text[0], 1)[0]  # "C:\Program Files\x.exe" -args
    elif not _FULL_PATH.match(text) and " " in text:
        text = text.split(" ", 1)[0]
    return re.split(r"[\\/]+", text.rstrip("\\/"))[-1].strip().strip('"').lower()


def is_generic_process(value: str) -> bool:
    """Interpreter, living-off-the-land binary or generic parent (see :data:`GENERIC_PROCESS_PATTERNS`)."""
    name = process_basename(value)
    if not name:
        return True
    if name in _GENERIC_EXACT:
        return True
    return any(fnmatch.fnmatchcase(name, pattern) for pattern in _GENERIC_GLOBS)


def normalize_free_text(value: str) -> str:
    """Replace volatile tokens (GUIDs, hex blobs, long digit runs) so repeated commands fingerprint alike."""
    return _VOLATILE.sub("#", value[:_FREE_TEXT_CHARS])


def cluster_hash(rule_id: str, values: Sequence[tuple[AnchorField, str]], bucket: int) -> int:
    """Hash of (fingerprint, time bucket). The fingerprint is the rule plus its anchor/attacker field values:
    volatile fields (ports, pids, record ids, GUIDs, timestamps) are never part of it."""
    parts = [rule_id]
    for item, value in values:
        parts.append(item.path)
        parts.append(normalize_free_text(value) if item.free_text else value)
    parts.append(str(bucket))
    return hash64("\x1f".join(parts))


# ---- value classification ----------------------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class ValueClass:
    """How one field value may be used in a condition."""

    alone: bool  # may be the only condition (a stable anchor that identifies a host)
    attacker: bool  # attacker-controllable: only allowed together with a stable anchor
    external: bool = False  # public IP address
    internal: bool = False  # internal IP address
    trusted: bool = False  # configured known-benign entity, or service account (never a machine account)
    host_like: bool = False  # identifies a host
    never: bool = False  # never a condition, not even paired with a host (interpreters, generic parents)
    chosen: bool = False  # a name someone else picked (an account trusted only by its name pattern): needs evidence


class IpClassifier:
    """Fast, cached :func:`ip_kind`: canonical dotted IPv4 goes through ``inet_pton`` and integer ranges; anything
    else (IPv6, invalid, non-canonical spellings) takes the ``ipaddress`` path, so results always agree."""

    __slots__ = ("_cache", "_tenant", "_v4")

    def __init__(self, tenant: TenantConfig) -> None:
        self._tenant = tenant
        self._cache: dict[str, str] = {}
        ranges: list[tuple[int, int]] = []
        for net in tenant.internal_networks:
            try:
                network = ipaddress.ip_network(net, strict=False)
            except ValueError:
                continue
            if network.version == 4:
                ranges.append((int(network.network_address), int(network.broadcast_address)))
        self._v4 = tuple(ranges)

    def kind(self, value: str) -> str:
        cached = self._cache.get(value)
        if cached is not None:
            return cached
        kind: str | None = None
        try:
            packed = socket.inet_pton(socket.AF_INET, value)
        except (OSError, ValueError, TypeError):
            packed = b""
        if len(packed) == 4 and socket.inet_ntop(socket.AF_INET, packed) == value:
            number = int.from_bytes(packed, "big")
            kind = "internal" if any(lo <= number <= hi for lo, hi in self._v4) else "external"
        if kind is None:
            kind = ip_kind(value, self._tenant)
        if len(self._cache) >= 100_000:
            self._cache.clear()
        self._cache[value] = kind
        return kind


def ip_kind(value: str, tenant: TenantConfig) -> str:
    """``internal`` | ``external`` | ``invalid`` (tenant.internal_networks decide what is internal).

    The value must be the address exactly as ``Condition.matches`` compares it: a padded ``"10.0.0.5 "`` is not an
    internal address (and the emitter could not express it)."""
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return "invalid"
    return "internal" if tenant.is_internal(value) else "external"


def _account_name(value: str) -> str:
    return value.replace("\\\\", "\\").rsplit("\\", 1)[-1].split("@", 1)[0].strip().lower()


def is_service_account(value: str, patterns: Sequence[str]) -> bool:
    """Service account by name pattern (DOMAIN\\ prefixes and @realm suffixes are ignored)."""
    name = _account_name(value)
    return bool(name) and any(fnmatch.fnmatchcase(name, p.lower()) for p in patterns)


def is_machine_account(value: str) -> bool:
    """Windows computer account (``DC01$``)."""
    name = _account_name(value)
    return len(name) >= 2 and name.endswith("$")


def is_own_machine_account(user: str, host: str) -> bool:
    """``SRV-01$`` on host ``srv-01`` (or ``srv-01.corp.example``): the host itself, not a narrower scope."""
    name = _account_name(user)
    short = host.strip().lower().split(".", 1)[0]
    return name.endswith("$") and name[:-1] == short


def is_full_path(value: str) -> bool:
    return bool(_FULL_PATH.match(value)) and "*" not in value and "?" not in value


# Locations any user (or an intruder without admin rights) can write to: a binary there is attacker-chosen.
_WRITABLE_DIRS: tuple[str, ...] = (  # path markers to recognize (never files we open)
    "\\users\\",
    "\\programdata\\",
    "\\appdata\\",
    "\\temp\\",
    "\\tmp\\",
    "\\windows\\tasks\\",
    "\\windows\\tracing\\",
    "\\windows\\debug\\",
    "\\perflogs\\",
    "\\$recycle.bin\\",
    "\\recycler\\",
    "\\downloads\\",
    "/tmp/",  # noqa: S108
    "/var/tmp/",  # noqa: S108
    "/dev/shm/",  # noqa: S108
    "/home/",
    "/run/user/",
    "/var/www/",
    "/users/",
    "/private/tmp/",
)
_BACKSLASHES = re.compile(r"\\+")


def is_user_writable_path(value: str) -> bool:
    """A path under a user-writable directory (profiles, temp, ProgramData, /tmp, /home, web roots) or on a network
    share: whoever can write there chooses what runs from it."""
    text = _BACKSLASHES.sub(r"\\", value.strip()).lower()  # Wazuh doubles backslashes: compare single ones
    if text.startswith("\\") and not text.startswith(("\\device\\", "\\??\\", "\\systemroot\\")):
        return True  # UNC path (\\server\share): whoever can write to the share chooses what runs from it
    return any(marker in text for marker in _WRITABLE_DIRS)


_ROLE_TRUST_KEYS: dict[str, str] = {ROLE_HOST: "host", ROLE_IP: "src_ip", ROLE_USER: "user", ROLE_PROCESS: "process"}


def classify(
    item: AnchorField,
    value: str,
    tenant: TenantConfig,
    *,
    failure_rule: bool,
    fim_rule: bool,
    service_patterns: Sequence[str] = DEFAULT_SERVICE_ACCOUNT_PATTERNS,
) -> ValueClass:
    """Decide whether ``field = value`` can anchor a condition set on its own (§5.2).

    Only values that identify a HOST stand alone: the host itself, a syslog sender (``location``), an internal
    source address, a FIM path (routed to ``fix_at_source``). Accounts and process paths only narrow a host scope:
    a scope keyed on an account follows the account (and whoever holds its credentials) to every host, and a scope
    keyed on an image path follows anything started from that path, anywhere. Machine accounts (``DC01$``) are
    never trusted by name pattern (any domain user can create one), and interpreters / living-off-the-land
    binaries / generic parents are never a condition at all (:func:`is_generic_process`).
    """
    role = item.role
    # canonical names ("user", "host"...) apply to every field of that role, whatever its path (generic mappings)
    trusted = tenant.is_trusted(item.path, value) or (
        role in _ROLE_TRUST_KEYS and tenant.is_trusted(_ROLE_TRUST_KEYS[role], value)
    )
    if role == ROLE_HOST:
        return ValueClass(alone=True, attacker=False, trusted=trusted, host_like=True)
    if role == ROLE_SOURCE:
        if item.path == "location" and (ip_kind(value, tenant) != "invalid" or "->" in value):
            return ValueClass(alone=True, attacker=False, trusted=trusted, host_like=True)
        return ValueClass(alone=False, attacker=False, trusted=trusted)
    if role in IP_ROLES:
        kind = ip_kind(value, tenant)
        if kind == "internal":
            return ValueClass(alone=role == ROLE_IP, attacker=False, internal=True, trusted=trusted)
        return ValueClass(alone=False, attacker=True, external=kind == "external")
    if role == ROLE_USER:
        if failure_rule and item.failure_sensitive:
            return ValueClass(alone=False, attacker=True)
        machine = is_machine_account(value)
        # a "*$" name pattern (e.g. in service_account_patterns) never makes a machine account trusted: computer
        # accounts can be created by any domain user (ms-DS-MachineAccountQuota) and do not identify an actor
        service = trusted or (not machine and is_service_account(value, service_patterns))
        # whoever can create accounts picks their names: only an account the tenant configured as trusted is vouched
        # for; one that merely LOOKS like a service account (or a machine account) still needs triage evidence
        return ValueClass(alone=False, attacker=not (service or machine), trusted=service, chosen=not trusted)
    if role == ROLE_PROCESS:
        if is_generic_process(value):
            return ValueClass(alone=False, attacker=True, never=True)
        if is_full_path(value) and not is_user_writable_path(value):
            return ValueClass(alone=False, attacker=False, trusted=trusted)
        return ValueClass(alone=False, attacker=True)  # bare names and user-writable locations are attacker-chosen
    if role == ROLE_FILE:
        if fim_rule and item.path in ("syscheck.path", "file.path"):
            return ValueClass(alone=True, attacker=False, trusted=trusted)
        return ValueClass(alone=False, attacker=True)
    if role == ROLE_CONTEXT:
        return ValueClass(alone=False, attacker=False)
    return ValueClass(alone=False, attacker=True)


def entity_for(item: AnchorField | None, value: str, tenant: TenantConfig | None = None) -> Entity | str:
    """Wrap an identifying value in :class:`Entity`; log-source names (decoders, log files) stay plain."""
    if item is None:
        return Entity("val", value)
    if item.path == "location":
        try:
            ipaddress.ip_address(value.strip())
        except ValueError:
            return Entity("host", value) if "->" in value else value
        return Entity("ip", value)
    if item.entity is None:
        return value
    return Entity(item.entity, value)


def cooccurrence_kind(item: AnchorField, value: str) -> str | None:
    """Entity kind used to link alerts across rules (host / ip / user), or None for generic values."""
    lowered = value.strip().lower()
    if item.role == ROLE_HOST:
        return "host"
    if item.role in IP_ROLES:
        return None if lowered in _GENERIC_IPS else "ip"
    if item.role == ROLE_USER:
        return None if lowered in _GENERIC_USERS else "user"
    if item.path == "location":
        try:
            ipaddress.ip_address(value.strip())
        except ValueError:
            return None
        return "ip"
    return None


@functools.lru_cache(maxsize=65_536)
def cooccurrence_key(kind: str, value: str) -> str:
    """Normalized value for the high-alert index. Linking too much is the safe direction, so spellings of the same
    entity meet: IPs in canonical form (``::ffff:203.0.113.5`` is ``203.0.113.5``), accounts without ``DOMAIN\\``
    or ``@realm`` and case-insensitive, hosts by their short name (``SRV-01.corp.example`` is ``srv-01``)."""
    text = value.strip()
    if kind == "ip":
        try:
            address = ipaddress.ip_address(text)
        except ValueError:
            return text.lower()
        mapped = getattr(address, "ipv4_mapped", None)
        return str(mapped if mapped is not None else address)
    if kind == "user":
        return _account_name(text) or text.lower()
    lowered = text.lower()
    if kind == "host":
        try:
            ipaddress.ip_address(lowered)
        except ValueError:
            return lowered.split(".", 1)[0] or lowered
    return lowered


class HighAlertIndex:
    """High-level alerts (level >= tenant.high_level) per entity value -> epoch hours (bounded)."""

    __slots__ = ("_frozen", "_hours", "max_values", "truncated")

    def __init__(self, max_values: int = 500_000) -> None:
        self.max_values = max_values
        self.truncated = False
        self._hours: dict[tuple[str, str], dict[int, int]] = {}
        self._frozen: dict[tuple[str, str], tuple[list[int], list[int]]] | None = None

    def add(self, kind: str, value: str, hour: int, count: int = 1) -> None:
        key = (kind, cooccurrence_key(kind, value))
        slot = self._hours.get(key)
        if slot is None:
            if len(self._hours) >= self.max_values:
                self.truncated = True
                return
            slot = self._hours[key] = {}
        slot[hour] = slot.get(hour, 0) + count
        self._frozen = None

    def merge(self, other: HighAlertIndex) -> None:
        for (kind, value), hours in other._hours.items():
            for hour, count in hours.items():
                self.add(kind, value, hour, count)
        self.truncated = self.truncated or other.truncated

    def hours(self, kind: str, value: str) -> Mapping[int, int]:
        """Epoch hour -> number of high-level alerts carrying that entity value."""
        return self._hours.get((kind, cooccurrence_key(kind, value)), {})

    def count_near(self, kind: str, value: str, hour: int, window_hours: int) -> int:
        """High-level alerts with this value within ``hour ± window_hours``."""
        key = (kind, cooccurrence_key(kind, value))
        if key not in self._hours:
            return 0
        if self._frozen is None:
            self._frozen = {}
        frozen = self._frozen.get(key)
        if frozen is None:
            ordered = sorted(self._hours[key].items())
            prefix = [0]
            for _, c in ordered:
                prefix.append(prefix[-1] + c)
            frozen = ([h for h, _ in ordered], prefix)
            self._frozen[key] = frozen
        hours, prefix = frozen
        lo = bisect.bisect_left(hours, hour - window_hours)
        hi = bisect.bisect_right(hours, hour + window_hours)
        return prefix[hi] - prefix[lo]

    def __len__(self) -> int:
        return len(self._hours)


def beacon_like(entry: SpaceSavingEntry[Any]) -> bool:
    """Periodic hourly activity: active in >= BEACON_MIN_ACTIVE_HOURS distinct hours that either cover
    >= BEACON_MIN_COVERAGE of its active span, or come in runs of consecutive hours averaging
    >= BEACON_MIN_RUN_HOURS (duty-cycled beacons: only while the machine is on, only in office hours).
    Applied only to public addresses."""
    active = entry.active_hours
    span = entry.hour_span()
    if active < BEACON_MIN_ACTIVE_HOURS or span <= 0:
        return False
    if active / span >= BEACON_MIN_COVERAGE:
        return True
    bits = entry.hours
    runs = (bits & ~(bits << 1)).bit_count()  # hours whose previous hour was idle: one per run of activity
    return runs > 0 and active / runs >= BEACON_MIN_RUN_HOURS


def regularity(entry: SpaceSavingEntry[Any]) -> float | None:
    """Inter-arrival regularity of a sketched value (see :meth:`SpaceSavingEntry.regularity`)."""
    return entry.regularity()


def noisy_thresholds(settings: NoiseSettings) -> tuple[int, float]:
    """(minimum alerts, minimum alerts per day) before a rule is called noisy (tunable in NoiseSettings)."""
    alerts = getattr(settings, "min_noisy_alerts", MIN_NOISY_ALERTS)
    per_day = getattr(settings, "min_noisy_per_day", MIN_NOISY_PER_DAY)
    return max(0, int(alerts)), max(0.0, float(per_day))


def is_noisy(total: int, days: float, settings: NoiseSettings) -> bool:
    """Enough volume to call a rule noisy: at least ``min_noisy_alerts`` alerts and ``min_noisy_per_day`` per day
    (a level-12 rule that fired once is not noise, and a rule with 3 alerts a day is not worth tuning)."""
    min_alerts, min_per_day = noisy_thresholds(settings)
    return total >= min_alerts and total / max(days, 1.0) >= min_per_day


def elapsed_days(window: Window) -> float:
    """Days elapsed between the first and the last alert (at least 1): the ONE day count used for per-day rates
    (local calendar dates, ``Window.n_days``, only count presence and bursts)."""
    return max(1.0, window.duration / 86400.0)


# ---- window ------------------------------------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class Window:
    """Analysis window: first/last event (epoch seconds) and the tenant-local days they span."""

    start: float
    end: float
    first_day: int  # date.toordinal() in tenant local time
    last_day: int

    @property
    def n_days(self) -> int:
        return max(0, self.last_day - self.first_day + 1)

    @property
    def duration(self) -> float:
        return max(0.0, self.end - self.start)

    def days(self) -> range:
        return range(self.first_day, self.last_day + 1)

    def is_learning(self, min_days: int) -> bool:
        """Too little history for a verdict: fewer than ``min_days`` local dates, or less than ``min_days - 1``
        full days elapsed (5 days of data can touch 7 dates when it starts late and ends early)."""
        return self.n_days < min_days or self.duration < (min_days - 1) * 86400.0


def day_label(day: int) -> str:
    return date.fromordinal(day).isoformat()


# ---- gates -------------------------------------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class CondFact:
    field: str
    value: str
    item: AnchorField | None
    cls: ValueClass


@dataclass(frozen=True, slots=True)
class CoHit:
    """A candidate value seen in high-level alerts within the co-occurrence window."""

    kind: str
    value: str
    alerts: int


@dataclass(frozen=True, slots=True)
class BeaconHit:
    """A public address with sustained hourly activity inside the scope. It is labelled *beaconing* only when the
    traffic goes TO it (outbound: C2 is initiated from the inside) and recurs at a steady interval; a public
    SOURCE active for hours (a scan, a password spray) or irregular traffic is "sustained activity" instead.
    Either way it blocks tuning."""

    value: str
    active_hours: int
    span_hours: int
    outbound: bool = False
    regularity: float | None = None  # share of inter-arrival gaps near the usual one (None: unknown)

    @property
    def periodic(self) -> bool:
        return self.regularity is not None and self.regularity >= PERIODIC_MIN_SHARE

    @property
    def beacon(self) -> bool:
        return self.outbound and self.periodic


@dataclass(slots=True)
class CandidateFacts:
    """Everything the gates need about one candidate condition set."""

    rule_id: str
    conditions: tuple[CondFact, ...]
    count_lower: int
    count_upper: int
    rule_total: int
    window: Window
    rule_level: int | None
    tactics: tuple[str, ...] = ()
    fim: bool = False
    check: bool = False
    process_creation: bool = False  # process-creation rule: as sensitive as a sensitive tactic
    rule_clusters: int = 0
    first_seen: float | None = None
    last_seen: float | None = None
    daily: Mapping[int, int] = field(default_factory=dict)
    dispositions: DispositionCounts = field(default_factory=DispositionCounts)
    dispositions_loaded: bool = False
    tp_rule_wide: int = 0
    co_hits: tuple[CoHit, ...] = ()
    co_index_truncated: bool = False
    external_share: float | None = None  # share of the scope's alerts sourced from public addresses (host scopes)
    beacons: tuple[BeaconHit, ...] = ()
    dependents: tuple[str, ...] | None = None  # None: not applicable (non-Wazuh data without a ruleset)
    dependents_error: bool = False
    dependents_unverified: str | None = None  # "no_ruleset" | "no_stock": correlation links could not be checked

    @property
    def share(self) -> float:
        return self.count_lower / self.rule_total if self.rule_total else 0.0

    @property
    def dup_ratio(self) -> float | None:
        if self.rule_total <= 0 or self.rule_clusters <= 0:
            return None
        return max(0.0, 1.0 - self.rule_clusters / self.rule_total)


@dataclass(frozen=True, slots=True)
class GateOutcome:
    """One gate result: ``passed`` or the verdict class it pushes towards, with a reason carrying numbers."""

    gate: str
    passed: bool
    message: Message
    verdict: str | None = None  # verdict implied on failure (do_not_tune | investigate | fix_at_source | ...)


@dataclass(slots=True)
class Decision:
    verdict: str
    outcomes: list[GateOutcome]
    action: str = "demote"
    fix_kind: str | None = None  # fim | check | exposure
    co_occurs: bool = False

    @property
    def reasons(self) -> list[Message]:
        """Failed gates first, most important first (true positives, beaconing, co-occurrence with high alerts,
        public addresses, novelty...), then passed ones (every gate outcome is explained)."""
        failed = sorted(
            (o for o in self.outcomes if not o.passed),
            key=lambda o: (_GATE_PRIORITY.get(o.gate, 50), 0 if _is_beacon_message(o.message) else 1),
        )
        passed = [o.message for o in self.outcomes if o.passed]
        return [o.message for o in failed] + passed

    def failed(self, gate: str) -> bool:
        return any(o.gate == gate and not o.passed for o in self.outcomes)


_GATE_PRIORITY: dict[str, int] = {
    "tp": 0,
    "tp_rule_wide": 0,
    "beacon": 1,
    "co_occurrence": 2,
    "external": 3,
    "novelty": 4,
    "burst": 5,
    "persistence": 6,
    "level": 7,
    "sensitive": 8,
    "attacker_field": 9,
    "fim": 10,
    "check": 10,
    "aggregate": 11,
    "dependents": 12,
}


def _is_beacon_message(message: Message) -> bool:
    return message.key == "noise.reason.beacon"


def normalize_tactic(name: str) -> str:
    return " ".join(name.strip().lower().replace("-", " ").replace("_", " ").split())


def sensitive_tactics(tactics: Iterable[str], settings: NoiseSettings) -> list[str]:
    wanted = {normalize_tactic(t) for t in settings.sensitive_tactics}
    return sorted({t for t in tactics if normalize_tactic(t) in wanted})


def daily_series(daily: Mapping[int, int], window: Window) -> list[int]:
    return [daily.get(day, 0) for day in window.days()]


def burst_stats(daily: Mapping[int, int], window: Window) -> tuple[int, float, int]:
    """(peak count, median daily count, peak day) over every day of the window (zeros included)."""
    series = daily_series(daily, window)
    if not series:
        return 0, 0.0, window.first_day
    peak = max(series)
    return peak, float(statistics.median(series)), window.first_day + series.index(peak)


def evaluate(facts: CandidateFacts, settings: NoiseSettings, tenant: TenantConfig) -> Decision:
    """Run every safety gate of §5.4 on one candidate and resolve its verdict.

    Precedence: learning > do_not_tune > investigate (novel, not persistent, burst, co-occurrence, beacon) >
    fix_at_source (FIM/rootcheck, public address) > sensitive tactic (investigate, or aggregate for duplicate
    storms) > tune. ``tune`` here means "passed the gates": the backtest still has to confirm it.
    """
    window = facts.window
    outcomes: list[GateOutcome] = []
    if window.is_learning(settings.min_history_days):
        outcomes.append(
            GateOutcome(
                "learning",
                False,
                M("noise.reason.learning", days=window.n_days, min=settings.min_history_days),
                "learning",
            )
        )
        return Decision("learning", outcomes)

    outcomes.append(
        GateOutcome(
            "share",
            True,
            M(
                "noise.reason.share",
                share=facts.share,
                lower=facts.count_lower,
                total=facts.rule_total,
                min=settings.min_share,
            ),
        )
    )
    outcomes.extend(_gate_level(facts, tenant))
    outcomes.extend(_gate_tp(facts))
    outcomes.extend(_gate_novelty(facts, settings))
    outcomes.extend(_gate_persistence(facts, settings))
    outcomes.extend(_gate_burst(facts, settings))
    outcomes.extend(_gate_cooccurrence(facts, settings, tenant))
    outcomes.extend(_gate_beacon(facts))
    sensitive = _gate_sensitive(facts, settings)
    outcomes.extend(sensitive)
    outcomes.extend(_gate_attacker_evidence(facts, settings))
    outcomes.extend(_gate_external(facts))
    outcomes.extend(_gate_source_fix(facts))
    dependents = _gate_dependents(facts)
    outcomes.extend(dependents)
    action = "review" if any(o.gate == "dependents" and not o.passed for o in dependents) else "demote"

    failed = {o.gate for o in outcomes if not o.passed and o.gate != "dependents"}
    co_occurs = "co_occurrence" in failed
    if failed & {"level", "tp", "tp_rule_wide"}:
        return Decision("do_not_tune", outcomes, action, co_occurs=co_occurs)
    hard = failed & {"novelty", "persistence", "burst", "co_occurrence", "beacon"}
    if hard:
        return Decision("investigate", outcomes, action, co_occurs=co_occurs)
    if "fim" in failed or "check" in failed:
        return Decision("fix_at_source", outcomes, action, fix_kind="fim" if "fim" in failed else "check")
    if "external" in failed:
        return Decision("fix_at_source", outcomes, action, fix_kind="exposure")
    if "sensitive" in failed:
        dup = facts.dup_ratio
        if dup is not None and dup >= AGGREGATE_DUP_RATIO:
            outcomes.append(
                GateOutcome(
                    "aggregate",
                    False,
                    M(
                        "noise.reason.aggregate",
                        dup=dup,
                        clusters=facts.rule_clusters,
                        alerts=facts.rule_total,
                        min=AGGREGATE_DUP_RATIO,
                    ),
                    "aggregate",
                )
            )
            return Decision("aggregate", outcomes, action)
        return Decision("investigate", outcomes, action)
    if "attacker_field" in failed:
        return Decision("investigate", outcomes, action)
    return Decision("tune", outcomes, action)


def _gate_level(facts: CandidateFacts, tenant: TenantConfig) -> list[GateOutcome]:
    level, top = facts.rule_level, tenant.max_tunable_level
    if level is None:
        return [GateOutcome("level", False, M("noise.reason.level_unknown", max=top), "do_not_tune")]
    if level > top:
        return [GateOutcome("level", False, M("noise.reason.level_blocked", level=level, max=top), "do_not_tune")]
    return [GateOutcome("level", True, M("noise.reason.level_ok", level=level, max=top))]


def _gate_tp(facts: CandidateFacts) -> list[GateOutcome]:
    out: list[GateOutcome] = []
    if facts.tp_rule_wide:
        out.append(
            GateOutcome(
                "tp_rule_wide",
                False,
                M("noise.reason.tp_rule_wide", tp=facts.tp_rule_wide, days=TP_LOOKBACK_DAYS),
                "do_not_tune",
            )
        )
    if facts.dispositions.tp:
        out.append(
            GateOutcome(
                "tp", False, M("noise.reason.tp", tp=facts.dispositions.tp, days=TP_LOOKBACK_DAYS), "do_not_tune"
            )
        )
    if not out:
        key = "noise.reason.no_tp" if facts.dispositions_loaded else "noise.reason.no_dispositions"
        out.append(GateOutcome("tp", True, M(key, days=TP_LOOKBACK_DAYS)))
    return out


def _gate_novelty(facts: CandidateFacts, settings: NoiseSettings) -> list[GateOutcome]:
    window = facts.window
    limit = window.start + settings.novelty_fraction * window.duration
    first = facts.first_seen
    if first is None or first > limit:
        label = _ts_label(first) if first is not None else "?"
        return [
            GateOutcome(
                "novelty",
                False,
                M("noise.reason.novel", first=label, fraction=settings.novelty_fraction),
                "investigate",
            )
        ]
    return [
        GateOutcome(
            "novelty", True, M("noise.reason.established", first=_ts_label(first), fraction=settings.novelty_fraction)
        )
    ]


def _gate_persistence(facts: CandidateFacts, settings: NoiseSettings) -> list[GateOutcome]:
    window = facts.window
    present = sum(1 for day in window.days() if facts.daily.get(day, 0) > 0)
    ratio = present / window.n_days if window.n_days else 0.0
    params = {"present": present, "days": window.n_days, "ratio": ratio, "min": settings.persistence}
    if ratio < settings.persistence:
        return [GateOutcome("persistence", False, M("noise.reason.not_persistent", **params), "investigate")]
    return [GateOutcome("persistence", True, M("noise.reason.persistent", **params))]


def _gate_burst(facts: CandidateFacts, settings: NoiseSettings) -> list[GateOutcome]:
    peak, median, peak_day = burst_stats(facts.daily, facts.window)
    base = max(median, 1.0)
    factor = peak / base
    params = {
        "peak": peak,
        "day": day_label(peak_day),
        "median": median,
        "factor": factor,
        "limit": settings.burst_factor,
    }
    if peak >= settings.burst_factor * base:
        return [GateOutcome("burst", False, M("noise.reason.burst", **params), "investigate")]
    return [GateOutcome("burst", True, M("noise.reason.no_burst", **params))]


def _gate_cooccurrence(facts: CandidateFacts, settings: NoiseSettings, tenant: TenantConfig) -> list[GateOutcome]:
    window = _hours_label(settings.co_occurrence_window.total_seconds())
    out: list[GateOutcome] = []
    for hit in facts.co_hits:
        out.append(
            GateOutcome(
                "co_occurrence",
                False,
                M(
                    "noise.reason.co_occurrence",
                    entity=Entity(hit.kind, hit.value),
                    count=hit.alerts,
                    level=tenant.high_level,
                    window=window,
                ),
                "investigate",
            )
        )
    if facts.co_index_truncated:
        out.append(GateOutcome("co_occurrence", False, M("noise.reason.co_occurrence_truncated"), "investigate"))
    if not out:
        out.append(
            GateOutcome(
                "co_occurrence", True, M("noise.reason.no_co_occurrence", level=tenant.high_level, window=window)
            )
        )
    return out


def _gate_beacon(facts: CandidateFacts) -> list[GateOutcome]:
    return [GateOutcome("beacon", False, beacon_message(hit), "investigate") for hit in facts.beacons]


def beacon_message(hit: BeaconHit) -> Message:
    """Why a public address with sustained activity blocks tuning (beaconing only when outbound and periodic)."""
    params = {"entity": Entity("ip", hit.value), "active": hit.active_hours, "span": hit.span_hours}
    if hit.beacon:
        return M("noise.reason.beacon", **params, regularity=hit.regularity or 0.0)
    return M("noise.reason.sustained_to" if hit.outbound else "noise.reason.sustained_from", **params)


def trusted_internal_anchor(facts: CandidateFacts) -> bool:
    """The candidate is anchored on internal infrastructure AND on a trusted entity or service account, and
    nothing attacker-controlled or public is part of it."""
    if not facts.conditions:
        return False
    if any(c.cls.attacker or c.cls.external for c in facts.conditions):
        return False
    if any(c.item is not None and c.item.role in IP_ROLES and not c.cls.internal for c in facts.conditions):
        return False
    return any(c.cls.trusted for c in facts.conditions)


def _gate_sensitive(facts: CandidateFacts, settings: NoiseSettings) -> list[GateOutcome]:
    tactics = sensitive_tactics(facts.tactics, settings)
    if not tactics and not facts.process_creation:
        return [GateOutcome("sensitive", True, M("noise.reason.not_sensitive"))]
    counts = facts.dispositions
    lower = counts.fp_lower_bound(settings.disposition_confidence, settings.min_dispositions)
    anchored = trusted_internal_anchor(facts)
    what: Message | str = ", ".join(tactics)
    if facts.process_creation:
        what = M("noise.label.tactics_and_process", tactics=what) if tactics else M("noise.label.process_creation")
    params: dict[str, Any] = {
        "tactics": what,
        "fp": lower if lower is not None else 0.0,
        "n": counts.triaged,
        "min_n": settings.min_dispositions,
        "min_fp": FP_EVIDENCE_MIN,
    }
    evidence_ok = lower is not None and lower >= FP_EVIDENCE_MIN and not counts.tp
    if anchored and evidence_ok:
        return [GateOutcome("sensitive", True, M("noise.reason.sensitive_ok", **params))]
    evidence = evidence_gap(counts, lower, settings)
    if not anchored:
        missing = anchor_gap(facts)
        if evidence is not None:
            missing = M("noise.reason.and", first=missing, second=evidence)
        return [
            GateOutcome(
                "sensitive", False, M("noise.reason.sensitive_anchor", **params, missing=missing), "investigate"
            )
        ]
    trusted = [c for c in facts.conditions if c.cls.trusted]
    named_only = all(c.cls.chosen for c in trusted)
    anchor_key = "noise.reason.anchor_named" if named_only else "noise.reason.anchor_trusted"
    anchor = M(anchor_key, field=trusted[0].field if trusted else "?")
    missing_evidence = evidence if evidence is not None else M("noise.evidence.missing")
    return [
        GateOutcome(
            "sensitive",
            False,
            M("noise.reason.sensitive_evidence", **params, anchor=anchor, missing=missing_evidence),
            "investigate",
        )
    ]


def anchor_gap(facts: CandidateFacts) -> Message:
    """What keeps the scope from being a trusted internal anchor (for the sensitive-rule reason)."""
    conds = facts.conditions
    if not conds:
        return M("noise.missing.rule_wide")
    public = [c.field for c in conds if c.cls.external]
    if public:
        return M("noise.missing.public", fields=", ".join(dict.fromkeys(public)))
    chosen = [c.field for c in conds if c.cls.attacker]
    if chosen:
        return M("noise.missing.attacker", fields=", ".join(dict.fromkeys(chosen)))
    not_internal = [c.field for c in conds if c.item is not None and c.item.role in IP_ROLES and not c.cls.internal]
    if not_internal:
        return M("noise.missing.not_internal", fields=", ".join(dict.fromkeys(not_internal)))
    return M("noise.missing.not_trusted", fields=", ".join(dict.fromkeys(c.field for c in conds)))


def evidence_gap(counts: DispositionCounts, lower: float | None, settings: NoiseSettings) -> Message | None:
    """What is missing from the triage evidence (None: FP evidence is sufficient and there is no TP)."""
    if counts.tp:
        return M("noise.evidence.tp", tp=counts.tp)
    if lower is None:
        return M("noise.evidence.too_few", n=counts.triaged, min_n=settings.min_dispositions, min_fp=FP_EVIDENCE_MIN)
    if lower < FP_EVIDENCE_MIN:
        return M("noise.evidence.low_fp", fp=lower, n=counts.triaged, min_fp=FP_EVIDENCE_MIN)
    return None


def _gate_attacker_evidence(facts: CandidateFacts, settings: NoiseSettings) -> list[GateOutcome]:
    """A scope that relies on a value an attacker can choose (a command line, a file name, a URL, a binary in a
    user-writable folder, a human account) is exactly what suppression poisoning seeds for weeks: it is tuned only
    with triage evidence (FP lower bound >= FP_EVIDENCE_MIN, n >= min_dispositions, no true positive)."""
    chosen = [c for c in facts.conditions if (c.cls.attacker or c.cls.chosen) and not c.cls.external]
    if not chosen:
        return []
    counts = facts.dispositions
    lower = counts.fp_lower_bound(settings.disposition_confidence, settings.min_dispositions)
    params: dict[str, Any] = {
        "field": chosen[0].field,
        "fp": lower if lower is not None else 0.0,
        "n": counts.triaged,
        "min_n": settings.min_dispositions,
        "min_fp": FP_EVIDENCE_MIN,
    }
    if lower is not None and lower >= FP_EVIDENCE_MIN and not counts.tp:
        return [GateOutcome("attacker_field", True, M("noise.reason.attacker_field_ok", **params))]
    missing = evidence_gap(counts, lower, settings) or M("noise.evidence.missing")
    # an account that only LOOKS like a service account (name pattern) is not attacker-chosen: say so
    key = "noise.reason.attacker_field" if chosen[0].cls.attacker else "noise.reason.named_account"
    return [GateOutcome("attacker_field", False, M(key, **params, missing=missing), "investigate")]


def _gate_external(facts: CandidateFacts) -> list[GateOutcome]:
    out = [
        GateOutcome("external", False, M("noise.reason.external", entity=Entity("ip", c.value)), "fix_at_source")
        for c in facts.conditions
        if c.cls.external
    ]
    share = facts.external_share
    if share is not None and share >= EXPOSURE_SHARE:
        # muting a host (or a whole rule) for traffic that mostly comes from the Internet hides Internet attacks
        key = "noise.reason.external_share_all" if share >= 0.995 else "noise.reason.external_share"
        out.append(GateOutcome("external", False, M(key, share=share, min=EXPOSURE_SHARE), "fix_at_source"))
    return out


def _gate_source_fix(facts: CandidateFacts) -> list[GateOutcome]:
    if facts.fim:
        return [GateOutcome("fim", False, M("noise.reason.fim"), "fix_at_source")]
    if facts.check:
        return [GateOutcome("check", False, M("noise.reason.check"), "fix_at_source")]
    return []


def _gate_dependents(facts: CandidateFacts) -> list[GateOutcome]:
    if facts.dependents_error:
        return [GateOutcome("dependents", False, M("noise.reason.dependents_error", rule=facts.rule_id))]
    out: list[GateOutcome] = []
    if facts.dependents:
        out.append(
            GateOutcome(
                "dependents",
                False,
                M("noise.reason.dependents", rule=facts.rule_id, dependents=", ".join(facts.dependents)),
            )
        )
    if facts.dependents_unverified is not None:
        # "nothing correlates on it" cannot be claimed without the stock correlation rules: review, never a pass
        key = f"noise.reason.dependents_{facts.dependents_unverified}"
        out.append(GateOutcome("dependents", False, M(key, rule=facts.rule_id)))
        return out
    if out:
        return out
    if facts.dependents is None:
        return [GateOutcome("dependents", True, M("noise.reason.dependents_unknown"))]
    return [GateOutcome("dependents", True, M("noise.reason.no_dependents", rule=facts.rule_id))]


def _ts_label(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _hours_label(seconds: float) -> str:
    hours = seconds / 3600
    return f"{hours:g}h"


register(
    {
        "noise.reason.learning": {
            "en": "Only {days} {days:plural:day|days} of data (at least {min} needed): no tuning verdict yet",
            "es": "Solo hay {days} {days:plural:día|días} de datos (se necesitan al menos {min}): todavía no "
            "hay veredicto",
        },
        "noise.reason.share": {
            "en": "Explains {share:.0%} of the rule's {total} {total:plural:alert|alerts} (at least {lower} "
            "{lower:plural:alert|alerts}; minimum share {min:.0%})",
            "es": "Explica el {share:.0%} de {total:plural:la única alerta|las {total} alertas} de la regla "
            "(al menos {lower} {lower:plural:alerta|alertas}; mínimo {min:.0%})",
        },
        "noise.reason.level_ok": {
            "en": "Rule level {level} is within the tunable maximum ({max})",
            "es": "El nivel {level} de la regla está dentro del máximo ajustable ({max})",
        },
        "noise.reason.level_blocked": {
            "en": "Rule level {level} is above the tunable maximum ({max}): never tuned",
            "es": "El nivel {level} de la regla supera el máximo ajustable ({max}): nunca se ajusta",
        },
        "noise.reason.level_unknown": {
            "en": "Rule level unknown: cannot confirm it is within the tunable maximum ({max})",
            "es": "Nivel de la regla desconocido: no se puede confirmar que esté dentro del máximo ajustable ({max})",
        },
        "noise.reason.tp": {
            "en": "{tp} true-positive {tp:plural:disposition|dispositions} on this scope in the last {days} days",
            "es": "{tp} {tp:plural:disposición|disposiciones} de verdadero positivo en este alcance en los "
            "últimos {days} días",
        },
        "noise.reason.tp_rule_wide": {
            "en": "{tp} true-positive {tp:plural:disposition covers|dispositions cover} the whole rule in the "
            "last {days} days",
            "es": "{tp} {tp:plural:disposición|disposiciones} de verdadero positivo {tp:plural:cubre|cubren} "
            "toda la regla en los últimos {days} días",
        },
        "noise.reason.no_tp": {
            "en": "No true-positive dispositions on this scope in the last {days} days",
            "es": "Sin disposiciones de verdadero positivo en este alcance en los últimos {days} días",
        },
        "noise.reason.no_dispositions": {
            "en": "No dispositions loaded: without triage history, true positives on this scope cannot be ruled out",
            "es": "No se cargaron disposiciones: sin historial de triaje no se pueden descartar verdaderos "
            "positivos en este alcance",
        },
        "noise.reason.novel": {
            "en": "First seen {first}, after the first {fraction:.0%} of the window: new activity is investigated, "
            "not tuned",
            "es": "Visto por primera vez el {first}, después del primer {fraction:.0%} de la ventana: la actividad "
            "nueva se investiga, no se ajusta",
        },
        "noise.reason.established": {
            "en": "First seen {first}, within the first {fraction:.0%} of the window",
            "es": "Visto por primera vez el {first}, dentro del primer {fraction:.0%} de la ventana",
        },
        "noise.reason.not_persistent": {
            "en": "Present on {present} of {days} days ({ratio:.0%}, below {min:.0%}): not persistent",
            "es": "Presente en {present} de {days} días ({ratio:.0%}, por debajo de {min:.0%}): no es persistente",
        },
        "noise.reason.persistent": {
            "en": "Present on {present} of {days} days ({ratio:.0%}, minimum {min:.0%})",
            "es": "Presente en {present} de {days} días ({ratio:.0%}, mínimo {min:.0%})",
        },
        "noise.reason.burst": {
            "en": "Burst: {peak} {peak:plural:alert|alerts} on {day}, {factor:.1f}× the median of "
            "{median:.1f} per day (limit {limit:.1f}×)",
            "es": "Pico: {peak} {peak:plural:alerta|alertas} el {day}, {factor:.1f}× la mediana de "
            "{median:.1f} por día (límite {limit:.1f}×)",
        },
        "noise.reason.no_burst": {
            "en": "No burst: busiest day {day} with {peak} {peak:plural:alert|alerts}, {factor:.1f}× the "
            "median of {median:.1f} (limit {limit:.1f}×)",
            "es": "Sin picos: el día de más volumen ({day}) tuvo {peak} {peak:plural:alerta|alertas}, "
            "{factor:.1f}× la mediana de {median:.1f} (límite {limit:.1f}×)",
        },
        "noise.reason.co_occurrence": {
            "en": "{entity} also appears in {count} {count:plural:alert|alerts} at level {level} or higher "
            "within ±{window}",
            "es": "{entity} también aparece en {count} {count:plural:alerta|alertas} de nivel {level} o "
            "superior dentro de ±{window}",
        },
        "noise.reason.co_occurrence_truncated": {
            "en": "The high-level alert index hit its size cap: co-occurrence with high alerts cannot be ruled out",
            "es": "El índice de alertas de nivel alto alcanzó su límite: no se puede descartar la coincidencia con "
            "alertas altas",
        },
        "noise.reason.no_co_occurrence": {
            "en": "No anchor value appears in alerts at level {level} or higher within ±{window}",
            "es": "Ningún valor ancla aparece en alertas de nivel {level} o superior dentro de ±{window}",
        },
        "noise.reason.beacon": {
            "en": "Connections to the public address {entity} recur at a steady interval ({regularity:.0%} of the "
            "gaps between them are about the same) in {active} of the {span} hours between its first and last "
            "activity: this looks like beaconing (command and control)",
            "es": "Las conexiones a la dirección pública {entity} se repiten a intervalos regulares (el "
            "{regularity:.0%} de las pausas entre ellas son casi iguales) en {active} de las {span} horas entre su "
            "primera y su última actividad: parece beaconing (comando y control)",
        },
        "noise.reason.sustained_to": {
            "en": "Traffic to the public address {entity} is active in {active} of the {span} hours between its "
            "first and last activity: sustained traffic to the Internet is investigated, not tuned",
            "es": "El tráfico hacia la dirección pública {entity} está activo en {active} de las {span} horas entre "
            "su primera y su última actividad: el tráfico sostenido hacia Internet se investiga, no se ajusta",
        },
        "noise.reason.sustained_from": {
            "en": "The public address {entity} is active in {active} of the {span} hours between its first and last "
            "activity: sustained activity from the Internet (a scan, brute force or password spray) is "
            "investigated, not tuned",
            "es": "La dirección pública {entity} está activa en {active} de las {span} horas entre su primera y su "
            "última actividad: la actividad sostenida desde Internet (un escaneo, fuerza bruta o password spray) "
            "se investiga, no se ajusta",
        },
        "noise.label.process_creation": {"en": "process creation", "es": "creación de procesos"},
        "noise.label.tactics_and_process": {
            "en": "{tactics} and process creation",
            "es": "{tactics} y creación de procesos",
        },
        "noise.reason.not_sensitive": {
            "en": "No sensitive ATT&CK tactic on this rule, and it is not a process-creation rule",
            "es": "La regla no tiene tácticas ATT&CK sensibles y no es una regla de creación de procesos",
        },
        "noise.reason.sensitive_ok": {
            "en": "Sensitive rule ({tactics}), but the scope is anchored on trusted internal infrastructure and "
            "dispositions show FP ≥ {fp:.0%} (n={n})",
            "es": "Regla sensible ({tactics}), pero el alcance está anclado en infraestructura interna de confianza y "
            "las disposiciones muestran FP ≥ {fp:.0%} (n={n})",
        },
        "noise.reason.sensitive_anchor": {
            "en": "Sensitive rule ({tactics}): tuning it needs a trusted internal anchor (a configured trusted "
            "entity or a service account, nothing attacker-controlled) plus FP evidence (FP ≥ {min_fp:.0%} with "
            "n ≥ {min_n}). Missing: {missing}",
            "es": "Regla sensible ({tactics}): para ajustarla hace falta un ancla interna de confianza (una entidad "
            "de confianza configurada o una cuenta de servicio, nada controlable por un atacante) más evidencia de "
            "FP (FP ≥ {min_fp:.0%} con n ≥ {min_n}). Falta: {missing}",
        },
        "noise.reason.sensitive_evidence": {
            "en": "Sensitive rule ({tactics}): the scope is anchored on {anchor}, but tuning it also needs FP "
            "evidence (FP ≥ {min_fp:.0%} with n ≥ {min_n} and no true positives). Missing: {missing}",
            "es": "Regla sensible ({tactics}): el alcance está anclado en {anchor}, pero para ajustarla también hace "
            "falta evidencia de FP (FP ≥ {min_fp:.0%} con n ≥ {min_n} y ningún verdadero positivo). Falta: {missing}",
        },
        "noise.reason.anchor_trusted": {
            "en": "{field}, a trusted internal entity",
            "es": "{field}, una entidad interna de confianza",
        },
        "noise.reason.anchor_named": {
            "en": "{field}, an account that looks like a service account by its name only (it is not listed in "
            "trusted_entities)",
            "es": "{field}, una cuenta que parece de servicio solo por su nombre (no figura en trusted_entities)",
        },
        "noise.reason.and": {"en": "{first}; {second}", "es": "{first}; {second}"},
        "noise.missing.rule_wide": {
            "en": "the scope is the whole rule, with no anchor at all",
            "es": "el alcance es toda la regla, sin ningún ancla",
        },
        "noise.missing.public": {
            "en": "{fields} is a public address",
            "es": "{fields} es una dirección pública",
        },
        "noise.missing.attacker": {
            "en": "{fields} can be chosen by an attacker",
            "es": "{fields} puede ser elegido por un atacante",
        },
        "noise.missing.not_internal": {
            "en": "{fields} is not an internal address",
            "es": "{fields} no es una dirección interna",
        },
        "noise.missing.not_trusted": {
            "en": "none of {fields} is a configured trusted entity or a service account (list it in "
            "trusted_entities to vouch for it)",
            "es": "ninguno de {fields} es una entidad de confianza configurada ni una cuenta de servicio (inclúyalo "
            "en trusted_entities para avalarlo)",
        },
        "noise.evidence.tp": {
            "en": "a clean triage record ({tp} {tp:plural:alert|alerts} in this scope {tp:plural:was|were} "
            "confirmed as true positives)",
            "es": "un historial de triaje limpio ({tp} {tp:plural:alerta|alertas} de este alcance se "
            "{tp:plural:confirmó|confirmaron} como verdaderos positivos)",
        },
        "noise.evidence.too_few": {
            "en": "triage evidence: only {n} triaged {n:plural:alert|alerts} in this scope, at least {min_n} "
            "needed to measure FP ≥ {min_fp:.0%}",
            "es": "evidencia de triaje: solo {n} {n:plural:alerta triada|alertas triadas} en este alcance, se "
            "necesitan al menos {min_n} para medir FP ≥ {min_fp:.0%}",
        },
        "noise.evidence.low_fp": {
            "en": "enough false positives: dispositions show FP ≥ {fp:.0%} (n={n}), below the required {min_fp:.0%}",
            "es": "suficientes falsos positivos: las disposiciones muestran FP ≥ {fp:.0%} (n={n}), por debajo del "
            "{min_fp:.0%} requerido",
        },
        "noise.evidence.missing": {"en": "triage evidence", "es": "evidencia de triaje"},
        "noise.reason.attacker_field": {
            "en": "The scope relies on {field}, a value an attacker can choose and could seed for weeks to get it "
            "tuned: it needs FP ≥ {min_fp:.0%} with n ≥ {min_n} and no true positives. Missing: {missing}",
            "es": "El alcance depende de {field}, un valor que un atacante puede elegir y sembrar durante semanas "
            "para que se ajuste: necesita FP ≥ {min_fp:.0%} con n ≥ {min_n} y ningún verdadero positivo. "
            "Falta: {missing}",
        },
        "noise.reason.named_account": {
            "en": "The scope relies on {field}, an account trusted only because its name looks like a service "
            "account (whoever creates accounts picks their names; list it in trusted_entities to vouch for it): it "
            "needs FP ≥ {min_fp:.0%} with n ≥ {min_n} and no true positives. Missing: {missing}",
            "es": "El alcance depende de {field}, una cuenta considerada de confianza solo porque su nombre parece "
            "de cuenta de servicio (quien crea cuentas elige sus nombres; inclúyala en trusted_entities para "
            "avalarla): necesita FP ≥ {min_fp:.0%} con n ≥ {min_n} y ningún verdadero positivo. Falta: {missing}",
        },
        "noise.reason.attacker_field_ok": {
            "en": "The scope relies on {field}, a value nobody vouched for, but dispositions show FP ≥ {fp:.0%} "
            "(n={n})",
            "es": "El alcance depende de {field}, un valor que nadie avaló, pero las disposiciones muestran "
            "FP ≥ {fp:.0%} (n={n})",
        },
        "noise.reason.external": {
            "en": "{entity} is a public address: restrict the exposure at the source instead of muting the alert",
            "es": "{entity} es una dirección pública: restrinja la exposición en el origen en lugar de silenciar "
            "la alerta",
        },
        "noise.reason.external_share": {
            "en": "At least {share:.0%} of these alerts come from public addresses (limit {min:.0%}): restrict the "
            "exposure instead of muting the host",
            "es": "Al menos el {share:.0%} de estas alertas proviene de direcciones públicas (límite {min:.0%}): "
            "restrinja la exposición en lugar de silenciar el equipo",
        },
        "noise.reason.external_share_all": {
            "en": "All of these alerts come from public addresses: restrict the exposure instead of muting the host",
            "es": "Todas estas alertas provienen de direcciones públicas: restrinja la exposición en lugar de "
            "silenciar el equipo",
        },
        "noise.reason.fim": {
            "en": "File-integrity (syscheck) noise: ignore the path in agent.conf instead of muting the rule",
            "es": "Ruido de integridad de archivos (syscheck): ignore la ruta en agent.conf en lugar de silenciar "
            "la regla",
        },
        "noise.reason.check": {
            "en": "Rootcheck/SCA noise: fix the check or the host configuration instead of muting the rule",
            "es": "Ruido de rootcheck/SCA: corrija el chequeo o la configuración del equipo en lugar de silenciar "
            "la regla",
        },
        "noise.reason.aggregate": {
            "en": "Duplicate ratio {dup:.0%} ({clusters} clusters for {alerts} alerts, threshold {min:.0%}): "
            "aggregate with frequency/timeframe instead of muting",
            "es": "Proporción de duplicados {dup:.0%} ({clusters} grupos para {alerts} alertas, umbral {min:.0%}): "
            "agregue con frequency/timeframe en lugar de silenciar",
        },
        "noise.reason.dependents": {
            "en": "Rule {rule} feeds correlation rules ({dependents}): review required. Those rules may stop "
            "counting demoted events (copying the parent's groups into the child does not keep "
            "if_matched_group rules counting them); validate with wazuh-logtest",
            "es": "La regla {rule} alimenta reglas de correlación ({dependents}): requiere revisión. Esas "
            "reglas pueden dejar de contar los eventos degradados (copiar los grupos de la regla padre "
            "en la hija no mantiene el conteo de las reglas if_matched_group); valide con wazuh-logtest",
        },
        "noise.reason.dependents_error": {
            "en": "Could not determine which rules correlate on rule {rule}: review required",
            "es": "No se pudo determinar qué reglas correlacionan sobre la regla {rule}: requiere revisión",
        },
        "noise.reason.dependents_unknown": {
            "en": "No Wazuh ruleset applies to this data: correlation dependencies were not checked",
            "es": "No hay un ruleset de Wazuh aplicable a estos datos: no se verificaron las dependencias de "
            "correlación",
        },
        "noise.reason.dependents_no_stock": {
            "en": "Stock ruleset not loaded: correlation dependencies of rule {rule} were not verified (the stock "
            "correlation rules live in /var/ossec/ruleset/rules): review required. Pass --ruleset "
            "/var/ossec/ruleset/rules --ruleset /var/ossec/etc/rules",
            "es": "Ruleset de fábrica no cargado: no se verificaron las dependencias de correlación de la regla "
            "{rule} (las reglas de correlación de fábrica están en /var/ossec/ruleset/rules): requiere revisión. "
            "Use --ruleset /var/ossec/ruleset/rules --ruleset /var/ossec/etc/rules",
        },
        "noise.reason.dependents_no_ruleset": {
            "en": "Wazuh ruleset not loaded: correlation dependencies of rule {rule} were not verified: review "
            "required. Pass --ruleset /var/ossec/ruleset/rules --ruleset /var/ossec/etc/rules",
            "es": "Ruleset de Wazuh no cargado: no se verificaron las dependencias de correlación de la regla "
            "{rule}: requiere revisión. Use --ruleset /var/ossec/ruleset/rules --ruleset /var/ossec/etc/rules",
        },
        "noise.reason.no_dependents": {
            "en": "No loaded rule correlates on rule {rule}",
            "es": "Ninguna regla cargada correlaciona sobre la regla {rule}",
        },
    }
)
