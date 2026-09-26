"""Normalization profiles: one raw SIEM document in, one :class:`~hushwatch.models.Event` out.

Profiles
--------
``wazuh4``
    Wazuh 4.x ``alerts.json`` / ``archives.json`` lines and ``wazuh-alerts-*`` / ``wazuh-archives-*`` indexer
    documents (nested) or dashboard CSV exports (flat dotted columns). ``timestamp`` is the manager processing
    time. ``rule.id`` is a string and ``rule.level`` a number; archives documents have no ``rule`` object.
``wazuh5``
    Wazuh 5.x (Wazuh Common Schema, ECS-based, ``wazuh.*`` namespace). Best effort: 5.x is not GA and its field
    layout is not verified, so the ingest layer adds a DataBasis warning and suppression output is refused.
``ecs``
    Elastic Common Schema events and Elastic Security alerts (``kibana.alert.*``), nested or with flat dotted
    keys as stored in ``.alerts-security.alerts-*``.
``generic``
    Anything else, driven by ``InputConfig.mapping`` (``{our_field: "dotted.source.path"}``, ``a|b`` for
    alternatives) with conservative name heuristics for unmapped fields.

Every value read here comes from logs and is attacker-controlled: nothing in this module raises on odd shapes
(lists where scalars are expected, NaN, huge numbers, deep nesting is bounded) and ``normalize`` returns
``None`` only when the timestamp cannot be parsed, so the caller can COUNT it.
"""

from __future__ import annotations

import functools
import ipaddress
import math
import re
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, tzinfo
from typing import Any, Final
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from ..config import InputConfig, TenantConfig
from ..models import Event, is_empty
from ..timeutil import UTC, parse_ts

PROFILES: Final[tuple[str, ...]] = ("wazuh4", "wazuh5", "ecs", "generic")
DETECT_SAMPLE: Final = 64  # documents inspected by detect_profile
MAX_LIST_ITEMS: Final = 64  # cap for tags / rule groups / tactics per event (hostile documents)
MAX_ENTITY_CHARS: Final = 32_768  # longer entity values are truncated (Windows command lines max out at 32767)
ENTITY_NAMES: Final[tuple[str, ...]] = (
    "src_ip",
    "dst_ip",
    "user",
    "host",
    "process",
    "parent_process",
    "command_line",
    "file",
    "url",
    "domain",
)
_MAX_RESOLVE_DEPTH: Final = 24
_MAX_RESOLVE_VALUES: Final = 256


# ---- dotted-path resolution -----------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _Path:
    text: str
    parts: tuple[str, ...]


@functools.lru_cache(maxsize=4096)
def _path(text: str) -> _Path:
    return _Path(text, tuple(text.split(".")))


def _paths(*texts: str) -> tuple[_Path, ...]:
    return tuple(_path(t) for t in texts)


class _Doc:
    """Read dotted paths from a document that may be nested (``{"rule": {"id": ...}}``), flat
    (``{"rule.id": ...}``, CSV and Elastic alert documents) or a mix of both, through lists of objects.

    Nested documents without dotted keys (every Wazuh alert) take a fast path of plain dict lookups.
    When ``track`` is set, every path that produced a value is recorded (projection keeps those keys).
    """

    __slots__ = ("_lower", "doc", "heads", "used")

    def __init__(self, doc: dict[str, Any], track: bool = False) -> None:
        self.doc = doc
        heads: set[str] | None = None
        for key in doc:
            if isinstance(key, str) and "." in key:
                heads = {k.split(".", 1)[0] for k in doc if isinstance(k, str)}
                break
        self.heads = heads  # None => no dotted top-level keys (fast path)
        self.used: list[str] | None = [] if track else None
        self._lower: dict[str, str] | None = None

    def has_namespace(self, name: str) -> bool:
        value = self.doc.get(name)
        if isinstance(value, dict) and value:
            return True
        return (
            self.heads is not None
            and name in self.heads
            and any(isinstance(k, str) and k.startswith(name + ".") for k in self.doc)
        )

    def raw(self, path: _Path) -> Any:
        """First value found at ``path`` (scalar, list or dict), or None."""
        value = self._lookup(path)
        if value is not None and self.used is not None:
            self.used.append(path.text)
        return value

    def all(self, path: _Path) -> list[Any]:
        """Every scalar found at ``path`` (lists are expanded, lists of objects are traversed)."""
        out: list[Any] = []
        if self.heads is None:
            node: Any = self.doc
            for index, part in enumerate(path.parts):
                if isinstance(node, dict):
                    node = node.get(part)
                    if node is None:
                        return out
                elif isinstance(node, list):
                    _resolve(node, path.parts, index, out, True, False, 0, _MAX_RESOLVE_VALUES)
                    break
                else:
                    return out
            else:
                _emit(node, out, True, 0, _MAX_RESOLVE_VALUES)
        else:
            _resolve(self.doc, path.parts, 0, out, True, True, 0, _MAX_RESOLVE_VALUES)
        if out and self.used is not None:
            self.used.append(path.text)
        return out

    def ci(self, name: str) -> Any:
        """Case-insensitive lookup of a TOP-LEVEL key (CSV headers vary in case)."""
        if self._lower is None:
            self._lower = {k.lower(): k for k in self.doc if isinstance(k, str)}
        key = self._lower.get(name.lower())
        if key is None:
            return None
        value = self.doc.get(key)
        if value is not None and self.used is not None:
            self.used.append(key)
        return value

    def _lookup(self, path: _Path) -> Any:
        doc = self.doc
        if self.heads is None:
            node: Any = doc
            for index, part in enumerate(path.parts):
                if isinstance(node, dict):
                    node = node.get(part)
                    if node is None:
                        return None
                elif isinstance(node, list):
                    found: list[Any] = []
                    _resolve(node, path.parts, index, found, False, False, 0, 1)
                    return found[0] if found else None
                else:
                    return None
            return node
        value = doc.get(path.text)
        if value is not None:
            return value
        if path.parts[0] not in self.heads:
            return None
        found = []
        _resolve(doc, path.parts, 0, found, False, True, 0, 1)
        return found[0] if found else None


def _emit(node: Any, out: list[Any], expand: bool, depth: int, limit: int) -> None:
    if node is None:
        return
    if expand and isinstance(node, list):
        for item in node:
            if len(out) >= limit:
                return
            if isinstance(item, list):
                if depth < _MAX_RESOLVE_DEPTH:
                    _emit(item, out, expand, depth + 1, limit)
            elif item is not None and not isinstance(item, dict):
                out.append(item)
    else:
        out.append(node)


def _resolve(
    node: Any, parts: tuple[str, ...], i: int, out: list[Any], expand: bool, dotted: bool, depth: int, limit: int
) -> None:
    """Collect values at ``parts[i:]`` below ``node`` into ``out`` (bounded depth and count)."""
    if len(out) >= limit or depth > _MAX_RESOLVE_DEPTH:
        return
    n = len(parts)
    if i >= n:
        _emit(node, out, expand, depth, limit)
        return
    if isinstance(node, dict):
        if not dotted:
            sub = node.get(parts[i])
            if sub is not None:
                _resolve(sub, parts, i + 1, out, expand, dotted, depth + 1, limit)
            return
        for j in range(n, i, -1):  # longest dotted key first: {"a.b": ...} before {"a": {"b": ...}}
            key = parts[i] if j == i + 1 else ".".join(parts[i:j])
            sub = node.get(key)
            if sub is not None:
                _resolve(sub, parts, j, out, expand, dotted, depth + 1, limit)
                if len(out) >= limit:
                    return
    elif isinstance(node, list):
        for item in node:
            if isinstance(item, (dict, list)):
                _resolve(item, parts, i, out, expand, dotted, depth + 1, limit)
                if len(out) >= limit:
                    return


# ---- scalar helpers -------------------------------------------------------------------------------------------


# The strings hushwatch.models.is_empty treats as "no information" (checked after strip()).
_EMPTY_TEXT: Final = frozenset(("", "-", "null", "NULL", "(NULL)", "None", "N/A", "n/a", "unknown"))


def _text(value: Any) -> str | None:
    """A scalar as text, or None when missing / empty (``""``, ``-``, ``(NULL)``...) / not a scalar."""
    if type(value) is str:
        return None if value.strip() in _EMPTY_TEXT else value
    if value is None:
        return None
    if isinstance(value, str):
        return None if is_empty(value) else value
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        try:
            return str(value)
        except ValueError:  # beyond the int->str digit limit
            return None
    if isinstance(value, float):
        if not math.isfinite(value):
            return None
        return str(int(value)) if value.is_integer() and abs(value) < 1e18 else repr(value)
    if isinstance(value, list):
        for item in value[:MAX_LIST_ITEMS]:
            if not isinstance(item, (list, dict)):
                text = _text(item)
                if text is not None:
                    return text
    return None


def _entity(value: str | None) -> str | None:
    if value is None:
        return None
    return value if len(value) <= MAX_ENTITY_CHARS else value[:MAX_ENTITY_CHARS]


def _pieces(value: Any) -> list[str]:
    """Split a scalar into non-empty items (``"a, b"`` -> ``["a", "b"]``, CSV exports join lists)."""
    text = _text(value)
    if text is None:
        return []
    if "," in text:
        return [p.strip() for p in text.split(",") if p.strip()]
    return [text.strip()] if text.strip() else []


def _clean_strings(value: Any) -> list[str] | None:
    """``value`` when it is a list of plain strings that need no splitting/stripping (the common case)."""
    if type(value) is not list or len(value) > MAX_LIST_ITEMS:
        return None
    for item in value:
        if type(item) is not str or "," in item or item.strip() != item or item in _EMPTY_TEXT:
            return None
    return value


def _strs(value: Any) -> tuple[str, ...]:
    """Distinct non-empty strings of a raw value (list or comma-joined text), in order, capped."""
    clean = _clean_strings(value)
    if clean is not None:
        return tuple(dict.fromkeys(clean))
    return _str_tuple(_many(value))


def _str_tuple(values: Iterable[Any]) -> tuple[str, ...]:
    out: list[str] = []
    for value in values:
        for piece in _pieces(value):
            if piece not in out:
                out.append(piece)
                if len(out) >= MAX_LIST_ITEMS:
                    return tuple(out)
    return tuple(out)


_TECHNIQUE: Final = re.compile(r"(?:attack\.)?(t\d{4}(?:\.\d{3})?)", re.IGNORECASE)
_TAG_TACTIC: Final = re.compile(r"attack\.([a-z][a-z_-]*[a-z])", re.IGNORECASE)


def _techniques(values: Iterable[Any]) -> tuple[str, ...]:
    """MITRE ATT&CK technique ids (``T1110``, ``T1110.001``), also from Sigma-style ``attack.t1110.001`` tags."""
    out: list[str] = []
    for value in values:
        for piece in (value,) if type(value) is str and "," not in value else _pieces(value):
            match = _TECHNIQUE.fullmatch(piece.strip())
            if match:
                technique = match.group(1).upper()
                if technique not in out:
                    out.append(technique)
                    if len(out) >= MAX_LIST_ITEMS:
                        return tuple(out)
    return tuple(out)


def _tag_tactics(values: Iterable[Any]) -> list[str]:
    """Tactic shortnames from Sigma-style tags (``attack.credential-access``)."""
    out: list[str] = []
    for value in values:
        for piece in _pieces(value):
            match = _TAG_TACTIC.fullmatch(piece)
            if match:
                out.append(match.group(1).lower().replace("_", "-"))
    return out


def _merge(*groups: Iterable[str]) -> tuple[str, ...]:
    out: list[str] = []
    for group in groups:
        for item in group:
            if item not in out:
                out.append(item)
                if len(out) >= MAX_LIST_ITEMS:
                    return tuple(out)
    return tuple(out)


_SEVERITY_NAMES: Final[dict[str, int]] = {
    "informational": 2,
    "information": 2,
    "info": 2,
    "low": 3,
    "medium": 7,
    "moderate": 7,
    "high": 10,
    "critical": 13,
}


def _number(value: Any) -> float | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return float(value) if abs(value) < 1e18 else None
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, str):
        text = value.strip()
        if not text or len(text) > 32:
            return None
        try:
            number = float(text)
        except ValueError:
            return None
        return number if math.isfinite(number) else None
    if isinstance(value, list) and value:
        return _number(value[0])
    return None


def _clamp_level(number: float) -> int:
    return max(0, min(16, int(number)))


def _level(value: Any) -> int | None:
    """Wazuh-scale level (0-16) from a number, a numeric string or a severity name."""
    if type(value) is int:  # every Wazuh alert: rule.level is a JSON integer
        return 0 if value < 0 else 16 if value > 16 else value
    if isinstance(value, str) and value.strip().lower() in _SEVERITY_NAMES:
        return _SEVERITY_NAMES[value.strip().lower()]
    number = _number(value)
    return None if number is None else _clamp_level(number)


def _risk_level(score: float) -> int:
    """Elastic risk score (0-100) buckets: low <= 21 < medium <= 47 < high <= 73 < critical."""
    if score <= 21:
        return 3
    if score <= 47:
        return 7
    if score <= 73:
        return 10
    return 13


def _level_or_risk(value: Any) -> int | None:
    """Numbers <= 16 are taken as Wazuh-scale levels, larger ones as 0-100 risk scores; names are mapped."""
    if isinstance(value, str) and value.strip().lower() in _SEVERITY_NAMES:
        return _SEVERITY_NAMES[value.strip().lower()]
    number = _number(value)
    if number is None or number < 0:
        return None
    return _clamp_level(number) if number <= 16 else _risk_level(min(number, 100.0))


_LINUX_NAMES: Final = frozenset(
    {
        "linux",
        "ubuntu",
        "debian",
        "centos",
        "rhel",
        "redhat",
        "fedora",
        "amzn",
        "amazon",
        "suse",
        "opensuse",
        "sles",
        "alpine",
        "arch",
        "oracle",
        "ol",
        "rocky",
        "almalinux",
        "kali",
        "gentoo",
        "raspbian",
    }
)


def _platform_name(value: str | None) -> str | None:
    if not value:
        return None
    name = value.strip().lower()
    if "windows" in name or name in ("win", "win32", "win64"):
        return "windows"
    if name in ("darwin", "macos", "osx", "mac os x", "macosx", "mac"):
        return "darwin"
    if name in _LINUX_NAMES or "linux" in name:
        return "linux"
    if name in ("network", "firewall", "router", "switch"):
        return "network"
    return None


_DRIVE: Final = re.compile(r"^[A-Za-z]:[\\/]")
_WINDOWS_CHANNEL: Final = re.compile(
    r"^(?:Security|System|Application|Setup|ForwardedEvents|Windows PowerShell|Microsoft-Windows-.+|WinEventLog.*)$"
)
_DARWIN_PREFIXES: Final = ("/Library/", "/System/", "/Applications/", "/private/", "/Users/")


def _platform_from_path(path: str | None) -> str | None:
    if not path:
        return None
    if _DRIVE.match(path) or path.upper().startswith(("HKEY_", "HKLM", "HKCU", "\\\\")):
        return "windows"
    if path.startswith(_DARWIN_PREFIXES):
        return "darwin"
    if path.startswith("/"):
        return "linux"
    return None


def _platform_from_log_source(log_source: str | None) -> str | None:
    if not log_source:
        return None
    if log_source in ("EventChannel", "WinEvtLog") or _WINDOWS_CHANNEL.match(log_source):
        return "windows"
    if log_source == "macos":
        return "darwin"
    if log_source in ("journald", "audit", "auditd") or log_source.startswith("/var/log/"):
        return "linux"
    return None


@functools.lru_cache(maxsize=4096)
def _is_ip(text: str) -> bool:
    """Whether ``text`` is an IP address (cached: syslog sender locations repeat on every event)."""
    if len(text) > 45:
        return False
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return False
    return True


# ---- time -----------------------------------------------------------------------------------------------------

_MONTHS: Final = {
    m: i
    for i, m in enumerate(("jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"), start=1)
}
# Kibana / Wazuh dashboard CSV exports: "Sep 25, 2026 @ 10:15:32.481" (browser local time, no offset).
_KIBANA_TS: Final = re.compile(
    r"^([A-Za-z]{3})\s+(\d{1,2}),\s*(\d{4})\s*@\s*(\d{1,2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?$"
)


@functools.lru_cache(maxsize=64)
def zone(name: str | None) -> tzinfo:
    """``tzinfo`` for an IANA name (UTC when empty). Raises ``ValueError`` for unknown names."""
    if not name:
        return UTC
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError, OSError):
        raise ValueError(f"unknown timezone {name!r} (use an IANA name such as Europe/Madrid)") from None


def _parse_kibana(text: str, naive_tz: tzinfo) -> datetime | None:
    match = _KIBANA_TS.match(text.strip())
    if not match:
        return None
    month = _MONTHS.get(match.group(1).lower())
    if month is None:
        return None
    micro = int((match.group(7) or "0")[:6].ljust(6, "0"))
    try:
        local = datetime(
            int(match.group(3)),
            month,
            int(match.group(2)),
            int(match.group(4)),
            int(match.group(5)),
            int(match.group(6)),
            micro,
            tzinfo=naive_tz,
        )
        return local.astimezone(UTC)
    except (ValueError, OverflowError):
        return None


def parse_time(value: Any, naive_tz: tzinfo = UTC, default_year: int | None = None) -> datetime | None:
    """Parse any timestamp shape SIEMs emit into aware UTC, or None. Never raises."""
    if isinstance(value, list):
        value = value[0] if value else None
    try:
        if isinstance(value, str) and len(value) >= 10 and value[4:5] == "-":
            try:  # C fast path (py3.11+ reads Wazuh's "+0000" offsets directly)
                parsed = datetime.fromisoformat(value)
            except ValueError:
                pass
            else:
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=naive_tz)
                return parsed.astimezone(UTC)
        result = parse_ts(value, naive_tz=naive_tz, default_year=default_year)
        if result is None and isinstance(value, str) and "@" in value:
            result = _parse_kibana(value, naive_tz)
        return result
    except (OverflowError, ValueError, TypeError):  # e.g. year 9999 with a negative offset
        return None


# ---- context --------------------------------------------------------------------------------------------------

_GENERIC_ATTRS: Final[tuple[str, ...]] = (
    "ts",
    "rule_id",
    "rule_name",
    "severity",
    "source",
    "log_source",
    "event_id",
    "event_code",
    "os_platform",
    "rule_groups",
    "tags",
    "mitre_tactics",
)
_GENERIC_ALIASES: Final[dict[str, str]] = {
    "timestamp": "ts",
    "@timestamp": "ts",
    "time": "ts",
    "level": "severity",
    "rule_level": "severity",
    "groups": "rule_groups",
    "tactics": "mitre_tactics",
    "techniques": "tags",
    "platform": "os_platform",
}


def canonical_mapping_key(key: str) -> str | None:
    """Our field name for a ``mapping`` key (aliases and ``entities.X`` accepted), or None if unknown."""
    name = key.strip()
    lowered = name.lower()
    for prefix in ("entities.", "entity."):
        if lowered.startswith(prefix):
            lowered = lowered[len(prefix) :]
            return lowered if lowered in ENTITY_NAMES else None
    lowered = _GENERIC_ALIASES.get(lowered, lowered)
    if lowered in _GENERIC_ATTRS or lowered in ENTITY_NAMES:
        return lowered
    return None


@functools.lru_cache(maxsize=64)
def _compile_mapping(items: tuple[tuple[str, str], ...]) -> dict[str, tuple[_Path, ...]]:
    out: dict[str, tuple[_Path, ...]] = {}
    for key, value in items:
        canonical = canonical_mapping_key(key)
        if canonical is None or not isinstance(value, str):
            continue
        alternatives = tuple(_path(v.strip()) for v in value.split("|") if v.strip())
        if alternatives:
            out[canonical] = alternatives
    return out


@dataclass(slots=True)
class _Ctx:
    naive_tz: tzinfo
    default_year: int | None
    mapping: dict[str, tuple[_Path, ...]]


# ---- value helpers over an extracted {dotted path: raw value} dict ----------------------------------------------


def _ts(values: dict[str, Any], keys: tuple[str, ...], ctx: _Ctx) -> datetime | None:
    for key in keys:
        value = values.get(key)
        if value is not None:
            parsed = parse_time(value, ctx.naive_tz, ctx.default_year)
            if parsed is not None:
                return parsed
    return None


def _pick(values: dict[str, Any], keys: tuple[str, ...]) -> str | None:
    for key in keys:
        value = values.get(key)
        if value is not None:
            text = _text(value)
            if text is not None:
                return text
    return None


def _many(value: Any) -> list[Any]:
    """Scalars of a raw value (lists expanded, objects dropped)."""
    if value is None:
        return []
    if isinstance(value, list):
        out: list[Any] = []
        _emit(value, out, True, 0, _MAX_RESOLVE_VALUES)
        return out
    return [value]


def _many_of(values: dict[str, Any], keys: tuple[str, ...]) -> list[Any]:
    out: list[Any] = []
    for key in keys:
        out.extend(_many(values.get(key)))
    return out


# ---- known-path extraction ------------------------------------------------------------------------------------


@dataclass(slots=True)
class _Node:
    leaf: str | None = None
    children: dict[str, _Node] = field(default_factory=dict)


def _walk_trie(obj: dict[str, Any], node: _Node, out: dict[str, Any]) -> bool:
    for key, child in node.children.items():
        value = obj.get(key)
        if value is None:
            continue
        if child.leaf is not None:
            out[child.leaf] = value
        if child.children:
            if type(value) is dict:
                if not _walk_trie(value, child, out):
                    return False
            elif isinstance(value, (list, dict)):  # lists of objects: needs the general resolver
                return False
    return True


class _Extractor:
    """Reads a profile's fixed set of dotted paths from one document.

    Nested documents (every Wazuh alert) are read with ONE walk over a trie of the paths; flat dotted keys
    (CSV exports, Elastic alert documents) and paths through lists of objects use the general resolver.
    ``single`` paths keep their raw value, ``multi`` paths collect every scalar.
    """

    __slots__ = ("multi", "root", "single")

    def __init__(self, single: Iterable[str], multi: Iterable[str] = ()) -> None:
        single_texts = tuple(dict.fromkeys(single))
        self.single = tuple(_path(t) for t in single_texts)
        self.multi = tuple(_path(t) for t in dict.fromkeys(multi) if t not in single_texts)
        self.root = _Node()
        for path in (*self.single, *self.multi):
            node = self.root
            for part in path.parts:
                node = node.children.setdefault(part, _Node())
            node.leaf = path.text

    def extract(self, d: _Doc) -> dict[str, Any]:
        out: dict[str, Any] = {}
        if d.heads is None and _walk_trie(d.doc, self.root, out):
            return out
        out = {}
        for path in self.single:
            value = d.raw(path)
            if value is not None:
                out[path.text] = value
        for path in self.multi:
            values = d.all(path)
            if values:
                out[path.text] = values
        return out


# ---- wazuh4 ---------------------------------------------------------------------------------------------------

P_AT_TIMESTAMP = _path("@timestamp")
P_RULE_ID = _path("rule.id")
P_RULE_LEVEL = _path("rule.level")
P_AGENT_ID = _path("agent.id")
P_MANAGER_NAME = _path("manager.name")
P_LOCATION = _path("location")
P_DECODER_NAME = _path("decoder.name")
P_FULL_LOG = _path("full_log")

_W4_TS = ("timestamp", "@timestamp")
_W4_EVENT_ID = ("id", "_id")
_W4_ENTITIES: Final[tuple[tuple[str, tuple[str, ...]], ...]] = (
    ("src_ip", ("data.srcip", "data.win.eventdata.ipAddress", "data.win.eventdata.sourceIp")),
    ("dst_ip", ("data.dstip", "data.win.eventdata.destinationIp")),
    (
        "user",
        (
            "data.dstuser",
            "data.srcuser",
            "data.win.eventdata.targetUserName",
            "data.win.eventdata.user",
            "data.win.eventdata.subjectUserName",
        ),
    ),
    ("process", ("data.win.eventdata.image", "data.win.eventdata.newProcessName")),
    ("parent_process", ("data.win.eventdata.parentImage", "data.win.eventdata.parentProcessName")),
    ("command_line", ("data.win.eventdata.commandLine",)),
    ("file", ("syscheck.path", "data.win.eventdata.targetFilename")),
    ("url", ("data.url",)),
    ("domain", ("data.win.eventdata.queryName", "data.win.eventdata.destinationHostname")),
)
_W4_EXTRACTOR: Final = _Extractor(
    (
        *_W4_TS,
        *_W4_EVENT_ID,
        "rule.id",
        "rule.level",
        "rule.description",
        "agent.id",
        "agent.name",
        "predecoder.hostname",
        "location",
        "decoder.name",
        "data.win.system.channel",
        "data.win.system.eventID",
        *(key for _, keys in _W4_ENTITIES for key in keys),
    ),
    ("rule.groups", "rule.mitre.id", "rule.mitre.tactic"),
)


def _entity_pairs(spec: tuple[tuple[str, tuple[str, ...]], ...]) -> tuple[tuple[str, str], ...]:
    return tuple((name, key) for name, keys in spec for key in keys)


_W4_ENTITY_PAIRS: Final = _entity_pairs(_W4_ENTITIES)


def _collect_entities(v: dict[str, Any], pairs: tuple[tuple[str, str], ...]) -> dict[str, str]:
    """First usable value per entity name, in ``pairs`` order (one flat loop: this runs for every event)."""
    entities: dict[str, str] = {}
    for name, key in pairs:
        if name in entities:
            continue
        value = v.get(key)
        if value is not None:
            text = _text(value)
            if text is not None:
                entities[name] = text if len(text) <= MAX_ENTITY_CHARS else text[:MAX_ENTITY_CHARS]
    return entities


def _strip_location(location: str | None) -> str | None:
    """``(agent) any->/var/log/auth.log`` or ``host->/path`` -> ``/path`` (alerts.json already strips it)."""
    if location is None or "->" not in location:
        return location
    tail = location.rsplit("->", 1)[1]
    return tail or location


def _wazuh_platform(
    loc: str | None,
    windows: bool,
    syslog_device: bool,
    decoder: str | None,
    groups: tuple[str, ...],
    fim_path: str | None,
) -> str | None:
    if windows or decoder == "windows_eventchannel":
        return "windows"
    if syslog_device:
        return "network"
    platform = _platform_from_log_source(loc)
    if platform is None and loc and loc.startswith(_DARWIN_PREFIXES):
        platform = "darwin"
    if platform is None and loc and _DRIVE.match(loc):
        platform = "windows"
    if platform is None and loc and loc.startswith(("/var/ossec/", "/etc/", "/opt/", "/usr/", "/home/", "/root/")):
        platform = "linux"
    if platform is None:
        platform = _platform_from_path(fim_path)
    if platform is None and any(g in ("windows", "windows_security", "sysmon") for g in groups):
        platform = "windows"
    if platform is None and decoder in ("auditd", "journald"):
        platform = "linux"
    return platform


def _map_wazuh4(v: dict[str, Any], ctx: _Ctx) -> Event | None:
    ts = _ts(v, _W4_TS, ctx)
    if ts is None:
        return None
    agent_id = _text(v.get("agent.id"))
    agent_name = _text(v.get("agent.name"))
    pre_host = _text(v.get("predecoder.hostname"))
    location = _strip_location(_text(v.get("location")))
    channel = _text(v.get("data.win.system.channel"))
    event_code = _text(v.get("data.win.system.eventID"))
    decoder = _text(v.get("decoder.name"))
    groups = _strs(v.get("rule.groups"))

    # Syslog devices reach the manager (agent 000): the device is the syslog header hostname and the JSON
    # location is the sender IP.
    syslog_device = agent_id == "000" and location is not None and _is_ip(location)
    source = pre_host if pre_host is not None and (agent_id == "000" or agent_name is None) else agent_name
    if channel is not None:
        log_source: str | None = channel
    elif syslog_device and pre_host is not None:
        log_source = "syslog"  # the device identity is in `source`; keep one comparable log source name
    else:
        log_source = location

    entities = _collect_entities(v, _W4_ENTITY_PAIRS)
    host = _entity(source)
    if host is not None:
        entities["host"] = host

    windows = channel is not None or event_code is not None or location in ("EventChannel", "WinEvtLog")
    return Event(
        ts=ts,
        rule_id=_text(v.get("rule.id")),
        rule_name=_text(v.get("rule.description")),
        severity=_level(v.get("rule.level")),
        source=source,
        log_source=log_source,
        entities=entities,
        tags=_techniques(_many(v.get("rule.mitre.id"))),
        event_id=_pick(v, _W4_EVENT_ID),
        rule_groups=groups,
        mitre_tactics=_strs(v.get("rule.mitre.tactic")),
        event_code=event_code,
        os_platform=_wazuh_platform(location, windows, syslog_device, decoder, groups, _text(v.get("syscheck.path"))),
    )


# ---- ecs ------------------------------------------------------------------------------------------------------

_ECS_TS = ("event.ingested", "@timestamp")
# Elastic Security 8+ alerts live under kibana.alert.*; 7.x .siem-signals-* documents under signal.*
_ECS_RULE_ID = ("kibana.alert.rule.uuid", "signal.rule.id", "rule.id", "rule.uuid")
_ECS_RULE_NAME = ("kibana.alert.rule.name", "signal.rule.name", "rule.name")
_ECS_SOURCE = ("host.name", "agent.name", "host.hostname")
_ECS_LOG_SOURCE = (
    "data_stream.dataset",
    "event.dataset",
    "winlog.channel",
    "kibana.alert.original_event.dataset",
    "signal.original_event.dataset",
)
_ECS_EVENT_CODE = ("event.code", "winlog.event_id", "kibana.alert.original_event.code", "signal.original_event.code")
_ECS_EVENT_ID = ("_id", "kibana.alert.uuid", "event.id")
_ECS_TECHNIQUES = (
    "threat.technique.id",
    "threat.technique.subtechnique.id",
    "kibana.alert.rule.threat.technique.id",
    "kibana.alert.rule.threat.technique.subtechnique.id",
    "signal.rule.threat.technique.id",
    "signal.rule.threat.technique.subtechnique.id",
)
_ECS_TACTICS = ("threat.tactic.name", "kibana.alert.rule.threat.tactic.name", "signal.rule.threat.tactic.name")
_ECS_PLATFORM = ("host.os.type", "host.os.platform", "host.os.family", "host.os.name")
_ECS_SEVERITY = (
    "kibana.alert.severity",
    "kibana.alert.risk_score",
    "signal.rule.severity",
    "signal.rule.risk_score",
    "event.severity",
)
# disposition evidence, kept in Event.fields (also under projection)
_ECS_WORKFLOW = ("kibana.alert.workflow_status", "kibana.alert.workflow_reason", "signal.status")
_ECS_ENTITIES: Final[tuple[tuple[str, tuple[str, ...]], ...]] = (
    ("src_ip", ("source.ip", "client.ip")),
    ("dst_ip", ("destination.ip", "server.ip")),
    ("user", ("user.name", "user.target.name", "winlog.event_data.TargetUserName")),
    ("process", ("process.executable",)),
    ("parent_process", ("process.parent.executable",)),
    ("command_line", ("process.command_line",)),
    ("file", ("file.path",)),
    ("url", ("url.full", "url.original")),
    ("domain", ("dns.question.name", "destination.domain", "url.domain")),
)
_ECS_SINGLE: Final = (
    "event.kind",  # "alert" / "signal": an alert document even without a rule id (input kind)
    *_ECS_TS,
    *_ECS_RULE_ID,
    *_ECS_RULE_NAME,
    *_ECS_SOURCE,
    *_ECS_LOG_SOURCE,
    *_ECS_EVENT_CODE,
    *_ECS_EVENT_ID,
    *_ECS_PLATFORM,
    *_ECS_SEVERITY,
    *_ECS_WORKFLOW,
    *(key for _, keys in _ECS_ENTITIES for key in keys),
)
_ECS_EXTRACTOR: Final = _Extractor(
    _ECS_SINGLE, (*_ECS_TECHNIQUES, *_ECS_TACTICS, "kibana.alert.rule.tags", "event.category")
)


def _ecs_entities(
    v: dict[str, Any], source: str | None, extra: Mapping[str, tuple[str, ...]] | None = None
) -> dict[str, str]:
    entities: dict[str, str] = {}
    for name, keys in _ECS_ENTITIES:
        value = _entity(_pick(v, keys))
        if value is None and extra is not None and name in extra:
            value = _entity(_pick(v, extra[name]))
        if value is not None:
            entities[name] = value
    host = _entity(_text(v.get("host.name")) or source)
    if host is not None:
        entities["host"] = host
    return entities


def _ecs_severity(v: dict[str, Any]) -> int | None:
    for name_key, risk_key in (
        ("kibana.alert.severity", "kibana.alert.risk_score"),
        ("signal.rule.severity", "signal.rule.risk_score"),
    ):
        named = _text(v.get(name_key))
        if named is not None and named.strip().lower() in _SEVERITY_NAMES:
            return _SEVERITY_NAMES[named.strip().lower()]
        risk = _number(v.get(risk_key))
        if risk is not None and risk >= 0:
            return _risk_level(min(risk, 100.0))
    return _level_or_risk(v.get("event.severity"))


def _map_ecs(v: dict[str, Any], ctx: _Ctx) -> Event | None:
    ts = _ts(v, _ECS_TS, ctx)
    if ts is None:
        return None
    source = _pick(v, _ECS_SOURCE)
    log_source = _pick(v, _ECS_LOG_SOURCE)
    platform = _platform_name(_pick(v, _ECS_PLATFORM))
    if platform is None and v.get("winlog.channel") is not None:
        platform = "windows"
    if platform is None:
        platform = _platform_from_log_source(log_source)
    groups = _strs(v.get("kibana.alert.rule.tags")) or _strs(v.get("event.category"))
    return Event(
        ts=ts,
        rule_id=_pick(v, _ECS_RULE_ID),
        rule_name=_pick(v, _ECS_RULE_NAME),
        severity=_ecs_severity(v),
        source=source,
        log_source=log_source,
        entities=_ecs_entities(v, source),
        tags=_techniques(_many_of(v, _ECS_TECHNIQUES)),
        event_id=_pick(v, _ECS_EVENT_ID),
        rule_groups=groups,
        mitre_tactics=_str_tuple(_many_of(v, _ECS_TACTICS)),
        event_code=_pick(v, _ECS_EVENT_CODE),
        os_platform=platform,
    )


# ---- wazuh5 (best effort) -------------------------------------------------------------------------------------

_W5_TS = ("event.ingested", "@timestamp", "timestamp")
_W5_RULE_ID = ("rule.id", "wazuh.rule.id", "rule.uuid")
_W5_RULE_NAME = ("rule.name", "rule.title", "rule.description", "wazuh.rule.name")
_W5_LEVEL = ("rule.level", "wazuh.rule.level", "rule.severity", "event.severity")
_W5_SOURCE = ("agent.name", "wazuh.agent.name", "host.name", "host.hostname")
_W5_LOG_SOURCE = (
    "event.dataset",
    "data_stream.dataset",
    "winlog.channel",
    "log.file.path",
    "wazuh.integration.name",
    "event.module",
    "location",
)
_W5_EVENT_ID = ("_id", "event.id", "id")
_W5_EVENT_CODE = (*_ECS_EVENT_CODE, "data.win.system.eventID")
_W5_TECHNIQUES = ("rule.mitre.id", "threat.technique.id", "threat.technique.subtechnique.id", "rule.tags")
_W5_TACTICS = ("rule.mitre.tactic", "threat.tactic.name")
_W5_GROUPS = ("rule.groups", "wazuh.decoders", "event.category")
_W5_PLATFORM = ("host.os.type", "host.os.platform", "agent.os.type", "wazuh.agent.host.os.type")
_W5_EXTRA: Final[dict[str, tuple[str, ...]]] = {name: keys for name, keys in _W4_ENTITIES}
_W5_EXTRACTOR: Final = _Extractor(
    (
        *_W5_TS,
        *_W5_RULE_ID,
        *_W5_RULE_NAME,
        *_W5_LEVEL,
        *_W5_SOURCE,
        *_W5_LOG_SOURCE,
        *_W5_EVENT_ID,
        *_W5_EVENT_CODE,
        *_W5_PLATFORM,
        "host.name",
        "data.win.system.channel",
        *(key for _, keys in _ECS_ENTITIES for key in keys),
        *(key for _, keys in _W4_ENTITIES for key in keys),
    ),
    (*_W5_TECHNIQUES, *_W5_TACTICS, *_W5_GROUPS),
)


def _map_wazuh5(v: dict[str, Any], ctx: _Ctx) -> Event | None:
    ts = _ts(v, _W5_TS, ctx)
    if ts is None:
        return None
    source = _pick(v, _W5_SOURCE)
    log_source = _pick(v, _W5_LOG_SOURCE)
    severity = None
    for key in _W5_LEVEL:
        severity = _level_or_risk(v.get(key))
        if severity is not None:
            break
    platform = _platform_name(_pick(v, _W5_PLATFORM))
    if platform is None and (v.get("winlog.channel") is not None or v.get("data.win.system.channel") is not None):
        platform = "windows"
    if platform is None:
        platform = _platform_from_log_source(log_source)
    return Event(
        ts=ts,
        rule_id=_pick(v, _W5_RULE_ID),
        rule_name=_pick(v, _W5_RULE_NAME),
        severity=severity,
        source=source,
        log_source=log_source,
        entities=_ecs_entities(v, source, _W5_EXTRA),
        tags=_techniques(_many_of(v, _W5_TECHNIQUES)),
        event_id=_pick(v, _W5_EVENT_ID),
        rule_groups=_str_tuple(_many_of(v, _W5_GROUPS)),
        mitre_tactics=_merge(_str_tuple(_many_of(v, _W5_TACTICS)), _tag_tactics(_many(v.get("rule.tags")))),
        event_code=_pick(v, _W5_EVENT_CODE),
        os_platform=platform,
    )


# ---- generic --------------------------------------------------------------------------------------------------

# Conservative name heuristics for unmapped fields: exact dotted paths first, then case-insensitive top-level
# column names. Ambiguous names (e.g. "event_id", which is a Windows EventID in some exports and a document
# id in others) are deliberately left to explicit mapping.
_HEURISTICS: Final[dict[str, tuple[str, ...]]] = {
    "ts": (
        "@timestamp",
        "timestamp",
        "event.ingested",
        "time",
        "_time",
        "ts",
        "datetime",
        "date",
        "event_time",
        "eventtime",
        "timegenerated",
        "timecreated",
        "created_at",
    ),
    "rule_id": ("rule_id", "rule.id", "ruleid", "signature_id", "detection_id"),
    "rule_name": ("rule_name", "rule.name", "rule.description", "signature", "alert_name", "title"),
    "severity": ("rule.level", "severity", "level", "priority"),  # see _generic_severity
    "source": (
        "host",
        "hostname",
        "host.name",
        "agent.name",
        "computer",
        "computer_name",
        "computername",
        "device",
        "device_name",
    ),
    "log_source": ("log_source", "channel", "event.dataset", "sourcetype", "source", "location", "log.file.path"),
    "event_id": ("_id", "alert_id", "document_id", "uuid"),
    "event_code": ("event_code", "event.code", "eventcode", "eventid"),
    "os_platform": ("os_platform", "platform", "host.os.type", "os"),
    "rule_groups": ("rule_groups", "rule.groups", "groups"),
    "tags": ("tags", "mitre", "technique", "techniques", "rule.mitre.id", "threat.technique.id"),
    "mitre_tactics": ("mitre_tactics", "tactic", "tactics", "rule.mitre.tactic", "threat.tactic.name"),
    "src_ip": ("src_ip", "srcip", "source.ip", "source_ip", "src", "client_ip", "data.srcip"),
    "dst_ip": ("dst_ip", "dstip", "destination.ip", "dest_ip", "dest", "data.dstip"),
    "user": ("user", "user.name", "username", "user_name", "account", "data.dstuser", "data.srcuser"),
    "host": ("host", "hostname", "host.name", "agent.name", "computer", "computer_name", "computername"),
    "process": ("process", "process.executable", "image", "process_path"),
    "parent_process": ("parent_process", "process.parent.executable", "parentimage"),
    "command_line": ("command_line", "process.command_line", "commandline", "cmdline"),
    "file": ("file", "file.path", "file_path", "targetfilename"),
    "url": ("url", "url.full", "url.original"),
    "domain": ("domain", "dns.question.name", "query"),
}
_HEURISTIC_PATHS: Final[dict[str, tuple[_Path, ...]]] = {k: _paths(*v) for k, v in _HEURISTICS.items()}


def _generic_raw(d: _Doc, ctx: _Ctx, name: str) -> Any:
    explicit = ctx.mapping.get(name)
    if explicit is not None:  # explicit mapping wins, no heuristics behind it; "a|b" tries b when a is empty
        for path in explicit:
            value = d.raw(path)
            if value is None:
                value = d.ci(path.text)
            if value is not None and _text(value) is not None:
                return value
        return None
    for path in _HEURISTIC_PATHS.get(name, ()):
        value = d.raw(path)
        if value is None:
            value = d.ci(path.text)
        if value is not None and _text(value) is not None:
            return value
    return None


def _generic_all(d: _Doc, ctx: _Ctx, name: str) -> list[Any]:
    explicit = ctx.mapping.get(name)
    paths = explicit if explicit is not None else _HEURISTIC_PATHS.get(name, ())
    for path in paths:
        values = d.all(path)
        if not values:
            single = d.ci(path.text)
            values = _many(single) if not isinstance(single, dict) else []
        if values:
            return values
    return []


def _generic_severity(d: _Doc, ctx: _Ctx) -> int | None:
    """Severity of a generic document.

    An explicitly mapped column is trusted (numbers <= 16 as Wazuh levels, larger ones as 0-100 risk scores).
    Unmapped columns are only read when unambiguous: ``rule.level`` (Wazuh semantics) or a severity NAME. A bare
    number in a column called severity / level / priority is ignored, because common sources use inverted
    scales (syslog severity 0 = emergency, Windows Level 1 = critical, Suricata/Snort priority 1 = highest):
    reading "1" as a low level would make a critical event look tunable, while an unknown level blocks tuning.
    """
    if "severity" in ctx.mapping:
        return _level_or_risk(_generic_raw(d, ctx, "severity"))
    for path in _HEURISTIC_PATHS["severity"]:
        value = d.raw(path)
        if value is None:
            value = d.ci(path.text)
        text = _text(value)
        if text is None:
            continue
        if path.text == "rule.level":
            return _level(value)
        named = _SEVERITY_NAMES.get(text.strip().lower())
        if named is not None:
            return named
    return None


def _norm_generic(d: _Doc, ctx: _Ctx) -> Event | None:
    raw_ts = _generic_raw(d, ctx, "ts")
    ts = parse_time(raw_ts, ctx.naive_tz, ctx.default_year) if raw_ts is not None else None
    if ts is None:
        return None
    source = _text(_generic_raw(d, ctx, "source"))
    if source is None and "source" not in ctx.mapping:
        source = _text(_generic_raw(d, ctx, "host"))
    log_source = _text(_generic_raw(d, ctx, "log_source"))
    entities: dict[str, str] = {}
    for name in ENTITY_NAMES:
        value = _entity(_text(_generic_raw(d, ctx, name)))
        if value is not None:
            entities[name] = value
    if "host" not in entities and source is not None:
        entities["host"] = _entity(source) or source
    platform = _platform_name(_text(_generic_raw(d, ctx, "os_platform"))) or _platform_from_log_source(log_source)
    tag_values = _generic_all(d, ctx, "tags")
    return Event(
        ts=ts,
        rule_id=_text(_generic_raw(d, ctx, "rule_id")),
        rule_name=_text(_generic_raw(d, ctx, "rule_name")),
        severity=_generic_severity(d, ctx),
        source=source,
        log_source=log_source,
        entities=entities,
        tags=_techniques(tag_values),
        event_id=_text(_generic_raw(d, ctx, "event_id")),
        rule_groups=_str_tuple(_generic_all(d, ctx, "rule_groups")),
        mitre_tactics=_merge(_str_tuple(_generic_all(d, ctx, "mitre_tactics")), _tag_tactics(tag_values)),
        event_code=_text(_generic_raw(d, ctx, "event_code")),
        os_platform=platform,
    )


_MAPPERS: Final[dict[str, tuple[_Extractor, Callable[[dict[str, Any], _Ctx], Event | None]]]] = {
    "wazuh4": (_W4_EXTRACTOR, _map_wazuh4),
    "wazuh5": (_W5_EXTRACTOR, _map_wazuh5),
    "ecs": (_ECS_EXTRACTOR, _map_ecs),
}


# ---- detection ------------------------------------------------------------------------------------------------

_ECS_MARKERS = _paths("event.kind", "event.dataset", "event.module", "event.category", "ecs.version", "agent.type")
_ECS_NAMESPACES: Final = ("kibana", "data_stream", "winlog", "ecs", "signal")


def _classify(doc: dict[str, Any]) -> str | None:
    d = _Doc(doc)
    rule_id = _text(d.raw(P_RULE_ID))
    numeric_level = _number(d.raw(P_RULE_LEVEL)) is not None
    location = d.raw(P_LOCATION)
    wazuh4_shape = (
        (rule_id is not None and numeric_level)
        or (d.raw(P_AGENT_ID) is not None and d.raw(P_MANAGER_NAME) is not None)
        or (location is not None and (d.raw(P_DECODER_NAME) is not None or d.raw(P_FULL_LOG) is not None))
    )
    wazuh_namespace = d.has_namespace("wazuh")
    if wazuh4_shape and (not wazuh_namespace or (rule_id is not None and numeric_level)):
        return "wazuh4"
    if wazuh_namespace:
        return "wazuh5"
    if d.raw(P_AT_TIMESTAMP) is not None and (
        any(d.raw(p) is not None for p in _ECS_MARKERS) or any(d.has_namespace(n) for n in _ECS_NAMESPACES)
    ):
        return "ecs"
    return None


def detect_profile(docs: Sequence[Mapping[str, Any]]) -> str:
    """Guess the profile (``wazuh4`` | ``wazuh5`` | ``ecs`` | ``generic``) from sample documents.

    Each of the first :data:`DETECT_SAMPLE` documents votes; the most common recognised shape wins (ties go
    to wazuh4, then wazuh5, then ecs). When no document matches a known shape the result is ``generic``.
    """
    counts = {"wazuh4": 0, "wazuh5": 0, "ecs": 0}
    for doc in list(docs[:DETECT_SAMPLE]):
        if not isinstance(doc, Mapping):
            continue
        try:
            kind = _classify(unwrap_hit(doc))
        except RecursionError:
            continue
        if kind is not None:
            counts[kind] += 1
    best = max(("wazuh4", "wazuh5", "ecs"), key=lambda k: counts[k])  # max keeps the first on ties
    return best if counts[best] > 0 else "generic"


# ---- fields ---------------------------------------------------------------------------------------------------


def _is_mapping(value: Any) -> bool:
    return type(value) is dict or isinstance(value, Mapping)


def _flatten_into(node: Mapping[str, Any], prefix: str, out: dict[str, Any]) -> None:
    """Exactly :func:`hushwatch.models.flatten`, specialised for JSON-decoded dicts (no ABC checks per value)."""
    for key, value in node.items():
        name = f"{prefix}.{key}" if prefix else (key if type(key) is str else str(key))
        kind = type(value)
        if kind is str or kind is int or kind is float or kind is bool or value is None:
            out[name] = value
        elif kind is dict:
            if value:
                _flatten_into(value, name, out)
            else:
                out[name] = None
        elif kind is list and (not value or type(value[0]) is str):  # the common lists (groups, MITRE ids...)
            out[name] = value
        elif isinstance(value, Mapping):
            if value:
                _flatten_into(value, name, out)
            else:
                out[name] = None
        elif isinstance(value, list) and value and _is_mapping(value[0]) and all(_is_mapping(v) for v in value):
            nested: dict[str, list[Any]] = {}
            for item in value:
                flat: dict[str, Any] = {}
                _flatten_into(item, name, flat)
                for sub_key, sub_value in flat.items():
                    nested.setdefault(sub_key, []).append(sub_value)
            out.update(nested)
        else:
            out[name] = value


def fast_flatten(doc: Mapping[str, Any]) -> dict[str, Any]:
    """Same result as :func:`hushwatch.models.flatten` (dotted keys), about twice as fast on JSON documents."""
    out: dict[str, Any] = {}
    _flatten_into(doc, "", out)
    return out


def _put_flat(out: dict[str, Any], key: str, value: Any) -> None:
    if isinstance(value, (dict, list)):
        _flatten_into({key: value}, "", out)
    else:
        out[key] = value


def _project(d: _Doc, project: tuple[str, ...], known: Mapping[str, Any]) -> dict[str, Any]:
    """Projected fields: the values behind the core attributes (``known``) plus the requested paths."""
    out: dict[str, Any] = {}
    for key, value in known.items():
        _put_flat(out, key, value)
    for text in project:
        if not isinstance(text, str) or not text or text in known or text in out:
            continue
        value = d._lookup(_path(text))
        if value is not None:
            _put_flat(out, text, value)
    return out


# ---- public entry points --------------------------------------------------------------------------------------

Normalizer = Callable[[Mapping[str, Any]], "Event | None"]


def unwrap_hit(doc: Mapping[str, Any]) -> dict[str, Any]:
    """Return the event document of an OpenSearch/Elasticsearch hit (``_source`` plus ``_id``/``_index``)
    or the document itself. Never mutates ``doc``."""
    source = doc.get("_source")
    if isinstance(source, dict) and ("_id" in doc or "_index" in doc):
        out = dict(source)
        for key in ("_id", "_index"):
            value = doc.get(key)
            if isinstance(value, str) and key not in out:
                out[key] = value
        return out
    return doc if type(doc) is dict else dict(doc)


def _body(doc: Mapping[str, Any]) -> dict[str, Any]:
    if type(doc) is dict and "_source" not in doc:
        return doc
    if not isinstance(doc, Mapping):
        raise TypeError("normalize() expects a mapping")
    return unwrap_hit(doc)


@functools.lru_cache(maxsize=256)
def _bind(
    profile: str,
    naive_timezone: str | None,
    mapping: tuple[tuple[str, str], ...],
    default_year: int | None,
    project: tuple[str, ...] | None,
) -> Normalizer:
    ctx = _Ctx(zone(naive_timezone), default_year, _compile_mapping(mapping) if mapping else {})
    if profile == "generic":

        def run_generic(doc: Mapping[str, Any]) -> Event | None:
            body = _body(doc)
            d = _Doc(body, track=project is not None)
            event = _norm_generic(d, ctx)
            if event is None:
                return None
            if project is None:
                event.fields = fast_flatten(body)
            else:
                used = {key: d._lookup(_path(key)) for key in d.used or ()}
                event.fields = _project(d, project, {k: v for k, v in used.items() if v is not None})
            return event

        return run_generic

    mapped = _MAPPERS.get(profile)
    if mapped is None:
        raise ValueError(f"unknown profile {profile!r}; expected one of {', '.join(PROFILES)} or auto")
    extractor, mapper = mapped

    def run(doc: Mapping[str, Any]) -> Event | None:
        body = _body(doc)
        d = _Doc(body)
        values = extractor.extract(d)
        event = mapper(values, ctx)
        if event is None:
            return None
        event.fields = fast_flatten(body) if project is None else _project(d, project, values)
        return event

    if profile == "wazuh4" and project is None:
        # Hot path (every Wazuh alert, full fields): the flattened document already holds every dotted path the
        # mapper reads, so it is the mapper's input too (no separate trie walk). Same values as the extractor for
        # Wazuh 4 documents, whose extracted paths never run through lists of objects.
        def run_flat(doc: Mapping[str, Any]) -> Event | None:
            flat = fast_flatten(_body(doc))
            event = mapper(flat, ctx)
            if event is not None:
                event.fields = flat
            return event

        return run_flat

    return run


def bind(
    profile: str,
    *,
    input_cfg: InputConfig | None = None,
    default_year: int | None = None,
    project: Sequence[str] | None = None,
) -> Normalizer:
    """``normalize`` with its configuration resolved once: returns ``f(doc) -> Event | None``.

    ``profile`` must be concrete (not ``auto``). Raises ``ValueError`` for an unknown profile or timezone.
    """
    mapping: tuple[tuple[str, str], ...] = ()
    if profile == "generic" and input_cfg is not None and input_cfg.mapping:
        mapping = tuple(sorted((str(k), str(v)) for k, v in input_cfg.mapping.items()))
    naive_timezone = input_cfg.naive_timezone if input_cfg is not None else None
    wanted = tuple(project) if project is not None else None
    return _bind(profile, naive_timezone or None, mapping, default_year, wanted)


_TS_KEYS: Final[dict[str, tuple[str, ...]]] = {"wazuh4": _W4_TS, "wazuh5": _W5_TS, "ecs": _ECS_TS}
_SYSLOG_NAIVE: Final = re.compile(r"^[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?$")
_OFFSET_SUFFIX: Final = re.compile(r"(?:[Zz]|[+-]\d{2}(?::?\d{2})?)$")


def _lacks_offset(value: Any) -> bool:
    """True when ``value`` is a textual timestamp without a UTC offset (read in ``naive_timezone``)."""
    if isinstance(value, list):
        value = value[0] if value else None
    if not isinstance(value, str):
        return False  # epoch numbers and datetimes are absolute
    text = value.strip()
    if text.isdigit() and len(text) == 8:
        return True  # basic ISO date YYYYMMDD
    if not text or text.replace(".", "", 1).isdigit():
        return False  # epoch seconds / milliseconds
    if _SYSLOG_NAIVE.match(text) or _KIBANA_TS.match(text):
        return True
    try:
        return datetime.fromisoformat(text).tzinfo is None
    except ValueError:
        return _OFFSET_SUFFIX.search(text) is None


def timestamp_lacks_offset(doc: Mapping[str, Any], profile: str, *, input_cfg: InputConfig | None = None) -> bool:
    """True when the timestamp ``normalize`` would read from ``doc`` carries no UTC offset.

    Such times are interpreted in ``input_cfg.naive_timezone`` (UTC when unset): if they are really local times,
    every event is shifted by the UTC offset (false silence followed by a false burst), so callers warn.
    """
    try:
        body = _body(doc)
        if profile == "generic":
            mapping = tuple(sorted((str(k), str(v)) for k, v in input_cfg.mapping.items())) if input_cfg else ()
            ctx = _Ctx(UTC, None, _compile_mapping(mapping) if mapping else {})
            return _lacks_offset(_generic_raw(_Doc(body), ctx, "ts"))
        mapped = _MAPPERS.get(profile)
        if mapped is None:
            return False
        values = mapped[0].extract(_Doc(body))
        for key in _TS_KEYS.get(profile, ()):
            value = values.get(key)
            if value is not None and parse_time(value, UTC, 2000) is not None:
                return _lacks_offset(value)
    except (RecursionError, TypeError):
        return False
    return False


def normalize(
    doc: Mapping[str, Any],
    profile: str,
    *,
    input_cfg: InputConfig | None = None,
    tenant: TenantConfig | None = None,
    default_year: int | None = None,
    project: Sequence[str] | None = None,
) -> Event | None:
    """Normalize one raw document with ``profile`` (``auto`` detects it from this document alone).

    Returns None when no timestamp can be parsed (the caller counts it in ``DataBasis.bad_timestamps``).
    ``Event.fields`` is ``flatten(doc)``; with ``project`` it holds only the projected dotted keys (a key that
    names an object keeps its whole flattened subtree) plus every source key behind the core attributes and
    entities, so suppression conditions on original paths (``agent.name``, ``data.srcip``...) still match.
    ``input_cfg`` supplies ``naive_timezone`` (for timestamps without an offset) and the generic ``mapping``;
    ``default_year`` completes year-less syslog timestamps. ``tenant`` is accepted for API symmetry.
    Search hits (``{"_id", "_source"}``) are unwrapped. Raises ``ValueError`` for an unknown profile or
    ``naive_timezone`` (configuration errors) and ``TypeError`` for a non-mapping; never for document content.
    """
    del tenant  # normalization is tenant-independent today
    if profile == "auto":
        profile = detect_profile([_body(doc)])
    return bind(profile, input_cfg=input_cfg, default_year=default_year, project=project)(doc)
