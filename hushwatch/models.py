"""Core data model shared by every hushwatch module.

* :class:`Event` — one normalized alert or log event, whatever SIEM it came from.
* :class:`Finding` — one problem hushwatch found (a noisy rule, a silent source, a risky suppression...).
* :class:`DataBasis` — what the analysis was actually based on (so a clean report never reads as "all good"
  when the data could not support the conclusion).
* :class:`Report` — findings + per-domain sections + assessment status for one tenant.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

from .i18n import Entity, Message

SCHEMA_VERSION = "1.0"
FINGERPRINT_SCHEME = "v1"


@dataclass(slots=True)
class Event:
    """A normalized event.

    ``ts`` is the *arrival* time at the SIEM when the source provides it (Wazuh ``timestamp`` is the manager
    processing time), which is what silence detection must use. ``fields`` holds the flattened original
    document (dotted keys) or, when a projection is requested, only the projected keys.
    """

    ts: datetime
    rule_id: str | None = None
    rule_name: str | None = None
    severity: int | None = None  # normalized to the 0-15 Wazuh scale
    source: str | None = None  # the agent / host that produced it
    log_source: str | None = None  # Windows channel, log file path, dataset...
    entities: dict[str, str] = field(default_factory=dict)
    fields: dict[str, Any] = field(default_factory=dict)
    tags: tuple[str, ...] = ()  # MITRE technique ids ("T1110.001") and rule groups ("group:authentication_failed")
    event_id: str | None = None  # SIEM document / alert id (joins dispositions)
    rule_groups: tuple[str, ...] = ()
    mitre_tactics: tuple[str, ...] = ()
    event_code: str | None = None  # Windows EventID / ECS event.code — discriminator for coverage checks
    os_platform: str | None = None  # windows | linux | darwin | network | None (inferred)


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]

    @property
    def sarif_level(self) -> str:
        return {"info": "note", "low": "note", "medium": "warning"}.get(self.value, "error")


_SEVERITY_RANK = {Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 2, Severity.HIGH: 3, Severity.CRITICAL: 4}


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


# Domains a finding can belong to. Report.assessment has one status per domain.
DOMAINS: tuple[str, ...] = ("noise", "silence", "pipeline", "coverage", "tuning", "assessment")


@dataclass(slots=True)
class Finding:
    """One hygiene problem, with the evidence behind it.

    * ``kind`` — dotted category, e.g. ``noise.candidate``, ``silence.silent``, ``pipeline.global_silence``.
    * ``subject`` — RAW identifier of what the finding is about (rule id, source key). Used for the
      fingerprint; renderers never print it directly when redaction is on.
    * ``title`` / ``reasons`` / ``recommendation`` — :class:`Message` objects (or plain strings) rendered per
      language; entity values inside them must be wrapped in :class:`Entity`.
    * ``evidence`` — JSON-serializable numbers/strings; entity values wrapped in :class:`Entity`.
    * ``fingerprint`` — stable across runs: sha256(scheme, tenant, kind, subject).
    """

    kind: str
    domain: str
    title: Message | str
    severity: Severity
    subject: str
    reasons: list[Message | str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    recommendation: Message | str | None = None
    confidence: Confidence = Confidence.MEDIUM
    score: float | None = None  # ranking helper within a kind (NOT a cross-kind "risk score")
    tenant: str | None = None
    fingerprint: str = ""
    related: list[str] = field(default_factory=list)  # fingerprints of findings this one explains / groups

    def __post_init__(self) -> None:
        if self.domain not in DOMAINS:
            raise ValueError(f"unknown domain {self.domain!r}")
        if not self.fingerprint:
            self.fingerprint = fingerprint(self.tenant, self.kind, self.subject)


def fingerprint(tenant: str | None, kind: str, subject: str) -> str:
    return stable_hash(FINGERPRINT_SCHEME, tenant or "", kind, subject, length=20)


@dataclass(slots=True)
class DataBasis:
    """What the analysis could actually see. Rendered as a banner on every report."""

    input_kind: str = "unknown"  # alerts | archives | mixed | indexer-alerts | indexer-archives | unknown
    profile: str = "unknown"  # wazuh4 | wazuh5 | ecs | generic
    sources: list[str] = field(default_factory=list)  # file paths / index patterns (no credentials)
    start: datetime | None = None
    end: datetime | None = None
    now: datetime | None = None  # reference "now" used for silence (max event ts for files, or --now)
    now_origin: str = "data"  # data | flag | wallclock
    events: int = 0
    malformed: int = 0  # unparseable lines / documents
    bad_timestamps: int = 0
    future_timestamps: int = 0
    sampled: bool = False
    truncated: bool = False  # caps hit (max events, max keys, max buckets)
    # shard failures, timeouts, auth errors, unreadable files; Message when a translation exists
    partial_failures: list[Message | str] = field(default_factory=list)
    excluded_by_window: int = 0  # events outside --since/--until (read but not analyzed)
    excluded_newest: datetime | None = None  # newest of those excluded events (explains an empty window)
    skipped_files: list[str] = field(default_factory=list)  # files in input dirs not read (unknown extension...)
    warnings: list[Message | str] = field(default_factory=list)
    not_evaluated: list[str] = field(default_factory=list)  # analyses the input could not support

    @property
    def complete(self) -> bool:
        return not self.partial_failures and not self.truncated and self.events > 0


@dataclass(slots=True)
class Report:
    tenant: str
    generated_at: datetime
    tool_version: str
    data_basis: DataBasis
    findings: list[Finding] = field(default_factory=list)
    sections: dict[str, dict[str, Any]] = field(default_factory=dict)
    assessment: dict[str, str] = field(default_factory=dict)  # domain -> ok | warn | fail | not_assessed


def stable_hash(*parts: str, length: int = 16) -> str:
    """Short deterministic hash (ids and fingerprints; not a security boundary)."""
    digest = hashlib.sha256("\x1f".join(parts).encode("utf-8", "surrogatepass")).hexdigest()
    return digest[:length]


def flatten(doc: Mapping[str, Any], prefix: str = "", out: dict[str, Any] | None = None) -> dict[str, Any]:
    """Flatten nested mappings into dotted keys. Lists of scalars are kept as lists; lists of
    mappings are flattened with the same dotted key (values collected into a list)."""
    result: dict[str, Any] = {} if out is None else out
    for key, value in doc.items():
        name = f"{prefix}.{key}" if prefix else str(key)
        if isinstance(value, Mapping):
            if value:
                flatten(value, name, result)
            else:
                result[name] = None
        elif isinstance(value, list) and value and all(isinstance(v, Mapping) for v in value):
            nested: dict[str, list[Any]] = {}
            for item in value:
                for sub_key, sub_val in flatten(item, name).items():
                    nested.setdefault(sub_key, []).append(sub_val)
            result.update(nested)
        else:
            result[name] = value
    return result


def get_path(doc: Mapping[str, Any], path: str) -> Any:
    """Read a dotted path from a nested mapping *or* from an already-flattened mapping."""
    if path in doc:
        return doc[path]
    current: Any = doc
    for part in path.split("."):
        if isinstance(current, Mapping) and part in current:
            current = current[part]
        else:
            return None
    return current


def is_empty(value: Any) -> bool:
    """True for values that carry no information (None, "", "-", "(NULL)", empty containers)."""
    if value is None:
        return True
    if isinstance(value, str):
        return value.strip() in ("", "-", "null", "NULL", "(NULL)", "None", "N/A", "n/a", "unknown")
    if isinstance(value, (list, tuple, dict, set)):
        return len(value) == 0
    return False


def sort_findings(findings: Iterable[Finding]) -> list[Finding]:
    """Most severe first, then highest score, then stable by kind/subject."""
    return sorted(findings, key=lambda f: (-f.severity.rank, -(f.score or 0.0), f.kind, f.subject))


def iter_entities(value: Any) -> Iterator[Entity]:
    """Yield every Entity nested in a message/evidence structure (used by redaction tests)."""
    if isinstance(value, Entity):
        yield value
    elif isinstance(value, Message):
        for v in value.params.values():
            yield from iter_entities(v)
    elif isinstance(value, Mapping):
        for v in value.values():
            yield from iter_entities(v)
    elif isinstance(value, (list, tuple, set)):
        for v in value:
            yield from iter_entities(v)
