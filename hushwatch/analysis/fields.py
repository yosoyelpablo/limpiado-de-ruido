"""Field health (§6.6): fields that a host's log source always carried and that suddenly vanished.

A parser/decoder change (firmware upgrade, new agent version, a broken Logstash filter...) can drop a field while
the source keeps sending events. Volume-based silence cannot see it, yet every rule that depends on the field goes
blind. Log sources are often shared by many hosts (every syslog device relayed by the Wazuh manager arrives as
``syslog``; every Windows host has a ``Security`` channel), and one firewall losing a field after a firmware upgrade
barely moves the presence rate of the whole log source. Field health is therefore tracked per **(host, log
source)**, and grouped at analysis time:

* fields lost on one host → one ``silence.field_lost`` finding for that host and log source
  (subject ``agent:<host>|ls:<log source>|field:<name>``, or ``...|fields:a,b`` when one change dropped
  several; the host as an Entity in title and evidence);
* the same field lost on several hosts of a log source (a decoder/ruleset change) → one finding for the log
  source listing the affected hosts (subject ``ls:<log source>|field:<name>``), never one per host.

:class:`FieldCollector` counts, per (host, log source) and tenant-local day, how many events carried each field
(values that are empty per :func:`hushwatch.models.is_empty` count as absent), and when each field was last seen
(so a finding says exactly when a field vanished, not just the day after). The alert envelope the SIEM writes itself
(``rule.*``, ``agent.*``, ``manager.*``, ids and arrival time) is not tracked: it is not parsed from the source, and
its presence only reflects which rules fired. :func:`analyze_fields` then picks
the most recent run of days where the field is (almost) absent and compares it with the baseline before it:
presence ``>= field_presence_before`` → ``<= field_presence_after`` with ``>= field_min_events`` events on both
sides. The transition day (field vanished mid-day) belongs to neither side.

Memory is bounded and every cap is reported: per log source at most ``max_fields_per_source`` field columns
(fields seen in fewer than 5% of the events are evicted to make room) shared by its hosts, counters are compact
``array`` rows (one per host and day), at most ``max_sources`` log sources and ``max_keys`` (host, log source)
pairs (later hosts are pooled into an overflow bucket that only feeds the log-source totals), and only the most
recent ``2 × (baseline + 3)`` days are kept per log source. Field and source names are length-capped (they come
from attacker-controllable documents).
"""

from __future__ import annotations

import math
from array import array
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from typing import Any

from ..config import TenantConfig
from ..i18n import Entity, M, Message, register
from ..models import Confidence, DataBasis, Event, Finding, Severity, is_empty, stable_hash
from ..timeutil import UTC

__all__ = ["DETECTION_FIELDS", "FieldCollector", "analyze_fields"]

MAX_FIELD_NAME = 200
MIN_PRESENCE_TRACKED = 0.05  # fields below this presence are evicted when the per-source table is full
PRUNE_MIN_EVENTS = 20  # a field is judged only after this many events since it was admitted
MAX_LOST_IN_SECTION = 100
MAX_FIELDS_IN_TITLE = 5
MAX_HOSTS_IN_EVIDENCE = 50
MIX_CHANGE_RATIO = 0.5  # daily volume after/before below this: the loss may come from what is sent, not how
SHARED_MIN_HOSTS = 2  # a field lost on at least this many hosts of one log source is reported once, for the source
HORIZON_EXTRA_DAYS = 3
MIN_EVICTED_SHARE = 0.05  # days below this share of an average kept day are evicted first (forged/skewed dates)
OVERFLOW = "\x00overflow"  # hosts beyond max_keys: they feed the log-source totals but are never reported alone

# Fields detection rules commonly depend on: losing one of them is a detection blind spot (high severity).
DETECTION_FIELDS: frozenset[str] = frozenset(
    {
        "data.srcip",
        "data.dstip",
        "data.srcuser",
        "data.dstuser",
        "data.srcport",
        "data.dstport",
        "data.url",
        "data.action",
        "data.protocol",
        "data.command",
        "data.win.system.eventID",
        "data.win.system.channel",
        "data.win.eventdata.commandLine",
        "data.win.eventdata.image",
        "data.win.eventdata.parentImage",
        "data.win.eventdata.parentCommandLine",
        "data.win.eventdata.targetUserName",
        "data.win.eventdata.subjectUserName",
        "data.win.eventdata.ipAddress",
        "data.win.eventdata.logonType",
        "data.win.eventdata.hashes",
        "data.win.eventdata.targetFilename",
        "data.win.eventdata.destinationIp",
        "data.audit.command",
        "data.audit.exe",
        "syscheck.path",
        "source.ip",
        "destination.ip",
        "user.name",
        "process.command_line",
        "process.executable",
        "process.parent.executable",
        "event.code",
        "event.action",
        "url.original",
    }
)

# Alert envelope written by the SIEM itself (the matched rule, the agent and manager, ids and arrival time), not
# parsed from the log: tracking it would only measure which rules fired. Field health covers the event content.
_ENVELOPE_KEYS: frozenset[str] = frozenset({"id", "_id", "_index", "timestamp", "@timestamp", "event.ingested"})
_ENVELOPE_PREFIXES: tuple[str, ...] = ("rule.", "agent.", "manager.", "cluster.", "kibana.alert.", "signal.")

# Must match hushwatch.models.is_empty for stripped strings (fast path; anything else goes through is_empty).
_EMPTY_STRINGS = frozenset({"", "-", "null", "NULL", "(NULL)", "None", "N/A", "n/a", "unknown"})
_PLAIN_TYPES = (int, float, bool)


def _absent(value: Any) -> bool:
    """Fast equivalent of :func:`hushwatch.models.is_empty` for the common value types."""
    if value is None:
        return True
    cls = value.__class__
    if cls is str:
        if value in _EMPTY_STRINGS:
            return True
        if value and (value[0].isspace() or value[-1].isspace()):
            return is_empty(value)
        return False
    if cls in _PLAIN_TYPES:
        return False
    return is_empty(value)


def _name(value: object) -> str:
    text = value if isinstance(value, str) else str(value)
    if len(text) <= MAX_FIELD_NAME:
        return text
    return text[: MAX_FIELD_NAME - 18] + "...#" + stable_hash(text, length=14)


@dataclass(slots=True)
class _Host:
    days: dict[int, array[int]] = field(default_factory=dict)  # local day ordinal -> counts by column (0 = events)
    # epoch seconds of the newest event that carried each column (0 = never): when a lost field was last seen
    last: array[float] = field(default_factory=lambda: array("d", [0.0]))


@dataclass(slots=True)
class _Source:
    columns: dict[str, int] = field(default_factory=dict)  # field -> column index (>= 1)
    names: list[str | None] = field(default_factory=lambda: [None])  # column -> field (0 = event count)
    free: list[int] = field(default_factory=list)
    admitted_at: dict[str, int] = field(default_factory=dict)  # field -> events of the source when admitted
    hosts: dict[str, _Host] = field(default_factory=dict)
    agg: dict[int, array[int]] = field(default_factory=dict)  # local day -> counts by column, all hosts
    n: int = 0
    next_prune: int = 0
    dropped_fields: int = 0
    dropped_days: int = 0
    truncated: bool = False


class FieldCollector:
    """Streaming per-(host, log source) field presence counters (bounded, mergeable)."""

    def __init__(
        self,
        tenant: TenantConfig,
        max_fields_per_source: int = 300,
        *,
        max_sources: int = 1000,
        max_keys: int = 20_000,
        max_fields_per_event: int = 1000,
    ) -> None:
        if min(max_fields_per_source, max_sources, max_keys, max_fields_per_event) < 1:
            raise ValueError("caps must be >= 1")
        self.tenant_name = tenant.name
        self._tz = tenant.tz
        self.max_fields_per_source = max_fields_per_source
        self.max_sources = max_sources
        self.max_keys = max_keys
        self.max_fields_per_event = max_fields_per_event
        self.max_days = 2 * (max(1, math.ceil(tenant.silence.baseline / timedelta(days=1))) + HORIZON_EXTRA_DAYS)
        self._sources: dict[str, _Source] = {}
        self._day_cache: dict[int, int] = {}
        self._epoch = 0.0  # epoch seconds of the event being added (set by _local_day)
        self._n_keys = 0
        self.events = 0
        self.skipped = 0  # events without log source, timestamp or fields
        self.dropped_sources = 0
        self.overflow_events = 0  # events of hosts beyond max_keys (pooled, not attributable)
        self.truncated = False

    # ---- ingestion ------------------------------------------------------------------------------------------

    def add(self, event: Event) -> None:
        """Record which (non-empty) fields ``event`` carries, for its host, log source and local day."""
        ls = event.log_source
        fields = event.fields
        if not ls or not fields or not isinstance(fields, Mapping):
            self.skipped += 1
            return
        ts = event.ts
        day = self._local_day(ts)
        if day is None:
            self.skipped += 1
            return
        src = self._sources.get(ls) if ls.__class__ is str and len(ls) <= MAX_FIELD_NAME else None
        if src is None:
            src = self._source(_name(ls))
            if src is None:
                return
        source = event.source
        host_name = source if source.__class__ is str and len(source) <= MAX_FIELD_NAME else _name(source or "")
        host = src.hosts.get(host_name) or self._host(src, host_name)
        width = len(src.names)
        row = host.days.get(day)
        agg = src.agg.get(day)
        if row is None or agg is None or len(row) < width or len(agg) < width:  # fast path: both rows exist
            rows = self._rows(src, host, day)
            if rows is None:
                return
            row, agg = rows
        last = host.last
        if len(last) < width:
            last.extend([0.0] * (width - len(last)))
        epoch = self._epoch
        row[0] += 1
        agg[0] += 1
        src.n += 1
        self.events += 1
        columns = src.columns
        empty = _EMPTY_STRINGS
        items: Iterable[tuple[Any, Any]] = fields.items()
        if len(fields) > self.max_fields_per_event:
            src.truncated = True
            items = list(fields.items())[: self.max_fields_per_event]
        for name, value in items:
            # inline _absent (hot loop): None, placeholder strings, empty containers are "absent"
            if value is None:
                continue
            col = columns.get(name)
            if col is None and (name in _ENVELOPE_KEYS or name.startswith(_ENVELOPE_PREFIXES)):
                continue  # written by the SIEM, not parsed from the source: its "loss" says nothing about parsing
            cls = value.__class__
            if cls is str:
                if value in empty or ((value[0].isspace() or value[-1].isspace()) and is_empty(value)):
                    continue
            elif cls is not int and cls is not float and cls is not bool and is_empty(value):
                continue
            if col is None:
                if name.__class__ is not str or len(name) > MAX_FIELD_NAME:
                    name = _name(name)
                    col = columns.get(name)
                if col is None:
                    col = self._admit(src, name)
                    if col < 0:
                        continue
                    width = len(src.names)
                    for target in (row, agg):
                        if len(target) < width:
                            target.extend([0] * (width - len(target)))
                    if len(last) < width:
                        last.extend([0.0] * (width - len(last)))
            row[col] += 1
            agg[col] += 1
            if epoch > last[col]:
                last[col] = epoch

    def _source(self, ls: str) -> _Source | None:
        src = self._sources.get(ls)
        if src is None:
            if len(self._sources) >= self.max_sources:
                self.dropped_sources += 1
                self.truncated = True
                return None
            src = _Source()
            self._sources[ls] = src
        return src

    def _host(self, src: _Source, name: str) -> _Host:
        host = src.hosts.get(name)
        if host is None:
            if self._n_keys >= self.max_keys:
                self.truncated = True
                self.overflow_events += 1
                name = OVERFLOW
                host = src.hosts.get(name)
                if host is not None:
                    return host
            else:
                self._n_keys += 1
            host = _Host()
            src.hosts[name] = host
        return host

    def _rows(self, src: _Source, host: _Host, day: int) -> tuple[array[int], array[int]] | None:
        width = len(src.names)
        agg = src.agg.get(day)
        if agg is None:
            if len(src.agg) >= self.max_days:
                oldest = min(src.agg)
                if day < oldest:
                    src.dropped_days += 1
                    return None
                # A negligible day (a few events with forged or skewed far-away dates) goes first; otherwise the oldest
                # day rotates out. Rotating out real history while the table also holds far-away days means the
                # baseline is being pushed out: reported as truncation, never a silent false green.
                victim = min(src.agg, key=lambda d: (src.agg[d][0], d))
                average = sum(row[0] for row in src.agg.values()) / len(src.agg)
                if src.agg[victim][0] >= MIN_EVICTED_SHARE * average:
                    victim = oldest
                    if max(src.agg) - oldest >= self.max_days:
                        src.truncated = True
                self._drop_day(src, victim)
            agg = array("Q", [0]) * width
            src.agg[day] = agg
        elif len(agg) < width:
            agg.extend([0] * (width - len(agg)))
        row = host.days.get(day)
        if row is None:
            row = array("I", [0]) * width
            host.days[day] = row
        elif len(row) < width:
            row.extend([0] * (width - len(row)))
        return row, agg

    def _drop_day(self, src: _Source, day: int) -> None:
        """Forget one day of a log source (bounded history; the analysis only looks at the baseline)."""
        src.dropped_days += 1
        del src.agg[day]
        for host in src.hosts.values():
            host.days.pop(day, None)

    def _admit(self, src: _Source, name: str) -> int:
        if len(src.columns) >= self.max_fields_per_source and not self._make_room(src):
            src.dropped_fields += 1
            src.truncated = True
            return -1
        if src.free:
            col = src.free.pop()
            src.names[col] = name
        else:
            col = len(src.names)
            src.names.append(name)
        src.columns[name] = col
        src.admitted_at[name] = src.n - 1
        return col

    def _make_room(self, src: _Source) -> bool:
        """Evict fields present in < 5% of the events since they were admitted (amortised)."""
        if src.n < src.next_prune:
            return False
        src.next_prune = src.n + max(100, src.n // 10)
        present = [0] * len(src.names)
        for agg in src.agg.values():
            for col in range(1, min(len(agg), len(present))):
                present[col] += agg[col]
        evict = [
            (name, col)
            for name, col in src.columns.items()
            if src.n - src.admitted_at[name] >= PRUNE_MIN_EVENTS
            and present[col] < MIN_PRESENCE_TRACKED * (src.n - src.admitted_at[name])
        ]
        for name, col in evict:
            del src.columns[name]
            del src.admitted_at[name]
            src.names[col] = None
            src.free.append(col)
            for agg in src.agg.values():
                if col < len(agg):
                    agg[col] = 0
            for host in src.hosts.values():
                if col < len(host.last):
                    host.last[col] = 0.0
                for row in host.days.values():
                    if col < len(row):
                        row[col] = 0
        return len(src.columns) < self.max_fields_per_source

    def _local_day(self, ts: object) -> int | None:
        """Tenant-local day ordinal of ``ts`` (None when unusable); leaves its epoch seconds in ``self._epoch``."""
        if not isinstance(ts, datetime):
            return None
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=UTC)
        try:
            epoch = ts.timestamp()
        except (OverflowError, OSError, ValueError):
            return None
        if not math.isfinite(epoch):
            return None
        self._epoch = epoch
        hour = int(epoch // 3600)
        day = self._day_cache.get(hour)
        if day is None:
            if len(self._day_cache) > 100_000:
                self._day_cache.clear()
            try:
                day = datetime.fromtimestamp(hour * 3600 + 1800, self._tz).toordinal()
            except (OverflowError, OSError, ValueError):
                return None
            self._day_cache[hour] = day
        return day

    def merge(self, other: FieldCollector) -> None:
        """Merge another collector (same tenant) into this one, respecting every cap."""
        for ls, theirs in other._sources.items():
            src = self._source(ls)
            if src is None:
                continue
            mapping: dict[int, int] = {0: 0}
            for col, name in enumerate(theirs.names):
                if col == 0 or name is None:
                    continue
                mine = src.columns.get(name)
                if mine is None:
                    mine = self._admit(src, name)
                    if mine >= 0 and src.n > 0:
                        src.admitted_at[name] = 0  # never tracked here: judge its presence from the beginning
                if mine >= 0:
                    mapping[col] = mine
            src.n += theirs.n
            for host_name, their_host in theirs.hosts.items():
                host = self._host(src, host_name)
                for day, their_row in their_host.days.items():
                    rows = self._rows(src, host, day)
                    if rows is None:
                        continue
                    row, agg = rows
                    for col, value in enumerate(their_row):
                        target = mapping.get(col)
                        if target is None or not value:
                            continue
                        row[target] += value
                        agg[target] += value
                width = len(src.names)
                if len(host.last) < width:
                    host.last.extend([0.0] * (width - len(host.last)))
                for col, seen in enumerate(their_host.last):
                    target = mapping.get(col)
                    if target is not None and seen > host.last[target]:
                        host.last[target] = seen
            src.truncated = src.truncated or theirs.truncated
            src.dropped_fields += theirs.dropped_fields
            src.dropped_days += theirs.dropped_days
        self.events += other.events
        self.skipped += other.skipped
        self.dropped_sources += other.dropped_sources
        self.overflow_events += other.overflow_events
        self.truncated = self.truncated or other.truncated

    # ---- queries --------------------------------------------------------------------------------------------

    def log_sources(self) -> list[str]:
        return sorted(self._sources)

    def hosts(self, log_source: str) -> list[str]:
        src = self._sources.get(log_source)
        return sorted(h for h in src.hosts if h != OVERFLOW) if src else []

    def fields(self, log_source: str) -> list[str]:
        src = self._sources.get(log_source)
        return sorted(src.columns) if src else []

    def presence(self, log_source: str, field_name: str, host: str | None = None) -> dict[date, tuple[int, int]]:
        """``{local date: (events carrying the field, events)}`` for a log source (or one host of it)."""
        src = self._sources.get(log_source)
        if src is None:
            return {}
        if host is None:
            rows = src.agg
        else:
            entry = src.hosts.get(host)
            if entry is None:
                return {}
            rows = entry.days
        col = src.columns.get(field_name, -1)
        return {
            date.fromordinal(day): ((row[col] if 0 < col < len(row) else 0), row[0])
            for day, row in sorted(rows.items())
        }


# ---- analysis ---------------------------------------------------------------------------------------------------


@dataclass(slots=True)
class _Lost:
    log_source: str
    host: str | None  # None: the log source as a whole (unattributed)
    field: str
    before: float
    after: float
    events_before: int
    events_after: int
    since: int  # day ordinal of the day the field vanished (the transition day when it vanished mid-day)
    volume_ratio: float  # events per day after / before (a collapse suggests a change in what is sent)
    last_seen: float = 0.0  # epoch seconds of the newest event that still carried the field (0: unknown)


def analyze_fields(
    collector: FieldCollector,
    *,
    tenant: TenantConfig,
    now: datetime,
    basis: DataBasis | None = None,
) -> tuple[list[Finding], dict[str, Any]]:
    """``silence.field_lost`` findings (per host and log source, or per log source when several hosts lost the same
    field) and the field-health section.

    ``basis`` is optional; alerts-only input lowers the confidence (fields of alerts depend on which rules fired).
    """
    cfg = tenant.silence
    if now.tzinfo is None:
        now = now.replace(tzinfo=UTC)
    end_day = (now - cfg.ingest_lag).astimezone(tenant.tz).toordinal()
    first_day = end_day - max(1, math.ceil(cfg.baseline / timedelta(days=1)))
    thresholds = (cfg.field_presence_before, cfg.field_presence_after, cfg.field_min_events)
    findings: list[Finding] = []
    rows_out: list[dict[str, Any]] = []
    tracked = 0
    for ls in collector.log_sources():
        src = collector._sources[ls]
        tracked += len(src.columns)
        per_host = _host_losses(ls, src, first_day, end_day, thresholds)
        aggregate = _aggregate_losses(ls, src, first_day, end_day, thresholds)
        shared: dict[str, list[_Lost]] = {}
        for losses in per_host.values():
            for item in losses:
                shared.setdefault(item.field, []).append(item)
        wide_fields = {name for name, items in shared.items() if len(items) >= SHARED_MIN_HOSTS}
        attributed = set(shared)
        wide = [item for item in aggregate if item.field in wide_fields or item.field not in attributed]
        for name in sorted(wide_fields - {item.field for item in wide}):
            best = max(shared[name], key=lambda i: i.events_before)  # aggregate diluted by healthy hosts
            since = min(i.since for i in shared[name])
            last_seen = max(i.last_seen for i in shared[name])
            wide.append(
                _Lost(ls, None, name, best.before, best.after, 0, 0, since, best.volume_ratio, last_seen=last_seen)
            )
        hosts_by_field = {name: sorted(i.host for i in shared.get(name, []) if i.host) for name in wide_fields}
        if wide:
            findings.append(_wide_finding(ls, wide, hosts_by_field, tenant, basis))
            rows_out.extend(_row(item, hosts_by_field.get(item.field, [])) for item in wide)
        for host in sorted(per_host):
            own = [item for item in per_host[host] if item.field not in wide_fields]
            if own:
                findings.append(_host_finding(ls, host, own, tenant, basis))
                rows_out.extend(_row(item, [host]) for item in own)
    if not collector._sources:
        status = "not_assessed"
    elif any(f.severity.rank >= Severity.HIGH.rank for f in findings):
        status = "fail"
    elif findings:
        status = "warn"
    else:
        status = "ok"
    section: dict[str, Any] = {
        "status": status,
        "log_sources": len(collector._sources),
        "hosts": sum(len([h for h in s.hosts if h != OVERFLOW]) for s in collector._sources.values()),
        "fields_tracked": tracked,
        "events": collector.events,
        "lost": rows_out[:MAX_LOST_IN_SECTION],
        "truncated": collector.truncated or any(s.truncated for s in collector._sources.values()),
        "overflow_events": collector.overflow_events,
        "dropped_days": sum(s.dropped_days for s in collector._sources.values()),
    }
    return findings, section


def _series(rows: Mapping[int, Sequence[int]], days: Sequence[int], col: int) -> list[tuple[int, int, int]]:
    return [(day, (rows[day][col] if col < len(rows[day]) else 0), rows[day][0]) for day in days]


def _host_losses(
    ls: str, src: _Source, first_day: int, end_day: int, thresholds: tuple[float, float, int]
) -> dict[str, list[_Lost]]:
    before_min, after_max, min_events = thresholds
    columns = [(col, name) for col, name in enumerate(src.names) if col and name]
    out: dict[str, list[_Lost]] = {}
    for host_name, host in src.hosts.items():
        if host_name in ("", OVERFLOW):
            continue  # unattributable: covered by the log-source aggregate
        days = sorted(d for d, row in host.days.items() if first_day <= d <= end_day and row[0] > 0)
        if len(days) < 2:
            continue
        last = host.days[days[-1]]
        for col, name in columns:
            # cheap prefilter: absent on the host's last day and common over the kept history
            if (last[col] if col < len(last) else 0) > after_max * last[0]:
                continue
            if sum(row[col] for row in host.days.values() if col < len(row)) < before_min * min_events:
                continue
            item = _field_lost(_series(host.days, days, col), before_min, after_max, min_events)
            if item is not None:
                item.log_source, item.host, item.field = ls, host_name, name
                item.last_seen = host.last[col] if col < len(host.last) else 0.0
                out.setdefault(host_name, []).append(item)
    return out


def _aggregate_losses(
    ls: str, src: _Source, first_day: int, end_day: int, thresholds: tuple[float, float, int]
) -> list[_Lost]:
    before_min, after_max, min_events = thresholds
    days = sorted(d for d, row in src.agg.items() if first_day <= d <= end_day and row[0] > 0)
    if len(days) < 2:
        return []
    out = []
    for col, name in enumerate(src.names):
        if not col or not name:
            continue
        item = _field_lost(_series(src.agg, days, col), before_min, after_max, min_events)
        if item is not None:
            item.log_source, item.host, item.field = ls, None, name
            item.last_seen = max((h.last[col] for h in src.hosts.values() if col < len(h.last)), default=0.0)
            out.append(item)
    return out


def _field_lost(
    series: list[tuple[int, int, int]], before_min: float, after_max: float, min_events: int
) -> _Lost | None:
    """``series`` = ``[(day, events with the field, events)]`` sorted by day (days with events only)."""
    # 1. the most recent run of days where the field is (almost) absent
    recent_present = recent_events = 0
    cut = len(series)
    for idx in range(len(series) - 1, -1, -1):
        _, present, n = series[idx]
        if present > after_max * n:
            break
        recent_present += present
        recent_events += n
        cut = idx
    if cut == len(series) or cut == 0 or recent_events < min_events:
        return None
    # 2. the baseline before it; the transition day (field vanished mid-day) belongs to neither side, but it is the
    #    day the loss began
    base = series[:cut]
    since = series[cut][0]
    if base[-1][1] < before_min * base[-1][2] and len(base) > 1:
        since = base[-1][0]
        base = base[:-1]
    base_present = sum(present for _, present, _ in base)
    base_events = sum(n for _, _, n in base)
    if base_events < min_events or base_present < before_min * base_events:
        return None
    return _Lost(
        log_source="",
        host=None,
        field="",
        before=base_present / base_events,
        after=recent_present / recent_events,
        events_before=base_events,
        events_after=recent_events,
        since=since,
        volume_ratio=(recent_events / (len(series) - cut)) / (base_events / len(base)),
    )


def _row(item: _Lost, hosts: list[str]) -> dict[str, Any]:
    return {
        "log_source": item.log_source,
        "hosts": [Entity("host", h) for h in hosts[:MAX_HOSTS_IN_EVIDENCE]],
        "field": item.field,
        "before": round(item.before, 4),
        "after": round(item.after, 4),
        "events_before": item.events_before,
        "events_after": item.events_after,
        "since": date.fromordinal(item.since).isoformat(),
        "last_seen": _iso(item.last_seen),
    }


def _field_evidence(items: list[_Lost]) -> list[dict[str, Any]]:
    return [
        {
            "field": i.field,
            "before": round(i.before, 4),
            "after": round(i.after, 4),
            "events_before": i.events_before,
            "events_after": i.events_after,
            "since": date.fromordinal(i.since).isoformat(),
            "last_seen": _iso(i.last_seen),
            "detection_relevant": i.field in DETECTION_FIELDS,
        }
        for i in items[:50]
    ]


def _field_reasons(items: list[_Lost], basis: DataBasis | None) -> tuple[list[Message | str], bool]:
    reasons: list[Message | str] = [
        M(
            "silence.field.reason",
            field=i.field,
            before=i.before,
            after=i.after,
            events_before=i.events_before,
            events_after=i.events_after,
            since=date.fromordinal(i.since).isoformat(),
            last_seen=_iso(i.last_seen) or "-",
        )
        if i.events_before
        else M(
            "silence.field.reason_hosts",
            field=i.field,
            since=date.fromordinal(i.since).isoformat(),
            last_seen=_iso(i.last_seen) or "-",
        )
        for i in items[:10]
    ]
    low = False
    if basis is not None and basis.input_kind in ("alerts", "indexer-alerts"):
        reasons.append(M("silence.field.alerts_only"))
        low = True
    volume_ratio = min(i.volume_ratio for i in items)
    if volume_ratio < MIX_CHANGE_RATIO:
        # e.g. only some event types (or, unattributed, some hosts) are still sent: not necessarily a parser change
        reasons.append(M("silence.field.mix_change", ratio=volume_ratio))
        low = True
    return reasons, low


def _iso(epoch: float) -> str | None:
    """ISO-8601 UTC for an epoch (None when unknown)."""
    if not epoch or not math.isfinite(epoch) or epoch <= 0:
        return None
    try:
        return datetime.fromtimestamp(epoch, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError, ValueError):
        return None


def _last_seen(items: list[_Lost]) -> str | None:
    """When the fields were last seen: the earliest of the per-field "last seen" times (the loss began then)."""
    known = [i.last_seen for i in items if i.last_seen > 0]
    return _iso(min(known)) if known else None


def _esc(component: str) -> str:
    """Subject component: ``|`` and ``,`` separate components and field lists, so they are percent-encoded (field
    and host names come from attacker-controllable documents and must not forge another finding's subject)."""
    return component.replace("|", "%7C").replace(",", "%2C")


def _subject(prefix: str, items: list[_Lost]) -> str:
    """``agent:<host>|ls:<source>|field:<name>`` (or ``fields:a,b,...`` when one change dropped several)."""
    names = sorted({_esc(i.field) for i in items})
    if len(names) == 1:
        return f"{prefix}|field:{names[0]}"
    shown = ",".join(names[:10])
    if len(names) > 10:
        shown += f",+{len(names) - 10}#{stable_hash(*names, length=10)}"
    return f"{prefix}|fields:{shown}"


def _names(items: list[_Lost]) -> list[str]:
    names = [i.field for i in sorted(items, key=lambda i: (i.field not in DETECTION_FIELDS, i.field))]
    shown = names[:MAX_FIELDS_IN_TITLE]
    if len(names) > MAX_FIELDS_IN_TITLE:
        shown.append(f"+{len(names) - MAX_FIELDS_IN_TITLE}")
    return shown


def _host_finding(ls: str, host: str, items: list[_Lost], tenant: TenantConfig, basis: DataBasis | None) -> Finding:
    items = sorted(items, key=lambda i: (i.field not in DETECTION_FIELDS, i.field))
    agent = Entity("host", host)
    since = date.fromordinal(min(i.since for i in items)).isoformat()
    title = (
        M("silence.field.title_host_one", field=items[0].field, log_source=ls, agent=agent)
        if len(items) == 1
        else M("silence.field.title_host", fields=_names(items), log_source=ls, agent=agent)
    )
    reasons, low = _field_reasons(items, basis)
    critical = tenant.tier_for(host) == "critical"
    severity = Severity.HIGH if critical or any(i.field in DETECTION_FIELDS for i in items) else Severity.MEDIUM
    return Finding(
        kind="silence.field_lost",
        domain="silence",
        title=title,
        severity=severity,
        subject=_subject(f"agent:{_esc(host)}|ls:{_esc(ls)}", items),
        reasons=reasons,
        evidence={
            "level": "agent_log_source",
            "agent": agent,
            "log_source": ls,
            "tier": tenant.tier_for(host),
            "since": since,
            "last_seen": _last_seen(items),
            "fields": _field_evidence(items),
            "fields_lost": len(items),
            "volume_ratio": round(min(i.volume_ratio for i in items), 4),
            "reproduce": {
                "filter": {"agent.name": agent, "log_source": ls},
                "from": _last_seen(items) or since,
                "missing_fields": [i.field for i in items[:20]],
            },
        },
        recommendation=M("silence.field.rec_host", log_source=ls, agent=agent),
        confidence=Confidence.LOW if low else Confidence.MEDIUM,
        score=float(len(items)),
        tenant=tenant.name,
    )


def _wide_finding(
    ls: str, items: list[_Lost], hosts_by_field: dict[str, list[str]], tenant: TenantConfig, basis: DataBasis | None
) -> Finding:
    items = sorted(items, key=lambda i: (i.field not in DETECTION_FIELDS, i.field))
    hosts = sorted({h for i in items for h in hosts_by_field.get(i.field, [])})
    since = date.fromordinal(min(i.since for i in items)).isoformat()
    names = _names(items)
    if hosts:
        title = M("silence.field.title_hosts", fields=names, log_source=ls, count=len(hosts))
    elif len(items) == 1:
        title = M("silence.field.title_one", field=items[0].field, log_source=ls)
    else:
        title = M("silence.field.title", fields=names, log_source=ls)
    reasons, low = _field_reasons(items, basis)
    if hosts:
        reasons.insert(0, M("silence.field.hosts", hosts=[Entity("host", h) for h in hosts[:10]], count=len(hosts)))
    critical = any(tenant.tier_for(h) == "critical" for h in hosts)
    severity = Severity.HIGH if critical or any(i.field in DETECTION_FIELDS for i in items) else Severity.MEDIUM
    return Finding(
        kind="silence.field_lost",
        domain="silence",
        title=title,
        severity=severity,
        subject=_subject(f"ls:{_esc(ls)}", items),
        reasons=reasons,
        evidence={
            "level": "log_source",
            "log_source": ls,
            "hosts": [Entity("host", h) for h in hosts[:MAX_HOSTS_IN_EVIDENCE]],
            "hosts_affected": len(hosts),
            "since": since,
            "last_seen": _last_seen(items),
            "fields": _field_evidence(items),
            "fields_lost": len(items),
            "volume_ratio": round(min(i.volume_ratio for i in items), 4),
            "reproduce": {
                "filter": {"log_source": ls},
                "from": _last_seen(items) or since,
                "missing_fields": [i.field for i in items[:20]],
            },
        },
        recommendation=M("silence.field.rec", log_source=ls),
        confidence=Confidence.LOW if low else Confidence.MEDIUM,
        score=float(len(items) * max(1, len(hosts))),
        tenant=tenant.name,
    )


register(
    {
        "silence.field.title": {
            "en": "Fields vanished from {log_source}: {fields}",
            "es": "Campos desaparecidos de {log_source}: {fields}",
        },
        "silence.field.title_one": {
            "en": "Field {field} vanished from {log_source}",
            "es": "El campo {field} desapareció de {log_source}",
        },
        "silence.field.title_host": {
            "en": "Fields vanished from {log_source} on {agent}: {fields}",
            "es": "Campos desaparecidos de {log_source} en {agent}: {fields}",
        },
        "silence.field.title_host_one": {
            "en": "Field {field} vanished from {log_source} on {agent}",
            "es": "El campo {field} desapareció de {log_source} en {agent}",
        },
        "silence.field.title_hosts": {
            "en": "Fields vanished from {log_source} on {count} hosts at once: {fields}",
            "es": "Campos desaparecidos de {log_source} en {count} equipos a la vez: {fields}",
        },
        "silence.field.hosts": {
            "en": "Affected hosts ({count}): {hosts}. The same change on several hosts points to a decoder, ruleset "
            "or central configuration change rather than to one device.",
            "es": "Equipos afectados ({count}): {hosts}. El mismo cambio en varios equipos apunta a un cambio de "
            "decoder, de reglas o de configuración central más que a un dispositivo concreto.",
        },
        "silence.field.reason": {
            "en": "{field} was present in {before:.0%} of {events_before} events until it vanished on {since} (last "
            "seen {last_seen}); since then only {after:.0%} of {events_after} events carry it.",
            "es": "{field} estaba presente en el {before:.0%} de {events_before} eventos hasta que desapareció el "
            "{since} (última vez visto: {last_seen}); desde entonces solo lo lleva el {after:.0%} de {events_after} "
            "eventos.",
        },
        "silence.field.reason_hosts": {
            "en": "{field} vanished on {since} (last seen {last_seen}) on each of the affected hosts.",
            "es": "{field} desapareció el {since} (última vez visto: {last_seen}) en cada uno de los equipos "
            "afectados.",
        },
        "silence.field.alerts_only": {
            "en": "Measured on alerts only: field presence depends on which rules fired, so confirm on raw events.",
            "es": "Medido solo sobre alertas: la presencia de campos depende de qué reglas se dispararon, así que "
            "confírmelo con eventos en bruto.",
        },
        "silence.field.mix_change": {
            "en": "The daily volume also fell to {ratio:.0%} of its baseline: the loss may come from a change in what "
            "is sent (event types or hosts; check the silence findings) rather than from a parser change.",
            "es": "El volumen diario también bajó al {ratio:.0%} de su línea base: la pérdida puede deberse a un "
            "cambio en lo que se envía (tipos de evento o equipos; revise los hallazgos de silencio) y no a un cambio "
            "de parser.",
        },
        "silence.field.rec": {
            "en": "Check the decoder/parser and the source configuration of {log_source} (firmware, agent or "
            "pipeline upgrades often rename or drop fields): rules that use these fields can no longer match.",
            "es": "Revise el decoder/parser y la configuración de la fuente {log_source} (las actualizaciones de "
            "firmware, agente o pipeline suelen renombrar o eliminar campos): las reglas que usan estos campos ya no "
            "pueden coincidir.",
        },
        "silence.field.rec_host": {
            "en": "Check what changed on {agent} (firmware or agent upgrade, logging format, audit settings) and "
            "whether the {log_source} decoder still parses its events: rules that use these fields can no longer "
            "match for this host.",
            "es": "Revise qué cambió en {agent} (actualización de firmware o de agente, formato de logs, configuración "
            "de auditoría) y si el decoder de {log_source} sigue interpretando sus eventos: las reglas que usan estos "
            "campos ya no pueden coincidir para este equipo.",
        },
    }
)
