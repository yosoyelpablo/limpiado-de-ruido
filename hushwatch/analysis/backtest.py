"""Backtest (second pass): replay each suggestion's exact predicate over the whole window (architecture §5.5).

Matching uses :meth:`hushwatch.tuning.Suggestion.matches` and nothing else, so what the backtest counts is
exactly what the generated Wazuh rule would hide. For every suggestion it measures hidden alerts per day,
analyst-facing alerts and clusters, distinct agents, the share of the rule's volume, levels, dispositions
(true positives by alert id and by field-scoped disposition rows) and keeps three example documents.

It also re-checks, on the hidden events themselves, what the first-pass gates could only approximate:

* any hidden event at level >= ``tenant.high_level``, or whose level is unknown;
* any hidden true positive (by alert id, or by a field-scoped TP row, compared case- and space-insensitively and
  with short field names such as ``srcip`` resolved: over-matching a veto is the safe direction);
* hidden events whose *actor* entities (source IPs, public destination IPs, users outside failed logons, and
  the host when the suggestion pins a host or a syslog sender) appear in a high-level alert within ± the
  co-occurrence window;
* hidden events carrying a public address with sustained hourly activity (labelled *beaconing* only for an
  outbound destination contacted at a steady interval; a public source active for hours is a scan, brute force
  or spray, not a beacon);
* any actor first seen after the novelty cut-off of the window (however few alerts it has: an intruder does not
  need many), or more distinct actors than can be verified;
* for scopes that do not pin a host (an internal source address, a syslog sender): any host first seen inside the
  scope after the novelty cut-off (lateral movement with a known identity);
* a scope whose hidden alerts mostly come from public addresses (exposure: fix at the source, never mute);
* a burst in the hidden per-day series.

Any of these downgrades the suggestion (see :func:`downgrade_reasons`): to ``fix_at_source`` when exposure is the
only problem, to ``investigate`` otherwise.
"""

from __future__ import annotations

import random
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from ..config import TenantConfig
from ..i18n import Entity, M, Message, register
from ..models import Event, stable_hash
from ..tuning import Suggestion
from . import gates as g
from .dispositions import DispositionCounts, Dispositions, inband_verdict
from .sketches import HyperLogLog, Reservoir, SpaceSaving

EXAMPLES = 3
ACTOR_CAPACITY = 64  # heavy actors (public peers, for beacon detection) tracked per suggestion
MAX_ACTORS = 2_000  # distinct actors (and, separately, public addresses) tracked exactly per suggestion
MAX_AGENTS = 10_000
MAX_LISTED_VALUES = 5
NOVEL_ACTOR_MIN = 1  # a single alert from an actor that appeared late is enough to refuse tuning
EXPOSURE_SHARE = g.EXPOSURE_SHARE
EXAMPLE_MAX_CHARS = 8192
_EXAMPLE_MAX_DEPTH = 8
_EXAMPLE_MAX_ITEMS = 500


@dataclass(slots=True)
class BacktestWatch:
    """Optional context for the backtest's safety re-checks (filled by the noise engine)."""

    high: g.HighAlertIndex | None = None
    co_window_hours: int = 24
    beacons: Mapping[str, frozenset[str]] = field(default_factory=dict)  # rule id -> sustained public IPs
    since: datetime | None = None  # disposition look-back start
    window: g.Window | None = None
    periodic: Mapping[str, frozenset[str]] = field(default_factory=dict)  # rule id -> beacons (outbound, steady)


@dataclass(slots=True)
class BacktestStats:
    """What one suggestion would hide."""

    fingerprint: str
    rule_id: str
    hidden_total: int = 0
    hidden_analyst_facing: int = 0
    hidden_high: int = 0
    hidden_unknown_level: int = 0
    hidden_external: int = 0  # hidden alerts whose source address is public
    tp_hidden: int = 0
    rule_total: int = 0
    rule_analyst_facing: int = 0
    dispositions: DispositionCounts = field(default_factory=DispositionCounts)
    per_day: dict[int, int] = field(default_factory=dict)
    analyst_facing_per_day: dict[int, int] = field(default_factory=dict)
    levels: dict[int, int] = field(default_factory=dict)
    agents: dict[str, float] = field(default_factory=dict)  # host -> first hidden alert (epoch seconds)
    agent_counts: dict[str, int] = field(default_factory=dict)
    agents_truncated: bool = False
    pins_host: bool = False  # the scope pins the host field itself (new hosts cannot enter it)
    novel_hosts: list[tuple[str, int]] = field(default_factory=list)  # (host, alerts) first seen late in scope
    novel_host_alerts: int = 0
    clusters: HyperLogLog = field(default_factory=HyperLogLog)
    analyst_facing_clusters: HyperLogLog = field(default_factory=HyperLogLog)
    first_seen: float | None = None
    last_seen: float | None = None
    co_occurring: int = 0
    co_values: list[tuple[str, str]] = field(default_factory=list)
    beacon_hits: int = 0  # hidden alerts carrying a beacon (outbound public destination at a steady interval)
    beacon_values: list[str] = field(default_factory=list)
    sustained_hits: int = 0  # hidden alerts carrying a public address with sustained, non-beacon activity
    sustained_values: list[str] = field(default_factory=list)
    public_sources: dict[str, int] = field(default_factory=dict)  # public SOURCE address -> hidden alerts
    outbound: set[str] = field(default_factory=set)  # public addresses seen as destinations
    novel_actors: list[tuple[str, str, int]] = field(default_factory=list)  # (kind, value, alerts), top 5
    novel_actor_alerts: int = 0  # hidden alerts from every late actor
    actors: SpaceSaving[tuple[str, str]] = field(default_factory=lambda: SpaceSaving(ACTOR_CAPACITY))
    actor_first: dict[tuple[str, str], list[float]] = field(default_factory=dict)  # actor -> [first ts, alerts]
    actors_truncated: bool = False  # more than MAX_ACTORS distinct actors: novelty cannot be verified
    public_first: dict[tuple[str, str], list[float]] = field(default_factory=dict)  # public addresses, same shape
    public_truncated: bool = False
    novel_public: list[tuple[str, str, int]] = field(default_factory=list)  # late public addresses, top 5
    novel_public_alerts: int = 0
    examples: Reservoir[Mapping[str, Any]] = field(default_factory=Reservoir)

    @property
    def hides_high(self) -> bool:
        """True when the suggestion would hide at least one alert at level >= tenant.high_level."""
        return self.hidden_high > 0

    @property
    def external_share(self) -> float:
        """Share of the hidden alerts whose source address is public."""
        return self.hidden_external / self.hidden_total if self.hidden_total else 0.0

    @property
    def share_of_rule(self) -> float:
        return self.hidden_total / self.rule_total if self.rule_total else 0.0

    @property
    def share_of_analyst_facing(self) -> float:
        return self.hidden_analyst_facing / self.rule_analyst_facing if self.rule_analyst_facing else 0.0

    @property
    def agents_affected(self) -> int:
        return len(self.agents)

    def example_docs(self) -> list[dict[str, Any]]:
        """Up to three hidden documents, long strings clipped (raw values: local suppression files only)."""
        return [clip_document(doc) for doc in self.examples.items]


def run_backtest(
    suggestions: Iterable[Suggestion],
    events: Iterable[Event],
    *,
    tenant: TenantConfig,
    dispositions: Dispositions | None,
    watch: BacktestWatch | None = None,
) -> dict[str, BacktestStats]:
    """Replay every suggestion over ``events`` (one pass) and return its stats by suggestion fingerprint."""
    if watch is None:
        watch = BacktestWatch(co_window_hours=_hours(tenant.noise.co_occurrence_window.total_seconds()))
    stats: dict[str, BacktestStats] = {}
    by_rule: dict[str, list[tuple[Suggestion, BacktestStats, bool]]] = {}
    host_paths = {path for path, item in g.all_fields(tenant).items() if item.role == g.ROLE_HOST}
    ips = g.IpClassifier(tenant)
    for suggestion in suggestions:
        if suggestion.fingerprint in stats:
            continue
        seed = int(stable_hash("backtest", suggestion.fingerprint, length=8), 16)
        entry = BacktestStats(
            suggestion.fingerprint, suggestion.rule_id, examples=Reservoir(EXAMPLES, random.Random(seed))
        )
        stats[suggestion.fingerprint] = entry
        # a rule-wide scope (explicit opt-in) mutes every host by definition; any other scope that does not pin the
        # host must not reach hosts it was never seen on
        entry.pins_host = not suggestion.conditions or any(c.field in host_paths for c in suggestion.conditions)
        # the scope stands for a device (a host, or a syslog sender): whatever hits that device is hidden with it
        host_anchored = entry.pins_host or any(
            c.field == "location" and _host_like_location(c.value, ips) for c in suggestion.conditions
        )
        by_rule.setdefault(suggestion.rule_id, []).append((suggestion, entry, host_anchored))
    if not by_rule:
        return stats

    tp_scopes: dict[str, list[tuple[tuple[str, ...], str]]] = {}
    if dispositions is not None:
        for rule_id in by_rule:
            tp_scopes[rule_id] = [
                (_tp_paths(row.field), _fold(row.value))
                for row in dispositions.scoped_for_rule(rule_id)
                if row.verdict == "tp"
                and row.field is not None
                and row.value is not None
                and (watch.since is None or row.closed_at is None or row.closed_at >= watch.since)
            ]
    triage, high = tenant.triage_level, tenant.high_level
    gap = max(1, int(tenant.noise.cluster_gap.total_seconds()))
    days = g.DayIndex(tenant.tz)
    resolvers: dict[str, g.SpecResolver] = {}
    rule_counts: dict[str, list[int]] = {rule_id: [0, 0] for rule_id in by_rule}
    high_index = watch.high if watch.high is not None and len(watch.high) else None
    window_hours = max(0, watch.co_window_hours)

    for event in events:
        event_rule = event.rule_id
        if event_rule is None:
            continue
        entries = by_rule.get(event_rule)
        if entries is None:
            continue
        level = _level(event.severity)
        analyst = level is None or level >= triage
        counts = rule_counts[event_rule]
        counts[0] += 1
        if analyst:
            counts[1] += 1
        matched = [item for item in entries if item[0].matches(event)]
        if not matched:
            continue
        try:
            epoch = event.ts.timestamp()
        except (AttributeError, OverflowError, OSError, ValueError):
            # an undatable alert counts as the NEWEST one: it must never make an actor or a host look established
            epoch = watch.window.end if watch.window is not None else 0.0
        day = days.day(epoch)
        hour = int(epoch // 3600)
        profile = matched[0][0].profile
        resolver = resolvers.get(profile)
        if resolver is None:
            resolver = resolvers[profile] = g.SpecResolver(profile, tenant)
        spec = resolver.for_fields(event.fields)
        extracted = g.extract(spec, event.fields, event.rule_groups)
        chash = g.cluster_hash(event_rule, extracted.values, int(epoch // gap))
        host = extracted.host[1] if extracted.host is not None else (event.source or None)
        verdict = (
            dispositions.verdict_for_alert(event.event_id, watch.since)
            if dispositions is not None and event.event_id
            else None
        )
        if spec.ecs_context:
            inband = inband_verdict(event.fields)
            if inband is not None and verdict != "tp":
                verdict = inband
        tp = verdict == "tp" or any(_tp_matches(event, paths, value) for paths, value in tp_scopes.get(event_rule, ()))
        actors: list[tuple[str, str]] = []
        host_hits: list[tuple[str, str]] = []
        if high_index is not None:
            actors, host_hits = _cooccurring(extracted, high_index, hour, window_hours, ips)
        actor_values = _actor_values(extracted, ips)
        external = any(
            item.direction == "src" and item.role in g.IP_ROLES and ips.kind(v) == "external"
            for item, v in extracted.values
        )
        rule_beacons = watch.beacons.get(event_rule)
        rule_periodic = watch.periodic.get(event_rule, frozenset())
        sustained = (
            [v for item, v in extracted.values if item.role in g.IP_ROLES and v in rule_beacons] if rule_beacons else []
        )
        beacons = [v for v in sustained if v in rule_periodic]
        sustained = [v for v in sustained if v not in rule_periodic]
        sources = [
            v
            for item, v in extracted.values
            if item.direction == "src" and item.role in g.IP_ROLES and ips.kind(v) == "external"
        ]
        for _suggestion, entry, host_anchored in matched:
            entry.hidden_total += 1
            entry.per_day[day] = entry.per_day.get(day, 0) + 1
            entry.clusters.add_hash(chash)
            if analyst:
                entry.hidden_analyst_facing += 1
                entry.analyst_facing_per_day[day] = entry.analyst_facing_per_day.get(day, 0) + 1
                entry.analyst_facing_clusters.add_hash(chash)
            if level is not None:
                entry.levels[level] = entry.levels.get(level, 0) + 1
                if level >= high:
                    entry.hidden_high += 1
            else:
                entry.hidden_unknown_level += 1  # cannot show it is below high_level
            if external:
                entry.hidden_external += 1
            if verdict is not None:
                entry.dispositions.add(verdict)
            if tp:
                entry.tp_hidden += 1
            if host:
                first = entry.agents.get(host)
                if first is not None:
                    entry.agent_counts[host] += 1
                    if epoch < first:
                        entry.agents[host] = epoch
                elif len(entry.agents) < MAX_AGENTS:
                    entry.agents[host] = epoch
                    entry.agent_counts[host] = 1
                else:
                    entry.agents_truncated = True
            hits = actors + host_hits if host_anchored else actors
            if hits:
                entry.co_occurring += 1
                for hit in hits:
                    if hit not in entry.co_values and len(entry.co_values) < MAX_LISTED_VALUES:
                        entry.co_values.append(hit)
            if beacons:
                entry.beacon_hits += 1
                for value in beacons:
                    if value not in entry.beacon_values and len(entry.beacon_values) < MAX_LISTED_VALUES:
                        entry.beacon_values.append(value)
            elif sustained:
                entry.sustained_hits += 1
                for value in sustained:
                    if value not in entry.sustained_values and len(entry.sustained_values) < MAX_LISTED_VALUES:
                        entry.sustained_values.append(value)
            for value in sources:
                if value in entry.public_sources:
                    entry.public_sources[value] += 1
                elif len(entry.public_sources) < MAX_ACTORS:
                    entry.public_sources[value] = 1
            if entry.first_seen is None or epoch < entry.first_seen:
                entry.first_seen = epoch
            if entry.last_seen is None or epoch > entry.last_seen:
                entry.last_seen = epoch
            entry.examples.add(event.fields)
            for actor, public, outbound in actor_values:
                if public:
                    entry.actors.add(actor, 1, epoch, None, hour)
                    if outbound and len(entry.outbound) < MAX_ACTORS:
                        entry.outbound.add(actor[1])
                table = entry.public_first if public else entry.actor_first
                seen = table.get(actor)
                if seen is not None:
                    seen[1] += 1
                    if epoch < seen[0]:
                        seen[0] = epoch
                elif len(table) < MAX_ACTORS:
                    table[actor] = [epoch, 1]
                elif public:
                    entry.public_truncated = True
                else:
                    entry.actors_truncated = True

    novelty_limit = None
    if watch.window is not None:
        novelty_limit = watch.window.start + tenant.noise.novelty_fraction * watch.window.duration
    for rule_id, entries in by_rule.items():
        total, analyst_total = rule_counts[rule_id]
        for suggestion, entry, _host in entries:
            entry.rule_total, entry.rule_analyst_facing = total, analyst_total
            _inspect_actors(suggestion, entry, novelty_limit)
    return stats


def _actor_values(extracted: g.Extracted, ips: g.IpClassifier) -> list[tuple[tuple[str, str], bool, bool]]:
    """((kind, value), is public IP, is a destination) for the actors of an event: source IPs, public
    destinations, users outside failed logons (attempted usernames are attacker-chosen noise) and process images
    (a binary that never ran in this scope before is new software, or malware)."""
    out: list[tuple[tuple[str, str], bool, bool]] = []
    for item, value in extracted.values:
        if item.role in g.IP_ROLES:
            kind = ips.kind(value)
            if item.direction == "dst" and kind != "external":
                continue
            if g.cooccurrence_kind(item, value) is not None:
                out.append((("ip", value), kind == "external", item.direction == "dst"))
        elif item.role == g.ROLE_USER and not (extracted.failure and item.failure_sensitive):
            if g.cooccurrence_kind(item, value) is not None:
                out.append((("user", value), False, False))
        elif item.role == g.ROLE_PROCESS:
            out.append((("file", value), False, False))
    return out


def _inspect_actors(suggestion: Suggestion, entry: BacktestStats, novelty_limit: float | None) -> None:
    """Actors (and, for scopes that do not pin a host, hosts) inside the hidden set that appeared after the novelty
    cut-off, and public addresses with beacon-like periodicity."""
    pinned = {c.value for c in suggestion.conditions}
    for actor in entry.actors.top():
        kind, value = actor.key
        if value in pinned or kind != "ip" or not g.beacon_like(actor):
            continue
        if value in entry.beacon_values or value in entry.sustained_values:
            continue
        periodic = value in entry.outbound and (actor.regularity() or 0.0) >= g.PERIODIC_MIN_SHARE
        if periodic:  # outbound and steady: a beacon
            entry.beacon_hits += actor.count - actor.error
            if len(entry.beacon_values) < MAX_LISTED_VALUES:
                entry.beacon_values.append(value)
        else:  # a public source active for hours (scan, spray) or irregular traffic: sustained, not a beacon
            entry.sustained_hits += actor.count - actor.error
            if len(entry.sustained_values) < MAX_LISTED_VALUES:
                entry.sustained_values.append(value)
    if novelty_limit is None:
        return
    # the suggestion's own anchor is skipped: its novelty was gated in pass 1
    for table, public in ((entry.actor_first, False), (entry.public_first, True)):
        novel = sorted(
            (
                (kind, value, int(count))
                for (kind, value), (first, count) in table.items()
                if first > novelty_limit and count >= NOVEL_ACTOR_MIN and value not in pinned
            ),
            key=lambda item: (-item[2], item[0], item[1]),
        )
        if public:
            entry.novel_public = novel[:MAX_LISTED_VALUES]
            entry.novel_public_alerts = sum(n for _, _, n in novel)
        else:
            entry.novel_actors = novel[:MAX_LISTED_VALUES]
            entry.novel_actor_alerts = sum(n for _, _, n in novel)
    if not entry.pins_host:
        hosts = sorted(
            (
                (host, entry.agent_counts.get(host, 0))
                for host, first in entry.agents.items()
                if first > novelty_limit and host not in pinned
            ),
            key=lambda item: (-item[1], item[0]),
        )
        entry.novel_hosts = hosts[:MAX_LISTED_VALUES]
        entry.novel_host_alerts = sum(n for _, n in hosts)


def _cooccurring(
    extracted: g.Extracted,
    index: g.HighAlertIndex,
    hour: int,
    window_hours: int,
    ips: g.IpClassifier,
) -> tuple[list[tuple[str, str]], list[tuple[str, str]]]:
    """(actor hits, host hits): entity values of a hidden event seen in high-level alerts within the window."""
    actors: list[tuple[str, str]] = []
    hosts: list[tuple[str, str]] = []
    for item, value in extracted.values:
        if item.role == g.ROLE_HOST:
            if index.count_near("host", value, hour, window_hours):
                hosts.append(("host", value))
            continue
        if item.path == "location":
            if _host_like_location(value, ips) and index.count_near("ip", value, hour, window_hours):
                hosts.append(("ip", value))  # a syslog sender: the device itself
            continue
        if item.role in g.IP_ROLES:
            if item.direction == "dst" and ips.kind(value) != "external":
                continue  # an internal target is not the actor
        elif item.role == g.ROLE_USER:
            if extracted.failure and item.failure_sensitive:
                continue  # usernames tried in failed logons are attacker-chosen noise
        else:
            continue
        kind = g.cooccurrence_kind(item, value)
        if kind is not None and index.count_near(kind, value, hour, window_hours):
            actors.append((kind, value))
    return actors, hosts


_TP_ALIASES: dict[str, tuple[str, ...]] = {
    "srcip": ("data.srcip",),
    "src_ip": ("data.srcip", "source.ip"),
    "source_ip": ("data.srcip", "source.ip"),
    "dstip": ("data.dstip",),
    "dst_ip": ("data.dstip", "destination.ip"),
    "srcuser": ("data.srcuser",),
    "dstuser": ("data.dstuser",),
    "user": (
        "data.srcuser",
        "data.dstuser",
        "data.win.eventdata.subjectUserName",
        "data.win.eventdata.targetUserName",
        "user.name",
    ),
    "host": ("agent.name", "predecoder.hostname", "host.name"),
    "agent": ("agent.name",),
    "hostname": ("predecoder.hostname", "host.name"),
    "image": ("data.win.eventdata.image", "process.executable"),
    "process": ("data.win.eventdata.image", "process.executable"),
    "commandline": ("data.win.eventdata.commandLine", "process.command_line"),
    "command_line": ("data.win.eventdata.commandLine", "process.command_line"),
    "url": ("data.url", "url.original", "url.full"),
}


def _fold(value: str) -> str:
    return value.strip().casefold()


def _tp_paths(field_name: str) -> tuple[str, ...]:
    """Where a TP row's ``field`` may live: as written, under ``data.`` and through common short names."""
    name = field_name.strip()
    paths = [name]
    if not name.startswith("data.") and "." not in name:
        paths.append(f"data.{name}")
    for alias in _TP_ALIASES.get(name.lower(), ()):
        if alias not in paths:
            paths.append(alias)
    return tuple(paths)


def _tp_matches(event: Event, paths: tuple[str, ...], value: str) -> bool:
    """A field-scoped TP row applies to ``event`` (case- and space-insensitive: over-matching a veto is safe)."""
    for path in paths:
        actual = g.field_value(event.fields, path)
        if actual is None:
            continue
        items = actual if isinstance(actual, (list, tuple)) else (actual,)
        if any(not isinstance(item, (dict, list)) and _fold(str(item)) == value for item in items):
            return True
    return False


def _host_like_location(value: str, ips: g.IpClassifier) -> bool:
    """A Wazuh ``location`` naming the sending device (syslog sender address or ``host->path``)."""
    return "->" in value or ips.kind(value) != "invalid"


def downgrade_reasons(
    stats: BacktestStats,
    *,
    tenant: TenantConfig,
    window: g.Window | None = None,
    burst_factor: float | None = None,
) -> list[Message]:
    """Reasons why a suggestion must NOT be tuned after its backtest (empty list: it passed)."""
    reasons: list[Message] = []
    if stats.hidden_high:
        reasons.append(M("noise.backtest.high", count=stats.hidden_high, level=tenant.high_level))
    if stats.hidden_unknown_level:
        reasons.append(M("noise.backtest.unknown_level", count=stats.hidden_unknown_level, level=tenant.high_level))
    if stats.tp_hidden:
        reasons.append(M("noise.backtest.tp", count=stats.tp_hidden))
    if stats.co_occurring:
        reasons.append(
            M(
                "noise.backtest.co_occurrence",
                count=stats.co_occurring,
                entities=[Entity(kind, value) for kind, value in stats.co_values],
                level=tenant.high_level,
                window=f"{_hours(tenant.noise.co_occurrence_window.total_seconds())}h",
            )
        )
    # in a scope that is mostly Internet traffic (exposure, below) ever-new public addresses ARE the exposure: the
    # verdict is fix_at_source for them; any other newcomer (an internal address, a user, a binary) is investigated
    exposure = bool(stats.hidden_total) and stats.external_share >= EXPOSURE_SHARE
    novel = list(stats.novel_actors)
    novel_alerts = stats.novel_actor_alerts or sum(n for _, _, n in stats.novel_actors)
    if not exposure:
        novel += stats.novel_public
        novel_alerts += stats.novel_public_alerts or sum(n for _, _, n in stats.novel_public)
    if novel:
        novel.sort(key=lambda item: (-item[2], item[0], item[1]))
        reasons.append(
            M(
                "noise.backtest.novel_actor",
                count=novel_alerts,
                entities=[Entity(kind, value) for kind, value, _ in novel[:MAX_LISTED_VALUES]],
            )
        )
    if stats.actors_truncated or (stats.public_truncated and not exposure):
        reasons.append(M("noise.backtest.actors_truncated", max=MAX_ACTORS))
    if stats.novel_hosts:
        reasons.append(
            M(
                "noise.backtest.novel_host",
                count=stats.novel_host_alerts or sum(n for _, n in stats.novel_hosts),
                entities=[Entity("host", host) for host, _ in stats.novel_hosts],
            )
        )
    if not stats.pins_host and stats.agents_truncated:
        reasons.append(M("noise.backtest.hosts_truncated", max=MAX_AGENTS))
    if exposure:
        reasons.append(exposure_reason(stats))
    if stats.beacon_hits:
        reasons.append(
            M(
                "noise.backtest.beacon",
                count=stats.beacon_hits,
                entities=[Entity("ip", value) for value in stats.beacon_values],
            )
        )
    if stats.sustained_hits:
        reasons.append(
            M(
                "noise.backtest.sustained",
                count=stats.sustained_hits,
                entities=[Entity("ip", value) for value in stats.sustained_values],
            )
        )
    factor = tenant.noise.burst_factor if burst_factor is None else burst_factor
    span = _span(window, stats.per_day)
    if span is not None and stats.hidden_total:
        peak, median, peak_day = g.burst_stats(stats.per_day, span)
        base = max(median, 1.0)
        if peak >= factor * base:
            reasons.append(
                M(
                    "noise.backtest.burst",
                    peak=peak,
                    day=g.day_label(peak_day),
                    median=median,
                    factor=peak / base,
                    limit=factor,
                )
            )
    return reasons


def exposure_reason(stats: BacktestStats) -> Message:
    """The downgrade reason for a scope whose hidden alerts mostly come from public addresses."""
    return M(
        "noise.backtest.exposure",
        count=stats.hidden_external,
        total=stats.hidden_total,
        share=stats.external_share,
        min=EXPOSURE_SHARE,
    )


EXPOSURE_KEY = "noise.backtest.exposure"


def summary_message(stats: BacktestStats, *, tenant: TenantConfig, days: float) -> Message:
    """One-line description of a clean backtest (``days``: elapsed days of the window)."""
    return M(
        "noise.backtest.clean",
        hidden=stats.hidden_total,
        per_day=rate(stats.hidden_total / max(1.0, days)),
        share=pct(stats.share_of_rule),
        analyst=stats.hidden_analyst_facing,
        agents=stats.agents_affected,
        level=tenant.high_level,
    )


def rate(per_day: float) -> Message:
    """A per-day rate with a precision that never shows a non-zero rate as 0.0/day."""
    if per_day <= 0:
        return M("noise.rate.day", value=0.0)
    if per_day < 0.01:
        return M("noise.rate.day_tiny")
    if per_day < 1:
        return M("noise.rate.day_small", value=per_day)
    return M("noise.rate.day", value=per_day)


def pct(share: float) -> Message:
    """A share with a precision that never shows a non-zero share as 0%."""
    if 0 < share < 0.001:
        return M("noise.pct_tiny")
    if 0 < share < 0.01:
        return M("noise.pct_small", value=share)
    return M("noise.pct", value=share)


def _span(window: g.Window | None, per_day: Mapping[int, int]) -> g.Window | None:
    days = [d for d, c in per_day.items() if c]
    if window is None and not days:
        return None
    first = min([*days, window.first_day] if window is not None else days)
    last = max([*days, window.last_day] if window is not None else days)
    start = window.start if window is not None else 0.0
    end = window.end if window is not None else 0.0
    return g.Window(start, end, first, last)


def _level(value: Any) -> int | None:
    """An integer rule level, or None when unknown (bools, strings, NaN and fractional numbers are unknown)."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return None


def _hours(seconds: float) -> int:
    return max(0, round(seconds / 3600))


def clip_document(doc: Mapping[str, Any]) -> dict[str, Any]:
    """Copy of an example document with very long strings clipped and nesting bounded."""
    clipped = _clip(doc, 0)
    return clipped if isinstance(clipped, dict) else {}


def _clip(value: Any, depth: int) -> Any:
    if isinstance(value, str):
        if len(value) > EXAMPLE_MAX_CHARS:
            return value[:EXAMPLE_MAX_CHARS] + f"…[+{len(value) - EXAMPLE_MAX_CHARS} chars]"
        return value
    if depth >= _EXAMPLE_MAX_DEPTH:
        return None if isinstance(value, (Mapping, list, tuple)) else value
    if isinstance(value, Mapping):
        return {str(k): _clip(v, depth + 1) for k, v in list(value.items())[:_EXAMPLE_MAX_ITEMS]}
    if isinstance(value, (list, tuple)):
        return [_clip(v, depth + 1) for v in list(value)[:_EXAMPLE_MAX_ITEMS]]
    return value


register(
    {
        "noise.backtest.high": {
            "en": "Backtest: would demote {count} alert(s) at level {level} or higher",
            "es": "Backtest: degradaría {count} alerta(s) de nivel {level} o superior",
        },
        "noise.backtest.tp": {
            "en": "Backtest: would demote {count} alert(s) confirmed as true positives",
            "es": "Backtest: degradaría {count} alerta(s) confirmadas como verdaderos positivos",
        },
        "noise.backtest.co_occurrence": {
            "en": "Backtest: {count} alert(s) it would demote involve {entities}, also seen in alerts at level "
            "{level} or higher within ±{window}",
            "es": "Backtest: {count} alerta(s) que degradaría involucran a {entities}, que también aparece(n) en "
            "alertas de nivel {level} o superior dentro de ±{window}",
        },
        "noise.backtest.beacon": {
            "en": "Backtest: {count} alert(s) it would demote go to {entities}, public address(es) contacted at a "
            "steady interval, like a beacon (command and control)",
            "es": "Backtest: {count} alerta(s) que degradaría van hacia {entities}, dirección(es) pública(s) "
            "contactada(s) a intervalos regulares, como un beacon (comando y control)",
        },
        "noise.backtest.sustained": {
            "en": "Backtest: {count} alert(s) it would demote involve {entities}, public address(es) active for "
            "many hours (a scan, brute force or spray from the Internet, or sustained traffic to it)",
            "es": "Backtest: {count} alerta(s) que degradaría involucran a {entities}, dirección(es) pública(s) "
            "activa(s) durante muchas horas (un escaneo, fuerza bruta o spray desde Internet, o tráfico sostenido "
            "hacia Internet)",
        },
        "noise.backtest.novel_actor": {
            "en": "Backtest: {count} alert(s) it would demote come from {entities}, first seen late in the window: "
            "new actors inside the scope are investigated, not tuned",
            "es": "Backtest: {count} alerta(s) que degradaría provienen de {entities}, vistos por primera vez al "
            "final de la ventana: los actores nuevos dentro del alcance se investigan, no se ajustan",
        },
        "noise.backtest.unknown_level": {
            "en": "Backtest: would demote {count} alert(s) whose level is unknown (they may be level {level} or "
            "higher)",
            "es": "Backtest: degradaría {count} alerta(s) de nivel desconocido (podrían ser de nivel {level} o "
            "superior)",
        },
        "noise.backtest.actors_truncated": {
            "en": "Backtest: the scope holds more than {max} distinct actors, so new actors inside it cannot be "
            "ruled out",
            "es": "Backtest: el alcance contiene más de {max} actores distintos, así que no se pueden descartar "
            "actores nuevos dentro de él",
        },
        "noise.backtest.novel_host": {
            "en": "Backtest: {count} alert(s) it would demote are on {entities}, first seen in this scope late in "
            "the window: a known identity reaching a new host is investigated, not tuned",
            "es": "Backtest: {count} alerta(s) que degradaría están en {entities}, vistos por primera vez en este "
            "alcance al final de la ventana: una identidad conocida que llega a un equipo nuevo se investiga, no se "
            "ajusta",
        },
        "noise.backtest.hosts_truncated": {
            "en": "Backtest: the scope reaches more than {max} hosts, so new hosts inside it cannot be ruled out",
            "es": "Backtest: el alcance llega a más de {max} equipos, así que no se pueden descartar equipos nuevos "
            "dentro de él",
        },
        "noise.backtest.exposure": {
            "en": "Backtest: {count} of the {total} alerts it would demote ({share:.0%}, limit {min:.0%}) come from "
            "public addresses: restrict the exposure at the source instead of muting",
            "es": "Backtest: {count} de las {total} alertas que degradaría ({share:.0%}, límite {min:.0%}) provienen "
            "de direcciones públicas: restrinja la exposición en el origen en lugar de silenciarlas",
        },
        "noise.backtest.burst": {
            "en": "Backtest: {peak} alerts it would demote on {day}, {factor:.1f}× the median of {median:.1f} per "
            "day (limit {limit:.1f}×)",
            "es": "Backtest: {peak} alertas que degradaría el {day}, {factor:.1f}× la mediana de {median:.1f} por "
            "día (límite {limit:.1f}×)",
        },
        "noise.backtest.clean": {
            "en": "Backtest: would demote {hidden} alerts ({per_day}, {share} of the rule; {analyst} analyst-facing) "
            "on {agents} agent(s); none at level {level} or higher and no true positives",
            "es": "Backtest: degradaría {hidden} alertas ({per_day}, {share} de la regla; {analyst} visibles para "
            "analistas) en {agents} agente(s); ninguna de nivel {level} o superior y ningún verdadero positivo",
        },
        "noise.backtest.empty": {
            "en": "Backtest: the condition matched no alert on the second pass (the input changed?); nothing to tune",
            "es": "Backtest: la condición no coincidió con ninguna alerta en la segunda pasada (¿cambió la "
            "entrada?); no hay nada que ajustar",
        },
        "noise.rate.day": {"en": "{value:.1f}/day", "es": "{value:.1f}/día"},
        "noise.rate.day_small": {"en": "{value:.2f}/day", "es": "{value:.2f}/día"},
        "noise.rate.day_tiny": {"en": "<0.01/day", "es": "<0,01/día"},
        "noise.pct": {"en": "{value:.0%}", "es": "{value:.0%}"},
        "noise.pct_small": {"en": "{value:.1%}", "es": "{value:.1%}"},
        "noise.pct_tiny": {"en": "<0.1%", "es": "<0,1%"},
    }
)
