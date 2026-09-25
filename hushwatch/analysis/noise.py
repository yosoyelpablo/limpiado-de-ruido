"""The noise engine: which alerts can be SAFELY tuned (architecture §5; findings §2.1; section §2.2).

Its first requirement is to never recommend hiding an attack. Volume, concentration, regularity and duplicates
describe brute force, spraying, scanning and beaconing as well as benign automation, so a candidate only
becomes ``tune`` after passing every safety gate (:mod:`hushwatch.analysis.gates`) AND a backtest over the whole
window (:mod:`hushwatch.analysis.backtest`). Anything else is ``investigate``, ``fix_at_source``, ``aggregate``,
``do_not_tune``, ``watch`` or ``learning``.

Flow::

    collector = NoiseCollector(tenant, profile, dispositions)
    for event in source: collector.add(event)            # pass 1, bounded memory, mergeable
    result = analyze_noise(collector, tenant=tenant, now=now, dependents=ruleset.dependents)
    result = apply_backtest(result, source, tenant=tenant)   # pass 2: finalizes findings and the section

Until :func:`apply_backtest` has run, candidates that passed the gates carry the verdict ``watch`` (pending the
backtest) and the result holds one ``assessment.incomplete`` finding, so nothing is ever proposed for tuning
without a backtest.

Pass 1 keeps, per rule: totals, per-day counts (tenant local dates), level range, groups, MITRE ids/tactics,
analyst-facing count (level >= ``triage_level``), first/last seen, a HyperLogLog of
``(fingerprint, floor(ts / cluster_gap))`` for clusters, three reservoir examples, a Space-Saving summary per
anchor field, per (host × other anchor) pair and per (host × account × logon type) triple, and the
disposition-bearing alerts. Globally it keeps, for
alerts at level >= ``high_level``, the hours at which each host / IP / user value appeared (co-occurrence).
"""

from __future__ import annotations

import random
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from typing import Any

from ..config import NoiseSettings, TenantConfig
from ..i18n import Entity, M, Message, register
from ..models import Confidence, Event, Finding, Severity, stable_hash
from ..timeutil import iso
from ..tuning import Condition, Suggestion
from . import gates as g
from .backtest import EXPOSURE_KEY, BacktestStats, BacktestWatch, downgrade_reasons, run_backtest, summary_message
from .dispositions import DispositionCounts, Dispositions, inband_verdict
from .sketches import HyperLogLog, Reservoir, SpaceSaving, SpaceSavingEntry

ANCHOR_FIELDS = g.ANCHOR_FIELDS  # anchor field paths per profile (documented in hushwatch.analysis.gates)
CLUSTER_HLL_P = 12
MAX_RULES = 20_000  # distinct rule ids tracked (hostile/generated rule ids must not exhaust memory)
MAX_DISPOSED_EVENTS = 200_000  # alerts with an alert-id disposition remembered for scope matching
MAX_LABELS = 64  # groups / MITRE ids / tactics kept per rule
MAX_LABEL_LEN = 256
EXPIRES_DAYS_MAX = 3650


# ---- pass 1 ------------------------------------------------------------------------------------------------------
class _RuleStats:
    """Streaming statistics for one rule id."""

    __slots__ = (
        "analyst_facing",
        "check",
        "clusters",
        "daily",
        "daily_af",
        "description",
        "disposed",
        "examples",
        "external_by_host",
        "external_src",
        "failure",
        "fim",
        "first_ts",
        "groups",
        "high",
        "last_labels",
        "last_ts",
        "level_max",
        "level_min",
        "mitre",
        "pairs",
        "process",
        "rule_id",
        "singles",
        "tactics",
        "total",
        "triples",
        "unknown_level",
    )

    def __init__(self, rule_id: str) -> None:
        self.rule_id = rule_id
        self.description: str | None = None
        self.level_max: int | None = None
        self.level_min: int | None = None
        self.unknown_level = 0
        self.groups: set[str] = set()
        self.mitre: set[str] = set()
        self.tactics: set[str] = set()
        self.last_labels: tuple[tuple[str, ...], ...] = ()
        self.total = 0
        self.analyst_facing = 0
        self.high = 0
        self.failure = 0
        self.fim = 0
        self.check = 0
        self.process = 0  # process-creation events (Sysmon 1, 4688, execve)
        self.daily: dict[int, int] = {}
        self.daily_af: dict[int, int] = {}
        self.first_ts = float("inf")
        self.last_ts = float("-inf")
        self.clusters = HyperLogLog(CLUSTER_HLL_P)
        seed = int(stable_hash("noise.examples", rule_id, length=8), 16)
        self.examples: Reservoir[Mapping[str, Any]] = Reservoir(3, random.Random(seed))
        self.singles: dict[str, SpaceSaving[str]] = {}
        self.pairs: dict[tuple[str, str], SpaceSaving[tuple[str, str]]] = {}
        # (host field, field, companion field) -> (host, value, companion value): e.g. host + user + logon type
        self.triples: dict[tuple[str, str, str], SpaceSaving[tuple[str, str, str]]] = {}
        # alerts with a disposition: (alert id, in-band verdict or None, anchor values by path)
        self.disposed: list[tuple[str, str | None, dict[str, frozenset[str]]]] = []
        self.external_src = 0  # alerts whose source address is public
        # (host field, host value) -> alerts with a public source address; host-like "location" senders included
        self.external_by_host: SpaceSaving[tuple[str, str]] | None = None

    def merge(self, other: _RuleStats, capacity: int) -> None:
        if other.description and not self.description:
            self.description = other.description
        for level in (other.level_max, other.level_min):
            if level is not None:
                self._level(level)
        self.unknown_level += other.unknown_level
        _add_labels(self.groups, other.groups)
        _add_labels(self.mitre, other.mitre)
        _add_labels(self.tactics, other.tactics)
        self.total += other.total
        self.analyst_facing += other.analyst_facing
        self.high += other.high
        self.failure += other.failure
        self.fim += other.fim
        self.check += other.check
        self.process += other.process
        for day, count in other.daily.items():
            self.daily[day] = self.daily.get(day, 0) + count
        for day, count in other.daily_af.items():
            self.daily_af[day] = self.daily_af.get(day, 0) + count
        self.first_ts = min(self.first_ts, other.first_ts)
        self.last_ts = max(self.last_ts, other.last_ts)
        self.clusters.merge(other.clusters)
        self.examples.merge(other.examples)
        for path, sketch in other.singles.items():
            mine = self.singles.get(path)
            if mine is None:
                mine = self.singles[path] = SpaceSaving(capacity)
            mine.merge(sketch)
        for key, pair_sketch in other.pairs.items():
            mine_pair = self.pairs.get(key)
            if mine_pair is None:
                mine_pair = self.pairs[key] = SpaceSaving(capacity)
            mine_pair.merge(pair_sketch)
        for key3, triple_sketch in other.triples.items():
            mine_triple = self.triples.get(key3)
            if mine_triple is None:
                mine_triple = self.triples[key3] = SpaceSaving(capacity)
            mine_triple.merge(triple_sketch)
        self.external_src += other.external_src
        if other.external_by_host is not None:
            if self.external_by_host is None:
                self.external_by_host = SpaceSaving(capacity)
            self.external_by_host.merge(other.external_by_host)
        room = MAX_DISPOSED_EVENTS - len(self.disposed)
        if room > 0:
            self.disposed.extend(other.disposed[:room])

    def _level(self, level: int) -> None:
        if self.level_max is None or level > self.level_max:
            self.level_max = level
        if self.level_min is None or level < self.level_min:
            self.level_min = level


def _add_labels(target: set[str], labels: Iterable[str]) -> None:
    for label in labels:
        if len(target) >= MAX_LABELS:
            return
        if isinstance(label, str) and label:
            target.add(label[:MAX_LABEL_LEN])


_LABEL_FALLBACK_EVENTS = 64
_TACTIC_PATHS = ("rule.mitre.tactic", "threat.tactic.name", "kibana.alert.rule.threat.tactic.name")
_TECHNIQUE_PATHS = ("rule.mitre.id", "threat.technique.id", "kibana.alert.rule.threat.technique.id")


def _labels_from_fields(stats: _RuleStats, event: Event) -> None:
    """Profiles that do not fill ``Event.mitre_tactics`` / ``rule_groups``: read the original fields (only for the
    first events of a rule: these are rule-level constants)."""
    fields = event.fields
    if not event.mitre_tactics:
        for path in _TACTIC_PATHS:
            _add_labels(stats.tactics, g.scalar_values(g.field_value(fields, path)))
        for path in _TECHNIQUE_PATHS:
            _add_labels(stats.mitre, g.scalar_values(g.field_value(fields, path)))
    if not event.rule_groups:
        _add_labels(stats.groups, g.scalar_values(g.field_value(fields, "rule.groups")))


def _valid_level(value: Any) -> int | None:
    """An integer rule level, or None when unknown (bools, strings, NaN and fractional numbers are unknown)."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return None


class NoiseCollector:
    """First-pass collector for the noise engine (bounded memory, mergeable).

    ``profile`` may be ``auto``: each event's anchor fields are then chosen by a per-event profile guess, and the
    engine may set ``collector.profile`` once the input's profile is known.
    """

    def __init__(
        self,
        tenant: TenantConfig,
        profile: str = "auto",
        dispositions: Dispositions | None = None,
        *,
        service_account_patterns: Sequence[str] | None = None,
        max_rules: int = MAX_RULES,
    ) -> None:
        self.tenant = tenant
        self.profile = profile
        self.dispositions = dispositions
        settings = tenant.noise
        self.capacity = max(1, int(settings.heavy_hitters))
        self.service_account_patterns: tuple[str, ...] = tuple(
            service_account_patterns
            if service_account_patterns is not None
            else getattr(settings, "service_account_patterns", None) or g.DEFAULT_SERVICE_ACCOUNT_PATTERNS
        )
        self.max_rules = max_rules
        self.events = 0
        self.skipped = 0  # events without a rule (archives) or with an unusable timestamp
        self.dropped = 0  # events of rules beyond max_rules
        self.rules_truncated = False
        self.inband_dispositions = 0  # alerts carrying their own disposition (Elastic workflow_reason)
        self.first_ts = float("inf")
        self.last_ts = float("-inf")
        self.high_index = g.HighAlertIndex()
        self._rules: dict[str, _RuleStats] = {}
        self._gap = max(1, int(settings.cluster_gap.total_seconds()))
        self._triage = tenant.triage_level
        self._high_level = tenant.high_level
        self._days = g.DayIndex(tenant.tz)
        self._resolver_profile = profile
        self._resolver = g.SpecResolver(profile, tenant)
        self._profile_counts: dict[str, int] = {}
        self._ips = g.IpClassifier(tenant)

    # ---- streaming -------------------------------------------------------------------------------------------------
    def add(self, event: Event) -> None:
        """Account one event (events without a rule id are skipped: they are not alerts)."""
        rule_id = event.rule_id
        if rule_id is None or rule_id == "":
            self.skipped += 1
            return
        rid = str(rule_id)
        try:
            epoch = event.ts.timestamp()
        except (AttributeError, OverflowError, OSError, ValueError):
            self.skipped += 1
            return
        stats = self._rules.get(rid)
        if stats is None:
            if len(self._rules) >= self.max_rules:
                self.rules_truncated = True
                self.dropped += 1
                level = _valid_level(event.severity)
                if level is not None and level >= self._high_level:  # never lose co-occurrence evidence
                    extracted = g.extract(self._spec(event), event.fields, event.rule_groups)
                    self._index_high(extracted, int(epoch // 3600))
                return
            stats = self._rules[rid] = _RuleStats(rid)
        self.events += 1
        if epoch < self.first_ts:
            self.first_ts = epoch
        if epoch > self.last_ts:
            self.last_ts = epoch
        day = self._days.day(epoch)
        hour = int(epoch // 3600)

        level = _valid_level(event.severity)
        stats.total += 1
        stats.daily[day] = stats.daily.get(day, 0) + 1
        if level is None:
            stats.unknown_level += 1
            analyst = True  # unknown level: counted as analyst-facing (upper bound)
        else:
            stats._level(level)
            analyst = level >= self._triage
        if analyst:
            stats.analyst_facing += 1
            stats.daily_af[day] = stats.daily_af.get(day, 0) + 1
        if epoch < stats.first_ts:
            stats.first_ts = epoch
        if epoch > stats.last_ts:
            stats.last_ts = epoch
        if stats.description is None and event.rule_name:
            stats.description = str(event.rule_name)[:MAX_LABEL_LEN]
        labels = (event.rule_groups, event.mitre_tactics, event.tags)
        if labels != stats.last_labels:  # constant per rule in practice: skip the set updates
            stats.last_labels = labels
            _add_labels(stats.groups, event.rule_groups)
            _add_labels(stats.tactics, event.mitre_tactics)
            _add_labels(stats.mitre, (t for t in event.tags if isinstance(t, str) and t[:1] in ("T", "t")))
        if stats.total <= _LABEL_FALLBACK_EVENTS and not (event.mitre_tactics and event.rule_groups):
            _labels_from_fields(stats, event)

        spec = self._spec(event)
        extracted = g.extract(spec, event.fields, event.rule_groups)
        if extracted.failure:
            stats.failure += 1
        if extracted.fim:
            stats.fim += 1
        if extracted.check:
            stats.check += 1
        if extracted.process:
            stats.process += 1

        capacity = self.capacity
        host = extracted.host
        host_path = host[0].path if host is not None else None
        host_value = host[1] if host is not None else None
        for item, value in extracted.values:
            path = item.path
            hour_arg = hour if item.hours else None
            if item.role != g.ROLE_ATTACKER:  # attacker-controlled values never anchor alone: pairs only
                sketch = stats.singles.get(path)
                if sketch is None:
                    sketch = stats.singles[path] = SpaceSaving(capacity)
                sketch.add(value, 1, epoch, day, hour_arg)
            if host_value is not None and host_path is not None and path != host_path:
                companion = item.companion
                context = g.companion_value(event.fields, companion) if companion is not None else None
                if companion is not None and context is not None:
                    key3 = (host_path, path, companion)
                    triple = stats.triples.get(key3)
                    if triple is None:
                        triple = stats.triples[key3] = SpaceSaving(capacity)
                    triple.add((host_value, value, context), 1, epoch, day, hour_arg)
                    continue  # the companion is pinned: no broader host + value scope from this event
                key = (host_path, path)
                pair = stats.pairs.get(key)
                if pair is None:
                    pair = stats.pairs[key] = SpaceSaving(capacity)
                pair.add((host_value, value), 1, epoch, day, hour_arg)

        for item, value in extracted.values:
            if item.direction == "src" and item.role in g.IP_ROLES and self._ips.kind(value) == "external":
                stats.external_src += 1
                by_host = stats.external_by_host
                if by_host is None:
                    by_host = stats.external_by_host = SpaceSaving(capacity)
                if host_value is not None and host_path is not None:
                    by_host.add((host_path, host_value))
                if host_path != "location":
                    for loc_item, loc in extracted.values:
                        if loc_item.path == "location" and self._host_like_location(loc):
                            by_host.add(("location", loc))
                break

        stats.clusters.add_hash(g.cluster_hash(rid, extracted.values, int(epoch // self._gap)))
        stats.examples.add(event.fields)

        dispositions = self.dispositions
        inband = inband_verdict(event.fields) if spec.ecs_context else None
        if len(stats.disposed) < MAX_DISPOSED_EVENTS and (
            inband is not None
            or (
                dispositions is not None
                and event.event_id
                and dispositions.verdict_for_alert(event.event_id) is not None
            )
        ):
            if inband is not None:
                self.inband_dispositions += 1
            values: dict[str, set[str]] = {}
            for item, value in extracted.values:
                values.setdefault(item.path, set()).add(value)
                if item.companion is not None and item.companion not in values:
                    context = g.companion_value(event.fields, item.companion)
                    if context is not None:
                        values[item.companion] = {context}
            stats.disposed.append((str(event.event_id or ""), inband, {k: frozenset(v) for k, v in values.items()}))

        if level is not None and level >= self._high_level:
            stats.high += 1
            self._index_high(extracted, hour)

    def _host_like_location(self, value: str) -> bool:
        """A ``location`` naming the sending device (a syslog sender address, or ``host->path``)."""
        return "->" in value or self._ips.kind(value) != "invalid"

    def _spec(self, event: Event) -> g.AnchorSpec:
        if self._resolver_profile != self.profile:  # the engine may set the profile once DataBasis knows it
            self._absorb_profile_counts()
            self._resolver_profile = self.profile
            self._resolver = g.SpecResolver(self.profile, self.tenant)
        return self._resolver.for_fields(event.fields)

    def _index_high(self, extracted: g.Extracted, hour: int) -> None:
        for item, value in extracted.values:
            kind = g.cooccurrence_kind(item, value)
            if kind is not None:
                self.high_index.add(kind, value, hour)

    def merge(self, other: NoiseCollector) -> None:
        """Fold another collector (same tenant) into this one, e.g. one per rotated file processed in parallel."""
        if other is self:
            raise ValueError("cannot merge a collector into itself")
        if other.tenant.name != self.tenant.name:
            raise ValueError("cannot merge noise collectors of different tenants")
        for rid, theirs in other._rules.items():
            mine = self._rules.get(rid)
            if mine is None:
                if len(self._rules) >= self.max_rules:
                    self.rules_truncated = True
                    self.dropped += theirs.total
                    continue
                mine = self._rules[rid] = _RuleStats(rid)
            mine.merge(theirs, self.capacity)
        self.high_index.merge(other.high_index)
        self.events += other.events
        self.skipped += other.skipped
        self.dropped += other.dropped
        self.rules_truncated = self.rules_truncated or other.rules_truncated
        self.inband_dispositions += other.inband_dispositions
        self.first_ts = min(self.first_ts, other.first_ts)
        self.last_ts = max(self.last_ts, other.last_ts)
        for name, count in other._all_profile_counts().items():
            self._profile_counts[name] = self._profile_counts.get(name, 0) + count

    # ---- accessors -------------------------------------------------------------------------------------------------
    @property
    def rules(self) -> Mapping[str, _RuleStats]:
        return self._rules

    def window(self) -> g.Window | None:
        """Analysis window (None when no alert was seen)."""
        if self.events == 0 or self.first_ts == float("inf"):
            return None
        return g.Window(self.first_ts, self.last_ts, self._days.day(self.first_ts), self._days.day(self.last_ts))

    def effective_profile(self) -> str:
        """The configured profile, or the most common per-event guess when it was ``auto``."""
        if self.profile in g.FIXED_PROFILES:
            return self.profile
        counted = {k: v for k, v in self._all_profile_counts().items() if k in g.FIXED_PROFILES}
        if counted:
            return max(sorted(counted), key=lambda k: counted[k])
        return "wazuh4"

    def day_index(self) -> g.DayIndex:
        return self._days

    def _all_profile_counts(self) -> dict[str, int]:
        merged = dict(self._profile_counts)
        for name, count in self._resolver.counts.items():
            merged[name] = merged.get(name, 0) + count
        return merged

    def _absorb_profile_counts(self) -> None:
        self._profile_counts = self._all_profile_counts()
        self._resolver.counts.clear()


# ---- result ------------------------------------------------------------------------------------------------------
@dataclass(slots=True)
class _Candidate:
    conditions: tuple[g.CondFact, ...]
    lower: int
    upper: int
    first_seen: float | None
    last_seen: float | None
    daily: Mapping[int, int]
    entry: SpaceSavingEntry[Any] | None
    host: tuple[str, str] | None = None  # (host field, host value) of a host+X pair
    container: int = 0  # upper bound of the smallest known scope containing this one


@dataclass(slots=True)
class _Record:
    """Everything known about one suggestion, kept to finalize after the backtest."""

    fingerprint: str
    rule_id: str
    subject: str
    facts: g.CandidateFacts
    decision: g.Decision
    verdict: str
    pending: bool
    est_analyst_per_day: float
    backtest: BacktestStats | None = None
    backtest_reasons: list[Message] = field(default_factory=list)
    fix_kind: str | None = None  # set when the backtest turns a candidate into fix_at_source (exposure)
    probe: bool = False  # blocked only for lack of triage evidence: backtested to tell exposure from the rest


@dataclass(slots=True)
class _RuleSummary:
    rule_id: str
    description: str | None
    level: int | None
    total: int
    analyst_facing: int
    clusters: int
    daily: dict[int, int]
    first_ts: float
    last_ts: float
    groups: tuple[str, ...]
    top_anchor: dict[str, Any] | None
    mined: bool = False
    level_blocked: bool = False
    burst: tuple[int, float, int] | None = None  # (peak, median, day) when the rule itself bursts


@dataclass(slots=True)
class _Context:
    tenant: TenantConfig
    now: datetime
    window: g.Window | None
    profile: str
    learning: bool
    rules: dict[str, _RuleSummary]
    records: dict[str, _Record]
    watch: BacktestWatch
    dispositions: Dispositions | None
    events: int
    skipped: int
    dropped: int
    rules_truncated: bool
    backtested: bool = False
    backtest_error: str | None = None


@dataclass(slots=True)
class NoiseResult:
    """Output of the noise engine.

    ``suggestions`` holds every candidate (all verdicts); ``findings`` and ``section`` (§2.2
    ``sections["noise"]``) are final only when ``backtested`` is True.
    """

    suggestions: list[Suggestion]
    findings: list[Finding]
    section: dict[str, Any]
    backtested: bool = False
    _ctx: _Context | None = field(default=None, repr=False, compare=False)


# ---- analysis ----------------------------------------------------------------------------------------------------
def analyze_noise(
    collector: NoiseCollector,
    *,
    tenant: TenantConfig,
    now: datetime,
    dependents: Callable[[str], Iterable[str]] | None = None,
    expires_days: int = 90,
) -> NoiseResult:
    """Mine scoped tuning candidates from pass-1 statistics and run the safety gates on each of them.

    ``dependents(rule_id)`` returns the rules that correlate on ``rule_id`` (``if_matched_sid`` /
    ``if_matched_group`` / frequency); a candidate on such a rule gets action ``review``. ``expires_days`` sets
    every suggestion's expiry. Call :func:`apply_backtest` next: until then nothing is ``tune``.
    """
    settings = tenant.noise
    now = now.replace(tzinfo=timezone.utc) if now.tzinfo is None else now
    window = collector.window()
    learning = window is not None and window.is_learning(settings.min_history_days)
    field_map = g.all_fields(tenant)
    profile = collector.effective_profile()
    days = collector.day_index()
    # TP look-back from the end of the DATA (or ``now`` if earlier): analyzing an old export with a later ``now``
    # must not age the true positives of that period out of the veto
    reference = now if window is None else min(now, datetime.fromtimestamp(window.end, tz=timezone.utc))
    since = reference - timedelta(days=g.TP_LOOKBACK_DAYS)
    expires = now.astimezone(tenant.tz).date() + timedelta(days=min(max(1, int(expires_days)), EXPIRES_DAYS_MAX))
    co_seconds = settings.co_occurrence_window.total_seconds()
    beacons_by_rule: dict[str, frozenset[str]] = {}
    watch = BacktestWatch(
        high=collector.high_index,
        co_window_hours=max(0, round(co_seconds / 3600)),
        beacons=beacons_by_rule,
        since=since,
        window=window,
    )
    ctx = _Context(
        tenant=tenant,
        now=now,
        window=window,
        profile=profile,
        learning=learning,
        rules={},
        records={},
        watch=watch,
        dispositions=collector.dispositions,
        events=collector.events,
        skipped=collector.skipped,
        dropped=collector.dropped,
        rules_truncated=collector.rules_truncated,
    )
    suggestions: list[Suggestion] = []
    if window is None:
        findings, section = _finalize(ctx, suggestions)
        return NoiseResult(suggestions, findings, section, False, ctx)

    rules = collector.rules
    for rid, stats in rules.items():
        ctx.rules[rid] = _summarize(stats, window, field_map, tenant)
    for rid in _mining_order(rules, settings):
        stats = rules[rid]
        summary = ctx.rules[rid]
        summary.mined = True
        summary.level_blocked = summary.level is None or summary.level > tenant.max_tunable_level
        deps, deps_error = _dependents(dependents, rid)
        beacons = _rule_beacons(stats, field_map, tenant)
        if beacons:
            beacons_by_rule[rid] = beacons
        for cand in _mine(stats, tenant, settings, field_map, collector.service_account_patterns):
            facts = _facts(
                cand,
                stats,
                window=window,
                tenant=tenant,
                field_map=field_map,
                high=collector.high_index,
                days=days,
                co_seconds=co_seconds,
                dispositions=collector.dispositions,
                since=since,
                deps=deps,
                deps_error=deps_error,
                inband_seen=collector.inband_dispositions > 0,
            )
            decision = g.evaluate(facts, settings, tenant)
            subject = _subject(rid, facts.conditions)
            fingerprint = stable_hash("noise.suggestion", tenant.name, subject, length=20)
            if fingerprint in ctx.records:
                continue
            pending = decision.verdict == "tune"
            failed_gates = {o.gate for o in decision.outcomes if not o.passed and o.gate != "dependents"}
            probe = decision.verdict == "investigate" and bool(failed_gates) and failed_gates <= _EVIDENCE_GATES
            verdict = "watch" if pending else decision.verdict
            reasons: list[Message | str] = list(decision.reasons)
            if pending:
                reasons.insert(0, M("noise.reason.pending_backtest"))
            share_af = stats.analyst_facing / stats.total if stats.total else 0.0
            n_days = max(1, window.n_days)
            suggestion = Suggestion(
                rule_id=rid,
                conditions=tuple(Condition(c.field, c.value) for c in facts.conditions),
                verdict=verdict,
                fingerprint=fingerprint,
                expires=expires,
                action=decision.action,
                rule_level=stats.level_max,
                rule_description=stats.description,
                rule_groups=tuple(sorted(stats.groups)),
                rule_mitre=tuple(sorted(stats.mitre)),
                profile=profile,
                dependents=deps or (),
                hidden_total=cand.lower,
                hidden_per_day=cand.lower / n_days,
                hidden_analyst_facing=round(cand.lower * share_af),
                share_of_rule=facts.share,
                reasons=reasons,
            )
            suggestions.append(suggestion)
            ctx.records[fingerprint] = _Record(
                fingerprint=fingerprint,
                rule_id=rid,
                subject=subject,
                facts=facts,
                decision=decision,
                verdict=verdict,
                pending=pending,
                est_analyst_per_day=cand.lower * share_af / n_days,
                probe=probe,
            )
    findings, section = _finalize(ctx, suggestions)
    return NoiseResult(suggestions, findings, section, False, ctx)


def apply_backtest(result: NoiseResult, events: Iterable[Event], *, tenant: TenantConfig) -> NoiseResult:
    """Second pass: replay every gate-passing candidate over ``events`` and finalize verdicts, findings and the
    section. A candidate becomes ``tune`` only when its backtest hides no alert at level >= ``high_level`` (or of
    unknown level), no true positive, no actor seen in a high-level alert, no beacon-like address, no actor (or,
    for scopes that do not pin a host, no host) that appeared late in the window, and no burst. A scope whose
    hidden alerts mostly come from public addresses becomes ``fix_at_source`` (restrict exposure)."""
    ctx = result._ctx
    if ctx is None:
        return result
    suggestions = [replace(s, reasons=list(s.reasons), examples=list(s.examples)) for s in result.suggestions]
    records = {fp: replace(rec, backtest_reasons=list(rec.backtest_reasons)) for fp, rec in ctx.records.items()}
    pending = [s for s in suggestions if s.fingerprint in records and records[s.fingerprint].pending]
    probes = [s for s in suggestions if s.fingerprint in records and records[s.fingerprint].probe]
    error: str | None = None
    if pending or probes:
        try:
            stats = run_backtest(
                pending + probes, events, tenant=tenant, dispositions=ctx.dispositions, watch=ctx.watch
            )
        except OSError as exc:  # the input vanished between passes: keep everything pending (never tune)
            error = str(exc)[:300]
            stats = {}
        n_days = max(1, ctx.window.n_days if ctx.window is not None else 1)
        for suggestion in probes if error is None else ():
            # never tuned (triage evidence is missing); the backtest only sharpens the advice: Internet traffic is
            # "restrict exposure", and whatever else it saw (new actors, high alerts...) is listed first
            rec = records[suggestion.fingerprint]
            entry = stats.get(suggestion.fingerprint)
            if entry is None or entry.hidden_total == 0:
                continue
            rec.probe = False
            rec.backtest = entry
            downgrade = downgrade_reasons(entry, tenant=tenant, window=ctx.window)
            rec.backtest_reasons = list(downgrade)
            if downgrade and all(r.key == EXPOSURE_KEY for r in downgrade):
                rec.verdict = suggestion.verdict = "fix_at_source"
                rec.fix_kind = "exposure"
            suggestion.reasons = [*rec.backtest_reasons, *suggestion.reasons]
            suggestion.examples = entry.example_docs()
        for suggestion in pending if error is None else ():
            rec = records[suggestion.fingerprint]
            entry = stats.get(suggestion.fingerprint)
            if entry is None:
                continue
            rec.pending = False
            rec.backtest = entry
            gate_reasons = [r for r in suggestion.reasons if not _is_pending_reason(r)]
            if entry.hidden_total == 0:
                verdict = "watch"
                rec.backtest_reasons = [M("noise.backtest.empty")]
            else:
                downgrade = downgrade_reasons(entry, tenant=tenant, window=ctx.window)
                if downgrade and all(r.key == EXPOSURE_KEY for r in downgrade):
                    verdict = "fix_at_source"  # mostly Internet traffic: restrict the exposure, never mute it
                    rec.fix_kind = "exposure"
                    rec.backtest_reasons = list(downgrade)
                elif downgrade:
                    verdict = "investigate"
                    rec.backtest_reasons = list(downgrade)
                else:
                    verdict = "tune"
                    rec.backtest_reasons = [summary_message(entry, tenant=tenant, days=n_days)]
            rec.verdict = verdict
            suggestion.verdict = verdict
            suggestion.reasons = [*rec.backtest_reasons, *gate_reasons]
            suggestion.hidden_total = entry.hidden_total
            suggestion.hidden_per_day = entry.hidden_total / n_days
            suggestion.hidden_analyst_facing = entry.hidden_analyst_facing
            suggestion.share_of_rule = entry.share_of_rule
            suggestion.examples = entry.example_docs()
    new_ctx = replace(ctx, records=records, backtested=error is None, backtest_error=error)
    findings, section = _finalize(new_ctx, suggestions)
    return NoiseResult(suggestions, findings, section, error is None, new_ctx)


_EVIDENCE_GATES = frozenset({"attacker_field", "sensitive"})  # gates that only ask for triage evidence


def _is_pending_reason(reason: Message | str) -> bool:
    return isinstance(reason, Message) and reason.key == "noise.reason.pending_backtest"


# ---- candidate mining --------------------------------------------------------------------------------------------
def _mining_order(rules: Mapping[str, _RuleStats], settings: NoiseSettings) -> list[str]:
    """Top rules by analyst-facing volume, then top rules by total volume (index noise)."""
    top = max(0, int(settings.top_rules))
    by_af = sorted(rules.values(), key=lambda r: (-r.analyst_facing, -r.total, r.rule_id))[:top]
    by_total = sorted(rules.values(), key=lambda r: (-r.total, -r.analyst_facing, r.rule_id))[:top]
    order: list[str] = []
    for stats in (*by_af, *by_total):
        if stats.rule_id not in order:
            order.append(stats.rule_id)
    return order


def _mine(
    stats: _RuleStats,
    tenant: TenantConfig,
    settings: NoiseSettings,
    field_map: Mapping[str, g.AnchorField],
    service_patterns: Sequence[str],
) -> list[_Candidate]:
    """Condition sets covering >= min_share of the rule, narrowed and reduced to a minimal non-nested set."""
    total = stats.total
    if total <= 0:
        return []
    threshold = max(settings.min_share * total, float(g.MIN_CANDIDATE_EVENTS))
    failure_rule = stats.failure > 0
    fim_rule = stats.fim > 0

    def fact(path: str, value: str) -> g.CondFact:
        item = field_map.get(path)
        if item is None:
            return g.CondFact(path, value, None, g.ValueClass(alone=False, attacker=True))
        cls = g.classify(
            item, value, tenant, failure_rule=failure_rule, fim_rule=fim_rule, service_patterns=service_patterns
        )
        return g.CondFact(path, value, item, cls)

    singles: list[_Candidate] = []
    for path, sketch in stats.singles.items():
        for entry in sketch.entries():
            lower = entry.count - entry.error
            if lower < threshold:
                continue
            cond = fact(path, entry.key)
            if cond.cls.alone and not cond.cls.never:
                host = (path, entry.key) if cond.cls.host_like else None
                singles.append(
                    _Candidate(
                        (cond,),
                        lower,
                        entry.count,
                        entry.first_seen,
                        entry.last_seen,
                        entry.daily,
                        entry,
                        host=host,
                        container=entry.count if host is not None else total,
                    )
                )

    pairs: list[_Candidate] = []
    children: dict[tuple[str, str], dict[str, int]] = {}
    stable_children: set[tuple[str, str]] = set()
    # a field whose companion was ever present in this rule is only scoped WITH its companion (a host + user pair
    # built from the events that lacked it would still match every logon type)
    pinned_fields = {(host_path, path) for host_path, path, _companion in stats.triples}
    scoped: list[tuple[str, str, str, tuple[tuple[str, str], ...], SpaceSavingEntry[Any]]] = []
    for (host_path, other_path), pair_sketch in stats.pairs.items():
        if (host_path, other_path) in pinned_fields:
            continue
        for pair_entry in pair_sketch.entries():
            host_value, other_value = pair_entry.key
            scoped.append((host_path, host_value, other_path, ((other_path, other_value),), pair_entry))
    for (host_path, other_path, companion), triple_sketch in stats.triples.items():
        for triple_entry in triple_sketch.entries():
            host_value, other_value, context = triple_entry.key
            extra = ((other_path, other_value), (companion, context))
            scoped.append((host_path, host_value, other_path, extra, triple_entry))
    for host_path, host_value, other_path, others, pair_entry in scoped:
        lower = pair_entry.count - pair_entry.error
        if lower < threshold:
            continue
        host_sketch = stats.singles.get(host_path)
        host_cond = fact(host_path, host_value)
        other_facts = [fact(path, value) for path, value in others]
        other_cond = other_facts[0]
        other_value = other_cond.value
        if not host_cond.cls.alone or any(c.cls.never for c in other_facts):
            continue  # interpreters / generic parents never scope anything, even on one host
        own_machine = (
            other_cond.item is not None
            and other_cond.item.role == g.ROLE_USER
            and g.is_own_machine_account(other_value, host_value)
        )
        if own_machine:
            # "SRV-01$ on SRV-01" is the host itself: never narrower, never trusted
            other_cond = g.CondFact(other_cond.field, other_value, other_cond.item, g.ValueClass(False, False))
            other_facts[0] = other_cond
        host_bounds = host_sketch.bounds(host_value) if host_sketch is not None else (0, 0)
        weak = own_machine or (other_cond.item is not None and other_cond.item.role == g.ROLE_SOURCE)
        if weak and pair_entry.count >= g.NARROW_RATIO * host_bounds[0]:
            continue  # the log file / decoder / provider of a host adds no real scoping: same as the host
        conds = tuple(sorted((host_cond, *other_facts), key=lambda c: c.field))
        pairs.append(
            _Candidate(
                conds,
                lower,
                pair_entry.count,
                pair_entry.first_seen,
                pair_entry.last_seen,
                pair_entry.daily,
                pair_entry,
                host=(host_path, host_value),
                container=host_bounds[1],
            )
        )
        if not weak:
            bucket = children.setdefault((host_path, host_value), {})
            bucket[other_path] = bucket.get(other_path, 0) + lower
            if not other_cond.cls.attacker:
                stable_children.add((host_path, host_value))

    kept: list[_Candidate] = []
    for cand in singles:
        cond = cand.conditions[0]
        if cond.item is not None and cond.cls.host_like:
            key = (cond.field, cond.value)
            covered = max(children.get(key, {}).values(), default=0)
            if covered >= g.NARROW_RATIO * cand.upper or key in stable_children:
                # narrower host+X scopes explain almost all of it, or a stable anchor (service account, internal
                # IP, image path) explains a big part: propose that and leave the rest of the host visible
                continue
        kept.append(cand)
    candidates = kept + pairs
    if settings.allow_rule_wide:
        best = max((c.lower for c in candidates), default=0)
        if best < g.NARROW_RATIO * total:
            candidates.append(
                _Candidate((), total, total, stats.first_ts, stats.last_ts, stats.daily, None, container=total)
            )

    # Biggest first (in 5% steps), then the safest anchor, then the narrowest scope.
    candidates.sort(
        key=lambda c: (
            -int(20 * c.lower / total),
            -_strength(c),
            -len(c.conditions),
            -c.lower,
            _subject(stats.rule_id, c.conditions),
        )
    )
    selected: list[_Candidate] = []
    limit = max(0, int(settings.max_candidates_per_rule))
    for cand in candidates:
        if len(selected) >= limit:
            break
        if any(_redundant(cand, other, total) for other in selected):
            continue
        selected.append(cand)
    return selected


def _strength(cand: _Candidate) -> int:
    """2: trusted anchor, nothing attacker-controlled; 1: nothing attacker-controlled; 0: otherwise."""
    conds = cand.conditions
    if not conds:
        return 0
    if any(c.cls.attacker or c.cls.external for c in conds):
        return 0
    if any(c.cls.trusted for c in conds):
        return 2
    return 1


def _redundant(cand: _Candidate, chosen: _Candidate, total: int) -> bool:
    """``cand`` adds (almost) nothing once ``chosen`` is selected: nested scopes, or a guaranteed overlap
    (inclusion-exclusion on the lower bounds inside their common container) of >= NARROW_RATIO of ``cand``."""
    cset = {(c.field, c.value) for c in cand.conditions}
    oset = {(c.field, c.value) for c in chosen.conditions}
    if cset <= oset or cset >= oset:
        return True
    container = total
    if cand.host is not None and cand.host == chosen.host:
        container = min(cand.container, chosen.container) or total
    overlap = cand.lower + chosen.lower - container
    return overlap >= g.NARROW_RATIO * cand.upper


def _rule_beacons(stats: _RuleStats, field_map: Mapping[str, g.AnchorField], tenant: TenantConfig) -> frozenset[str]:
    """Public addresses with beacon-like hourly activity anywhere in the rule."""
    found: set[str] = set()
    for path, sketch in stats.singles.items():
        item = field_map.get(path)
        if item is None or item.role not in g.IP_ROLES:
            continue
        for entry in sketch.entries():
            if g.beacon_like(entry) and g.ip_kind(entry.key, tenant) == "external":
                found.add(entry.key)
    for (_host_path, other_path), pair_sketch in stats.pairs.items():
        item = field_map.get(other_path)
        if item is None or item.role not in g.IP_ROLES:
            continue
        for pair_entry in pair_sketch.entries():
            value = pair_entry.key[1]
            if value not in found and g.beacon_like(pair_entry) and g.ip_kind(value, tenant) == "external":
                found.add(value)
    return frozenset(found)


def _facts(
    cand: _Candidate,
    stats: _RuleStats,
    *,
    window: g.Window,
    tenant: TenantConfig,
    field_map: Mapping[str, g.AnchorField],
    high: g.HighAlertIndex,
    days: g.DayIndex,
    co_seconds: float,
    dispositions: Dispositions | None,
    since: datetime,
    deps: tuple[str, ...] | None,
    deps_error: bool,
    inband_seen: bool = False,
) -> g.CandidateFacts:
    conds = cand.conditions
    # co-occurrence: a candidate value seen in a high-level alert within ± window of a day the candidate fired
    co_hits: list[g.CoHit] = []
    for cond in conds:
        if cond.item is None:
            continue
        kind = g.cooccurrence_kind(cond.item, cond.value)
        if kind is None:
            continue
        hits = 0
        for hour, count in high.hours(kind, cond.value).items():
            lo = days.day(hour * 3600 - co_seconds)
            hi = days.day(hour * 3600 + 3599 + co_seconds)
            if any(cand.daily.get(day, 0) > 0 for day in range(lo, hi + 1)):
                hits += count
        if hits:
            co_hits.append(g.CoHit(kind, cond.value, hits))

    # beacon-like public addresses inside the candidate's scope
    beacons: dict[str, g.BeaconHit] = {}
    pinned = {c.field: c.value for c in conds}
    for cond in conds:
        if cond.item is None or cond.item.role not in g.IP_ROLES or not cond.cls.external:
            continue
        single = stats.singles.get(cond.field)
        for entry in (cand.entry if len(conds) == 2 else None, single.get(cond.value) if single else None):
            if entry is not None and g.beacon_like(entry):
                beacons[cond.value] = g.BeaconHit(cond.value, entry.active_hours, entry.hour_span())
                break
    host_cond = next((c for c in conds if c.item is not None and c.cls.host_like), None)
    if host_cond is not None:
        for (host_path, other_path), pair_sketch in stats.pairs.items():
            item = field_map.get(other_path)
            if host_path != host_cond.field or item is None or item.role not in g.IP_ROLES or other_path in pinned:
                continue
            for pair_entry in pair_sketch.entries():
                host_value, value = pair_entry.key
                if host_value != host_cond.value or value in beacons:
                    continue
                if g.beacon_like(pair_entry) and g.ip_kind(value, tenant) == "external":
                    beacons[value] = g.BeaconHit(value, pair_entry.active_hours, pair_entry.hour_span())

    # dispositions in scope (last TP_LOOKBACK_DAYS)
    counts = DispositionCounts()
    tp_rule_wide = 0
    if dispositions is not None:
        pairs = [(c.field, c.value) for c in conds]
        counts = dispositions.counts_for_scope(stats.rule_id, pairs, since=since, include_rule_wide=not conds)
        if conds:
            tp_rule_wide = sum(
                1
                for row in dispositions.rule_wide(stats.rule_id)
                if row.verdict == "tp" and (row.closed_at is None or row.closed_at >= since)
            )
    for alert_id, inband, values in stats.disposed:
        if all(c.value in values.get(c.field, ()) for c in conds):
            listed = dispositions.verdict_for_alert(alert_id, since) if dispositions is not None else None
            verdict = "tp" if "tp" in (inband, listed) else (listed or inband)  # a TP anywhere wins
            if verdict is not None:
                counts.add(verdict)

    external_share: float | None = None
    narrowing = [
        c for c in conds if c.item is None or not (c.cls.host_like or c.item.role in (g.ROLE_HOST, g.ROLE_SOURCE))
    ]
    if not conds:
        external_share = stats.external_src / stats.total if stats.total else None
    elif host_cond is not None and not narrowing and cand.upper:
        # a whole host (or syslog sender): muting it for traffic that mostly comes from the Internet hides
        # Internet attacks. Narrowed scopes are measured exactly by the backtest.
        by_host = stats.external_by_host
        lower = by_host.bounds((host_cond.field, host_cond.value))[0] if by_host is not None else 0
        external_share = min(1.0, lower / cand.upper)

    return g.CandidateFacts(
        rule_id=stats.rule_id,
        conditions=conds,
        count_lower=cand.lower,
        count_upper=cand.upper,
        rule_total=stats.total,
        window=window,
        rule_level=stats.level_max,
        tactics=tuple(sorted(stats.tactics)),
        fim=stats.fim > 0,
        check=stats.check > 0,
        process_creation=stats.process > 0,
        rule_clusters=stats.clusters.count(),
        first_seen=cand.first_seen,
        last_seen=cand.last_seen,
        daily=cand.daily,
        dispositions=counts,
        dispositions_loaded=dispositions is not None or inband_seen,
        tp_rule_wide=tp_rule_wide,
        co_hits=tuple(co_hits),
        co_index_truncated=high.truncated,
        beacons=tuple(beacons.values()),
        external_share=external_share,
        dependents=deps,
        dependents_error=deps_error,
    )


def _dependents(fn: Callable[[str], Iterable[str]] | None, rule_id: str) -> tuple[tuple[str, ...] | None, bool]:
    if fn is None:
        return None, False
    try:
        found = {str(d) for d in fn(rule_id) if d is not None and str(d) != rule_id}
    except Exception:  # a broken ruleset must not crash the run: require review instead
        return (), True
    return tuple(sorted(found, key=_rule_sort_key)), False


def _rule_sort_key(rule_id: str) -> tuple[int, str]:
    return (int(rule_id), "") if rule_id.isdigit() and len(rule_id) < 19 else (1 << 62, rule_id)


def _subject(rule_id: str, conds: Sequence[g.CondFact]) -> str:
    """RAW stable identifier: ``rule:5710|data.srcip:10.0.0.5`` (``|`` and ``\\`` in values are escaped)."""
    if not conds:
        return f"rule:{rule_id}|*"
    parts = [f"{c.field}:{c.value.replace(chr(92), chr(92) * 2).replace('|', chr(92) + '|')}" for c in conds]
    return "|".join([f"rule:{rule_id}", *sorted(parts)])


def _summarize(
    stats: _RuleStats, window: g.Window, field_map: Mapping[str, g.AnchorField], tenant: TenantConfig
) -> _RuleSummary:
    best: tuple[int, int, str, str] | None = None
    for path in sorted(stats.singles):
        item = field_map.get(path)
        # identifying fields first: "decoder.name = sshd" explains 100% of an sshd rule and says nothing
        rank = 0 if item is not None and item.role == g.ROLE_SOURCE else 1
        for entry in stats.singles[path].top(1):
            lower = entry.count - entry.error
            if best is None or (rank, lower) > (best[0], best[1]):
                best = (rank, lower, path, entry.key)
    top_anchor: dict[str, Any] | None = None
    if best is not None and stats.total:
        _rank, lower, path, value = best
        wrapped = g.entity_for(field_map.get(path), value, tenant)
        top_anchor = {
            "field": path,
            "value": wrapped if isinstance(wrapped, Entity) else Entity("val", wrapped),
            "share": round(lower / stats.total, 4),
        }
    peak, median, peak_day = g.burst_stats(stats.daily, window)
    burst = (
        (peak, median, peak_day)
        if peak >= tenant.noise.burst_factor * max(median, 1.0) and peak >= g.MIN_CANDIDATE_EVENTS
        else None
    )
    return _RuleSummary(
        rule_id=stats.rule_id,
        description=stats.description,
        level=stats.level_max,
        total=stats.total,
        analyst_facing=stats.analyst_facing,
        clusters=min(stats.clusters.count(), stats.total),
        daily=dict(stats.daily),
        first_ts=stats.first_ts,
        last_ts=stats.last_ts,
        groups=tuple(sorted(stats.groups)),
        top_anchor=top_anchor,
        burst=burst,
    )


# ---- findings and section ----------------------------------------------------------------------------------------
_VERDICT_ORDER = ("investigate", "tune", "fix_at_source", "aggregate", "do_not_tune", "watch", "learning")


def _finalize(ctx: _Context, suggestions: list[Suggestion]) -> tuple[list[Finding], dict[str, Any]]:
    tenant = ctx.tenant
    findings: list[Finding] = []
    window = ctx.window
    by_fp = {s.fingerprint: s for s in suggestions}

    if ctx.learning and window is not None:
        findings.append(
            Finding(
                kind="assessment.learning",
                domain="assessment",
                title=M("noise.title.learning", days=window.n_days, min=tenant.noise.min_history_days),
                # a short input is not a failed analysis: the noise section is "not_assessed" (grey), which is
                # what keeps it from reading as green; MEDIUM here would force exit code 3 on a legitimate run
                severity=Severity.LOW,
                subject="noise:learning",
                reasons=[M("noise.reason.learning", days=window.n_days, min=tenant.noise.min_history_days)],
                evidence={"days": window.n_days, "min_history_days": tenant.noise.min_history_days},
                recommendation=M("noise.rec.learning", min=tenant.noise.min_history_days),
                confidence=Confidence.HIGH,
                tenant=tenant.name,
            )
        )
    else:
        for rec in ctx.records.values():
            suggestion = by_fp.get(rec.fingerprint)
            if suggestion is None:
                continue
            finding = _candidate_finding(ctx, rec, suggestion)
            if finding is not None:
                findings.append(finding)
        findings.extend(_rule_findings(ctx))

    pending = [rec for rec in ctx.records.values() if rec.pending]
    if pending and not ctx.learning:
        reasons: list[Message | str] = [M("noise.reason.not_backtested", count=len(pending))]
        if ctx.backtest_error:
            reasons.append(M("noise.reason.backtest_error", error=ctx.backtest_error))
        findings.append(
            Finding(
                kind="assessment.incomplete",
                domain="assessment",
                title=M("noise.title.not_backtested", count=len(pending)),
                severity=Severity.MEDIUM,
                subject="noise:backtest",
                reasons=reasons,
                evidence={"pending": len(pending)},
                recommendation=M("noise.rec.not_backtested"),
                confidence=Confidence.HIGH,
                tenant=tenant.name,
            )
        )
    if ctx.rules_truncated:
        findings.append(
            Finding(
                kind="assessment.incomplete",
                domain="assessment",
                title=M("noise.title.rules_cap", cap=MAX_RULES, dropped=ctx.dropped),
                severity=Severity.MEDIUM,
                subject="noise:rules-cap",
                evidence={"dropped_events": ctx.dropped, "max_rules": MAX_RULES},
                tenant=tenant.name,
            )
        )
    disp = ctx.dispositions
    if disp is not None and (disp.bad_rows or disp.truncated):
        findings.append(
            Finding(
                kind="assessment.incomplete",
                domain="assessment",
                title=M("noise.title.dispositions_bad", bad=disp.bad_rows),
                severity=Severity.MEDIUM if disp.truncated else Severity.LOW,
                subject="noise:dispositions",
                evidence={k: v for k, v in disp.stats().items()},
                tenant=tenant.name,
            )
        )
    return findings, _section(ctx, suggestions, findings)


def _scope(conds: Sequence[g.CondFact], tenant: TenantConfig) -> Message:
    if not conds:
        return M("noise.scope.rule_wide")
    values = [(c.field, g.entity_for(c.item, c.value, tenant)) for c in conds]
    if len(values) == 1:
        return M("noise.scope.one", field=values[0][0], value=values[0][1])
    if len(values) == 2:
        return M("noise.scope.two", field1=values[0][0], value1=values[0][1], field2=values[1][0], value2=values[1][1])
    head = M("noise.scope.one", field=values[0][0], value=values[0][1])
    for field_name, value in values[1:-1]:
        head = M("noise.scope.list", first=head, field=field_name, value=value)
    return M("noise.scope.and", first=head, field=values[-1][0], value=values[-1][1])


def _candidate_finding(ctx: _Context, rec: _Record, suggestion: Suggestion) -> Finding | None:
    tenant = ctx.tenant
    facts = rec.facts
    verdict = rec.verdict
    summary = ctx.rules.get(rec.rule_id)
    description = (summary.description if summary else None) or ""
    scope = _scope(facts.conditions, tenant)
    common: dict[str, Any] = {"rule": rec.rule_id, "description": description, "scope": scope}
    backtest = rec.backtest
    analyst_hidden = backtest.hidden_analyst_facing if backtest is not None else 0
    n_days = max(1, ctx.window.n_days if ctx.window is not None else 1)
    kind: str
    severity: Severity
    confidence = Confidence.MEDIUM
    score = rec.est_analyst_per_day
    if verdict == "tune":
        if backtest is None:
            return None
        kind = "noise.tune"
        severity = Severity.MEDIUM if analyst_hidden > 0 else Severity.LOW
        title = M("noise.title.tune", **common)
        if suggestion.review_required:
            recommendation = M(
                "noise.rec.tune_review",
                **common,
                expires=suggestion.expires.isoformat(),
                dependents=", ".join(suggestion.dependents) or "?",
            )
        else:
            recommendation = M("noise.rec.tune", **common, expires=suggestion.expires.isoformat())
        score = backtest.analyst_facing_clusters.count() / n_days
        evidence_fp = facts.dispositions.fp_lower_bound(
            tenant.noise.disposition_confidence, tenant.noise.min_dispositions
        )
        if evidence_fp is not None and evidence_fp >= g.FP_EVIDENCE_MIN:
            confidence = Confidence.HIGH
    elif verdict == "investigate":
        kind = "noise.investigate"
        co = rec.decision.co_occurs or (backtest is not None and (backtest.co_occurring > 0 or backtest.hides_high))
        severity = Severity.HIGH if co else Severity.MEDIUM
        title = M("noise.title.investigate_high" if co else "noise.title.investigate", **common)
        recommendation = M("noise.rec.investigate", **common)
    elif verdict == "fix_at_source":
        kind = "noise.fix_at_source"
        severity = Severity.MEDIUM if rec.est_analyst_per_day > 0 else Severity.LOW
        fix = rec.fix_kind or rec.decision.fix_kind or "exposure"
        title = M(f"noise.title.fix_at_source.{fix}", **common)
        recommendation = M(f"noise.rec.fix_at_source.{fix}", **common)
    elif verdict == "aggregate":
        kind = "noise.aggregate"
        severity = Severity.MEDIUM if rec.est_analyst_per_day > 0 else Severity.LOW
        title = M("noise.title.aggregate", **common)
        recommendation = M("noise.rec.aggregate", **common)
    elif verdict == "do_not_tune":
        if rec.decision.failed("level"):
            return None  # reported once per rule
        kind = "noise.do_not_tune"
        severity = Severity.LOW
        title = M("noise.title.do_not_tune_tp", **common)
        recommendation = M("noise.rec.do_not_tune_tp", **common)
    else:
        return None
    reasons: list[Message | str] = list(suggestion.reasons)
    if ctx.window is not None:
        reasons.append(
            M(
                "noise.reproduce",
                rule=rec.rule_id,
                scope=scope,
                start=iso(_dt(ctx.window.start)) or "",
                end=iso(_dt(ctx.window.end)) or "",
            )
        )
    return Finding(
        kind=kind,
        domain="noise",
        title=title,
        severity=severity,
        subject=rec.subject,
        reasons=reasons,
        evidence=_evidence(ctx, rec, suggestion),
        recommendation=recommendation,
        confidence=confidence,
        score=round(score, 4),
        tenant=tenant.name,
    )


def _evidence(ctx: _Context, rec: _Record, suggestion: Suggestion) -> dict[str, Any]:
    facts = rec.facts
    window = facts.window
    tenant = ctx.tenant
    counts = facts.dispositions
    present = sum(1 for day in window.days() if facts.daily.get(day, 0) > 0)
    fp_lower = counts.fp_lower_bound(tenant.noise.disposition_confidence, tenant.noise.min_dispositions)
    evidence: dict[str, Any] = {
        "rule_id": rec.rule_id,
        "rule_level": facts.rule_level,
        "conditions": [{"field": c.field, "value": g.entity_for(c.item, c.value, tenant)} for c in facts.conditions],
        "verdict": rec.verdict,
        "action": suggestion.action,
        "review_required": suggestion.review_required,
        "dependents": list(suggestion.dependents),
        "suggestion": suggestion.fingerprint,
        "expires": suggestion.expires.isoformat(),
        "alerts": facts.count_lower,
        "alerts_upper_bound": facts.count_upper,
        "share_of_rule": round(facts.share, 4),
        "analyst_facing_per_day_estimate": round(rec.est_analyst_per_day, 2),
        "days_present": present,
        "days": window.n_days,
        "first_seen": iso(_dt(facts.first_seen)) if facts.first_seen is not None else None,
        "last_seen": iso(_dt(facts.last_seen)) if facts.last_seen is not None else None,
        "daily": g.daily_series(facts.daily, window),
        "gates": _gate_summary(rec.decision),
        "dispositions": {
            **counts.as_dict(),
            "triaged": counts.triaged,
            "fp_lower_bound": round(fp_lower, 4) if fp_lower is not None else None,
        },
        "co_occurrence": [{"entity": Entity(hit.kind, hit.value), "alerts": hit.alerts} for hit in facts.co_hits],
        "beacons": [
            {"entity": Entity("ip", hit.value), "active_hours": hit.active_hours, "span_hours": hit.span_hours}
            for hit in facts.beacons
        ],
        "backtest": _backtest_evidence(rec.backtest, window) if rec.backtest is not None else None,
    }
    if rec.verdict == "tune" and rec.backtest is not None:
        per_day = rec.backtest.analyst_facing_clusters.count() / max(1, window.n_days)
        low, high = tenant.noise.minutes_per_alert
        evidence["time_saved_minutes_per_day"] = [round(per_day * low, 1), round(per_day * high, 1)]
        evidence["time_saved_kind"] = "upper_bound_estimate"
    return evidence


def _gate_summary(decision: g.Decision) -> dict[str, bool]:
    """Gate name -> passed (a gate that produced several outcomes passed only if all of them did)."""
    out: dict[str, bool] = {}
    for outcome in decision.outcomes:
        out[outcome.gate] = out.get(outcome.gate, True) and outcome.passed
    return out


def _backtest_evidence(stats: BacktestStats, window: g.Window) -> dict[str, Any]:
    n_days = max(1, window.n_days)
    return {
        "hidden": stats.hidden_total,
        "hidden_per_day": round(stats.hidden_total / n_days, 2),
        "hidden_analyst_facing": stats.hidden_analyst_facing,
        "hidden_high": stats.hidden_high,
        "tp_hidden": stats.tp_hidden,
        "share_of_rule": round(stats.share_of_rule, 4),
        "share_of_analyst_facing": round(stats.share_of_analyst_facing, 4),
        "clusters": stats.clusters.count(),
        "analyst_facing_clusters_per_day": round(stats.analyst_facing_clusters.count() / n_days, 2),
        "agents": stats.agents_affected,
        "agents_truncated": stats.agents_truncated,
        "hidden_unknown_level": stats.hidden_unknown_level,
        "hidden_external": stats.hidden_external,
        "novel_actors": [{"entity": Entity(kind, value), "alerts": n} for kind, value, n in stats.novel_actors],
        "novel_hosts": [{"entity": Entity("host", host), "alerts": n} for host, n in stats.novel_hosts],
        "levels": {str(k): v for k, v in sorted(stats.levels.items())},
        "co_occurring": stats.co_occurring,
        "beacon_hits": stats.beacon_hits,
        "dispositions": stats.dispositions.as_dict(),
        "daily": g.daily_series(stats.per_day, window),
    }


def _rule_findings(ctx: _Context) -> list[Finding]:
    tenant = ctx.tenant
    window = ctx.window
    if window is None:
        return []
    out: list[Finding] = []
    n_days = max(1, window.n_days)
    burst_seen = {rec.rule_id for rec in ctx.records.values() if rec.decision.failed("burst")}
    for summary in ctx.rules.values():
        if not summary.mined:
            continue
        common = {"rule": summary.rule_id, "description": summary.description or ""}
        volume = M(
            "noise.reason.rule_volume",
            total=summary.total,
            per_day=summary.total / n_days,
            analyst=summary.analyst_facing,
        )
        if summary.level_blocked:
            level_reason = (
                M("noise.reason.level_unknown", max=tenant.max_tunable_level)
                if summary.level is None
                else M("noise.reason.level_blocked", level=summary.level, max=tenant.max_tunable_level)
            )
            out.append(
                Finding(
                    kind="noise.do_not_tune",
                    domain="noise",
                    title=M(
                        "noise.title.do_not_tune_level",
                        **common,
                        level=summary.level if summary.level is not None else "?",
                        max=tenant.max_tunable_level,
                    ),
                    severity=Severity.INFO,
                    subject=f"rule:{summary.rule_id}",
                    reasons=[level_reason, volume],
                    evidence=_rule_evidence(summary, window),
                    recommendation=M("noise.rec.do_not_tune_level", **common),
                    confidence=Confidence.HIGH,
                    score=round(summary.analyst_facing / n_days, 4),
                    tenant=tenant.name,
                )
            )
            continue
        if summary.burst is not None and summary.rule_id not in burst_seen:
            peak, median, day = summary.burst
            base = max(median, 1.0)
            out.append(
                Finding(
                    kind="noise.investigate",
                    domain="noise",
                    title=M("noise.title.rule_burst", **common, peak=peak, day=g.day_label(day), factor=peak / base),
                    severity=Severity.MEDIUM,
                    subject=f"rule:{summary.rule_id}",
                    reasons=[
                        M(
                            "noise.reason.burst",
                            peak=peak,
                            day=g.day_label(day),
                            median=median,
                            factor=peak / base,
                            limit=tenant.noise.burst_factor,
                        ),
                        volume,
                    ],
                    evidence=_rule_evidence(summary, window),
                    recommendation=M("noise.rec.rule_burst", **common, day=g.day_label(day)),
                    score=round(summary.analyst_facing / n_days, 4),
                    tenant=tenant.name,
                )
            )
    return out


def _rule_evidence(summary: _RuleSummary, window: g.Window) -> dict[str, Any]:
    return {
        "rule_id": summary.rule_id,
        "rule_level": summary.level,
        "alerts": summary.total,
        "analyst_facing": summary.analyst_facing,
        "clusters": summary.clusters,
        "daily": g.daily_series(summary.daily, window),
        "top_anchor": summary.top_anchor,
    }


def _rule_verdict(ctx: _Context, summary: _RuleSummary, verdicts: Mapping[str, list[str]]) -> str:
    if ctx.learning:
        return "learning"
    if summary.mined and summary.level_blocked:
        return "do_not_tune"
    found = list(verdicts.get(summary.rule_id, []))
    if summary.mined and summary.burst is not None:
        found.append("investigate")  # the rule-level burst finding
    for verdict in _VERDICT_ORDER:
        if verdict in found:
            return verdict
    return "watch"


def _section(ctx: _Context, suggestions: list[Suggestion], findings: list[Finding]) -> dict[str, Any]:
    tenant = ctx.tenant
    settings = tenant.noise
    window = ctx.window
    summaries = list(ctx.rules.values())
    total = sum(s.total for s in summaries)
    if window is None or total == 0:
        return {
            "status": "not_assessed",
            "totals": {"alerts": 0, "analyst_facing": 0, "rules": 0, "days": 0.0, "clusters": 0, "top5_share": 0.0},
            "rules": [],
            "time_saved_minutes_per_day": None,
            "suppressions_file": None,
            "backtested": ctx.backtested,
            "learning": False,
            "verdicts": {},
            "skipped_events": ctx.skipped,
        }
    n_days = max(1, window.n_days)
    verdicts: dict[str, list[str]] = {}
    for rec in ctx.records.values():
        verdicts.setdefault(rec.rule_id, []).append(rec.verdict)
    ordered = sorted(summaries, key=lambda s: (-s.analyst_facing, -s.total, s.rule_id))
    rows: list[dict[str, Any]] = []
    for summary in ordered[: max(0, int(settings.top_rules))]:
        rows.append(
            {
                "rule_id": summary.rule_id,
                "description": summary.description or "",
                "level": summary.level if summary.level is not None else 0,
                "total": summary.total,
                "per_day": round(summary.total / n_days, 2),
                "analyst_facing": summary.analyst_facing,
                "share": round(summary.total / total, 4),
                "clusters": summary.clusters,
                "days_active": sum(1 for c in summary.daily.values() if c > 0),
                "days": window.n_days,
                "top_anchor": summary.top_anchor,
                "verdict": _rule_verdict(ctx, summary, verdicts),
                "daily": g.daily_series(summary.daily, window),
            }
        )
    top5 = sum(s.total for s in sorted(summaries, key=lambda s: -s.total)[:5])
    counts: dict[str, int] = {}
    for suggestion in suggestions:
        counts[suggestion.verdict] = counts.get(suggestion.verdict, 0) + 1
    noise_findings = [f for f in findings if f.domain == "noise"]
    if ctx.learning:
        status = "not_assessed"
    elif any(f.severity.rank >= Severity.HIGH.rank for f in noise_findings):
        status = "fail"
    elif any(f.severity.rank >= Severity.MEDIUM.rank for f in noise_findings):
        status = "warn"
    else:
        status = "ok"
    return {
        "status": status,
        "totals": {
            "alerts": total,
            "analyst_facing": sum(s.analyst_facing for s in summaries),
            "rules": len(summaries),
            "days": round(window.duration / 86400, 2),
            "clusters": sum(s.clusters for s in summaries),
            "top5_share": round(top5 / total, 4),
        },
        "rules": rows,
        "time_saved_minutes_per_day": _time_saved(ctx),
        "time_saved_kind": "upper_bound_estimate",
        "suppressions_file": None,
        "backtested": ctx.backtested,
        "learning": ctx.learning,
        "verdicts": dict(sorted(counts.items())),
        "window": {"start": iso(_dt(window.start)), "end": iso(_dt(window.end)), "days": window.n_days},
        "skipped_events": ctx.skipped,
    }


def _time_saved(ctx: _Context) -> list[float] | None:
    """UPPER-BOUND estimate: distinct analyst-facing clusters/day hidden by ``tune`` suggestions × the configured
    minutes-per-alert range (overlapping suggestions are de-duplicated through the HyperLogLog union)."""
    tuned = [rec.backtest for rec in ctx.records.values() if rec.verdict == "tune" and rec.backtest is not None]
    if not tuned or ctx.window is None:
        return None
    union = HyperLogLog(tuned[0].analyst_facing_clusters.p)
    for stats in tuned:
        union.merge(stats.analyst_facing_clusters)
    per_day = union.count() / max(1, ctx.window.n_days)
    low, high = ctx.tenant.noise.minutes_per_alert
    return [round(per_day * low, 1), round(per_day * high, 1)]


def _dt(epoch: float) -> datetime:
    return datetime.fromtimestamp(epoch, tz=timezone.utc)


register(
    {
        "noise.scope.rule_wide": {"en": "every alert of the rule", "es": "todas las alertas de la regla"},
        "noise.scope.one": {"en": "{field} = {value}", "es": "{field} = {value}"},
        "noise.scope.two": {
            "en": "{field1} = {value1} and {field2} = {value2}",
            "es": "{field1} = {value1} y {field2} = {value2}",
        },
        "noise.scope.list": {"en": "{first}, {field} = {value}", "es": "{first}, {field} = {value}"},
        "noise.scope.and": {"en": "{first} and {field} = {value}", "es": "{first} y {field} = {value}"},
        "noise.title.tune": {
            "en": "Rule {rule} ({description}) can be safely tuned for {scope}",
            "es": "La regla {rule} ({description}) se puede ajustar de forma segura para {scope}",
        },
        "noise.title.investigate": {
            "en": "Rule {rule} ({description}) is noisy for {scope}, but it is not safe to tune: investigate",
            "es": "La regla {rule} ({description}) es ruidosa para {scope}, pero no es seguro ajustarla: investigue",
        },
        "noise.title.investigate_high": {
            "en": "Rule {rule} ({description}): noisy activity for {scope} is linked to high-level alerts",
            "es": "Regla {rule} ({description}): la actividad ruidosa de {scope} está relacionada con alertas de "
            "nivel alto",
        },
        "noise.title.fix_at_source.fim": {
            "en": "Rule {rule} ({description}): file-integrity noise on {scope}; fix it in the agent configuration",
            "es": "Regla {rule} ({description}): ruido de integridad de archivos en {scope}; corríjalo en la "
            "configuración del agente",
        },
        "noise.title.fix_at_source.check": {
            "en": "Rule {rule} ({description}): rootcheck/SCA noise on {scope}; fix the check or the host",
            "es": "Regla {rule} ({description}): ruido de rootcheck/SCA en {scope}; corrija el chequeo o el equipo",
        },
        "noise.title.fix_at_source.exposure": {
            "en": "Rule {rule} ({description}): persistent noise from a public address ({scope}); restrict exposure",
            "es": "Regla {rule} ({description}): ruido persistente desde una dirección pública ({scope}); "
            "restrinja la exposición",
        },
        "noise.title.aggregate": {
            "en": "Rule {rule} ({description}): duplicate storm for {scope}; aggregate instead of muting",
            "es": "Regla {rule} ({description}): tormenta de duplicados para {scope}; agregue en lugar de silenciar",
        },
        "noise.title.do_not_tune_tp": {
            "en": "Rule {rule} ({description}): {scope} has confirmed true positives; do not tune",
            "es": "Regla {rule} ({description}): {scope} tiene verdaderos positivos confirmados; no la ajuste",
        },
        "noise.title.do_not_tune_level": {
            "en": "Rule {rule} ({description}) is noisy, but level {level} is above the tunable maximum ({max})",
            "es": "La regla {rule} ({description}) es ruidosa, pero su nivel {level} supera el máximo ajustable "
            "({max})",
        },
        "noise.title.rule_burst": {
            "en": "Rule {rule} ({description}) spiked to {peak} alerts on {day} ({factor:.1f}× its median): "
            "investigate",
            "es": "La regla {rule} ({description}) se disparó a {peak} alertas el {day} ({factor:.1f}× su "
            "mediana): investigue",
        },
        "noise.title.learning": {
            "en": "Noise analysis is still learning: {days} day(s) of data, at least {min} needed",
            "es": "El análisis de ruido todavía está aprendiendo: {days} día(s) de datos, se necesitan al menos {min}",
        },
        "noise.title.not_backtested": {
            "en": "{count} tuning candidate(s) were not backtested, so none is recommended",
            "es": "{count} candidato(s) de ajuste no se pudieron verificar con el backtest, así que no se recomienda "
            "ninguno",
        },
        "noise.title.rules_cap": {
            "en": "Noise analysis hit its cap of {cap} distinct rules; {dropped} alert(s) were not analyzed",
            "es": "El análisis de ruido alcanzó su límite de {cap} reglas distintas; {dropped} alerta(s) no se "
            "analizaron",
        },
        "noise.title.dispositions_bad": {
            "en": "Dispositions file: {bad} invalid row(s) were ignored",
            "es": "Archivo de disposiciones: se ignoraron {bad} fila(s) no válidas",
        },
        "noise.reason.pending_backtest": {
            "en": "Passed every safety gate; waiting for the backtest before it can be tuned",
            "es": "Superó todos los controles de seguridad; falta el backtest antes de poder ajustarla",
        },
        "noise.reason.not_backtested": {
            "en": "{count} candidate(s) passed the safety gates, but the input could not be read a second time to "
            "backtest them",
            "es": "{count} candidato(s) superaron los controles de seguridad, pero la entrada no se pudo leer una "
            "segunda vez para el backtest",
        },
        "noise.reason.backtest_error": {
            "en": "Backtest error: {error}",
            "es": "Error en el backtest: {error}",
        },
        "noise.reason.rule_volume": {
            "en": "{total} alerts ({per_day:.1f}/day), {analyst} of them analyst-facing",
            "es": "{total} alertas ({per_day:.1f}/día), {analyst} de ellas visibles para los analistas",
        },
        "noise.reproduce": {
            "en": "Reproduce: filter rule.id = {rule} and {scope} between {start} and {end}",
            "es": "Para reproducir: filtre rule.id = {rule} y {scope} entre {start} y {end}",
        },
        "noise.rec.tune": {
            "en": "Demote rule {rule} for {scope} only, with a scoped child rule that expires on {expires}; test "
            "it with wazuh-logtest before deploying",
            "es": "Reduzca el nivel de la regla {rule} solo para {scope}, con una regla hija acotada que vence el "
            "{expires}; "
            "pruébela con wazuh-logtest antes de desplegarla",
        },
        "noise.rec.tune_review": {
            "en": "REVIEW REQUIRED: rule {rule} feeds the correlation rule(s) {dependents}. Demoting it for {scope} "
            "(expiring on {expires}) may make those rules stop counting the demoted events, even when the child "
            "rule copies the parent's groups, so a multi-event detection (brute force, repeated failures) could "
            "miss activity in this scope. Deploy it only after validating with wazuh-logtest that {dependents} "
            "still fire as expected, or tune the correlation rule instead",
            "es": "REQUIERE REVISIÓN: la regla {rule} alimenta la(s) regla(s) de correlación {dependents}. Reducir "
            "su nivel para {scope} (con vencimiento el {expires}) puede hacer que esas reglas dejen de contar los "
            "eventos rebajados, aunque la regla hija copie los grupos de la regla padre, y una detección de varios "
            "eventos (fuerza bruta, fallos repetidos) podría pasar por alto actividad en este alcance. Despliéguela "
            "solo después de validar con wazuh-logtest que {dependents} se siguen disparando como se espera, o "
            "ajuste la regla de correlación en su lugar",
        },
        "noise.rec.investigate": {
            "en": "Investigate {scope} before any tuning; do not mute these alerts",
            "es": "Investigue {scope} antes de cualquier ajuste; no silencie estas alertas",
        },
        "noise.rec.fix_at_source.fim": {
            "en": "If the changes are expected, ignore {scope} in the syscheck section of agent.conf (centralized "
            "configuration) instead of muting rule {rule}",
            "es": "Si los cambios son esperados, ignore {scope} en la sección syscheck de agent.conf "
            "(configuración centralizada) en lugar de silenciar la regla {rule}",
        },
        "noise.rec.fix_at_source.check": {
            "en": "Fix the failing check or the host configuration behind {scope} instead of muting rule {rule}",
            "es": "Corrija el chequeo fallido o la configuración del equipo detrás de {scope} en lugar de "
            "silenciar la regla {rule}",
        },
        "noise.rec.fix_at_source.exposure": {
            "en": "Restrict exposure: block or filter {scope} at the firewall or the service (or close the port) "
            "instead of muting rule {rule}",
            "es": "Restrinja la exposición: bloquee o filtre {scope} en el firewall o en el servicio (o cierre el "
            "puerto) en lugar de silenciar la regla {rule}",
        },
        "noise.rec.aggregate": {
            "en": "Replace per-event alerts for {scope} with a frequency/timeframe rule (one alert per burst) "
            "instead of muting rule {rule}",
            "es": "Reemplace las alertas por evento de {scope} por una regla con frequency/timeframe (una alerta "
            "por ráfaga) en lugar de silenciar la regla {rule}",
        },
        "noise.rec.do_not_tune_tp": {
            "en": "Keep rule {rule} as is for {scope}; reduce the noise by fixing its cause",
            "es": "Mantenga la regla {rule} tal como está para {scope}; reduzca el ruido corrigiendo su causa",
        },
        "noise.rec.do_not_tune_level": {
            "en": "Keep rule {rule}; if it is noisy, fix the cause or review the rule logic instead of tuning it",
            "es": "Mantenga la regla {rule}; si es ruidosa, corrija la causa o revise la lógica de la regla en "
            "lugar de ajustarla",
        },
        "noise.rec.rule_burst": {
            "en": "Review what rule {rule} fired on around {day} before treating it as noise",
            "es": "Revise qué disparó la regla {rule} alrededor del {day} antes de considerarlo ruido",
        },
        "noise.rec.learning": {
            "en": "Run again once at least {min} days of alerts are available",
            "es": "Vuelva a ejecutar cuando haya al menos {min} días de alertas",
        },
        "noise.rec.not_backtested": {
            "en": "Run the analysis on a re-readable input (files or the indexer) so candidates can be backtested",
            "es": "Ejecute el análisis sobre una entrada que se pueda releer (archivos o el indexador) para poder "
            "hacer el backtest de los candidatos",
        },
    }
)
