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
from ..models import fingerprint as finding_fingerprint
from ..timeutil import iso
from ..tuning import DEMOTE_LEVEL, LOG_ALERT_LEVEL, Condition, Suggestion
from . import gates as g
from .backtest import EXPOSURE_KEY, BacktestStats, BacktestWatch, downgrade_reasons, run_backtest, summary_message
from .backtest import rate as _rate
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
        "compliance",
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
        self.compliance: set[str] = set()  # pci_dss_10.2.4, gdpr_IV_35.7.d...: rule groups alerts carry apart
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
        _add_labels(self.compliance, other.compliance)
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


# Wazuh 4.x alerts carry a rule's compliance groups apart from rule.groups (rule.pci_dss: ["10.2.4"] is the group
# "pci_dss_10.2.4" in the rule file). A generated child rebuilds them when no ruleset was loaded.
_COMPLIANCE_PATHS = (
    ("rule.pci_dss", "pci_dss_"),
    ("rule.gdpr", "gdpr_"),
    ("rule.hipaa", "hipaa_"),
    ("rule.nist_800_53", "nist_800_53_"),
    ("rule.tsc", "tsc_"),
    ("rule.gpg13", "gpg13_"),
)


def _compliance_from_fields(stats: _RuleStats, fields: Mapping[str, Any]) -> None:
    for path, prefix in _COMPLIANCE_PATHS:
        values = g.scalar_values(g.field_value(fields, path))
        if values:
            _add_labels(stats.compliance, (prefix + value for value in values))


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
        if stats.total <= _LABEL_FALLBACK_EVENTS:
            if not (event.mitre_tactics and event.rule_groups):
                _labels_from_fields(stats, event)
            _compliance_from_fields(stats, event.fields)

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
    impact: str = ""  # "analyst" | "index_volume" once backtested clean (see hushwatch.tuning.IMPACTS)
    public_sources: tuple[tuple[str, int], ...] = ()  # dominant public source addresses in the scope (pass 1)


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
    fim_paths: tuple[tuple[str, str, int, int], ...] = ()  # FIM rules: (field, path, alerts, days present)
    fim_hosts: tuple[tuple[str, int], ...] = ()  # FIM rules: hosts where those paths change, (host, alerts)


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
    backtest_error: Message | str | None = None


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
    ``if_matched_group`` / frequency); a candidate on such a rule gets action ``review``. When the result carries
    ``verified=False`` (:class:`hushwatch.wazuh.ruleset.DependentIds`: no stock rule was loaded), or when no
    ``dependents`` is given for Wazuh 4.x data, the correlation links are UNKNOWN and every candidate gets action
    ``review`` too ("not verified", never "nothing correlates on it"). ``expires_days`` sets every suggestion's
    expiry. Call :func:`apply_backtest` next: until then nothing is ``tune``.

    Only *noisy* rules are mined (at least ``min_noisy_alerts`` alerts and ``min_noisy_per_day`` per day, see
    :func:`hushwatch.analysis.gates.is_noisy`). Each suggestion's fingerprint is the fingerprint its
    ``noise.tune`` finding has (tenant, kind, subject), so the finding, the generated Wazuh rule and the
    suppression spec share one id.
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
    periodic_by_rule: dict[str, frozenset[str]] = {}
    watch = BacktestWatch(
        high=collector.high_index,
        co_window_hours=max(0, round(co_seconds / 3600)),
        beacons=beacons_by_rule,
        since=since,
        window=window,
        periodic=periodic_by_rule,
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
    elapsed = g.elapsed_days(window)
    for rid, stats in rules.items():
        ctx.rules[rid] = _summarize(stats, window, field_map, tenant)
    for rid in _mining_order(rules, settings, elapsed):
        stats = rules[rid]
        summary = ctx.rules[rid]
        summary.mined = True
        summary.level_blocked = summary.level is None or summary.level > tenant.max_tunable_level
        if stats.fim:
            summary.fim_paths, summary.fim_hosts = _fim_paths(stats, window, settings, field_map)
        deps, deps_error, unverified = _dependents(dependents, rid, profile)
        beacons, periodic = _rule_beacons(stats, field_map, tenant)
        if beacons:
            beacons_by_rule[rid] = beacons
        if periodic:
            periodic_by_rule[rid] = periodic
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
                deps_unverified=unverified,
                inband_seen=collector.inband_dispositions > 0,
            )
            decision = g.evaluate(facts, settings, tenant)
            subject = _subject(rid, facts.conditions)
            # the id of the noise.tune finding this suggestion becomes (same tenant, kind and subject): one
            # fingerprint across the finding, the generated rule's description and the suppression spec
            fingerprint = finding_fingerprint(tenant.name, "noise.tune", subject)
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
            suggestion = Suggestion(
                rule_id=rid,
                conditions=tuple(Condition(c.field, c.value) for c in facts.conditions),
                verdict=verdict,
                fingerprint=fingerprint,
                expires=expires,
                action=decision.action,
                rule_level=stats.level_max,
                rule_description=stats.description,
                rule_groups=tuple(sorted(stats.groups | stats.compliance)),
                rule_mitre=tuple(sorted(stats.mitre)),
                profile=profile,
                dependents=tuple(deps or ()),
                hidden_total=cand.lower,
                hidden_per_day=cand.lower / elapsed,
                hidden_analyst_facing=round(cand.lower * share_af),
                share_of_rule=facts.share,
                reasons=reasons,
                dependents_verified=unverified is None,
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
                est_analyst_per_day=cand.lower * share_af / elapsed,
                probe=probe,
                public_sources=_public_sources(cand, stats, field_map, tenant),
            )
    findings, section = _finalize(ctx, suggestions)
    return NoiseResult(suggestions, findings, section, False, ctx)


def apply_backtest(result: NoiseResult, events: Iterable[Event], *, tenant: TenantConfig) -> NoiseResult:
    """Second pass: replay every gate-passing candidate over ``events`` and finalize verdicts, findings and the
    section. A candidate becomes ``tune`` only when its backtest hides no alert at level >= ``high_level`` (or of
    unknown level), no true positive, no actor seen in a high-level alert, no beacon-like address, no actor (or,
    for scopes that do not pin a host, no host) that appeared late in the window, and no burst. A scope whose
    hidden alerts mostly come from public addresses becomes ``fix_at_source`` (restrict exposure).

    A clean candidate whose alerts are already at or below the demote level, or that no analyst sees (below
    ``triage_level``), has nothing to gain from a demote rule: it stays ``watch`` with impact ``index_volume``
    (reported apart, never counted as a tuning candidate). If the second pass fails (the file vanished, the
    indexer lost the point-in-time), nothing is tuned and the result is marked not backtested."""
    from ..net import RemoteError  # lazy: the network stack is only needed when the second pass hits it

    ctx = result._ctx
    if ctx is None:
        return result
    suggestions = [replace(s, reasons=list(s.reasons), examples=list(s.examples)) for s in result.suggestions]
    records = {fp: replace(rec, backtest_reasons=list(rec.backtest_reasons)) for fp, rec in ctx.records.items()}
    pending = [s for s in suggestions if s.fingerprint in records and records[s.fingerprint].pending]
    probes = [s for s in suggestions if s.fingerprint in records and records[s.fingerprint].probe]
    error: Message | str | None = None
    if pending or probes:
        try:
            stats = run_backtest(
                pending + probes, events, tenant=tenant, dispositions=ctx.dispositions, watch=ctx.watch
            )
        except RemoteError as exc:  # the indexer failed during pass 2 (a lost PIT...): never tune, never crash
            error = exc.message if isinstance(exc.message, Message) else str(exc)[:300]
            stats = {}
        except OSError as exc:  # the input vanished between passes: keep everything pending (never tune)
            error = str(exc)[:300]
            stats = {}
        days = g.elapsed_days(ctx.window) if ctx.window is not None else 1.0
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
            rec.public_sources = _backtest_sources(entry) or rec.public_sources
            suggestion.reasons = [*rec.backtest_reasons, *suggestion.reasons]
            suggestion.examples = entry.example_docs()
        for suggestion in pending if error is None else ():
            rec = records[suggestion.fingerprint]
            entry = stats.get(suggestion.fingerprint)
            if entry is None:
                continue
            rec.pending = False
            rec.backtest = entry
            rec.public_sources = _backtest_sources(entry) or rec.public_sources
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
                    clean = summary_message(entry, tenant=tenant, days=days)
                    nothing = _nothing_to_gain(entry, suggestion.rule_level, tenant)
                    if nothing is not None:
                        # demoting changes nothing for analysts: never "tune", report it as index volume
                        verdict = "watch"
                        rec.impact = suggestion.impact = "index_volume"
                        rec.backtest_reasons = [nothing, clean]
                    else:
                        verdict = "tune"
                        rec.impact = suggestion.impact = "analyst"
                        rec.backtest_reasons = [clean]
            rec.verdict = verdict
            suggestion.verdict = verdict
            suggestion.reasons = [*rec.backtest_reasons, *gate_reasons]
            suggestion.hidden_total = entry.hidden_total
            suggestion.hidden_per_day = entry.hidden_total / days
            suggestion.hidden_analyst_facing = entry.hidden_analyst_facing
            suggestion.share_of_rule = entry.share_of_rule
            suggestion.examples = entry.example_docs()
    new_ctx = replace(ctx, records=records, backtested=error is None, backtest_error=error)
    findings, section = _finalize(new_ctx, suggestions)
    return NoiseResult(suggestions, findings, section, error is None, new_ctx)


_EVIDENCE_GATES = frozenset({"attacker_field", "sensitive"})  # gates that only ask for triage evidence


def _is_pending_reason(reason: Message | str) -> bool:
    return isinstance(reason, Message) and reason.key == "noise.reason.pending_backtest"


def _nothing_to_gain(entry: BacktestStats, rule_level: int | None, tenant: TenantConfig) -> Message | None:
    """Why a clean candidate would gain nothing from a demote rule (None: analysts would see fewer alerts).

    The generated child is level DEMOTE_LEVEL (still written at Wazuh's default log_alert_level), so alerts
    already at or below it are unchanged, and alerts below ``triage_level`` never reached an analyst anyway."""
    levels = [level for level, count in entry.levels.items() if count]
    top = max(levels) if levels else rule_level
    if top is not None and top <= DEMOTE_LEVEL:
        return M("noise.reason.nothing_to_gain.demoted", level=top, demote=DEMOTE_LEVEL)
    if entry.hidden_analyst_facing == 0:
        return M(
            "noise.reason.nothing_to_gain.triage",
            level=top if top is not None else "?",
            triage=tenant.triage_level,
        )
    return None


MAX_LISTED_SOURCES = 5


def _backtest_sources(entry: BacktestStats) -> tuple[tuple[str, int], ...]:
    """Public source addresses of the backtested scope, most frequent first (exact counts, top 5)."""
    ranked = sorted(entry.public_sources.items(), key=lambda item: (-item[1], item[0]))
    return tuple(ranked[:MAX_LISTED_SOURCES])


# ---- candidate mining --------------------------------------------------------------------------------------------
def _mining_order(rules: Mapping[str, _RuleStats], settings: NoiseSettings, days: float) -> list[str]:
    """Top noisy rules by analyst-facing volume, then top noisy rules by total volume (index noise). A rule below
    the noisy thresholds (:func:`hushwatch.analysis.gates.is_noisy`) is not noise: it is never mined."""
    top = max(0, int(settings.top_rules))
    noisy = [r for r in rules.values() if g.is_noisy(r.total, days, settings)]
    by_af = sorted(noisy, key=lambda r: (-r.analyst_facing, -r.total, r.rule_id))[:top]
    by_total = sorted(noisy, key=lambda r: (-r.total, -r.analyst_facing, r.rule_id))[:top]
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


def _rule_beacons(
    stats: _RuleStats, field_map: Mapping[str, g.AnchorField], tenant: TenantConfig
) -> tuple[frozenset[str], frozenset[str]]:
    """(public addresses with sustained hourly activity anywhere in the rule, the subset that are beacons: an
    outbound destination contacted at a steady interval). Both block tuning; only the second is "beaconing"."""
    found: set[str] = set()
    periodic: set[str] = set()
    for path, sketch in stats.singles.items():
        item = field_map.get(path)
        if item is None or item.role not in g.IP_ROLES:
            continue
        for entry in sketch.entries():
            if g.beacon_like(entry) and g.ip_kind(entry.key, tenant) == "external":
                found.add(entry.key)
                if _beacon_hit(entry.key, entry, item).beacon:
                    periodic.add(entry.key)
    for (_host_path, other_path), pair_sketch in stats.pairs.items():
        item = field_map.get(other_path)
        if item is None or item.role not in g.IP_ROLES:
            continue
        for pair_entry in pair_sketch.entries():
            value = pair_entry.key[1]
            if value in periodic or not g.beacon_like(pair_entry) or g.ip_kind(value, tenant) != "external":
                continue
            found.add(value)
            if _beacon_hit(value, pair_entry, item).beacon:
                periodic.add(value)
    return frozenset(found), frozenset(periodic)


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
    deps_unverified: str | None = None,
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
                beacons[cond.value] = _beacon_hit(cond.value, entry, cond.item)
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
                    beacons[value] = _beacon_hit(value, pair_entry, item)

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
        dependents_unverified=deps_unverified,
    )


def _beacon_hit(value: str, entry: SpaceSavingEntry[Any], item: g.AnchorField | None) -> g.BeaconHit:
    """A public address with sustained hourly activity; beaconing only when outbound and periodic."""
    outbound = item is not None and item.direction == "dst"
    return g.BeaconHit(value, entry.active_hours, entry.hour_span(), outbound, entry.regularity())


def _public_sources(
    cand: _Candidate, stats: _RuleStats, field_map: Mapping[str, g.AnchorField], tenant: TenantConfig
) -> tuple[tuple[str, int], ...]:
    """The public SOURCE addresses behind a scope, most frequent first: the condition itself when it is a public
    address, else the public sources seen with the scope's host (pass-1 lower bounds; the backtest refines
    them). Named in exposure and investigate findings instead of the host or log-source anchor."""
    conds = cand.conditions
    own = [(c.value, cand.lower) for c in conds if c.cls.external]
    if own:
        return tuple(own[:MAX_LISTED_SOURCES])
    host = next((c for c in conds if c.cls.host_like), None)
    if host is None:
        return ()
    found: dict[str, int] = {}
    for (host_path, other_path), sketch in stats.pairs.items():
        item = field_map.get(other_path)
        if host_path != host.field or item is None or item.role not in g.IP_ROLES or item.direction != "src":
            continue
        for entry in sketch.entries():
            host_value, value = entry.key
            lower = entry.count - entry.error
            if host_value == host.value and lower > 0 and g.ip_kind(value, tenant) == "external":
                found[value] = max(found.get(value, 0), lower)
    ranked = sorted(found.items(), key=lambda item: (-item[1], item[0]))
    return tuple(ranked[:MAX_LISTED_SOURCES])


def _dependents(
    fn: Callable[[str], Iterable[str]] | None, rule_id: str, profile: str
) -> tuple[tuple[str, ...] | None, bool, str | None]:
    """(dependent rule ids or None, lookup failed, why the links are unverified or None).

    Wazuh 4.x data without a ruleset, or with a ruleset holding no stock rule (``DependentIds.verified`` False),
    cannot prove that nothing correlates on the rule: that is "not verified" (review), never "no dependents"."""
    if fn is None:
        return None, False, ("no_ruleset" if profile == "wazuh4" else None)
    try:
        result = fn(rule_id)
        found = {str(d) for d in result if d is not None and str(d) != rule_id}
    except Exception:  # a broken ruleset must not crash the run: require review instead
        return (), True, None
    unverified = "no_stock" if getattr(result, "verified", True) is False else None
    return tuple(sorted(found, key=_rule_sort_key)), False, unverified


def _rule_sort_key(rule_id: str) -> tuple[int, str]:
    return (int(rule_id), "") if rule_id.isdigit() and len(rule_id) < 19 else (1 << 62, rule_id)


MAX_FIM_PATHS = 10


def _fim_paths(
    stats: _RuleStats, window: g.Window, settings: NoiseSettings, field_map: Mapping[str, g.AnchorField]
) -> tuple[tuple[tuple[str, str, int, int], ...], tuple[tuple[str, int], ...]]:
    """Recurring file-integrity paths of a FIM rule (``syscheck.path`` / ``file.path`` values that change on most
    days since early in the window, without bursts: the candidates for an ``<ignore>`` in agent.conf) and the hosts
    where they change. A path that changed a few times, or only lately, is never listed: that is what FIM is for."""
    novelty_limit = window.start + settings.novelty_fraction * window.duration
    days = max(1, window.n_days)
    paths: list[tuple[str, str, int, int]] = []
    for path_field in ("syscheck.path", "file.path"):
        sketch = stats.singles.get(path_field)
        if sketch is None:
            continue
        for entry in sketch.top():
            lower = entry.count - entry.error
            if lower < g.MIN_CANDIDATE_EVENTS or entry.first_seen is None or entry.first_seen > novelty_limit:
                continue
            present = sum(1 for day in window.days() if entry.daily.get(day, 0) > 0)
            if present / days < settings.persistence:
                continue
            peak, median, _day = g.burst_stats(entry.daily, window)
            if peak >= settings.burst_factor * max(median, 1.0):
                continue
            paths.append((path_field, entry.key, lower, present))
    paths.sort(key=lambda item: (-item[2], item[1]))
    paths = paths[:MAX_FIM_PATHS]
    wanted = {(f, v) for f, v, _n, _d in paths}
    hosts: dict[str, int] = {}
    for (host_path, other_path), pair_sketch in stats.pairs.items():
        item = field_map.get(host_path)
        if item is None or item.role != g.ROLE_HOST:
            continue
        for pair in pair_sketch.entries():
            host, value = pair.key
            if (other_path, value) in wanted:
                hosts[host] = hosts.get(host, 0) + pair.count - pair.error
    ranked = sorted(hosts.items(), key=lambda item: (-item[1], item[0]))[:MAX_LISTED_SOURCES]
    return tuple(paths), tuple(ranked)


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
# Rules-table verdict: the most important verdict any scope of the rule got (a confirmed true positive first).
_VERDICT_ORDER = ("do_not_tune", "investigate", "fix_at_source", "aggregate", "tune", "watch", "learning")
FIREWALL_DROP_GROUPS = frozenset({"firewall_drop", "firewall_deny", "firewall_block"})
_DROP_WORDS = ("drop", "deny", "denied", "block", "reject")


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
        _retarget_firewall_drops(ctx, by_fp)
        fim: dict[str, list[_Record]] = {}
        for rec in ctx.records.values():
            suggestion = by_fp.get(rec.fingerprint)
            if suggestion is None:
                continue
            if rec.verdict == "fix_at_source" and _fix_kind(rec) == "fim":
                fim.setdefault(rec.rule_id, []).append(rec)  # one finding per FIM rule, with its path set
                continue
            finding = _candidate_finding(ctx, rec, suggestion)
            if finding is not None:
                findings.append(finding)
        for rule_id, recs in fim.items():
            findings.append(_fim_finding(ctx, rule_id, recs, by_fp))
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


def _fix_kind(rec: _Record) -> str:
    return rec.fix_kind or rec.decision.fix_kind or "exposure"


def _is_firewall_drop(summary: _RuleSummary | None) -> bool:
    """A firewall rule for denied connections (Wazuh 4101-style ``firewall_drop``): what it reports was already
    blocked, so the answer to its volume is aggregation, never "block the source" (it is blocked) or a mute."""
    if summary is None:
        return False
    groups = {group.lower() for group in summary.groups}
    if groups & FIREWALL_DROP_GROUPS:
        return True
    description = (summary.description or "").lower()
    return "firewall" in groups and any(word in description for word in _DROP_WORDS)


def _retarget_firewall_drops(ctx: _Context, by_fp: Mapping[str, Suggestion]) -> None:
    """Exposure on a firewall-drop rule is aggregation: the device already blocked those connections, and its own
    address (the log source) is never what to filter."""
    for rec in ctx.records.values():
        if rec.verdict != "fix_at_source" or _fix_kind(rec) != "exposure":
            continue
        if not _is_firewall_drop(ctx.rules.get(rec.rule_id)):
            continue
        rec.verdict = "aggregate"
        rec.fix_kind = "firewall"
        suggestion = by_fp.get(rec.fingerprint)
        if suggestion is not None:
            suggestion.verdict = "aggregate"


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


def _number(value: float) -> Message:
    """A per-day count that never reads 0.0 when it is not zero."""
    if value <= 0:
        return M("noise.num1", value=0.0)
    if value < 0.01:
        return M("noise.num_tiny")
    return M("noise.num2" if value < 1 else "noise.num1", value=value)


def _alerts(count: int) -> Message:
    return M("noise.n.alert" if count == 1 else "noise.n.alerts", n=count)


DOMINANT_SHARE = 0.2  # a public source named as "mostly from" / "driven by" covers at least this share of the scope


def _sources(rec: _Record, limit: int = 3, *, dominant: bool = False) -> list[Entity]:
    """The top public source addresses of a scope ("such as"), or only the dominant ones (>= DOMINANT_SHARE of the
    scope's alerts) when the text says "mostly from"."""
    total = rec.backtest.hidden_total if rec.backtest is not None else rec.facts.count_lower
    return [
        Entity("ip", value)
        for value, n in rec.public_sources[:limit]
        if not dominant or (total > 0 and n >= DOMINANT_SHARE * total)
    ]


def _beacon_targets(rec: _Record) -> list[Entity]:
    """Public destinations contacted at a steady interval (pass 1 and backtest), never the host's own address."""
    found = [hit.value for hit in rec.facts.beacons if hit.beacon]
    if rec.backtest is not None:
        found += [value for value in rec.backtest.beacon_values if value not in found]
    return [Entity("ip", value) for value in found[:3]]


def _host_of(rec: _Record, tenant: TenantConfig) -> Message | Entity | str:
    host = next((c for c in rec.facts.conditions if c.cls.host_like), None)
    if host is None:
        return _scope(rec.facts.conditions, tenant)
    return g.entity_for(host.item, host.value, tenant)


def _has_tp(rec: _Record) -> bool:
    return bool(rec.facts.dispositions.tp or rec.facts.tp_rule_wide) or (
        rec.backtest is not None and rec.backtest.tp_hidden > 0
    )


def _is_novel(rec: _Record) -> bool:
    backtest = rec.backtest
    return rec.decision.failed("novelty") or (
        backtest is not None and bool(backtest.novel_actors or backtest.novel_public or backtest.novel_hosts)
    )


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
    days = _days(ctx)
    sources = _sources(rec)  # "such as": exposure and firewall texts
    dominant = _sources(rec, dominant=True)  # "mostly from" / "driven by": investigate texts
    kind: str
    severity: Severity
    confidence = Confidence.MEDIUM
    score = rec.est_analyst_per_day
    reasons: list[Message | str] = list(suggestion.reasons)
    if verdict == "tune":
        if backtest is None:
            return None
        kind = "noise.tune"
        severity = Severity.MEDIUM if analyst_hidden > 0 else Severity.LOW
        expiry = {"expires": suggestion.expires.isoformat()}
        if suggestion.review_required:
            # never "safely": a correlation rule depends on it, or that could not be verified
            title = M("noise.title.tune_review", **common)
            if suggestion.dependents:
                recommendation = M(
                    "noise.rec.tune_review", **common, **expiry, dependents=", ".join(suggestion.dependents)
                )
            else:
                recommendation = M("noise.rec.tune_unverified", **common, **expiry)
        else:
            title = M("noise.title.tune", **common)
            recommendation = M("noise.rec.tune", **common, **expiry)
        score = backtest.analyst_facing_clusters.count() / days
        evidence_fp = facts.dispositions.fp_lower_bound(
            tenant.noise.disposition_confidence, tenant.noise.min_dispositions
        )
        if evidence_fp is not None and evidence_fp >= g.FP_EVIDENCE_MIN:
            confidence = Confidence.HIGH
    elif verdict == "watch" and rec.impact == "index_volume" and backtest is not None:
        # passed every gate and the backtest, but demoting it changes nothing for analysts: index volume only
        kind = "noise.index_volume"
        severity = Severity.LOW
        level = suggestion.rule_level if suggestion.rule_level is not None else "?"
        title = M("noise.title.index_volume", **common, per_day=_number(backtest.hidden_total / days))
        recommendation = M(
            "noise.rec.index_volume", **common, level=level, log_alert=LOG_ALERT_LEVEL, demote=DEMOTE_LEVEL
        )
        score = backtest.hidden_total / days
    elif verdict == "investigate":
        kind = "noise.investigate"
        co = rec.decision.co_occurs or (backtest is not None and (backtest.co_occurring > 0 or backtest.hides_high))
        beacons = _beacon_targets(rec)
        tp = _has_tp(rec)
        # a confirmed true positive, a beacon, a link to high-level alerts, or a NEW public source is not noise
        severity = Severity.HIGH if (tp or co or beacons or (dominant and _is_novel(rec))) else Severity.MEDIUM
        if tp:
            title = M("noise.title.confirmed_tp", **common)
            recommendation = M("noise.rec.confirmed_tp", **common)
        elif beacons:
            title = M("noise.title.investigate_beacon", **common, host=_host_of(rec, tenant), beacon=beacons)
            recommendation = M("noise.rec.investigate_beacon", **common, beacon=beacons)
        elif co and dominant:
            title = M("noise.title.investigate_high_public", **common, sources=dominant)
            recommendation = M("noise.rec.investigate_public", **common, sources=dominant)
        elif co:
            title = M("noise.title.investigate_high", **common)
            recommendation = M("noise.rec.investigate", **common)
        elif dominant:
            title = M("noise.title.investigate_public", **common, sources=dominant)
            recommendation = M("noise.rec.investigate_public", **common, sources=dominant)
        else:
            title = M("noise.title.investigate", **common)
            recommendation = M("noise.rec.investigate", **common)
    elif verdict == "fix_at_source":
        kind = "noise.fix_at_source"
        severity = Severity.MEDIUM if rec.est_analyst_per_day > 0 else Severity.LOW
        fix = _fix_kind(rec)
        if fix == "exposure":
            title, recommendation = _exposure_texts(rec, common, sources, _host_of(rec, tenant))
        else:
            title = M(f"noise.title.fix_at_source.{fix}", **common)
            recommendation = M(f"noise.rec.fix_at_source.{fix}", **common)
    elif verdict == "aggregate":
        kind = "noise.aggregate"
        severity = Severity.MEDIUM if rec.est_analyst_per_day > 0 else Severity.LOW
        if rec.fix_kind == "firewall":
            per_day = _number((backtest.hidden_total if backtest is not None else facts.count_lower) / days)
            key = "noise.title.aggregate.firewall" if sources else "noise.title.aggregate.firewall_unknown"
            title = M(key, **common, per_day=per_day, sources=sources)
            recommendation = M("noise.rec.aggregate.firewall", **common, device=_host_of(rec, tenant))
        else:
            title = M("noise.title.aggregate", **common)
            recommendation = M("noise.rec.aggregate", **common)
    elif verdict == "do_not_tune":
        if rec.decision.failed("level"):
            return None  # reported once per rule
        kind = "noise.do_not_tune"
        # confirmed true positives are attack activity, never "noise": HIGH, so cron mode notifies it
        severity = Severity.HIGH
        title = M("noise.title.do_not_tune_tp", **common)
        recommendation = M("noise.rec.do_not_tune_tp", **common)
    else:
        return None
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


def _exposure_texts(
    rec: _Record, common: Mapping[str, Any], sources: list[Entity], device: Message | Entity | str
) -> tuple[Message, Message]:
    """Restrict-exposure advice that names the PUBLIC sources, never the anchor: a ``location`` (a syslog sender,
    often the firewall or the log relay itself) or a host identifies the monitored device, not the attacker."""
    conds = rec.facts.conditions
    own_ip = any(c.cls.external for c in conds)
    relay = any(c.field == "location" for c in conds)
    title_key = "noise.title.fix_at_source.exposure" if sources else "noise.title.fix_at_source.exposure_unknown"
    if own_ip:
        rec_key = "noise.rec.fix_at_source.exposure_ip"
    elif relay:
        rec_key = "noise.rec.fix_at_source.exposure_relay"
    else:
        rec_key = "noise.rec.fix_at_source.exposure"
    if not sources:
        rec_key += "_unknown"
    return M(title_key, **common, sources=sources), M(rec_key, **common, sources=sources, device=device)


def _fim_finding(ctx: _Context, rule_id: str, recs: list[_Record], by_fp: Mapping[str, Suggestion]) -> Finding:
    """ONE finding per file-integrity rule: the recurring paths to ignore in agent.conf (with the exact syscheck
    syntax) and the hosts where they change. A host is never what syscheck ignores."""
    tenant = ctx.tenant
    summary = ctx.rules.get(rule_id)
    description = (summary.description if summary else None) or ""
    days = _days(ctx)
    paths = summary.fim_paths if summary is not None else ()
    hosts = [Entity("host", host) for host, _n in (summary.fim_hosts if summary is not None else ())]
    if not hosts:
        hosts = list(
            dict.fromkeys(Entity("host", c.value) for rec in recs for c in rec.facts.conditions if c.cls.host_like)
        )[:MAX_LISTED_SOURCES]
    common: dict[str, Any] = {"rule": rule_id, "description": description}
    path_entities = [Entity("file", value) for _f, value, _n, _d in paths]
    alerts = sum(n for _f, _v, n, _d in paths) or max(rec.facts.count_lower for rec in recs)
    pattern = _sregex_for(value for _f, value, _n, _d in paths)
    host_list: list[Entity] | Message = hosts or M("noise.fim.hosts_unknown")
    if paths:
        title = M(
            "noise.title.fix_at_source.fim_paths",
            **common,
            count=len(paths),
            paths=path_entities[:3],
            hosts=host_list,
        )
        if pattern is not None:
            recommendation = M(
                "noise.rec.fix_at_source.fim_pattern",
                **common,
                pattern=Entity("file", pattern),
                first=path_entities[0],
                hosts=host_list,
            )
        else:
            recommendation = M(
                "noise.rec.fix_at_source.fim_paths",
                **common,
                first=path_entities[0],
                others=path_entities[1:] or M("noise.fim.no_others"),
                hosts=host_list,
            )
    else:
        title = M("noise.title.fix_at_source.fim_hosts", **common, hosts=host_list)
        recommendation = M("noise.rec.fix_at_source.fim_hosts", **common, hosts=host_list)
    reasons: list[Message | str] = [M("noise.reason.fim")]
    if paths:
        reasons.append(
            M("noise.reason.fim_paths", count=len(paths), alerts=_alerts(alerts), per_day=_rate(alerts / days))
        )
    first = recs[0]
    reasons.extend(r for r in (by_fp[first.fingerprint].reasons if first.fingerprint in by_fp else []) if _gate(r))
    analyst = sum(rec.est_analyst_per_day for rec in recs)
    window = ctx.window
    evidence: dict[str, Any] = {
        "rule_id": rule_id,
        "rule_level": summary.level if summary is not None else None,
        "verdict": "fix_at_source",
        "fix": "fim",
        "paths": [
            {"path": Entity("file", value), "field": path_field, "alerts": n, "days_present": d}
            for path_field, value, n, d in paths
        ],
        "hosts": [{"host": Entity("host", host), "alerts": n} for host, n in (summary.fim_hosts if summary else ())],
        "ignore_pattern": Entity("file", pattern) if pattern is not None else None,
        "alerts": alerts,
        "alerts_per_day": round(alerts / days, 2),
        "days": window.n_days if window is not None else 0,
        "suggestions": [rec.fingerprint for rec in recs],
    }
    if window is not None:
        reasons.append(
            M(
                "noise.reproduce",
                rule=rule_id,
                scope=M("noise.scope.fim"),
                start=iso(_dt(window.start)) or "",
                end=iso(_dt(window.end)) or "",
            )
        )
    return Finding(
        kind="noise.fix_at_source",
        domain="noise",
        title=title,
        severity=Severity.MEDIUM if analyst > 0 else Severity.LOW,
        subject=f"rule:{rule_id}|fim",
        reasons=reasons,
        evidence=evidence,
        recommendation=recommendation,
        confidence=Confidence.MEDIUM,
        score=round(analyst, 4),
        tenant=tenant.name,
    )


def _gate(reason: Message | str) -> bool:
    """Gate reasons worth repeating on the merged FIM finding (not the per-scope share/level boilerplate)."""
    return isinstance(reason, Message) and reason.key in (
        "noise.reason.novel",
        "noise.reason.not_persistent",
        "noise.reason.burst",
        "noise.reason.co_occurrence",
        "noise.reason.tp",
    )


_SREGEX_SPECIAL = frozenset("$()\\|<")


def _sregex_escape(text: str) -> str:
    """Escape for Wazuh's simple regex (OS_Regex): ``$ ( ) \\ | <`` need a backslash; every other character
    (including ``.``) is literal."""
    return "".join("\\" + ch if ch in _SREGEX_SPECIAL else ch for ch in text)


def _sregex_for(paths: Iterable[str]) -> str | None:
    """``^/var/log/app/\\S+.log$`` when at least two recurring paths share a directory and an extension (OS_Regex:
    ``\\S+`` is any run of non-space characters; a plain ``.`` is a literal dot). None otherwise: exact paths."""
    items = [p for p in paths if p and p[-1:] not in ("/", "\\")]
    if len(items) < 2:
        return None
    parents: set[str] = set()
    extensions: set[str] = set()
    for path in items:
        cut = max(path.rfind("/"), path.rfind("\\"))
        if cut <= 0:
            return None
        parent, name = path[: cut + 1], path[cut + 1 :]
        dot = name.rfind(".")
        if dot <= 0 or any(ch.isspace() for ch in name):
            return None
        parents.add(parent)
        extensions.add(name[dot:])
    if len(parents) != 1 or len(extensions) != 1:
        return None
    return f"^{_sregex_escape(parents.pop())}\\S+{_sregex_escape(extensions.pop())}$"


def _evidence(ctx: _Context, rec: _Record, suggestion: Suggestion) -> dict[str, Any]:
    facts = rec.facts
    window = facts.window
    tenant = ctx.tenant
    counts = facts.dispositions
    present = sum(1 for day in window.days() if facts.daily.get(day, 0) > 0)
    fp_lower = counts.fp_lower_bound(tenant.noise.disposition_confidence, tenant.noise.min_dispositions)
    days = g.elapsed_days(window)
    evidence: dict[str, Any] = {
        "rule_id": rec.rule_id,
        "rule_level": facts.rule_level,
        "conditions": [{"field": c.field, "value": g.entity_for(c.item, c.value, tenant)} for c in facts.conditions],
        "verdict": rec.verdict,
        "action": suggestion.action,
        "review_required": suggestion.review_required,
        "dependents": list(suggestion.dependents),
        "dependents_verified": suggestion.dependents_verified,
        "suggestion": suggestion.fingerprint,
        "expires": suggestion.expires.isoformat(),
        "alerts": facts.count_lower,
        "alerts_upper_bound": facts.count_upper,
        "share_of_rule": round(facts.share, 6),
        "analyst_facing_per_day_estimate": round(rec.est_analyst_per_day, 2),
        "days_present": present,
        "days": window.n_days,
        "days_elapsed": round(days, 2),
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
            {
                "entity": Entity("ip", hit.value),
                "active_hours": hit.active_hours,
                "span_hours": hit.span_hours,
                "outbound": hit.outbound,
                "regularity": round(hit.regularity, 3) if hit.regularity is not None else None,
                "beaconing": hit.beacon,
            }
            for hit in facts.beacons
        ],
        "public_sources": [{"entity": Entity("ip", value), "alerts": n} for value, n in rec.public_sources],
        "backtest": _backtest_evidence(rec.backtest, window) if rec.backtest is not None else None,
    }
    if rec.impact:
        evidence["impact"] = rec.impact
    if rec.verdict == "tune" and rec.backtest is not None:
        per_day = rec.backtest.analyst_facing_clusters.count() / days
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
    days = g.elapsed_days(window)
    return {
        "hidden": stats.hidden_total,
        "hidden_per_day": round(stats.hidden_total / days, 2),
        "hidden_analyst_facing": stats.hidden_analyst_facing,
        "hidden_high": stats.hidden_high,
        "tp_hidden": stats.tp_hidden,
        "share_of_rule": round(stats.share_of_rule, 6),
        "share_of_analyst_facing": round(stats.share_of_analyst_facing, 6),
        "clusters": stats.clusters.count(),
        "analyst_facing_clusters_per_day": round(stats.analyst_facing_clusters.count() / days, 2),
        "agents": stats.agents_affected,
        "agents_truncated": stats.agents_truncated,
        "hidden_unknown_level": stats.hidden_unknown_level,
        "hidden_external": stats.hidden_external,
        "novel_actors": [{"entity": Entity(kind, value), "alerts": n} for kind, value, n in stats.novel_actors],
        "novel_hosts": [{"entity": Entity("host", host), "alerts": n} for host, n in stats.novel_hosts],
        "levels": {str(k): v for k, v in sorted(stats.levels.items())},
        "co_occurring": stats.co_occurring,
        "beacon_hits": stats.beacon_hits,
        "sustained_hits": stats.sustained_hits,
        "dispositions": stats.dispositions.as_dict(),
        "daily": g.daily_series(stats.per_day, window),
    }


def _rule_findings(ctx: _Context) -> list[Finding]:
    tenant = ctx.tenant
    window = ctx.window
    if window is None:
        return []
    out: list[Finding] = []
    days = g.elapsed_days(window)
    burst_seen = {rec.rule_id for rec in ctx.records.values() if rec.decision.failed("burst")}
    for summary in ctx.rules.values():
        if not summary.mined:  # only noisy rules are mined: a rule that fired a handful of times is not noise
            continue
        common = {"rule": summary.rule_id, "description": summary.description or ""}
        volume = _volume(summary, days)
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
                        "noise.title.do_not_tune_level"
                        if summary.level is not None
                        else "noise.title.do_not_tune_level_unknown",
                        **common,
                        level=summary.level if summary.level is not None else "?",
                        max=tenant.max_tunable_level,
                        volume=volume,
                    ),
                    severity=Severity.INFO,
                    subject=f"rule:{summary.rule_id}",
                    reasons=[level_reason, volume],
                    evidence=_rule_evidence(summary, window),
                    recommendation=M("noise.rec.do_not_tune_level", **common),
                    confidence=Confidence.HIGH,
                    score=round(summary.analyst_facing / days, 4),
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
                    score=round(summary.analyst_facing / days, 4),
                    tenant=tenant.name,
                )
            )
    return out


def _volume(summary: _RuleSummary, days: float) -> Message:
    return M(
        "noise.reason.rule_volume",
        alerts=_alerts(summary.total),
        per_day=_rate(summary.total / days),
        analyst=summary.analyst_facing,
    )


def _rule_evidence(summary: _RuleSummary, window: g.Window) -> dict[str, Any]:
    return {
        "rule_id": summary.rule_id,
        "rule_level": summary.level,
        "alerts": summary.total,
        "alerts_per_day": round(summary.total / g.elapsed_days(window), 2),
        "analyst_facing": summary.analyst_facing,
        "clusters": summary.clusters,
        "daily": g.daily_series(summary.daily, window),
        "top_anchor": summary.top_anchor,
    }


def _rule_verdict(ctx: _Context, summary: _RuleSummary, verdicts: Mapping[str, list[str]]) -> str:
    if ctx.learning:
        return "learning"
    if summary.level is None or summary.level > ctx.tenant.max_tunable_level:
        return "do_not_tune"  # a property of the rule, noisy or not: it is never tuned
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
    min_alerts, min_per_day = g.noisy_thresholds(settings)
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
            "safe_tuning_candidates": 0,
            "review_required_candidates": 0,
            "index_volume_candidates": 0,
            "skipped_events": ctx.skipped,
        }
    days = g.elapsed_days(window)
    verdicts: dict[str, list[str]] = {}
    rule_wide: set[tuple[str, str]] = set()  # (rule, verdict) given to a whole-rule suggestion (allow_rule_wide)
    for rec in ctx.records.values():
        verdicts.setdefault(rec.rule_id, []).append(rec.verdict)
        if not rec.facts.conditions:
            rule_wide.add((rec.rule_id, rec.verdict))
    ordered = sorted(summaries, key=lambda s: (-s.analyst_facing, -s.total, s.rule_id))
    rows: list[dict[str, Any]] = []
    for summary in ordered[: max(0, int(settings.top_rules))]:
        verdict = _rule_verdict(ctx, summary, verdicts)
        found = verdicts.get(summary.rule_id, [])
        rule_blocked = summary.level is None or summary.level > tenant.max_tunable_level
        rows.append(
            {
                "rule_id": summary.rule_id,
                "description": summary.description or "",
                "level": summary.level if summary.level is not None else 0,
                "total": summary.total,
                "per_day": round(summary.total / days, 2),
                "analyst_facing": summary.analyst_facing,
                "share": round(summary.total / total, 6),
                "clusters": summary.clusters,
                "days_active": sum(1 for c in summary.daily.values() if c > 0),
                "days": window.n_days,
                "top_anchor": summary.top_anchor,
                "verdict": verdict,
                # the verdict comes from scoped suggestions (a host, an account...), not from the whole rule
                "verdict_scoped": verdict in found and not rule_blocked and (summary.rule_id, verdict) not in rule_wide,
                "verdict_counts": {v: found.count(v) for v in _VERDICT_ORDER if v in found},
                "noisy": g.is_noisy(summary.total, days, settings),
                "daily": g.daily_series(summary.daily, window),
            }
        )
    top5 = sum(s.total for s in sorted(summaries, key=lambda s: -s.total)[:5])
    counts: dict[str, int] = {}
    for suggestion in suggestions:
        counts[suggestion.verdict] = counts.get(suggestion.verdict, 0) + 1
    tuned = [s for s in suggestions if s.verdict == "tune"]
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
            "days": round(days, 2),
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
        # "safe" means: passed every gate and the backtest, analysts gain from it, and no review is required
        "safe_tuning_candidates": sum(1 for s in tuned if not s.review_required),
        "review_required_candidates": sum(1 for s in tuned if s.review_required),
        "index_volume_candidates": sum(1 for s in suggestions if s.index_volume),
        "noisy_threshold": {"alerts": min_alerts, "per_day": min_per_day},
        "window": {
            "start": iso(_dt(window.start)),
            "end": iso(_dt(window.end)),
            "days": round(days, 2),
            "dates": window.n_days,
        },
        "skipped_events": ctx.skipped,
    }


def _time_saved(ctx: _Context) -> list[float] | None:
    """UPPER-BOUND estimate: distinct analyst-facing clusters/day demoted by ``tune`` suggestions × the configured
    minutes-per-alert range (overlapping suggestions are de-duplicated through the HyperLogLog union)."""
    tuned = [rec.backtest for rec in ctx.records.values() if rec.verdict == "tune" and rec.backtest is not None]
    if not tuned or ctx.window is None:
        return None
    union = HyperLogLog(tuned[0].analyst_facing_clusters.p)
    for stats in tuned:
        union.merge(stats.analyst_facing_clusters)
    per_day = union.count() / g.elapsed_days(ctx.window)
    low, high = ctx.tenant.noise.minutes_per_alert
    return [round(per_day * low, 1), round(per_day * high, 1)]


def _days(ctx: _Context) -> float:
    return g.elapsed_days(ctx.window) if ctx.window is not None else 1.0


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
        "noise.scope.fim": {"en": "the paths listed above", "es": "las rutas indicadas arriba"},
        "noise.n.alert": {"en": "{n} alert", "es": "{n} alerta"},
        "noise.n.alerts": {"en": "{n} alerts", "es": "{n} alertas"},
        # ---- titles ------------------------------------------------------------------------------------------
        "noise.title.tune": {
            "en": "Rule {rule} ({description}) can be safely demoted for {scope}",
            "es": "La regla {rule} ({description}) se puede degradar de forma segura para {scope}",
        },
        "noise.title.tune_review": {
            "en": "Rule {rule} ({description}) passed every safety gate and the backtest for {scope}, but needs "
            "review before it is demoted (correlation rules)",
            "es": "La regla {rule} ({description}) superó todos los controles de seguridad y el backtest para "
            "{scope}, pero requiere revisión antes de degradarla (reglas de correlación)",
        },
        "noise.title.index_volume": {
            "en": "Rule {rule} ({description}): {scope} adds {per_day} alerts a day that no analyst sees (index "
            "volume only, nothing to gain by demoting them)",
            "es": "Regla {rule} ({description}): {scope} suma {per_day} alertas por día que ningún analista ve "
            "(solo volumen del índice; degradarlas no aporta nada)",
        },
        "noise.num1": {"en": "{value:.1f}", "es": "{value:.1f}"},
        "noise.num2": {"en": "{value:.2f}", "es": "{value:.2f}"},
        "noise.num_tiny": {"en": "fewer than 0.01", "es": "menos de 0,01"},
        "noise.title.confirmed_tp": {
            "en": "Rule {rule} ({description}): {scope} includes confirmed true positives. This is attack activity: "
            "investigate and respond, do not tune",
            "es": "Regla {rule} ({description}): {scope} incluye verdaderos positivos confirmados. Es actividad de "
            "ataque: investigue y responda, no la ajuste",
        },
        "noise.title.investigate": {
            "en": "Rule {rule} ({description}) is noisy for {scope}, but it is not safe to tune: investigate",
            "es": "La regla {rule} ({description}) es ruidosa para {scope}, pero no es seguro ajustarla: investigue",
        },
        "noise.title.investigate_high": {
            "en": "Rule {rule} ({description}): noisy activity for {scope} is linked to high-level alerts: investigate",
            "es": "Regla {rule} ({description}): la actividad ruidosa de {scope} está relacionada con alertas de "
            "nivel alto: investigue",
        },
        "noise.title.investigate_high_public": {
            "en": "Rule {rule} ({description}): activity on {scope}, mostly from the public address(es) {sources}, "
            "is linked to high-level alerts: investigate",
            "es": "Regla {rule} ({description}): la actividad en {scope}, sobre todo desde la(s) dirección(es) "
            "pública(s) {sources}, está relacionada con alertas de nivel alto: investigue",
        },
        "noise.title.investigate_public": {
            "en": "Rule {rule} ({description}) is noisy for {scope}, driven by the public address(es) {sources}: "
            "investigate, do not tune",
            "es": "La regla {rule} ({description}) es ruidosa para {scope}, por la(s) dirección(es) pública(s) "
            "{sources}: investigue, no la ajuste",
        },
        "noise.title.investigate_beacon": {
            "en": "Rule {rule} ({description}): {host} contacts the public address {beacon} at a steady interval, "
            "like a beacon: investigate",
            "es": "Regla {rule} ({description}): {host} contacta la dirección pública {beacon} a intervalos "
            "regulares, como un beacon: investigue",
        },
        "noise.title.fix_at_source.fim": {
            "en": "Rule {rule} ({description}): file-integrity noise on {scope}; fix it in the agent configuration",
            "es": "Regla {rule} ({description}): ruido de integridad de archivos en {scope}; corríjalo en la "
            "configuración del agente",
        },
        "noise.title.fix_at_source.fim_paths": {
            "en": "Rule {rule} ({description}): file-integrity noise from {count} recurring path(s) such as {paths} "
            "on {hosts}; ignore them in agent.conf",
            "es": "Regla {rule} ({description}): ruido de integridad de archivos de {count} ruta(s) recurrente(s) "
            "como {paths} en {hosts}; ignórelas en agent.conf",
        },
        "noise.title.fix_at_source.fim_hosts": {
            "en": "Rule {rule} ({description}): file-integrity noise on {hosts}, spread over many paths",
            "es": "Regla {rule} ({description}): ruido de integridad de archivos en {hosts}, repartido en muchas rutas",
        },
        "noise.title.fix_at_source.check": {
            "en": "Rule {rule} ({description}): rootcheck/SCA noise on {scope}; fix the check or the host",
            "es": "Regla {rule} ({description}): ruido de rootcheck/SCA en {scope}; corrija el chequeo o el equipo",
        },
        "noise.title.fix_at_source.exposure": {
            "en": "Rule {rule} ({description}): alerts for {scope} mostly come from public addresses such as "
            "{sources}; restrict the exposure",
            "es": "Regla {rule} ({description}): las alertas de {scope} provienen sobre todo de direcciones públicas "
            "como {sources}; restrinja la exposición",
        },
        "noise.title.fix_at_source.exposure_unknown": {
            "en": "Rule {rule} ({description}): alerts for {scope} mostly come from public addresses; restrict the "
            "exposure",
            "es": "Regla {rule} ({description}): las alertas de {scope} provienen sobre todo de direcciones "
            "públicas; restrinja la exposición",
        },
        "noise.title.aggregate": {
            "en": "Rule {rule} ({description}): duplicate storm for {scope}; aggregate instead of muting",
            "es": "Regla {rule} ({description}): tormenta de duplicados para {scope}; agrúpelas en lugar de "
            "silenciarlas",
        },
        "noise.title.aggregate.firewall": {
            "en": "Rule {rule} ({description}): {scope} reports {per_day} denied connections a day, mostly from "
            "public addresses such as {sources}; alert once per source instead of once per packet",
            "es": "Regla {rule} ({description}): {scope} informa {per_day} conexiones denegadas por día, sobre todo "
            "desde direcciones públicas como {sources}; alerte una vez por origen en lugar de una vez por paquete",
        },
        "noise.title.aggregate.firewall_unknown": {
            "en": "Rule {rule} ({description}): {scope} reports {per_day} denied connections a day, mostly from "
            "public addresses; alert once per source instead of once per packet",
            "es": "Regla {rule} ({description}): {scope} informa {per_day} conexiones denegadas por día, sobre todo "
            "desde direcciones públicas; alerte una vez por origen en lugar de una vez por paquete",
        },
        "noise.title.do_not_tune_tp": {
            "en": "Rule {rule} ({description}): {scope} has confirmed true positives. This is attack activity: "
            "investigate and respond, do not tune",
            "es": "Regla {rule} ({description}): {scope} tiene verdaderos positivos confirmados. Es actividad de "
            "ataque: investigue y responda, no la ajuste",
        },
        "noise.title.do_not_tune_level": {
            "en": "Rule {rule} ({description}): level {level} is a high-severity rule, out of scope for tuning "
            "({volume})",
            "es": "Regla {rule} ({description}): el nivel {level} es de severidad alta, fuera del alcance del ajuste "
            "({volume})",
        },
        "noise.title.do_not_tune_level_unknown": {
            "en": "Rule {rule} ({description}): its level is unknown, so it is out of scope for tuning ({volume})",
            "es": "Regla {rule} ({description}): su nivel es desconocido, así que queda fuera del alcance del ajuste "
            "({volume})",
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
        # ---- reasons -----------------------------------------------------------------------------------------
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
            "en": "{alerts} ({per_day}), {analyst} of them analyst-facing",
            "es": "{alerts} ({per_day}), {analyst} de ellas visibles para los analistas",
        },
        "noise.reason.fim_paths": {
            "en": "{count} path(s) changed on most days since early in the window: {alerts} ({per_day})",
            "es": "{count} ruta(s) cambiaron casi todos los días desde el comienzo de la ventana: {alerts} ({per_day})",
        },
        "noise.reason.nothing_to_gain.demoted": {
            "en": "Nothing to gain: rule level {level} is already at or below the demote level ({demote}), so a "
            "demote rule would change nothing",
            "es": "No hay nada que ganar: el nivel {level} de la regla ya es igual o inferior al nivel de "
            "degradación ({demote}), así que una regla de degradación no cambiaría nada",
        },
        "noise.reason.nothing_to_gain.triage": {
            "en": "Nothing to gain: rule level {level} is below the triage level ({triage}), so no analyst sees "
            "these alerts and demoting them changes nothing for the SOC",
            "es": "No hay nada que ganar: el nivel {level} de la regla es inferior al nivel de triaje ({triage}), "
            "así que ningún analista ve estas alertas y degradarlas no cambia nada para el SOC",
        },
        "noise.reproduce": {
            "en": "Reproduce: filter rule.id = {rule} and {scope} between {start} and {end}",
            "es": "Para reproducir: filtre rule.id = {rule} y {scope} entre {start} y {end}",
        },
        "noise.fim.hosts_unknown": {"en": "the affected agents", "es": "los agentes afectados"},
        "noise.fim.no_others": {"en": "no other path", "es": "ninguna otra ruta"},
        # ---- recommendations ---------------------------------------------------------------------------------
        "noise.rec.tune": {
            "en": "Demote rule {rule} for {scope} only, with a scoped child rule marked to expire on {expires}. "
            "Wazuh rules never expire by themselves: the date is written in the rule description and "
            "`hushwatch audit` reports the rule as expired (tuning.expired) once it passes. Test it with "
            "wazuh-logtest before deploying",
            "es": "Degrade la regla {rule} solo para {scope}, con una regla hija acotada que vence el {expires}. Las "
            "reglas de Wazuh no vencen solas: la fecha queda en la descripción de la regla y `hushwatch audit` la "
            "informa como vencida (tuning.expired) cuando pasa. Pruébela con wazuh-logtest antes de desplegarla",
        },
        "noise.rec.tune_review": {
            "en": "REVIEW REQUIRED: rule {rule} feeds the correlation rule(s) {dependents}. Demoting it for {scope} "
            "(marked to expire on {expires}; Wazuh has no rule expiry, `hushwatch audit` enforces the date) may "
            "make those rules stop counting the demoted events, even when the child rule copies the parent's "
            "groups, so a multi-event detection (brute force, repeated failures) could miss activity in this "
            "scope. Deploy it only after validating with wazuh-logtest that {dependents} still fire as expected, "
            "or tune the correlation rule instead",
            "es": "REQUIERE REVISIÓN: la regla {rule} alimenta la(s) regla(s) de correlación {dependents}. "
            "Degradarla para {scope} (con vencimiento el {expires}; Wazuh no hace vencer reglas, `hushwatch audit` "
            "controla la fecha) puede hacer que esas reglas dejen de contar los eventos degradados, aunque la regla "
            "hija copie los grupos de la regla padre, y una detección de varios eventos (fuerza bruta, fallos "
            "repetidos) podría pasar por alto actividad en este alcance. Despliéguela solo después de validar con "
            "wazuh-logtest que {dependents} se siguen disparando como se espera, o ajuste la regla de correlación en "
            "su lugar",
        },
        "noise.rec.tune_unverified": {
            "en": "REVIEW REQUIRED: the stock Wazuh ruleset was not loaded, so it was not verified whether "
            "correlation rules count rule {rule}. Re-run with --ruleset /var/ossec/ruleset/rules --ruleset "
            "/var/ossec/etc/rules, or check with wazuh-logtest that no correlation rule (if_matched_sid, "
            "if_matched_group, frequency) depends on it, before demoting it for {scope} (marked to expire on "
            "{expires}; `hushwatch audit` enforces the date)",
            "es": "REQUIERE REVISIÓN: no se cargó el ruleset de fábrica de Wazuh, así que no se verificó si alguna "
            "regla de correlación cuenta la regla {rule}. Vuelva a ejecutar con --ruleset /var/ossec/ruleset/rules "
            "--ruleset /var/ossec/etc/rules, o compruebe con wazuh-logtest que ninguna regla de correlación "
            "(if_matched_sid, if_matched_group, frequency) depende de ella, antes de degradarla para {scope} (con "
            "vencimiento el {expires}; `hushwatch audit` controla la fecha)",
        },
        "noise.rec.index_volume": {
            "en": "Nothing to do for analysts: rule {rule} is level {level}, and a demote rule (level {demote}) "
            "would change nothing. hushwatch writes no rule for it. If index volume is a real problem, the options "
            "are: (1) a scoped child rule with <options>no_log</options>, or at a level below log_alert_level "
            "({log_alert}): these alerts stop being written to alerts.json and the indexer (they stay only in "
            "archives, if enabled), and correlation rules on rule {rule} stop counting them; or (2) an overwrite of "
            'rule {rule} (overwrite="yes", with its full body) with <options>no_log</options>: every alert of '
            "the rule disappears, on every agent. Both make these events unsearchable during an investigation: "
            "prefer keeping them",
            "es": "No hay nada que hacer para los analistas: la regla {rule} es de nivel {level} y una regla de "
            "degradación (nivel {demote}) no cambiaría nada. hushwatch no genera ninguna regla para ella. Si el "
            "volumen del índice es un problema real, las opciones son: (1) una regla hija acotada con "
            "<options>no_log</options>, o con un nivel inferior a log_alert_level ({log_alert}): estas alertas "
            "dejan de escribirse en alerts.json y en el indexador (quedan solo en archives, si está habilitado), y "
            "las reglas de correlación sobre la regla {rule} dejan de contarlas; o (2) una sobrescritura de la "
            'regla {rule} (overwrite="yes", con su cuerpo completo) con <options>no_log</options>: desaparecen '
            "todas las alertas de la regla, en todos los agentes. Ambas impiden buscar estos eventos durante una "
            "investigación: es preferible conservarlos",
        },
        "noise.rec.confirmed_tp": {
            "en": "Handle {scope} as an incident: investigate and respond (contain the source, reset the affected "
            "credentials). Keep rule {rule} exactly as it is",
            "es": "Trate {scope} como un incidente: investigue y responda (contenga el origen, restablezca las "
            "credenciales afectadas). Mantenga la regla {rule} tal como está",
        },
        "noise.rec.investigate": {
            "en": "Investigate {scope} before any tuning; do not mute these alerts",
            "es": "Investigue {scope} antes de cualquier ajuste; no silencie estas alertas",
        },
        "noise.rec.investigate_public": {
            "en": "Investigate the traffic from {sources} to {scope}: block or rate-limit it at the perimeter if it "
            "is hostile; do not mute rule {rule}",
            "es": "Investigue el tráfico desde {sources} hacia {scope}: bloquéelo o límitelo en el perímetro si es "
            "hostil; no silencie la regla {rule}",
        },
        "noise.rec.investigate_beacon": {
            "en": "Treat the regular connections to {beacon} as possible command and control: identify the process "
            "behind them, check the destination's reputation, and isolate the host if it is not a known service. "
            "Do not mute rule {rule}",
            "es": "Trate las conexiones regulares hacia {beacon} como posible comando y control: identifique el "
            "proceso que las origina, verifique la reputación del destino y aísle el equipo si no es un servicio "
            "conocido. No silencie la regla {rule}",
        },
        "noise.rec.fix_at_source.fim": {
            "en": "If the changes are expected, ignore the changing paths in the <syscheck> section of agent.conf "
            "instead of muting rule {rule}",
            "es": "Si los cambios son esperados, ignore las rutas que cambian en la sección <syscheck> de agent.conf "
            "en lugar de silenciar la regla {rule}",
        },
        "noise.rec.fix_at_source.fim_pattern": {
            "en": "If these changes are expected (log or data files, never binaries or configuration), add to the "
            "<syscheck> section of the shared agent.conf of the group of {hosts} (or of their ossec.conf): "
            "<ignore type=\"sregex\">{pattern}</ignore> (Wazuh simple regex: \\S+ is any file name and a plain '.' "
            "is a literal dot), or one exact <ignore> per file, such as <ignore>{first}</ignore>. Keep rule {rule}: "
            "never mute it",
            "es": "Si estos cambios son esperados (archivos de log o de datos, nunca binarios ni configuración), "
            "agregue a la sección <syscheck> del agent.conf compartido del grupo de {hosts} (o de su ossec.conf): "
            '<ignore type="sregex">{pattern}</ignore> (regex simple de Wazuh: \\S+ es cualquier nombre de archivo '
            "y un '.' es un punto literal), o un <ignore> exacto por archivo, como <ignore>{first}</ignore>. "
            "Mantenga la regla {rule}: nunca la silencie",
        },
        "noise.rec.fix_at_source.fim_paths": {
            "en": "If these changes are expected (log or data files, never binaries or configuration), add one "
            "exact <ignore> per file to the <syscheck> section of the shared agent.conf of the group of {hosts} "
            "(or of their ossec.conf): <ignore>{first}</ignore>, and likewise for {others}. Keep rule {rule}: never "
            "mute it",
            "es": "Si estos cambios son esperados (archivos de log o de datos, nunca binarios ni configuración), "
            "agregue un <ignore> exacto por archivo a la sección <syscheck> del agent.conf compartido del grupo de "
            "{hosts} (o de su ossec.conf): <ignore>{first}</ignore>, y lo mismo para {others}. Mantenga la regla "
            "{rule}: nunca la silencie",
        },
        "noise.rec.fix_at_source.fim_hosts": {
            "en": "No single path changes often enough to ignore it safely: review which files change on {hosts} "
            "(syscheck.path in these alerts) and ignore only the expected ones with <ignore> in the <syscheck> "
            "section of agent.conf. Do not mute rule {rule}",
            "es": "Ninguna ruta cambia con la frecuencia suficiente para ignorarla con seguridad: revise qué "
            "archivos cambian en {hosts} (syscheck.path en estas alertas) e ignore solo los esperados con <ignore> "
            "en la sección <syscheck> de agent.conf. No silencie la regla {rule}",
        },
        "noise.rec.fix_at_source.check": {
            "en": "Fix the failing check or the host configuration behind {scope} instead of muting rule {rule}",
            "es": "Corrija el chequeo fallido o la configuración del equipo detrás de {scope} en lugar de "
            "silenciar la regla {rule}",
        },
        "noise.rec.fix_at_source.exposure": {
            "en": "Restrict the exposure of the service behind {scope}: its alerts come from public addresses such "
            "as {sources}. Block or rate-limit them at the perimeter, or close the port, instead of muting rule "
            "{rule}",
            "es": "Restrinja la exposición del servicio detrás de {scope}: sus alertas provienen de direcciones "
            "públicas como {sources}. Bloquéelas o limítelas en el perímetro, o cierre el puerto, en lugar de "
            "silenciar la regla {rule}",
        },
        "noise.rec.fix_at_source.exposure_unknown": {
            "en": "Restrict the exposure of the service behind {scope}: its alerts come from public addresses. "
            "Block or rate-limit them at the perimeter, or close the port, instead of muting rule {rule}",
            "es": "Restrinja la exposición del servicio detrás de {scope}: sus alertas provienen de direcciones "
            "públicas. Bloquéelas o limítelas en el perímetro, o cierre el puerto, en lugar de silenciar la regla "
            "{rule}",
        },
        "noise.rec.fix_at_source.exposure_ip": {
            "en": "Restrict exposure: block or rate-limit {sources} at the perimeter, or close the exposed service, "
            "instead of muting rule {rule}",
            "es": "Restrinja la exposición: bloquee o limite {sources} en el perímetro, o cierre el servicio "
            "expuesto, en lugar de silenciar la regla {rule}",
        },
        "noise.rec.fix_at_source.exposure_ip_unknown": {
            "en": "Restrict exposure: block or rate-limit the public sources at the perimeter, or close the exposed "
            "service, instead of muting rule {rule}",
            "es": "Restrinja la exposición: bloquee o limite los orígenes públicos en el perímetro, o cierre el "
            "servicio expuesto, en lugar de silenciar la regla {rule}",
        },
        "noise.rec.fix_at_source.exposure_relay": {
            "en": "Restrict exposure: the alerts reported by {scope} come from public addresses such as {sources}; "
            "block or rate-limit them at the perimeter, or close the exposed service, instead of muting rule "
            "{rule}. Never block or filter {device} itself: it is the device (or log relay) that reports the "
            "traffic, not the attacker",
            "es": "Restrinja la exposición: las alertas que informa {scope} provienen de direcciones públicas como "
            "{sources}; bloquéelas o limítelas en el perímetro, o cierre el servicio expuesto, en lugar de "
            "silenciar la regla {rule}. Nunca bloquee ni filtre {device}: es el dispositivo (o el relé de logs) que "
            "informa el tráfico, no el atacante",
        },
        "noise.rec.fix_at_source.exposure_relay_unknown": {
            "en": "Restrict exposure: the alerts reported by {scope} come from public addresses; block or rate-limit "
            "them at the perimeter, or close the exposed service, instead of muting rule {rule}. Never block or "
            "filter {device} itself: it is the device (or log relay) that reports the traffic, not the attacker",
            "es": "Restrinja la exposición: las alertas que informa {scope} provienen de direcciones públicas; "
            "bloquéelas o limítelas en el perímetro, o cierre el servicio expuesto, en lugar de silenciar la regla "
            "{rule}. Nunca bloquee ni filtre {device}: es el dispositivo (o el relé de logs) que informa el tráfico, "
            "no el atacante",
        },
        "noise.rec.aggregate": {
            "en": "Replace per-event alerts for {scope} with a frequency/timeframe rule (one alert per burst) "
            "instead of muting rule {rule}",
            "es": "Reemplace las alertas por evento de {scope} por una regla con frequency/timeframe (una alerta "
            "por ráfaga) en lugar de silenciar la regla {rule}",
        },
        "noise.rec.aggregate.firewall": {
            "en": "The firewall already blocked these connections. Alert once per source instead of once per "
            "packet: rely on (or tune) a frequency rule on rule {rule} (if_matched_sid with same_srcip, like "
            "Wazuh's stock rule for multiple drops from the same source), or stop forwarding deny logs from this "
            "device if nobody uses them. Never block or filter {device} itself: it is the firewall (the log source), "
            "not the attacker",
            "es": "El firewall ya bloqueó estas conexiones. Alerte una vez por origen en lugar de una vez por "
            "paquete: use (o ajuste) una regla con frequency sobre la regla {rule} (if_matched_sid con same_srcip, "
            "como la regla de fábrica de Wazuh para varios descartes desde el mismo origen), o deje de reenviar "
            "los logs de denegaciones de este dispositivo si nadie los usa. Nunca bloquee ni filtre {device}: es el "
            "firewall (la fuente de logs), no el atacante",
        },
        "noise.rec.do_not_tune_tp": {
            "en": "Handle {scope} as an incident: investigate and respond (contain the source, reset the affected "
            "credentials). Keep rule {rule} exactly as it is: its alerts caught real attacks",
            "es": "Trate {scope} como un incidente: investigue y responda (contenga el origen, restablezca las "
            "credenciales afectadas). Mantenga la regla {rule} tal como está: sus alertas detectaron ataques "
            "reales",
        },
        "noise.rec.do_not_tune_level": {
            "en": "Keep rule {rule} as it is. If it fires this often, find out why (a misconfigured system, a "
            "scanner, or an attack in progress) and fix the cause: high-severity rules are out of scope for tuning",
            "es": "Mantenga la regla {rule} tal como está. Si se dispara con tanta frecuencia, averigüe por qué (un "
            "sistema mal configurado, un escáner o un ataque en curso) y corrija la causa: las reglas de severidad "
            "alta quedan fuera del alcance del ajuste",
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
