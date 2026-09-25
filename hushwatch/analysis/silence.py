"""Silence engine: calibrated detection of sources, agents, channels and heartbeat rules that went quiet (§6.2).

The design goal is *not to become alert fatigue* (a calibrated false-alarm rate) while *never showing a false
green*. For every key of the :class:`~hushwatch.analysis.cube.CubeCollector`:

1. **Reference time.** Evaluation ends at ``now - ingest_lag`` (late data is excluded). Events stamped in the
   future (clock skew) cannot hide a silence: the last bucket at or before ``now`` is used instead.
2. **Baseline** ``[end - baseline, end - window)`` in tenant-local time (zoneinfo, DST-safe), calendar days
   excluded everywhere (baseline, gaps, windows). Keys with less than ``min_history_days`` of history are
   ``learning`` (grey, never OK). A key already silent for longer than ``window`` gets a *frozen* baseline that
   ends when it went quiet, so an ongoing outage is never learned as normal.
3. **Model.** ``mu(t) = scale × shape(how(t)) / 24``: ``shape`` is the key's hour-of-week profile when the
   baseline has ≥ 21 days, otherwise an hour-of-day profile times a day-of-week factor (so a 14-day baseline does
   not flag every weekend); a weekday factor is learnt from ~2 days, so its deviation from the key's own
   weekday/weekend split is shrunk. The profile is shrunk toward the peer profile of its level with weight
   ``m / (n + m)``, ``m = 48``; one-off spike days (> 3× the median day, not repeated on that weekday) are
   winsorized first. With < 21 days a second, per-slot hour-of-week model (the separable rate as a one-event gamma
   prior) catches weekly batch jobs the separable profile misreads. ``scale`` is the 10% trimmed mean of
   (deseasonalised) daily totals. Counts are negative binomial with size ``k`` from the method of moments on
   baseline residuals (degrees-of-freedom corrected), clipped to [0.5, 1000] and pooled over the level for sparse
   keys. Day-to-day swings: the larger of the method-of-moments and a robust log-scale (MAD) estimate, inflated for
   the profile having been fitted to those same few days (``(1 + p/n) / (1 - p/n)``), give ``k_day`` and a lognormal
   ``day_sigma``; the uncertainty of ``scale`` itself (``n_eff``) widens every test.
4. **SILENT** (also gaps and rule-dark): ``P0 = Π_b (1 + mu_b/k)^-k`` over the hour buckets since the last event
   (partial buckets weighted), integrated per local day over the lognormal day multiplier (Gauss-Hermite). The ±1 h
   tolerance is the *largest* P0 over the profile shifted by −1/0/+1 h and over both models; the scale-uncertainty
   predictive ``(1 + Λ/n_eff)^-n_eff`` is a floor. Bursty sources (on/off applications, clustered alerts) keep
   quiet once quiet: a burstiness ``theta`` estimated by maximum likelihood from the key's own baseline lulls makes
   each hour of a gap cost ``theta`` times its NB cost. Keys that are not always-on (laptops, business-hours
   sources) get a day-level "day off" mixture: the first day off with a rate learnt from their history and an
   empirical-Bayes prior from their peers (same tier, weekend-active or not), further days off with the peers'
   day-off persistence curve (vacations). Critical keys use their own record only, and an agent the Wazuh API
   shows connected right now gets no day-off tolerance. Alarm when ``P0 < alpha_eff = alarm_budget /
   keys_evaluated`` (a zero budget is clamped to 1e-6, never "detection off").
5. **DROP**: window ``window`` grown by whole days until ``expected ≥ 20`` spread over ≥ 6 effective hours (max
   7 days; the unsmoothed profile, the smaller of both models, most conservative ±1 h alignment); NB lower tail
   with a size combining hourly, daily and scale uncertainty, mixed over "low days" for sources that skip days. The
   same test on the part since the maximum-likelihood change point (Bonferroni-corrected for the candidate points)
   catches a sharp drop hours earlier; alarm when ``p < alpha_eff`` AND the observed/expected ratio (whole window,
   or since the change point) is below ``drop_ratio``. A source that still trickles after the change point is a
   DROP even if its sparse gaps are also significant. **DECAY**: last 7 days vs an earlier reference (up to 28
   days), both medians and totals below 0.5 (per-weekday expectations), NB test with the reference's own
   day-to-day variability.
6. **Duty class** (always_on / business_hours / intermittent) and **monitorability**: ``t_min`` = hours of silence
   needed (median over start hours of the week, same day-level structure as the test) before ``P0 < alpha_eff``;
   critical keys with ``t_min`` above their SLA are ``unmonitorable`` (one finding per critical agent).
7. **Root cause grouping.** An agent anomaly carried by exactly one of its channels is that channel's; any other is
   a whole-host anomaly explaining its channels. ≥ ``global_fraction`` of the agents (always-on first, or all with
   ≥ 5 of them) with whole-host SILENT or DROP beginning within 2 h, a silent tenant, or a tenant-wide drop no agent
   or log source accounts for → one ``pipeline.global_silence`` explaining every anomaly that began with it (an EPS
   limit is one finding, not one per agent). A log source is explained by the host findings that cover its deficit
   (≥ 70%) or by its only anomalous channel; with several anomalous channels it is itself the root cause (Sysmon
   lost on 40 hosts is one finding). Heartbeat rules (active on ≥ ``heartbeat_rule_days`` of days) go ``rule_dark``
   only while one of their sources (or, when unknown, the tenant) keeps sending; otherwise they are explained.
8. **Tampering**: a SILENT/DROP (including one inside a global outage) preceded by log clearing, audit-policy
   change, Sysmon/agent stop or auditd reconfiguration on the same agent in ``[start − 2 h, start + 10 min]``
   (a DROP change point is known to the hour: + 1 h) → ``silence.tampering`` (critical, T1070.001 / T1562.002 /
   T1562.001 and the precursor's own technique).

Silence measured on alerts-only data is *alert* silence: those findings get LOW/MEDIUM confidence and say so
(rule-level findings too: that a rule's sources are "alive" rests on other alerts).
"""

from __future__ import annotations

import bisect
import math
from array import array
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from typing import Any

from ..config import TenantConfig
from ..i18n import Entity, M, Message, register
from ..inventory import AgentInfo
from ..models import Confidence, DataBasis, Finding, Severity, fingerprint
from ..timeutil import UTC, humanize, iso
from . import stats
from .cube import LEVELS, PRECURSOR_CODES, CubeCollector, Precursor

__all__ = ["DUTY_CLASSES", "STATUSES", "SilenceResult", "analyze_silence"]

StatusKey = tuple[str, tuple[str, ...]]

STATUSES: tuple[str, ...] = (
    "ok",
    "silent",
    "drop",
    "decay",
    "rule_dark",
    "tampering",
    "explained",
    "learning",
    "unmonitorable",
    "not_evaluated",
)
DUTY_CLASSES: tuple[str, ...] = ("always_on", "business_hours", "intermittent", "unknown")

# ---- tuning constants (documented in the module docstring; not user configuration) -------------------------------
SHRINK_M = 48.0  # pseudo-events of the peer profile in the shape shrinkage
HOW_MIN_DAYS = 21  # hour-of-week profile only with >= 3 weeks of baseline
MIN_BASELINE_DAYS = 2  # full local days needed to fit a model at all
FIRST_SEEN_SLACK_H = 24  # a key first seen within this slack of the observable start counts as covered
PEER_MIN_EVENTS = 24  # keys with fewer baseline events do not shape the peer profile
SPARSE_EVENTS = 100  # keys with fewer baseline events use the pooled dispersion of their level
ELIGIBLE_DAY_EXPECTED = 3.0  # a day "should" have events when its own expected total is >= this
MIN_DROP_EXPECTED = 20.0
MIN_ALARM_BUDGET = 1e-6
MIN_DROP_SPREAD_H = 6.0  # the expected volume of a DROP window must be spread over >= this many "effective" hours
OFF_PRIOR_MIN, OFF_PRIOR_MAX = 2.0, 200.0  # empirical-Bayes strength of the peer off-day rate (pseudo-days)
MAX_DROP_WINDOW_H = 168
TAIL_H = 336  # hours of recent counts kept per key (drop window + calendar slack)
DECAY_RECENT_DAYS = 7
DECAY_MIN_RECENT_DAYS = 5
DECAY_MIN_REF_DAYS = 7
DECAY_SPAN_DAYS = 28  # reference for DECAY reaches up to this far back
DECAY_RATIO = 0.5
DECAY_MIN_REF_MEDIAN = 5.0
ATTRIBUTION_SHARE = 0.7  # a parent's deficit explained by its anomalous children -> parent explained
GLOBAL_WINDOW_S = 7200.0
GLOBAL_MIN_AGENTS = 3
GLOBAL_MIN_ANY_AGENTS = 5
PRECURSOR_BEFORE_S = 7200.0
PRECURSOR_AFTER_S = 600.0
MAX_LOOKBACK_DAYS = 400
MAX_GAP_H = 60 * 24
TMIN_HORIZON_H = 28 * 24
LOG_FLOOR = -700.0
MAX_SECTION_SOURCES = 200
MAX_RELATED = 200
MAX_EXPLAINED_EVIDENCE = 20
KEEPALIVE_FRESH_S = 1800.0
FUTURE_TOLERANCE_S = 300.0
SPIKE_DAY_FACTOR = 3.0  # a baseline day above this × the median day that does not recur weekly is winsorized
MIN_SPIKE_DAYS = 4  # active baseline days needed before spike days are judged
PERSIST_MIN_RUNS = 5  # informative quiet periods needed (after trimming) before burstiness is estimated
PERSIST_INFO = 0.5  # a quiet period is informative when the model expected at least this much in/after it
PERSIST_LR = 1.355  # half the 90% chi-square(1) quantile: the least correction the data support is used
THETA_MIN = 0.01
PRIOR_COMPAT_P = 0.01  # a key whose own off days are this unlikely under its peers' rate ignores that prior
DAY_VAR_MAX_INFLATION = 4.0
FAST_TAIL_MEAN = 200.0  # above these, the DROP tail uses the lognormal closed form (exact quadrature below)
FAST_TAIL_OBSERVED = 20.0
DOW_PRIOR_DAYS = 2.0  # pseudo-days behind a key's weekday/weekend split when shrinking its weekday factors
DAY_SIGMA_MIN_EXPECTED = 20.0  # days expected to carry fewer events say little about day-to-day swings
# Gauss-Hermite (physicists', 10 nodes, positive half): day multipliers D = exp(sqrt(2) sigma x - sigma^2 / 2)
_GH_NODES = (0.342901327223705, 1.036610829789514, 1.756683649299882, 2.532731674232790, 3.436159118837738)
_GH_WEIGHTS = (0.610862633735326, 0.240138611082315, 0.033874394455481, 0.001343645746781, 0.000007640432855)
STAY_PRIOR_RUNS = 2.0  # pseudo-runs behind each point of the day-off persistence curve
MAX_OFF_RUNS = 32  # most recent runs of days off kept per key
STAY_CURVE_DAYS = 14
ALT_PRIOR_EVENTS = 1.0  # strength of the separable profile as a prior for the per-slot hour-of-week model
TAMPER_BUCKET_S = 3600.0  # a DROP start is known to the hour: widen the precursor window by one bucket

_TIER_RANK = {"low": 0, "standard": 1, "critical": 2}
_SILENT_SEV = {"critical": Severity.CRITICAL, "standard": Severity.HIGH, "low": Severity.MEDIUM}
_DROP_SEV = {"critical": Severity.HIGH, "standard": Severity.MEDIUM, "low": Severity.LOW}
_DECAY_SEV = {"critical": Severity.MEDIUM, "standard": Severity.LOW, "low": Severity.LOW}
_STATUS_ORDER = {s: i for i, s in enumerate(("tampering", "silent", "drop", "rule_dark", "decay", "unmonitorable"))}
_ANOMALOUS = ("silent", "drop", "decay")
_ALERTS_ONLY = ("alerts", "indexer-alerts")
_ARCHIVES = ("archives", "indexer-archives")
_WIN_CHANNELS = frozenset(
    {"security", "system", "application", "setup", "forwardedevents", "windows powershell", "hardwareevents"}
)
_KIND_OF_STATUS = {
    "silent": "silence.silent",
    "drop": "silence.drop",
    "decay": "silence.decay",
    "rule_dark": "silence.rule_dark",
    "tampering": "silence.tampering",
}
TAMPERING_TECHNIQUES: tuple[str, ...] = ("T1070.001", "T1562.002", "T1562.001")


# ---- public result -----------------------------------------------------------------------------------------------


@dataclass(slots=True)
class SilenceResult:
    """Findings, the ``sections["silence"]`` dict (§2.2) and the final status of every cube key."""

    findings: list[Finding]
    section: dict[str, Any]
    statuses: dict[StatusKey, str]


# ---- internal records --------------------------------------------------------------------------------------------


@dataclass(slots=True)
class _KeyEval:
    level: str
    key: tuple[str, ...]
    first: float
    last: float  # effective last seen (never after "now")
    total: int
    tier: str = "standard"
    status: str = "learning"  # raw verdict of the statistical tests
    final: str = ""  # after hierarchy / grouping / tampering
    duty: str = "unknown"
    note: str = ""  # why a key is learning / not evaluated
    heartbeat: bool = False
    frozen: bool = False
    model: str = ""
    baseline_days: int = 0
    base_events: float = 0.0
    scale: float = 0.0
    k: float = stats.K_MAX
    k_day: float = stats.K_MAX
    day_sigma: float = 0.0  # robust sd of log(daily total / expected): whole-day swings (lognormal)
    n_eff: float = math.inf
    pi_off: float = 0.0
    stay: tuple[float, ...] = ()  # P(another day off | n days off so far), n = 1, 2, ... (vacations)
    pi_low: float = 0.0
    theta: float = 1.0  # burstiness: quiet periods last 1/theta times longer than independent hours predict
    rate: list[float] | None = None
    rate_p0: list[float] | None = None
    gap: float = 0.0
    expected_gap: float = 0.0
    log_p0: float = 0.0
    win_start: int = 0
    win_end: int = 0
    observed: float = 0.0
    expected: float = 0.0
    day_observed: float = 0.0
    day_expected: float = 0.0
    drop_p: float | None = None
    drop_ratio: float | None = None
    drop_start: float | None = None
    drop_segment: tuple[float, float] | None = None  # (observed, expected) since the change point
    decay_ratio: float | None = None
    decay_p: float | None = None
    decay_recent: float = 0.0
    decay_reference: float = 0.0
    decay_ref_days: int = 0
    decay_start: int = 0
    decay_days: int = DECAY_RECENT_DAYS  # recent days the DECAY test compared
    t_min: float | None = None
    q: float | None = None
    explained_by: _KeyEval | None = None
    explained_global: bool = False
    children: list[_KeyEval] = field(default_factory=list)
    alive_sources: list[_KeyEval] = field(default_factory=list)
    precursors: list[Precursor] = field(default_factory=list)
    fp: str = ""

    @property
    def evaluated(self) -> bool:
        return self.status not in ("learning", "not_evaluated")


@dataclass(slots=True)
class _P1:
    """Pass-1 aggregates of one key (kept only while its level is being evaluated)."""

    counts_c: array[float]  # baseline counts per hour-of-week slot
    counts_q: array[float]  # baseline squared counts per slot
    exposure: list[int]  # baseline hour buckets per slot (non-calendar)
    n: float
    base_days: list[tuple[int, float]]  # (clock day index, total) full non-calendar baseline days
    all_days: list[tuple[int, float]]  # full non-calendar days of the whole extraction (DECAY)
    tail: array[int]  # counts of the last hours before end_hour
    n_elig: int
    n_off: int
    n_low: int
    off_runs: tuple[tuple[int, bool], ...] = ()  # (eligible days off in a row, still running at the end)
    nz: bytes = b""  # 1 per baseline hour with events (calendar hours are 0): quiet-period structure
    i_base: int = 0  # clock index of the first baseline hour
    weekend: bool | None = None  # the key is active on weekends (peer group for the day-off prior); None: unknown


@dataclass(slots=True)
class _PeerAcc:
    how: list[float] = field(default_factory=lambda: [0.0] * 168)
    how_n: list[int] = field(default_factory=lambda: [0] * 168)
    hod: list[float] = field(default_factory=lambda: [0.0] * 24)
    dow: list[float] = field(default_factory=lambda: [0.0] * 7)
    keys: int = 0
    num: float = 0.0
    den: float = 0.0
    # (tier, weekend active or None for all) -> [(off, low, eligible)] and the runs of days off of the peers
    off: dict[tuple[str, bool | None], list[tuple[int, int, int]]] = field(default_factory=dict)
    runs: dict[tuple[str, bool | None], list[tuple[int, bool]]] = field(default_factory=dict)


@dataclass(slots=True)
class _Peers:
    how: list[float]
    hod: list[float]
    dow: list[float]
    pooled_k: float
    # (tier, active on weekends) -> (peer rate, prior strength in pseudo-days)
    off: dict[tuple[str, bool | None], tuple[float, float]]
    low: dict[tuple[str, bool | None], tuple[float, float]]
    stay: dict[tuple[str, bool | None], tuple[float, ...]]  # pooled P(another day off | n days off so far)


class _Clock:
    """Tenant-local structure of every UTC hour in the analysis range, shared by all keys."""

    def __init__(self, tz: Any, in_calendar: Callable[[date], bool], start_hour: int, end_hour: int) -> None:
        self.start = start_hour
        n = max(0, end_hour - start_hour)
        self.n = n
        self.slot: list[int] = [0] * n
        self.day: list[int] = [0] * n
        self.cal: list[bool] = [False] * n
        self.day_ord: list[int] = []
        self.day_first: list[int] = []
        self.day_last: list[int] = []
        self.day_dow: list[int] = []
        self.day_cal: list[bool] = []
        for i in range(n):
            local = datetime.fromtimestamp((start_hour + i) * 3600 + 1800, tz)
            ordinal = local.toordinal()
            if not self.day_ord or ordinal != self.day_ord[-1]:
                self.day_ord.append(ordinal)
                self.day_first.append(i)
                self.day_last.append(i)
                self.day_dow.append(local.weekday())
                self.day_cal.append(bool(in_calendar(date.fromordinal(ordinal))))
            else:
                self.day_last[-1] = i
            j = len(self.day_ord) - 1
            self.slot[i] = local.weekday() * 24 + local.hour
            self.day[i] = j
            self.cal[i] = self.day_cal[j]
        self.day_std = [
            self.day_last[j] - self.day_first[j] == 23
            and self.slot[self.day_first[j]] == self.day_dow[j] * 24
            and self.slot[self.day_last[j]] == self.day_dow[j] * 24 + 23
            for j in range(len(self.day_ord))
        ]
        self._exposure_cache: dict[tuple[int, int], list[int]] = {}

    def index(self, hour: int) -> int:
        return hour - self.start

    def exposure(self, i0: int, i1: int) -> list[int]:
        """Number of non-calendar hour buckets per hour-of-week slot in clock indices ``[i0, i1)``."""
        cache_key = (i0, i1)
        cached = self._exposure_cache.get(cache_key)
        if cached is None:
            cached = [0] * 168
            slot = self.slot
            cal = self.cal
            for i in range(max(0, i0), min(self.n, i1)):
                if not cal[i]:
                    cached[slot[i]] += 1
            self._exposure_cache[cache_key] = cached
        return cached

    def day_expected(self, rate: Sequence[float], day_sums: Sequence[float], j: int) -> float:
        if self.day_std[j]:
            return day_sums[self.day_dow[j]]
        slot = self.slot
        return math.fsum(rate[slot[i]] for i in range(self.day_first[j], self.day_last[j] + 1))


# ---- entry point -------------------------------------------------------------------------------------------------


def analyze_silence(
    cube: CubeCollector,
    *,
    tenant: TenantConfig,
    now: datetime,
    basis: DataBasis,
    agents: list[AgentInfo] | None = None,
) -> SilenceResult:
    """Evaluate every key of ``cube`` at reference time ``now`` and return findings, section and statuses.

    ``now`` is the analysis reference ("max event timestamp" for files, ``--now``, or wall clock); ``basis`` says
    what the input could see (alerts-only input lowers confidence); ``agents`` (Wazuh API inventory) enriches the
    evidence (keepalive vs. data) and flags agents that are no longer registered.
    """
    return _Engine(cube, tenant, now, basis, agents).run()


# ---- the engine --------------------------------------------------------------------------------------------------


class _Engine:
    def __init__(
        self,
        cube: CubeCollector,
        tenant: TenantConfig,
        now: datetime,
        basis: DataBasis,
        agents: list[AgentInfo] | None,
    ) -> None:
        self.cube = cube
        self.tenant = tenant
        self.cfg = tenant.silence
        self.basis = basis
        if now.tzinfo is None:
            now = now.replace(tzinfo=UTC)
        self.now_dt = now.astimezone(UTC)
        self.now = self.now_dt.timestamp()
        self.end = self.now - max(0.0, self.cfg.ingest_lag.total_seconds())
        self.end_hour = int(self.end // 3600)
        self.window_h = max(1, round(self.cfg.window.total_seconds() / 3600))
        self.base_len_h = max(24, round((self.cfg.baseline - self.cfg.window).total_seconds() / 3600))
        self.min_history_s = max(0.0, self.cfg.min_history_days * 86400.0)
        self.agents = agents
        self.inventory: dict[str, AgentInfo] = {}
        for info in agents or ():
            if info.name:
                self.inventory.setdefault(info.name.lower(), info)
        # agents the Wazuh API shows connected right now (keepalive within KEEPALIVE_FRESH_S of "now", never judged
        # against an old export): they are demonstrably not "taking the day off", so no day-off tolerance applies
        self.fresh_agents = {
            name
            for name, info in self.inventory.items()
            if info.status == "active"
            and (seen := _aware(info.last_keepalive)) is not None
            and abs(self.now - seen.timestamp()) <= KEEPALIVE_FRESH_S
        }
        self.profile = basis.profile
        self.alerts_only = basis.input_kind in _ALERTS_ONLY
        self.partial = bool(basis.partial_failures) or basis.sampled
        self.evals: dict[StatusKey, _KeyEval] = {}
        self.alpha = 1.0
        self.log_alpha = 0.0
        self.global_finding: Finding | None = None
        self.global_ev: _KeyEval | None = None
        self.global_window: tuple[float, float] | None = None
        self.global_agents: list[_KeyEval] = []
        self.global_total = 0
        tenant_first = cube.first_seen("tenant", (cube.tenant_name,))
        data_start = tenant_first if tenant_first is not None else self.end
        self.map_start = max(int(data_start // 3600), self.end_hour - MAX_LOOKBACK_DAYS * 24)
        self.obs_start = self.map_start
        self.clock = _Clock(tenant.tz, tenant.in_calendar, self.map_start, self.end_hour + 1)

    # ---- orchestration --------------------------------------------------------------------------------------

    def run(self) -> SilenceResult:
        levels: dict[str, list[tuple[_KeyEval, _P1]]] = {}
        for level in LEVELS:
            levels[level] = self._pass1_level(level)
        keys_evaluated = sum(1 for ev in self.evals.values() if ev.evaluated)
        # a zero/negative budget means "as strict as possible", never "detection off" (that would be a false green)
        budget = max(MIN_ALARM_BUDGET, self.cfg.alarm_budget if self.cfg.alarm_budget == self.cfg.alarm_budget else 0)
        self.alpha = min(0.5, budget / max(1, keys_evaluated))
        self.log_alpha = math.log(self.alpha)
        self._tiers()
        for level in LEVELS:
            items = levels.pop(level)
            peers = self._peers(items, level)
            for ev, p1 in items:
                self._fit_and_test(ev, p1, peers)
        self._q_values()
        self._resolve_hierarchy()
        self._resolve_rules()
        self._tampering()
        self._monitorability()
        findings = self._findings(keys_evaluated)
        section = self._section(keys_evaluated, findings)
        statuses = {k: (ev.final or ev.status) for k, ev in self.evals.items()}
        return SilenceResult(findings=findings, section=section, statuses=statuses)

    # ---- pass 1 ---------------------------------------------------------------------------------------------

    def _pass1_level(self, level: str) -> list[tuple[_KeyEval, _P1]]:
        out: list[tuple[_KeyEval, _P1]] = []
        for key, first, last, total in self.cube.iter_level(level):
            ev = _KeyEval(level=level, key=key, first=first, last=last, total=total)
            self.evals[(level, key)] = ev
            p1 = self._pass1(ev)
            if p1 is not None:
                out.append((ev, p1))
        return out

    def _effective_last(self, ev: _KeyEval) -> float | None:
        if ev.last <= self.now + FUTURE_TOLERANCE_S:
            return min(ev.last, self.end)
        # The latest event is in the future (clock skew): use the last bucket at or before "now" instead, so a
        # skewed event can never hide a silence.
        lo = max(self.map_start, self.end_hour - MAX_GAP_H)
        counts = self.cube.dense(ev.level, ev.key, lo, self.end_hour + 1)
        for idx in range(len(counts) - 1, -1, -1):
            if counts[idx]:
                return min(float((lo + idx + 1) * 3600 - 1), self.end)
        return None

    def _pass1(self, ev: _KeyEval) -> _P1 | None:
        clock = self.clock
        last = self._effective_last(ev)
        if last is None or ev.first > self.end:
            ev.status, ev.note = "learning", "no_data_before_now"
            return None
        ev.last = last
        first_h = int(ev.first // 3600)
        key_start = self.obs_start if first_h <= self.obs_start + FIRST_SEEN_SLACK_H else first_h
        key_start = max(key_start, self.map_start)
        if self.end - key_start * 3600.0 < self.min_history_s - 3600.0:
            ev.status, ev.note = "learning", "short_history"
            return None
        standard_end = self.end_hour - self.window_h
        last_h = int(ev.last // 3600)
        if last_h < standard_end:
            base_end = last_h  # frozen: never learn an ongoing outage as normal
            ev.frozen = True
        else:
            base_end = standard_end
        base_lo = max(key_start, base_end - self.base_len_h)
        ext_start = max(key_start, min(base_lo, self.end_hour - DECAY_SPAN_DAYS * 24))
        if base_end - base_lo < 24:
            ev.status, ev.note = "learning", "short_baseline"
            return None
        counts = self.cube.dense(ev.level, ev.key, ext_start, self.end_hour)
        i_ext = clock.index(ext_start)
        b_rel = base_lo - ext_start
        e_rel = base_end - ext_start
        cc = array("d", bytes(8 * 168))
        qq = array("d", bytes(8 * 168))
        slot = clock.slot
        days = clock.day
        cal = clock.cal
        base = counts[b_rel:e_rel]
        i_base = i_ext + b_rel
        if any(cal[i_base : i_base + len(base)]):
            base = [0 if cal[i_base + idx] else c for idx, c in enumerate(base)]
        active = len(base) - base.count(0)
        # daily totals per local day (C-level sums over each day's slice of the extraction)
        day_tot: dict[int, float] = {}
        if counts:
            j_first, j_last = days[i_ext], days[i_ext + len(counts) - 1]
            for j in range(j_first, j_last + 1):
                if clock.day_cal[j]:
                    continue
                lo = max(clock.day_first[j], i_ext) - i_ext
                hi = min(clock.day_last[j], i_ext + len(counts) - 1) - i_ext + 1
                day_tot[j] = float(sum(counts[lo:hi]))
        exposure = clock.exposure(clock.index(base_lo), clock.index(base_end))
        base_hours = sum(exposure)
        if base_hours == 0:
            ev.status, ev.note = "learning", "baseline_in_calendar"
            return None
        # full local days (all their hours inside the extraction), calendar days excluded
        i_key = clock.index(key_start)
        i_end = clock.index(self.end_hour)
        i_base_lo = clock.index(base_lo)
        i_base_end = clock.index(base_end)
        base_days: list[tuple[int, float]] = []
        all_days: list[tuple[int, float]] = []
        first_day = days[max(0, min(clock.n - 1, i_ext))]
        last_day = days[max(0, min(clock.n - 1, i_end - 1))]
        for j in range(first_day, last_day + 1):
            if (
                clock.day_cal[j]
                or clock.day_first[j] < max(i_ext, i_key)
                or clock.day_last[j] >= i_end
                or clock.day_last[j] - clock.day_first[j] < 22  # a partial day at the edge of the data
            ):
                continue
            total = day_tot.get(j, 0.0)
            all_days.append((j, total))
            if clock.day_first[j] >= i_base_lo and clock.day_last[j] < i_base_end:
                base_days.append((j, total))
        # hour-of-week sums; one-off spike days (a burst, a backlog flush) are winsorized so a single heavy day
        # cannot teach the profile that every such weekday is heavy (next week's normal day would read as a DROP)
        spikes = _spike_factors(base_days, clock.day_dow)
        if spikes:
            for idx, (c, s) in enumerate(zip(base, slot[i_base : i_base + len(base)], strict=True)):
                if c:
                    x = c * spikes.get(days[i_base + idx], 1.0)
                    cc[s] += x
                    qq[s] += x * x
        else:
            for c, s in zip(base, slot[i_base : i_base + len(base)], strict=True):
                if c:
                    cc[s] += c
                    qq[s] += float(c) * c
        n = math.fsum(cc)
        ev.base_events = n
        if len(base_days) < MIN_BASELINE_DAYS:
            ev.status, ev.note = "learning", "short_baseline"
            return None
        active_days = sum(1 for _, total in base_days if total > 0)
        if ev.level == "rule":
            ev.heartbeat = active_days / len(base_days) >= self.cfg.heartbeat_rule_days
            if not ev.heartbeat:
                ev.status, ev.note = "not_evaluated", "not_heartbeat"
                return None
        if n <= 0:
            ev.status, ev.note = "not_evaluated", "no_baseline_events"
            return None
        # duty class
        hod_business = math.fsum(cc[s] for s in range(168) if 7 <= s % 24 < 19)
        if active / base_hours >= 0.9:
            ev.duty = "always_on"
        elif active_days / len(base_days) >= 0.5 and hod_business / n >= 0.7:
            ev.duty = "business_hours"
        else:
            ev.duty = "intermittent"
        # own raw per-slot rates -> expected daily totals -> eligible / off days (for the day-off mixture)
        raw = [cc[s] / exposure[s] if exposure[s] else 0.0 for s in range(168)]
        raw_day = [math.fsum(raw[d * 24 : d * 24 + 24]) for d in range(7)]
        # off / low days over all the history before the evaluation window (up to DECAY_SPAN_DAYS): more days give
        # the day-off prior a chance to tell a server that never skips a day from a laptop that happened not to
        n_elig = n_off = n_low = 0
        runs: list[tuple[int, bool]] = []
        run = 0
        for j, total in all_days:
            if clock.day_last[j] >= i_base_end:
                continue
            day_exp = clock.day_expected(raw, raw_day, j)
            if day_exp >= ELIGIBLE_DAY_EXPECTED:
                n_elig += 1
                if total <= 0:
                    n_off += 1
                    run += 1
                elif run:
                    runs.append((run, False))
                    run = 0
                if total < self.cfg.drop_ratio * day_exp:
                    n_low += 1
        if run:
            runs.append((run, True))
        ev.status = "ok"
        tail_len = min(len(counts), TAIL_H)
        tail = array("q", counts[len(counts) - tail_len :])
        weekday = [t for j, t in base_days if clock.day_dow[j] < 5]
        weekend = [t for j, t in base_days if clock.day_dow[j] >= 5]
        # weekend-active keys (servers) and weekday-only keys (workstations, office apps) learn day-off habits from
        # different peers; means, not medians, so a week of vacation in the baseline does not flip the flag
        weekend_active: bool | None = None  # unknown without both kinds of days in the baseline
        if weekday and weekend:
            weekend_active = math.fsum(weekend) / len(weekend) >= 0.1 * math.fsum(weekday) / len(weekday)
        return _P1(
            cc,
            qq,
            exposure,
            n,
            base_days,
            all_days,
            tail,
            n_elig,
            n_off,
            n_low,
            off_runs=tuple(runs[-MAX_OFF_RUNS:]),
            nz=bytes(1 if c else 0 for c in base),
            i_base=i_base,
            weekend=weekend_active,
        )

    def _tiers(self) -> None:
        tier_for = self.tenant.tier_for
        ls_tier: dict[str, str] = {}
        agent_tiers: list[str] = []
        for (level, key), ev in self.evals.items():
            if level in ("agent", "agent_log_source"):
                ev.tier = tier_for(key[0])
                if level == "agent_log_source":
                    ls_tier[key[1]] = _max_tier(ls_tier.get(key[1], "low"), ev.tier)
                else:
                    agent_tiers.append(ev.tier)
        for (level, key), ev in self.evals.items():
            if level == "log_source":
                ev.tier = ls_tier.get(key[0], "standard")
            elif level == "tenant":
                ev.tier = _max_tier_of(agent_tiers) if agent_tiers else "standard"
            elif level == "rule":
                pairs, _ = self.cube.rule_sources(key[0])
                tiers = [tier_for(agent) for agent, _ in pairs if agent]
                ev.tier = _max_tier_of(tiers) if tiers else "standard"

    # ---- peers ----------------------------------------------------------------------------------------------

    def _peers(self, items: list[tuple[_KeyEval, _P1]], level: str) -> _Peers:
        acc = _PeerAcc()
        for ev, p1 in items:
            cc, qq, ex = p1.counts_c, p1.counts_q, p1.exposure
            if p1.n >= PEER_MIN_EVENTS:
                rates = [cc[s] / ex[s] for s in range(168) if ex[s]]
                mean = math.fsum(rates) / len(rates) if rates else 0.0
                if mean > 0:
                    acc.keys += 1
                    for s in range(168):
                        if ex[s]:
                            acc.how[s] += cc[s] / ex[s] / mean
                            acc.how_n[s] += 1
                    hod, dow = _own_hod_dow(cc, ex)
                    for h in range(24):
                        acc.hod[h] += hod[h]
                    for d in range(7):
                        acc.dow[d] += dow[d]
            if p1.n >= SPARSE_EVENTS:
                num = den = 0.0
                for s in range(168):
                    e = ex[s]
                    if e >= 2:
                        r = cc[s] / e
                        num += e * r * r
                        den += (qq[s] - cc[s] * cc[s] / e) * e / (e - 1) - cc[s]
                acc.num += num
                acc.den += den
            if ev.status == "ok" and p1.n_elig:
                groups: tuple[bool | None, ...] = (None,) if p1.weekend is None else (p1.weekend, None)
                for weekend in groups:  # the (tier, None) group pools every key of the tier
                    acc.off.setdefault((ev.tier, weekend), []).append((p1.n_off, p1.n_low, p1.n_elig))
                    acc.runs.setdefault((ev.tier, weekend), []).extend(p1.off_runs)
        if acc.keys:
            how = [acc.how[s] / acc.how_n[s] if acc.how_n[s] else 0.0 for s in range(168)]
            hod = [v / acc.keys for v in acc.hod]
            dow = [v / acc.keys for v in acc.dow]
        else:
            how, hod, dow = [1.0] * 168, [1.0] * 24, [1.0] * 7
        pooled = stats.mom_size_from_sums(acc.num, acc.den) if acc.num > 0 else stats.K_MAX
        off = {key: _beta_prior([(o, e) for o, _, e in v]) for key, v in acc.off.items()}
        low = {key: _beta_prior([(lo, e) for _, lo, e in v]) for key, v in acc.off.items()}
        stay = {key: _stay_curve(acc.runs.get(key, []), off[key][0]) for key in acc.off}
        return _Peers(
            how=_normalize(how),
            hod=_normalize(hod),
            dow=_normalize(dow),
            pooled_k=pooled,
            off=off,
            low=low,
            stay=stay,
        )

    # ---- pass 2: model + tests ------------------------------------------------------------------------------

    def _fit_and_test(self, ev: _KeyEval, p1: _P1, peers: _Peers) -> None:
        clock = self.clock
        cc, qq, ex = p1.counts_c, p1.counts_q, p1.exposure
        n = p1.n
        w = n / (n + SHRINK_M)
        n_days = len(p1.base_days)
        ev.baseline_days = n_days
        w_dow = 1.0
        if n_days >= HOW_MIN_DAYS:
            ev.model = "hour_of_week"
            own = [cc[s] / ex[s] if ex[s] else math.nan for s in range(168)]
            defined = [v for v in own if v == v]
            mean = math.fsum(defined) / len(defined) if defined else 0.0
            shape_raw = [
                (w * (own[s] / mean) + (1 - w) * peers.how[s]) if (own[s] == own[s] and mean > 0) else peers.how[s]
                for s in range(168)
            ]
            p_shape = 168.0
        else:
            ev.model = "hour_of_day"
            hod_own, dow_own = _own_hod_dow(cc, ex)
            hod = [w * hod_own[h] + (1 - w) * peers.hod[h] for h in range(24)]
            # A weekday factor is a day-level quantity: its evidence is the number of such days (about two in a
            # two-week baseline), not the number of events. The key's own weekday/weekend split is kept, and each
            # day's deviation from it is shrunk accordingly (it is mostly noise), then the whole toward the peers.
            w_dow = (n_days / 7.0) / (n_days / 7.0 + DOW_PRIOR_DAYS)
            weekday_mean = math.fsum(dow_own[:5]) / 5.0
            weekend_mean = math.fsum(dow_own[5:]) / 2.0
            dow_key = [w_dow * dow_own[d] + (1 - w_dow) * (weekday_mean if d < 5 else weekend_mean) for d in range(7)]
            dow = [w * dow_key[d] + (1 - w) * peers.dow[d] for d in range(7)]
            shape_raw = [dow[s // 24] * hod[s % 24] for s in range(168)]
            p_shape = 31.0
        # Two views of the same profile: smoothed ±1 h (DROP, DECAY, t_min, scale) and unsmoothed for P0, where the
        # ±1 h robustness comes from maximising P0 over ±1 h shifts instead (smoothing a sharp spike and then
        # shifting it would still expect events an hour away from where a UTC-scheduled job moved after DST).
        shape_p0 = _normalize(shape_raw)
        shape = _normalize(stats.smooth_circular(shape_raw))
        day_shape = [math.fsum(shape[d * 24 : d * 24 + 24]) / 24.0 for d in range(7)]
        # scale: trimmed mean of deseasonalised daily totals (days the profile says are nearly empty are skipped)
        deseason = []
        shape_day_sums = [v * 24.0 for v in day_shape]
        for j, total in p1.base_days:
            f = clock.day_expected(shape, shape_day_sums, j) / 24.0
            if f >= 0.25:
                deseason.append(total / f)
        if not deseason:
            deseason = [total for _, total in p1.base_days]
        scale = stats.trimmed_mean(deseason, 0.1)
        ev.scale = scale
        if scale <= 0:
            ev.status, ev.note = "not_evaluated", "no_baseline_events"
            return
        rate = [scale / 24.0 * v for v in shape]
        rate_p0 = [scale / 24.0 * v for v in shape_p0]
        rate_alt: list[float] | None = None
        rate_low = rate_p0
        if ev.model == "hour_of_day":
            # The separable hour × weekday profile cannot represent a weekly batch (a Sunday 03:00 job makes every
            # 03:00 and every Sunday hour "expected"). A second, hour-of-week model keeps the key's own counts per
            # slot with the separable rate as a weak gamma prior (one pseudo-event): SILENT uses whichever model
            # expects less (the larger P0) and DROP the smaller expectation per hour, so a weekly pattern the
            # separable model misreads never raises an alarm on its own.
            a0 = ALT_PRIOR_EVENTS
            alt = [(cc[s] + a0) / (ex[s] + a0 / rate_p0[s]) if ex[s] and rate_p0[s] > 0 else 0.0 for s in range(168)]
            if math.fsum(alt) > 0:
                rate_alt = [scale / 24.0 * v for v in _normalize(alt)]
                rate_low = [min(a, b) for a, b in zip(rate_p0, rate_alt, strict=True)]
        day_sums = [math.fsum(rate[d * 24 : d * 24 + 24]) for d in range(7)]
        # hourly dispersion from the residuals of the profile P0 uses (degrees-of-freedom corrected); pooled for
        # sparse keys
        if n >= SPARSE_EVENTS:
            n_buckets = float(sum(ex))
            num = math.fsum(ex[s] * rate_p0[s] * rate_p0[s] for s in range(168))
            resid = math.fsum(qq[s] - 2.0 * rate_p0[s] * cc[s] + ex[s] * rate_p0[s] * rate_p0[s] for s in range(168))
            dof = n_buckets / max(1.0, n_buckets - (1.0 + w * p_shape))
            ev.k = stats.mom_size_from_sums(num, resid * dof - n)
        else:
            ev.k = peers.pooled_k
        # day-level dispersion (whole-day swings the hourly model cannot see) and scale uncertainty
        exp_days = [(clock.day_expected(rate, day_sums, j), total) for j, total in p1.base_days]
        num_d = math.fsum(e * e for e, _ in exp_days)
        den_d = math.fsum((t - e) * (t - e) - t for e, t in exp_days)
        # Predictive day-level variance. The residuals are measured against a profile fitted to these same days: the
        # scale and (with weights w, w_dow) weekday factors, each learnt from only ~2 days in a two-week baseline, which
        # absorb part of the day-to-day swings and are themselves uncertain for the next day. Both effects are undone
        # with the (1 + p/n) / (1 - p/n) factor, p = 1 + w (1 + 5 w_dow) effective parameters over n days.
        p_day = 1.0 + w * (1.0 + 5.0 * w_dow)
        inflate = min(DAY_VAR_MAX_INFLATION, (1.0 + p_day / n_days) / max(0.25, 1.0 - p_day / n_days))
        # Day-to-day spread on the log scale (winsorized, so one spike or one near-empty day does not dominate; days
        # that fall far below expectation are the low-day mixture's business); the method of moments only when too
        # few days carry enough events for a log-scale estimate.
        log_sigma = _day_log_sigma(exp_days)
        cv2 = math.expm1(log_sigma**2) if log_sigma > 0 else 1.0 / stats.mom_size_from_sums(num_d, den_d)
        inv_day = cv2 * inflate
        ev.day_sigma = math.sqrt(math.log1p(cv2 * inflate))
        ev.k_day = stats.clip(1.0 / max(inv_day, 1.0 / stats.K_MAX), stats.K_MIN, stats.K_MAX)
        ev.n_eff = n_days / (1.0 / scale + 1.0 / ev.k_day)
        powered_on = ev.level in ("agent", "agent_log_source") and ev.key[0].lower() in self.fresh_agents
        if ev.duty != "always_on" and not powered_on:
            # sources that skip whole days (laptops, desktops...) learn how often from their history and peers;
            # always-on sources never get this tolerance, so their outages stay detectable within hours
            group = (ev.tier, p1.weekend)
            ev.pi_off = _day_rate(p1.n_off, p1.n_elig, ev.tier, peers.off.get(group))
            ev.pi_low = _day_rate(p1.n_low, p1.n_elig, ev.tier, peers.low.get(group))
            if ev.pi_off > 0:
                # days off come in runs (sick days, vacations): how likely one more day off is after n of them,
                # from the peers' runs (critical keys: their own record only, as for the day-off rate). Trade-off: a
                # standard-tier weekday-only source that dies over a weekend is reported once this tolerance is used
                # up (a connected agent per the Wazuh API gets none; critical keys rely on their own record).
                if ev.tier == "critical":
                    ev.stay = _stay_curve(list(p1.off_runs), ev.pi_off)[:1]
                else:
                    ev.stay = peers.stay.get(group, ())
        ev.theta = _persistence(p1, rate_p0, ev.k, self.clock, ev.pi_off > 0.0)
        ev.rate = rate
        ev.rate_p0 = rate_p0
        occ = n_days * 3.0 / (7.0 if ev.model == "hour_of_week" else 1.0)
        self._test_silent(ev, occ, rate_alt)
        if ev.level != "rule":
            self._test_drop(ev, p1, rate_low)
            if ev.status == "ok" and not ev.frozen:
                self._test_decay(ev, p1)
        ev.rate_p0 = None
        if ev.status == "ok" and not self._needs_rate(ev):
            ev.rate = None  # free memory; anomalous and critical keys keep their model

    def _needs_rate(self, ev: _KeyEval) -> bool:
        return ev.status in _ANOMALOUS or (ev.tier == "critical" and ev.level in ("agent", "agent_log_source"))

    def _test_silent(self, ev: _KeyEval, occ: float, rate_alt: Sequence[float] | None = None) -> None:
        rate = ev.rate_p0
        assert rate is not None
        start = max(ev.last, self.end - MAX_GAP_H * 3600.0)
        ev.gap = max(0.0, self.end - ev.last)
        if self.end <= start:
            ev.log_p0 = 0.0
            ev.expected_gap = 0.0
            return
        best = -math.inf
        for model in (rate, rate_alt):
            if model is None:
                continue
            for shift in (0, -1, 1):
                log_nb, lam = self._log_p0_gap(
                    model, ev.k, ev.pi_off, start, self.end, shift, ev.stay, ev.day_sigma, ev.theta
                )
                if shift == 0 and model is rate:
                    ev.expected_gap = lam
                # scale uncertainty; a bursty source (theta < 1) has proportionally fewer "independent" events
                eff = lam * ev.theta
                n_used = min(ev.n_eff, max(1.0, lam * occ))
                pred = -n_used * math.log1p(eff / n_used) if eff > 0 and not math.isinf(n_used) else -eff
                best = max(best, log_nb, pred)
        ev.log_p0 = min(0.0, best)
        if ev.log_p0 < self.log_alpha:
            ev.status = "silent"

    def _log_p0_gap(
        self,
        rate: Sequence[float],
        k: float,
        pi_off: float,
        start: float,
        stop: float,
        shift: int,
        stay: Sequence[float] = (),
        day_sigma: float = 0.0,
        theta: float = 1.0,
    ) -> tuple[float, float]:
        """``(log P0, expected events)`` of the gap ``[start, stop)``.

        With a day-off rate ``pi_off`` every local day after the first is a mixture: the key took the day off, or it
        was on and sent nothing. Days off come in runs (vacations, a laptop left in a drawer): the first substantial
        day of the gap is off with probability ``pi_off``, the next ones with ``max(pi_off, stay[n - 1])`` after ``n``
        days off (the last value repeats). A key whose daily volume swings (``day_sigma``, lognormal) is integrated over
        its day multiplier per local day: a quiet gap on a slow day is less surprising than on an average one. Bursty
        keys (``theta`` < 1, see :func:`_persistence`) pay ``theta`` times each hour's cost, given the day multiplier.
        """
        clock = self.clock
        slots, days, cal = clock.slot, clock.day, clock.cal
        base = clock.start
        h0 = int(start // 3600)
        h1 = min(int(stop // 3600), base + clock.n - 1)
        if h0 < base:
            h0 = base
            start = float(base * 3600)
        last_day = days[h0 - base] if 0 <= h0 - base < clock.n else -1
        probs = [min(0.999, max(pi_off, q)) for q in stay]
        mults: list[float] = []
        log_w: list[float] = []
        if day_sigma >= 0.05:
            for x, w in zip(_GH_NODES, _GH_WEIGHTS, strict=True):
                for sign in (-1.0, 1.0):
                    mults.append(math.exp(sign * math.sqrt(2.0) * day_sigma * x - day_sigma * day_sigma / 2.0))
                    log_w.append(math.log(w / math.sqrt(math.pi)))
        node_acc = [0.0] * len(mults)
        total = 0.0
        lam = 0.0
        acc = 0.0
        lam_day = 0.0
        days_off = 0  # substantial days of this gap so far (all of them were necessarily off)
        cur = -1
        floor_hit = False

        def close_day() -> float:
            nonlocal days_off
            day = acc
            if mults:  # E_D[P0 of the day's hours | D], D ~ lognormal day multiplier (Gauss-Hermite)
                day = -math.inf
                for lw, a in zip(log_w, node_acc, strict=True):
                    day = stats.logaddexp(day, lw + a)
                day = min(0.0, max(day, acc))
            if pi_off <= 0 or cur == last_day:
                return day
            q = probs[min(days_off, len(probs)) - 1] if days_off and probs else pi_off
            if lam_day >= ELIGIBLE_DAY_EXPECTED:
                days_off += 1
            return stats.logaddexp(math.log(q), math.log1p(-q) + day) if q < 1.0 else 0.0

        for h in range(h0, h1 + 1):
            lo = start if h == h0 else h * 3600.0
            hi = min(stop, h * 3600.0 + 3600.0)
            if hi <= lo:
                continue
            i = h - base
            if cal[i]:
                continue
            mu = rate[(slots[i] - shift) % 168] * ((hi - lo) / 3600.0)
            if mu <= 0.0:
                continue
            lam += mu
            if floor_hit:
                continue
            d = days[i]
            if d != cur:
                if cur >= 0:
                    total += close_day()
                    if total < LOG_FLOOR:
                        floor_hit = True
                        continue
                cur = d
                acc = 0.0
                lam_day = 0.0
                node_acc = [0.0] * len(mults)
            acc -= theta * k * math.log1p(mu / k)
            lam_day += mu
            for idx, m in enumerate(mults):
                node_acc[idx] -= theta * k * math.log1p(mu * m / k)
        if not floor_hit and cur >= 0:
            total += close_day()
        return max(total, LOG_FLOOR) if floor_hit else total, lam

    def _test_drop(self, ev: _KeyEval, p1: _P1, rate: list[float]) -> None:
        clock = self.clock
        tail = p1.tail
        tail_start = self.end_hour - len(tail)
        # expected per hour: the unsmoothed profile, taking the most conservative of the ±1 h alignments at the end
        # (smoothing would spill a business-hours edge into hours that are always empty)
        observed = 0.0
        sums = [0.0, 0.0, 0.0]
        sq = 0.0
        hours = 0
        mus: list[float] = []
        obs: list[float] = []
        slots: list[int] = []
        day_of: list[int] = []
        first_hour = self.end_hour
        for idx in range(len(tail) - 1, -1, -1):
            h = tail_start + idx
            i = h - clock.start
            if i < 0 or clock.cal[i]:
                continue
            s = clock.slot[i]
            mu = rate[s]
            c = float(tail[idx])
            observed += c
            sums[0] += mu
            sums[1] += rate[(s + 1) % 168]
            sums[2] += rate[(s - 1) % 168]
            sq += mu * mu
            mus.append(mu)
            obs.append(c)
            slots.append(s)
            day_of.append(clock.day[i])
            hours += 1
            first_hour = h
            if hours == self.window_h:
                ev.day_observed, ev.day_expected = observed, sums[0]
            if (
                hours >= self.window_h
                and hours % 24 == self.window_h % 24
                and (
                    (sums[0] >= MIN_DROP_EXPECTED and sq > 0 and sums[0] * sums[0] / sq >= MIN_DROP_SPREAD_H)
                    or hours >= MAX_DROP_WINDOW_H
                )
            ):
                break
        shift = min(range(3), key=lambda j: sums[j])
        if shift:
            step = 1 if shift == 1 else -1
            mus = [rate[(s + step) % 168] for s in slots]
        expected = sums[shift]
        day_expected: dict[int, float] = {}
        for mu, day in zip(mus, day_of, strict=True):
            day_expected[day] = day_expected.get(day, 0.0) + mu
        if hours < self.window_h:
            ev.day_observed, ev.day_expected = observed, sums[0]
        ev.observed, ev.expected = observed, expected
        ev.win_start, ev.win_end = first_hour, self.end_hour
        if expected < MIN_DROP_EXPECTED or hours == 0:
            return
        # maximum-likelihood change point of the window: when the drop began, and how deep it is since then
        fwd_mus = mus[::-1]
        fwd_obs = obs[::-1]
        best_i = _drop_change_point(fwd_mus, fwd_obs)
        seg_slots = slots[::-1][best_i:]
        seg_step = min((0, 1, -1), key=lambda j: math.fsum(rate[(s + j) % 168] for s in seg_slots))
        seg_mus = [rate[(s + seg_step) % 168] for s in seg_slots]  # the most conservative ±1 h alignment again
        seg_expected = math.fsum(seg_mus)
        seg_observed = math.fsum(fwd_obs[best_i:])
        onset = float((first_hour + self._offset_non_calendar(first_hour, best_i)) * 3600)
        # A source that has sent nothing for most of the window, or since shortly after the change point, is SILENT;
        # one that still trickles is a DROP even when its (now sparse) inter-event gaps are also significant.
        quiet_since_change = ev.gap >= 0.5 * max(0.0, self.end - onset)
        if ev.status == "silent" and (
            observed <= 0 or ev.gap >= hours * 1800.0 or seg_observed <= 0 or quiet_since_change
        ):
            if observed > 0 and seg_observed < seg_expected:
                ev.drop_start = onset  # it dwindled before going quiet: the onset groups it with its peers
            return
        ratio = observed / expected
        ev.drop_ratio = ratio
        # Effect size: the whole window, or the part since the change point when that part alone carries enough
        # expected volume and the source still trickles in it (a sharp 80% drop 6 hours ago is a DROP now, not after
        # most of the window has elapsed; an empty stretch is a gap, the SILENT test's business, and one followed by
        # events in the current hour is a lull that already ended).
        use_segment = best_i > 0 and seg_expected >= MIN_DROP_EXPECTED and seg_observed > 0
        effect = ratio
        if use_segment:
            effect = min(effect, seg_observed / seg_expected)
        if effect >= self.cfg.drop_ratio:
            return
        pi_low = max(ev.pi_off, ev.pi_low)
        k_hour = stats.matched_size(mus, ev.k)
        days = max(1.0, hours / 24.0)
        if ev.day_sigma >= 0.05:
            # day swings as a lognormal multiplier of the window total (averaged over the window's days)
            sigma = math.sqrt(math.log1p(math.expm1(ev.day_sigma**2) / days))
            size = stats.combine_sizes(k_hour, ev.n_eff)
        else:
            sigma = 0.0
            size = stats.combine_sizes(k_hour, ev.k_day * days, ev.n_eff)
        log_p = self._drop_logcdf(observed, expected, size, pi_low, day_expected, sigma, ev.baseline_days - 1.0)
        if use_segment:
            # the same NB tail on the part since the change point, Bonferroni-corrected for the candidate change
            # points: a sharp drop (audit policy switched off at 14:40) is significant hours before the whole window.
            # Hours of a bursty source are not independent: its multi-hour sums vary theta^-1 times more.
            seg_days: dict[int, float] = {}
            for mu, day in zip(seg_mus, day_of[::-1][best_i:], strict=True):
                seg_days[day] = seg_days.get(day, 0.0) + mu
            seg_hour = stats.matched_size(seg_mus, ev.k) * ev.theta
            seg_days_n = max(1.0, len(seg_mus) / 24.0)
            if ev.day_sigma >= 0.05:
                seg_sigma = math.sqrt(math.log1p(math.expm1(ev.day_sigma**2) / seg_days_n))
                seg_size = stats.combine_sizes(seg_hour, ev.n_eff)
            else:
                seg_sigma = 0.0
                seg_size = stats.combine_sizes(seg_hour, ev.k_day * seg_days_n, ev.n_eff)
            seg_log_p = self._drop_logcdf(
                seg_observed, seg_expected, seg_size, pi_low, seg_days, seg_sigma, ev.baseline_days - 1.0
            )
            log_p = min(log_p, min(0.0, seg_log_p + math.log(hours)))
        ev.drop_p = math.exp(log_p)
        if log_p < self.log_alpha:
            ev.status = "drop"
            ev.drop_start = onset
            ev.drop_segment = (seg_observed, seg_expected)

    @staticmethod
    def _drop_logcdf(
        observed: float,
        expected: float,
        size: float,
        pi_off: float,
        day_expected: dict[int, float],
        sigma: float = 0.0,
        dof: float = math.inf,
    ) -> float:
        """NB lower tail of the window total, mixed over "low days" for sources that skip (parts of) whole days.

        With ``D`` days carrying a substantial share of the expected volume and a low-day probability ``pi`` (a day
        below ``drop_ratio`` of its expectation, learned from the key's history and peers), the number of low days
        is Binomial(D, pi); ``j`` low days are conservatively treated as empty, leaving ``(D - j) / D`` of the
        expected volume. With ``sigma`` > 0 the day-to-day swing of the window total is a lognormal multiplier
        (Gauss-Hermite), as in the SILENT test, instead of being folded into ``size``: a gamma with the same variance
        has a far heavier lower tail and would hide real drops of sources whose volume swings. ``sigma`` itself was
        estimated from ``dof + 1`` days, so it is integrated over its chi-square sampling distribution (a Student-t
        on the log scale): at the tiny ``alpha_eff`` a plug-in variance would be badly overconfident.
        """

        def nb_tail(mean: float, k: float) -> float:
            if mean <= 0:
                return 0.0
            return (
                stats.nb_logcdf(observed, mean, k) if not math.isinf(k) else stats.poisson_logcdf(int(observed), mean)
            )

        scales = _sigma_mixture(sigma, dof) if sigma >= 0.05 else []

        def tail(mean: float, k: float) -> float:
            if not scales or mean <= 0:
                return nb_tail(mean, k)
            if mean >= FAST_TAIL_MEAN and observed >= FAST_TAIL_OBSERVED:
                # large counts: the NB part is itself close to lognormal, so the day multiplier and the count noise
                # combine in closed form (a normal CDF per variance scale) instead of 60 NB tail evaluations
                noise = math.log1p(1.0 / mean + (0.0 if math.isinf(k) else 1.0 / k))
                total = -math.inf
                for log_ws, sig in scales:
                    var = sig * sig + noise
                    z = (math.log((observed + 0.5) / mean) + var / 2.0) / math.sqrt(var)
                    total = stats.logaddexp(total, log_ws + _log_ndtr(z))
                return min(0.0, total)
            total = -math.inf
            for log_ws, sig in scales:
                for x, w in zip(_GH_NODES, _GH_WEIGHTS, strict=True):
                    for sign in (-1.0, 1.0):
                        mult = math.exp(sign * math.sqrt(2.0) * sig * x - sig * sig / 2.0)
                        total = stats.logaddexp(
                            total, log_ws + math.log(w / math.sqrt(math.pi)) + nb_tail(mean * mult, k)
                        )
            return min(0.0, total)

        base = tail(expected, size)
        if pi_off <= 0:
            return base
        floor = max(ELIGIBLE_DAY_EXPECTED, 0.1 * expected)
        n_days = sum(1 for value in day_expected.values() if value >= floor)
        if n_days == 0:
            return base
        log_pi = math.log(pi_off)
        log_on = math.log1p(-pi_off) if pi_off < 1 else -math.inf
        total = -math.inf
        for j in range(n_days + 1):
            share = (n_days - j) / n_days
            weight = math.log(math.comb(n_days, j)) + j * log_pi + ((n_days - j) * log_on if n_days > j else 0.0)
            total = stats.logaddexp(total, weight + tail(expected * share, size * share if share > 0 else size))
        return min(0.0, total)

    def _offset_non_calendar(self, first_hour: int, n: int) -> int:
        """Absolute hour offset of the ``n``-th non-calendar hour at or after ``first_hour``."""
        clock = self.clock
        seen = -1
        h = first_hour
        while h < self.end_hour:
            i = h - clock.start
            if 0 <= i < clock.n and not clock.cal[i]:
                seen += 1
                if seen == n:
                    return h - first_hour
            h += 1
        return max(0, self.end_hour - 1 - first_hour)

    def _test_decay(self, ev: _KeyEval, p1: _P1) -> None:
        """Sustained decline: the most recent days against an older reference (up to ``DECAY_SPAN_DAYS``).

        The spec's test compares the last 7 days with the reference, in medians AND in totals (a single noisy
        statistic does not fire: two days off in a week of a laptop collapse the median, not the total), ratio below
        ``DECAY_RATIO``. The last 2..6 days are also compared (a drop below ``drop_ratio``): once a partial drop has
        been in the rolling baseline for a day or two, the DROP test no longer sees it, while this reference predates
        it. Expectations are per weekday from the reference; the day-to-day variability is the reference's own
        (inflated for its weekday means being estimated from few days each) as a lognormal multiplier; sources that
        skip whole days get the same low-day mixture as DROP; the spans are Bonferroni-corrected.
        """
        days = p1.all_days
        if len(days) < DECAY_MIN_REF_DAYS + 2:
            return
        clock = self.clock
        last_day = days[-1][0]
        reference = [(j, t) for j, t in days if j <= last_day - DECAY_RECENT_DAYS]
        if len(reference) < DECAY_MIN_REF_DAYS:
            return
        med_ref = stats.median(t for _, t in reference)
        if med_ref < DECAY_MIN_REF_MEDIAN:
            return
        mean_ref = stats.trimmed_mean((t for _, t in reference), 0.1)
        if mean_ref <= 0:
            return
        # Expected day = the reference's mean for that weekday, shrunk toward its weekday/weekend mean (a weekday mean
        # of 2-3 days is mostly noise). The day-to-day variability comes from the reference itself (the baseline can
        # contain the very decline under test), with leave-one-out expectations: each reference day is predicted
        # without itself, which measures the prediction error directly (no small-sample bias, no inflation factor).
        dow_sum = [0.0] * 7
        dow_n = [0] * 7
        for j, total in reference:
            dow_sum[clock.day_dow[j]] += total
            dow_n[clock.day_dow[j]] += 1

        def expect(dow: int, leave_out: float | None = None) -> float:
            drop = 0 if leave_out is None else 1
            span = range(5) if dow < 5 else range(5, 7)
            n_group = sum(dow_n[d] for d in span) - drop
            sum_group = math.fsum(dow_sum[d] for d in span) - (leave_out or 0.0)
            n_all = len(reference) - drop
            base = sum_group / n_group if n_group > 0 else (math.fsum(dow_sum) - (leave_out or 0.0)) / max(1, n_all)
            n_day = dow_n[dow] - drop
            if n_day <= 0:
                return base
            weight = n_day / (n_day + DOW_PRIOR_DAYS)
            return weight * (dow_sum[dow] - (leave_out or 0.0)) / n_day + (1.0 - weight) * base

        ref_exp = [(expect(clock.day_dow[j], t), t) for j, t in reference]
        num = math.fsum(e * e for e, _ in ref_exp)
        den = math.fsum((t - e) * (t - e) - t for e, t in ref_exp)
        cv2 = max(1.0 / stats.mom_size_from_sums(num, den), math.expm1(_day_log_sigma(ref_exp) ** 2))
        pi_low = max(ev.pi_off, ev.pi_low)
        spans = range(2, DECAY_RECENT_DAYS + 1)
        best: tuple[float, int, float, float, float] | None = None  # (log p, span, ratio, recent median, observed)
        for span in spans:
            recent = [(j, t) for j, t in days if j > last_day - span]
            if len(recent) < (DECAY_MIN_RECENT_DAYS if span == DECAY_RECENT_DAYS else max(2, span - 2)):
                continue
            expected_by_day = {j: expect(clock.day_dow[j]) for j, _ in recent}
            observed = math.fsum(t for _, t in recent)
            expected = math.fsum(expected_by_day.values())
            if expected <= 0:
                continue
            ratio = observed / expected
            med_recent = stats.median(t for _, t in recent)
            if span == DECAY_RECENT_DAYS:
                ev.decay_ratio = ratio
                ev.decay_recent, ev.decay_reference, ev.decay_ref_days = med_recent, med_ref, len(reference)
                ev.decay_start = clock.day_first[recent[0][0]] + clock.start
                if ratio >= DECAY_RATIO or med_recent >= DECAY_RATIO * med_ref:
                    continue
            elif ratio >= self.cfg.drop_ratio:
                continue
            spread = math.fsum(e * e for e in expected_by_day.values()) * cv2
            sigma = math.sqrt(math.log1p(spread / (expected * expected))) if spread > 0 else 0.0
            size = ev.k * 24.0 * len(recent)  # hourly overdispersion of the recent total (the day part is sigma)
            log_p = self._drop_logcdf(observed, expected, size, pi_low, expected_by_day, sigma, len(reference) - 1.0)
            log_p = min(0.0, log_p + math.log(len(spans)))
            if best is None or log_p < best[0]:
                best = (log_p, span, ratio, med_recent, observed)
        if best is None:
            return
        log_p, span, ratio, med_recent, _ = best
        ev.decay_p = math.exp(log_p)
        if log_p < self.log_alpha:
            ev.status = "decay"
            ev.decay_days = span
            ev.decay_ratio = ratio
            ev.decay_recent = med_recent
            recent_first = min(j for j, _ in days if j > last_day - span)
            ev.decay_start = clock.day_first[recent_first] + clock.start

    def _q_values(self) -> None:
        tested = [ev for ev in self.evals.values() if ev.evaluated]
        pvals = [min(1.0, math.exp(ev.log_p0)) for ev in tested]
        for ev, q in zip(tested, stats.benjamini_hochberg(pvals), strict=True):
            ev.q = q

    # ---- hierarchy ------------------------------------------------------------------------------------------

    def _by_level(self, level: str) -> list[_KeyEval]:
        return [ev for (lv, _), ev in self.evals.items() if lv == level]

    def _explain(self, child: _KeyEval, parent: _KeyEval | None, *, by_global: bool = False) -> None:
        if child.final:
            return
        child.final = "explained"
        child.explained_by = parent
        child.explained_global = by_global
        if parent is not None:
            parent.children.append(child)

    def _deficit(self, ev: _KeyEval, start_hour: int, end_hour: int) -> float:
        if ev.rate is None or end_hour <= start_hour:
            return 0.0
        clock = self.clock
        counts = self.cube.dense(ev.level, ev.key, start_hour, end_hour)
        total = 0.0
        for idx, c in enumerate(counts):
            i = start_hour + idx - clock.start
            if 0 <= i < clock.n and not clock.cal[i]:
                total += ev.rate[clock.slot[i]] - c
        return total

    def _anomaly_window(self, ev: _KeyEval) -> tuple[int, int]:
        if ev.status == "decay":
            return ev.decay_start, self.end_hour
        if ev.status == "drop":
            return ev.win_start, ev.win_end
        return int(ev.last // 3600), self.end_hour

    def _attributable(self, parent: _KeyEval, kids: Sequence[_KeyEval]) -> bool:
        if not kids:
            return False
        ws, we = self._anomaly_window(parent)
        need = self._deficit(parent, ws, we)
        if need <= 0:
            return False
        have = math.fsum(max(0.0, self._deficit(kid, ws, we)) for kid in kids)
        return have >= ATTRIBUTION_SHARE * need

    def _start(self, ev: _KeyEval) -> float:
        """When the anomaly of ``ev`` began: last event (SILENT), change point (DROP), first recent day (DECAY)."""
        if ev.status == "silent":
            return ev.last
        if ev.status == "decay":
            return ev.decay_start * 3600.0
        return ev.drop_start if ev.drop_start is not None else ev.win_start * 3600.0

    def _onset(self, ev: _KeyEval) -> float:
        """Onset used to group anomalies: like :meth:`_start`, but a source that dwindled before going quiet counts
        from the change point of its decline."""
        if ev.status == "silent" and ev.drop_start is not None:
            return min(ev.last, ev.drop_start)
        return self._start(ev)

    def _silent_at(self, ev: _KeyEval, t: float) -> bool:
        """Whether the gap of ``ev`` was already a SILENT alarm at time ``t`` (same model, smoothed profile)."""
        if ev.rate is None or t <= ev.last:
            return False
        log_p0, _ = self._log_p0_gap(ev.rate, ev.k, ev.pi_off, ev.last, t, 0, ev.stay, ev.day_sigma, ev.theta)
        return log_p0 < self.log_alpha

    def _single_cause(self, parent: _KeyEval, anomalous: Sequence[_KeyEval]) -> _KeyEval | None:
        """The only anomalous child, when it alone carries >= ATTRIBUTION_SHARE of the parent's deficit."""
        if len(anomalous) != 1:
            return None
        kid = anomalous[0]
        return kid if self._attributable(parent, [kid]) else None

    def _resolve_hierarchy(self) -> None:
        """Root-cause grouping: one finding per root cause, everything it explains listed as related.

        * An agent anomaly carried by exactly one of its channels (that channel holds >= 70% of the deficit) is the
          channel's problem; any other anomalous agent is a whole-host problem (silent, or several channels down).
        * Whole-host anomalies (SILENT or DROP) of >= ``global_fraction`` of the agents starting within 2 h, a silent
          tenant, or a tenant-wide drop that no agent or log source accounts for → one ``pipeline.global_silence``
          explaining every anomaly that started with it (an EPS limit or an indexer problem is one finding, not 400).
        * A log source is explained by the agents whose own findings already cover its deficit, or by its only
          anomalous channel; when several hosts' channels are anomalous the log source itself is the root cause
          (Sysmon lost on 40 hosts is one finding, not 40).
        """
        agents = {ev.key[0]: ev for ev in self._by_level("agent")}
        sources = {ev.key[0]: ev for ev in self._by_level("log_source")}
        kids_of_agent: dict[str, list[_KeyEval]] = {}
        kids_of_source: dict[str, list[_KeyEval]] = {}
        for ev in self._by_level("agent_log_source"):
            kids_of_agent.setdefault(ev.key[0], []).append(ev)
            kids_of_source.setdefault(ev.key[1], []).append(ev)
        # 0. whole-host anomalies vs anomalies carried by one channel
        whole: list[_KeyEval] = []
        carried: dict[str, _KeyEval] = {}
        for name in sorted(agents):
            agent = agents[name]
            if agent.status not in _ANOMALOUS:
                continue
            kids = kids_of_agent.get(name, [])
            if agent.status != "silent":
                single = self._single_cause(agent, [kid for kid in kids if kid.status in _ANOMALOUS])
                if single is not None:
                    carried[name] = single  # reported as the channel (the more specific key)
                    if sum(1 for kid in kids if kid.evaluated) >= 2:
                        continue  # other channels are fine: a channel problem, not a host problem
            whole.append(agent)
        # 1. tenant
        tenant_ev = self.evals.get(("tenant", (self.cube.tenant_name,)))
        if tenant_ev is not None and tenant_ev.status in _ANOMALOUS:
            evaluated_agents = [a for a in agents.values() if a.evaluated]
            sudden = [a for a in whole if a.status in ("silent", "drop")]
            accounted = [*whole, *carried.values(), *(ls for ls in sources.values() if ls.status in _ANOMALOUS)]
            if tenant_ev.status == "silent":
                self._declare_global(tenant_ev, list(agents.values()))
            elif tenant_ev.status == "drop" and len(sudden) >= max(
                GLOBAL_MIN_AGENTS, self.cfg.global_fraction * len(evaluated_agents)
            ):
                self._declare_global(tenant_ev, sudden, total=len(evaluated_agents))
            elif self._attributable(tenant_ev, accounted):
                tenant_ev.final = "explained"
            elif tenant_ev.status == "drop":
                self._declare_global(tenant_ev, sudden, total=len(evaluated_agents))
            else:
                tenant_ev.final = tenant_ev.status
        # 2. correlated whole-host silences / drops across agents
        if self.global_ev is None:
            self._cluster(list(agents.values()), whole)
        if self.global_window is not None:
            lo, hi = self.global_window
            for ev in self.evals.values():
                if ev.final or ev.level in ("tenant", "rule") or ev.status not in _ANOMALOUS:
                    continue
                if ev.status == "silent":
                    # quiet since the outage, or quiet before it but not yet significant when it began (a sparse
                    # source); a source that was already an alarm before the outage keeps its own finding
                    same_outage = lo - 3600.0 <= self._onset(ev) <= hi + 3600.0 or (
                        ev.last < lo - 3600.0 and not self._silent_at(ev, lo)
                    )
                elif ev.status == "drop":
                    start = self._start(ev)
                    same_outage = lo - GLOBAL_WINDOW_S <= start <= hi + GLOBAL_WINDOW_S or (
                        ev.level == "log_source" and self._attributable(ev, self.global_agents)
                    )
                else:
                    same_outage = False
                if same_outage:
                    self._explain(ev, self.global_ev, by_global=True)
        # 3. agents: a whole-host anomaly is the root cause of its anomalous channels
        for name in sorted(agents):
            parent = agents[name]
            if parent.status not in _ANOMALOUS:
                continue
            anomalous = [kid for kid in kids_of_agent.get(name, []) if kid.status in _ANOMALOUS]
            if parent.final == "explained":
                # whatever explains the parent (a global outage...) also explains its anomalous children
                for kid in anomalous:
                    self._explain(kid, parent.explained_by, by_global=parent.explained_global)
                continue
            if parent.final:
                continue
            channel = carried.get(name)
            if channel is not None:
                parent.final = "explained"  # the channel's own finding (or its log source's) is the root cause
                parent.explained_by = channel
                channel.children.append(parent)
                continue
            parent.final = parent.status
            for kid in anomalous:
                self._explain(kid, parent)
        # 4. log sources
        for name in sorted(sources):
            parent = sources[name]
            if parent.status not in _ANOMALOUS:
                continue
            kids = kids_of_source.get(name, [])
            anomalous = [kid for kid in kids if kid.status in _ANOMALOUS]
            if parent.final == "explained":
                for kid in anomalous:
                    self._explain(kid, parent.explained_by, by_global=parent.explained_global)
                continue
            if parent.final:
                continue
            owned = [kid for kid in anomalous if kid.final == "explained" and kid.explained_by is not None]
            pending = [kid for kid in anomalous if not kid.final]
            if owned and self._attributable(parent, owned):
                # e.g. the hosts that carried most of this log source are down: their findings cover it
                parent.final = "explained"
                parent.explained_by = owned[0].explained_by
                continue
            single = self._single_cause(parent, pending)
            if single is not None:
                parent.final = "explained"  # one host's channel: reported as that channel
                parent.explained_by = single
                single.children.append(parent)
                continue
            parent.final = parent.status
            for kid in pending:
                self._explain(kid, parent)
        # 5. whatever is left is its own root cause
        for ev in self.evals.values():
            if not ev.final and ev.status in _ANOMALOUS and ev.level != "rule":
                ev.final = ev.status

    def _declare_global(self, source: _KeyEval, agents: list[_KeyEval], total: int | None = None) -> None:
        source.final = source.status
        self.global_ev = source
        start = self._start(source)
        self.global_window = (start, start)
        self.global_agents = [a for a in agents if a.status in _ANOMALOUS]
        self.global_total = total if total is not None else sum(1 for a in agents if a.evaluated)

    def _cluster(self, agents: list[_KeyEval], whole: list[_KeyEval]) -> None:
        """Find >= ``global_fraction`` of the agents whose whole-host SILENT/DROP began within ``GLOBAL_WINDOW_S``."""
        candidates = {id(a) for a in whole if a.status in ("silent", "drop")}
        for population, minimum in (
            ([a for a in agents if a.evaluated and a.duty == "always_on"], GLOBAL_MIN_AGENTS),
            ([a for a in agents if a.evaluated], GLOBAL_MIN_ANY_AGENTS),
        ):
            hit = sorted(((self._onset(a), a) for a in population if id(a) in candidates), key=lambda t: t[0])
            best, best_lo = 0, 0
            lo = 0
            for hi in range(len(hit)):
                while hit[hi][0] - hit[lo][0] > GLOBAL_WINDOW_S:
                    lo += 1
                if hi - lo + 1 > best:
                    best, best_lo = hi - lo + 1, lo
            if best >= minimum and best >= self.cfg.global_fraction * len(population):
                members = [a for _, a in hit[best_lo : best_lo + best]]
                self.global_agents = members
                self.global_total = len(population)
                self.global_window = (hit[best_lo][0], hit[best_lo + best - 1][0])
                anchor = _KeyEval(
                    level="tenant", key=(self.cube.tenant_name,), first=0.0, last=hit[best_lo][0], total=0
                )
                anchor.status = anchor.final = "silent"
                self.global_ev = anchor
                return

    def _resolve_rules(self) -> None:
        """Heartbeat rule silent: ``rule_dark`` if at least one of its sources kept sending, else explained."""
        for ev in self._by_level("rule"):
            if ev.status != "silent":
                continue
            pairs, _ = self.cube.rule_sources(ev.key[0])
            sources: list[_KeyEval] = []
            for agent, ls in sorted(pairs):
                if agent and ls:
                    src = self.evals.get(("agent_log_source", (agent, ls)))
                elif agent:
                    src = self.evals.get(("agent", (agent,)))
                elif ls:
                    src = self.evals.get(("log_source", (ls,)))
                else:
                    src = self.evals.get(("tenant", (self.cube.tenant_name,)))
                if src is not None:
                    sources.append(src)
            if not sources:
                # sources unknown (indexer path without rule/source pairs): the tenant as a whole is the source
                tenant_ev = self.evals.get(("tenant", (self.cube.tenant_name,)))
                sources = [tenant_ev] if tenant_ev is not None else []
            alive: list[_KeyEval] = []
            dead: list[_KeyEval] = []
            for src in sources:
                sending = src.last > ev.last + 60.0 and src.status != "silent"
                if sending and src.status in ("drop", "decay"):
                    # the source dropped: either because this rule stopped (rule is the root cause) or on its own
                    sending = self._attributable(src, [ev])
                    if sending and src.final in ("drop", "decay"):
                        src.final = "explained"
                        src.explained_by = ev
                (alive if sending else dead).append(src)
            if alive:
                ev.final = "rule_dark"
                ev.alive_sources = alive
                continue
            ev.final = "explained"
            owner = next((src.explained_by or src for src in dead), None)
            ev.explained_by = owner
            if owner is not None:
                owner.children.append(ev)

    # ---- tampering ------------------------------------------------------------------------------------------

    def _tampering(self) -> None:
        for ev in self.evals.values():
            if ev.level not in ("agent", "agent_log_source", "log_source"):
                continue
            reported = ev.final in ("silent", "drop")
            global_child = ev.explained_global and ev.status in ("silent", "drop") and ev.level != "log_source"
            if not (reported or global_child):
                continue
            start = self._start(ev)
            # a SILENT start is the last event (to the second with raw events); a DROP change point is only known to
            # the hour, and a source that dwindled before going quiet also counts from the onset of its decline
            slack = TAMPER_BUCKET_S if ev.status == "drop" else 0.0
            windows = [(start - PRECURSOR_BEFORE_S, start + PRECURSOR_AFTER_S + slack)]
            onset = self._onset(ev)
            if onset < start:
                windows.append((onset - PRECURSOR_BEFORE_S, onset + PRECURSOR_AFTER_S + TAMPER_BUCKET_S))
            if ev.level == "log_source":
                names = sorted({kid.key[0] for kid in ev.children if kid.level == "agent_log_source"})[:500]
            else:
                names = [ev.key[0]]
            found: list[Precursor] = []
            for name in names:
                for pre in self.cube.precursors_for(name):
                    if any(lo <= pre.ts <= hi for lo, hi in windows):
                        found.append(pre)
            if found:
                ev.precursors = sorted(found, key=lambda p: (p.ts, p.agent, p.code))
                ev.final = "tampering"
                if ev.explained_global:
                    ev.explained_global = False
                    if ev.explained_by is not None and ev in ev.explained_by.children:
                        ev.explained_by.children.remove(ev)
                    ev.explained_by = None

    # ---- monitorability -------------------------------------------------------------------------------------

    def _monitorability(self) -> None:
        sla = self.tenant.sla
        for ev in self.evals.values():
            if not ev.evaluated:
                continue
            if ev.tier == "critical" and ev.level in ("agent", "agent_log_source") and ev.rate is not None:
                ev.t_min = self._t_min(ev)
                limit = sla.get("critical", timedelta(hours=4)).total_seconds() / 3600.0
                if not ev.final and ev.status == "ok" and ev.t_min > limit:
                    ev.final = "unmonitorable"
            elif ev.scale > 0:
                ev.t_min = stats.t_min_hours(ev.scale / 24.0, ev.k, self.alpha) / ev.theta
            if not ev.final:
                ev.final = "ok" if ev.status in ("ok", "silent", "drop", "decay") else ev.status

    def _t_min(self, ev: _KeyEval) -> float:
        """Hours of silence (median over start times across the week) before the SILENT test fires."""
        rate = ev.rate
        assert rate is not None
        if ev.day_sigma >= 0.05 or ev.pi_off > 0:
            return self._t_min_scan(ev, rate)
        k = ev.k
        periods = TMIN_HORIZON_H // 168 + 2
        lp = [-k * math.log1p(r / k) if r > 0 else 0.0 for r in rate] * periods
        mus = list(rate) * periods
        neg_l = [0.0]
        cum_m = [0.0]
        for a, b in zip(lp, mus, strict=True):
            neg_l.append(neg_l[-1] - a)
            cum_m.append(cum_m[-1] + b)
        target = -self.log_alpha / ev.theta  # a bursty key needs proportionally longer silences
        n_eff = ev.n_eff
        lam_star = 0.0 if math.isinf(n_eff) else n_eff * math.expm1(target / n_eff)
        values: list[float] = []
        for s0 in range(168):
            i1 = bisect.bisect_right(neg_l, neg_l[s0] + target)
            i2 = bisect.bisect_right(cum_m, cum_m[s0] + lam_star)
            t = max(i1, i2) - s0
            values.append(float(t) if max(i1, i2) < len(neg_l) and t <= TMIN_HORIZON_H else math.inf)
        values.sort()
        return values[len(values) // 2]

    def _t_min_scan(self, ev: _KeyEval, rate: Sequence[float]) -> float:
        """:meth:`_t_min` for keys with day-level structure (lognormal day swings, days off): the same per-day
        integration and day-off mixture as the SILENT test, over a synthetic week (local midnights at slot % 24 == 0),
        from start times spread over the week."""
        k = ev.k
        theta = ev.theta
        target = self.log_alpha
        mults: list[float] = []
        log_w: list[float] = []
        if ev.day_sigma >= 0.05:
            for x, w in zip(_GH_NODES, _GH_WEIGHTS, strict=True):
                for sign in (-1.0, 1.0):
                    mults.append(math.exp(sign * math.sqrt(2.0) * ev.day_sigma * x - ev.day_sigma**2 / 2.0))
                    log_w.append(math.log(w / math.sqrt(math.pi)))
        pi_off = ev.pi_off
        probs = [min(0.999, max(pi_off, q)) for q in ev.stay]
        n_eff = ev.n_eff
        values: list[float] = []
        for s0 in range(0, 168, 7):
            closed = 0.0
            acc = 0.0
            nodes = [0.0] * len(mults)
            lam = lam_day = 0.0
            first = True
            days_off = 0
            found = math.inf
            for h in range(TMIN_HORIZON_H):
                slot = (s0 + h) % 168
                if h and slot % 24 == 0:  # local midnight: close the day
                    closed += self._day_value(acc, nodes, log_w, first, pi_off, probs, days_off)
                    if not first and pi_off > 0 and lam_day >= ELIGIBLE_DAY_EXPECTED:
                        days_off += 1
                    first = False
                    acc = lam_day = 0.0
                    nodes = [0.0] * len(mults)
                mu = rate[slot]
                if mu <= 0.0:
                    continue
                lam += mu
                lam_day += mu
                acc -= theta * k * math.log1p(mu / k)
                for idx, m in enumerate(mults):
                    nodes[idx] -= theta * k * math.log1p(mu * m / k)
                current = closed + self._day_value(acc, nodes, log_w, first, pi_off, probs, days_off)
                pred = -n_eff * math.log1p(theta * lam / n_eff) if not math.isinf(n_eff) else -theta * lam
                if max(current, pred) < target:
                    found = float(h + 1)
                    break
            values.append(found)
        values.sort()
        return values[len(values) // 2]

    @staticmethod
    def _day_value(
        acc: float,
        nodes: Sequence[float],
        log_w: Sequence[float],
        first: bool,
        pi_off: float,
        probs: Sequence[float],
        days_off: int,
    ) -> float:
        day = acc
        if nodes:
            day = -math.inf
            for lw, a in zip(log_w, nodes, strict=True):
                day = stats.logaddexp(day, lw + a)
            day = min(0.0, max(day, acc))
        if first or pi_off <= 0:
            return day
        q = probs[min(days_off, len(probs)) - 1] if days_off and probs else pi_off
        return stats.logaddexp(math.log(q), math.log1p(-q) + day) if q < 1.0 else 0.0

    # ---- findings -------------------------------------------------------------------------------------------

    def _findings(self, keys_evaluated: int) -> list[Finding]:
        out: list[Finding] = []
        name = self.tenant.name
        for ev in self.evals.values():
            if ev.final in _KIND_OF_STATUS:
                ev.fp = fingerprint(name, _KIND_OF_STATUS[ev.final], _subject(ev.level, ev.key))
        if self.global_ev is not None:
            out.append(self._global_finding())
        for ev in sorted(self.evals.values(), key=lambda e: (LEVELS.index(e.level), e.key)):
            if ev is self.global_ev:
                continue
            if ev.final in ("silent", "drop", "decay", "tampering"):
                out.append(self._key_finding(ev))
            elif ev.final == "rule_dark":
                out.append(self._rule_finding(ev))
        out.extend(self._unmonitorable_findings())
        out.extend(self._assessment_findings(keys_evaluated))
        return out

    def _related(self, ev: _KeyEval) -> list[str]:
        related: list[str] = []
        for kid in ev.children[:MAX_RELATED]:
            kind = "silence.rule_dark" if kid.level == "rule" else _KIND_OF_STATUS.get(kid.status, "silence.silent")
            related.append(kid.fp or fingerprint(self.tenant.name, kind, _subject(kid.level, kid.key)))
        return related

    def _confidence(self, ev: _KeyEval) -> Confidence:
        if self.partial:
            return Confidence.LOW
        if ev.level == "rule":
            # the rule stopping is certain (an alert IS the rule firing), but on alerts-only input "its sources are
            # alive" rests on other alerts, not on the raw events: that is alert silence, MEDIUM at most (§2.4)
            return Confidence.MEDIUM if self.alerts_only or self.basis.input_kind == "unknown" else Confidence.HIGH
        if self.alerts_only:
            return Confidence.MEDIUM if ev.scale >= 20.0 else Confidence.LOW
        if self.basis.input_kind in _ARCHIVES:
            return Confidence.HIGH
        return Confidence.MEDIUM

    def _common_reasons(self, ev: _KeyEval) -> list[Message | str]:
        reasons: list[Message | str] = [
            M(
                "silence.reason.profile",
                duty=M(f"silence.duty.{ev.duty}"),
                tier=M(f"silence.tier.{ev.tier}"),
                days=ev.baseline_days,
                model=M(f"silence.model.{ev.model or 'hour_of_day'}"),
                k=ev.k,
            )
        ]
        if ev.theta < 0.95:
            reasons.append(M("silence.reason.bursty", factor=1.0 / ev.theta))
        if ev.pi_off >= 0.01:
            reasons.append(M("silence.reason.days_off", share=ev.pi_off))
        if self.alerts_only and ev.level != "rule":
            reasons.append(M("silence.reason.alerts_only"))
        if self.partial:
            reasons.append(M("silence.reason.partial_input"))
        return reasons

    def _agent_reasons(self, ev: _KeyEval) -> tuple[list[Message | str], Confidence | None]:
        """Wazuh API context for agent keys: reasons, and HIGH confidence when a live agent sends nothing."""
        if ev.level not in ("agent", "agent_log_source") or self.agents is None:
            return [], None
        info = self.inventory.get(ev.key[0].lower())
        if info is None:
            # Never downgrade on absence: syslog devices (firewalls...) report through the manager and are not
            # Wazuh agents, so "not in the inventory" is context, not evidence of retirement.
            return ([M("silence.reason.agent_unregistered")] if self.inventory else []), None
        seen = _aware(info.last_keepalive)
        keepalive = iso(seen) or "-"
        status = _agent_status(info.status)
        if ev.key[0].lower() in self.fresh_agents:
            # connected now (keepalive near "now", never a keepalive newer than an old export) yet quiet; on alerts-only
            # input the quiet part is alerts, not events, so it does not raise the confidence
            if self.alerts_only:
                return [M("silence.reason.agent_active_alerts", status=status, keepalive=keepalive)], None
            confidence = None if self.partial else Confidence.HIGH
            return [M("silence.reason.agent_active", status=status, keepalive=keepalive)], confidence
        if info.status in ("disconnected", "never_connected", "pending"):
            return [M("silence.reason.agent_disconnected", status=status, keepalive=keepalive)], None
        return [], None

    def _key_finding(self, ev: _KeyEval) -> Finding:
        kind = _KIND_OF_STATUS[ev.final]
        key_msg = _key_message(ev.level, ev.key)
        filt, filt_evidence = self._filter(ev.level, ev.key)
        since_ts = ev.last if ev.status == "silent" else (ev.drop_start or ev.win_start * 3600.0)
        reasons: list[Message | str] = []
        evidence = self._evidence(ev)
        evidence["reproduce"] = {
            "filter": filt_evidence,
            "from": iso(_dt(min(since_ts, self.end) - 86400.0)),
            "to": iso(_dt(self.end)),
        }
        if ev.status == "silent":
            reasons.append(
                M(
                    "silence.reason.p0",
                    expected=ev.expected_gap,
                    last_seen=iso(_dt(ev.last)) or "-",
                    p0=math.exp(ev.log_p0),
                    alpha=self.alpha,
                )
            )
        elif ev.status == "drop":
            reasons.append(
                M(
                    "silence.reason.drop",
                    observed=int(ev.observed),
                    expected=ev.expected,
                    ratio=ev.drop_ratio or 0.0,
                    p=ev.drop_p if ev.drop_p is not None else 1.0,
                    alpha=self.alpha,
                )
            )
            if ev.drop_segment is not None and ev.drop_start is not None and ev.drop_segment[1] > 0:
                seg_observed, seg_expected = ev.drop_segment
                reasons.append(
                    M(
                        "silence.reason.drop_since",
                        since=iso(_dt(ev.drop_start)) or "-",
                        observed=int(seg_observed),
                        expected=seg_expected,
                        ratio=seg_observed / seg_expected,
                    )
                )
        elif ev.status == "decay" and ev.decay_days < DECAY_RECENT_DAYS:
            reasons.append(
                M(
                    "silence.reason.decay_days",
                    days=ev.decay_days,
                    ratio=ev.decay_ratio or 0.0,
                    ref_days=ev.decay_ref_days,
                    p=ev.decay_p if ev.decay_p is not None else 1.0,
                )
            )
        elif ev.status == "decay":
            reasons.append(
                M(
                    "silence.reason.decay",
                    recent=ev.decay_recent,
                    reference=ev.decay_reference,
                    ref_days=ev.decay_ref_days,
                    p=ev.decay_p if ev.decay_p is not None else 1.0,
                )
            )
        reasons.extend(self._common_reasons(ev))
        agent_reasons, conf_override = self._agent_reasons(ev)
        reasons.extend(agent_reasons)
        if ev.children:
            reasons.append(M("silence.reason.explained", count=len(ev.children)))
        if ev.level == "tenant" and self.basis.now_origin in ("flag", "wallclock"):
            reasons.append(M("silence.reason.stale_now", origin=M(f"silence.origin.{self.basis.now_origin}")))
        gap_text = humanize(timedelta(seconds=int(ev.gap)))
        if ev.final == "tampering":
            first = ev.precursors[0]
            title = M("silence.title.tampering", key=key_msg, precursor=M(f"silence.precursor.{first.code}"))
            for pre in ev.precursors[:10]:
                start = ev.last if ev.status == "silent" else (ev.drop_start or ev.win_start * 3600.0)
                delta = round((start - pre.ts) / 60.0)
                reasons.insert(
                    0,
                    M(
                        "silence.reason.precursor",
                        what=M(f"silence.precursor.{pre.code}"),
                        agent=Entity("host", pre.agent),
                        ts=iso(_dt(pre.ts)) or "-",
                        rule_id=pre.rule_id or "-",
                        when=M("silence.when.before" if delta >= 0 else "silence.when.after", minutes=abs(delta)),
                    ),
                )
            evidence["precursors"] = [
                {
                    "agent": Entity("host", pre.agent),
                    "ts": iso(_dt(pre.ts)),
                    "code": pre.code,
                    "rule_id": pre.rule_id,
                    "technique": PRECURSOR_CODES.get(pre.code),
                }
                for pre in ev.precursors[:20]
            ]
            evidence["mitre"] = sorted(
                set(TAMPERING_TECHNIQUES)
                | {PRECURSOR_CODES[p.code] for p in ev.precursors if p.code in PRECURSOR_CODES}
            )
            severity = Severity.CRITICAL
            recommendation: Message = M("silence.rec.tampering", key=key_msg)
            confidence = Confidence.MEDIUM if not self.partial else Confidence.LOW
        else:
            if ev.final == "silent":
                title = M("silence.title.silent", key=key_msg, gap=gap_text)
                severity = _SILENT_SEV[ev.tier]
                recommendation = M("silence.rec.silent", key=key_msg, filter=filt, since=iso(_dt(ev.last)) or "-")
            elif ev.final == "drop":
                title = M(
                    "silence.title.drop",
                    key=key_msg,
                    observed=int(ev.observed),
                    expected=ev.expected,
                    hours=ev.win_end - ev.win_start,
                )
                severity = _DROP_SEV[ev.tier]
                recommendation = M("silence.rec.drop", key=key_msg, filter=filt, since=iso(_dt(since_ts)) or "-")
            else:
                title = M("silence.title.decay", key=key_msg, ratio=ev.decay_ratio or 0.0)
                # a sustained loss as deep as a DROP is as serious as one
                deep = ev.decay_ratio is not None and ev.decay_ratio < self.cfg.drop_ratio
                severity = (_DROP_SEV if deep else _DECAY_SEV)[ev.tier]
                recommendation = M("silence.rec.decay", key=key_msg, filter=filt)
            confidence = conf_override or self._confidence(ev)
        return Finding(
            kind=kind,
            domain="silence",
            title=title,
            severity=severity,
            subject=_subject(ev.level, ev.key),
            reasons=reasons,
            evidence=evidence,
            recommendation=recommendation,
            confidence=confidence,
            score=_score(ev),
            tenant=self.tenant.name,
            fingerprint=ev.fp,
            related=self._related(ev),
        )

    def _rule_finding(self, ev: _KeyEval) -> Finding:
        rule_id = ev.key[0]
        filt, filt_evidence = self._filter("rule", ev.key)
        evidence = self._evidence(ev)
        evidence["reproduce"] = {"filter": filt_evidence, "from": iso(_dt(ev.last - 86400.0)), "to": iso(_dt(self.end))}
        evidence["sources_alive"] = [_key_dict(src.level, src.key) for src in ev.alive_sources[:MAX_EXPLAINED_EVIDENCE]]
        pairs, _ = self.cube.rule_sources(rule_id)
        reasons: list[Message | str] = [
            M(
                "silence.reason.p0",
                expected=ev.expected_gap,
                last_seen=iso(_dt(ev.last)) or "-",
                p0=math.exp(ev.log_p0),
                alpha=self.alpha,
            ),
            M(
                "silence.reason.sources_alive",
                alive=len(ev.alive_sources),
                total=max(len(pairs), len(ev.alive_sources)),
            ),
        ]
        reasons.extend(self._common_reasons(ev))
        return Finding(
            kind="silence.rule_dark",
            domain="silence",
            title=M("silence.title.rule_dark", rule_id=rule_id, gap=humanize(timedelta(seconds=int(ev.gap)))),
            severity=_SILENT_SEV[ev.tier],
            subject=_subject("rule", ev.key),
            reasons=reasons,
            evidence=evidence,
            recommendation=M("silence.rec.rule_dark", rule_id=rule_id, filter=filt),
            confidence=self._confidence(ev),
            score=-ev.log_p0,
            tenant=self.tenant.name,
            fingerprint=ev.fp,
        )

    def _global_finding(self) -> Finding:
        source = self.global_ev
        assert source is not None
        explained = [ev for ev in self.evals.values() if ev.explained_global and ev.explained_by is source]
        explained.sort(key=lambda e: (LEVELS.index(e.level), e.key))
        related = [
            fingerprint(self.tenant.name, _KIND_OF_STATUS.get(ev.status, "silence.silent"), _subject(ev.level, ev.key))
            for ev in explained[:MAX_RELATED]
        ]
        lo, hi = self.global_window or (source.last, source.last)
        tenant_key = self.cube.tenant_name
        reasons: list[Message | str] = []
        evidence: dict[str, Any] = {
            "level": "tenant",
            "tenant": tenant_key,
            "agents_silent": len(self.global_agents),
            "agents_dropped": sum(1 for a in self.global_agents if a.status != "silent"),
            "agents_total": self.global_total,
            "window": {"start": iso(_dt(lo)), "end": iso(_dt(hi))},
            "alpha_eff": self.alpha,
            "explained_count": len(explained),
            "explained": [_key_dict(ev.level, ev.key) for ev in explained[:MAX_EXPLAINED_EVIDENCE]],
            "agents": [Entity("host", ev.key[0]) for ev in self.global_agents[:MAX_EXPLAINED_EVIDENCE]],
        }
        if source.level == "tenant" and source.total > 0:
            evidence.update(self._evidence(source))
        tiers = [a.tier for a in self.global_agents]
        severity = Severity.CRITICAL if ("critical" in tiers or source.total > 0) else Severity.HIGH
        start_text = iso(_dt(lo)) or "-"
        if source.total > 0 and source.status == "silent":
            title = M("silence.title.global_tenant", tenant=tenant_key, start=start_text)
            reasons.append(
                M(
                    "silence.reason.p0",
                    expected=source.expected_gap,
                    last_seen=iso(_dt(source.last)) or "-",
                    p0=math.exp(source.log_p0),
                    alpha=self.alpha,
                )
            )
        elif source.total > 0:
            title = M(
                "silence.title.global_drop",
                tenant=tenant_key,
                observed=int(source.observed),
                expected=source.expected,
                hours=source.win_end - source.win_start,
            )
        else:
            mixed = any(a.status != "silent" for a in self.global_agents)
            title = M(
                "silence.title.global_mixed" if mixed else "silence.title.global_silence",
                count=len(self.global_agents),
                total=self.global_total,
                start=start_text,
            )
            reasons.append(
                M(
                    "silence.reason.global_mixed" if mixed else "silence.reason.global",
                    count=len(self.global_agents),
                    total=self.global_total,
                    share=len(self.global_agents) / max(1, self.global_total),
                    start=iso(_dt(lo)) or "-",
                    end=iso(_dt(hi)) or "-",
                )
            )
        if explained:
            reasons.append(M("silence.reason.explained", count=len(explained)))
        if self.basis.now_origin in ("flag", "wallclock"):
            reasons.append(M("silence.reason.stale_now", origin=M(f"silence.origin.{self.basis.now_origin}")))
        if self.partial:
            reasons.append(M("silence.reason.partial_input"))
        return Finding(
            kind="pipeline.global_silence",
            domain="pipeline",
            title=title,
            severity=severity,
            subject="global_silence",
            reasons=reasons,
            evidence=evidence,
            recommendation=M("silence.rec.global"),
            confidence=Confidence.LOW if self.partial else Confidence.HIGH,
            score=float(len(explained)),
            tenant=self.tenant.name,
            related=related,
        )

    def _unmonitorable_findings(self) -> list[Finding]:
        by_agent: dict[str, list[_KeyEval]] = {}
        for ev in self.evals.values():
            if ev.final == "unmonitorable":
                by_agent.setdefault(ev.key[0], []).append(ev)
        sla = self.tenant.sla.get("critical", timedelta(hours=4))
        out: list[Finding] = []
        for agent in sorted(by_agent):
            items = sorted(by_agent[agent], key=lambda e: (LEVELS.index(e.level), e.key))
            host_level = next((e for e in items if e.level == "agent"), None)
            main = host_level or items[0]
            t_min = main.t_min if main.t_min is not None else math.inf
            t_text = humanize(timedelta(hours=t_min)) if not math.isinf(t_min) else "> 28d"
            key_msg = _key_message(main.level, main.key)
            if host_level is not None:
                title = M("silence.title.unmonitorable", key=key_msg, t_min=t_text, sla=humanize(sla))
                severity = Severity.MEDIUM
            else:
                title = M("silence.title.unmonitorable_channels", agent=Entity("host", agent), sla=humanize(sla))
                severity = Severity.LOW
            evidence: dict[str, Any] = {
                "level": main.level,
                "agent": Entity("host", agent),
                "tier": "critical",
                "sla_hours": sla.total_seconds() / 3600.0,
                "alpha_eff": self.alpha,
                "keys": [
                    {
                        **_key_dict(e.level, e.key),
                        "t_min_hours": None if e.t_min is None or math.isinf(e.t_min) else round(e.t_min, 1),
                        "rate_per_hour": round(e.scale / 24.0, 4),
                        "duty": e.duty,
                    }
                    for e in items[:MAX_EXPLAINED_EVIDENCE]
                ],
            }
            out.append(
                Finding(
                    kind="silence.unmonitorable",
                    domain="silence",
                    title=title,
                    severity=severity,
                    subject=f"agent:{_esc(agent)}",
                    reasons=[
                        M(
                            "silence.reason.unmonitorable",
                            rate=main.scale / 24.0,
                            t_min=t_text,
                            tier=M("silence.tier.critical"),
                            sla=humanize(sla),
                        ),
                        *self._common_reasons(main),
                    ],
                    evidence=evidence,
                    recommendation=M("silence.rec.unmonitorable", key=key_msg),
                    confidence=Confidence.MEDIUM,
                    score=t_min if not math.isinf(t_min) else 1e9,
                    tenant=self.tenant.name,
                )
            )
        return out

    def _assessment_findings(self, keys_evaluated: int) -> list[Finding]:
        out: list[Finding] = []
        learning = [ev for ev in self.evals.values() if ev.status == "learning"]
        days = self.cfg.min_history_days
        if keys_evaluated == 0:
            out.append(
                Finding(
                    kind="assessment.learning",
                    domain="assessment",
                    title=M("silence.title.nothing_evaluable", days=days),
                    severity=Severity.MEDIUM,
                    subject="silence:learning",
                    reasons=[
                        M("silence.reason.learning", count=len(learning), critical=_critical_count(learning), days=days)
                    ],
                    evidence={"learning": len(learning), "keys": len(self.evals)},
                    recommendation=M("silence.rec.learning"),
                    confidence=Confidence.HIGH,
                    tenant=self.tenant.name,
                )
            )
        elif learning:
            out.append(
                Finding(
                    kind="assessment.learning",
                    domain="assessment",
                    title=M("silence.title.learning", count=len(learning), days=days),
                    severity=Severity.LOW,
                    subject="silence:learning",
                    reasons=[
                        M("silence.reason.learning", count=len(learning), critical=_critical_count(learning), days=days)
                    ],
                    evidence={
                        "learning": len(learning),
                        "keys": len(self.evals),
                        "examples": [_key_dict(ev.level, ev.key) for ev in learning[:MAX_EXPLAINED_EVIDENCE]],
                    },
                    recommendation=M("silence.rec.learning"),
                    confidence=Confidence.HIGH,
                    tenant=self.tenant.name,
                )
            )
        cube = self.cube
        if cube.truncated:
            dropped = sum(cube.dropped_events.values())
            out.append(
                Finding(
                    kind="assessment.incomplete",
                    domain="assessment",
                    title=M("silence.title.truncated", max_keys=cube.max_keys, dropped=dropped),
                    severity=Severity.MEDIUM,
                    subject="silence:cube_truncated",
                    reasons=[M("silence.reason.truncated")],
                    evidence={
                        "max_keys": cube.max_keys,
                        "dropped_events": dict(cube.dropped_events),
                        "dropped_keys": dict(cube.dropped_keys),
                    },
                    recommendation=M("silence.rec.truncated"),
                    confidence=Confidence.HIGH,
                    tenant=self.tenant.name,
                )
            )
        return out

    # ---- evidence / section ---------------------------------------------------------------------------------

    def _evidence(self, ev: _KeyEval) -> dict[str, Any]:
        evidence: dict[str, Any] = {"level": ev.level, **_key_dict(ev.level, ev.key)}
        evidence.update(
            {
                "status": ev.status,
                "last_seen": iso(_dt(ev.last)),
                "gap_seconds": int(ev.gap),
                "gap": humanize(timedelta(seconds=int(ev.gap))),
                "expected_in_gap": round(ev.expected_gap, 3),
                "p0": math.exp(ev.log_p0),
                "q": ev.q,
                "alpha_eff": self.alpha,
                "observed": ev.observed,
                "expected": round(ev.expected, 3),
                "window": (
                    {"start": iso(_dt(ev.win_start * 3600.0)), "end": iso(_dt(ev.win_end * 3600.0))}
                    if ev.win_end > ev.win_start
                    else None
                ),
                "p": ev.drop_p,
                "ratio": ev.drop_ratio,
                "duty": ev.duty,
                "tier": ev.tier,
                "baseline_days": ev.baseline_days,
                "model": ev.model,
                "rate_per_hour": round(ev.scale / 24.0, 4),
                "dispersion_k": round(ev.k, 3),
                "dispersion_k_day": round(ev.k_day, 3),
                "day_sigma": round(ev.day_sigma, 4),
                "off_day_probability": round(ev.pi_off, 4),
                "off_day_persistence": [round(q, 4) for q in ev.stay[:7]],
                "low_day_probability": round(ev.pi_low, 4),
                "t_min_hours": None if ev.t_min is None or math.isinf(ev.t_min) else round(ev.t_min, 1),
                "frozen_baseline": ev.frozen,
                "burstiness": round(ev.theta, 4),
            }
        )
        if ev.drop_segment is not None and ev.drop_start is not None:
            evidence["since_change"] = {
                "start": iso(_dt(ev.drop_start)),
                "observed": ev.drop_segment[0],
                "expected": round(ev.drop_segment[1], 3),
                "ratio": ev.drop_segment[0] / ev.drop_segment[1] if ev.drop_segment[1] > 0 else None,
            }
        if ev.decay_ratio is not None:
            evidence["decay"] = {
                "recent_median": ev.decay_recent,
                "reference_median": ev.decay_reference,
                "reference_days": ev.decay_ref_days,
                "recent_days": ev.decay_days,
                "ratio": ev.decay_ratio,
                "p": ev.decay_p,
            }
        if ev.children:
            evidence["explained_count"] = len(ev.children)
            evidence["explained"] = [_key_dict(kid.level, kid.key) for kid in ev.children[:MAX_EXPLAINED_EVIDENCE]]
        if self.agents is not None and ev.level in ("agent", "agent_log_source"):
            info = self.inventory.get(ev.key[0].lower())
            evidence["agent_status"] = info.status if info else "not_registered"
            evidence["last_keepalive"] = iso(_aware(info.last_keepalive)) if info else None
        return evidence

    def _filter(self, level: str, key: tuple[str, ...]) -> tuple[Message, dict[str, Any]]:
        profile = self.profile
        if profile == "ecs":
            host_f, rule_f = "host.name", "kibana.alert.rule.uuid"
            ls_f = "event.dataset"
        elif profile in ("wazuh4", "wazuh5", "unknown", "mixed"):
            host_f, rule_f = "agent.name", "rule.id"
            ls_f = ""
        else:
            host_f, rule_f, ls_f = "source", "rule_id", "log_source"
        if level == "tenant":
            return M("silence.filter.all"), {}
        if level == "rule":
            return M("silence.filter.one", field=rule_f, value=_quoted(key[0])), {rule_f: key[0]}
        if level == "agent":
            return M("silence.filter.one", field=host_f, value=Entity("host", key[0])), {host_f: Entity("host", key[0])}
        ls = key[-1]
        field_ls = ls_f or _wazuh_ls_field(ls)
        if level == "log_source":
            return M("silence.filter.one", field=field_ls, value=_quoted(ls)), {field_ls: ls}
        return (
            M("silence.filter.two", field1=host_f, value1=Entity("host", key[0]), field2=field_ls, value2=_quoted(ls)),
            {host_f: Entity("host", key[0]), field_ls: ls},
        )

    def _section(self, keys_evaluated: int, findings: list[Finding]) -> dict[str, Any]:
        counts = {status: 0 for status in STATUSES}
        for ev in self.evals.values():
            counts[ev.final or ev.status] = counts.get(ev.final or ev.status, 0) + 1
        ranks = [f.severity.rank for f in findings if f.domain in ("silence", "pipeline")]
        if keys_evaluated == 0:
            status = "not_assessed"
        elif any(r >= Severity.HIGH.rank for r in ranks):
            status = "fail"
        elif any(r >= Severity.MEDIUM.rank for r in ranks):
            status = "warn"
        else:
            status = "ok"
        critical = [
            ev
            for ev in self.evals.values()
            if ev.tier == "critical" and ev.level in ("agent", "agent_log_source") and ev.evaluated
        ]
        monitorable = [ev for ev in critical if ev.t_min is not None and ev.t_min <= self._sla_hours("critical")]
        listed = [
            ev
            for ev in self.evals.values()
            if (ev.final or ev.status) not in ("ok", "not_evaluated")
            or (ev.tier == "critical" and ev.level != "tenant")
        ]
        listed.sort(
            key=lambda e: (
                -_TIER_RANK.get(e.tier, 1),
                _STATUS_ORDER.get(e.final or e.status, 99),
                e.log_p0,
                LEVELS.index(e.level),
                e.key,
            )
        )
        sources = [self._source_row(ev) for ev in listed[:MAX_SECTION_SOURCES]]
        return {
            "status": status,
            "alpha_eff": self.alpha,
            "keys_evaluated": keys_evaluated,
            "alarm_budget": self.cfg.alarm_budget,
            "evaluated_until": iso(_dt(self.end)),
            "status_counts": counts,
            "sources": sources,
            "sources_truncated": len(listed) > MAX_SECTION_SOURCES,
            "monitorability": {
                "critical_total": len(critical),
                "critical_monitorable": len(monitorable),
                "sla_hours": self._sla_hours("critical"),
            },
            "input_kind": self.basis.input_kind,
            "alerts_only": self.alerts_only,
            "cube_truncated": self.cube.truncated,
            "precursors_truncated": self.cube.precursors_truncated,
        }

    def _sla_hours(self, tier: str) -> float:
        return self.tenant.sla.get(tier, timedelta(hours=24)).total_seconds() / 3600.0

    def _source_row(self, ev: _KeyEval) -> dict[str, Any]:
        status = ev.final or ev.status
        p: float | None
        if ev.status == "silent" or status in ("silent", "rule_dark"):
            observed, expected, p = 0.0, ev.expected_gap, math.exp(ev.log_p0)
        elif ev.status in ("drop",):
            observed, expected, p = ev.observed, ev.expected, ev.drop_p
        elif ev.status == "decay":
            observed, expected, p = ev.decay_recent, ev.decay_reference, ev.decay_p
        else:
            observed, expected, p = ev.day_observed, ev.day_expected, (math.exp(ev.log_p0) if ev.evaluated else None)
        return {
            "level": ev.level,
            "key": _key_dict(ev.level, ev.key),
            "status": status,
            "last_seen": iso(_dt(ev.last)),
            "observed": float(observed),
            "expected": round(float(expected), 3),
            "p": p,
            "tier": ev.tier,
            "duty": ev.duty,
            "gap_hours": round(ev.gap / 3600.0, 2),
            "t_min_hours": None if ev.t_min is None or math.isinf(ev.t_min) else round(ev.t_min, 1),
            "daily": self._daily(ev),
        }

    def _daily(self, ev: _KeyEval) -> list[int]:
        clock = self.clock
        start = max(clock.start, self.end_hour - DECAY_SPAN_DAYS * 24)
        counts = self.cube.dense(ev.level, ev.key, start, self.end_hour + 1)
        per_day: dict[int, int] = {}
        for idx, c in enumerate(counts):
            i = start + idx - clock.start
            if 0 <= i < clock.n:
                per_day[clock.day[i]] = per_day.get(clock.day[i], 0) + int(c)
        if not per_day:
            return []
        lo, hi = min(per_day), max(per_day)
        return [per_day.get(j, 0) for j in range(lo, hi + 1)]


# ---- helpers ------------------------------------------------------------------------------------------------------


def _dt(ts: float) -> datetime:
    return datetime.fromtimestamp(max(0.0, ts), UTC)


def _aware(ts: datetime | None) -> datetime | None:
    """API datetimes should be aware UTC; a naive one is read as UTC (never as the machine's local time)."""
    if ts is not None and ts.tzinfo is None:
        return ts.replace(tzinfo=UTC)
    return ts


def _score(ev: _KeyEval) -> float:
    """Ranking helper: -log(p) of the test that fired (larger = more surprising)."""
    if ev.status == "silent":
        return -ev.log_p0
    p = ev.drop_p if ev.status == "drop" else ev.decay_p if ev.status == "decay" else None
    return -math.log(max(p, 1e-300)) if p is not None else 0.0


def _drop_change_point(mus: Sequence[float], obs: Sequence[float]) -> int:
    """Index where a rate drop most likely started: the maximum-likelihood change point of a Poisson rate.

    For every suffix ``[t, n)`` the post-change ratio is ``r = sum(c) / sum(mu)`` and the log-likelihood ratio
    against "no change" is ``sum(c) log r - sum(mu) (r - 1)``; the best suffix with ``r < 1`` wins. Pre-change
    hours that happen to run low barely move it, unlike a raw cumulative deficit.
    """
    best_i, best = len(mus) - 1, -math.inf
    sum_c = sum_mu = 0.0
    for i in range(len(mus) - 1, -1, -1):
        sum_c += obs[i]
        sum_mu += mus[i]
        if sum_mu <= 0.0 or sum_c >= sum_mu:
            continue
        ratio = sum_c / sum_mu
        llr = (sum_c * math.log(ratio) if sum_c > 0 else 0.0) - sum_mu * (ratio - 1.0)
        if llr > best:
            best, best_i = llr, i
    return best_i


_AGENT_STATUSES = frozenset({"active", "disconnected", "never_connected", "pending", "unknown"})


def _agent_status(status: str) -> Message | str:
    return M(f"silence.agent_status.{status}") if status in _AGENT_STATUSES else status


def _ratio(num: float, den: float) -> float:
    return num / den if den else 0.0


def _beta_prior(items: Sequence[tuple[int, int]]) -> tuple[float, float]:
    """Empirical-Bayes Beta prior (mean, strength) for per-key day rates from ``(events, days)`` of the peers.

    The strength comes from the between-key variance beyond binomial noise: homogeneous peers (a fleet of
    laptops) give a strong prior so a laptop that happened not to skip a day in its baseline still inherits the
    fleet's habit; heterogeneous peers give a weak one so each key speaks for itself.
    """
    total_days = sum(days for _, days in items)
    if total_days == 0:
        return 0.0, OFF_PRIOR_MIN
    mean = sum(events for events, _ in items) / total_days
    if mean <= 0.0 or mean >= 1.0:
        return min(1.0, max(0.0, mean)), OFF_PRIOR_MAX
    usable = [(events / days, days) for events, days in items if days >= 5]
    if len(usable) < 3:
        return mean, OFF_PRIOR_MIN
    rates = [r for r, _ in usable]
    avg = sum(rates) / len(rates)
    observed_var = sum((r - avg) ** 2 for r in rates) / (len(rates) - 1)
    binomial_var = sum(mean * (1.0 - mean) / days for _, days in usable) / len(usable)
    between = observed_var - binomial_var
    if between <= 0.0:
        return mean, OFF_PRIOR_MAX
    return mean, stats.clip(mean * (1.0 - mean) / between - 1.0, OFF_PRIOR_MIN, OFF_PRIOR_MAX)


def _day_rate(events: int, eligible: int, tier: str, prior: tuple[float, float] | None) -> float:
    """Posterior rate of off (or low) days of one key: its own record plus its peers' rate as an empirical-Bayes prior.

    The peer prior is dropped (own record only) for critical keys, so a critical server that never skipped a day keeps
    hour-level sensitivity even when its peers are laptops, and for any key whose own record is implausible under the
    peers' rate (binomial lower tail below ``PRIOR_COMPAT_P``: a server pooled with a fleet of laptops).
    """
    rate, strength = prior if prior is not None else (0.0, OFF_PRIOR_MIN)
    implausible = rate > 0.0 and eligible > 0 and _binom_logcdf(events, eligible, rate) < math.log(PRIOR_COMPAT_P)
    if tier == "critical" or implausible:
        rate, strength = 0.0, OFF_PRIOR_MIN
    return (events + strength * rate) / (eligible + strength)


def _binom_logcdf(x: int, n: int, p: float) -> float:
    """``log P(X <= x)`` for ``X ~ Binomial(n, p)`` (small ``n``: days of a baseline)."""
    if x >= n or p <= 0.0:
        return 0.0
    if p >= 1.0:
        return -math.inf
    lp, lq = math.log(p), math.log1p(-p)
    total = -math.inf
    for i in range(0, x + 1):
        term = math.lgamma(n + 1) - math.lgamma(i + 1) - math.lgamma(n - i + 1) + i * lp + (n - i) * lq
        total = stats.logaddexp(total, term)
    return min(0.0, total)


def _persistence(p1: _P1, rate: Sequence[float], k: float, clock: _Clock, within_day: bool) -> float:
    """Burstiness ``theta`` in (0, 1] of a key, from the quiet periods of its own baseline.

    The P0 test multiplies independent hourly zero-probabilities. Many sources are bursty instead (on/off
    applications, alerts that come in clusters): once quiet they tend to stay quiet, and an independent-hours P0 would
    call their normal lulls outages. Within each baseline quiet period (a run of empty hours; the first hour is not
    counted, and with ``within_day`` a run is followed only until the end of its local day because whole days off are
    the day-off mixture's business), the chance that one more hour stays empty is modelled as ``P0_h ** theta``.
    ``theta`` is the maximum-likelihood value over the key's runs, with the longest 10% censored at the next longest
    (one maintenance window is not burstiness) and at least ``PERSIST_MIN_RUNS`` informative runs; the *largest* theta
    within the 90% likelihood interval is used (the least correction the data support). ``theta = 1`` is the plain
    model; in the SILENT test every hour of a gap costs ``theta`` times its NB cost.
    """
    nz = p1.nz
    n = len(nz)
    if n < 3 or nz.count(0) < 2 or nz.count(1) < 2:
        return 1.0
    slot, days, cal = clock.slot, clock.day, clock.cal
    i0 = p1.i_base

    def cost(i: int) -> float:
        mu = rate[slot[i]]
        return k * math.log1p(mu / k) if mu > 0.0 and not cal[i] else 0.0

    runs: list[tuple[float, float]] = []  # (continuation cost C, termination cost T; 0 when censored)
    idx = nz.find(1)  # quiet periods before the first event have an unknown start
    while 0 <= idx < n:
        start = nz.find(0, idx)
        if start < 0:
            break
        end = nz.find(1, start)
        stop = n if end < 0 else end
        run_day = days[i0 + start]
        total = 0.0
        same_day = True
        for j in range(start + 1, stop):
            i = i0 + j
            if within_day and days[i] != run_day:
                same_day = False
                break
            total += cost(i)
        term = cost(i0 + end) if end >= 0 and same_day and (not within_day or days[i0 + end] == run_day) else 0.0
        if total + term >= PERSIST_INFO:
            runs.append((total, term))
        if end < 0:
            break
        idx = end
    if len(runs) < PERSIST_MIN_RUNS + 1:
        return 1.0
    # the longest 10% (at least one) are censored at the next longest: an outlier (one maintenance window) gets a
    # bounded say while a genuinely long-tailed source keeps its tail evidence
    runs.sort(key=lambda r: r[0])
    cut = len(runs) - max(1, len(runs) // 10)
    cap = runs[cut - 1][0]
    runs = runs[:cut] + [(min(c, cap), 0.0) for c, _ in runs[cut:]]
    sum_c = math.fsum(c for c, _ in runs)
    terms = [t for _, t in runs if t > 0.0]

    def slope(theta: float) -> float:
        # d/dtheta log(1 - exp(-theta t)) = t / (exp(theta t) - 1), written so that it never overflows
        total = -sum_c
        for t in terms:
            x = theta * t
            total += 1.0 / theta if x < 1e-12 else t * math.exp(-x) / -math.expm1(-x)
        return total

    def loglik(theta: float) -> float:
        total = -theta * sum_c
        for t in terms:
            total += math.log(max(-math.expm1(-theta * t), 1e-300))
        return total

    if sum_c <= 0.0 or slope(1.0) >= 0.0:
        return 1.0
    # bisection in log(theta): the log-likelihood is concave, its slope decreasing
    lo, hi = math.log(1e-6), 0.0
    if terms and slope(1e-6) > 0.0:
        for _ in range(40):
            mid = 0.5 * (lo + hi)
            if slope(math.exp(mid)) > 0.0:
                lo = mid
            else:
                hi = mid
    best = math.exp(0.5 * (lo + hi)) if terms else 1e-6
    peak = loglik(best)
    if peak - loglik(1.0) <= PERSIST_LR:
        return 1.0
    lo, hi = math.log(best), 0.0
    for _ in range(30):
        mid = 0.5 * (lo + hi)
        if peak - loglik(math.exp(mid)) <= PERSIST_LR:
            lo = mid
        else:
            hi = mid
    return max(THETA_MIN, math.exp(lo))


# (probability, weight) of the chi-square quantiles used to integrate an estimated variance (midpoint rule on
# [0, .04, .2, .4, .6, .8, 1]); the lowest quantiles give the largest sigmas and dominate a lower tail
_CHI2_POINTS = ((0.02, 0.04), (0.12, 0.16), (0.3, 0.2), (0.5, 0.2), (0.7, 0.2), (0.9, 0.2))


def _normal_quantile(p: float) -> float:
    """Inverse standard normal CDF (Acklam's rational approximation, |error| < 1.2e-9)."""
    a = (
        -39.69683028665376,
        220.9460984245205,
        -275.9285104469687,
        138.3577518672690,
        -30.66479806614716,
        2.506628277459239,
    )
    b = (-54.47609879822406, 161.5858368580409, -155.6989798598866, 66.80131188771972, -13.28068155288572)
    c = (
        -0.007784894002430293,
        -0.3223964580411365,
        -2.400758277161838,
        -2.549732539343734,
        4.374664141464968,
        2.938163982698783,
    )
    d = (0.007784695709041462, 0.3224671290700398, 2.445134137142996, 3.754408661907416)
    if p < 0.02425:
        q = math.sqrt(-2.0 * math.log(p))
        return (((((c[0] * q + c[1]) * q + c[2]) * q + c[3]) * q + c[4]) * q + c[5]) / (
            (((d[0] * q + d[1]) * q + d[2]) * q + d[3]) * q + 1.0
        )
    if p > 1.0 - 0.02425:
        return -_normal_quantile(1.0 - p)
    q = p - 0.5
    r = q * q
    return (
        (((((a[0] * r + a[1]) * r + a[2]) * r + a[3]) * r + a[4]) * r + a[5])
        * q
        / (((((b[0] * r + b[1]) * r + b[2]) * r + b[3]) * r + b[4]) * r + 1.0)
    )


def _log_ndtr(z: float) -> float:
    """``log Phi(z)`` (standard normal CDF), stable deep in the lower tail."""
    if z > -30.0:
        return math.log(max(0.5 * math.erfc(-z / math.sqrt(2.0)), 1e-300))
    return -0.5 * z * z - math.log(-z) - 0.5 * math.log(2.0 * math.pi)


def _sigma_mixture(sigma: float, dof: float) -> list[tuple[float, float]]:
    """``[(log weight, sigma_i)]``: ``sigma`` estimated with ``dof`` degrees of freedom, integrated over the chi-square
    sampling distribution of its variance (Wilson-Hilferty quantiles); a plain ``[(0, sigma)]`` for infinite dof."""
    if not math.isfinite(dof) or dof <= 0:
        return [(0.0, sigma)]
    dof = max(1.0, dof)
    out: list[tuple[float, float]] = []
    for p, w in _CHI2_POINTS:
        z = _normal_quantile(p)
        c = 2.0 / (9.0 * dof)
        chi2 = dof * max(1e-6, 1.0 - c + z * math.sqrt(c)) ** 3
        out.append((math.log(w), sigma * math.sqrt(dof / chi2)))
    return out


def _day_log_sigma(exp_days: Sequence[tuple[float, float]]) -> float:
    """Robust standard deviation of ``log(total / expected)`` over the active baseline days: the variance after
    winsorizing at the median ± 2.5 robust (MAD) standard deviations, minus the Poisson part. Days off are the
    day-off mixture's business and are left out; 0 when fewer than 5 days qualify."""
    logs: list[float] = []
    noise: list[float] = []
    for e, t in exp_days:
        if e >= DAY_SIGMA_MIN_EXPECTED and t > 0:
            logs.append(math.log(t / e))
            noise.append(1.0 / e)
    if len(logs) < 5:
        return 0.0
    center = stats.median(logs)
    spread = 1.4826 * stats.median(abs(x - center) for x in logs)
    lo, hi = center - 2.5 * spread, center + 2.5 * spread
    clipped = [min(hi, max(lo, x)) for x in logs]
    mean = math.fsum(clipped) / len(clipped)
    var = math.fsum((x - mean) ** 2 for x in clipped) / (len(clipped) - 1)
    return math.sqrt(max(0.0, var - stats.median(noise)))


def _stay_curve(runs: Sequence[tuple[int, bool]], pi_off: float) -> tuple[float, ...]:
    """``P(another day off | n days off so far)`` for n = 1..``STAY_CURVE_DAYS`` from runs of days off.

    Kaplan-Meier style (a run still going at the end of the history is censored). Each point is shrunk with
    ``STAY_PRIOR_RUNS`` pseudo-runs toward the previous point (the first one toward the overall continuation rate,
    itself shrunk toward ``pi_off``, i.e. independent days), so where the data thin out the curve carries its last
    well-supported value forward, and the curve never decreases. Vacations make it rise: after three days off, a
    fourth is likely.
    """
    if not runs:
        return ()
    continued = sum(length - 1 for length, _ in runs)
    ended = sum(1 for _, censored in runs if not censored)
    overall = (continued + STAY_PRIOR_RUNS * pi_off) / (continued + ended + STAY_PRIOR_RUNS)
    curve: list[float] = []
    prior = overall
    for n in range(1, STAY_CURVE_DAYS + 1):
        at_risk = sum(1 for length, censored in runs if length > n or (length == n and not censored))
        more = sum(1 for length, _ in runs if length > n)
        # never less likely to continue than after fewer days off (small samples make the raw curve dip)
        prior = max(prior, (more + STAY_PRIOR_RUNS * prior) / (at_risk + STAY_PRIOR_RUNS))
        curve.append(prior)
    return tuple(curve)


def _spike_factors(base_days: Sequence[tuple[int, float]], day_dow: Sequence[int]) -> dict[int, float]:
    """Scale factors (< 1) for one-off spike days of a baseline.

    A day above ``SPIKE_DAY_FACTOR`` × the median active day is capped at that level unless another baseline day on
    the same weekday reached at least half of it (a weekly batch job is a pattern, not a spike).
    """
    active = [t for _, t in base_days if t > 0]
    if len(active) < MIN_SPIKE_DAYS:
        return {}
    cap = SPIKE_DAY_FACTOR * stats.median(active)
    out: dict[int, float] = {}
    for j, total in base_days:
        if total <= cap:
            continue
        if any(j2 != j and day_dow[j2] == day_dow[j] and t2 >= 0.5 * total for j2, t2 in base_days):
            continue
        out[j] = cap / total
    return out


def _own_hod_dow(cc: Sequence[float], ex: Sequence[int]) -> tuple[list[float], list[float]]:
    """A key's own hour-of-day profile and day-of-week factors (both normalized to mean 1)."""
    hod = _normalize([_ratio(sum(cc[h::24]), sum(ex[h::24])) for h in range(24)])
    dow = _normalize([_ratio(sum(cc[d * 24 : d * 24 + 24]), sum(ex[d * 24 : d * 24 + 24])) for d in range(7)])
    return hod, dow


def _normalize(values: Sequence[float]) -> list[float]:
    """Scale to mean 1 (a flat profile when everything is zero)."""
    total = math.fsum(values)
    if total <= 0 or not values:
        return [1.0] * len(values)
    factor = len(values) / total
    return [v * factor for v in values]


def _max_tier(a: str, b: str) -> str:
    return a if _TIER_RANK.get(a, 1) >= _TIER_RANK.get(b, 1) else b


def _max_tier_of(tiers: Iterable[str]) -> str:
    best = "low"
    for tier in tiers:
        best = _max_tier(best, tier)
    return best


def _critical_count(evals: Iterable[_KeyEval]) -> int:
    return sum(1 for ev in evals if ev.tier == "critical" and ev.level == "agent")


def _quoted(value: str) -> str:
    """A value for the ``field:"value"`` reproduce hint: backslashes and quotes escaped (Lucene/DQL), so a log source
    name cannot close the quote and turn the hint into a different query. Host entities are left to the renderer
    (they may be pseudonymized)."""
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _esc(component: str) -> str:
    """Subject component: ``|`` separates components, so it is percent-encoded (a spoofed syslog hostname such as
    ``dc01|ls:Security`` must not produce the subject, and so the fingerprint, of another key)."""
    return component.replace("|", "%7C")


def _subject(level: str, key: tuple[str, ...]) -> str:
    if level == "tenant":
        return f"tenant:{_esc(key[0])}"
    if level == "log_source":
        return f"ls:{_esc(key[0])}"
    if level == "agent":
        return f"agent:{_esc(key[0])}"
    if level == "agent_log_source":
        return f"agent:{_esc(key[0])}|ls:{_esc(key[1])}"
    return f"rule:{_esc(key[0])}"


def _key_dict(level: str, key: tuple[str, ...]) -> dict[str, Any]:
    if level == "tenant":
        return {"tenant": key[0]}
    if level == "log_source":
        return {"log_source": key[0]}
    if level == "agent":
        return {"agent": Entity("host", key[0])}
    if level == "agent_log_source":
        return {"agent": Entity("host", key[0]), "log_source": key[1]}
    return {"rule_id": key[0]}


def _key_message(level: str, key: tuple[str, ...]) -> Message:
    if level == "tenant":
        return M("silence.key.tenant", tenant=key[0])
    if level == "log_source":
        return M("silence.key.log_source", log_source=key[0])
    if level == "agent":
        return M("silence.key.agent", agent=Entity("host", key[0]))
    if level == "agent_log_source":
        return M("silence.key.agent_log_source", agent=Entity("host", key[0]), log_source=key[1])
    return M("silence.key.rule", rule_id=key[0])


def _wazuh_ls_field(log_source: str) -> str:
    """Wazuh 4.x log_source is ``data.win.system.channel`` for Windows events, else ``location``."""
    lowered = log_source.lower()
    if lowered in _WIN_CHANNELS or lowered.startswith("microsoft-"):
        return "data.win.system.channel"
    return "location"


# ---- messages ------------------------------------------------------------------------------------------------------

register(
    {
        # key descriptions (no article in Spanish: templates put them in parentheses or after a colon)
        "silence.key.tenant": {"en": "all sources of tenant {tenant}", "es": "todas las fuentes del tenant {tenant}"},
        "silence.key.log_source": {"en": "log source {log_source}", "es": "fuente de logs {log_source}"},
        "silence.key.agent": {"en": "agent {agent}", "es": "agente {agent}"},
        "silence.key.agent_log_source": {"en": "{log_source} on {agent}", "es": "{log_source} en {agent}"},
        "silence.key.rule": {"en": "rule {rule_id}", "es": "regla {rule_id}"},
        # vocabulary
        "silence.duty.always_on": {"en": "always on", "es": "siempre activa"},
        "silence.duty.business_hours": {"en": "business hours", "es": "horario laboral"},
        "silence.duty.intermittent": {"en": "intermittent", "es": "intermitente"},
        "silence.duty.unknown": {"en": "unknown activity pattern", "es": "patrón de actividad desconocido"},
        "silence.tier.critical": {"en": "critical", "es": "crítico"},
        "silence.tier.standard": {"en": "standard", "es": "estándar"},
        "silence.tier.low": {"en": "low", "es": "bajo"},
        "silence.model.hour_of_day": {
            "en": "hour-of-day × weekday profile",
            "es": "perfil por hora del día × día de la semana",
        },
        "silence.model.hour_of_week": {"en": "hour-of-week profile", "es": "perfil por hora de la semana"},
        "silence.agent_status.active": {"en": "active", "es": "activo"},
        "silence.agent_status.disconnected": {"en": "disconnected", "es": "desconectado"},
        "silence.agent_status.never_connected": {"en": "never connected", "es": "nunca conectado"},
        "silence.agent_status.pending": {"en": "pending", "es": "pendiente"},
        "silence.agent_status.unknown": {"en": "unknown", "es": "desconocido"},
        "silence.origin.data": {"en": "the data itself", "es": "los propios datos"},
        "silence.origin.flag": {"en": "the --now option", "es": "la opción --now"},
        "silence.origin.wallclock": {"en": "the system clock", "es": "el reloj del sistema"},
        "silence.when.before": {
            "en": "{minutes} min before the silence began",
            "es": "{minutes} min antes de que empezara el silencio",
        },
        "silence.when.after": {
            "en": "{minutes} min after the silence began",
            "es": "{minutes} min después de que empezara el silencio",
        },
        # filters (reproduce hints; field names are never translated)
        "silence.filter.all": {"en": "all events of the tenant", "es": "todos los eventos del tenant"},
        "silence.filter.one": {"en": '{field}:"{value}"', "es": '{field}:"{value}"'},
        "silence.filter.two": {
            "en": '{field1}:"{value1}" AND {field2}:"{value2}"',
            "es": '{field1}:"{value1}" AND {field2}:"{value2}"',
        },
        # titles
        "silence.title.silent": {
            "en": "Silent source: {key} has sent no events for {gap}",
            "es": "Fuente en silencio ({key}): ningún evento desde hace {gap}",
        },
        "silence.title.drop": {
            "en": "Volume drop: {key} sent {observed} events in the last {hours} h, about {expected:,.0f} expected",
            "es": "Caída de volumen ({key}): {observed} eventos en las últimas {hours} h, frente a unos "
            "{expected:,.0f} esperados",
        },
        "silence.title.decay": {
            "en": "Sustained decline: the daily volume of {key} fell to {ratio:.0%} of its reference",
            "es": "Descenso sostenido ({key}): el volumen diario bajó al {ratio:.0%} de su referencia",
        },
        "silence.title.rule_dark": {
            "en": "Detection went dark: rule {rule_id} has not fired for {gap} while its sources keep sending",
            "es": "Detección apagada: la regla {rule_id} no se dispara desde hace {gap} aunque sus fuentes siguen "
            "enviando",
        },
        "silence.title.tampering": {
            "en": "Possible log tampering: {key} went quiet right after {precursor}",
            "es": "Posible manipulación de registros ({key}): silencio justo después de {precursor}",
        },
        "silence.title.unmonitorable": {
            "en": "Critical source not monitorable by volume: {key} needs about {t_min} of silence before it can be "
            "detected (SLA {sla})",
            "es": "Fuente crítica no vigilable por volumen ({key}): hacen falta unas {t_min} de silencio para "
            "detectarlo (SLA {sla})",
        },
        "silence.title.unmonitorable_channels": {
            "en": "Some log sources of critical agent {agent} are too sparse to detect silence within {sla}",
            "es": "Algunas fuentes de logs del agente crítico {agent} son demasiado escasas para detectar un silencio "
            "en menos de {sla}",
        },
        "silence.title.global_silence": {
            "en": "{count} of {total} agents went silent together around {start}: likely a collection or ingestion "
            "problem",
            "es": "{count} de {total} agentes quedaron en silencio a la vez hacia las {start}: probable problema de "
            "recolección o ingesta",
        },
        "silence.title.global_mixed": {
            "en": "{count} of {total} agents went silent or lost most of their events together around {start}: likely "
            "a collection or ingestion problem",
            "es": "{count} de {total} agentes quedaron en silencio o perdieron la mayor parte de sus eventos a la vez "
            "hacia las {start}: probable problema de recolección o ingesta",
        },
        "silence.title.global_tenant": {
            "en": "Every source of tenant {tenant} went silent at {start}: collection or ingestion is down",
            "es": "Todas las fuentes del tenant {tenant} quedaron en silencio a las {start}: la recolección o la "
            "ingesta está caída",
        },
        "silence.title.global_drop": {
            "en": "Tenant-wide volume drop: {tenant} received {observed} events in the last {hours} h, about "
            "{expected:,.0f} expected",
            "es": "Caída de volumen en todo el tenant {tenant}: {observed} eventos en las últimas {hours} h, frente a "
            "unos {expected:,.0f} esperados",
        },
        "silence.title.learning": {
            "en": "Silence baselines still learning (less than {days} days of history): {count}",
            "es": "Líneas base de silencio aún en aprendizaje (menos de {days} días de historial): {count}",
        },
        "silence.title.nothing_evaluable": {
            "en": "Silence could not be assessed: no source has {days} days of usable history yet",
            "es": "No se pudo evaluar el silencio: ninguna fuente tiene todavía {days} días de historial utilizable",
        },
        "silence.title.truncated": {
            "en": "Silence analysis incomplete: the key cap ({max_keys}) was reached and {dropped} events were not "
            "tracked",
            "es": "Análisis de silencio incompleto: se alcanzó el límite de claves ({max_keys}) y {dropped} eventos no "
            "se contabilizaron",
        },
        # reasons
        "silence.reason.p0": {
            "en": "At its usual rate about {expected:,.1f} events were expected since the last one ({last_seen}); "
            "the probability of seeing none is {p0:.1e} (alarm threshold {alpha:.1e}).",
            "es": "Con su ritmo habitual se esperaban unos {expected:,.1f} eventos desde el último ({last_seen}); la "
            "probabilidad de no ver ninguno es {p0:.1e} (umbral de alarma {alpha:.1e}).",
        },
        "silence.reason.drop": {
            "en": "Observed {observed} events vs about {expected:,.0f} expected ({ratio:.0%}); negative-binomial "
            "lower tail p = {p:.1e} (threshold {alpha:.1e}).",
            "es": "Se observaron {observed} eventos frente a unos {expected:,.0f} esperados ({ratio:.0%}); cola "
            "inferior binomial negativa p = {p:.1e} (umbral {alpha:.1e}).",
        },
        "silence.reason.drop_since": {
            "en": "Since the drop began (about {since}): {observed} events vs about {expected:,.0f} expected "
            "({ratio:.0%}).",
            "es": "Desde que empezó la caída (hacia {since}): {observed} eventos frente a unos {expected:,.0f} "
            "esperados ({ratio:.0%}).",
        },
        "silence.reason.decay": {
            "en": "Median of the last 7 days: {recent:,.0f} events/day vs {reference:,.0f} over the {ref_days} "
            "previous days (p = {p:.1e}).",
            "es": "Mediana de los últimos 7 días: {recent:,.0f} eventos/día frente a {reference:,.0f} en los "
            "{ref_days} días anteriores (p = {p:.1e}).",
        },
        "silence.reason.decay_days": {
            "en": "Over the last {days} days it sent {ratio:.0%} of the volume expected from the {ref_days} earlier "
            "days (p = {p:.1e}): a sustained loss the rolling baseline would soon absorb.",
            "es": "En los últimos {days} días envió el {ratio:.0%} del volumen esperado según los {ref_days} días "
            "anteriores (p = {p:.1e}): una pérdida sostenida que la línea base móvil pronto absorbería.",
        },
        "silence.reason.profile": {
            "en": "Profile: {duty}, tier {tier}, {days} days of baseline ({model}), dispersion k = {k:.1f}.",
            "es": "Perfil: {duty}, nivel {tier}, {days} días de línea base ({model}), dispersión k = {k:.1f}.",
        },
        "silence.reason.bursty": {
            "en": "This source is bursty: once quiet it tends to stay quiet (its lulls last about {factor:,.1f}× "
            "longer than independent hours would give), and the test allows for that.",
            "es": "Esta fuente funciona a ráfagas: cuando se queda en silencio tiende a seguir así (sus pausas duran "
            "unas {factor:,.1f} veces más de lo que darían horas independientes), y la prueba lo tiene en cuenta.",
        },
        "silence.reason.days_off": {
            "en": "This source skips whole days now and then (about {share:.0%} of its days, learnt from it and its "
            "peers), so a missing day weighs less than missing hours.",
            "es": "Esta fuente se salta días completos de vez en cuando (alrededor del {share:.0%} de sus días, "
            "aprendido de ella y de sus pares), así que un día sin eventos pesa menos que unas horas sin eventos.",
        },
        "silence.reason.alerts_only": {
            "en": "Measured on alerts only (no archives): this is alert silence, which does not always mean the "
            "source stopped logging.",
            "es": "Medido solo sobre alertas (sin archives): es silencio de alertas, lo que no siempre significa que "
            "la fuente haya dejado de registrar.",
        },
        "silence.reason.partial_input": {
            "en": "The input had partial failures or was sampled; confirm in the SIEM before acting.",
            "es": "La entrada tuvo fallos parciales o fue muestreada; confírmelo en el SIEM antes de actuar.",
        },
        "silence.reason.explained": {
            "en": "Related sources that also went quiet and are explained by this finding (not reported separately): "
            "{count}.",
            "es": "Fuentes relacionadas que también quedaron en silencio y que este hallazgo explica (no se reportan "
            "por separado): {count}.",
        },
        "silence.reason.precursor": {
            "en": "Precursor: {what} on {agent} at {ts} (rule {rule_id}), {when}.",
            "es": "Precursor: {what} en {agent} a las {ts} (regla {rule_id}), {when}.",
        },
        "silence.reason.sources_alive": {
            "en": "Its log sources are still sending ({alive} of {total} alive), so the rule itself stopped matching: "
            "check decoder and ruleset changes and recent suppressions.",
            "es": "Sus fuentes de logs siguen enviando ({alive} de {total} activas), así que es la regla la que dejó "
            "de coincidir: revise cambios en decoders y reglas y las supresiones recientes.",
        },
        "silence.reason.agent_active": {
            "en": "The Wazuh API reports the agent as {status} with a recent keepalive ({keepalive}): the agent is "
            "connected but its events are not arriving, so log collection is broken.",
            "es": "Según la API de Wazuh el agente está {status} y con un keepalive reciente ({keepalive}): está "
            "conectado pero sus eventos no llegan, así que la recolección de logs está rota.",
        },
        "silence.reason.agent_active_alerts": {
            "en": "The Wazuh API reports the agent as {status} with a recent keepalive ({keepalive}): it is connected, "
            "so its alerts stopped for another reason (log collection, decoders/rules, or the activity itself).",
            "es": "Según la API de Wazuh el agente está {status} y con un keepalive reciente ({keepalive}): está "
            "conectado, así que sus alertas se detuvieron por otro motivo (recolección de logs, decoders/reglas o la "
            "propia actividad).",
        },
        "silence.reason.agent_disconnected": {
            "en": "The Wazuh API reports the agent as {status} (last keepalive {keepalive}).",
            "es": "Según la API de Wazuh el agente está {status} (último keepalive {keepalive}).",
        },
        "silence.reason.agent_unregistered": {
            "en": "This host is not in the Wazuh API agent list: it is either a device that reports through the "
            "manager (syslog) or a retired agent. If it was retired, accept this finding.",
            "es": "Este equipo no figura en la lista de agentes de la API de Wazuh: o bien es un dispositivo que "
            "reporta a través del manager (syslog) o bien un agente dado de baja. Si se dio de baja, acepte este "
            "hallazgo.",
        },
        "silence.reason.global": {
            "en": "{count} agents ({share:.0%} of {total}) stopped sending within two hours of each other, between "
            "{start} and {end}.",
            "es": "{count} agentes ({share:.0%} de {total}) dejaron de enviar con menos de dos horas de diferencia, "
            "entre {start} y {end}.",
        },
        "silence.reason.global_mixed": {
            "en": "{count} agents ({share:.0%} of {total}) stopped sending or lost most of their volume within two "
            "hours of each other, between {start} and {end} (an EPS limit, a full queue or an indexer problem affects "
            "every agent at once).",
            "es": "{count} agentes ({share:.0%} de {total}) dejaron de enviar o perdieron la mayor parte de su volumen "
            "con menos de dos horas de diferencia, entre {start} y {end} (un límite de EPS, una cola llena o un "
            "problema del indexador afecta a todos los agentes a la vez).",
        },
        "silence.reason.stale_now": {
            "en": "The reference time comes from {origin}; if the input is an old export, run again with --now set "
            "to its end.",
            "es": "La hora de referencia proviene de {origin}; si la entrada es una exportación antigua, vuelva a "
            "ejecutar con --now en su fecha final.",
        },
        "silence.reason.unmonitorable": {
            "en": "With its normal traffic ({rate:,.2f} events/h) a silence becomes statistically detectable only "
            "after about {t_min}; the SLA for tier {tier} is {sla}.",
            "es": "Con su tráfico normal ({rate:,.2f} eventos/h) un silencio solo es detectable estadísticamente "
            "tras unas {t_min}; el SLA del nivel {tier} es {sla}.",
        },
        "silence.reason.learning": {
            "en": "Keys still learning: {count} (critical agents among them: {critical}). A key is evaluated once it "
            "has {days} days of history; until then its silence is not assessed.",
            "es": "Claves aún en aprendizaje: {count} (agentes críticos entre ellas: {critical}). Cada clave se "
            "evalúa cuando tiene {days} días de historial; hasta entonces su silencio no se evalúa.",
        },
        "silence.reason.truncated": {
            "en": "Sources that did not fit in the cube were not evaluated, so their silence is unknown.",
            "es": "Las fuentes que no cupieron en el cubo no se evaluaron, así que se desconoce si están en silencio.",
        },
        # recommendations
        "silence.rec.silent": {
            "en": "Check the agent and its log collection for {key}, and confirm in the SIEM with {filter} since "
            "{since}.",
            "es": "Revise el agente y su recolección de logs ({key}) y confírmelo en el SIEM con {filter} desde "
            "{since}.",
        },
        "silence.rec.drop": {
            "en": "Compare {key} with its usual volume in the SIEM ({filter}, since {since}): look for audit-policy, "
            "agent-configuration or collector changes.",
            "es": "Compare el volumen actual con el habitual en el SIEM ({key}; {filter}, desde {since}): busque "
            "cambios en la directiva de auditoría, en la configuración del agente o en el colector.",
        },
        "silence.rec.decay": {
            "en": "Review what changed on {key} over the last weeks ({filter}): audit policy, agent configuration, "
            "log rotation or filters. A gradual loss of logging can hide defense evasion.",
            "es": "Revise qué cambió en las últimas semanas ({key}; {filter}): directiva de auditoría, configuración "
            "del agente, rotación de logs o filtros. Una pérdida gradual de registros puede ocultar una evasión de "
            "defensas.",
        },
        "silence.rec.tampering": {
            "en": "Treat this as a potential incident: check {key} for log clearing, audit-policy changes or stopped "
            "agents/Sysmon, preserve evidence, and only then restore collection.",
            "es": "Trátelo como un posible incidente: revise el equipo afectado ({key}) en busca de borrado de logs, "
            "cambios en la directiva de auditoría o agentes/Sysmon detenidos, preserve las evidencias y solo después "
            "restablezca la recolección.",
        },
        "silence.rec.rule_dark": {
            "en": "Replay a recent sample through wazuh-logtest for rule {rule_id}, review decoder/ruleset changes and "
            "local suppressions, and confirm with {filter}.",
            "es": "Reproduzca una muestra reciente con wazuh-logtest para la regla {rule_id}, revise cambios en "
            "decoders/reglas y supresiones locales, y confírmelo con {filter}.",
        },
        "silence.rec.unmonitorable": {
            "en": "Add a heartbeat for {key} (agent keepalive monitoring, a scheduled canary event or periodic command "
            "output) so its silence can be detected within the SLA.",
            "es": "Añada un latido (heartbeat) a esta fuente ({key}): vigilancia del keepalive del agente, un evento "
            "canario programado o la salida periódica de un comando, para poder detectar su silencio dentro del SLA.",
        },
        "silence.rec.global": {
            "en": "Check the manager, indexer and ingestion pipeline first (disk space, read-only indices, shard "
            "limits, remoted/analysisd drops, Filebeat) before investigating individual agents.",
            "es": "Revise primero el manager, el indexador y la canalización de ingesta (espacio en disco, índices en "
            "solo lectura, límite de shards, descartes de remoted/analysisd, Filebeat) antes de investigar agentes "
            "individuales.",
        },
        "silence.rec.learning": {
            "en": "Keep collecting data: a source is evaluated once it has enough history. Until then its silence is "
            "not assessed (shown grey, never as OK).",
            "es": "Siga recopilando datos: una fuente se evalúa cuando tiene historial suficiente. Hasta entonces su "
            "silencio no se evalúa (se muestra en gris, nunca como OK).",
        },
        "silence.rec.truncated": {
            "en": "Raise silence.max_keys or narrow the input (fewer tenants or index patterns per run).",
            "es": "Aumente silence.max_keys o acote la entrada (menos tenants o patrones de índice por ejecución).",
        },
        # tampering precursors (noun phrases: they are used after "right after" / "Precursor:")
        "silence.precursor.win_1102": {
            "en": "a Security log clear (EventID 1102)",
            "es": "un borrado del registro de Seguridad (EventID 1102)",
        },
        "silence.precursor.win_104": {
            "en": "an event log clear (EventID 104)",
            "es": "un borrado de un registro de eventos (EventID 104)",
        },
        "silence.precursor.win_1100": {
            "en": "an event logging service shutdown (EventID 1100)",
            "es": "una parada del servicio de registro de eventos (EventID 1100)",
        },
        "silence.precursor.win_4719": {
            "en": "a system audit policy change (EventID 4719)",
            "es": "un cambio en la directiva de auditoría del sistema (EventID 4719)",
        },
        "silence.precursor.win_4906": {
            "en": "a CrashOnAuditFail change (EventID 4906)",
            "es": "un cambio del valor CrashOnAuditFail (EventID 4906)",
        },
        "silence.precursor.sysmon_4": {
            "en": "a Sysmon service state change (Sysmon EventID 4)",
            "es": "un cambio de estado del servicio Sysmon (Sysmon EventID 4)",
        },
        "silence.precursor.sysmon_16": {
            "en": "a Sysmon configuration change (Sysmon EventID 16)",
            "es": "un cambio de configuración de Sysmon (Sysmon EventID 16)",
        },
        "silence.precursor.wazuh_506": {
            "en": "a Wazuh agent stop (rule 506)",
            "es": "una parada del agente Wazuh (regla 506)",
        },
        "silence.precursor.wazuh_504": {
            "en": "a Wazuh agent disconnection (rule 504)",
            "es": "una desconexión del agente Wazuh (regla 504)",
        },
        "silence.precursor.wazuh_202": {
            "en": "a filling Wazuh agent event queue (rule 202)",
            "es": "una cola de eventos del agente Wazuh casi llena (regla 202)",
        },
        "silence.precursor.wazuh_203": {
            "en": "a full Wazuh agent event queue, with events possibly lost (rule 203)",
            "es": "una cola de eventos del agente Wazuh llena, con posible pérdida de eventos (regla 203)",
        },
        "silence.precursor.wazuh_204": {
            "en": "a flooded Wazuh agent event queue (rule 204)",
            "es": "una cola de eventos del agente Wazuh desbordada (regla 204)",
        },
        "silence.precursor.auditd_config": {
            "en": "an auditd configuration change",
            "es": "un cambio en la configuración de auditd",
        },
        "silence.precursor.auditd_stop": {"en": "an auditd daemon stop", "es": "una parada del demonio auditd"},
    }
)
