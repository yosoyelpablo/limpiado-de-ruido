"""Tests for hushwatch.state: finding lifecycle, hysteresis, flapping, reminders, accept file, privacy, concurrency."""

from __future__ import annotations

import os
import sqlite3
import stat
import subprocess
import sys
import textwrap
import threading
from collections.abc import Iterator
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from hushwatch.i18n import Entity, M, Message, register, render
from hushwatch.models import Finding, Severity
from hushwatch.state import (
    STATE_FILENAME,
    AcceptEntry,
    AcceptFileError,
    AcceptList,
    StateError,
    StateStore,
    load_accept_file,
    parse_accept,
)

UTC = timezone.utc
T0 = datetime(2026, 9, 1, tzinfo=UTC)
HOUR = timedelta(hours=1)
TENANT = "acme"
REPO = Path(__file__).resolve().parents[1]

register(
    {
        "test.state.title": {
            "en": "{host} stopped sending {channel} events ({n} expected)",
            "es": "{host} dejó de enviar eventos {channel} ({n} esperados)",
        },
        "test.state.login": {"en": "{user} logged in from {ip}: {raw}", "es": "{user} inició sesión desde {ip}: {raw}"},
    }
)


def make_finding(
    kind: str = "coverage.missing_source",
    severity: Severity = Severity.MEDIUM,
    *,
    host: str = "srv-web-01.example",
    tenant: str | None = TENANT,
    subject: str | None = None,
) -> Finding:
    return Finding(
        kind=kind,
        domain=kind.split(".", 1)[0],
        title=M("test.state.title", host=Entity("host", host), channel="Security", n=12),
        severity=severity,
        subject=subject if subject is not None else f"agent:{host}|ls:Security",
        tenant=tenant,
        evidence={"host": Entity("host", host), "ip": Entity("ip", "198.51.100.23")},
    )


@pytest.fixture
def store(tmp_path: Path) -> Iterator[StateStore]:
    s = StateStore(tmp_path / "state" / STATE_FILENAME)
    yield s
    s.close()


def run_pattern(
    store: StateStore, pattern: str, finding: Finding, *, step: timedelta = HOUR, start: datetime = T0, **kwargs: object
) -> list[list[str]]:
    """P = the finding is reported by the run, A = absent. Returns transition types per run."""
    result = []
    for i, mark in enumerate(pattern):
        outcome = store.record_run(TENANT, [finding] if mark == "P" else [], now=start + i * step, **kwargs)  # type: ignore[arg-type]
        result.append([t.type for t in outcome.transitions])
    return result


# ---- lifecycle (table-driven) --------------------------------------------------------------------------------

LIFECYCLE_CASES = [
    # id, kind, severity, pattern, kwargs, expected transition types per run
    ("hysteresis_opens_on_second_run", "coverage.missing_source", Severity.MEDIUM, "PP", {}, [[], ["opened"]]),
    ("open_after_3", "coverage.missing_source", Severity.MEDIUM, "PPP", {"open_after": 3}, [[], [], ["opened"]]),
    ("open_after_1", "coverage.missing_source", Severity.LOW, "P", {"open_after": 1}, [["opened"]]),
    ("single_blips_never_open", "coverage.missing_source", Severity.HIGH, "PAPAPA", {}, [[]] * 6),
    ("immediate_kind_silent", "silence.silent", Severity.HIGH, "P", {}, [["opened"]]),
    ("immediate_kind_tampering", "silence.tampering", Severity.HIGH, "P", {}, [["opened"]]),
    ("immediate_kind_global_silence", "pipeline.global_silence", Severity.HIGH, "P", {}, [["opened"]]),
    ("immediate_kind_incomplete", "assessment.incomplete", Severity.HIGH, "P", {}, [["opened"]]),
    ("critical_opens_immediately", "coverage.missing_source", Severity.CRITICAL, "P", {}, [["opened"]]),
    (
        "critical_immediate_disabled",
        "coverage.missing_source",
        Severity.CRITICAL,
        "PP",
        {"critical_immediate": False},
        [[], ["opened"]],
    ),
    (
        "custom_immediate_kinds",
        "silence.silent",
        Severity.HIGH,
        "PP",
        {"immediate_kinds": ()},
        [[], ["opened"]],
    ),
    (
        "resolve_needs_two_clean_runs",
        "coverage.missing_source",
        Severity.MEDIUM,
        "PPAA",
        {},
        [[], ["opened"], [], ["resolved"]],
    ),
    (
        "resolve_interrupted_by_reappearance",
        "coverage.missing_source",
        Severity.MEDIUM,
        "PPAPAA",
        {},
        [[], ["opened"], [], [], [], ["resolved"]],
    ),
    (
        "resolve_after_1",
        "coverage.missing_source",
        Severity.MEDIUM,
        "PPA",
        {"resolve_after": 1},
        [[], ["opened"], ["resolved"]],
    ),
    (
        "regression_with_hysteresis",
        "coverage.missing_source",
        Severity.MEDIUM,
        "PPAAPP",
        {"step": timedelta(hours=6)},
        [[], ["opened"], [], ["resolved"], [], ["regressed"]],
    ),
    (
        "immediate_regression",
        "silence.silent",
        Severity.HIGH,
        "PAAP",
        {"step": timedelta(hours=12)},
        [["opened"], [], ["resolved"], ["regressed"]],
    ),
    (
        # opened + resolved + regressed within 24 h is the third change: reported once as flapping
        "quick_regression_is_flapping",
        "silence.silent",
        Severity.HIGH,
        "PAAP",
        {},
        [["opened"], [], ["resolved"], ["flapping"]],
    ),
    ("pending_then_gone_is_silent", "coverage.missing_source", Severity.MEDIUM, "PAAAAP", {}, [[]] * 6),
    ("steady_open_is_quiet", "coverage.missing_source", Severity.HIGH, "PPPPPP", {}, [[], ["opened"], [], [], [], []]),
]


@pytest.mark.parametrize(
    ("kind", "severity", "pattern", "kwargs", "expected"),
    [c[1:] for c in LIFECYCLE_CASES],
    ids=[c[0] for c in LIFECYCLE_CASES],
)
def test_lifecycle_table(
    store: StateStore, kind: str, severity: Severity, pattern: str, kwargs: dict[str, Any], expected: list[list[str]]
) -> None:
    assert run_pattern(store, pattern, make_finding(kind, severity), **kwargs) == expected


def test_status_values_follow_lifecycle(store: StateStore) -> None:
    finding = make_finding()
    statuses = []
    for i, mark in enumerate("PPAAPP"):
        store.record_run(TENANT, [finding] if mark == "P" else [], now=T0 + i * HOUR)
        state = store.get(TENANT, finding.fingerprint)
        assert state is not None
        statuses.append(state.status)
    assert statuses == ["new", "open", "open", "resolved", "resolved", "regressed"]
    final = store.get(TENANT, finding.fingerprint)
    assert final is not None
    assert final.times_opened == 2 and final.regressions == 1
    assert final.opened_at == T0 + 5 * HOUR and final.resolved_at == T0 + 3 * HOUR


def test_counts(store: StateStore) -> None:
    crit = make_finding("silence.silent", Severity.CRITICAL, host="dc01.corp.example")
    pending = make_finding("coverage.missing_source", Severity.MEDIUM)
    outcome = store.record_run(TENANT, [crit, pending], now=T0)
    assert outcome.counts["findings"] == 2
    assert outcome.counts["open"] == 1 and outcome.counts["open.critical"] == 1
    assert outcome.counts["pending"] == 1
    assert outcome.transition_counts["opened"] == 1
    assert [t.fingerprint for t in outcome.opened] == [crit.fingerprint]
    assert outcome.resolved == [] and outcome.regressed == [] and outcome.reminders == []


def test_duplicate_fingerprints_are_merged_keeping_highest_severity(store: StateStore) -> None:
    low = make_finding("coverage.missing_source", Severity.LOW)
    crit = make_finding("coverage.missing_source", Severity.CRITICAL)
    assert low.fingerprint == crit.fingerprint
    outcome = store.record_run(TENANT, [low, crit, low], now=T0)
    assert [t.type for t in outcome.transitions] == ["opened"]
    assert outcome.transitions[0].severity is Severity.CRITICAL
    assert outcome.counts["findings"] == 1


def test_findings_of_another_tenant_are_ignored(store: StateStore) -> None:
    foreign = make_finding("silence.silent", Severity.CRITICAL, tenant="other")
    outcome = store.record_run(TENANT, [foreign], now=T0)
    assert outcome.transitions == [] and outcome.counts["ignored"] == 1
    assert store.findings(TENANT) == []


def test_tenants_are_isolated(store: StateStore) -> None:
    a = make_finding("silence.silent", Severity.HIGH, tenant="acme")
    b = make_finding("silence.silent", Severity.HIGH, tenant="globex")
    assert store.record_run("acme", [a], now=T0).opened
    assert store.record_run("globex", [b], now=T0).opened
    assert store.record_run("acme", [], now=T0 + HOUR).transitions == []
    assert [s.fingerprint for s in store.open_findings("globex")] == [b.fingerprint]


def test_severity_update_is_stored(store: StateStore) -> None:
    run_pattern(store, "PP", make_finding(severity=Severity.MEDIUM))
    store.record_run(TENANT, [make_finding(severity=Severity.HIGH)], now=T0 + 2 * HOUR)
    state = store.get(TENANT, make_finding().fingerprint)
    assert state is not None and state.severity is Severity.HIGH


# ---- flapping --------------------------------------------------------------------------------------------------


def test_flapping_notifies_once_then_groups_until_stable(store: StateStore) -> None:
    finding = make_finding("silence.silent", Severity.HIGH)
    got = run_pattern(store, "PAPAPAP", finding, resolve_after=1)
    assert got == [["opened"], ["resolved"], ["flapping"], [], [], [], []]
    outcome = store.record_run(TENANT, [finding], now=T0 + 7 * HOUR, resolve_after=1)
    assert outcome.counts["flapping"] == 1
    state = store.get(TENANT, finding.fingerprint)
    assert state is not None and state.flapping
    # stable (continuously present) for a full window: the flag clears without a new notification
    quiet = [store.record_run(TENANT, [finding], now=T0 + h * HOUR, resolve_after=1).transitions for h in range(8, 32)]
    assert all(t == [] for t in quiet)
    state = store.get(TENANT, finding.fingerprint)
    assert state is not None and not state.flapping and state.status == "regressed"
    # once stable, lifecycle notifications resume
    outcome = store.record_run(TENANT, [], now=T0 + 32 * HOUR, resolve_after=1)
    assert [t.type for t in outcome.transitions] == ["resolved"]


def test_flapping_transition_carries_detail(store: StateStore) -> None:
    finding = make_finding("silence.silent", Severity.HIGH)
    run_pattern(store, "PA", finding, resolve_after=1)
    outcome = store.record_run(TENANT, [finding], now=T0 + 2 * HOUR, resolve_after=1)
    (flap,) = outcome.flapping
    assert flap.flapping and flap.status == "regressed"
    assert isinstance(flap.detail, Message)
    assert "3" in render(flap.detail, "en") and "24" in render(flap.detail, "es")


def test_flapping_threshold_is_configurable(store: StateStore) -> None:
    finding = make_finding("silence.silent", Severity.HIGH)
    got = run_pattern(store, "PAPAP", finding, resolve_after=1, flap_threshold=5)
    assert got == [["opened"], ["resolved"], ["regressed"], ["resolved"], ["flapping"]]


def test_slow_changes_are_not_flapping(store: StateStore) -> None:
    finding = make_finding("silence.silent", Severity.HIGH)
    got = run_pattern(store, "PAPAP", finding, step=timedelta(hours=13), resolve_after=1)
    assert got == [["opened"], ["resolved"], ["regressed"], ["resolved"], ["regressed"]]


# ---- lifecycle invariants under random orders of events -----------------------------------------------------------


@pytest.mark.parametrize("seed", range(24))
def test_receiver_view_matches_the_lifecycle_under_random_runs(tmp_path: Path, seed: int) -> None:
    """Replay random runs (present / absent / domain not assessed / random severity / lost deliveries) and check
    that what a receiver was told always matches the stored lifecycle once the finding is not flapping:
    no "resolved" while the run reports the finding, no unannounced escalation, no stale "still open"."""
    import random

    rng = random.Random(seed)
    kind = rng.choice(["coverage.missing_source", "silence.silent"])
    kwargs = {"open_after": rng.randint(1, 3), "resolve_after": rng.randint(1, 3)}
    view: str | None = None
    view_severity: Severity | None = None
    now = T0
    with StateStore(tmp_path / "s.sqlite3") as store:
        for _ in range(40):
            now += timedelta(minutes=rng.choice([15, 60, 240, 900]))
            mark = rng.choice("PPAAN")
            severity = rng.choice(list(Severity)) if rng.random() < 0.4 else Severity.MEDIUM
            finding = make_finding(kind, severity)
            outcome = store.record_run(
                TENANT,
                [finding] if mark == "P" else [],
                now=now,
                assessed={"noise"} if mark == "N" else None,
                **kwargs,  # type: ignore[arg-type]
            )
            lost = bool(outcome.transitions) and rng.random() < 0.25
            if lost:
                store.mark_undelivered(TENANT, outcome.run_id)
            for t in [] if lost else outcome.transitions:
                assert not (t.type == "resolved" and mark == "P")
                if t.type == "escalated":
                    assert t.previous_severity is not None and t.previous_severity.rank < t.severity.rank
                if t.status in ("open", "regressed"):
                    view, view_severity = "active", t.severity
                elif t.status == "resolved":
                    view = "resolved"
            state = store.get(TENANT, finding.fingerprint)
            if state is None or state.flapping or lost:
                continue
            phase = {"open": "active", "regressed": "active", "resolved": "resolved"}.get(state.status)
            if phase == "resolved" and (view is None or mark == "P"):
                continue  # never announced as open, or resolved but reported again below the re-open threshold
            assert phase == view, (seed, mark, state.status, view)
            if phase == "active" and mark == "P":
                assert view_severity is not None and view_severity.rank >= state.severity.rank


# ---- escalation ------------------------------------------------------------------------------------------------


def test_open_finding_that_gets_more_severe_is_notified_again(store: StateStore) -> None:
    # regression: a finding opened as LOW (below a target's min_severity) that became CRITICAL was never notified
    sequence = [Severity.LOW, Severity.LOW, Severity.HIGH, Severity.HIGH, Severity.MEDIUM, Severity.CRITICAL]
    got = []
    for i, severity in enumerate(sequence):
        outcome = store.record_run(TENANT, [make_finding(severity=severity)], now=T0 + i * HOUR)
        got.append([(t.type, t.severity.value, t.previous_severity) for t in outcome.transitions])
    assert got == [
        [],
        [("opened", "low", None)],
        [("escalated", "high", Severity.LOW)],
        [],
        [],  # de-escalation is not a notification
        [("escalated", "critical", Severity.HIGH)],
    ]
    assert store.record_run(TENANT, [make_finding(severity=Severity.CRITICAL)], now=T0 + 6 * HOUR).transitions == []


def test_undelivered_escalation_is_sent_again(store: StateStore) -> None:
    store.record_run(TENANT, [make_finding("silence.silent", Severity.MEDIUM)], now=T0)
    outcome = store.record_run(TENANT, [make_finding("silence.silent", Severity.HIGH)], now=T0 + HOUR)
    assert [t.type for t in outcome.transitions] == ["escalated"]
    assert store.mark_undelivered(TENANT, outcome.run_id) == 1
    again = store.record_run(TENANT, [make_finding("silence.silent", Severity.HIGH)], now=T0 + 2 * HOUR)
    assert [(t.type, t.previous_severity) for t in again.transitions] == [("escalated", Severity.MEDIUM)]


def test_escalation_of_an_accepted_finding_is_suppressed(store: StateStore) -> None:
    finding = make_finding("silence.silent", Severity.MEDIUM)
    assert store.record_run(TENANT, [finding], now=T0).opened
    accept = accept_for(finding, T0 + timedelta(days=5))
    outcome = store.record_run(TENANT, [make_finding("silence.silent", Severity.HIGH)], now=T0 + HOUR, accept=accept)
    assert outcome.transitions == [] and outcome.counts["suppressed"] == 1


# ---- deferred notifications never contradict the current run ----------------------------------------------------


def test_deferred_resolved_is_not_sent_while_the_finding_is_reported(store: StateStore) -> None:
    # regression: a "resolved" handed back (or deferred by flapping) went out while the run still reported it
    finding = make_finding()
    got = run_pattern(store, "PPAA", finding)
    assert got[-1] == ["resolved"]
    last = store.last_run(TENANT)
    assert last is not None and store.mark_undelivered(TENANT, last.run_id) == 1
    pending = store.record_run(TENANT, [finding], now=T0 + 4 * HOUR)  # present again, below the re-open threshold
    assert pending.transitions == []
    gone = store.record_run(TENANT, [], now=T0 + 5 * HOUR)
    assert [t.type for t in gone.transitions] == ["resolved"]


def test_reminder_during_flapping_counts_as_telling_it_is_open(store: StateStore) -> None:
    # regression: after a "still open" reminder sent while flapping, the final resolution was never announced
    finding = make_finding("silence.silent", Severity.CRITICAL)
    kwargs = {"resolve_after": 1, "flap_threshold": 2}
    got = run_pattern(store, "PA" + "P" * 13 + "A" * 30, finding, **kwargs)  # type: ignore[arg-type]
    flat = [(i, t) for i, types in enumerate(got) for t in types]
    assert flat[0] == (0, "opened") and flat[1] == (1, "flapping")
    reminder = [i for i, t in flat if t == "reminder"]
    resolved = [i for i, t in flat if t == "resolved"]
    assert reminder and resolved and resolved[0] > reminder[-1]
    state = store.get(TENANT, finding.fingerprint)
    assert state is not None and state.status == "resolved" and not state.flapping


# ---- reminders -------------------------------------------------------------------------------------------------


def test_reminders_for_open_critical_findings(store: StateStore) -> None:
    finding = make_finding("silence.silent", Severity.CRITICAL)
    got = run_pattern(store, "P" * 31, finding)
    reminders = [i for i, types in enumerate(got) if types == ["reminder"]]
    assert got[0] == ["opened"]
    assert reminders == [12, 24]


def test_reminder_interval_is_configurable(store: StateStore) -> None:
    finding = make_finding("silence.silent", Severity.CRITICAL)
    got = run_pattern(store, "P" * 10, finding, remind_every=timedelta(hours=4))
    assert [i for i, types in enumerate(got) if types == ["reminder"]] == [4, 8]


def test_no_reminders_for_non_critical(store: StateStore) -> None:
    got = run_pattern(store, "P" * 30, make_finding("silence.silent", Severity.HIGH))
    assert got[0] == ["opened"] and all(types == [] for types in got[1:])


def test_no_reminder_while_absent(store: StateStore) -> None:
    finding = make_finding("silence.silent", Severity.CRITICAL)
    got = run_pattern(store, "P" * 12 + "A" + "P", finding)
    assert got[12] == [] and got[13] == ["reminder"]


# ---- accept / snooze -------------------------------------------------------------------------------------------


def accept_for(finding: Finding, expires: datetime, **kwargs: Any) -> AcceptList:
    return AcceptList(
        [
            AcceptEntry(
                owner="alice",
                reason="known lab host",
                expires=expires,
                fingerprint=finding.fingerprint,
                index=1,
                **kwargs,
            )
        ]
    )


def test_accepted_findings_are_tracked_but_not_notified(store: StateStore) -> None:
    finding = make_finding("silence.silent", Severity.CRITICAL)
    accept = accept_for(finding, T0 + timedelta(days=30))
    outcome = store.record_run(TENANT, [finding], now=T0, accept=accept)
    assert outcome.transitions == []
    assert outcome.counts["accepted"] == 1 and outcome.counts["suppressed"] == 1 and outcome.counts["open"] == 1
    state = store.get(TENANT, finding.fingerprint)
    assert state is not None and state.status == "open" and state.accepted_until == T0 + timedelta(days=30)
    # no reminders while accepted either
    got = run_pattern(store, "P" * 30, finding, start=T0 + HOUR, accept=accept)
    assert all(types == [] for types in got)


def test_acceptance_expiry_produces_one_transition_then_normal_flow(store: StateStore) -> None:
    finding = make_finding("silence.silent", Severity.CRITICAL)
    accept = accept_for(finding, T0 + timedelta(days=2))
    assert store.record_run(TENANT, [finding], now=T0, accept=accept).transitions == []
    later = T0 + timedelta(days=3)
    outcome = store.record_run(TENANT, [finding], now=later, accept=accept)
    assert [t.type for t in outcome.transitions] == ["acceptance_expired"]
    expired = outcome.transitions[0]
    assert expired.fingerprint == finding.fingerprint and expired.accept_id == accept.entries[0].id
    assert expired.status == "open" and isinstance(expired.detail, Message)
    detail = render(expired.detail, "en")
    assert "alice" in detail and "2026-09-02" in detail
    # announced once; no duplicate "opened"; reminders resume on the critical cadence
    assert store.record_run(TENANT, [finding], now=later + HOUR, accept=accept).transitions == []
    outcome = store.record_run(TENANT, [finding], now=later + 12 * HOUR, accept=accept)
    assert [t.type for t in outcome.transitions] == ["reminder"]


def test_expired_entry_matching_nothing_is_announced_once(store: StateStore) -> None:
    entry = AcceptEntry(
        owner="svc_backup",
        reason="old",
        expires=T0 - timedelta(days=1),
        kind="silence.silent",
        subject="agent:gone-*",
        index=4,
    )
    accept = AcceptList([entry])
    outcome = store.record_run(TENANT, [], now=T0, accept=accept)
    (only,) = outcome.transitions
    assert only.type == "acceptance_expired" and only.fingerprint == "" and only.accept_id == entry.id
    assert only.kind == "silence.silent" and only.domain == "silence" and only.status == ""
    text = render(only.summary, "en", lambda e: "<" + e.kind + ">")
    assert "#4" in text and "<user>" in text
    assert store.record_run(TENANT, [], now=T0 + HOUR, accept=accept).transitions == []


def test_removing_an_acceptance_notifies_the_open_finding(store: StateStore) -> None:
    finding = make_finding("silence.silent", Severity.HIGH)
    accept = accept_for(finding, T0 + timedelta(days=30))
    assert run_pattern(store, "PP", finding, accept=accept) == [[], []]
    outcome = store.record_run(TENANT, [finding], now=T0 + 2 * HOUR, accept=None)
    assert [t.type for t in outcome.transitions] == ["opened"]


def test_acceptance_expiring_on_a_resolved_finding(store: StateStore) -> None:
    finding = make_finding("silence.silent", Severity.HIGH)
    assert store.record_run(TENANT, [finding], now=T0).opened  # notified as open
    accept = accept_for(finding, T0 + timedelta(days=1))
    assert store.record_run(TENANT, [finding], now=T0 + HOUR, accept=accept).transitions == []
    got = run_pattern(store, "AA", finding, start=T0 + 2 * HOUR, accept=accept)
    assert got == [[], []]  # resolution suppressed while accepted
    outcome = store.record_run(TENANT, [], now=T0 + timedelta(days=2), accept=accept)
    assert [(t.type, t.status) for t in outcome.transitions] == [("acceptance_expired", "resolved")]


def test_glob_acceptance_and_tenant_scope(store: StateStore) -> None:
    lab = make_finding("coverage.missing_source", Severity.HIGH, host="lab-07.corp.example")
    prod = make_finding("coverage.missing_source", Severity.HIGH, host="srv-web-01.example")
    accept = AcceptList(
        [
            AcceptEntry(
                owner="alice",
                reason="lab",
                expires=T0 + timedelta(days=10),
                kind="coverage.missing_source",
                subject="agent:lab-*|*",
                index=1,
            ),
            AcceptEntry(
                owner="alice",
                reason="other tenant",
                expires=T0 + timedelta(days=10),
                fingerprint=prod.fingerprint,
                tenant="globex",
                index=2,
            ),
        ]
    )
    store.record_run(TENANT, [lab, prod], now=T0, accept=accept)
    outcome = store.record_run(TENANT, [lab, prod], now=T0 + HOUR, accept=accept)
    assert [t.fingerprint for t in outcome.opened] == [prod.fingerprint]
    assert outcome.counts["accepted"] == 1


# ---- never a false green ---------------------------------------------------------------------------------------


def test_unassessed_domains_do_not_resolve(store: StateStore) -> None:
    finding = make_finding("silence.drop", Severity.HIGH)
    run_pattern(store, "PP", finding)
    for h in range(2, 6):
        outcome = store.record_run(TENANT, [], now=T0 + h * HOUR, assessed={"noise", "coverage"})
        assert outcome.transitions == [] and outcome.counts["not_assessed"] == 1
    state = store.get(TENANT, finding.fingerprint)
    assert state is not None and state.status == "open" and state.consecutive_good == 0
    got = run_pattern(store, "AA", finding, start=T0 + 6 * HOUR, assessed={"silence"})
    assert got == [[], ["resolved"]]
    # resolved findings kept for history are not "open findings that could not be re-checked"
    outcome = store.record_run(TENANT, [], now=T0 + 8 * HOUR, assessed={"noise"})
    assert outcome.counts["not_assessed"] == 0


def test_incomplete_run_cannot_resolve_other_domains_by_default(store: StateStore) -> None:
    finding = make_finding("silence.drop", Severity.HIGH)
    run_pattern(store, "PP", finding)
    incomplete = Finding(
        kind="assessment.incomplete", domain="assessment", title="indexer timed out", severity=Severity.HIGH,
        subject="indexer", tenant=TENANT,
    )  # fmt: skip
    for h in (2, 3, 4):
        outcome = store.record_run(TENANT, [incomplete], now=T0 + h * HOUR)
        assert "resolved" not in [t.type for t in outcome.transitions]
    state = store.get(TENANT, finding.fingerprint)
    assert state is not None and state.status == "open"


def test_stale_run_changes_nothing(store: StateStore) -> None:
    finding = make_finding("silence.silent", Severity.CRITICAL)
    first = store.record_run(TENANT, [finding], now=T0 + 2 * HOUR)
    stale = store.record_run(TENANT, [], now=T0 + HOUR)
    assert stale.stale and stale.transitions == []
    last = store.last_run(TENANT)
    assert last is not None and last.run_id == first.run_id
    same_time = store.record_run(TENANT, [finding], now=T0 + 2 * HOUR)
    assert not same_time.stale


def test_future_dated_run_does_not_freeze_the_lifecycle(store: StateStore) -> None:
    # regression: one run with a bogus future "now" made every later run stale: no notification for years
    wallclock = datetime.now(UTC).replace(microsecond=0)
    tampering = make_finding("silence.tampering", Severity.CRITICAL)
    assert not store.record_run(TENANT, [], now=wallclock + timedelta(days=3650)).stale
    outcome = store.record_run(TENANT, [tampering], now=wallclock)
    assert not outcome.stale and [t.type for t in outcome.opened] == ["opened"]
    last = store.last_run(TENANT)
    assert last is not None and last.run_id == outcome.run_id
    # ordinary late runs are still stale
    assert store.record_run(TENANT, [], now=wallclock - HOUR).stale


# ---- delivery hand-back -----------------------------------------------------------------------------------------


def test_mark_undelivered_resends_on_next_run(store: StateStore) -> None:
    finding = make_finding("coverage.missing_source", Severity.HIGH)
    store.record_run(TENANT, [finding], now=T0)
    opened = store.record_run(TENANT, [finding], now=T0 + HOUR)
    assert [t.type for t in opened.transitions] == ["opened"]
    assert store.mark_undelivered(TENANT, opened.run_id) == 1
    again = store.record_run(TENANT, [finding], now=T0 + 2 * HOUR)
    assert [t.type for t in again.transitions] == ["opened"]
    assert store.record_run(TENANT, [finding], now=T0 + 3 * HOUR).transitions == []
    assert store.mark_undelivered(TENANT, "no-such-run") == 0


def test_mark_undelivered_only_selected_fingerprints(store: StateStore) -> None:
    a = make_finding("silence.silent", Severity.HIGH, host="srv-web-01.example")
    b = make_finding("silence.silent", Severity.HIGH, host="dc01.corp.example")
    outcome = store.record_run(TENANT, [a, b], now=T0)
    assert len(outcome.opened) == 2
    assert store.mark_undelivered(TENANT, outcome.run_id, [a.fingerprint]) == 1
    again = store.record_run(TENANT, [a, b], now=T0 + HOUR)
    assert [t.fingerprint for t in again.opened] == [a.fingerprint]


def test_mark_undelivered_reannounces_expired_acceptance(store: StateStore) -> None:
    entry = AcceptEntry(owner="alice", reason="x", expires=T0 - HOUR, kind="silence.silent", subject="*", index=1)
    accept = AcceptList([entry])
    outcome = store.record_run(TENANT, [], now=T0, accept=accept)
    assert len(outcome.acceptance_expired) == 1
    assert store.mark_undelivered(TENANT, outcome.run_id, [""]) == 1
    assert len(store.record_run(TENANT, [], now=T0 + HOUR, accept=accept).acceptance_expired) == 1


def test_mark_undelivered_makes_reminder_due_again(store: StateStore) -> None:
    finding = make_finding("silence.silent", Severity.CRITICAL)
    got = run_pattern(store, "P" * 13, finding)
    assert got[12] == ["reminder"]
    reminder_run = store.last_run(TENANT)
    assert reminder_run is not None
    assert store.mark_undelivered(TENANT, reminder_run.run_id) == 1
    outcome = store.record_run(TENANT, [finding], now=T0 + 13 * HOUR)
    assert [t.type for t in outcome.transitions] == ["reminder"]


# ---- queries, heartbeat, validation ----------------------------------------------------------------------------


def test_last_run_heartbeat_and_open_findings(store: StateStore) -> None:
    assert store.last_run(TENANT) is None and store.last_heartbeat(TENANT) is None
    crit = make_finding("silence.silent", Severity.CRITICAL, host="dc01.corp.example")
    high = make_finding("silence.silent", Severity.HIGH)
    outcome = store.record_run(TENANT, [high, crit], now=T0)
    last = store.last_run(TENANT)
    assert last is not None and last.run_id == outcome.run_id and last.run_at == T0
    assert last.counts["open"] == 2
    assert [s.severity for s in store.open_findings(TENANT)] == [Severity.CRITICAL, Severity.HIGH]
    store.heartbeat(TENANT, T0, True, "ok: 2 findings")
    store.heartbeat(TENANT, T0 + HOUR, False, "indexer unreachable")
    newest = store.last_heartbeat(TENANT)
    assert newest is not None and not newest.ok and newest.at == T0 + HOUR
    last_ok = store.last_heartbeat(TENANT, ok=True)
    assert last_ok is not None and last_ok.detail == "ok: 2 findings"


def test_summary_placeholders_render_in_both_languages(store: StateStore) -> None:
    finding = make_finding("silence.silent", Severity.HIGH)
    (opened,) = store.record_run(TENANT, [finding], now=T0).transitions
    assert render(opened.summary, "en") == "[host] stopped sending [channel] events (12 expected)"
    assert render(opened.summary, "es") == "[host] dejó de enviar eventos [channel] (12 esperados)"


def test_invalid_arguments(store: StateStore) -> None:
    with pytest.raises(ValueError, match="aware"):
        store.record_run(TENANT, [], now=datetime(2026, 9, 1))
    with pytest.raises(ValueError):
        store.record_run(TENANT, [], now=T0, open_after=0)
    with pytest.raises(ValueError):
        store.record_run(TENANT, [], now=T0, remind_every=timedelta(0))


def test_retention_prunes_old_resolved_findings(store: StateStore) -> None:
    finding = make_finding("silence.silent", Severity.HIGH)
    run_pattern(store, "PAA", finding)
    assert store.get(TENANT, finding.fingerprint) is not None
    store.record_run(TENANT, [], now=T0 + timedelta(days=100))
    assert store.get(TENANT, finding.fingerprint) is None


# ---- storage: permissions, schema, privacy ---------------------------------------------------------------------


def _mode(path: Path) -> int:
    return stat.S_IMODE(os.stat(path).st_mode)


def test_file_and_directory_permissions(tmp_path: Path) -> None:
    db = tmp_path / "a" / "b" / "state.sqlite3"
    with StateStore(db) as s:
        s.record_run(TENANT, [make_finding()], now=T0)
        assert _mode(db) == 0o600
        for suffix in ("-wal", "-shm"):
            side = Path(str(db) + suffix)
            if side.exists():
                assert _mode(side) == 0o600
    assert _mode(tmp_path / "a") == 0o700 and _mode(tmp_path / "a" / "b") == 0o700


def test_symlinked_database_is_refused(tmp_path: Path) -> None:
    # regression: the store opened (and chmod-ed, then overwrote) whatever file the link pointed to
    victim = tmp_path / "victim.txt"
    victim.write_text("")
    os.chmod(victim, 0o644)
    state_dir = tmp_path / "state"
    state_dir.mkdir(mode=0o700)
    (state_dir / STATE_FILENAME).symlink_to(victim)
    with pytest.raises(StateError, match="symbolic link"):
        StateStore(state_dir / STATE_FILENAME)
    assert victim.read_bytes() == b"" and _mode(victim) == 0o644


@pytest.mark.parametrize("suffix", ["-wal", "-shm", "-journal"])
def test_symlinked_side_files_are_refused(tmp_path: Path, suffix: str) -> None:
    victim = tmp_path / "victim.txt"
    victim.write_text("precious")
    state_dir = tmp_path / "state"
    state_dir.mkdir(mode=0o700)
    Path(str(state_dir / STATE_FILENAME) + suffix).symlink_to(victim)
    with pytest.raises(StateError, match="symbolic link"):
        StateStore(state_dir / STATE_FILENAME)
    assert victim.read_text() == "precious"


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions")
@pytest.mark.parametrize("mode", [0o777, 0o1777, 0o770, 0o702])
def test_state_directory_writable_by_others_is_refused(tmp_path: Path, mode: int) -> None:
    shared = tmp_path / "shared"
    shared.mkdir()
    os.chmod(shared, mode)
    with pytest.raises(StateError, match="other users"):
        StateStore(shared / STATE_FILENAME)
    assert not (shared / STATE_FILENAME).exists()
    assert "otros usuarios" in _raises(shared).render("es").lower()


def _raises(directory: Path) -> StateError:
    try:
        StateStore(directory / STATE_FILENAME)
    except StateError as exc:
        return exc
    raise AssertionError("StateStore accepted an unsafe directory")


@pytest.mark.skipif(os.name != "posix" or os.geteuid() != 0, reason="needs root to chown")
def test_state_directory_owned_by_another_user_is_refused(tmp_path: Path) -> None:
    foreign = tmp_path / "foreign"
    foreign.mkdir(mode=0o700)
    os.chown(foreign, 54321, 54321)
    with pytest.raises(StateError, match="another user"):
        StateStore(foreign / STATE_FILENAME)


def test_tighten_never_follows_symlinks(tmp_path: Path) -> None:
    from hushwatch.state import _tighten

    victim = tmp_path / "victim.txt"
    victim.write_text("x")
    os.chmod(victim, 0o644)
    link = tmp_path / "link"
    link.symlink_to(victim)
    _tighten(link)
    assert _mode(victim) == 0o644
    _tighten(victim)
    assert _mode(victim) == 0o600


def test_existing_loose_file_is_tightened(tmp_path: Path) -> None:
    db = tmp_path / "loose.sqlite3"
    sqlite3.connect(db).close()
    os.chmod(db, 0o644)
    StateStore(db).close()
    assert _mode(db) == 0o600


def test_directory_path_means_default_file_name(tmp_path: Path) -> None:
    with StateStore(tmp_path) as s:
        assert s.path == tmp_path / STATE_FILENAME
    assert (tmp_path / STATE_FILENAME).exists()


def test_schema_migrations_table(tmp_path: Path) -> None:
    db = tmp_path / "s.sqlite3"
    StateStore(db).close()
    with StateStore(db) as s:  # reopening is idempotent
        assert s.schema_version() == 2
    rows = sqlite3.connect(db).execute("SELECT version, name FROM schema_migrations ORDER BY version").fetchall()
    assert rows == [(1, "initial schema"), (2, "notified severity (escalation)")]


def test_version_1_database_is_migrated(tmp_path: Path) -> None:
    db = tmp_path / "s.sqlite3"
    finding = make_finding("silence.silent", Severity.HIGH)
    with StateStore(db) as s:
        assert s.record_run(TENANT, [finding], now=T0).opened
    conn = sqlite3.connect(db)  # turn it back into a version-1 database
    conn.execute("ALTER TABLE findings DROP COLUMN notified_severity")
    conn.execute("ALTER TABLE notices DROP COLUMN prev_severity")
    conn.execute("DELETE FROM schema_migrations WHERE version = 2")
    conn.commit()
    conn.close()
    with StateStore(db) as s:
        assert s.schema_version() == 2
        # the migration assumes the last notification carried the stored severity: no spurious escalation
        assert s.record_run(TENANT, [finding], now=T0 + HOUR).transitions == []
        outcome = s.record_run(TENANT, [make_finding("silence.silent", Severity.CRITICAL)], now=T0 + 2 * HOUR)
        assert [t.type for t in outcome.transitions] == ["escalated"]


def test_newer_schema_is_refused(tmp_path: Path) -> None:
    db = tmp_path / "s.sqlite3"
    StateStore(db).close()
    conn = sqlite3.connect(db)
    conn.execute("INSERT INTO schema_migrations VALUES (99, 'future', 0)")
    conn.commit()
    conn.close()
    with pytest.raises(StateError, match="newer"):
        StateStore(db)


def test_corrupt_database_is_a_state_error(tmp_path: Path) -> None:
    db = tmp_path / "s.sqlite3"
    db.write_bytes(b"this is not a sqlite database at all" * 100)
    with pytest.raises(StateError):
        StateStore(db)


RAW_VALUES = ("srv-web-01", "198.51.100.23", "alice", "hunter2pass", "tok3nSECRET", "198.51.100.7", "corp.example")


def _state_bytes(directory: Path) -> bytes:
    return b"".join(p.read_bytes() for p in directory.iterdir() if p.is_file())


def test_state_holds_no_raw_subjects_or_entities(tmp_path: Path) -> None:
    directory = tmp_path / "state"
    finding = Finding(
        kind="noise.investigate",
        domain="noise",
        title=M(
            "test.state.login",
            user=Entity("user", "alice"),
            ip=Entity("ip", "198.51.100.23"),
            raw="alice@corp.example on srv-web-01.example",  # a plain-string param must not leak either
        ),
        severity=Severity.HIGH,
        subject="rule:5710|srcip:198.51.100.23|agent:srv-web-01.example",
        tenant=TENANT,
        reasons=[M("test.state.title", host=Entity("host", "srv-web-01.example"), channel="Security", n=1)],
        evidence={"user": Entity("user", "alice"), "full_log": "Failed password for alice from 198.51.100.23"},
    )
    silent = make_finding("silence.silent", Severity.CRITICAL)
    plain_title = Finding(
        kind="pipeline.lag", domain="pipeline", title="srv-web-01.example lags behind (alice)", severity=Severity.HIGH,
        subject="agent:srv-web-01.example", tenant=TENANT,
    )  # fmt: skip
    s = StateStore(directory / STATE_FILENAME)
    for h in range(3):
        s.record_run(TENANT, [finding, silent, plain_title], now=T0 + h * HOUR)
    s.heartbeat(
        TENANT,
        T0,
        False,
        "indexer https://svc_backup:hunter2pass@198.51.100.7:9200/_search?token=tok3nSECRET "
        "failed for alice@corp.example",
    )
    hb = s.last_heartbeat(TENANT)
    assert hb is not None and "https://" in hb.detail
    blob_open = _state_bytes(directory)  # includes the WAL while the store is open
    s.close()
    blob_closed = _state_bytes(directory)
    for blob in (blob_open, blob_closed):
        for raw in RAW_VALUES:
            assert raw.encode() not in blob, raw
    # the stored summary keeps the shape of the title with placeholders
    with StateStore(directory / STATE_FILENAME) as s2:
        state = s2.get(TENANT, finding.fingerprint)
        assert state is not None
        assert render(state.summary, "en") == "[user] logged in from [ip]: [raw]"
        assert state.subject_hash and finding.subject not in state.subject_hash
        plain = s2.get(TENANT, plain_title.fingerprint)
        assert plain is not None and plain.summary == "pipeline.lag"


def test_fallback_template_is_scrubbed_before_storage(tmp_path: Path) -> None:
    finding = Finding(
        kind="pipeline.lag", domain="pipeline", severity=Severity.HIGH, subject="x", tenant=TENANT,
        title=M("test.state.unregistered", "lag from 198.51.100.23 reported by alice@corp.example ({n} s)", n=5),
    )  # fmt: skip
    directory = tmp_path / "state"
    with StateStore(directory / STATE_FILENAME) as s:
        s.record_run(TENANT, [finding], now=T0)
        state = s.get(TENANT, finding.fingerprint)
        assert state is not None
        text = render(state.summary, "en")
        assert text.startswith("lag from ") and text.endswith("(5 s)")
    blob = _state_bytes(directory)
    assert b"198.51.100.23" not in blob and b"alice@corp.example" not in blob


@pytest.mark.parametrize(
    "password", ["hunter2pass", "Pa@ss!w0rd", "p@ss@word!", "x!y@z#w"], ids=["plain", "at", "two_at", "hash"]
)
def test_heartbeat_detail_drops_url_credentials(store: StateStore, password: str) -> None:
    # regression: a password containing '@' was split and its first part stored in clear
    record = store.heartbeat(TENANT, T0, False, f"indexer https://svc_backup:{password}@indexer.corp.example:9200/x")
    for fragment in {password, *(p for p in password.replace("@", " ").replace("!", " ").split() if len(p) >= 2)}:
        assert fragment not in record.detail, (fragment, record.detail)
    assert "svc_backup" not in record.detail and "https://" in record.detail


def test_subject_hash_is_keyed_per_database(tmp_path: Path) -> None:
    finding = make_finding()
    hashes = []
    for name in ("one.sqlite3", "two.sqlite3"):
        with StateStore(tmp_path / name) as s:
            s.record_run(TENANT, [finding], now=T0)
            state = s.get(TENANT, finding.fingerprint)
            assert state is not None
            hashes.append(state.subject_hash)
    assert hashes[0] != hashes[1]


# ---- concurrency -----------------------------------------------------------------------------------------------


def test_two_stores_same_file_threads(tmp_path: Path) -> None:
    db = tmp_path / "shared.sqlite3"
    finding = make_finding("silence.silent", Severity.HIGH)
    errors: list[BaseException] = []
    barrier = threading.Barrier(2)

    def worker() -> None:
        try:
            with StateStore(db, busy_timeout=30) as s:
                barrier.wait()
                for _ in range(25):
                    s.record_run(TENANT, [finding], now=T0)  # same instant: no run is stale
                    s.heartbeat(TENANT, T0, True, "ok")
        except BaseException as exc:  # pragma: no cover - reported below
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    with StateStore(db) as s:
        state = s.get(TENANT, finding.fingerprint)
        assert state is not None and state.consecutive_bad == 50  # no lost read-modify-write updates
        assert state.times_opened == 1
    conn = sqlite3.connect(db)
    assert conn.execute("SELECT COUNT(*) FROM runs").fetchone()[0] == 50
    assert conn.execute("SELECT COUNT(*) FROM heartbeats").fetchone()[0] == 50
    assert conn.execute("SELECT COUNT(*) FROM history WHERE event = 'opened'").fetchone()[0] == 1


def test_opening_a_store_never_opens_sqlite_files_behind_its_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # regression: an open()+close() on the -shm/-wal/database while SQLite holds POSIX locks on them drops those
    # locks (they are per process, released by ANY close); another process then re-initialized the WAL index
    # under a live reader (SIGBUS / corruption)
    db = tmp_path / "shared.sqlite3"
    first = StateStore(db)
    first.record_run(TENANT, [make_finding()], now=T0)
    opened: list[str] = []
    real_open = os.open

    def spy(path: Any, flags: int, *args: Any, **kwargs: Any) -> int:
        fd = real_open(path, flags, *args, **kwargs)
        opened.append(str(path))
        return fd

    monkeypatch.setattr(os, "open", spy)
    for suffix in ("", "-wal", "-shm"):
        side = Path(str(db) + suffix)
        if side.exists():
            os.chmod(side, 0o644)  # loose modes must still be tightened, without opening the files
    second = StateStore(db)
    assert [p for p in opened if p.startswith(str(db))] == []
    assert _mode(db) == 0o600
    second.record_run(TENANT, [make_finding()], now=T0 + HOUR)
    first.record_run(TENANT, [make_finding()], now=T0 + 2 * HOUR)
    second.close()
    first.close()


def test_two_processes_same_file(tmp_path: Path) -> None:
    db = tmp_path / "shared.sqlite3"
    script = textwrap.dedent(
        f"""
        from datetime import datetime, timezone
        from hushwatch.models import Finding, Severity
        from hushwatch.state import StateStore
        f = Finding(kind="silence.silent", domain="silence", title="t", severity=Severity.HIGH,
                    subject="agent:srv-web-01.example|ls:Security", tenant="acme")
        with StateStore({str(db)!r}) as s:
            for _ in range(15):
                s.record_run("acme", [f], now=datetime(2026, 9, 1, tzinfo=timezone.utc))
        """
    )
    env = dict(os.environ, PYTHONPATH=str(REPO) + os.pathsep + os.environ.get("PYTHONPATH", ""))
    procs = [
        subprocess.Popen([sys.executable, "-c", script], env=env, stderr=subprocess.PIPE, text=True) for _ in range(2)
    ]
    for p in procs:
        _, stderr = p.communicate(timeout=120)
        assert p.returncode == 0, stderr
    fp = Finding(
        kind="silence.silent", domain="silence", title="t", severity=Severity.HIGH,
        subject="agent:srv-web-01.example|ls:Security", tenant="acme",
    ).fingerprint  # fmt: skip
    with StateStore(db) as s:
        state = s.get("acme", fp)
        assert state is not None and state.consecutive_bad == 30
    assert sqlite3.connect(db).execute("SELECT COUNT(*) FROM runs").fetchone()[0] == 30


# ---- accept file ------------------------------------------------------------------------------------------------

NOW = datetime(2026, 9, 25, 10, 0, tzinfo=UTC)


def test_accept_file_valid(tmp_path: Path) -> None:
    path = tmp_path / "hushwatch-accept.yml"
    fp = make_finding().fingerprint
    path.write_text(
        textwrap.dedent(
            f"""
            version: 1
            accept:
              - fingerprint: {fp.upper()}
                owner: soc-team
                reason: decommissioned host, change CHG-1234
                expires: 2026-12-31
              - kind: silence.silent
                subject: "agent:lab-*|*"
                tenant: acme
                owner: alice
                reason: lab machines are powered off at weekends
                expires: "2026-10-15T18:00:00Z"
            """
        ),
        encoding="utf-8",
    )
    accept = load_accept_file(path, now=NOW)
    assert len(accept) == 2
    first, second = accept.entries
    assert first.fingerprint == fp and first.owner == "soc-team" and first.index == 1
    assert first.expires == datetime(2027, 1, 1, tzinfo=UTC)  # valid through the end of the day
    assert first.expires_label() == "2026-12-31"
    assert second.kind == "silence.silent" and second.tenant == "acme"
    assert second.expires == datetime(2026, 10, 15, 18, tzinfo=UTC)
    assert first.id != second.id and len(first.id) == 16


def test_accept_file_bare_list_and_empty(tmp_path: Path) -> None:
    text = "- fingerprint: 0123456789abcdef0123\n  owner: alice\n  reason: r\n  expires: 2026-10-01\n"
    assert len(parse_accept(text, now=NOW)) == 1
    assert len(parse_accept("", now=NOW)) == 0
    assert len(parse_accept("accept: []\n", now=NOW)) == 0


def _problems(text: str) -> str:
    with pytest.raises(AcceptFileError) as info:
        parse_accept(text, now=NOW)
    return str(info.value)


def test_accept_missing_expiry_is_rejected() -> None:
    message = _problems("- fingerprint: 0123456789abcdef0123\n  owner: alice\n  reason: r\n")
    assert "entry 1" in message and "'expires' is mandatory" in message


def test_accept_expiry_more_than_a_year_ahead_is_rejected() -> None:
    message = _problems("- fingerprint: 0123456789abcdef0123\n  owner: alice\n  reason: r\n  expires: 2027-09-26\n")
    assert "more than 365 days" in message
    ok = parse_accept(
        "- fingerprint: 0123456789abcdef0123\n  owner: alice\n  reason: r\n  expires: 2027-09-25\n", now=NOW
    )
    assert len(ok) == 1
    far_ts = "- fingerprint: 0123456789abcdef0123\n  owner: a\n  reason: r\n  expires: 2027-09-25T10:00:01Z\n"
    assert "more than 365 days" in _problems(far_ts)


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        ("  fingerprint: 0123456789abcdef0123\n  kind: silence.silent\n  subject: x\n", "not both"),
        ("  kind: silence.silent\n", "'kind' and 'subject' together"),
        ("  subject: 'agent:*'\n", "'kind' and 'subject' together"),
        ("  fingerprint: not-hex!\n", "hushwatch fingerprint"),
        ("  kind: bogus.kind\n  subject: x\n", "is not a finding kind"),
        ("  fingerprint: 0123456789abcdef0123\n  expiry: 2026-10-01\n", "did you mean 'expires'"),
        ("  fingerprint: 0123456789abcdef0123\n  colour: red\n", "unknown key 'colour'"),
    ],
)
def test_accept_entry_validation(body: str, expected: str) -> None:
    text = "- owner: alice\n  reason: r\n  expires: 2026-10-01\n" + body
    assert expected in _problems(text)


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ("  expires: next week\n", "must be a date"),
        ("  expires: 2026-13-40\n", "not valid YAML (ValueError: month must be in 1..12)"),
        ("  expires: true\n", "must be a date"),
        ("  expires: 1790000000\n", "must be a date"),
        ("  expires:\n", "is mandatory"),
    ],
)
def test_accept_expiry_formats(line: str, expected: str) -> None:
    text = "- fingerprint: 0123456789abcdef0123\n  owner: alice\n  reason: r\n" + line
    assert expected in _problems(text)


def test_accept_missing_owner_and_reason_and_all_problems_reported() -> None:
    text = "- fingerprint: 0123456789abcdef0123\n  expires: 2026-10-01\n- fingerprint: abc\n  owner: ''\n"
    message = _problems(text)
    for fragment in ("entry 1: 'owner' is required", "entry 1: 'reason' is required", "entry 2: 'owner' must be"):
        assert fragment in message
    assert "entry 2: 'expires' is mandatory" in message


def test_accept_errors_render_in_spanish() -> None:
    with pytest.raises(AcceptFileError) as info:
        parse_accept("- fingerprint: 0123456789abcdef0123\n  owner: alice\n  reason: r\n", now=NOW)
    spanish = info.value.render("es")
    assert "no válido" in spanish and "'expires' es obligatorio" in spanish


@pytest.mark.parametrize(
    "text",
    [
        "- !!python/object/apply:os.system ['echo pwned']\n",
        "accept: !!python/object/new:os.system ['echo pwned']\n",
        "just a string\n",
        "accept: {fingerprint: x}\n",
        "version: 2\naccept: []\n",
        "extra: 1\n",
        "[unclosed\n",
        "- 42\n",
        "- fingerprint: 0123456789abcdef0123\n  owner: a\n  reason: r\n  expires: 2026-02-30\n",
        "[" * 5000 + "]" * 5000,
        "a: &a [x, x]\nb: &b [*a, *a, *a]\nc: &c [*b, *b, *b]\naccept: [*c, *c]\n",
    ],
    ids=[
        "python_apply_tag",
        "python_new_tag",
        "scalar",
        "accept_not_list",
        "version_2",
        "unknown_top_key",
        "broken_yaml",
        "entry_not_mapping",
        "impossible_date",
        "deep_nesting",
        "alias_expansion",
    ],
)
def test_accept_hostile_or_malformed_documents(text: str) -> None:
    with pytest.raises(AcceptFileError):
        parse_accept(text, now=NOW)


def test_accept_file_io(tmp_path: Path) -> None:
    missing = tmp_path / "nope.yml"
    assert len(load_accept_file(missing, now=NOW)) == 0
    with pytest.raises(AcceptFileError, match="does not exist"):
        load_accept_file(missing, now=NOW, missing_ok=False)
    huge = tmp_path / "huge.yml"
    huge.write_bytes(b"#" * 1_000_001)
    with pytest.raises(AcceptFileError, match="larger than"):
        load_accept_file(huge, now=NOW)
    binary = tmp_path / "bin.yml"
    binary.write_bytes(b"\xff\xfe\x00junk")
    with pytest.raises(AcceptFileError):
        load_accept_file(binary, now=NOW)


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions")
def test_world_writable_accept_file_is_refused(tmp_path: Path) -> None:
    # regression: any local user could append "kind: silence.tampering, subject: '*'" and silence findings
    path = tmp_path / "hushwatch-accept.yml"
    path.write_text("- fingerprint: 0123456789abcdef0123\n  owner: a\n  reason: r\n  expires: 2026-10-01\n")
    os.chmod(path, 0o666)
    with pytest.raises(AcceptFileError, match="any local user"):
        load_accept_file(path, now=NOW)
    os.chmod(path, 0o644)
    assert len(load_accept_file(path, now=NOW)) == 1


@pytest.mark.skipif(os.name != "posix" or os.geteuid() != 0, reason="needs root to chown")
def test_foreign_accept_file_in_a_shared_directory_is_refused(tmp_path: Path) -> None:
    shared = tmp_path / "tmp"
    shared.mkdir()
    os.chmod(shared, 0o1777)
    path = shared / "hushwatch-accept.yml"
    path.write_text("[]\n")
    os.chown(path, 54321, 54321)
    with pytest.raises(AcceptFileError, match="any local user"):
        load_accept_file(path, now=NOW)


def test_accept_matching_globs_case_and_expiry() -> None:
    accept = parse_accept(
        textwrap.dedent(
            """
            - kind: coverage.missing_source
              subject: "agent:lab-*|ls:Sec*"
              owner: alice
              reason: lab
              expires: 2026-10-01
            """
        ),
        now=NOW,
    )
    lab = make_finding(host="lab-07.corp.example")
    upper = make_finding(subject="agent:LAB-07|ls:Security")
    prod = make_finding(host="srv-web-01.example")
    other_kind = make_finding("silence.silent", host="lab-07.corp.example")
    assert accept.is_accepted(lab, NOW) is accept.entries[0]
    assert accept.is_accepted(upper, NOW) is None  # case-sensitive: fail loud, never hide more than written
    assert accept.is_accepted(prod, NOW) is None
    assert accept.is_accepted(other_kind, NOW) is None
    # valid through the whole expiry day (UTC), expired from the next midnight
    assert accept.is_accepted(lab, datetime(2026, 10, 1, 23, 59, 59, tzinfo=UTC)) is not None
    after = datetime(2026, 10, 2, tzinfo=UTC)
    assert accept.is_accepted(lab, after) is None
    assert accept.expired(after) == list(accept.entries) and accept.active(after) == []


def test_accept_glob_does_not_backtrack_catastrophically() -> None:
    accept = AcceptList(
        [
            AcceptEntry(
                owner="a",
                reason="r",
                expires=NOW + timedelta(days=1),
                kind="noise.tune",
                subject="*a*a*a*a*a*a*a*b",
                index=1,
            )
        ]
    )
    hostile = make_finding("noise.tune", subject="a" * 5000)
    assert accept.is_accepted(hostile, NOW) is None


def test_accept_tenant_scope() -> None:
    finding = make_finding()
    accept = AcceptList(
        [
            AcceptEntry(
                owner="a", reason="r", expires=NOW + timedelta(days=1), fingerprint=finding.fingerprint, tenant="globex"
            )
        ]
    )
    assert accept.is_accepted(finding, NOW) is None
    assert accept.is_accepted(finding, NOW, tenant="globex") is not None


def test_accept_entry_naive_expiry_is_utc() -> None:
    entry = AcceptEntry(owner="a", reason="r", expires=datetime(2026, 10, 1), fingerprint="0123456789abcdef0123")
    assert entry.expires.tzinfo is not None and entry.expires == datetime(2026, 10, 1, tzinfo=UTC)
    assert date(2026, 10, 1) == entry.expires.date()


def test_accept_yaml_datetime_forms() -> None:
    naive = parse_accept(
        "- fingerprint: 0123456789abcdef0123\n  owner: a\n  reason: r\n  expires: 2026-10-15 18:00:00\n", now=NOW
    )
    assert naive.entries[0].expires == datetime(2026, 10, 15, 18, tzinfo=UTC)
    aware = parse_accept(
        "- fingerprint: 0123456789abcdef0123\n  owner: a\n  reason: r\n  expires: 2026-10-15T20:00:00+02:00\n",
        now=NOW,
    )
    assert aware.entries[0].expires == datetime(2026, 10, 15, 18, tzinfo=UTC)
    assert aware.entries[0].expires_label() == "2026-10-15T18:00:00Z"


def test_accept_unquoted_numeric_fingerprint_is_rejected() -> None:
    # YAML 1.1 reads 01234567012345670123 as an OCTAL integer: silently a different number, so it must be quoted
    for fp in ("01234567012345670123", "12345678901234567890"):
        message = _problems(f"- fingerprint: {fp}\n  owner: a\n  reason: r\n  expires: 2026-10-01\n")
        assert "'fingerprint' must be non-empty text" in message
    ok = parse_accept(
        "- fingerprint: '01234567890123456789'\n  owner: 1234\n  reason: r\n  expires: 2026-10-01\n", now=NOW
    )
    assert ok.entries[0].fingerprint == "01234567890123456789" and ok.entries[0].owner == "1234"


def test_mark_undelivered_does_not_clobber_a_later_notification(store: StateStore) -> None:
    finding = make_finding("silence.silent", Severity.CRITICAL)
    first = store.record_run(TENANT, [finding], now=T0)
    assert first.opened
    got = run_pattern(store, "P" * 12, finding, start=T0 + HOUR)
    assert got[-1] == ["reminder"]  # h12: a later run notified again
    store.mark_undelivered(TENANT, first.run_id)  # a late hand-back of the h0 notification
    state = store.get(TENANT, finding.fingerprint)
    assert state is not None and state.last_notified_at == T0 + 12 * HOUR
    assert store.record_run(TENANT, [finding], now=T0 + 13 * HOUR).transitions == []


def test_two_expired_entries_matching_one_finding(store: StateStore) -> None:
    finding = make_finding("silence.silent", Severity.HIGH)
    entries = [
        AcceptEntry(owner="alice", reason="a", expires=T0 - HOUR, fingerprint=finding.fingerprint, index=1),
        AcceptEntry(owner="svc_backup", reason="b", expires=T0 - HOUR, kind="silence.silent", subject="*", index=2),
    ]
    outcome = store.record_run(TENANT, [finding], now=T0, accept=AcceptList(entries))
    assert [t.type for t in outcome.transitions] == ["acceptance_expired", "acceptance_expired"]
    assert {t.accept_id for t in outcome.transitions} == {e.id for e in entries}
    assert store.mark_undelivered(TENANT, outcome.run_id, [finding.fingerprint]) == 2
    again = store.record_run(TENANT, [finding], now=T0 + HOUR, accept=AcceptList(entries))
    assert [t.type for t in again.transitions] == ["acceptance_expired", "acceptance_expired"]
    assert store.record_run(TENANT, [finding], now=T0 + 2 * HOUR, accept=AcceptList(entries)).transitions == []


def test_heartbeats_are_pruned(store: StateStore) -> None:
    store.heartbeat(TENANT, T0, True, "old")
    store.heartbeat(TENANT, T0 + timedelta(days=120), True, "new")
    conn = sqlite3.connect(store.path)
    assert conn.execute("SELECT detail FROM heartbeats").fetchall() == [("new",)]
