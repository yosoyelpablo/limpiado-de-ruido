"""End-to-end regression suite: the full engine against the demo dataset's planted ground truth.

This is the contract hushwatch is judged by:

* every planted problem is found (noise, silence, coverage, pipeline, tuning debt);
* no ``tune`` suggestion ever matches an event of a planted attack (``must_not_hide``);
* no silence false alarms on healthy sources (laptops off at night, holidays...).
"""

from __future__ import annotations

import os
import re
from collections.abc import Iterable
from pathlib import Path
from typing import Any

import pytest

from hushwatch.config import load_config
from hushwatch.demo import SCANNER_IP, PlantedScenario, generate, load_demo_agents
from hushwatch.engine import ALL_ANALYSES, AnalysisOptions, AnalysisOutcome, analyze, open_sources
from hushwatch.i18n import Entity
from hushwatch.ingest import open_files
from hushwatch.models import Event, Finding, fingerprint, get_path, iter_entities

pytestmark = pytest.mark.e2e


class Run:
    def __init__(self, manifest: Any, outcome: AnalysisOutcome, events: list[Event]) -> None:
        self.manifest = manifest
        self.outcome = outcome
        self.events = events

    @property
    def findings(self) -> list[Finding]:
        return self.outcome.report.findings


@pytest.fixture(scope="module")
def run(tmp_path_factory: pytest.TempPathFactory) -> Run:
    out = tmp_path_factory.mktemp("demo")
    manifest = generate(out)
    tenant = load_config(manifest.config_path).tenant()
    opts = AnalysisOptions(
        analyses=frozenset(ALL_ANALYSES),
        dispositions=str(manifest.dispositions_path),
        ruleset_dirs=[str(manifest.rules_dir)],
        emit_suppressions=out / "suppressions",
        use_api=False,
    )
    source = open_sources(tenant, paths=[str(manifest.alerts_path)], options=opts)
    outcome = analyze(
        tenant, source, options=opts, agents=load_demo_agents(manifest.agents_path), wallclock=manifest.now
    )
    events = list(open_files([str(manifest.alerts_path)], tenant=tenant))
    return Run(manifest, outcome, events)


# ---- helpers ----------------------------------------------------------------------------------------------------

_SPLIT = re.compile(r"[|:,;=\s()\[\]{}\"']+")


def _strings(value: Any) -> Iterable[str]:
    if isinstance(value, Entity):
        yield value.value
    elif isinstance(value, str):
        yield value
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        yield str(value)
    elif isinstance(value, dict):
        for k, v in value.items():
            yield str(k)
            yield from _strings(v)
    elif isinstance(value, (list, tuple, set)):
        for v in value:
            yield from _strings(v)


def tokens(finding: Finding) -> set[str]:
    out: set[str] = set()
    raw = [finding.subject, *(e.value for e in iter_entities([finding.title, finding.reasons, finding.evidence]))]
    raw.extend(_strings(finding.evidence))
    for text in raw:
        out.add(text)
        out.update(t for t in _SPLIT.split(text) if t)
    return out


def names_of(sc: PlantedScenario) -> set[str]:
    names = {sc.agent} if sc.agent else set()
    names.update(sc.details.get("agents", []) if isinstance(sc.details, dict) else [])
    names.update(v for _, v in sc.conditions)
    return {n for n in names if n}


def about(finding: Finding, sc: PlantedScenario) -> bool:
    toks = tokens(finding)
    if sc.category == "tuning":
        return bool(set(sc.rule_ids) & toks)
    if sc.category in ("noise_safe", "noise_trap"):
        # same rule AND the scenario's own scope (a legit tune on another scope of the same rule is not "about" it)
        if not set(sc.rule_ids) & toks:
            return False
        return bool(names_of(sc) & toks) or not names_of(sc)
    if sc.category in ("silence", "coverage", "pipeline"):
        if names_of(sc) & toks:
            return True
        return bool(not sc.agent and set(sc.rule_ids) & toks)
    return False


def scenario_events(run: Run, sc: PlantedScenario) -> list[Event]:
    selected = []
    for ev in run.events:
        if sc.rule_ids and ev.rule_id not in sc.rule_ids:
            continue
        if sc.start and ev.ts < sc.start:
            continue
        if sc.end and ev.ts > sc.end:
            continue
        if sc.agent and get_path(ev.fields, "agent.name") != sc.agent and ev.source != sc.agent:
            continue
        if any(str(get_path(ev.fields, f)) != v for f, v in sc.conditions if f != "agent.name"):
            continue
        selected.append(ev)
    return selected


def scenarios(run: Run, category: str | None = None) -> list[PlantedScenario]:
    return [sc for sc in run.manifest.ground_truth if category is None or sc.category == category]


# ---- the contract ----------------------------------------------------------------------------------------------


def test_analysis_is_complete(run: Run) -> None:
    assert run.outcome.report.assessment["assessment"] == "ok", [
        (f.kind, f.subject) for f in run.findings if f.domain == "assessment"
    ]


def test_no_tune_suggestion_hides_any_planted_attack(run: Run) -> None:
    tunes = [s for s in run.outcome.suggestions if s.verdict == "tune"]
    assert tunes, "expected at least one safe tuning suggestion in the demo"
    for sc in scenarios(run):
        if not sc.must_not_hide:
            continue
        attack = scenario_events(run, sc)
        assert attack, f"scenario {sc.id}: could not select its planted events"
        for suggestion in tunes:
            hidden = [ev for ev in attack if suggestion.matches(ev)]
            assert not hidden, (
                f"scenario {sc.id} ({sc.title}): tune suggestion {suggestion.rule_id} "
                f"{suggestion.conditions} would hide {len(hidden)} attack event(s)"
            )


@pytest.mark.parametrize("sid", ["a", "b", "c", "u"])
def test_safe_noise_is_found_with_the_right_verdict(run: Run, sid: str) -> None:
    sc = run.manifest.scenario(sid)
    mine = [s for s in run.outcome.suggestions if s.rule_id in sc.rule_ids]
    verdicts = {s.verdict for s in mine}
    assert verdicts & set(sc.allowed_verdicts or [sc.expected_verdict]), (sid, sorted(verdicts))
    if sc.expected_kinds:
        assert any(f.kind in sc.expected_kinds and about(f, sc) for f in run.findings), (sid, sc.expected_kinds)
    if sc.review_required is not None and sc.expected_verdict == "tune":
        tuned = [s for s in mine if s.verdict == "tune"]
        assert any(s.review_required == sc.review_required for s in tuned), (sid, [s.dependents for s in tuned])


@pytest.mark.parametrize("sid", ["d", "e", "f", "g", "h", "s"])
def test_attack_traps_are_never_tuned(run: Run, sid: str) -> None:
    sc = run.manifest.scenario(sid)
    for f in run.findings:
        if f.kind in sc.forbidden_kinds and about(f, sc):
            conditions = f.evidence.get("conditions") if isinstance(f.evidence, dict) else None
            pytest.fail(f"scenario {sid}: forbidden {f.kind} about it: {f.subject} {conditions}")
    if sc.expected_kinds:
        assert any(f.kind in sc.expected_kinds and about(f, sc) for f in run.findings), sid


@pytest.mark.parametrize("sid", ["i", "j", "k", "l", "r", "n", "o", "p1", "p2", "p3", "t1", "t2", "t3", "t4"])
def test_planted_problem_is_detected(run: Run, sid: str) -> None:
    sc = run.manifest.scenario(sid)
    hits = [f for f in run.findings if f.kind in sc.expected_kinds and about(f, sc)]
    assert hits, (sid, sc.expected_kinds, sorted({(f.kind, f.subject) for f in run.findings if about(f, sc)}))


def test_the_clean_analyst_facing_candidate_is_tuned_without_review(run: Run) -> None:
    """Scenario u is the demo's showcase: analyst-facing, no correlation rule depends on it, FP evidence."""
    sc = run.manifest.scenario("u")
    tuned = [s for s in run.outcome.suggestions if s.rule_id in sc.rule_ids and s.verdict == "tune"]
    assert tuned and all(not s.review_required for s in tuned), [(s.conditions, s.dependents) for s in tuned]
    assert all(dict((c.field, c.value) for c in s.conditions).get("data.srcip") == SCANNER_IP for s in tuned)


def test_one_incident_is_one_finding(run: Run) -> None:
    """Cross-domain duplicates are folded into the finding with the most specific cause (listed as related)."""
    tenant = run.outcome.report.tenant
    by_fp = {f.fingerprint: f for f in run.findings}
    folded = (
        # dc02: tampering explains "agent alive but no data" and the sparse-channel note
        ("silence.tampering", "agent:dc02", "pipeline.agent_no_data", "agent:dc02"),
        ("silence.tampering", "agent:dc02", "silence.unmonitorable", "agent:dc02"),
        # srv-legacy-01: the disconnection is the cause of the silence
        ("pipeline.agent_disconnected", "agent:srv-legacy-01", "silence.silent", "agent:srv-legacy-01"),
    )
    for kind, subject, gone_kind, gone_subject in folded:
        keeper = next((f for f in run.findings if f.kind == kind and f.subject == subject), None)
        assert keeper is not None, (kind, subject)
        gone = fingerprint(tenant, gone_kind, gone_subject)
        assert gone not in by_fp, (gone_kind, gone_subject)
        assert gone in keeper.related, (kind, subject, gone_kind)
        assert keeper.evidence.get("explained"), (kind, subject)
    # srv-backup-01: Sysmon stopped is silence (it was seen and stopped), not a second coverage finding
    sysmon = next(f for f in run.findings if f.kind == "silence.silent" and "srv-backup-01" in f.subject)
    contract = fingerprint(
        tenant,
        "coverage.missing_source",
        "contract:windows servers|ls:Microsoft-Windows-Sysmon/Operational|state:silent|tier:standard",
    )
    assert contract not in by_fp and contract in sysmon.related


def test_controls_are_left_alone(run: Run) -> None:
    sc = run.manifest.scenario("t5")
    bad = [f for f in run.findings if f.kind in sc.forbidden_kinds and about(f, sc)]
    assert not bad, [(f.kind, f.subject) for f in bad]


def test_no_silence_false_alarms(run: Run) -> None:
    laptops = run.manifest.scenario("m")
    allowed = set(run.manifest.scenario("q").details["silence_findings_only_about"])
    expected_rules = {rid for sc in scenarios(run, "silence") for rid in sc.rule_ids}
    all_agents = set(run.manifest.agent_names) if run.manifest.agent_names else set()
    for f in run.findings:
        # "unmonitorable" is an honest capability statement (too sparse to detect silence within SLA), not an alarm
        if not f.kind.startswith("silence.") or f.kind == "silence.unmonitorable":
            continue
        toks = tokens(f)
        assert not (toks & set(laptops.details["agents"])), f"laptop false alarm: {f.kind} {f.subject}"
        if toks & expected_rules:  # rule-level finding about a planted rule (e.g. rule dark across its hosts)
            continue
        if toks & allowed:  # a planted silent source (fw-edge-01 is a syslog device, not a Wazuh agent)
            named = (toks & all_agents) - allowed
            assert not named, f"false alarm about {sorted(named)}: {f.kind} {f.subject}"
            continue
        named = toks & all_agents
        if named:
            assert named <= allowed, f"false alarm about {sorted(named - allowed)}: {f.kind} {f.subject}"
        else:
            pytest.fail(f"unexpected silence finding: {f.kind} {f.subject}")


def test_suppression_file_is_written_and_valid(run: Run) -> None:
    emitted = run.outcome.emitted
    assert emitted is not None and emitted.paths, "expected Wazuh suppression rules for the safe candidates"
    xml_path = Path(emitted.paths[0])
    assert os.name != "posix" or xml_path.stat().st_mode & 0o077 == 0
    import xml.etree.ElementTree as ET

    root = ET.fromstring(f"<root>{xml_path.read_text(encoding='utf-8')}</root>")
    ids = [int(r.get("id", "0")) for r in root.iter("rule")]
    assert ids and len(ids) == len(set(ids)) and all(100000 <= i <= 120000 for i in ids)
    assert all(r.get("level") != "0" for r in root.iter("rule")), "demo suppressions must DEMOTE, never drop"
