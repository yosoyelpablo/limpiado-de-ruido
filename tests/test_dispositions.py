"""Dispositions CSV: robust loading, lookups, Wilson lower bound, FP evidence rules."""

from __future__ import annotations

import io
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from hushwatch.analysis.dispositions import (
    DispositionCounts,
    Dispositions,
    normalize_verdict,
    wilson_lower_bound,
)

UTC = timezone.utc


def _load(text: str, **kw: str) -> Dispositions:
    return Dispositions.from_lines(io.StringIO(text), **kw)


# ---- Wilson ------------------------------------------------------------------------------------------------------
def test_wilson_lower_bound_reference_values() -> None:
    assert wilson_lower_bound(0, 0) == 0.0
    # 10/10 at one-sided 95% (z = 1.645): the "100% FP (n=10)" trap is really "FP >= 78.7%"
    assert wilson_lower_bound(10, 10, 0.95) == pytest.approx(0.787, abs=0.001)
    # classic two-sided 95% Wilson interval for 81/100 is [0.722, 0.872] -> one-sided 97.5%
    assert wilson_lower_bound(81, 100, 0.975) == pytest.approx(0.7222, abs=0.0005)
    assert wilson_lower_bound(0, 50) == 0.0


def test_wilson_lower_bound_properties() -> None:
    assert wilson_lower_bound(2, 2) < wilson_lower_bound(40, 40) < 1.0
    assert wilson_lower_bound(40, 42, 0.99) < wilson_lower_bound(40, 42, 0.95)
    assert wilson_lower_bound(50, 10) == wilson_lower_bound(10, 10)  # clamped
    assert 0.0 <= wilson_lower_bound(1, 1_000_000) <= 1.0
    with pytest.raises(ValueError):
        wilson_lower_bound(-1, 5)
    with pytest.raises(ValueError):
        wilson_lower_bound(1, -5)


def test_counts_fp_evidence_never_includes_untriaged_or_duplicates() -> None:
    counts = DispositionCounts()
    for verdict, n in (("fp", 3), ("btp", 2), ("untriaged", 100), ("duplicate", 50), ("tp", 1)):
        counts.add(verdict, n)
    counts.add("bogus")
    assert counts.fp_evidence == 5
    assert counts.triaged == 6
    assert counts.fp_lower_bound(0.95, min_n=10) is None  # not enough evidence
    lower = counts.fp_lower_bound(0.95, min_n=5)
    assert lower is not None and lower < 5 / 6
    other = DispositionCounts(fp=1)
    counts.merge(other)
    assert counts.fp == 4 and counts.as_dict()["untriaged"] == 100


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("TP", "tp"),
        ("true_positive", "tp"),
        ("True Positive", "tp"),
        ("FALSE-POSITIVE", "fp"),
        ("benign", "btp"),
        ("benign_positive", "btp"),
        ("Benign True Positive", "btp"),
        ("duplicate", "duplicate"),
        ("auto-closed", "untriaged"),
        ("closed", None),
        ("", None),
        (None, None),
    ],
)
def test_normalize_verdict(text: str | None, expected: str | None) -> None:
    assert normalize_verdict(text) == expected


# ---- loading -----------------------------------------------------------------------------------------------------
def test_load_csv_with_bom_aliases_extra_columns_and_bad_rows(tmp_path: Path) -> None:
    path = tmp_path / "dispositions.csv"
    rows = [
        "Alert_ID,Rule_ID,Field,Value,Verdict,Closed_At,analyst_notes,tenant",
        "1790331332.1234567,5710,,,FP,2026-09-20T10:00:00Z,looked fine,",
        "1790331332.2,,,,true_positive,2026-09-19,,",
        ",5710,data.srcip,10.20.0.15,benign,2026-09-01,internal scanner,",
        ",60122,,,tp,,,",
        ",5710,data.srcip,,fp,,,",  # field without value -> bad
        ",,,,fp,,,",  # no id at all -> bad
        "1790331332.3,,,,maybe,,,",  # unknown verdict -> bad
        "1790331332.4,,,,fp,not-a-date,,",  # undatable FP -> bad
        "1790331332.5,,,,tp,not-a-date,,",  # undatable TP -> kept (dropping a TP is unsafe)
        "",
        "1790331332.6,,,,fp,2026-09-10,,other-tenant",
    ]
    path.write_bytes(("﻿" + "\r\n".join(rows) + "\r\n").encode("utf-8"))
    disp = Dispositions.load(path, tenant="acme")
    assert disp.source == str(path)
    assert disp.bad_rows == 4
    assert disp.undated_tp == 1
    assert disp.skipped_other_tenant == 1
    assert len(disp) == 5
    # an alert-id row is never a rule-wide statement, even with rule_id filled in
    assert disp.verdict_for_alert("1790331332.1234567") == "fp"
    assert disp.rule_wide("5710") == []
    assert [r.verdict for r in disp.rule_wide("60122")] == ["tp"]
    scoped = disp.for_scope("5710", "data.srcip", "10.20.0.15")
    assert [r.verdict for r in scoped] == ["btp"]
    assert disp.for_scope("5710", "data.srcip", "10.20.0.16") == []
    assert disp.verdict_for_alert("1790331332.5") == "tp"
    assert disp.verdict_for_alert(None) is None and disp.verdict_for_alert("nope") is None
    stats = disp.stats()
    assert stats["bad_rows"] == 4 and stats["alert_rows"] == 3 and stats["scope_rows"] == 1


def test_load_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(OSError):
        Dispositions.load(tmp_path / "absent.csv")


def test_header_without_required_columns_is_an_error() -> None:
    with pytest.raises(ValueError):
        _load("id_of_something,comment\n1,x\n")
    with pytest.raises(ValueError):
        _load("alert_id,comment\n1,x\n")


def test_hostile_csv_content_does_not_crash() -> None:
    huge = "x" * 200_000  # beyond csv.field_size_limit: counted as a bad row, parsing continues
    text = (
        "alert_id,verdict,value\n"
        f"{huge},fp,\n"
        'a1,fp,=HYPERLINK("http://198.51.100.9")\n'
        "a2\x00,tp,\n"
        '"a3,with,commas",btp,"multi\nline"\n'
        f"a4,fp,{'y' * 5000}\n"
        'a5,fp,</field></rule><rule id="100999" level="0">\n'
    )
    disp = _load(text)
    assert disp.verdict_for_alert("a1") == "fp"
    assert disp.verdict_for_alert("a2") == "tp"  # NUL dropped consistently on every Python version
    assert disp.verdict_for_alert("a3,with,commas") == "btp"
    assert disp.verdict_for_alert("a5") == "fp"
    assert disp.verdict_for_alert("a4") is None
    assert disp.bad_rows == 2  # the field beyond the csv limit, and a4's over-long value


def test_verdict_for_alert_is_conservative_and_respects_since() -> None:
    now = datetime(2026, 9, 25, tzinfo=UTC)
    disp = _load(
        "alert_id,verdict,closed_at\n"
        "x,fp,2026-09-01T00:00:00Z\n"
        "x,tp,2026-01-01T00:00:00Z\n"
        "y,fp,2026-09-01T00:00:00Z\n"
        "y,btp,2026-09-10T00:00:00Z\n"
    )
    assert disp.verdict_for_alert("x") == "tp"  # any TP wins
    assert disp.verdict_for_alert("x", since=now - timedelta(days=90)) == "fp"  # old TP out of the look-back
    assert disp.verdict_for_alert("y") == "btp"  # most recent


def test_counts_for_scope() -> None:
    now = datetime(2026, 9, 25, tzinfo=UTC)
    disp = Dispositions.from_rows(
        [
            {"rule_id": "60106", "field": "agent.name", "value": "srv-backup-01", "verdict": "btp"},
            {"rule_id": "60106", "field": "data.win.eventdata.targetUserName", "value": "svc_backup", "verdict": "fp"},
            {"rule_id": "60106", "field": "data.win.eventdata.targetUserName", "value": "alice", "verdict": "tp"},
            {"rule_id": "60106", "verdict": "fp", "closed_at": "2026-09-20"},
            {"rule_id": "60106", "verdict": "tp", "closed_at": "2025-01-01"},
            {
                "rule_id": "60106",
                "field": "agent.name",
                "value": "srv-backup-01",
                "verdict": "fp",
                "closed_at": "2025-01-01",
            },
            {"Rule": "5710", "Verdict": "FP", "unknown column": "ignored"},
        ]
    )
    conds = [("agent.name", "srv-backup-01"), ("data.win.eventdata.targetUserName", "svc_backup")]
    counts = disp.counts_for_scope("60106", conds)
    assert (counts.fp, counts.btp, counts.tp) == (2, 1, 0)
    recent = disp.counts_for_scope("60106", conds, since=now - timedelta(days=90))
    assert (recent.fp, recent.btp) == (1, 1)
    with_rule_wide = disp.counts_for_scope("60106", [], since=now - timedelta(days=90), include_rule_wide=True)
    assert (with_rule_wide.fp, with_rule_wide.tp) == (1, 0)
    assert len(disp.scoped_for_rule("60106")) == 4
    assert [r.verdict for r in disp.rule_wide("5710")] == ["fp"]
    assert disp.has_alert_rows() is False


def test_inband_verdict() -> None:
    from hushwatch.analysis.dispositions import inband_verdict

    assert inband_verdict({"kibana.alert.workflow_reason": "false_positive"}) == "fp"
    assert inband_verdict({"kibana": {"alert": {"workflow_reason": "Benign positive"}}}) == "btp"
    assert inband_verdict({"kibana.alert.workflow_reason": "whatever"}) is None
    assert inband_verdict({"kibana": "not a mapping"}) is None
    assert inband_verdict({}) is None


def test_true_positives_survive_tenant_case_and_long_values() -> None:
    long_cmd = "powershell.exe -enc " + "A" * 10_000
    disp = Dispositions.from_rows(
        [
            {"rule_id": "92001", "field": "data.win.eventdata.commandLine", "value": long_cmd, "verdict": "tp",
             "tenant": "ACME"},
            {"rule_id": "92001", "field": "data.win.eventdata.commandLine", "value": long_cmd, "verdict": "fp"},
            {"rule_id": "5710", "verdict": "tp", "tenant": "globex"},
        ],
        tenant="acme",
    )  # fmt: skip
    assert [r.verdict for r in disp] == ["tp"]  # the TP veto is kept, the oversized FP row is not evidence
    assert disp.bad_rows == 1 and disp.skipped_other_tenant == 1
