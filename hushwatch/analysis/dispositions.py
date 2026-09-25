"""Analyst dispositions (how alerts were closed) as evidence for, or against, tuning.

CSV format (header row required; column names are case-insensitive, extra columns are ignored)::

    alert_id,rule_id,field,value,verdict,closed_at,tenant
    1790331332.1234567,,,,fp,2026-09-20T10:00:00Z,
    ,5710,data.srcip,10.20.0.15,benign,2026-09-01,
    ,60122,,,tp,,

* ``alert_id`` (Wazuh ``id`` / indexer ``_id``) scopes a row to ONE alert. A row with an ``alert_id`` is never
  read as a rule-wide statement, even when ``rule_id`` is also filled in.
* Otherwise ``rule_id`` is required; ``field`` + ``value`` (both or neither) narrow the row to the alerts of
  that rule whose ORIGINAL dotted field has exactly that value. A ``rule_id`` row without a field covers the
  whole rule.
* ``verdict``: ``tp``, ``fp``, ``btp`` (benign true positive), ``duplicate`` or ``untriaged`` — case-insensitive;
  ``true_positive``, ``false_positive``, ``benign``, ``benign_positive``, ``benign_true_positive`` and
  ``auto_closed`` (→ untriaged) are accepted too.
* ``closed_at``: optional ISO-8601 / epoch timestamp. An unparseable value makes an FP/BTP row invalid (it
  could not be dated), while a TP row is kept undated — dropping a true positive would be the unsafe choice.
* ``tenant``: optional; when :meth:`Dispositions.load` is given a tenant, rows for other tenants are skipped.

FP evidence is ``fp + btp`` over triaged rows (``tp + fp + btp``). ``untriaged``/auto-closed and
``duplicate`` never count as FP evidence: about 40% of alerts are never investigated, and counting them would
turn "nobody looked" into "safe to mute". Rates are reported as a Wilson score lower bound with a minimum n.
"""

from __future__ import annotations

import csv
import math
import statistics
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from ..timeutil import parse_ts

VERDICTS: tuple[str, ...] = ("tp", "fp", "btp", "duplicate", "untriaged")

_VERDICT_ALIASES: dict[str, str] = {
    "tp": "tp",
    "true_positive": "tp",
    "truepositive": "tp",
    "fp": "fp",
    "false_positive": "fp",
    "falsepositive": "fp",
    "btp": "btp",
    "benign": "btp",
    "benign_positive": "btp",
    "benign_true_positive": "btp",
    "duplicate": "duplicate",
    "dup": "duplicate",
    "untriaged": "untriaged",
    "auto_closed": "untriaged",
    "autoclosed": "untriaged",
}

_COLUMN_ALIASES: dict[str, str] = {
    "alert_id": "alert_id",
    "alertid": "alert_id",
    "_id": "alert_id",
    "id": "alert_id",
    "rule_id": "rule_id",
    "ruleid": "rule_id",
    "rule": "rule_id",
    "field": "field",
    "value": "value",
    "verdict": "verdict",
    "disposition": "verdict",
    "classification": "verdict",
    "closed_at": "closed_at",
    "closed": "closed_at",
    "closed_time": "closed_at",
    "resolved_at": "closed_at",
    "tenant": "tenant",
}

MAX_ROWS = 2_000_000
_MAX_LEN = {"alert_id": 256, "rule_id": 128, "field": 256, "value": 4096, "tenant": 256, "closed_at": 64}
# a true positive is a veto: it is kept even when its value is long (a whole command line, up to the Windows limit)
_MAX_TP_VALUE = 32_768


def normalize_verdict(text: str | None) -> str | None:
    """Map a free-form verdict to one of :data:`VERDICTS` (None when unknown)."""
    if text is None:
        return None
    key = text.strip().lower().replace("-", "_").replace(" ", "_")
    return _VERDICT_ALIASES.get(key)


# Elastic Security stores the analyst's closing reason on the alert document itself.
INBAND_VERDICT_PATHS: tuple[str, ...] = ("kibana.alert.workflow_reason", "signal.workflow_reason")


def inband_verdict(fields: Mapping[str, object]) -> str | None:
    """Disposition carried by the alert document (``kibana.alert.workflow_reason``), if any."""
    for path in INBAND_VERDICT_PATHS:
        raw = fields.get(path)
        if raw is None and "." in path:
            head = path.split(".", 1)[0]
            node = fields.get(head)
            if isinstance(node, Mapping):
                for part in path.split(".")[1:]:
                    node = node.get(part) if isinstance(node, Mapping) else None
                raw = node
        if isinstance(raw, str):
            verdict = normalize_verdict(raw)
            if verdict is not None:
                return verdict
    return None


def wilson_lower_bound(successes: int, n: int, confidence: float = 0.95) -> float:
    """One-sided Wilson score lower bound of a proportion.

    ``confidence`` is the probability that the true rate is at least the returned value
    (z = Φ⁻¹(confidence): 1.645 at 0.95). Returns 0.0 when ``n`` is 0.
    """
    if n < 0 or successes < 0:
        raise ValueError("successes and n must be >= 0")
    if n == 0:
        return 0.0
    successes = min(successes, n)
    confidence = min(max(confidence, 0.5), 0.999999)
    z = statistics.NormalDist().inv_cdf(confidence)
    phat = successes / n
    z2 = z * z
    centre = phat + z2 / (2 * n)
    margin = z * math.sqrt(phat * (1 - phat) / n + z2 / (4 * n * n))
    return max(0.0, (centre - margin) / (1 + z2 / n))


@dataclass(frozen=True, slots=True)
class Disposition:
    """One valid CSV row."""

    verdict: str
    alert_id: str | None = None
    rule_id: str | None = None
    field: str | None = None
    value: str | None = None
    closed_at: datetime | None = None
    line: int = 0

    @property
    def rule_wide(self) -> bool:
        return self.alert_id is None and self.rule_id is not None and self.field is None


@dataclass(slots=True)
class DispositionCounts:
    """Verdict counts for one scope."""

    tp: int = 0
    fp: int = 0
    btp: int = 0
    duplicate: int = 0
    untriaged: int = 0

    def add(self, verdict: str, weight: int = 1) -> None:
        if verdict in VERDICTS:
            setattr(self, verdict, getattr(self, verdict) + weight)

    def merge(self, other: DispositionCounts) -> None:
        for verdict in VERDICTS:
            self.add(verdict, getattr(other, verdict))

    @property
    def fp_evidence(self) -> int:
        """FP + benign true positives (never untriaged, never duplicates)."""
        return self.fp + self.btp

    @property
    def triaged(self) -> int:
        """Rows that carry evidence either way: TP + FP + BTP."""
        return self.tp + self.fp + self.btp

    def fp_lower_bound(self, confidence: float, min_n: int) -> float | None:
        """Wilson lower bound of the FP rate, or None when fewer than ``min_n`` triaged dispositions exist."""
        if self.triaged < max(1, min_n):
            return None
        return wilson_lower_bound(self.fp_evidence, self.triaged, confidence)

    def as_dict(self) -> dict[str, int]:
        return {v: getattr(self, v) for v in VERDICTS}


@dataclass(slots=True)
class Dispositions:
    """Loaded dispositions with lookups by alert id and by ``(rule_id, field, value)`` scope."""

    rows: list[Disposition] = field(default_factory=list)
    source: str | None = None
    bad_rows: int = 0
    skipped_other_tenant: int = 0
    undated_tp: int = 0
    truncated: bool = False
    _by_alert: dict[str, list[Disposition]] = field(default_factory=dict, repr=False)
    _by_scope: dict[tuple[str, str, str], list[Disposition]] = field(default_factory=dict, repr=False)
    _rule_wide: dict[str, list[Disposition]] = field(default_factory=dict, repr=False)
    _scoped_by_rule: dict[str, list[Disposition]] = field(default_factory=dict, repr=False)

    def __post_init__(self) -> None:
        rows, self.rows = self.rows, []
        for row in rows:
            self._index(row)

    # ---- construction ----------------------------------------------------------------------------------------
    @classmethod
    def load(cls, path: str | Path, *, tenant: str | None = None) -> Dispositions:
        """Read a dispositions CSV. Bad rows are counted in ``bad_rows`` and skipped, never fatal.

        A missing/unreadable file raises ``OSError``: silently ignoring configured dispositions would drop
        true-positive vetoes.
        """
        file_path = Path(path).expanduser()
        with file_path.open("r", encoding="utf-8-sig", errors="replace", newline="") as handle:
            result = cls.from_lines(handle, tenant=tenant)
        result.source = str(file_path)
        return result

    @classmethod
    def from_lines(cls, lines: Iterable[str], *, tenant: str | None = None) -> Dispositions:
        """Parse CSV text lines (first line = header)."""
        result = cls()
        reader = csv.reader(lines)
        header: list[str | None] | None = None
        while True:
            try:
                raw = next(reader)
            except StopIteration:
                break
            except csv.Error:
                if header is not None:
                    result.bad_rows += 1
                continue
            if header is None:
                if not any(cell.strip() for cell in raw):
                    continue
                header = [_COLUMN_ALIASES.get(_norm_header(cell)) for cell in raw]
                if "verdict" not in header or ("alert_id" not in header and "rule_id" not in header):
                    raise ValueError("dispositions CSV needs a 'verdict' column and an 'alert_id' or 'rule_id' column")
                continue
            if not any(cell.strip() for cell in raw):
                continue
            if len(result.rows) >= MAX_ROWS:
                result.truncated = True
                break
            row: dict[str, str] = {}
            for name, cell in zip(header, raw, strict=False):
                if name is not None and name not in row:
                    row[name] = cell.strip()
            parsed = result._parse_row(row, reader.line_num, tenant)
            if parsed is not None:
                result._index(parsed)
        return result

    @classmethod
    def from_rows(cls, rows: Iterable[Mapping[str, str | None]], *, tenant: str | None = None) -> Dispositions:
        """Build from dict rows (same column names as the CSV)."""
        result = cls()
        for number, raw in enumerate(rows, start=1):
            row = {
                _COLUMN_ALIASES.get(_norm_header(str(k)), ""): str(v).strip() for k, v in raw.items() if v is not None
            }
            row.pop("", None)
            parsed = result._parse_row(row, number, tenant)
            if parsed is not None:
                result._index(parsed)
        return result

    def _parse_row(self, row: Mapping[str, str], line: int, tenant: str | None) -> Disposition | None:
        verdict = normalize_verdict(row.get("verdict"))
        for name, limit in _MAX_LEN.items():
            if name == "value" and verdict == "tp":
                limit = _MAX_TP_VALUE
            if len(row.get(name, "")) > limit:
                self.bad_rows += 1
                return None
        row_tenant = (row.get("tenant") or "").strip()
        # tenant names are compared case-insensitively: "Acme" in the CSV must not silently drop Acme's TP vetoes
        if tenant is not None and row_tenant and row_tenant.casefold() != tenant.strip().casefold():
            self.skipped_other_tenant += 1
            return None
        alert_id = row.get("alert_id") or None
        rule_id = row.get("rule_id") or None
        field_name = row.get("field") or None
        value = row.get("value") or None
        if verdict is None or (alert_id is None and rule_id is None):
            self.bad_rows += 1
            return None
        if alert_id is None and (field_name is None) != (value is None):
            self.bad_rows += 1
            return None
        if alert_id is not None:
            field_name = value = None  # an alert-level row is about that alert only
        closed_at: datetime | None = None
        closed_raw = row.get("closed_at") or ""
        if closed_raw:
            closed_at = parse_ts(closed_raw)
            if closed_at is None:
                if verdict != "tp":
                    self.bad_rows += 1
                    return None
                self.undated_tp += 1
        return Disposition(verdict, alert_id, rule_id, field_name, value, closed_at, line)

    def _index(self, row: Disposition) -> None:
        self.rows.append(row)
        if row.alert_id is not None:
            self._by_alert.setdefault(row.alert_id, []).append(row)
        elif row.rule_id is not None:
            if row.field is None:
                self._rule_wide.setdefault(row.rule_id, []).append(row)
            else:
                assert row.value is not None
                self._by_scope.setdefault((row.rule_id, row.field, row.value), []).append(row)
                self._scoped_by_rule.setdefault(row.rule_id, []).append(row)

    # ---- lookups ---------------------------------------------------------------------------------------------
    def verdict_for_alert(self, alert_id: str | None, since: datetime | None = None) -> str | None:
        """Verdict of one alert: ``tp`` if any row says so (conservative), else the most recently closed row."""
        if not alert_id:
            return None
        rows = self._by_alert.get(alert_id)
        if not rows:
            return None
        rows = [r for r in rows if _in_range(r, since)]
        if not rows:
            return None
        if any(r.verdict == "tp" for r in rows):
            return "tp"
        return max(rows, key=_row_order).verdict

    def for_scope(self, rule_id: str, field_name: str, value: str) -> list[Disposition]:
        """Rows scoped exactly to ``rule_id`` + ``field`` = ``value``."""
        return list(self._by_scope.get((rule_id, field_name, value), ()))

    def rule_wide(self, rule_id: str) -> list[Disposition]:
        """Rows that cover the whole rule (``rule_id`` without field/value and without alert id)."""
        return list(self._rule_wide.get(rule_id, ()))

    def scoped_for_rule(self, rule_id: str) -> list[Disposition]:
        """All field-scoped rows of a rule (any field)."""
        return list(self._scoped_by_rule.get(rule_id, ()))

    def counts_for_scope(
        self,
        rule_id: str,
        conditions: Iterable[tuple[str, str]],
        *,
        since: datetime | None = None,
        include_rule_wide: bool = False,
    ) -> DispositionCounts:
        """Counts of rule-scoped rows that apply to a condition set.

        A ``(rule_id, field, value)`` row applies when ``(field, value)`` is one of ``conditions`` (the row's
        scope contains the candidate's). Rule-wide rows are only included on request: a rule-wide FP rate says
        nothing about one entity (Simpson's paradox), but a rule-wide TP is a conservative veto.
        """
        counts = DispositionCounts()
        seen: set[int] = set()
        for field_name, value in conditions:
            for row in self._by_scope.get((rule_id, field_name, value), ()):
                if id(row) not in seen and _in_range(row, since):
                    seen.add(id(row))
                    counts.add(row.verdict)
        if include_rule_wide:
            for row in self._rule_wide.get(rule_id, ()):
                if _in_range(row, since):
                    counts.add(row.verdict)
        return counts

    def has_alert_rows(self) -> bool:
        return bool(self._by_alert)

    def stats(self) -> dict[str, int | bool]:
        return {
            "rows": len(self.rows),
            "alert_rows": sum(len(v) for v in self._by_alert.values()),
            "scope_rows": sum(len(v) for v in self._by_scope.values()),
            "rule_wide_rows": sum(len(v) for v in self._rule_wide.values()),
            "bad_rows": self.bad_rows,
            "skipped_other_tenant": self.skipped_other_tenant,
            "undated_tp": self.undated_tp,
            "truncated": self.truncated,
        }

    def __len__(self) -> int:
        return len(self.rows)

    def __iter__(self) -> Iterator[Disposition]:
        return iter(self.rows)


def _norm_header(cell: str) -> str:
    return cell.strip().strip("﻿").lower().replace("-", "_").replace(" ", "_")


def _in_range(row: Disposition, since: datetime | None) -> bool:
    """Undated rows are always in range (conservative for TP vetoes)."""
    return since is None or row.closed_at is None or row.closed_at >= since


def _row_order(row: Disposition) -> tuple[float, int]:
    return (row.closed_at.timestamp() if row.closed_at is not None else float("-inf"), row.line)
