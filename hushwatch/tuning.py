"""Types shared by the noise analyzer (which proposes tuning) and the Wazuh emitter/audit (which writes it).

A :class:`Suggestion` is a *scoped* tuning proposal: one rule plus 1-2 exact-match conditions on source
fields. ``Suggestion.matches`` is the single source of truth for its semantics: the backtest uses it to count
what would be hidden, and the Wazuh emitter must generate XML that matches exactly the same events
(anchored, case-sensitive, exact values).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import date
from typing import Any

from .i18n import Message
from .models import Event, get_path

_USER_FIELDS = frozenset({"data.srcuser", "data.dstuser"})
_BACKSLASH_RUN = re.compile(r"\\+")


def _norm(value: str) -> str:
    return _BACKSLASH_RUN.sub("\\\\", value) if "\\" in value else value


VERDICTS: tuple[str, ...] = ("tune", "investigate", "fix_at_source", "aggregate", "do_not_tune", "watch", "learning")
ACTIONS: tuple[str, ...] = ("demote", "review")
# What a suggestion would change: "analyst" (alerts leave the triage queue), "index_volume" (passed every gate and
# the backtest, but its rule is already at/below the demote level or below triage_level, so demoting it changes
# nothing for analysts: only index volume could be saved, and never by a demote rule), "" (not assessed yet).
IMPACTS: tuple[str, ...] = ("analyst", "index_volume", "")
DEMOTE_LEVEL = 3  # level of the generated child rules (Wazuh's default log_alert_level: still indexed)
LOG_ALERT_LEVEL = 3  # Wazuh default <log_alert_level>: alerts below it are not written to alerts.json


@dataclass(frozen=True, slots=True)
class Condition:
    """Exact match of a source field. ``field`` is the dotted path in the ORIGINAL document, e.g.
    ``agent.name``, ``predecoder.hostname``, ``location``, ``data.srcip``, ``data.win.eventdata.image``."""

    field: str
    value: str

    def matches(self, event: Event) -> bool:
        r"""Exactly the events the generated Wazuh rule would match.

        Two Wazuh behaviours are mirrored so the backtest never under-counts what a rule hides:
        ``<user>`` tests ``dstuser`` when present and falls back to ``srcuser``; and Windows backslashes are
        matched as runs (``(?:\x{5c})+``) because eventchannel values carry doubled backslashes.
        """
        if self.field in _USER_FIELDS:
            dst = get_path(event.fields, "data.dstuser")
            actual: Any = dst if dst not in (None, "") else get_path(event.fields, "data.srcuser")
        else:
            actual = get_path(event.fields, self.field)
        want = _norm(self.value)
        if isinstance(actual, list):
            return any(_norm(str(v)) == want for v in actual)
        return actual is not None and _norm(str(actual)) == want


@dataclass(slots=True)
class Suggestion:
    rule_id: str
    conditions: tuple[Condition, ...]
    verdict: str
    fingerprint: str
    expires: date
    action: str = "demote"
    rule_level: int | None = None
    rule_description: str | None = None
    rule_groups: tuple[str, ...] = ()
    rule_mitre: tuple[str, ...] = ()
    profile: str = "wazuh4"
    dependents: tuple[str, ...] = ()  # rules that correlate on rule_id (if_matched_* / frequency)
    hidden_total: int = 0
    hidden_per_day: float = 0.0
    hidden_analyst_facing: int = 0
    share_of_rule: float = 0.0
    reasons: list[Message | str] = field(default_factory=list)
    examples: list[dict[str, Any]] = field(default_factory=list)  # raw example docs (local files only)
    impact: str = ""  # see IMPACTS
    dependents_verified: bool = True  # False: the stock ruleset (or any ruleset) was not loaded

    def matches(self, event: Event) -> bool:
        if event.rule_id != self.rule_id:
            return False
        return all(condition.matches(event) for condition in self.conditions)

    @property
    def review_required(self) -> bool:
        return bool(self.dependents) or self.action == "review" or not self.dependents_verified

    @property
    def index_volume(self) -> bool:
        """Passed every gate and the backtest, but only index volume is at stake (see :data:`IMPACTS`)."""
        return self.impact == "index_volume"
