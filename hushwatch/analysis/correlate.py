"""Cross-domain root-cause linking: one incident, one finding.

The analyzers look at the same incident from different angles. A domain controller whose audit log was cleared
and that then went quiet shows up as possible tampering (silence), as an agent that is connected but sends nothing
(pipeline), and as a critical host whose sparse channels are hard to monitor (silence). An agent that is
disconnected is also a silent source. A Sysmon channel that stopped on one host breaks the telemetry contract
of its host group (coverage). Reporting each of these separately makes one problem look like three and sends the
analyst down three different runbooks.

:func:`link_findings` keeps the finding with the most specific cause for each incident and folds the others into
it: their fingerprints go into ``related`` (so cron mode keeps them "present", never "resolved") and a human-readable
line per folded finding goes into ``evidence["explained"]`` and into the reasons. The rules:

* ``silence.tampering`` / ``silence.silent`` / ``silence.drop`` on a whole host X (or ``pipeline.global_silence``
  listing X) explains ``pipeline.agent_no_data`` and ``silence.unmonitorable`` on X;
* the same silence on X, or on log source L of X, explains ``coverage.missing_source`` (contract, ``state`` =
  ``silent``) for X + L: the source was seen on X and stopped, which is silence, not a coverage gap;
* ``pipeline.agent_disconnected`` on X and a ``silence.silent`` / ``silence.drop`` on X are one incident: the
  disconnection is the more specific cause and is kept; ``silence.tampering`` on X is more specific still and
  explains the disconnection.

A finding is never folded into one that is LESS severe than itself (then both stay), and grouped findings (several
hosts) are only folded when every host they list is explained. The function is pure: the input findings are not
modified; the returned list keeps the input order.
"""

from __future__ import annotations

import fnmatch
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, replace
from typing import Any

from ..i18n import Entity, M, Message, register
from ..models import Finding

__all__ = ["link_findings"]

MAX_REASONS = 5  # folded findings named in the explainer's reasons (the evidence lists them all, capped below)
MAX_EXPLAINED_ITEMS = 50

# host-level silence kinds that can explain other findings, most specific cause first
_SILENCE_SPECIFICITY = {"silence.tampering": 3, "silence.silent": 2, "silence.drop": 1, "pipeline.global_silence": 0}
_PAIRED_SILENCE = frozenset({"silence.silent", "silence.drop"})

register(
    {
        "correlate.explained.item": {
            "en": "{title} ({domain}, {severity})",
            "es": "{title} ({domain}, {severity})",
        },
        "correlate.reason.explains": {
            "en": "Same incident, reported once here: {title} ({domain}).",
            "es": "Mismo incidente, informado una sola vez aquí: {title} ({domain}).",
        },
        "correlate.reason.explains_more": {
            "en": "Also covers {count} more related {count:plural:finding|findings}, listed in the evidence.",
            "es": "También cubre {count} {count:plural:hallazgo relacionado|hallazgos relacionados} más, "
            "{count:plural:listado|listados} en la evidencia.",
        },
    }
)


@dataclass(slots=True)
class _Scope:
    """What a finding is about: host names (casefolded) and, for channel-level findings, the log source."""

    hosts: tuple[str, ...]
    complete: bool  # every host of the finding is listed (grouped findings may cap their host list)
    log_source: str | None = None


def link_findings(findings: list[Finding]) -> list[Finding]:
    """Fold findings that describe the same incident into the one with the most specific cause.

    Returns a new list (input order kept, folded findings removed); explainers are copies whose ``related``,
    ``evidence["explained"]`` / ``evidence["explained_count"]`` and ``reasons`` list what they absorbed.
    """
    items = list(findings)
    host_silence: dict[str, list[int]] = {}  # host -> host-level silence findings (and global outages)
    channel_silence: dict[str, list[tuple[str, int]]] = {}  # host -> [(log source, index)]
    disconnected: dict[str, list[int]] = {}  # host -> pipeline.agent_disconnected findings
    for i, finding in enumerate(items):
        kind = finding.kind
        if kind in _SILENCE_SPECIFICITY:
            scope = _silence_scope(finding)
            if scope is None:
                continue
            for host in scope.hosts:
                if scope.log_source is None:
                    host_silence.setdefault(host, []).append(i)
                else:
                    channel_silence.setdefault(host, []).append((scope.log_source, i))
        elif kind == "pipeline.agent_disconnected":
            scope = _hosts_scope(finding)
            if scope is not None:
                for host in scope.hosts:
                    disconnected.setdefault(host, []).append(i)

    def best(candidates: Iterable[int]) -> int | None:
        pool = list(dict.fromkeys(candidates))
        if not pool:
            return None
        return max(pool, key=lambda j: (_SILENCE_SPECIFICITY.get(items[j].kind, 0), items[j].severity.rank, -j))

    def rank(j: int) -> int:
        return items[j].severity.rank

    link: dict[int, int] = {}  # explained -> explainer
    for i, finding in enumerate(items):
        kind = finding.kind
        if kind in ("pipeline.agent_no_data", "silence.unmonitorable"):
            scope = _hosts_scope(finding)
            if scope is None or not scope.complete:
                continue
            per_host = [best(host_silence.get(h, ())) for h in scope.hosts]
            if per_host and all(j is not None for j in per_host):
                target = _strongest([j for j in per_host if j is not None], items)
                if target != i:
                    link[i] = target
        elif kind == "coverage.missing_source":
            evidence = _evidence(finding)
            pattern = evidence.get("log_source")
            if evidence.get("check") != "contract" or evidence.get("state") != "silent" or not isinstance(pattern, str):
                continue
            scope = _hosts_scope(finding)
            if scope is None or not scope.complete:
                continue
            per_host = []
            for host in scope.hosts:
                channel = [j for ls, j in channel_silence.get(host, ()) if _ls_match(ls, pattern)]
                per_host.append(best(channel) if channel else best(host_silence.get(host, ())))
            if per_host and all(j is not None for j in per_host):
                link[i] = _strongest([j for j in per_host if j is not None], items)
        elif kind == "pipeline.agent_disconnected":
            scope = _hosts_scope(finding)
            if scope is None or not scope.complete or len(scope.hosts) != 1:
                continue
            host = scope.hosts[0]
            tampering = [j for j in host_silence.get(host, ()) if items[j].kind == "silence.tampering"]
            if tampering:
                link[i] = _strongest(tampering, items)  # the attack is the more specific cause of the disconnection
                continue
            # a silence clearly MORE severe than the disconnection keeps its own finding and absorbs it
            louder = [j for j in host_silence.get(host, ()) if items[j].kind in _PAIRED_SILENCE and rank(j) > rank(i)]
            if louder:
                link[i] = _strongest(louder, items)
        elif kind in _PAIRED_SILENCE:
            scope = _silence_scope(finding)
            if scope is None or scope.log_source is not None or len(scope.hosts) != 1:
                continue
            # the disconnection names the cause of this silence: fold the silence into it (unless louder)
            candidates = [j for j in disconnected.get(scope.hosts[0], ()) if rank(j) >= rank(i)]
            if candidates:
                link[i] = _strongest(candidates, items)

    roots = _resolve(link, items)
    absorbed: dict[int, list[int]] = {}
    for i in range(len(items)):
        root = roots.get(i, i)
        if root != i:
            absorbed.setdefault(root, []).append(i)
    out: list[Finding] = []
    for i, finding in enumerate(items):
        if roots.get(i, i) != i:
            continue
        members = absorbed.get(i)
        out.append(_fold(finding, [items[j] for j in members]) if members else finding)
    return out


# ---- helpers ------------------------------------------------------------------------------------------------------


def _resolve(link: Mapping[int, int], items: Sequence[Finding]) -> dict[int, int]:
    """Root explainer of every linked finding. A finding more severe than the root it would be folded into stays
    on its own (and becomes the root of whatever was linked to it)."""
    memo: dict[int, int] = {}

    def root(i: int, seen: frozenset[int]) -> int:
        cached = memo.get(i)
        if cached is not None:
            return cached
        target = link.get(i)
        if target is None or target == i or target in seen:
            memo[i] = i
            return i
        top = root(target, seen | {i})
        memo[i] = i if items[i].severity.rank > items[top].severity.rank else top
        return memo[i]

    for i in link:
        root(i, frozenset())
    return memo


def _strongest(candidates: Sequence[int], items: Sequence[Finding]) -> int:
    """The explainer to fold into: most severe, then most specific cause, then first in the input."""
    return max(candidates, key=lambda j: (items[j].severity.rank, _SILENCE_SPECIFICITY.get(items[j].kind, 4), -j))


def _fold(root: Finding, members: Sequence[Finding]) -> Finding:
    evidence = dict(_evidence(root))
    existing = evidence.get("explained")
    explained: list[Any] = list(existing) if isinstance(existing, (list, tuple)) else []
    base_count = evidence.get("explained_count")
    count = base_count if isinstance(base_count, int) and not isinstance(base_count, bool) else len(explained)
    items: list[Message] = [
        M(
            "correlate.explained.item",
            title=_title(m),
            domain=M(f"domain.{m.domain}"),
            severity=M(f"severity.{m.severity.value}"),
        )
        for m in members
    ]
    evidence["explained"] = (explained + items)[: max(len(explained), MAX_EXPLAINED_ITEMS)]
    evidence["explained_count"] = count + len(members)
    reasons: list[Message | str] = list(root.reasons)
    for m in members[:MAX_REASONS]:
        reasons.append(M("correlate.reason.explains", title=_title(m), domain=M(f"domain.{m.domain}")))
    if len(members) > MAX_REASONS:
        reasons.append(M("correlate.reason.explains_more", count=len(members) - MAX_REASONS))
    related = list(root.related)
    for m in members:
        related.append(m.fingerprint)
        related.extend(m.related)
    related = [fp for fp in dict.fromkeys(related) if fp and fp != root.fingerprint]
    return replace(root, evidence=evidence, reasons=reasons, related=related)


def _title(finding: Finding) -> Message | str:
    return finding.title if isinstance(finding.title, (Message, str)) else finding.kind


def _evidence(finding: Finding) -> Mapping[str, Any]:
    return finding.evidence if isinstance(finding.evidence, Mapping) else {}


def _name(value: Any) -> str | None:
    text = value.value if isinstance(value, Entity) else value
    if isinstance(text, str) and text.strip():
        return text.strip().casefold()
    return None


def _silence_scope(finding: Finding) -> _Scope | None:
    """Host (and log source) of a silence finding, from its evidence (``level`` + ``agent`` / ``log_source``)."""
    evidence = _evidence(finding)
    if finding.kind == "pipeline.global_silence":
        agents = evidence.get("agents")
        hosts = tuple(h for h in (_name(a) for a in agents) if h) if isinstance(agents, (list, tuple)) else ()
        return _Scope(hosts, complete=False) if hosts else None
    host = _name(evidence.get("agent"))
    if host is None:
        return None
    level = evidence.get("level")
    if level == "agent":
        return _Scope((host,), complete=True)
    log_source = evidence.get("log_source")
    if level == "agent_log_source" and isinstance(log_source, str) and log_source:
        return _Scope((host,), complete=True, log_source=log_source)
    return None


def _hosts_scope(finding: Finding) -> _Scope | None:
    """Hosts of a per-host or grouped finding (``host`` / ``agent`` or ``hosts`` + ``hosts_total``)."""
    evidence = _evidence(finding)
    single = _name(evidence.get("host")) or _name(evidence.get("agent"))
    if single is not None and "hosts" not in evidence:
        return _Scope((single,), complete=True)
    hosts_value = evidence.get("hosts")
    if not isinstance(hosts_value, (list, tuple)) or not hosts_value:
        return None
    names = [_name(h) for h in hosts_value]
    hosts = tuple(dict.fromkeys(n for n in names if n))
    if not hosts:
        return None
    total = evidence.get("hosts_total")
    complete = None not in names and (not isinstance(total, int) or total <= len(hosts_value))
    return _Scope(hosts, complete=complete)


def _ls_match(name: str, pattern: str) -> bool:
    """Contract log-source match (as in coverage): case-insensitive, glob when the pattern has wildcards."""
    if any(ch in pattern for ch in "*?["):
        return fnmatch.fnmatchcase(name.casefold(), pattern.casefold())
    return name.casefold() == pattern.casefold()
