"""Audit EXISTING Wazuh tuning: risky suppressions, expired ones, broken correlation, ruleset problems.

Only LOCAL rules are audited (``etc/rules``, ``local_rules*.xml``, anything not recognizably stock); the whole
ruleset is used as context (parents, correlation dependents, groups). Checks per local rule that hides or
demotes the events of the rule(s) it is attached to:

* whole-rule mute: no condition narrows the scope (only ``if_sid``/``if_group``) — high for level 0/no_log;
* substring matching: ``match``/``regex``/``field``/... without ``^...$`` (``admin`` also matches
  ``administrator``), or very broad network ranges — medium;
* conditions only on attacker-controllable data (log text, usernames, URLs, command lines, external IPs) —
  high: anyone who can put that value into a log is hidden;
* the parent feeds correlation (``if_matched_sid``/``if_matched_group``/frequency): the muted events no longer
  count, so e.g. brute-force detection stops for that scope — high;
* the parent is level >= ``tenant.high_level`` or mapped to a sensitive ATT&CK tactic — high (medium when the
  suppression is narrowly anchored on a stable entity);
* no description — low; ``expires YYYY-MM-DD`` in the past — ``tuning.expired``;
* ``overwrite="yes"`` that lowers a stock rule's level, mutes it, weakens a correlation threshold or drops the
  groups a correlation rule relies on.

Parse errors and duplicate ids become ``assessment.incomplete`` findings: part of the ruleset could not be
analyzed, and many of those errors also stop ``wazuh-analysisd``.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import date
from pathlib import PurePath
from typing import Any

from ..config import TenantConfig
from ..i18n import Entity, M, Message, register
from ..models import Confidence, Finding, Severity
from .ruleset import RuleCondition, Ruleset, RulesetError, WazuhRule, evaluation_priority, osmatch

__all__ = ["AuditResult", "audit_ruleset", "technique_tactics"]

DEFAULT_LOG_ALERT_LEVEL = 3  # Wazuh default <log_alert_level>: lower levels never reach alerts.json
_NON_NARROWING = frozenset({"time", "weekday", "decoded_as", "category", "if_fts"})
_ANCHOR_TAGS = frozenset(
    {
        "match",
        "regex",
        "field",
        "user",
        "hostname",
        "location",
        "program_name",
        "url",
        "id",
        "status",
        "action",
        "protocol",
        "system_name",
        "extra_data",
        "data",
        "srcport",
        "dstport",
    }
)
_DEFAULT_TYPE = {"regex": "osregex", "field": "osregex"}
_ATTACKER_TAGS = frozenset(
    {"match", "regex", "url", "extra_data", "data", "id", "status", "system_name", "srcgeoip", "dstgeoip", "srcport"}
)
_ATTACKER_FIELD_HINTS = (
    "commandline",
    "command_line",
    "cmdline",
    "url",
    "uri",
    "useragent",
    "user_agent",
    "filename",
    "file_name",
    "query",
    "scriptblock",
    "message",
    "payload",
    "referer",
    "referrer",
    "request",
    "body",
    "subject",
    "username",
    "user_name",
    "account",
    "workstation",
    "ipaddress",
    "srcip",
    "src_ip",
    "sourceip",
    "source_ip",
    "clientip",
    "client_ip",
    "domain",
    "originalfilename",
    "description",
)
_USER_FIELD_HINTS = ("username", "user_name", "account", "user")
_IP_FIELD_HINTS = ("ipaddress", "srcip", "src_ip", "sourceip", "source_ip", "clientip", "client_ip")
_PATH_FIELD_HINTS = ("image", "processname", "process_name", "path", "exe", "executable")
_EXPIRES = re.compile(
    r"(?i)\b(?:expires?|expiry|expiration|expira|caduca|vence)\b\s*(?:on|el|:|=)?\s*(\d{4}-\d{2}-\d{2})"
)
_PCRE_PREFIX = re.compile(r"^(?:\(\*[A-Z_]+(?:=\d+)?\)|\(\?[A-Za-z^-]*\))*")
_HEX = re.compile(r"\\x\{([0-9A-Fa-f]{1,6})\}|\\x([0-9A-Fa-f]{2})")
_MAX_LISTED = 20
_MAX_ERROR_REASONS = 5

# ATT&CK Enterprise technique (base id) -> tactics, for the techniques Wazuh rules commonly carry. Rule XML has
# technique ids only; the alert's tactic names come from Wazuh's MITRE database, which the audit does not have.
_TACTICS: dict[str, tuple[str, ...]] = {
    # credential access
    "T1003": ("credential access",),
    "T1040": ("credential access", "discovery"),
    "T1056": ("collection", "credential access"),
    "T1110": ("credential access",),
    "T1111": ("credential access",),
    "T1187": ("credential access",),
    "T1212": ("credential access",),
    "T1528": ("credential access",),
    "T1539": ("credential access",),
    "T1552": ("credential access",),
    "T1555": ("credential access",),
    "T1556": ("credential access", "defense evasion", "persistence"),
    "T1557": ("credential access", "collection"),
    "T1558": ("credential access",),
    "T1606": ("credential access",),
    "T1621": ("credential access",),
    "T1649": ("credential access",),
    # lateral movement
    "T1021": ("lateral movement",),
    "T1072": ("execution", "lateral movement"),
    "T1080": ("lateral movement",),
    "T1091": ("lateral movement", "initial access"),
    "T1210": ("lateral movement",),
    "T1534": ("lateral movement",),
    "T1550": ("defense evasion", "lateral movement"),
    "T1563": ("lateral movement",),
    "T1570": ("lateral movement",),
    # command and control
    "T1001": ("command and control",),
    "T1008": ("command and control",),
    "T1071": ("command and control",),
    "T1090": ("command and control",),
    "T1092": ("command and control",),
    "T1095": ("command and control",),
    "T1102": ("command and control",),
    "T1104": ("command and control",),
    "T1105": ("command and control",),
    "T1132": ("command and control",),
    "T1205": ("defense evasion", "persistence", "command and control"),
    "T1219": ("command and control",),
    "T1568": ("command and control",),
    "T1571": ("command and control",),
    "T1572": ("command and control",),
    "T1573": ("command and control",),
    "T1659": ("initial access", "command and control"),
    # exfiltration
    "T1011": ("exfiltration",),
    "T1020": ("exfiltration",),
    "T1029": ("exfiltration",),
    "T1030": ("exfiltration",),
    "T1041": ("exfiltration",),
    "T1048": ("exfiltration",),
    "T1052": ("exfiltration",),
    "T1537": ("exfiltration",),
    "T1567": ("exfiltration",),
    # impact
    "T1485": ("impact",),
    "T1486": ("impact",),
    "T1489": ("impact",),
    "T1490": ("impact",),
    "T1491": ("impact",),
    "T1495": ("impact",),
    "T1496": ("impact",),
    "T1498": ("impact",),
    "T1499": ("impact",),
    "T1529": ("impact",),
    "T1531": ("impact",),
    "T1561": ("impact",),
    "T1565": ("impact",),
    "T1657": ("impact",),
    # defense evasion
    "T1006": ("defense evasion",),
    "T1014": ("defense evasion",),
    "T1027": ("defense evasion",),
    "T1036": ("defense evasion",),
    "T1055": ("defense evasion", "privilege escalation"),
    "T1070": ("defense evasion",),
    "T1078": ("defense evasion", "persistence", "privilege escalation", "initial access"),
    "T1112": ("defense evasion", "persistence"),
    "T1127": ("defense evasion",),
    "T1134": ("defense evasion", "privilege escalation"),
    "T1140": ("defense evasion",),
    "T1197": ("defense evasion", "persistence"),
    "T1202": ("defense evasion",),
    "T1207": ("defense evasion",),
    "T1211": ("defense evasion",),
    "T1216": ("defense evasion",),
    "T1218": ("defense evasion",),
    "T1220": ("defense evasion",),
    "T1221": ("defense evasion",),
    "T1222": ("defense evasion",),
    "T1480": ("defense evasion",),
    "T1484": ("defense evasion", "privilege escalation"),
    "T1497": ("defense evasion", "discovery"),
    "T1542": ("defense evasion", "persistence"),
    "T1548": ("privilege escalation", "defense evasion"),
    "T1553": ("defense evasion",),
    "T1562": ("defense evasion",),
    "T1564": ("defense evasion",),
    "T1574": ("persistence", "privilege escalation", "defense evasion"),
    "T1578": ("defense evasion",),
    "T1599": ("defense evasion",),
    "T1600": ("defense evasion",),
    "T1601": ("defense evasion",),
    "T1610": ("defense evasion", "execution"),
    "T1620": ("defense evasion",),
    "T1622": ("defense evasion", "discovery"),
    # privilege escalation / persistence
    "T1037": ("persistence", "privilege escalation"),
    "T1053": ("execution", "persistence", "privilege escalation"),
    "T1068": ("privilege escalation",),
    "T1098": ("persistence", "privilege escalation"),
    "T1133": ("persistence", "initial access"),
    "T1136": ("persistence",),
    "T1137": ("persistence",),
    "T1176": ("persistence",),
    "T1505": ("persistence",),
    "T1525": ("persistence",),
    "T1543": ("persistence", "privilege escalation"),
    "T1546": ("persistence", "privilege escalation"),
    "T1547": ("persistence", "privilege escalation"),
    "T1554": ("persistence",),
    "T1611": ("privilege escalation",),
    # common non-sensitive ones (listed so evidence can name them)
    "T1046": ("discovery",),
    "T1057": ("discovery",),
    "T1082": ("discovery",),
    "T1083": ("discovery",),
    "T1087": ("discovery",),
    "T1059": ("execution",),
    "T1203": ("execution",),
    "T1204": ("execution",),
    "T1190": ("initial access",),
    "T1566": ("initial access",),
    "T1595": ("reconnaissance",),
}

register(
    {
        "wazuh.audit.title.risky": {
            "en": "Risky suppression: local rule {rule} ({file})",
            "es": "Supresión arriesgada: regla local {rule} ({file})",
        },
        "wazuh.audit.title.undocumented": {
            "en": "Undocumented suppression: local rule {rule} ({file})",
            "es": "Supresión sin documentar: regla local {rule} ({file})",
        },
        "wazuh.audit.title.overwrite": {
            "en": "Local overwrite weakens rule {rule} ({file})",
            "es": "Una sobrescritura local debilita la regla {rule} ({file})",
        },
        "wazuh.audit.action.drop": {
            "en": "level 0: events are dropped and invisible to correlation",
            "es": "nivel 0: los eventos se descartan y la correlación no los ve",
        },
        "wazuh.audit.action.hide": {
            "en": "no alert is written",
            "es": "no se escribe ninguna alerta",
        },
        "wazuh.audit.action.demote": {
            "en": "level lowered to {level}",
            "es": "nivel reducido a {level}",
        },
        "wazuh.audit.reason.whole_rule": {
            "en": "It mutes rule(s) {parents} entirely ({action}): no condition narrows the scope",
            "es": "Silencia por completo la(s) regla(s) {parents} ({action}): ninguna condición acota el alcance",
        },
        "wazuh.audit.reason.unanchored": {
            "en": "Substring matching on {conditions}: an unanchored value such as 'admin' also matches "
            "'administrator'; anchor it (^...$) or use type=\"pcre2\" with an exact value",
            "es": "Coincidencia por subcadena en {conditions}: un valor sin anclar como 'admin' también coincide "
            "con 'administrator'; áncorelo (^...$) o use type=\"pcre2\" con un valor exacto",
        },
        "wazuh.audit.reason.broad_network": {
            "en": "Very broad network range on {conditions}",
            "es": "Rango de red muy amplio en {conditions}",
        },
        "wazuh.audit.reason.attacker_only": {
            "en": "Only attacker-controllable conditions ({conditions}): anyone who can write that value into a log "
            "is hidden; add a stable anchor (agent/host, internal IP, log file)",
            "es": "Solo condiciones controlables por un atacante ({conditions}): cualquiera que pueda escribir ese "
            "valor en un log queda oculto; añada un ancla estable (agente/host, IP interna, archivo de log)",
        },
        "wazuh.audit.reason.breaks_correlation": {
            "en": "Rule(s) {parents} feed correlation rule(s) {dependents}: events caught here no longer count for "
            "them, so for example brute-force detection stops for this scope",
            "es": "La(s) regla(s) {parents} alimentan la(s) regla(s) de correlación {dependents}: los eventos que "
            "captura esta regla dejan de contar para ellas; por ejemplo, la detección de fuerza bruta se detiene "
            "en este ámbito",
        },
        "wazuh.audit.reason.preempts": {
            "en": "analysisd tries it before other children of rule(s) {parents}, so rule(s) {rules} (up to level "
            "{level}) never fire for the events it catches",
            "es": "analysisd la evalúa antes que otras hijas de la(s) regla(s) {parents}, así que la(s) regla(s) "
            "{rules} (hasta nivel {level}) nunca se disparan para los eventos que captura",
        },
        "wazuh.audit.reason.high_level": {
            "en": "It mutes rule {parent}, level {level} (high-severity threshold is {high_level})",
            "es": "Silencia la regla {parent}, de nivel {level} (el umbral de severidad alta es {high_level})",
        },
        "wazuh.audit.reason.sensitive": {
            "en": "It mutes rule {parent}, mapped to sensitive ATT&CK tactic(s): {tactics}",
            "es": "Silencia la regla {parent}, asociada a táctica(s) ATT&CK sensibles: {tactics}",
        },
        "wazuh.audit.reason.missing_parent": {
            "en": "It is attached to rule(s) {ids}, which are not in the loaded ruleset or load after it: analysisd "
            "discards a child whose parent is not loaded yet, so it may never run",
            "es": "Está asociada a la(s) regla(s) {ids}, que no están en el ruleset cargado o se cargan después: "
            "analysisd descarta una regla hija cuya padre aún no está cargada, así que podría no ejecutarse nunca",
        },
        "wazuh.audit.reason.no_description": {
            "en": "No description: nobody can tell why this suppression exists or when to remove it",
            "es": "Sin descripción: nadie puede saber por qué existe esta supresión ni cuándo quitarla",
        },
        "wazuh.audit.reason.overwrite_level": {
            "en": "It overwrites rule {rule} for every agent, lowering its level from {old} to {new}",
            "es": "Sobrescribe la regla {rule} para todos los agentes y baja su nivel de {old} a {new}",
        },
        "wazuh.audit.reason.overwrite_mute": {
            "en": "It overwrites rule {rule} for every agent so that it no longer alerts ({action})",
            "es": "Sobrescribe la regla {rule} para todos los agentes de modo que ya no alerta ({action})",
        },
        "wazuh.audit.reason.overwrite_threshold": {
            "en": "It overwrites correlation rule {rule}: {attribute} changed from {old} to {new}, so it fires "
            "later or less often",
            "es": "Sobrescribe la regla de correlación {rule}: {attribute} cambia de {old} a {new}, así que se "
            "dispara más tarde o con menos frecuencia",
        },
        "wazuh.audit.reason.overwrite_groups": {
            "en": "It overwrites rule {rule} dropping groups that correlation rule(s) {dependents} rely on",
            "es": "Sobrescribe la regla {rule} quitando grupos de los que dependen las reglas de correlación "
            "{dependents}",
        },
        "wazuh.audit.rec.risky": {
            "en": "Scope it to a stable anchor with exact anchored values (hushwatch can generate a safe DEMOTE "
            "rule), keep it out of correlation chains, and describe it with owner, ticket and 'expires "
            "YYYY-MM-DD'.",
            "es": "Acótela a un ancla estable con valores exactos y anclados (hushwatch puede generar una regla "
            "DEMOTE segura), manténgala fuera de cadenas de correlación y descríbala con responsable, ticket y "
            "'expires AAAA-MM-DD'.",
        },
        "wazuh.audit.rec.correlation": {
            "en": "Do not mute rules that feed correlation: demote with a child that keeps the parent's groups, or "
            "tune the correlation rule itself, and verify with wazuh-logtest.",
            "es": "No silencie reglas que alimentan correlaciones: degrade con una regla hija que conserve los "
            "grupos de la padre, o ajuste la propia regla de correlación, y verifíquelo con wazuh-logtest.",
        },
        "wazuh.audit.rec.overwrite": {
            "en": "Restore the stock level and thresholds, or replace the overwrite with a narrowly scoped child rule.",
            "es": "Restaure el nivel y los umbrales originales, o sustituya la sobrescritura por una regla hija de "
            "alcance acotado.",
        },
        "wazuh.audit.rec.description": {
            "en": "Add a description with the reason, owner, ticket and 'expires YYYY-MM-DD'.",
            "es": "Añada una descripción con el motivo, el responsable, el ticket y 'expires AAAA-MM-DD'.",
        },
        "wazuh.audit.title.expired": {
            "en": "Suppression expired on {expires}: local rule {rule} ({file})",
            "es": "Supresión caducada el {expires}: regla local {rule} ({file})",
        },
        "wazuh.audit.reason.expired": {
            "en": "Its description says it expires on {expires} ({days} day(s) ago), but it is still active",
            "es": "Su descripción indica que caduca el {expires} (hace {days} día(s)), pero sigue activa",
        },
        "wazuh.audit.rec.expired": {
            "en": "Review it: remove the rule, or renew it with a fresh justification and expiry date.",
            "es": "Revísela: elimine la regla o renuévela con una nueva justificación y fecha de caducidad.",
        },
        "wazuh.audit.title.errors": {
            "en": "Rule file {file} could not be fully analyzed ({count} problem(s))",
            "es": "El archivo de reglas {file} no se pudo analizar por completo ({count} problema(s))",
        },
        "wazuh.audit.reason.errors_more": {
            "en": "... and {count} more",
            "es": "... y {count} más",
        },
        "wazuh.audit.rec.errors": {
            "en": "Run /var/ossec/bin/wazuh-analysisd -t on the manager: problems like these can stop analysisd "
            "from starting, and the audit could not check the affected rules.",
            "es": "Ejecute /var/ossec/bin/wazuh-analysisd -t en el manager: problemas como estos pueden impedir que "
            "analysisd arranque, y la auditoría no pudo revisar las reglas afectadas.",
        },
        "wazuh.audit.title.duplicates": {
            "en": "{count} rule id(s) in {skipped} repeat ids already defined in {kept}",
            "es": "{count} id(s) de regla de {skipped} repiten ids ya definidos en {kept}",
        },
        "wazuh.audit.reason.duplicates": {
            "en": "Wazuh keeps the first definition and skips the later one, which never runs (ids: {ids})",
            "es": "Wazuh conserva la primera definición y omite la posterior, que nunca se ejecuta (ids: {ids})",
        },
        "wazuh.audit.rec.duplicates": {
            "en": 'Give each custom rule a unique id in 100000-120000, or use overwrite="yes" when replacing a '
            "rule on purpose.",
            "es": 'Asigne a cada regla personalizada un id único entre 100000 y 120000, o use overwrite="yes" '
            "cuando reemplace una regla a propósito.",
        },
        "wazuh.audit.title.no_rules": {
            "en": "No Wazuh rules could be parsed: the tuning audit did not run",
            "es": "No se pudo analizar ninguna regla de Wazuh: la auditoría de tuning no se ejecutó",
        },
    }
)


@dataclass(slots=True)
class AuditResult:
    """Findings (``tuning.risky_suppression``, ``tuning.expired``, ``assessment.incomplete``) and the
    ``sections["tuning"]`` dict."""

    findings: list[Finding] = field(default_factory=list)
    section: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class _Issue:
    check: str
    severity: Severity
    reason: Message


def technique_tactics(technique: str) -> tuple[str, ...]:
    """ATT&CK tactics (lower-case names) of a technique id such as ``T1110.001``; empty when unknown."""
    base = technique.strip().upper().split(".", 1)[0]
    return _TACTICS.get(base, ())


def _norm_tactic(name: str) -> str:
    return name.strip().lower().replace("-", " ").replace("_", " ")


# ---- condition analysis ---------------------------------------------------------------------------------------------


def _negated(cond: RuleCondition) -> bool:
    return cond.attrs.get("negate", "").strip().lower() == "yes"


def _cond_type(cond: RuleCondition) -> str:
    return cond.attrs.get("type", "").strip().lower() or _DEFAULT_TYPE.get(cond.tag, "osmatch")


def _cond_label(cond: RuleCondition) -> str:
    if cond.tag == "field":
        return f"field {cond.attrs.get('name', '?')[:64]}"
    return cond.tag


def _split_top_level(pattern: str, kind: str) -> list[str]:
    """Split a pattern on its top-level ``|`` (PCRE2: outside groups/classes; OS_Regex/OS_Match: unescaped)."""
    if kind == "osmatch":
        return pattern.split("|")
    parts: list[str] = []
    depth = 0
    in_class = False
    current: list[str] = []
    i = 0
    while i < len(pattern):
        char = pattern[i]
        if char == "\\" and i + 1 < len(pattern):
            current.append(pattern[i : i + 2])
            i += 2
            continue
        if kind == "pcre2":
            if in_class:
                if char == "]":
                    in_class = False
            elif char == "[":
                in_class = True
                if pattern[i + 1 : i + 2] == "]":  # "[]...]" and "[^]...]" keep the first "]" literal
                    current.append(char)
                    i += 1
                    char = pattern[i]
            elif char == "(":
                depth += 1
            elif char == ")":
                depth = max(0, depth - 1)
        if char == "|" and depth == 0 and not in_class:
            parts.append("".join(current))
            current = []
        else:
            current.append(char)
        i += 1
    parts.append("".join(current))
    return parts


def _ends_anchored(alternative: str, kind: str) -> bool:
    if kind == "pcre2" and alternative.endswith(("\\z", "\\Z")):
        return not alternative.endswith(("\\\\z", "\\\\Z"))
    if not alternative.endswith("$"):
        return False
    backslashes = len(alternative[:-1]) - len(alternative[:-1].rstrip("\\"))
    return kind == "osmatch" or backslashes % 2 == 0


def _starts_anchored(alternative: str, kind: str) -> bool:
    return alternative.startswith("^") or (kind == "pcre2" and alternative.startswith("\\A"))


def _anchored(cond: RuleCondition) -> bool | None:
    """True/False for conditions where substring semantics apply; None when not applicable."""
    if cond.tag not in _ANCHOR_TAGS or _negated(cond):
        return None
    kind = _cond_type(cond)
    text = cond.text.strip()
    if kind == "pcre2":
        text = _PCRE_PREFIX.sub("", text)
    elif kind == "osmatch" and text.startswith("!"):
        return None  # a negated OS_Match pattern: does not narrow the scope in the usual sense
    if not text:
        return None
    for alternative in _split_top_level(text, kind):
        alternative = alternative.strip() if kind == "osmatch" else alternative
        if not alternative:
            return False
        start = _starts_anchored(alternative, kind)
        end = _ends_anchored(alternative, kind)
        if cond.tag == "location":
            closes_agent = start and any(t in alternative for t in (")", "\\)", "\\x{29}", "\\x29"))
            if not (end or closes_agent):
                return False
        elif not (start and end):
            return False
    return True


def _literal(cond: RuleCondition) -> str | None:
    """The exact value of an anchored single-value pattern (``^svc_backup$``), else None."""
    kind = _cond_type(cond)
    text = cond.text.strip()
    if kind == "pcre2":
        text = _PCRE_PREFIX.sub("", text)
        if text.endswith(("\\z", "\\Z")) and not text.endswith(("\\\\z", "\\\\Z")):
            text = text[:-2] + "$"  # hushwatch writes ^...\z (PCRE2 "$" also accepts a trailing newline)
    if not (text.startswith("^") and text.endswith("$")) or len(text) < 2:
        return None
    body = text[1:-1]
    if kind == "osmatch":
        return None if any(ch in body for ch in "|^$") else body
    out: list[str] = []
    i = 0
    raw_bytes: list[int] = []

    def flush() -> None:
        if raw_bytes:
            out.append(bytes(raw_bytes).decode("utf-8", errors="replace"))
            raw_bytes.clear()

    while i < len(body):
        char = body[i]
        if char == "\\" and i + 1 < len(body):
            hexmatch = _HEX.match(body, i)
            if kind == "pcre2" and hexmatch is not None:
                value = int(hexmatch.group(1) or hexmatch.group(2), 16)
                if value < 256:
                    raw_bytes.append(value)
                else:
                    flush()
                    out.append(chr(value))
                i = hexmatch.end()
                continue
            nxt = body[i + 1]
            if nxt.isalnum() or (kind == "osregex" and nxt == "."):
                return None  # a class like \d, \w, \S or OS_Regex "\." (any character)
            flush()
            out.append(nxt)
            i += 2
            continue
        if kind == "pcre2" and char in ".[](){}*+?|^$":
            return None
        if kind == "osregex" and char in "+*|^$()":
            return None
        flush()
        out.append(char)
        i += 1
    flush()
    return "".join(out)


def _is_service_account(value: str | None, tenant: TenantConfig) -> bool:
    if not value:
        return False
    lowered = value.lower()
    return tenant.is_trusted("user", value) or value.endswith("$") or lowered.startswith(("svc", "service"))


def _network_internal(value: str, tenant: TenantConfig) -> bool:
    candidate = value.strip()
    if candidate.startswith("!") or candidate.lower() == "any":
        return False
    try:
        network = ipaddress.ip_network(candidate, strict=False)
    except ValueError:
        return False
    return tenant.is_internal(str(network.network_address)) and tenant.is_internal(str(network.broadcast_address))


def _broad_network(value: str) -> bool:
    candidate = value.strip().lstrip("!")
    if candidate.lower() == "any":
        return True
    try:
        network = ipaddress.ip_network(candidate, strict=False)
    except ValueError:
        return False
    return network.prefixlen < (16 if network.version == 4 else 48)


def _attacker_controlled(cond: RuleCondition, tenant: TenantConfig) -> bool:
    tag = cond.tag
    if tag in _ATTACKER_TAGS:
        return True
    if tag in ("srcip", "dstip"):
        return not _network_internal(cond.text, tenant)
    if tag == "user":
        return not _is_service_account(_literal(cond), tenant)
    if tag == "field":
        name = cond.attrs.get("name", "").lower()
        if any(hint in name for hint in _ATTACKER_FIELD_HINTS):
            literal = _literal(cond)
            if any(hint in name for hint in _USER_FIELD_HINTS) and _is_service_account(literal, tenant):
                return False
            return not (any(hint in name for hint in _IP_FIELD_HINTS) and literal and tenant.is_internal(literal))
        if any(hint in name for hint in _PATH_FIELD_HINTS):
            return _anchored(cond) is not True
        return False
    return False


def _narrowing(cond: RuleCondition) -> bool:
    if cond.tag in _NON_NARROWING or _negated(cond):
        return False
    if cond.tag in ("srcip", "dstip") and cond.text.strip().lower() in ("any", "!any"):
        return False
    return not (_cond_type(cond) == "osmatch" and cond.text.strip().startswith("!"))


# ---- rule analysis --------------------------------------------------------------------------------------------------


def _parents(ruleset: Ruleset, rule: WazuhRule) -> list[WazuhRule]:
    """The rules this child is attached to: analysisd only attaches it to rules loaded before it."""
    found: dict[str, WazuhRule] = {}
    for sid in rule.if_sid or rule.if_matched_sid:
        parent = ruleset.get(sid)
        if parent is not None and parent.id != rule.id and not _loaded_after(ruleset, parent.id, rule.id):
            found[parent.id] = parent
    if rule.if_group:
        for candidate in ruleset.rules.values():
            if (
                candidate.id != rule.id
                and not _loaded_after(ruleset, candidate.id, rule.id)
                and any(osmatch(p, candidate.group_string) for p in rule.if_group)
            ):
                found[candidate.id] = candidate
    return sorted(found.values(), key=lambda r: int(r.id))


def _visibility(rule: WazuhRule, parents: Sequence[WazuhRule]) -> str | None:
    """drop (level 0) / hide (no alert written) / demote (lower level than its parents) / None."""
    if rule.level == 0:
        return "drop"
    if rule.no_log or rule.noalert or rule.level < DEFAULT_LOG_ALERT_LEVEL:
        return "hide"
    top = max((p.level for p in parents), default=0)
    if parents and rule.level < top:
        return "demote"
    return None


def _action(rule: WazuhRule, visibility: str) -> Message:
    if visibility == "drop":
        return M("wazuh.audit.action.drop")
    if visibility == "hide":
        return M("wazuh.audit.action.hide")
    return M("wazuh.audit.action.demote", level=rule.level)


def _ids(rules: Iterable[WazuhRule | str]) -> str:
    ids = [r if isinstance(r, str) else r.id for r in rules]
    shown = ", ".join(ids[:_MAX_LISTED])
    return shown + (f" (+{len(ids) - _MAX_LISTED})" if len(ids) > _MAX_LISTED else "")


def _loaded_after(ruleset: Ruleset, later: str, earlier: str) -> bool:
    a, b = ruleset.position(later), ruleset.position(earlier)
    return a is not None and b is not None and a > b


def _broken_dependents(ruleset: Ruleset, rule: WazuhRule, parents: Sequence[WazuhRule]) -> list[str]:
    """Correlation rules of the parents that stop counting the events this child takes over (analysisd records an
    event under the rule it finally matched; level 0 is never recorded).

    * ``if_matched_sid`` on a parent: always broken.
    * ``if_matched_group``: the correlation list is wired when the CORRELATION rule loads, over rules already
      loaded; only a correlation rule loaded after this child, whose pattern matches the child's groups, counts it.
    * frequency via ``if_sid``: counts every recent event whatever rule it ended in, as long as it is tried
      before this child (higher priority, or equal and loaded first) and the child is not level 0."""
    broken: set[str] = set()
    group_string = rule.group_string
    own = evaluation_priority(rule)
    for parent in parents:
        for dep_id, via in ruleset.dependents_detail(parent.id):
            if dep_id == rule.id:
                continue
            dependent = ruleset.get(dep_id)
            if rule.level > 0 and dependent is not None:
                if (
                    via == "if_matched_group"
                    and _loaded_after(ruleset, dep_id, rule.id)
                    and any(osmatch(p, group_string) for p in dependent.if_matched_group)
                ):
                    continue
                if via == "frequency_if_sid":
                    priority = evaluation_priority(dependent)
                    if priority > own or (priority == own and _loaded_after(ruleset, rule.id, dep_id)):
                        continue
            broken.add(dep_id)
    return sorted(broken, key=int)


def _preempted(ruleset: Ruleset, rule: WazuhRule, parents: Sequence[WazuhRule], skip: Iterable[str]) -> list[WazuhRule]:
    """Rules more severe than the muted parent that never fire for the events this child catches, because
    analysisd tries the child before their branch (siblings are tried by descending priority)."""
    hidden: dict[str, WazuhRule] = {}
    skipped = set(skip) | {rule.id}
    for parent in parents:
        for sibling_id in ruleset.evaluated_after(parent.id, rule):
            for rule_id in (sibling_id, *ruleset.descendants(sibling_id)):
                candidate = ruleset.get(rule_id)
                if (
                    candidate is not None
                    and rule_id not in skipped
                    and candidate.level > rule.level
                    and candidate.level > parent.level
                ):
                    hidden.setdefault(rule_id, candidate)
    return sorted(hidden.values(), key=lambda r: (-r.level, int(r.id)))


def _sensitive_tactics(rule: WazuhRule, sensitive: frozenset[str]) -> list[str]:
    tactics: list[str] = []
    for technique in rule.mitre:
        for tactic in technique_tactics(technique):
            if _norm_tactic(tactic) in sensitive and tactic not in tactics:
                tactics.append(tactic)
    return tactics


def _suppression_issues(
    ruleset: Ruleset,
    rule: WazuhRule,
    parents: Sequence[WazuhRule],
    visibility: str,
    tenant: TenantConfig,
    sensitive: frozenset[str],
    has_stock: bool,
) -> list[_Issue]:
    issues: list[_Issue] = []
    hides = visibility in ("drop", "hide") or rule.level < tenant.triage_level
    narrowing = [c for c in rule.conditions if _narrowing(c)]
    parent_ids = _ids(parents) if parents else _ids(rule.if_sid or rule.if_matched_sid or rule.if_group)

    if not narrowing:
        severity = Severity.HIGH if visibility in ("drop", "hide") else Severity.MEDIUM
        reason = M("wazuh.audit.reason.whole_rule", parents=parent_ids, action=_action(rule, visibility))
        issues.append(_Issue("whole_rule", severity, reason))
    unanchored = [_cond_label(c) for c in narrowing if _anchored(c) is False]
    if unanchored:
        reason = M("wazuh.audit.reason.unanchored", conditions=", ".join(dict.fromkeys(unanchored)))
        issues.append(_Issue("unanchored", Severity.MEDIUM, reason))
    broad = [c.tag for c in narrowing if c.tag in ("srcip", "dstip") and _broad_network(c.text)]
    if broad:
        reason = M("wazuh.audit.reason.broad_network", conditions=", ".join(dict.fromkeys(broad)))
        issues.append(_Issue("broad_network", Severity.MEDIUM, reason))
    stable = [c for c in narrowing if not _attacker_controlled(c, tenant)]
    if narrowing and not stable:
        labels = ", ".join(dict.fromkeys(_cond_label(c) for c in narrowing))
        severity = Severity.HIGH if hides else Severity.MEDIUM
        issues.append(_Issue("attacker_only", severity, M("wazuh.audit.reason.attacker_only", conditions=labels)))
    broken = _broken_dependents(ruleset, rule, parents)
    if broken:
        feeding = [p for p in parents if any(d in broken for d in ruleset.dependents(p.id))]
        reason = M("wazuh.audit.reason.breaks_correlation", parents=_ids(feeding), dependents=_ids(broken))
        issues.append(_Issue("breaks_correlation", Severity.HIGH, reason))
    preempted = _preempted(ruleset, rule, parents, broken)
    if preempted:
        severe = any(r.level >= tenant.high_level or _sensitive_tactics(r, sensitive) for r in preempted[:_MAX_LISTED])
        reason = M(
            "wazuh.audit.reason.preempts",
            parents=_ids(parents),
            rules=_ids(preempted),
            level=max(r.level for r in preempted),
        )
        issues.append(_Issue("preempts", Severity.HIGH if severe else Severity.MEDIUM, reason))
    if hides:
        narrow = bool(narrowing) and bool(stable) and all(_anchored(c) is not False for c in narrowing)
        for parent in parents[:_MAX_LISTED]:
            if parent.level >= tenant.high_level:
                reason = M(
                    "wazuh.audit.reason.high_level", parent=parent.id, level=parent.level, high_level=tenant.high_level
                )
                issues.append(_Issue("high_level_parent", Severity.HIGH, reason))
                continue
            tactics = _sensitive_tactics(parent, sensitive)
            if tactics:
                reason = M("wazuh.audit.reason.sensitive", parent=parent.id, tactics=", ".join(tactics))
                issues.append(_Issue("sensitive_parent", Severity.MEDIUM if narrow else Severity.HIGH, reason))
    if has_stock:
        missing = [
            sid
            for sid in (rule.if_sid or rule.if_matched_sid)
            if ruleset.get(sid) is None or _loaded_after(ruleset, sid, rule.id)
        ]
        if missing:
            issues.append(
                _Issue("missing_parent", Severity.MEDIUM, M("wazuh.audit.reason.missing_parent", ids=_ids(missing)))
            )
    if rule.description is None:
        issues.append(_Issue("no_description", Severity.LOW, M("wazuh.audit.reason.no_description")))
    return issues


def _overwrite_issues(
    ruleset: Ruleset,
    original: WazuhRule,
    rule: WazuhRule,
    tenant: TenantConfig,
    sensitive: frozenset[str],
    load_index: dict[int, int],
) -> list[_Issue]:
    issues: list[_Issue] = []
    was_alerting = original.level >= DEFAULT_LOG_ALERT_LEVEL and not original.no_log and not original.noalert
    now_silent = rule.level < DEFAULT_LOG_ALERT_LEVEL or rule.no_log or rule.noalert
    if was_alerting and now_silent:
        visibility = "drop" if rule.level == 0 else "hide"
        reason = M("wazuh.audit.reason.overwrite_mute", rule=rule.id, action=_action(rule, visibility))
        issues.append(_Issue("overwrite_mute", Severity.HIGH, reason))
    elif rule.level < original.level:
        reason = M("wazuh.audit.reason.overwrite_level", rule=rule.id, old=original.level, new=rule.level)
        issues.append(_Issue("overwrite_level", Severity.MEDIUM, reason))
    for attribute, weaker in (("frequency", 1), ("timeframe", -1), ("ignore", 1)):
        old = getattr(original, attribute)
        new = getattr(rule, attribute)
        if new is None or old == new:
            continue
        if (old is None and attribute == "ignore") or (old is not None and (new - old) * weaker > 0):
            reason = M(
                "wazuh.audit.reason.overwrite_threshold",
                rule=rule.id,
                attribute=attribute,
                old="-" if old is None else old,
                new=new,
            )
            issues.append(_Issue("overwrite_threshold", Severity.MEDIUM, reason))
    if rule.level == 0 and was_alerting:
        dropped = [d for d in ruleset.dependents(rule.id) if d != rule.id]
        if dropped:
            reason = M("wazuh.audit.reason.breaks_correlation", parents=rule.id, dependents=_ids(dropped))
            issues.append(_Issue("breaks_correlation", Severity.HIGH, reason))
    else:
        # An overwrite keeps the correlation lists already wired to the rule (OS_AddRuleInfo does not touch them):
        # only correlation rules loaded AFTER the overwrite look at its new groups.
        overwrite_at = load_index.get(id(rule), -1)
        lost: set[str] = set()
        for candidate in ruleset.rules.values():
            if load_index.get(id(candidate), -1) <= overwrite_at:
                continue
            for pattern in candidate.if_matched_group:
                if osmatch(pattern, original.group_string) and not osmatch(pattern, rule.group_string):
                    lost.add(candidate.id)
        lost.discard(rule.id)
        if lost:
            ordered: list[str] = sorted(lost, key=int)
            reason = M("wazuh.audit.reason.overwrite_groups", rule=rule.id, dependents=_ids(ordered))
            issues.append(_Issue("overwrite_groups", Severity.HIGH, reason))
    hidden = now_silent or (rule.level < tenant.triage_level <= original.level)
    if hidden:
        if original.level >= tenant.high_level:
            reason = M(
                "wazuh.audit.reason.high_level", parent=rule.id, level=original.level, high_level=tenant.high_level
            )
            issues.append(_Issue("high_level_parent", Severity.HIGH, reason))
        else:
            tactics = _sensitive_tactics(original, sensitive) or _sensitive_tactics(rule, sensitive)
            if tactics:
                reason = M("wazuh.audit.reason.sensitive", parent=rule.id, tactics=", ".join(tactics))
                issues.append(_Issue("sensitive_parent", Severity.HIGH, reason))
    return issues


def _load_index(ruleset: Ruleset) -> dict[int, int]:
    """Load position of every rule ELEMENT (keyed by object id); an effective overwrite takes the position of
    the first definition it replaced, as its correlation wiring does."""
    index: dict[int, int] = {id(rule): i for i, rule in enumerate(ruleset.all_rules)}
    first: dict[str, int] = {}
    for i, rule in enumerate(ruleset.all_rules):
        first.setdefault(rule.id, i)
    for rule in ruleset.rules.values():
        index.setdefault(id(rule), first.get(rule.id, -1))
    return index


def _expiry(rule: WazuhRule) -> date | None:
    if not rule.description:
        return None
    match = _EXPIRES.search(rule.description)
    if match is None:
        return None
    try:
        return date.fromisoformat(match.group(1))
    except ValueError:
        return None


def _basename(path: str) -> str:
    return PurePath(path).name or path


def _subject(rule: WazuhRule) -> str:
    return f"rule:{rule.id}|file:{_basename(rule.file)}"


def _finding_for(rule: WazuhRule, issues: Sequence[_Issue], parents: Sequence[WazuhRule], overwrite: bool) -> Finding:
    severity = max((i.severity for i in issues), key=lambda s: s.rank)
    checks = list(dict.fromkeys(i.check for i in issues))
    params = {"rule": rule.id, "file": Entity("file", _basename(rule.file))}
    if overwrite:
        title = M("wazuh.audit.title.overwrite", **params)
        recommendation = M("wazuh.audit.rec.overwrite")
    elif checks == ["no_description"]:
        title = M("wazuh.audit.title.undocumented", **params)
        recommendation = M("wazuh.audit.rec.description")
    else:
        title = M("wazuh.audit.title.risky", **params)
        correlation = "breaks_correlation" in checks
        recommendation = M("wazuh.audit.rec.correlation" if correlation else "wazuh.audit.rec.risky")
    ordered = sorted(issues, key=lambda i: -i.severity.rank)
    return Finding(
        kind="tuning.risky_suppression",
        domain="tuning",
        title=title,
        severity=severity,
        subject=_subject(rule),
        reasons=[i.reason for i in ordered],
        evidence={
            "rule_id": rule.id,
            "level": rule.level,
            "file": Entity("file", rule.file),
            "line": rule.line,
            "parents": [p.id for p in parents[:_MAX_LISTED]],
            "parents_total": len(parents),
            "checks": checks,
            "conditions": len(rule.conditions),
            "options": list(rule.options),
            "overwrite": overwrite,
        },
        recommendation=recommendation,
        confidence=Confidence.HIGH,
        score=float(sum(i.severity.rank for i in issues)),
    )


def _expired_finding(rule: WazuhRule, expires: date, now: date) -> Finding:
    days = (now - expires).days
    return Finding(
        kind="tuning.expired",
        domain="tuning",
        title=M(
            "wazuh.audit.title.expired",
            rule=rule.id,
            file=Entity("file", _basename(rule.file)),
            expires=expires.isoformat(),
        ),
        severity=Severity.MEDIUM,
        subject=f"{_subject(rule)}|expired",
        reasons=[M("wazuh.audit.reason.expired", expires=expires.isoformat(), days=days)],
        evidence={
            "rule_id": rule.id,
            "file": Entity("file", rule.file),
            "line": rule.line,
            "expires": expires.isoformat(),
            "days_overdue": days,
            "level": rule.level,
        },
        recommendation=M("wazuh.audit.rec.expired"),
        confidence=Confidence.HIGH,
        score=float(days),
    )


def _error_findings(ruleset: Ruleset) -> list[Finding]:
    by_file: dict[str, list[RulesetError]] = {}
    for error in ruleset.errors:
        by_file.setdefault(error.file, []).append(error)
    local_files = set(ruleset.local_files)
    findings: list[Finding] = []
    for path, errors in by_file.items():
        reasons: list[Message | str] = [e.message for e in errors[:_MAX_ERROR_REASONS]]
        if len(errors) > _MAX_ERROR_REASONS:
            reasons.append(M("wazuh.audit.reason.errors_more", count=len(errors) - _MAX_ERROR_REASONS))
        is_local = path in local_files or path not in ruleset.files
        findings.append(
            Finding(
                kind="assessment.incomplete",
                domain="assessment",
                title=M("wazuh.audit.title.errors", file=Entity("file", _basename(path)), count=len(errors)),
                severity=Severity.HIGH if is_local else Severity.MEDIUM,
                subject=f"ruleset-errors:{_basename(path)}",
                reasons=reasons,
                evidence={
                    "file": Entity("file", path),
                    "errors": len(errors),
                    "local": is_local,
                    "lines": [e.line for e in errors[:_MAX_LISTED] if e.line is not None],
                    "rules": sorted({e.rule_id for e in errors if e.rule_id}, key=int)[:_MAX_LISTED],
                },
                recommendation=M("wazuh.audit.rec.errors"),
                confidence=Confidence.HIGH,
            )
        )
    return findings


def _duplicate_findings(ruleset: Ruleset) -> list[Finding]:
    pairs: dict[tuple[str, str], list[str]] = {}
    for rule_id, kept, skipped in ruleset.duplicates:
        pairs.setdefault((kept, skipped), []).append(rule_id)
    findings: list[Finding] = []
    for (kept, skipped), ids in pairs.items():
        unique = sorted(set(ids), key=int)
        findings.append(
            Finding(
                kind="assessment.incomplete",
                domain="assessment",
                title=M(
                    "wazuh.audit.title.duplicates",
                    count=len(unique),
                    kept=Entity("file", _basename(kept)),
                    skipped=Entity("file", _basename(skipped)),
                ),
                severity=Severity.MEDIUM,
                subject=f"duplicate-rule-ids:{_basename(kept)}|{_basename(skipped)}",
                reasons=[M("wazuh.audit.reason.duplicates", ids=_ids(unique))],
                evidence={
                    "ids": unique[:_MAX_LISTED],
                    "count": len(unique),
                    "kept_file": Entity("file", kept),
                    "skipped_file": Entity("file", skipped),
                },
                recommendation=M("wazuh.audit.rec.duplicates"),
                confidence=Confidence.HIGH,
            )
        )
    return findings


def audit_ruleset(ruleset: Ruleset, *, tenant: TenantConfig, now: date) -> AuditResult:
    """Audit the LOCAL rules of ``ruleset`` (the rest is context) and return findings plus the tuning section.

    Kinds: ``tuning.risky_suppression`` (one finding per local rule, aggregating every risk found, severity =
    worst), ``tuning.expired`` (``expires YYYY-MM-DD`` in the description is in the past) and
    ``assessment.incomplete`` (parse errors per file, duplicate ids, nothing parsed).
    """
    sensitive = frozenset(_norm_tactic(t) for t in tenant.noise.sensitive_tactics)
    findings: list[Finding] = []
    findings.extend(_error_findings(ruleset))
    findings.extend(_duplicate_findings(ruleset))
    # Only rule elements analysisd actually runs: skipped duplicates and superseded overwrites are not active.
    last_overwrite = {rule.id: rule for _, rule in ruleset.overwrites}
    overwrites: dict[int, WazuhRule] = {}
    for replaced, overwriting in ruleset.overwrites:
        root = replaced
        while (earlier := root.original) is not None:
            root = earlier
        if last_overwrite[overwriting.id] is overwriting:
            overwrites[id(overwriting)] = root
    has_stock = any(not r.is_local for r in ruleset.all_rules)
    load_index = _load_index(ruleset)
    local = ruleset.local_rules()
    for rule in local:
        original = overwrites.get(id(rule))
        if original is None and ruleset.rules.get(rule.id) is not rule:
            continue  # a skipped duplicate or a definition replaced by an overwrite: it never runs
        expires = _expiry(rule)
        if expires is not None and expires < now:
            findings.append(_expired_finding(rule, expires, now))
        if not rule.valid:
            continue  # already reported as a load error; its semantics are unreliable
        if original is not None:
            issues = _overwrite_issues(ruleset, original, rule, tenant, sensitive, load_index)
            if issues:
                findings.append(_finding_for(rule, issues, [original], overwrite=True))
            continue
        if not (rule.if_sid or rule.if_group or rule.if_matched_sid or rule.if_matched_group):
            continue  # a base rule, not a suppression of something else
        parents = _parents(ruleset, rule)
        visibility = _visibility(rule, parents)
        if visibility is None:
            continue
        issues = _suppression_issues(ruleset, rule, parents, visibility, tenant, sensitive, has_stock)
        if issues:
            findings.append(_finding_for(rule, issues, parents, overwrite=False))

    if not ruleset.rules:
        findings.append(
            Finding(
                kind="assessment.incomplete",
                domain="assessment",
                title=M("wazuh.audit.title.no_rules"),
                severity=Severity.HIGH,
                subject="ruleset-empty",
                evidence={"files": len(ruleset.files), "errors": len(ruleset.errors)},
                recommendation=M("wazuh.audit.rec.errors"),
                confidence=Confidence.HIGH,
            )
        )
    risky = [f for f in findings if f.kind == "tuning.risky_suppression"]
    if not ruleset.rules:
        status = "not_assessed"
    else:
        worst = max((f.severity.rank for f in findings), default=Severity.INFO.rank)
        status = "fail" if worst >= Severity.HIGH.rank else "warn" if worst >= Severity.MEDIUM.rank else "ok"
    section: dict[str, Any] = {
        "status": status,
        "rules_parsed": len(ruleset.rules),
        "local_rules": len(local),
        "risky": len(risky),
        "risky_high": sum(1 for f in risky if f.severity.rank >= Severity.HIGH.rank),
        "expired": sum(1 for f in findings if f.kind == "tuning.expired"),
        "parse_errors": len(ruleset.errors),
        "duplicate_ids": len(ruleset.duplicates),
        "files": len(ruleset.files),
        "local_files": len(ruleset.local_files),
    }
    return AuditResult(findings=findings, section=section)
