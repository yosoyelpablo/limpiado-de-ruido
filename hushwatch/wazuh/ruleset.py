"""Parse Wazuh 4.x rule files into a dependency-aware :class:`Ruleset`.

Wazuh rule files are *not* single-rooted XML documents: they hold several top-level ``<group>`` elements plus
``<var>`` definitions, and Wazuh's own parser (``os_xml``) is more lenient than a real XML parser. This module:

* wraps every file in a synthetic root and parses it with expat (line numbers kept, DTDs and entity
  declarations refused so no entity expansion can ever happen);
* when a file is not well-formed XML, retries after repairing what ``os_xml`` tolerates (comments containing
  ``--``, a bare ``&`` or ``<`` inside regexes), then falls back to parsing each top-level block on its own;
* substitutes ``$VAR`` references (file-scoped, case-insensitive, in element text and attribute values);
* applies ``overwrite="yes"`` like analysisd (everything is replaced except the ``if_*`` links);
* records every problem in :attr:`Ruleset.errors` instead of raising, and still recovers the rule ids of
  unparseable parts so that id allocation can never collide with a rule it could not read.

Errors are *also* a lint: many of them (unknown attributes, ``<field>`` on a static field, several values in
one ``<options>``...) make ``wazuh-analysisd`` refuse to start.
"""

from __future__ import annotations

import bisect
import functools
import ipaddress
import re
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import NamedTuple
from xml.parsers import expat

from ..i18n import Entity, M, Message, register, render

__all__ = [
    "MAX_FILE_BYTES",
    "RuleCondition",
    "Ruleset",
    "RulesetError",
    "WazuhRule",
    "evaluation_priority",
    "is_static_field",
    "load_ruleset",
    "osmatch",
    "parse_rules_text",
]

MAX_FILE_BYTES = 64 * 1024 * 1024  # a rules file larger than this is not a rules file

# Element names that are valid inside <rule> (Wazuh 4.x rules.c), lower-case.
MATCH_TAGS: frozenset[str] = frozenset(
    {
        "match",
        "regex",
        "decoded_as",
        "category",
        "field",
        "srcip",
        "dstip",
        "srcport",
        "dstport",
        "data",
        "extra_data",
        "user",
        "system_name",
        "program_name",
        "protocol",
        "hostname",
        "time",
        "weekday",
        "id",
        "url",
        "location",
        "action",
        "status",
        "srcgeoip",
        "dstgeoip",
        "list",
    }
)
_IF_TAGS = frozenset({"if_sid", "if_group", "if_level", "if_matched_sid", "if_matched_group", "if_fts"})
_META_TAGS = frozenset({"description", "info", "options", "group", "mitre", "var"})
_OTHER_TAGS = frozenset(
    {"global_frequency", "ignore", "check_if_ignored", "check_diff", "compiled_rule", "if_matched_regex"}
)
_CORRELATION_PREFIXES = ("same_", "different_", "not_same_")
_RULE_ATTRS = frozenset(
    {"id", "level", "maxsize", "frequency", "timeframe", "ignore", "accuracy", "noalert", "overwrite"}
)
VALID_OPTIONS = frozenset(
    {"alert_by_email", "no_email_alert", "no_log", "no_full_log", "no_counter", "no_ar", "log_alert"}
)
# <field name="X"> on these is a FATAL load error in analysisd ("Field X is static").
STATIC_FIELDS = frozenset(
    {
        "srcip",
        "dstip",
        "srcgeoip",
        "dstgeoip",
        "srcport",
        "dstport",
        "user",
        "srcuser",
        "dstuser",
        "url",
        "id",
        "data",
        "extra_data",
        "status",
        "protocol",
        "system_name",
        "action",
    }
)

_ROOT = "hushwatch_synthetic_root_7f3a"
_XML_DECL = re.compile(r"\A\s*<\?xml[^>]*\?>", re.IGNORECASE)
# Every scan of raw file text is linear: a rules file is untrusted input and must never hang the parser, so no
# pattern below may backtrack over the rest of the file (comments, DOCTYPEs, CDATA and blocks use str.find).
_DOCTYPE_START = re.compile(r"<!DOCTYPE", re.IGNORECASE)
_ENTITY_DECL = re.compile(r"<!ENTITY", re.IGNORECASE)
_CDATA_START = "<![CDATA["
_SURROGATES = re.compile("[\ud800-\udfff]")
_BARE_AMP = re.compile(r"&(?!(?:amp|lt|gt|quot|apos|#[0-9]+|#x[0-9A-Fa-f]+);)")
_BAD_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")
_KNOWN_TAG_NAMES = sorted(
    MATCH_TAGS | _IF_TAGS | _META_TAGS | _OTHER_TAGS | {"group", "rule", "tactic", "technique"},
    key=len,
    reverse=True,
)
_STRAY_LT = re.compile(
    r"<(?!(?:/?(?:" + "|".join(_KNOWN_TAG_NAMES) + r"|(?:same|different|not_same)_\w+)(?=[\s/>]))|!|\?)",
    re.IGNORECASE,
)
_BLOCK_START = re.compile(r"<(group|var)\b", re.IGNORECASE)
_BLOCK_END = {
    "group": re.compile(r"</group\s*>", re.IGNORECASE),
    "var": re.compile(r"</var\s*>", re.IGNORECASE),
}
# Salvage scan in two linear steps: a bounded, non-overlapping start-tag match (no backtracking), then the id
# attribute inside it. A lazy "[^>]*?" run would rescan the rest of the text for every "<rule" without ">".
_SALVAGE_TAG = re.compile(r"<rule\b([^>]{0,512})", re.IGNORECASE)
_SALVAGE_ID = re.compile(r"\bid\s*=\s*[\"']\s*0*([0-9]{1,6})\s*[\"']", re.IGNORECASE)
_VAR_REF = re.compile(r"\$([A-Za-z_][A-Za-z0-9_-]*)")
_RULE_ID = re.compile(r"^[0-9]{1,6}$")
_INT = re.compile(r"^[0-9]{1,9}$")
_LIST_SPLIT = re.compile(r"[\s,]+")
_STOCK_FILE = re.compile(r"^\d{4}-[\w.+-]+\.xml$", re.IGNORECASE)
_OsMatch = tuple[bool, tuple[tuple[bool, bool, str], ...]]  # (negate, ((start, end, core), ...))
_MAX_DEPTH = 8
_MAX_VALUE_IN_MESSAGE = 80


register(
    {
        "wazuh.err.read": {
            "en": "Cannot read rule file {file}: {error}",
            "es": "No se puede leer el archivo de reglas {file}: {error}",
        },
        "wazuh.err.not_found": {
            "en": "Ruleset path {file} does not exist",
            "es": "La ruta del ruleset {file} no existe",
        },
        "wazuh.err.no_files": {
            "en": "No *.xml rule files found in {file}",
            "es": "No se encontraron archivos de reglas *.xml en {file}",
        },
        "wazuh.err.too_large": {
            "en": "Rule file {file} is larger than {limit} MiB and was skipped",
            "es": "El archivo de reglas {file} supera {limit} MiB y se omitió",
        },
        "wazuh.err.xml": {
            "en": "XML syntax error in {file} line {line}: {detail}",
            "es": "Error de sintaxis XML en {file}, línea {line}: {detail}",
        },
        "wazuh.err.dtd": {
            "en": "{file}: DOCTYPE/ENTITY declarations are not valid in Wazuh rule files and were ignored",
            "es": "{file}: las declaraciones DOCTYPE/ENTITY no son válidas en archivos de reglas de Wazuh y se "
            "ignoraron",
        },
        "wazuh.err.cdata": {
            "en": "{file}: CDATA sections are not supported by Wazuh's XML parser (it reads '<!' as the start of a "
            "comment), so analysisd will not read this file as intended",
            "es": "{file}: el analizador XML de Wazuh no admite secciones CDATA (interpreta '<!' como inicio de un "
            "comentario), así que analysisd no leerá este archivo como se espera",
        },
        "wazuh.err.comment": {
            "en": "{file}: a comment is never closed (analysisd refuses the file); everything after it was ignored",
            "es": "{file}: hay un comentario sin cerrar (analysisd rechaza el archivo); se ignoró todo lo que le sigue",
        },
        "wazuh.err.root_element": {
            "en": "{file} line {line}: unexpected top-level element <{tag}> (only <group> and <var> are allowed)",
            "es": "{file}, línea {line}: elemento de primer nivel inesperado <{tag}> (solo se admiten <group> y <var>)",
        },
        "wazuh.err.group_element": {
            "en": "{file} line {line}: unexpected element <{tag}> inside <group> (only <rule> is allowed)",
            "es": "{file}, línea {line}: elemento inesperado <{tag}> dentro de <group> (solo se admite <rule>)",
        },
        "wazuh.err.empty_group": {
            "en": "{file} line {line}: <group> without any <rule> (analysisd rejects it)",
            "es": "{file}, línea {line}: <group> sin ninguna <rule> (analysisd lo rechaza)",
        },
        "wazuh.err.too_deep": {
            "en": "{file} line {line}: groups nested too deeply; content ignored",
            "es": "{file}, línea {line}: grupos anidados demasiado profundo; contenido ignorado",
        },
        "wazuh.err.rule_id": {
            "en": "{file} line {line}: rule with a missing or invalid id ({value}); ids are 1-999999",
            "es": "{file}, línea {line}: regla con id ausente o no válido ({value}); los ids van de 1 a 999999",
        },
        "wazuh.err.level": {
            "en": "{file} line {line}: rule {rule} has a missing or invalid level ({value}); levels are 0-16",
            "es": "{file}, línea {line}: la regla {rule} tiene un nivel ausente o no válido ({value}); los niveles "
            "van de 0 a 16",
        },
        "wazuh.err.attribute": {
            "en": "{file} line {line}: rule {rule} has an unknown attribute '{name}' (analysisd refuses to start)",
            "es": "{file}, línea {line}: la regla {rule} tiene un atributo desconocido '{name}' (analysisd no arranca)",
        },
        "wazuh.err.attr_value": {
            "en": "{file} line {line}: rule {rule} has an invalid {name} value ({value})",
            "es": "{file}, línea {line}: la regla {rule} tiene un valor de {name} no válido ({value})",
        },
        "wazuh.err.option": {
            "en": "{file} line {line}: rule {rule} has an unknown element <{tag}> (analysisd refuses to start)",
            "es": "{file}, línea {line}: la regla {rule} tiene un elemento desconocido <{tag}> (analysisd no arranca)",
        },
        "wazuh.err.options_value": {
            "en": "{file} line {line}: rule {rule} has an invalid <options> value ({value}); write exactly one "
            "value per <options> element",
            "es": "{file}, línea {line}: la regla {rule} tiene un valor de <options> no válido ({value}); escriba "
            "exactamente un valor por elemento <options>",
        },
        "wazuh.err.field_static": {
            "en": "{file} line {line}: rule {rule} uses <field> on the static field '{name}' (analysisd refuses "
            "to start; use the dedicated element)",
            "es": "{file}, línea {line}: la regla {rule} usa <field> sobre el campo estático '{name}' (analysisd no "
            "arranca; use el elemento dedicado)",
        },
        "wazuh.err.field_name": {
            "en": "{file} line {line}: rule {rule} has a <field> without a name",
            "es": "{file}, línea {line}: la regla {rule} tiene un <field> sin nombre",
        },
        "wazuh.err.ip": {
            "en": "{file} line {line}: rule {rule} has an invalid <{tag}> value ({value})",
            "es": "{file}, línea {line}: la regla {rule} tiene un valor de <{tag}> no válido ({value})",
        },
        "wazuh.err.sid_list": {
            "en": "{file} line {line}: rule {rule} has an invalid <{tag}> value ({value})",
            "es": "{file}, línea {line}: la regla {rule} tiene un valor de <{tag}> no válido ({value})",
        },
        "wazuh.note.repaired": {
            "en": "{file} is not well-formed XML; parsed after repairing constructs Wazuh tolerates (comments, bare "
            "& or <)",
            "es": "{file} no es XML bien formado; se analizó tras reparar construcciones que Wazuh tolera "
            "(comentarios, & o < sueltos)",
        },
        "wazuh.note.partial": {
            "en": "{file}: parsed block by block; {failed} block(s) could not be read",
            "es": "{file}: analizado bloque a bloque; no se pudieron leer {failed} bloque(s)",
        },
        "wazuh.note.salvaged": {
            "en": "{file}: {count} rule id(s) recovered by text scan from unreadable parts (reserved, not analyzed)",
            "es": "{file}: {count} id(s) de regla recuperados por búsqueda de texto en partes ilegibles "
            "(reservados, no analizados)",
        },
        "wazuh.note.encoding": {
            "en": "{file} is not valid UTF-8; undecodable bytes were replaced",
            "es": "{file} no es UTF-8 válido; se reemplazaron los bytes no decodificables",
        },
        "wazuh.note.overwrite_missing": {
            "en": '{file} line {line}: rule {rule} has overwrite="yes" but no earlier rule has that id (Wazuh '
            "adds it as a new rule)",
            "es": '{file}, línea {line}: la regla {rule} tiene overwrite="yes" pero ninguna regla anterior tiene '
            "ese id (Wazuh la añade como regla nueva)",
        },
        "wazuh.note.nested_group": {
            "en": "{file} line {line}: nested <group> elements (not standard Wazuh syntax)",
            "es": "{file}, línea {line}: elementos <group> anidados (sintaxis no estándar de Wazuh)",
        },
    }
)


class RuleCondition(NamedTuple):
    """One match element of a rule: ``("field", {"name": "win.system.channel"}, "^Security$")``."""

    tag: str
    attrs: dict[str, str]
    text: str


@dataclass(slots=True)
class WazuhRule:
    """One ``<rule>`` as written (``Ruleset.all_rules``) or as effective after overwrites (``Ruleset.rules``).

    ``groups`` joins the enclosing ``<group name="...">`` names and the rule's own ``<group>`` elements, which is
    what ``if_group`` / ``if_matched_group`` see. ``conditions`` keeps every match element in file order.
    """

    id: str
    level: int
    description: str | None = None
    groups: tuple[str, ...] = ()
    if_sid: list[str] = field(default_factory=list)
    if_group: list[str] = field(default_factory=list)
    if_matched_sid: list[str] = field(default_factory=list)
    if_matched_group: list[str] = field(default_factory=list)
    if_level: str | None = None
    frequency: int | None = None
    timeframe: int | None = None
    ignore: int | None = None
    noalert: bool = False
    options: tuple[str, ...] = ()
    overwrite: bool = False
    conditions: list[RuleCondition] = field(default_factory=list)
    correlation: tuple[str, ...] = ()  # same_* / different_* / global_frequency options
    mitre: tuple[str, ...] = ()
    file: str = ""
    line: int | None = None
    is_local: bool = False
    valid: bool = True  # False when analysisd would reject this rule (see Ruleset.errors)
    attributes: dict[str, str] = field(default_factory=dict)  # raw attributes after $VAR substitution
    original: WazuhRule | None = None  # effective overwrite: the rule it replaced

    @property
    def is_correlation(self) -> bool:
        """True for rules that count earlier events (if_matched_* or a frequency threshold)."""
        return bool(self.if_matched_sid or self.if_matched_group or "frequency" in self.attributes)

    @property
    def group_string(self) -> str:
        """Groups as analysisd stores them (``"syslog,sshd,authentication_failed,"``)."""
        return "".join(f"{g}," for g in self.groups)

    @property
    def no_log(self) -> bool:
        return "no_log" in self.options

    @property
    def parents(self) -> tuple[str, ...]:
        """Rule ids this rule is attached to as a child (if_sid, or if_matched_sid when there is no if_sid)."""
        return tuple(self.if_sid) if self.if_sid else tuple(self.if_matched_sid)


@dataclass(frozen=True, slots=True)
class RulesetError:
    """A problem found while loading rules. ``fatal`` means analysisd would most likely refuse the file."""

    file: str
    line: int | None
    message: Message
    rule_id: str | None = None
    fatal: bool = True

    def __str__(self) -> str:
        return render(self.message)


@dataclass(slots=True)
class Ruleset:
    """Parsed rules plus the correlation graph.

    * ``rules`` — effective rule per id (first definition wins; ``overwrite="yes"`` merges like analysisd).
    * ``all_rules`` — every ``<rule>`` element in load order (duplicates and overwrites included).
    * ``errors`` — problems that make the ruleset (or analysisd) incomplete; ``notes`` — tolerated oddities.
    """

    rules: dict[str, WazuhRule] = field(default_factory=dict)
    all_rules: list[WazuhRule] = field(default_factory=list)
    files: list[str] = field(default_factory=list)
    local_files: list[str] = field(default_factory=list)
    errors: list[RulesetError] = field(default_factory=list)
    notes: list[RulesetError] = field(default_factory=list)
    duplicates: list[tuple[str, str, str]] = field(default_factory=list)  # (id, file kept, file skipped)
    overwrites: list[tuple[WazuhRule, WazuhRule]] = field(default_factory=list)  # (replaced, overwriting)
    salvaged_ids: set[int] = field(default_factory=set)
    _index: _Index | None = field(default=None, repr=False)
    _dep_cache: dict[str, tuple[tuple[str, str], ...]] = field(default_factory=dict, repr=False)
    _child_cache: dict[str, tuple[str, ...]] = field(default_factory=dict, repr=False)
    _desc_cache: dict[tuple[str, int], tuple[str, ...]] = field(default_factory=dict, repr=False)

    # ---- lookups ---------------------------------------------------------------------------------------------
    def get(self, rule_id: str | int) -> WazuhRule | None:
        """Effective rule by id (``"5710"``, ``5710`` and ``"05710"`` are the same id)."""
        return self.rules.get(_norm_id(rule_id))

    @property
    def used_ids(self) -> set[int]:
        """Every rule id defined anywhere, including ids recovered from unparseable parts."""
        ids = {int(r.id) for r in self.all_rules}
        ids.update(self.salvaged_ids)
        return ids

    def local_rules(self) -> list[WazuhRule]:
        """Rule elements from local files (``etc/rules``, ``local_rules*.xml``...), in load order."""
        return [r for r in self.all_rules if r.is_local]

    def dependents(self, rule_id: str | int) -> tuple[str, ...]:
        """Rules that correlate on ``rule_id``: ``if_matched_sid`` containing it, ``if_matched_group`` matching
        one of its groups, or frequency rules chained to it via ``if_sid``. Sorted numerically.

        Like analysisd, a link only exists when ``rule_id`` loaded BEFORE the correlation rule: the correlation
        lists are wired once, when the correlation rule is loaded (``OS_MarkID``/``OS_MarkGroup``), so a rule
        loaded later never feeds it even if its groups match."""
        return tuple(sorted({dep for dep, _ in self.dependents_detail(rule_id)}, key=_id_key))

    def dependents_detail(self, rule_id: str | int) -> tuple[tuple[str, str], ...]:
        """Like :meth:`dependents` but with the link kind: ``if_matched_sid``, ``if_matched_group`` or
        ``frequency_if_sid``. A dependent linked in two ways appears twice."""
        key = _norm_id(rule_id)
        cached = self._dep_cache.get(key)
        if cached is not None:
            return cached
        index = self._ensure_index()
        found: set[tuple[str, str]] = set()
        for dep in index.matched_sid.get(key, ()):
            found.add((dep, "if_matched_sid"))
        for dep in index.freq_if_sid.get(key, ()):
            found.add((dep, "frequency_if_sid"))
        rule = self.rules.get(key)
        if rule is not None and rule.groups:
            subject = rule.group_string.lower()
            for compiled, dep in index.matched_group:
                if _osmatch_compiled(compiled, subject):
                    found.add((dep, "if_matched_group"))
        found = {(dep, via) for dep, via in found if dep != key and index.loaded_before(key, dep)}
        result = tuple(sorted(found, key=lambda item: (_id_key(item[0]), item[1])))
        self._dep_cache[key] = result
        return result

    def children(self, rule_id: str | int) -> tuple[str, ...]:
        """Rules evaluated as children of ``rule_id`` (``if_sid``, ``if_matched_sid`` without ``if_sid``, or an
        ``if_group`` matching its groups) that loaded after it (analysisd attaches a child only to rules that are
        already loaded). Sorted numerically."""
        key = _norm_id(rule_id)
        cached = self._child_cache.get(key)
        if cached is not None:
            return cached
        index = self._ensure_index()
        found = set(index.if_sid.get(key, ()))
        found.update(index.auto_child.get(key, ()))
        rule = self.rules.get(key)
        if rule is not None and rule.groups:
            subject = rule.group_string.lower()
            found.update(child for compiled, child in index.if_group if _osmatch_compiled(compiled, subject))
        found = {child for child in found if child != key and index.loaded_before(key, child)}
        result = tuple(sorted(found, key=_id_key))
        self._child_cache[key] = result
        return result

    def position(self, rule_id: str | int) -> int | None:
        """Load position of a rule id (its first definition; an overwrite keeps it), or None when unknown."""
        return self._ensure_index().position.get(_norm_id(rule_id))

    def descendants(self, rule_id: str | int, limit: int = 5000) -> tuple[str, ...]:
        """Every rule below ``rule_id`` in analysisd's rule tree (children, their children...), cycle-safe and
        capped at ``limit`` ids."""
        root = _norm_id(rule_id)
        cached = self._desc_cache.get((root, limit))
        if cached is not None:
            return cached
        seen: dict[str, None] = {}
        stack = list(self.children(root))
        while stack and len(seen) < limit:
            current = stack.pop()
            if current in seen or current == root:
                continue
            seen[current] = None
            stack.extend(self.children(current))
        result = tuple(sorted(seen, key=_id_key))
        self._desc_cache[(root, limit)] = result
        return result

    def evaluated_after(self, parent_id: str | int, rule: WazuhRule) -> tuple[str, ...]:
        """Children of ``parent_id`` that analysisd tries AFTER ``rule`` (a child of it): siblings are tried in
        descending priority (level 0 counts as 99, levels x100 unless ``accuracy="0"``), equal priorities in load
        order. Whenever ``rule`` matches, these siblings (and everything below them) never see the event."""
        own = evaluation_priority(rule)
        own_position = self.position(rule.id)
        after: list[str] = []
        for sibling_id in self.children(parent_id):
            sibling = self.rules.get(sibling_id)
            if sibling is None or sibling_id == rule.id:
                continue
            priority = evaluation_priority(sibling)
            if priority < own:
                after.append(sibling_id)
            elif priority == own:
                position = self.position(sibling_id)
                if own_position is None or (position is not None and position > own_position):
                    after.append(sibling_id)
        return tuple(after)

    # ---- internals -------------------------------------------------------------------------------------------
    def _ensure_index(self) -> _Index:
        if self._index is None:
            self._index = _Index.build(self.rules.values())
        return self._index

    def _invalidate(self) -> None:
        self._index = None
        self._dep_cache.clear()
        self._child_cache.clear()
        self._desc_cache.clear()


@dataclass(slots=True)
class _Index:
    matched_sid: dict[str, list[str]]
    freq_if_sid: dict[str, list[str]]
    matched_group: list[tuple[_OsMatch, str]]
    if_sid: dict[str, list[str]]
    auto_child: dict[str, list[str]]
    if_group: list[tuple[_OsMatch, str]]
    position: dict[str, int]

    def loaded_before(self, first: str, second: str) -> bool:
        """True when rule ``first`` was loaded before rule ``second`` (unknown positions count as True)."""
        a, b = self.position.get(first), self.position.get(second)
        return a is None or b is None or a < b

    @classmethod
    def build(cls, rules: Iterable[WazuhRule]) -> _Index:
        index = cls({}, {}, [], {}, {}, [], {})
        for rule in rules:  # Ruleset.rules keeps first-definition (load) order
            index.position.setdefault(rule.id, len(index.position))
            for sid in rule.if_matched_sid:
                index.matched_sid.setdefault(sid, []).append(rule.id)
            if "frequency" in rule.attributes:
                for sid in rule.if_sid:
                    index.freq_if_sid.setdefault(sid, []).append(rule.id)
            index.matched_group.extend((_compile_osmatch(p), rule.id) for p in rule.if_matched_group)
            for sid in rule.if_sid:
                index.if_sid.setdefault(sid, []).append(rule.id)
            if not rule.if_sid:
                for sid in rule.if_matched_sid:
                    index.auto_child.setdefault(sid, []).append(rule.id)
            index.if_group.extend((_compile_osmatch(p), rule.id) for p in rule.if_group)
        return index


# ---- public helpers ----------------------------------------------------------------------------------------------


@functools.lru_cache(maxsize=4096)
def _compile_osmatch(pattern: str) -> _OsMatch:
    negate = pattern.startswith("!")
    body = pattern[1:] if negate else pattern
    alternatives: list[tuple[bool, bool, str]] = []
    for alternative in body.lower().split("|"):
        if not alternative:
            continue
        start = alternative.startswith("^")
        core = alternative[1:] if start else alternative
        end = core.endswith("$")
        alternatives.append((start, end, core[:-1] if end else core))
    return negate, tuple(alternatives)


def _osmatch_compiled(compiled: _OsMatch, subject: str) -> bool:
    """``subject`` must already be lower-case."""
    negate, alternatives = compiled
    matched = False
    for start, end, core in alternatives:
        if start and end:
            ok = subject == core
        elif start:
            ok = subject.startswith(core)
        elif end:
            ok = subject.endswith(core)
        else:
            ok = core in subject
        if ok:
            matched = True
            break
    return matched != negate


def osmatch(pattern: str, text: str) -> bool:
    """Approximate Wazuh ``OS_Match``: case-insensitive substring, ``|`` alternatives, ``^``/``$`` anchors and a
    leading ``!`` negation. Used for ``if_group``/``if_matched_group`` against a rule's group string."""
    return _osmatch_compiled(_compile_osmatch(pattern), text.lower())


def evaluation_priority(rule: WazuhRule) -> int:
    """analysisd's sibling ordering key (higher is tried first): level 0 becomes 99 so that "ignore" rules win,
    and levels are multiplied by 100 unless the rule sets ``accuracy="0"``."""
    level = 99 if rule.level == 0 else rule.level
    return level if _parse_int(rule.attributes.get("accuracy")) == 0 else level * 100


def is_static_field(name: str) -> bool:
    """True when ``<field name=...>`` would be a fatal "Field X is static" error in analysisd."""
    return name.strip().lower() in STATIC_FIELDS


def load_ruleset(paths: Sequence[str | Path], *, local_paths: Sequence[str | Path] = ()) -> Ruleset:
    """Load Wazuh rule files and/or directories of ``*.xml`` files.

    Directories are read like analysisd reads a ``rule_dir`` (``*.xml``, not recursive); a Wazuh install root
    (``/var/ossec``) or a directory holding ``ruleset/rules`` and ``etc/rules`` is expanded to both. Files load in
    analysisd's order: every file of every rule directory sorted together by FILE NAME (``rules-config.c``
    sorts on the basename), a stock file first when two share a name. So ``0095-sshd_rules.xml`` loads before
    ``hushwatch_local_rules.xml``, which loads before ``local_rules.xml``; load order decides overwrites and
    which rules a correlation rule can see (see :meth:`Ruleset.dependents`).
    Files under ``etc/rules``, named ``*local*``, or in/under ``local_paths`` are *local* (audited); files
    under ``ruleset/rules`` or named like ``0095-sshd_rules.xml`` are stock; anything else counts as local so an
    audit never skips it silently. Problems are recorded in :attr:`Ruleset.errors`; this never raises for bad
    input files.
    """
    if isinstance(paths, (str, Path)):
        paths = [paths]
    ruleset = Ruleset()
    forced_local = {_resolve(Path(p).expanduser()) for p in local_paths}
    seen: set[Path] = set()
    candidates: list[tuple[Path, bool]] = []
    for raw in paths:
        path = Path(raw).expanduser()
        found: list[Path]
        if path.is_dir():
            found = _files_in_dir(path)
            if not found:
                ruleset.errors.append(RulesetError(str(path), None, M("wazuh.err.no_files", file=_file(path))))
        elif path.is_file():
            found = [path]
        else:
            ruleset.errors.append(RulesetError(str(path), None, M("wazuh.err.not_found", file=_file(path))))
            found = []
        for file_path in found:
            resolved = _resolve(file_path)
            if resolved in seen:
                continue
            seen.add(resolved)
            forced = any(resolved == f or f in resolved.parents for f in forced_local)
            candidates.append((file_path, forced or _is_local_file(file_path)))
    candidates.sort(key=lambda item: (item[0].name, item[1]))  # analysisd: by basename; stock first on a tie
    for file_path, is_local in candidates:
        _load_file(ruleset, file_path, is_local)
    ruleset._invalidate()
    return ruleset


def parse_rules_text(text: str, *, file: str = "<text>", is_local: bool = True, into: Ruleset | None = None) -> Ruleset:
    """Parse one rules document given as a string (tests, the emitter's re-parse check, API downloads)."""
    ruleset = into if into is not None else Ruleset()
    ruleset.files.append(file)
    if is_local:
        ruleset.local_files.append(file)
    _parse_into(ruleset, text, file, is_local)
    ruleset._invalidate()
    return ruleset


# ---- file handling -----------------------------------------------------------------------------------------------


def _resolve(path: Path) -> Path:
    try:
        return path.resolve()
    except (OSError, RuntimeError):
        return path.absolute()


def _files_in_dir(directory: Path) -> list[Path]:
    subdirs = [
        directory / "ruleset" / "rules",
        directory / "rules",
        directory / "etc" / "rules",
    ]
    out: list[Path] = []
    for folder in [directory, *subdirs]:
        if not folder.is_dir():
            continue
        try:
            entries = sorted(folder.iterdir(), key=lambda p: p.name)
        except OSError:
            continue
        out.extend(p for p in entries if p.suffix.lower() == ".xml" and p.is_file())
    return out


def _is_local_file(path: Path) -> bool:
    parts = [part.lower() for part in path.absolute().parts]
    for i in range(len(parts) - 1, 0, -1):  # the innermost directory pair decides
        pair = (parts[i - 1], parts[i])
        if pair == ("etc", "rules"):
            return True
        if pair == ("ruleset", "rules"):
            return False
    name = path.name.lower()
    if "local" in name or name.startswith("hushwatch"):
        return True
    return not _STOCK_FILE.match(path.name)


def _file(path: str | Path) -> Entity:
    return Entity("file", str(path))


def _short(value: str) -> str:
    value = value.replace("\n", " ").replace("\r", " ")
    if len(value) > _MAX_VALUE_IN_MESSAGE:
        return value[: _MAX_VALUE_IN_MESSAGE - 3] + "..."
    return value


def _load_file(ruleset: Ruleset, path: Path, is_local: bool) -> None:
    name = str(path)
    ruleset.files.append(name)
    if is_local:
        ruleset.local_files.append(name)
    try:
        size = path.stat().st_size
        if size > MAX_FILE_BYTES:
            ruleset.errors.append(
                RulesetError(name, None, M("wazuh.err.too_large", file=_file(name), limit=MAX_FILE_BYTES // 2**20))
            )
            return
        data = path.read_bytes()
    except OSError as exc:
        ruleset.errors.append(
            RulesetError(name, None, M("wazuh.err.read", file=_file(name), error=exc.strerror or type(exc).__name__))
        )
        return
    text = _decode(data, ruleset, name)
    _parse_into(ruleset, text, name, is_local)


def _decode(data: bytes, ruleset: Ruleset, name: str) -> str:
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        try:
            return data.decode("utf-16")
        except UnicodeDecodeError:
            pass
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError:
        ruleset.notes.append(RulesetError(name, None, M("wazuh.note.encoding", file=_file(name)), fatal=False))
        return data.decode("utf-8-sig", errors="replace")


# ---- XML parsing ---------------------------------------------------------------------------------------------------


@dataclass(slots=True)
class _Node:
    tag: str
    attrs: dict[str, str]
    line: int
    children: list[_Node] = field(default_factory=list)
    parts: list[str] = field(default_factory=list)

    @property
    def text(self) -> str:
        return "".join(self.parts)


class _XMLFailure(Exception):
    def __init__(self, line: int | None, detail: str) -> None:
        super().__init__(detail)
        self.line = line
        self.detail = detail


class _Forbidden(Exception):
    """A DTD or entity declaration: refused (no entity expansion, ever)."""


def _xml_tree(text: str, line_offset: int = 0) -> _Node:
    """Parse ``text`` wrapped in a synthetic root with expat. Line numbers match the original text (plus
    ``line_offset`` when ``text`` is a block cut out of a larger document)."""
    parser = expat.ParserCreate()
    parser.buffer_text = True
    root = _Node("#root", {}, 0)
    stack: list[_Node] = [root]

    def start(name: str, attrs: dict[str, str]) -> None:
        line = parser.CurrentLineNumber + line_offset
        node = _Node(name.lower(), {k.lower(): v for k, v in attrs.items()}, line)
        stack[-1].children.append(node)
        stack.append(node)

    def end(_name: str) -> None:
        stack.pop()

    def chars(data: str) -> None:
        stack[-1].parts.append(data)

    def forbid(*_args: object) -> None:
        raise _Forbidden

    parser.StartElementHandler = start
    parser.EndElementHandler = end
    parser.CharacterDataHandler = chars
    parser.StartDoctypeDeclHandler = forbid
    parser.EntityDeclHandler = forbid
    parser.UnparsedEntityDeclHandler = forbid
    parser.ExternalEntityRefHandler = forbid  # type: ignore[assignment]
    parser.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)
    try:
        parser.Parse(f"<{_ROOT}>{text}</{_ROOT}>", True)
    except expat.ExpatError as exc:
        raise _XMLFailure(exc.lineno + line_offset, expat.errors.messages.get(exc.code, str(exc))) from None
    except _Forbidden:
        raise _XMLFailure(parser.CurrentLineNumber + line_offset, "DOCTYPE/ENTITY declaration") from None
    except RecursionError:  # pragma: no cover - expat is not recursive, defensive only
        raise _XMLFailure(None, "document too deep") from None
    if len(root.children) != 1:  # pragma: no cover - the synthetic root is always the single child
        raise _XMLFailure(None, "unexpected document structure")
    return root.children[0]


def _blank(match: re.Match[str]) -> str:
    """Replace a removed construct by as many newlines as it spanned (keeps line numbers)."""
    return "\n" * match.group(0).count("\n")


def _strip_comments(text: str) -> tuple[str, bool]:
    """Blank out ``<!-- ... -->`` comments in linear time. Returns ``(text, unterminated)``; an unterminated
    comment swallows the rest of the text (os_xml fails with "Comment not closed")."""
    if "<!--" not in text:
        return text, False
    out: list[str] = []
    pos = 0
    while True:
        start = text.find("<!--", pos)
        if start < 0:
            out.append(text[pos:])
            return "".join(out), False
        out.append(text[pos:start])
        end = text.find("-->", start + 4)
        if end < 0:
            out.append("\n" * text.count("\n", start))
            return "".join(out), True
        out.append("\n" * text.count("\n", start, end + 3))
        pos = end + 3


def _strip_doctypes(text: str) -> str:
    """Blank out ``<!DOCTYPE ...>`` declarations (with an internal ``[...]`` subset) in linear time."""
    out: list[str] = []
    pos = 0
    while (match := _DOCTYPE_START.search(text, pos)) is not None:
        start = match.start()
        gt = text.find(">", match.end())
        bracket = text.find("[", match.end())
        if bracket >= 0 and (gt < 0 or bracket < gt):
            close = text.find("]", bracket + 1)
            gt = -1 if close < 0 else text.find(">", close + 1)
        end = len(text) if gt < 0 else gt + 1
        out.append(text[pos:start])
        out.append("\n" * text.count("\n", start, end))
        pos = end
    out.append(text[pos:])
    return "".join(out)


def _split_cdata(text: str) -> list[str]:
    """Split like ``re.split`` with a capturing group: even items are outside CDATA, odd items are sections."""
    pieces: list[str] = []
    pos = 0
    while True:
        start = text.find(_CDATA_START, pos)
        end = -1 if start < 0 else text.find("]]>", start + len(_CDATA_START))
        if end < 0:
            pieces.append(text[pos:])
            return pieces
        pieces.append(text[pos:start])
        pieces.append(text[start : end + 3])
        pos = end + 3


def _block_spans(text: str) -> Iterator[tuple[int, int]]:
    """Top-level ``<group>``/``<var>`` blocks, each ending at the first matching closing tag (like a lazy regex,
    but O(n log n): an unclosed block never makes the scan re-read the rest of the file)."""
    closers = {name: [(m.start(), m.end()) for m in pattern.finditer(text)] for name, pattern in _BLOCK_END.items()}
    closer_starts = {name: [start for start, _ in spans] for name, spans in closers.items()}
    pos = 0
    while (match := _BLOCK_START.search(text, pos)) is not None:
        name = match.group(1).lower()
        gt = text.find(">", match.end())
        if gt < 0:
            return
        if text[gt - 1] == "/":
            yield match.start(), gt + 1
            pos = gt + 1
            continue
        index = bisect.bisect_left(closer_starts[name], gt + 1)
        if index == len(closer_starts[name]):
            pos = match.end()
            continue
        end = closers[name][index][1]
        yield match.start(), end
        pos = end


def _repair(text: str) -> str:
    """Make os_xml-tolerated input well-formed: drop comments/DOCTYPE, escape bare ``&`` and stray ``<``."""
    text, _ = _strip_comments(text)
    text = _strip_doctypes(text)
    pieces = _split_cdata(text)
    for i in range(0, len(pieces), 2):  # even indexes are outside CDATA sections
        piece = _BAD_CHARS.sub(" ", pieces[i])
        piece = _BARE_AMP.sub("&amp;", piece)
        pieces[i] = _STRAY_LT.sub("&lt;", piece)
    return "".join(pieces)


def _parse_into(ruleset: Ruleset, text: str, name: str, is_local: bool) -> None:
    if text.startswith("\ufeff"):
        text = text[1:]
    text = _SURROGATES.sub("\ufffd", text)  # expat needs encodable text
    text = _XML_DECL.sub(_blank, text, count=1)
    if _DOCTYPE_START.search(text) or _ENTITY_DECL.search(text):
        ruleset.errors.append(RulesetError(name, None, M("wazuh.err.dtd", file=_file(name))))
    if _CDATA_START in text:  # os_xml reads "<!" as a comment that only "-->" or "!>" closes
        ruleset.errors.append(RulesetError(name, None, M("wazuh.err.cdata", file=_file(name))))
    if _strip_comments(text)[1]:
        ruleset.errors.append(RulesetError(name, None, M("wazuh.err.comment", file=_file(name))))
    try:
        tops = _xml_tree(text).children
    except _XMLFailure as strict_failure:
        repaired = _repair(text)
        try:
            tops = _xml_tree(repaired).children
            ruleset.notes.append(RulesetError(name, None, M("wazuh.note.repaired", file=_file(name)), fatal=False))
        except _XMLFailure:
            tops = _parse_blocks(ruleset, repaired, name, strict_failure)
    _walk_document(ruleset, tops, name, is_local)


def _parse_blocks(ruleset: Ruleset, text: str, name: str, first_failure: _XMLFailure) -> list[_Node]:
    """Last resort: parse each top-level <group>/<var> block alone; salvage rule ids of the broken ones."""
    tops: list[_Node] = []
    failed = 0
    covered_until = 0
    lines_before = 0  # newlines in text[:covered_until], counted incrementally (linear)
    broken_text: list[str] = []
    for start, end in _block_spans(text):
        lines_before += text.count("\n", covered_until, start)
        broken_text.append(text[covered_until:start])
        block = text[start:end]
        try:
            tops.extend(_xml_tree(block, line_offset=lines_before).children)
        except _XMLFailure as failure:
            failed += 1
            broken_text.append(block)
            ruleset.errors.append(
                RulesetError(
                    name,
                    failure.line,
                    M("wazuh.err.xml", file=_file(name), line=failure.line or 0, detail=failure.detail),
                )
            )
        lines_before += block.count("\n")
        covered_until = end
    broken_text.append(text[covered_until:])
    if failed == 0:
        # Every recognizable block parsed, so the damage is outside them (an unclosed <group>, junk between
        # blocks): report the original error once.
        ruleset.errors.append(
            RulesetError(
                name,
                first_failure.line,
                M("wazuh.err.xml", file=_file(name), line=first_failure.line or 0, detail=first_failure.detail),
            )
        )
    if tops:
        note = M("wazuh.note.partial", file=_file(name), failed=max(failed, 1))
        ruleset.notes.append(RulesetError(name, None, note, fatal=False))
    parsed_ids = {int(m) for block in tops for m in _ids_in_nodes(block)}
    salvaged = {
        int(found.group(1))
        for tag in _SALVAGE_TAG.finditer("".join(broken_text))
        if (found := _SALVAGE_ID.search(tag.group(1))) is not None
    } - parsed_ids
    salvaged.discard(0)
    if salvaged:
        ruleset.salvaged_ids.update(salvaged)
        ruleset.notes.append(
            RulesetError(name, None, M("wazuh.note.salvaged", file=_file(name), count=len(salvaged)), fatal=False)
        )
    return tops


def _ids_in_nodes(node: _Node) -> Iterable[str]:
    stack = [node]
    while stack:
        current = stack.pop()
        if current.tag == "rule":
            value = current.attrs.get("id", "").strip()
            if value.isdigit() and len(value) <= 9:
                yield value
        stack.extend(current.children)


# ---- document walking ----------------------------------------------------------------------------------------------


@dataclass(slots=True)
class _Ctx:
    ruleset: Ruleset
    file: str
    is_local: bool
    variables: dict[str, str]

    def error(self, line: int | None, message: Message, rule_id: str | None = None) -> None:
        self.ruleset.errors.append(RulesetError(self.file, line, message, rule_id))

    def note(self, line: int | None, message: Message, rule_id: str | None = None) -> None:
        self.ruleset.notes.append(RulesetError(self.file, line, message, rule_id, fatal=False))

    def subst(self, value: str) -> str:
        if "$" not in value or not self.variables:
            return value
        return _VAR_REF.sub(lambda m: self.variables.get(m.group(1).lower(), m.group(0)), value)


def _walk_document(ruleset: Ruleset, tops: list[_Node], name: str, is_local: bool) -> None:
    ctx = _Ctx(ruleset, name, is_local, {})
    for node in tops:  # variables first: they are file-scoped
        if node.tag == "var":
            var_name = node.attrs.get("name", "").strip()
            if var_name:
                ctx.variables[var_name.lower()] = node.text
    for node in tops:
        if node.tag == "group":
            _walk_group(ctx, node, (), 0)
        elif node.tag != "var":
            ctx.error(node.line, M("wazuh.err.root_element", file=_file(name), line=node.line, tag=_short(node.tag)))


def _walk_group(ctx: _Ctx, node: _Node, inherited: tuple[str, ...], depth: int) -> None:
    if depth > _MAX_DEPTH:
        ctx.error(node.line, M("wazuh.err.too_deep", file=_file(ctx.file), line=node.line))
        return
    groups = _merge_groups(inherited, _split_groups(ctx.subst(node.attrs.get("name", ""))))
    content = 0
    for child in node.children:
        if child.tag == "rule":
            content += 1
            rule = _build_rule(ctx, child, groups)
            if rule is not None:
                _register(ctx, rule)
        elif child.tag == "group":
            content += 1
            ctx.note(child.line, M("wazuh.note.nested_group", file=_file(ctx.file), line=child.line))
            _walk_group(ctx, child, groups, depth + 1)
        elif child.tag != "var":
            ctx.error(
                child.line, M("wazuh.err.group_element", file=_file(ctx.file), line=child.line, tag=_short(child.tag))
            )
    if content == 0:
        ctx.error(node.line, M("wazuh.err.empty_group", file=_file(ctx.file), line=node.line))


def _split_groups(value: str) -> tuple[str, ...]:
    return tuple(part.strip() for part in value.split(",") if part.strip())


def _merge_groups(*sources: Iterable[str]) -> tuple[str, ...]:
    seen: dict[str, None] = {}
    for source in sources:
        for group in source:
            seen.setdefault(group, None)
    return tuple(seen)


def _norm_id(value: str | int) -> str:
    text = str(value).strip()
    if text.isdigit():
        return str(int(text))
    return text


def _id_key(value: str) -> tuple[int, str]:
    return (int(value), "") if value.isdigit() else (1 << 62, value)


def _parse_int(value: str | None) -> int | None:
    if value is None:
        return None
    text = value.strip()
    return int(text) if _INT.match(text) else None


def _build_rule(ctx: _Ctx, node: _Node, wrapper_groups: tuple[str, ...]) -> WazuhRule | None:
    fname = _file(ctx.file)
    line = node.line
    attrs = {k: ctx.subst(v) for k, v in node.attrs.items()}
    raw_id = attrs.get("id", "").strip()
    if not _RULE_ID.match(raw_id) or int(raw_id) == 0:
        ctx.error(line, M("wazuh.err.rule_id", file=fname, line=line, value=_short(raw_id)))
        return None
    rule_id = str(int(raw_id))
    valid = True
    level_value = _parse_int(attrs.get("level"))
    if level_value is None or level_value > 16:
        message = M("wazuh.err.level", file=fname, line=line, rule=rule_id, value=_short(attrs.get("level", "")))
        ctx.error(line, message, rule_id)
        level_value = 0
        valid = False
    for attr in attrs:
        if attr not in _RULE_ATTRS:
            ctx.error(line, M("wazuh.err.attribute", file=fname, line=line, rule=rule_id, name=_short(attr)), rule_id)
            valid = False
    numbers: dict[str, int | None] = {}
    for attr, digits in (("frequency", 4), ("timeframe", 5), ("ignore", 6), ("maxsize", 4)):
        raw = attrs.get(attr)
        parsed = _parse_int(raw)
        if raw is not None and (parsed is None or len(raw.strip()) > digits):
            ctx.error(
                line,
                M("wazuh.err.attr_value", file=fname, line=line, rule=rule_id, name=attr, value=_short(raw)),
                rule_id,
            )
            valid = False
        numbers[attr] = parsed
    for attr, allowed in (("noalert", ("0", "1")), ("overwrite", ("yes", "no"))):
        raw = attrs.get(attr)
        if raw is not None and raw.strip().lower() not in allowed:
            ctx.error(
                line,
                M("wazuh.err.attr_value", file=fname, line=line, rule=rule_id, name=attr, value=_short(raw)),
                rule_id,
            )
            valid = False

    description_parts: list[str] = []
    own_groups: list[str] = []
    options: list[str] = []
    mitre: list[str] = []
    correlation: list[str] = []
    conditions: list[RuleCondition] = []
    links: dict[str, list[str]] = {"if_sid": [], "if_group": [], "if_matched_sid": [], "if_matched_group": []}
    if_level: str | None = None
    for child in node.children:
        tag = child.tag
        text = ctx.subst(child.text)
        cline = child.line
        if tag in ("if_sid", "if_matched_sid"):
            for item in _LIST_SPLIT.split(text.strip()):
                if not item:
                    continue
                if _RULE_ID.match(item):
                    links[tag].append(str(int(item)))
                else:
                    ctx.error(
                        cline,
                        M("wazuh.err.sid_list", file=fname, line=cline, rule=rule_id, tag=tag, value=_short(item)),
                        rule_id,
                    )
                    valid = False
        elif tag in ("if_group", "if_matched_group"):
            if text.strip():
                links[tag].append(text.strip())
        elif tag == "if_level":
            if_level = text.strip() or None
        elif tag == "description":
            description_parts.append(text)
        elif tag == "group":
            own_groups.extend(_split_groups(text))
        elif tag == "options":
            values = [v.strip() for v in text.split(",") if v.strip()]
            options.extend(values)
            if len(values) != 1 or values[0] not in VALID_OPTIONS:
                ctx.error(
                    cline,
                    M("wazuh.err.options_value", file=fname, line=cline, rule=rule_id, value=_short(text.strip())),
                    rule_id,
                )
                valid = False
        elif tag == "mitre":
            mitre.extend(ctx.subst(sub.text).strip() for sub in child.children if sub.tag == "id" and sub.text.strip())
        elif tag in MATCH_TAGS:
            cattrs = {k: ctx.subst(v) for k, v in child.attrs.items()}
            conditions.append(RuleCondition(tag, cattrs, text))
            valid = _check_condition(ctx, rule_id, child.line, tag, cattrs, text) and valid
        elif tag.startswith(_CORRELATION_PREFIXES) or tag == "global_frequency":
            correlation.append(f"{tag}:{text.strip()}" if text.strip() else tag)
        elif tag in _OTHER_TAGS or tag in ("info", "if_fts", "var"):
            continue
        else:
            ctx.error(cline, M("wazuh.err.option", file=fname, line=cline, rule=rule_id, tag=_short(tag)), rule_id)
            valid = False

    description = "".join(description_parts).strip() or None
    return WazuhRule(
        id=rule_id,
        level=level_value,
        description=description,
        groups=_merge_groups(wrapper_groups, own_groups),
        if_sid=links["if_sid"],
        if_group=links["if_group"],
        if_matched_sid=links["if_matched_sid"],
        if_matched_group=links["if_matched_group"],
        if_level=if_level,
        frequency=numbers["frequency"],
        timeframe=numbers["timeframe"],
        ignore=numbers["ignore"],
        noalert=attrs.get("noalert", "").strip() == "1",
        options=tuple(options),
        overwrite=attrs.get("overwrite", "").strip().lower() == "yes",
        conditions=conditions,
        correlation=tuple(correlation),
        mitre=tuple(mitre),
        file=ctx.file,
        line=line,
        is_local=ctx.is_local,
        valid=valid,
        attributes=attrs,
    )


def _check_condition(ctx: _Ctx, rule_id: str, line: int, tag: str, attrs: dict[str, str], text: str) -> bool:
    fname = _file(ctx.file)
    if tag == "field":
        name = attrs.get("name", "").strip()
        if not name:
            ctx.error(line, M("wazuh.err.field_name", file=fname, line=line, rule=rule_id), rule_id)
            return False
        if is_static_field(name):
            ctx.error(
                line, M("wazuh.err.field_static", file=fname, line=line, rule=rule_id, name=_short(name)), rule_id
            )
            return False
    elif tag in ("srcip", "dstip"):
        value = text.strip()
        if not _valid_ip_expression(value):
            ctx.error(
                line, M("wazuh.err.ip", file=fname, line=line, rule=rule_id, tag=tag, value=_short(value)), rule_id
            )
            return False
    return True


def _valid_ip_expression(value: str) -> bool:
    candidate = value[1:] if value.startswith("!") else value
    if candidate.lower() == "any":
        return True
    if not candidate or "%" in candidate:
        return False
    try:
        ipaddress.ip_network(candidate, strict=False)
    except ValueError:
        return False
    return True


def _register(ctx: _Ctx, rule: WazuhRule) -> None:
    ruleset = ctx.ruleset
    ruleset.all_rules.append(rule)
    existing = ruleset.rules.get(rule.id)
    if existing is None:
        if rule.overwrite:
            ctx.note(rule.line, M("wazuh.note.overwrite_missing", file=_file(ctx.file), line=rule.line, rule=rule.id))
        ruleset.rules[rule.id] = rule
        return
    if rule.overwrite:
        ruleset.rules[rule.id] = replace(
            rule,
            if_sid=list(existing.if_sid),
            if_group=list(existing.if_group),
            if_matched_sid=list(existing.if_matched_sid),
            if_matched_group=list(existing.if_matched_group),
            if_level=existing.if_level,
            original=existing,
        )
        ruleset.overwrites.append((existing, rule))
        return
    ruleset.duplicates.append((rule.id, existing.file, rule.file))
