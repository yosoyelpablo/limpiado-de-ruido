"""Write SAFE Wazuh 4.x suppression rules for reviewed tuning suggestions.

A bad ``local_rules`` file stops ``wazuh-analysisd`` (every agent on that manager goes blind), and every value
in a suggestion comes from logs an attacker can write. So this module:

* builds the XML with :mod:`xml.etree.ElementTree` only — never string concatenation of data;
* turns every value into a PCRE2 literal anchored ``^...\\z`` in which each character outside ``[A-Za-z0-9_]`` is a
  ``\\x{HH}`` escape: no regex metacharacter, XML special character, ``$`` variable reference or control character
  survives. analysisd compiles PCRE2 with no options (``expression.c``): byte mode, where non-ASCII must be written
  as its UTF-8 bytes (a code point above ``\\x{ff}`` is a compile error that stops analysisd), and where ``$``
  would also match before a trailing newline (hence ``\\z``);
* maps each condition to the one Wazuh element with the same meaning as :meth:`Suggestion.matches` (§8 table),
  and refuses — never drops — conditions it cannot express exactly (dropping one would widen the scope);
* DEMOTES by default: a child rule at ``level`` (3) that copies the parent's groups (compliance groups included,
  rebuilt from the alerts' ``rule.pci_dss``/``gdpr``... when no ruleset was loaded), its MITRE ids and its
  output options (``no_full_log``...) plus ``hushwatch_tuned``, so events stay indexed, measurable and shaped like
  the parent's; level 0 only on request. A child that would not LOWER the parent's level is never written
  (nothing to gain); index-volume-only candidates are explained in ``VALIDATION.md`` instead. A child changes
  the rule an event is recorded under, so ``if_matched_sid`` correlations on the parent, and ``if_matched_group``
  correlations loaded before this file (every stock one: analysisd wires group lists at load time), stop counting
  those events. Siblings tried after the child (lower priority) and everything below them stop firing for them;
* allocates ids from the tenant range, skipping every id of the loaded ruleset, and flags REVIEW REQUIRED (with
  the affected rules in ``VALIDATION.md``) when any of that happens;
* re-parses its own output (ElementTree and the Wazuh-aware parser), compiles and self-tests every pattern, and
  writes nothing unless all checks pass. Files are 0600 in a 0700 directory and never silently overwritten.

Wazuh has no rule expiry: each rule's expiry date is written in its description, and ``hushwatch audit`` reports
the rule as ``tuning.expired`` once the date passes.

Outputs: ``hushwatch_local_rules.xml``, ``hushwatch_suppressions.json`` (tool-agnostic spec), ``VALIDATION.md``
(EN/ES checklist) and ``logtest_samples.txt`` (sample lines for ``wazuh-logtest``).
"""

from __future__ import annotations

import ipaddress
import json
import math
import os
import re
import tempfile
import unicodedata
import xml.etree.ElementTree as ET
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import date, datetime
from pathlib import Path, PurePath
from typing import Any

from .. import __version__
from ..i18n import Entity, M, Message, register, render
from ..models import get_path, stable_hash
from ..tuning import Condition, Suggestion
from .ruleset import Ruleset, WazuhRule, evaluation_priority, is_static_field, osmatch, parse_rules_text

__all__ = [
    "SAMPLES_FILE",
    "SPEC_FILE",
    "TUNED_GROUP",
    "VALIDATION_FILE",
    "XML_FILE",
    "EmitError",
    "EmitResult",
    "emit_suppressions",
    "pcre2_escape",
    "pcre2_exact",
]

XML_FILE = "hushwatch_local_rules.xml"
SPEC_FILE = "hushwatch_suppressions.json"
VALIDATION_FILE = "VALIDATION.md"
SAMPLES_FILE = "logtest_samples.txt"
TUNED_GROUP = "hushwatch_tuned"
WRAPPER_GROUPS = ("local", "hushwatch")
SPEC_SCHEMA_VERSION = "1"

# analysisd copies <location>/<user>/<hostname> content with loadmemory(), which rejects 2048+ bytes (a rules
# load error stops analysisd); keep a wide margin. Values whose escaped pattern exceeds this are refused, never
# truncated.
MAX_PATTERN_CHARS = 1800
# The group list (the <group name> attribute plus every <group> element) is concatenated with loadmemory() too,
# which refuses to append once the list holds more than 2048 bytes.
MAX_GROUP_STRING = 2000
_MAX_LISTED_PREEMPTED = 50
_MAX_DESCRIPTION = 400
_MAX_DESC_VALUE = 40
_MAX_SAMPLE_CHARS = 65_535
_MAX_SAMPLES_PER_RULE = 3
_BACKSLASH_RUN = r"(?:\x{5c})+"
_WORD = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_")
_DESC_SAFE = frozenset(_WORD | set(" .:/@-\\"))
_LABEL_SAFE = frozenset(_WORD | set(" .:-"))
_FINGERPRINT = re.compile(r"^[A-Za-z0-9_.:]+(?:-[A-Za-z0-9_.:]+)*$")
_FIELD_NAME = re.compile(r"^[A-Za-z0-9_]+(?:[. -][A-Za-z0-9_]+)*$")
_GROUP_NAME = re.compile(r"^[A-Za-z0-9_.-]+$")
_RULE_ID = re.compile(r"^[1-9][0-9]{0,5}$")
_HEX_ESCAPE = re.compile(rb"\\x\{([0-9a-f]{2})\}")
_XML_COMMENT = re.compile(r"<!--(.*?)-->", re.DOTALL)
_DESCRIPTION_FORMAT = "hushwatch: demote {parent} for {scope} (fp:{fingerprint}, expires {expires}){review}"
_COMMENT_FORMAT = " hushwatch fingerprint={fingerprint} created={created} expires={expires} review_required={review} "
_REFUSED_PREFIXES = ("agent.", "rule.", "manager.", "cluster.", "decoder.", "predecoder.", "syscheck.", "location.")
# Parent options that shape the child's OUTPUT and are copied to it (no_log/alert_by_email are not: a demoted alert
# must stay logged, and must not start emailing anyone).
COPIED_OPTIONS = ("no_full_log", "no_email_alert", "no_ar", "no_counter")
_MITRE_ID = re.compile(r"^T[0-9]{4}(?:\.[0-9]{3})?$")

register(
    {
        # ---- errors (EmitError) ------------------------------------------------------------------------------
        "wazuh.emit.err.profile": {
            "en": "Refusing to write Wazuh rules for profile '{profile}': local_rules suppression exists only in "
            "Wazuh 4.x (5.x uses Sigma rules and engine filters)",
            "es": "No se escriben reglas de Wazuh para el perfil '{profile}': la supresión con local_rules solo "
            "existe en Wazuh 4.x (5.x usa reglas Sigma y filtros del motor)",
        },
        "wazuh.emit.err.level": {
            "en": "Invalid level {level}: use 1-16 (level 0 requires allow_level_zero=True)",
            "es": "Nivel {level} no válido: use 1-16 (el nivel 0 requiere allow_level_zero=True)",
        },
        "wazuh.emit.err.range": {
            "en": "Invalid rule id range {low}-{high}",
            "es": "Rango de ids de regla no válido {low}-{high}",
        },
        "wazuh.emit.err.exhausted": {
            "en": "The rule id range {low}-{high} has no free id left for {count} {count:plural:rule|rules}",
            "es": "El rango de ids {low}-{high} no tiene ids libres para {count} {count:plural:regla|reglas}",
        },
        "wazuh.emit.err.collision": {
            "en": "Generated rule id {rule} collides with an existing or duplicated rule id; nothing was written",
            "es": "El id de regla generado {rule} coincide con un id existente o duplicado; no se escribió nada",
        },
        "wazuh.emit.err.verify": {
            "en": "The generated rules failed their safety re-check ({detail}); nothing was written",
            "es": "Las reglas generadas no superaron la verificación de seguridad ({detail}); no se escribió nada",
        },
        "wazuh.emit.err.exists": {
            "en": "{path} already exists; run again with --force to replace it (or choose another directory)",
            "es": "{path} ya existe; vuelva a ejecutar con --force para reemplazarlo (o elija otro directorio)",
        },
        "wazuh.emit.err.out_dir": {
            "en": "Output path {path} exists and is not a directory",
            "es": "La ruta de salida {path} existe y no es un directorio",
        },
        "wazuh.emit.err.out_dir_unsafe": {
            "en": "Output directory {path} is writable by other users or owned by another user: someone could "
            "swap the rules before they are deployed; use a private directory",
            "es": "El directorio de salida {path} tiene permiso de escritura para otros usuarios o pertenece a otro "
            "usuario: alguien podría cambiar las reglas antes de desplegarlas; use un directorio privado",
        },
        # ---- skipped suggestions -------------------------------------------------------------------------------
        "wazuh.emit.skip.verdict": {
            "en": "Suggestion {fingerprint} (rule {rule}) skipped: verdict is '{verdict}'; only 'tune' is emitted",
            "es": "Sugerencia {fingerprint} (regla {rule}) omitida: el veredicto es '{verdict}'; solo se emite 'tune'",
        },
        "wazuh.emit.skip.profile": {
            "en": "Suggestion {fingerprint} (rule {rule}) skipped: profile '{profile}' is not Wazuh 4.x",
            "es": "Sugerencia {fingerprint} (regla {rule}) omitida: el perfil '{profile}' no es Wazuh 4.x",
        },
        "wazuh.emit.skip.rule_id": {
            "en": "Suggestion {fingerprint} skipped: '{rule}' is not a Wazuh rule id",
            "es": "Sugerencia {fingerprint} omitida: '{rule}' no es un id de regla de Wazuh",
        },
        "wazuh.emit.skip.expires": {
            "en": "Suggestion {fingerprint} (rule {rule}) skipped: it has no valid expiry date or already expired",
            "es": "Sugerencia {fingerprint} (regla {rule}) omitida: no tiene una fecha de vencimiento válida "
            "o ya venció",
        },
        "wazuh.emit.skip.rule_wide": {
            "en": "Suggestion {fingerprint} (rule {rule}) skipped: it has no condition and would demote the whole "
            "rule (needs allow_rule_wide)",
            "es": "Sugerencia {fingerprint} (regla {rule}) omitida: no tiene condiciones y degradaría la regla "
            "completa (requiere allow_rule_wide)",
        },
        "wazuh.emit.skip.field": {
            "en": "Suggestion {fingerprint} (rule {rule}) skipped: a condition on '{field}' cannot be expressed "
            "exactly as a Wazuh rule condition",
            "es": "Sugerencia {fingerprint} (regla {rule}) omitida: una condición sobre '{field}' no se puede "
            "expresar de forma exacta en una regla de Wazuh",
        },
        "wazuh.emit.skip.static_field": {
            "en": "Suggestion {fingerprint} (rule {rule}) skipped: '{field}' is a static Wazuh field without a "
            "safe mapping (<field> on it stops analysisd)",
            "es": "Sugerencia {fingerprint} (regla {rule}) omitida: '{field}' es un campo estático de Wazuh sin "
            "equivalencia segura (<field> sobre él detiene analysisd)",
        },
        "wazuh.emit.skip.field_name": {
            "en": "Suggestion {fingerprint} (rule {rule}) skipped: the field name '{field}' has characters that are "
            "not safe in a rule",
            "es": "Sugerencia {fingerprint} (regla {rule}) omitida: el nombre de campo '{field}' tiene caracteres "
            "no seguros en una regla",
        },
        "wazuh.emit.skip.ip": {
            "en": "Suggestion {fingerprint} (rule {rule}) skipped: the {field} value is not a single valid IP address",
            "es": "Sugerencia {fingerprint} (regla {rule}) omitida: el valor de {field} no es una única dirección "
            "IP válida",
        },
        "wazuh.emit.skip.value": {
            "en": "Suggestion {fingerprint} (rule {rule}) skipped: the {field} value is empty or not text",
            "es": "Sugerencia {fingerprint} (regla {rule}) omitida: el valor de {field} está vacío o no es texto",
        },
        "wazuh.emit.skip.conflict": {
            "en": "Suggestion {fingerprint} (rule {rule}) skipped: contradictory conditions on '{field}' (they can "
            "never match together)",
            "es": "Sugerencia {fingerprint} (regla {rule}) omitida: condiciones contradictorias sobre '{field}' "
            "(nunca pueden cumplirse a la vez)",
        },
        "wazuh.emit.skip.users": {
            "en": "Suggestion {fingerprint} (rule {rule}) skipped: data.srcuser and data.dstuser both map to one "
            "<user> element and cannot be combined exactly",
            "es": "Sugerencia {fingerprint} (regla {rule}) omitida: data.srcuser y data.dstuser corresponden al "
            "mismo elemento <user> y no se pueden combinar con exactitud",
        },
        "wazuh.emit.skip.too_long": {
            "en": "Suggestion {fingerprint} (rule {rule}) skipped: the {field} value is too long for a safe rule "
            "({length} characters once escaped; Wazuh rejects element content above 2048 bytes)",
            "es": "Sugerencia {fingerprint} (regla {rule}) omitida: el valor de {field} es demasiado largo para una "
            "regla segura ({length} caracteres escapado; Wazuh rechaza contenidos de más de 2048 bytes)",
        },
        "wazuh.emit.skip.parent_missing": {
            "en": "Suggestion {fingerprint} skipped: parent rule {rule} is not in the loaded ruleset (analysisd "
            "would discard a child of a missing rule)",
            "es": "Sugerencia {fingerprint} omitida: la regla padre {rule} no está en el ruleset cargado (analysisd "
            "descartaría una regla hija de una regla inexistente)",
        },
        "wazuh.emit.skip.host_pair": {
            "en": "Suggestion {fingerprint} (rule {rule}) skipped: agent.name and predecoder.hostname cannot be "
            "combined exactly (for agent events Wazuh's <hostname> holds the agent name)",
            "es": "Sugerencia {fingerprint} (regla {rule}) omitida: agent.name y predecoder.hostname no se pueden "
            "combinar de forma exacta (en eventos de agentes, el <hostname> de Wazuh contiene el nombre del agente)",
        },
        "wazuh.emit.skip.groups_too_long": {
            "en": "Suggestion {fingerprint} (rule {rule}) skipped: the parent's groups take {length} characters and "
            "analysisd rejects a rule whose group list exceeds 2048 bytes",
            "es": "Sugerencia {fingerprint} (regla {rule}) omitida: los grupos de la regla padre ocupan {length} "
            "caracteres y analysisd rechaza una regla cuya lista de grupos supera los 2048 bytes",
        },
        "wazuh.emit.skip.not_lower": {
            "en": "Suggestion {fingerprint} (rule {rule}) skipped: rule {rule} is already level {parent_level}, so a "
            "level-{level} child would not lower it (nothing to gain)",
            "es": "Sugerencia {fingerprint} (regla {rule}) omitida: la regla {rule} ya es de nivel {parent_level}, "
            "así que una hija de nivel {level} no lo reduciría (no hay nada que ganar)",
        },
        "wazuh.emit.skip.raises": {
            "en": "Suggestion {fingerprint} skipped: rule {rule} is level {parent_level}; a child at level {level} "
            "would raise it, not demote it",
            "es": "Sugerencia {fingerprint} omitida: la regla {rule} es de nivel {parent_level}; una hija de nivel "
            "{level} lo subiría en lugar de bajarlo",
        },
        "wazuh.emit.skip.level_zero": {
            "en": "Suggestion {fingerprint} (rule {rule}) skipped: level 0 would stop rules {dependents} "
            "(correlation rules, or rules analysisd tries after it) from seeing these events",
            "es": "Sugerencia {fingerprint} (regla {rule}) omitida: el nivel 0 impediría que las reglas "
            "{dependents} (de correlación, o que analysisd evalúa después) vean estos eventos",
        },
        "wazuh.emit.skip.duplicate": {
            "en": "Suggestion {fingerprint} (rule {rule}) skipped: same rule and conditions as suggestion {other}",
            "es": "Sugerencia {fingerprint} (regla {rule}) omitida: misma regla y condiciones que la sugerencia "
            "{other}",
        },
        # ---- warnings -----------------------------------------------------------------------------------------
        "wazuh.emit.warn.no_ruleset": {
            "en": "No ruleset was loaded: parent rules, id collisions and correlation dependents were not verified; "
            "every rule is marked REVIEW REQUIRED",
            "es": "No se cargó ningún ruleset: no se verificaron reglas padre, colisiones de ids ni dependencias de "
            "correlación; todas las reglas quedan marcadas como REVISIÓN OBLIGATORIA",
        },
        "wazuh.emit.warn.ruleset_errors": {
            "en": "The ruleset had {count} load {count:plural:error|errors}: correlation dependents and used "
            "ids may be incomplete",
            "es": "El ruleset tuvo {count} {count:plural:error|errores} de carga: las dependencias de "
            "correlación y los ids usados pueden estar incompletos",
        },
        "wazuh.emit.warn.no_stock": {
            "en": "Only local rules were loaded (no stock ruleset): correlation rules that depend on the parents "
            "were not verified; every rule is marked REVIEW REQUIRED. Load /var/ossec/ruleset/rules as well",
            "es": "Solo se cargaron reglas locales (sin el ruleset de fábrica): no se verificaron las reglas de "
            "correlación que dependen de las reglas padre; todas las reglas quedan marcadas como REVISIÓN "
            "OBLIGATORIA. Cargue también /var/ossec/ruleset/rules",
        },
        "wazuh.emit.warn.parent_unverified": {
            "en": "Parent rule {rule} is not in the loaded ruleset (only local rules were given): confirm it exists "
            "before deploying",
            "es": "La regla padre {rule} no está en el ruleset cargado (solo se dieron reglas locales): confirme "
            "que existe antes de desplegar",
        },
        "wazuh.emit.warn.groups_unknown": {
            "en": "The groups of rule {rule} are unknown: correlation by group (if_matched_group) may stop seeing "
            "the demoted events",
            "es": "Se desconocen los grupos de la regla {rule}: la correlación por grupo (if_matched_group) podría "
            "dejar de ver los eventos degradados",
        },
        "wazuh.emit.warn.group_dropped": {
            "en": "Group '{group}' of rule {rule} was not copied (characters not safe in a rule file)",
            "es": "El grupo '{group}' de la regla {rule} no se copió (caracteres no seguros en un archivo de reglas)",
        },
        "wazuh.emit.warn.manager_agent": {
            "en": "Suggestion {fingerprint}: agent-name scoping cannot match manager-local events (agent 000), whose "
            "location has no '(agent)' prefix",
            "es": "Sugerencia {fingerprint}: el filtro por nombre de agente no puede coincidir con eventos locales "
            "del manager (agente 000), cuya ubicación no lleva el prefijo '(agente)'",
        },
        "wazuh.emit.warn.hostname_agent": {
            "en": "Suggestion {fingerprint}: some examples come from agents, where Wazuh's <hostname> holds "
            "the agent name instead of predecoder.hostname; the rule only covers events the manager "
            "receives itself (syslog, agent 000), so it hides fewer events than the backtest counted",
            "es": "Sugerencia {fingerprint}: algunos ejemplos proceden de agentes, donde el <hostname> de "
            "Wazuh contiene el nombre del agente en lugar de predecoder.hostname; la regla solo cubre "
            "eventos que recibe el propio manager (syslog, agente 000), así que degrada menos eventos "
            "de los que contó el backtest",
        },
        "wazuh.emit.warn.parent_after": {
            "en": "Parent rule {rule} is defined in {file}, which analysisd loads after {output} (files load in "
            "name order): the hushwatch rule would be discarded; add it to {file} after rule {rule} instead",
            "es": "La regla padre {rule} está definida en {file}, que analysisd carga después de {output} (los "
            "archivos se cargan por orden de nombre): la regla de hushwatch se descartaría; añádala a {file} "
            "después de la regla {rule}",
        },
        "wazuh.emit.warn.user_semantics": {
            "en": "Suggestion {fingerprint}: <user> compares data.dstuser when present, otherwise data.srcuser; the "
            "examples carry both fields, so the rule may not match exactly what the backtest counted",
            "es": "Sugerencia {fingerprint}: <user> compara data.dstuser si existe y, si no, data.srcuser; los "
            "ejemplos traen ambos campos, así que la regla podría no coincidir exactamente con lo contado en el "
            "backtest",
        },
        "wazuh.emit.warn.fingerprint": {
            "en": "Suggestion for rule {rule} has an unusable fingerprint; a hash of it is used instead "
            "({fingerprint})",
            "es": "La sugerencia de la regla {rule} tiene una huella no utilizable; se usa un hash de ella "
            "({fingerprint})",
        },
        "wazuh.emit.warn.range": {
            "en": "Rule id range {low}-{high} is outside the custom range 100000-120000 recommended by Wazuh",
            "es": "El rango de ids {low}-{high} está fuera del rango personalizado 100000-120000 que recomienda Wazuh",
        },
        "wazuh.emit.warn.level_zero": {
            "en": "Level 0 DROPS events: they are not indexed, not measurable and invisible to correlation rules",
            "es": "El nivel 0 DESCARTA eventos: no se indexan, no se pueden medir y las reglas de correlación no los "
            "ven",
        },
        "wazuh.emit.warn.nothing": {
            "en": "No suggestion could be turned into a rule; no files were written",
            "es": "Ninguna sugerencia se pudo convertir en regla; no se escribió ningún archivo",
        },
        "wazuh.emit.warn.dir_mode": {
            "en": "The output directory {path} is accessible to other users; the files themselves are 0600",
            "es": "El directorio de salida {path} es accesible para otros usuarios; los archivos en sí son 0600",
        },
        # ---- XML header -----------------------------------------------------------------------------------------
        "wazuh.emit.header": {
            "en": "Generated by hushwatch {version} on {created}: suppression rules for HUMAN REVIEW. They contain "
            "real values from your alerts; keep this file local. Validate before deploying (see VALIDATION.md). "
            "Requires Wazuh 4.3 or later.",
            "es": "Generado por hushwatch {version} el {created}: reglas de supresión para REVISIÓN HUMANA. "
            "Contienen valores reales de sus alertas; mantenga este archivo en local. Valide antes de desplegar "
            "(vea VALIDATION.md). Requiere Wazuh 4.3 o posterior.",
        },
        "wazuh.emit.notice": {
            "en": "Contains real values from your alerts (they are needed for the rules to work): keep it local and "
            "never share it.",
            "es": "Contiene valores reales de sus alertas (las reglas los necesitan para funcionar): manténgalo en "
            "local y no lo comparta.",
        },
        # ---- VALIDATION.md -----------------------------------------------------------------------------------
        "wazuh.validation.title": {
            "en": "Validating the hushwatch suppression rules",
            "es": "Validación de las reglas de supresión de hushwatch",
        },
        "wazuh.validation.intro": {
            "en": "These rules are suggestions for human review, generated on {created}. A rules file that "
            "analysisd rejects stops the whole manager, so every agent goes blind: follow every step, on the "
            "master node if the manager is clustered. Requires Wazuh 4.3 or later (PCRE2 in rules).",
            "es": "Estas reglas son sugerencias para revisión humana, generadas el {created}. Un archivo de reglas "
            "que analysisd rechace detiene todo el manager y todos los agentes quedan sin visibilidad: siga todos "
            "los pasos, en el nodo master si el manager está en clúster. Requiere Wazuh 4.3 o posterior (PCRE2 "
            "en reglas).",
        },
        "wazuh.validation.expiry": {
            "en": "Wazuh has no rule expiry: a rule stays active until someone removes it. Each rule's expiry date "
            "is written in its description, and `hushwatch audit /var/ossec/etc/rules` reports it as expired "
            "(tuning.expired) once the date passes: schedule that audit, then remove or renew the rule.",
            "es": "Wazuh no hace vencer las reglas: una regla sigue activa hasta que alguien la quita. La fecha de "
            "vencimiento de cada regla está en su descripción, y `hushwatch audit /var/ossec/etc/rules` la informa "
            "como vencida (tuning.expired) cuando pasa: programe esa auditoría y luego quite o renueve la regla.",
        },
        "wazuh.validation.step_backup": {
            "en": "Back up the current custom rules:",
            "es": "Haga una copia de seguridad de las reglas personalizadas actuales:",
        },
        "wazuh.validation.step_copy": {
            "en": "Copy the new file next to local_rules.xml, with the owner and mode Wazuh expects:",
            "es": "Copie el nuevo archivo junto a local_rules.xml, con el propietario y los permisos que espera Wazuh:",
        },
        "wazuh.validation.step_check": {
            "en": "Test the configuration and the ruleset. It must finish without errors, and any warning that "
            "names a hushwatch rule id (duplicate id, parent 'not found') means that rule was discarded:",
            "es": "Pruebe la configuración y el ruleset. Debe terminar sin errores, y cualquier aviso que mencione un "
            "id de regla de hushwatch (id duplicado, padre 'not found') significa que esa regla se descartó:",
        },
        "wazuh.validation.step_logtest": {
            "en": "Replay the lines of {samples} with wazuh-logtest: each must now end in the hushwatch rule "
            "at level {level}. Replay a line from another host or user too: it must keep its original "
            "rule. Rules see the location as '(agent) ip->path', so for agent- or file-scoped rules "
            "pass an agent-style location to logtest:",
            "es": "Reproduzca las líneas de {samples} con wazuh-logtest: cada una debe terminar ahora en la "
            "regla de hushwatch con nivel {level}. Reproduzca también una línea de otro equipo o "
            "usuario: debe mantener su regla original. Las reglas ven la ubicación como '(agente) "
            "ip->ruta', así que para reglas filtradas por agente o archivo indique a logtest una "
            "ubicación de estilo agente:",
        },
        "wazuh.validation.step_restart": {
            "en": "Restart the manager and confirm that it is running:",
            "es": "Reinicie el manager y confirme que está en marcha:",
        },
        "wazuh.validation.step_watch": {
            "en": "Watch the result: demoted alerts keep arriving at level {level} with the group {group}, so they "
            "stay measurable. Check that the correlation rules listed below still fire in a test.",
            "es": "Vigile el resultado: las alertas degradadas siguen llegando con nivel {level} y el grupo "
            "{group}, así que se pueden medir. Compruebe con una prueba que las reglas de correlación de abajo "
            "siguen disparándose.",
        },
        "wazuh.validation.step_rollback": {
            "en": "Rollback: remove the file and restart the manager.",
            "es": "Marcha atrás: elimine el archivo y reinicie el manager.",
        },
        "wazuh.validation.rules_heading": {"en": "Rules in this file", "es": "Reglas de este archivo"},
        "wazuh.validation.rule_line": {
            "en": "Rule {rule} demotes rule {parent} to level {level} for {fields} (fingerprint "
            "{fingerprint}, expires {expires}; logtest samples: {samples})",
            "es": "La regla {rule} degrada la regla {parent} a nivel {level} para {fields} (huella "
            "{fingerprint}, vence el {expires}; muestras para logtest: {samples})",
        },
        "wazuh.validation.samples_lines": {"en": "lines {first}-{last}", "es": "líneas {first}-{last}"},
        "wazuh.validation.samples_line": {"en": "line {line}", "es": "línea {line}"},
        "wazuh.validation.no_samples": {
            "en": "none, as the examples carry no full_log (Windows events never do); test with a live event",
            "es": "ninguna, porque los ejemplos no traen full_log (los eventos de Windows nunca lo traen); pruebe "
            "con un evento real",
        },
        "wazuh.validation.review": {
            "en": "REVIEW REQUIRED before deploying.",
            "es": "REVISIÓN OBLIGATORIA antes de desplegar.",
        },
        "wazuh.validation.dependent_broken": {
            "en": "Correlation rule {rule} ({via}) will NOT count the demoted events: prove it still detects "
            "an attack from this scope, or drop the suggestion.",
            "es": "La regla de correlación {rule} ({via}) NO contará los eventos degradados: demuestre que "
            "sigue detectando un ataque desde este alcance o descarte la sugerencia.",
        },
        "wazuh.validation.dependent_kept": {
            "en": "Correlation rule {rule} ({via}) should keep counting the demoted events; verify it in a test.",
            "es": "La regla de correlación {rule} ({via}) debería seguir contando los eventos degradados; "
            "verifíquelo con una prueba.",
        },
        "wazuh.validation.preempted": {
            "en": "Rule {rule} (level {level}) is reached through a sibling that analysisd tries AFTER the "
            "hushwatch rule: for these events it will no longer fire. Prove it cannot detect an attack "
            "from this scope, or drop the suggestion.",
            "es": "La regla {rule} (nivel {level}) se alcanza a través de una regla hermana que analysisd "
            "evalúa DESPUÉS de la regla de hushwatch: para estos eventos dejará de dispararse. "
            "Demuestre que no puede detectar un ataque desde este alcance o descarte la sugerencia.",
        },
        "wazuh.validation.parent_after": {
            "en": "The parent rule is defined in a file that loads after {output}: add this rule to that "
            "file, after the parent, or analysisd discards it.",
            "es": "La regla padre está definida en un archivo que se carga después de {output}: agregue esta "
            "regla a ese archivo, después de la padre, o analysisd la descartará.",
        },
        "wazuh.validation.warnings_heading": {"en": "Warnings", "es": "Avisos"},
        "wazuh.validation.skipped_heading": {
            "en": "Suggestions not written as rules",
            "es": "Sugerencias que no se escribieron como reglas",
        },
        "wazuh.validation.volume_heading": {
            "en": "Index volume only (no rule written)",
            "es": "Solo volumen del índice (no se escribió ninguna regla)",
        },
        "wazuh.validation.volume_intro": {
            "en": "These scopes passed every safety gate and the backtest, but their rules are already at or below "
            "level {level} or below the triage level, so a demote rule would change nothing for analysts. If index "
            "volume is a real problem, the options are: (1) a scoped child rule (same if_sid and conditions as a "
            "hushwatch rule) with <options>no_log</options>, or with a level below log_alert_level (3 by default): "
            "the alerts are no longer written to alerts.json or the indexer (only to archives, if logall is on), "
            "and correlation rules on the parent stop counting them; or (2) an overwrite of the parent rule "
            '(overwrite="yes" with its full original body) with <options>no_log</options>: every alert of that '
            "rule disappears, on every agent, and future Wazuh updates of the rule are masked. Both make these "
            "events unsearchable during an investigation; hushwatch generates neither. Prefer keeping them.",
            "es": "Estos alcances superaron todos los controles de seguridad y el backtest, pero sus reglas ya "
            "tienen nivel {level} o inferior, o están por debajo del nivel de triaje, así que una regla de "
            "degradación no cambiaría nada para los analistas. Si el volumen del índice es un problema real, las "
            "opciones son: (1) una regla hija acotada (mismo if_sid y condiciones que una regla de hushwatch) con "
            "<options>no_log</options>, o con un nivel inferior a log_alert_level (3 por defecto): las alertas "
            "dejan de escribirse en alerts.json y en el indexador (solo quedan en archives, si logall está "
            "activo), y las reglas de correlación sobre la regla padre dejan de contarlas; o (2) una sobrescritura "
            'de la regla padre (overwrite="yes" con su cuerpo original completo) con <options>no_log</options>: '
            "desaparecen todas las alertas de esa regla, en todos los agentes, y se ocultan las actualizaciones "
            "futuras de la regla en Wazuh. Ambas impiden buscar estos eventos durante una investigación; hushwatch "
            "no genera ninguna de las dos. Es preferible conservarlos.",
        },
        "wazuh.validation.volume_line": {
            "en": "Rule {parent} for {fields} (fingerprint {fingerprint}): {per_day} alerts/day, level {level}",
            "es": "Regla {parent} para {fields} (huella {fingerprint}): {per_day} alertas/día, nivel {level}",
        },
    }
)


class EmitError(Exception):
    """The suppression file was refused. ``message`` is the translatable reason; ``str()`` is English."""

    def __init__(self, message: Message) -> None:
        super().__init__(render(message, "en"))
        self.message = message


@dataclass(slots=True)
class EmitResult:
    """What was written: ``paths`` (the rules XML first), ``rules`` as ``(id, fingerprint)``, ``skipped`` (the
    suggestions NOT written as rules) as ``(fingerprint, reason)``, ``warnings`` (things to know about what WAS
    written, or about the run; skipped suggestions are never repeated here), ``review_required`` (rule ids) and
    ``index_volume`` (fingerprints of index-volume-only suggestions, explained in VALIDATION.md, never written)."""

    paths: list[Path] = field(default_factory=list)
    rules: list[tuple[int, str]] = field(default_factory=list)
    warnings: list[Message] = field(default_factory=list)
    skipped: list[tuple[str, Message]] = field(default_factory=list)
    review_required: list[int] = field(default_factory=list)
    index_volume: list[str] = field(default_factory=list)


# ---- PCRE2 escaping ----------------------------------------------------------------------------------------------


def pcre2_escape(value: str) -> str:
    """Escape ``value`` as a PCRE2 literal: ``[A-Za-z0-9_]`` stay, everything else becomes ``\\x{HH}``.

    Non-ASCII characters are written as their UTF-8 bytes (each ``\\x{HH}`` <= ``ff``), which is valid in both
    PCRE2 byte and UTF modes (a code point above ``\\x{ff}`` is a *compile error* without UTF mode, and that
    would stop analysisd). Any run of backslashes becomes ``(?:\\x{5c})+`` because Windows eventchannel values
    may carry single or doubled backslashes.
    """
    out: list[str] = []
    in_backslashes = False
    for char in value:
        if char == "\\":
            if not in_backslashes:
                out.append(_BACKSLASH_RUN)
                in_backslashes = True
            continue
        in_backslashes = False
        if char in _WORD:
            out.append(char)
        else:
            out.extend(f"\\x{{{byte:02x}}}" for byte in char.encode("utf-8", "surrogatepass"))
    return "".join(out)


def pcre2_exact(value: str) -> str:
    """Anchored exact-match PCRE2 pattern ``^...\\z`` for ``value`` (see :func:`pcre2_escape`).

    The end anchor is ``\\z``, not ``$``: analysisd compiles PCRE2 without options, where ``$`` also matches
    before a trailing newline, so ``^admin$`` would hide ``admin\\n`` as well."""
    return f"^{pcre2_escape(value)}{_END}"


_END = r"\z"  # end of subject only (PCRE2 "$" also matches before a final "\n")
# "(agent) ip->" as analysisd sees it (cleanevent.c strips "[id] "). The agent name stops at the first ")" and
# holds no ">"; the registered IP ("any" or an address) holds neither " " nor ">". So the "->" matched here is the
# first ">" of the location, exactly where the alert JSON cuts "location" (W_JSON_ParseLocation).
_AGENT_NAME_ANY = r"[^\x{29}\x{3e}]*"
_AFTER_AGENT = r"\x{29}\x{20}[^\x{20}\x{3e}]*\x{2d}\x{3e}"  # ") ip->"
_NOT_AGENT = r"(?!\x{28})"  # manager-side event: the location does not start with "(agent)"


def _location_pattern(agent: str | None, path: str | None, *, manager_only: bool = False) -> str:
    """Pattern over the INTERNAL location analysisd matches: ``(agent) ip->path`` for agent events, the bare
    path (or the sender) for events received by the manager itself. ``manager_only`` restricts it to the latter
    (needed with ``<hostname>``, which holds the agent name for agent events)."""
    if manager_only:
        assert agent is None
        return f"^{_NOT_AGENT}{pcre2_escape(path)}{_END}" if path is not None else f"^{_NOT_AGENT}"
    if agent is not None and path is not None:
        return rf"^\x{{28}}{pcre2_escape(agent)}{_AFTER_AGENT}{pcre2_escape(path)}{_END}"
    if agent is not None:
        return rf"^\x{{28}}{pcre2_escape(agent)}\x{{29}}\x{{20}}"
    assert path is not None
    return rf"^(?:\x{{28}}{_AGENT_NAME_ANY}{_AFTER_AGENT})?{pcre2_escape(path)}{_END}"


# ---- planning ------------------------------------------------------------------------------------------------------


@dataclass(slots=True)
class _Element:
    tag: str
    attrs: dict[str, str]
    text: str
    fields: tuple[str, ...]
    values: tuple[str, ...]
    manager_only: bool = False  # location element that also excludes agent events (see _location_pattern)


@dataclass(slots=True)
class _Plan:
    suggestion: Suggestion
    fingerprint: str
    parent: str
    expires: date
    elements: list[_Element]
    groups: tuple[str, ...]
    dependents: list[tuple[str, str, bool]]  # (rule id, link kind, still counts demoted events)
    review: bool
    parent_level: int | None
    parent_rule: WazuhRule | None
    samples: list[str] = field(default_factory=list)
    preempted: list[tuple[str, int]] = field(default_factory=list)  # (rule id, level) that stop firing
    parent_after: bool = False  # the parent loads after XML_FILE: analysisd would discard the rule
    options: tuple[str, ...] = ()  # parent output options copied to the child (COPIED_OPTIONS)
    mitre: tuple[str, ...] = ()  # parent MITRE technique ids copied to the child
    rule_id: int = 0
    description: str = ""
    comment: str = ""


class _Skip(Exception):
    def __init__(self, message: Message) -> None:
        super().__init__(message.key)
        self.message = message


def _label(value: object, limit: int = 80) -> str:
    """Safe short label for messages/markdown: only ``[A-Za-z0-9_ .:-]``, others become ``?``."""
    text = "".join(ch if ch in _LABEL_SAFE else "?" for ch in str(value)[:limit])
    return text + ("..." if len(str(value)) > limit else "")


def _as_date(value: object) -> date | None:
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    return None


def _fingerprint(suggestion: Suggestion, warnings: list[Message]) -> str:
    raw = suggestion.fingerprint
    if isinstance(raw, str) and len(raw) <= 64 and _FINGERPRINT.match(raw):
        return raw
    safe = "h" + stable_hash("hushwatch-fp", repr(raw), repr(suggestion.rule_id), length=19)
    warnings.append(M("wazuh.emit.warn.fingerprint", rule=_label(suggestion.rule_id), fingerprint=safe))
    return safe


def _exact_ip(value: str) -> str | None:
    if value != value.strip() or "%" in value or "/" in value:
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def _map_conditions(conditions: Sequence[Condition], fp: str, rule: str) -> list[_Element]:
    """Map conditions to Wazuh elements with the SAME semantics, or raise :class:`_Skip`."""
    values: dict[str, str] = {}
    for condition in conditions:
        name = getattr(condition, "field", None)
        value = getattr(condition, "value", None)
        if not isinstance(name, str) or not name:
            raise _Skip(M("wazuh.emit.skip.field", fingerprint=fp, rule=rule, field=_label(name)))
        if not isinstance(value, str) or value == "":
            raise _Skip(M("wazuh.emit.skip.value", fingerprint=fp, rule=rule, field=_label(name)))
        previous = values.get(name)
        if previous is not None and previous != value:
            raise _Skip(M("wazuh.emit.skip.conflict", fingerprint=fp, rule=rule, field=_label(name)))
        values[name] = value

    elements: list[_Element] = []
    agent = values.pop("agent.name", None)
    location = values.pop("location", None)
    hostname = values.pop("predecoder.hostname", None)
    # <hostname> is the syslog-header host only for events the manager receives itself; for agent events
    # analysisd replaces it with the agent name (cleanevent.c). So predecoder.hostname is expressed as <hostname>
    # PLUS "not an agent event" on <location>; with agent.name as well it cannot be expressed at all.
    if hostname is not None and agent is not None:
        raise _Skip(M("wazuh.emit.skip.host_pair", fingerprint=fp, rule=rule))
    manager_only = hostname is not None
    if agent is not None or location is not None or manager_only:
        fields = tuple(f for f, v in (("agent.name", agent), ("location", location)) if v is not None)
        kept = tuple(v for v in (agent, location) if v is not None)
        pattern = _location_pattern(agent, location, manager_only=manager_only)
        elements.append(_Element("location", {"type": "pcre2"}, pattern, fields, kept, manager_only))
    if hostname is not None:
        elements.append(
            _Element("hostname", {"type": "pcre2"}, pcre2_exact(hostname), ("predecoder.hostname",), (hostname,))
        )
    for source, tag in (("data.srcip", "srcip"), ("data.dstip", "dstip")):
        raw_ip = values.pop(source, None)
        if raw_ip is None:
            continue
        address = _exact_ip(raw_ip)
        if address is None:
            raise _Skip(M("wazuh.emit.skip.ip", fingerprint=fp, rule=rule, field=source))
        elements.append(_Element(tag, {}, address, (source,), (raw_ip,)))
    srcuser = values.pop("data.srcuser", None)
    dstuser = values.pop("data.dstuser", None)
    if srcuser is not None and dstuser is not None:
        raise _Skip(M("wazuh.emit.skip.users", fingerprint=fp, rule=rule))
    user_field, user = ("data.srcuser", srcuser) if srcuser is not None else ("data.dstuser", dstuser)
    if user is not None:
        elements.append(_Element("user", {"type": "pcre2"}, pcre2_exact(user), (user_field,), (user,)))
    for name in sorted(values):
        value = values[name]
        if not name.startswith("data.") or name.startswith(_REFUSED_PREFIXES):
            raise _Skip(M("wazuh.emit.skip.field", fingerprint=fp, rule=rule, field=_label(name)))
        wazuh_name = name[len("data.") :]
        if len(wazuh_name) > 128 or not _FIELD_NAME.match(wazuh_name):
            raise _Skip(M("wazuh.emit.skip.field_name", fingerprint=fp, rule=rule, field=_label(name)))
        if is_static_field(wazuh_name):
            raise _Skip(M("wazuh.emit.skip.static_field", fingerprint=fp, rule=rule, field=_label(name)))
        elements.append(_Element("field", {"name": wazuh_name, "type": "pcre2"}, pcre2_exact(value), (name,), (value,)))
    for element in elements:
        if len(element.text) > MAX_PATTERN_CHARS:
            raise _Skip(
                M(
                    "wazuh.emit.skip.too_long",
                    fingerprint=fp,
                    rule=rule,
                    field="/".join(element.fields),
                    length=len(element.text),
                )
            )
    return elements


def _desc_value(value: str) -> str:
    text = "".join(ch if ch in _DESC_SAFE else "?" for ch in value[: _MAX_DESC_VALUE + 1])
    return text[:_MAX_DESC_VALUE] + "..." if len(value) > _MAX_DESC_VALUE else text


def _description(plan: _Plan) -> str:
    scope_parts = [
        f"{_label(f)}={_desc_value(v)}"
        for element in plan.elements
        for f, v in zip(element.fields, element.values, strict=True)
    ]
    review = " REVIEW REQUIRED" if plan.review else ""
    scope = ", ".join(scope_parts) or "all events"
    text = _DESCRIPTION_FORMAT.format(
        parent=plan.parent, scope=scope, fingerprint=plan.fingerprint, expires=plan.expires.isoformat(), review=review
    )
    if len(text) > _MAX_DESCRIPTION:
        room = max(10, len(scope) - (len(text) - _MAX_DESCRIPTION) - 3)
        text = _DESCRIPTION_FORMAT.format(
            parent=plan.parent,
            scope=scope[:room] + "...",
            fingerprint=plan.fingerprint,
            expires=plan.expires.isoformat(),
            review=review,
        )
    return text


def _parent_groups(
    parent_rule: WazuhRule | None, suggestion: Suggestion, rule: str, warnings: list[Message]
) -> tuple[tuple[str, ...], bool]:
    """(groups to copy, complete). ``complete`` is False when the parent's groups are unknown or some had to be
    dropped (unsafe characters), because correlation by group could then lose the demoted events."""
    source: Sequence[object] = parent_rule.groups if parent_rule is not None else tuple(suggestion.rule_groups or ())
    kept: list[str] = []
    complete = bool(source)
    for group in source:
        if isinstance(group, str) and len(group) <= 64 and _GROUP_NAME.match(group):
            if group not in kept and group not in WRAPPER_GROUPS and group != TUNED_GROUP:
                kept.append(group)
        else:
            complete = False
            warnings.append(M("wazuh.emit.warn.group_dropped", group=_label(group, 64), rule=rule))
    return tuple(kept), complete


def _file_name(rule: WazuhRule) -> str:
    return PurePath(rule.file).name


def _priority(level: int) -> int:
    return (99 if level == 0 else level) * 100  # like evaluation_priority() for a rule without accuracy="0"


def _dependents(
    ruleset: Ruleset | None, suggestion: Suggestion, parent: str, child_groups: tuple[str, ...], level: int
) -> list[tuple[str, str, bool]]:
    """Correlation rules fed by ``parent`` and whether they still count the events our child takes over.

    From analysisd: an event is recorded under the rule it FINALLY matched (our child), so ``if_matched_sid``
    rules on the parent lose it. ``if_matched_group`` lists are wired when the correlation rule is LOADED, over
    the rules already loaded; our file (``XML_FILE``) loads after every stock file, so only a correlation rule in
    a file whose name sorts after it can see the child, whatever groups it copies. A frequency rule attached with
    ``if_sid`` counts every recent event (whatever rule it ended in, unless level 0) and is tried before our
    child when its priority is higher, so it keeps working."""
    found: list[tuple[str, str, bool]] = []
    seen: set[str] = set()
    group_string = "".join(f"{g}," for g in child_groups)
    if ruleset is not None:
        for dep_id, via in ruleset.dependents_detail(parent):
            kept = False
            dep = ruleset.get(dep_id)
            if level > 0 and dep is not None:
                if via == "if_matched_group":
                    kept = _file_name(dep) > XML_FILE and any(osmatch(p, group_string) for p in dep.if_matched_group)
                elif via == "frequency_if_sid":
                    priority = evaluation_priority(dep)
                    kept = priority > _priority(level) or (priority == _priority(level) and _file_name(dep) < XML_FILE)
            found.append((dep_id, via, kept))
            seen.add(dep_id)
    for dep_id in suggestion.dependents:
        text = str(dep_id)
        if text not in seen and _RULE_ID.match(text):
            found.append((text, "reported", False))
            seen.add(text)
    return found


def _preempted(ruleset: Ruleset | None, parent: str, level: int) -> list[tuple[str, int]]:
    """Rules that stop firing for the covered events because our child is tried BEFORE their branch.

    analysisd tries the parent's children in descending priority (equal priorities in load order) and follows
    the first that matches. Every sibling tried after our child, and everything below it, never sees the events
    our child takes; any of those rules with a level above ``level`` is an alert the backtest never counted."""
    if ruleset is None:
        return []
    own = _priority(level)
    hidden: dict[str, int] = {}
    for sibling_id in ruleset.children(parent):
        sibling = ruleset.get(sibling_id)
        if sibling is None:
            continue
        priority = evaluation_priority(sibling)
        if priority > own or (priority == own and _file_name(sibling) < XML_FILE):
            continue  # tried before our child: it still wins
        for rule_id in (sibling_id, *ruleset.descendants(sibling_id)):
            rule = ruleset.get(rule_id)
            if rule is not None and rule.level > level and rule_id != parent:
                hidden.setdefault(rule_id, rule.level)
    ordered = sorted(hidden.items(), key=lambda item: (-item[1], int(item[0]) if item[0].isdigit() else 0))
    return ordered[:_MAX_LISTED_PREEMPTED]


def _sample_ok(line: str) -> bool:
    if not line.strip() or len(line) > _MAX_SAMPLE_CHARS:
        return False
    for char in line:
        if char == "\t":
            continue
        if unicodedata.category(char) in ("Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"):
            return False
    return True


def _samples(examples: Sequence[Any]) -> list[str]:
    out: list[str] = []
    for example in examples:
        if not isinstance(example, Mapping):
            continue
        line = get_path(example, "full_log")
        if isinstance(line, str) and _sample_ok(line) and line not in out:
            out.append(line)
        if len(out) >= _MAX_SAMPLES_PER_RULE:
            break
    return out


def _example_warnings(plan: _Plan, warnings: list[Message]) -> None:
    examples = [e for e in (plan.suggestion.examples or ()) if isinstance(e, Mapping)]
    if not examples:
        return
    fields = {f for element in plan.elements for f in element.fields}
    agent_ids = {str(v) for v in (get_path(e, "agent.id") for e in examples) if v is not None}
    if "agent.name" in fields and "000" in agent_ids:
        warnings.append(M("wazuh.emit.warn.manager_agent", fingerprint=plan.fingerprint))
    if "predecoder.hostname" in fields and agent_ids - {"000"}:
        warnings.append(M("wazuh.emit.warn.hostname_agent", fingerprint=plan.fingerprint))
    if fields & {"data.srcuser", "data.dstuser"} and any(
        get_path(e, "data.srcuser") is not None and get_path(e, "data.dstuser") is not None for e in examples
    ):
        warnings.append(M("wazuh.emit.warn.user_semantics", fingerprint=plan.fingerprint))


def _plan(
    suggestion: Suggestion,
    *,
    ruleset: Ruleset | None,
    has_stock: bool,
    now: date,
    level: int,
    allow_rule_wide: bool,
    warnings: list[Message],
) -> _Plan:
    fp = _fingerprint(suggestion, warnings)
    raw_rule = suggestion.rule_id
    rule = _label(raw_rule, 32)
    if suggestion.verdict != "tune":
        raise _Skip(M("wazuh.emit.skip.verdict", fingerprint=fp, rule=rule, verdict=_label(suggestion.verdict, 32)))
    if suggestion.profile != "wazuh4":
        raise _Skip(M("wazuh.emit.skip.profile", fingerprint=fp, rule=rule, profile=_label(suggestion.profile, 32)))
    if not isinstance(raw_rule, str) or not _RULE_ID.match(raw_rule.strip()):
        raise _Skip(M("wazuh.emit.skip.rule_id", fingerprint=fp, rule=rule))
    parent = str(int(raw_rule.strip()))
    expires = _as_date(suggestion.expires)
    if expires is None or expires < now:
        raise _Skip(M("wazuh.emit.skip.expires", fingerprint=fp, rule=parent))
    if not suggestion.conditions and not allow_rule_wide:
        raise _Skip(M("wazuh.emit.skip.rule_wide", fingerprint=fp, rule=parent))
    elements = _map_conditions(suggestion.conditions, fp, parent)

    review = suggestion.review_required
    parent_rule = ruleset.get(parent) if ruleset is not None else None
    if ruleset is None:
        review = True
    elif parent_rule is None:
        if has_stock:
            raise _Skip(M("wazuh.emit.skip.parent_missing", fingerprint=fp, rule=parent))
        warnings.append(M("wazuh.emit.warn.parent_unverified", rule=parent))
        review = True
    elif not has_stock:
        review = True  # only local rules: the stock correlation rules on this parent were not verified
    parent_level = parent_rule.level if parent_rule is not None and parent_rule.level > 0 else suggestion.rule_level
    if isinstance(parent_level, int) and not isinstance(parent_level, bool):
        if level > parent_level:
            raise _Skip(
                M("wazuh.emit.skip.raises", fingerprint=fp, rule=parent, parent_level=parent_level, level=level)
            )
        if level == parent_level:  # a child that does not lower the level changes nothing: never written
            raise _Skip(
                M("wazuh.emit.skip.not_lower", fingerprint=fp, rule=parent, parent_level=parent_level, level=level)
            )
    else:
        parent_level = None

    groups, complete = _parent_groups(parent_rule, suggestion, parent, warnings)
    child_groups = (*WRAPPER_GROUPS, *groups, TUNED_GROUP)
    group_length = sum(len(g) + 1 for g in child_groups)
    if group_length > MAX_GROUP_STRING:
        raise _Skip(M("wazuh.emit.skip.groups_too_long", fingerprint=fp, rule=parent, length=group_length))
    if not complete:
        review = True
        if not groups:
            warnings.append(M("wazuh.emit.warn.groups_unknown", rule=parent))
    parent_after = parent_rule is not None and _file_name(parent_rule) >= XML_FILE
    if parent_after and parent_rule is not None:
        warnings.append(
            M(
                "wazuh.emit.warn.parent_after",
                rule=parent,
                file=Entity("file", _file_name(parent_rule)),
                output=XML_FILE,
            )
        )
        review = True
    dependents = _dependents(ruleset, suggestion, parent, child_groups, level)
    listed = {dep for dep, _, _ in dependents}
    preempted = [(rule_id, lvl) for rule_id, lvl in _preempted(ruleset, parent, level) if rule_id not in listed]
    if level == 0 and (dependents or preempted):
        affected = dict.fromkeys([*(d for d, _, _ in dependents), *(r for r, _ in preempted)])
        raise _Skip(M("wazuh.emit.skip.level_zero", fingerprint=fp, rule=parent, dependents=", ".join(affected)))
    review = review or bool(dependents) or bool(preempted)
    plan = _Plan(
        suggestion=suggestion,
        fingerprint=fp,
        parent=parent,
        expires=expires,
        elements=elements,
        groups=(*groups, TUNED_GROUP),
        dependents=dependents,
        review=review,
        parent_level=parent_level,
        parent_rule=parent_rule,
        samples=_samples(suggestion.examples or ()),
        preempted=preempted,
        parent_after=parent_after,
        options=tuple(o for o in COPIED_OPTIONS if parent_rule is not None and o in parent_rule.options),
        mitre=_mitre_ids(parent_rule.mitre if parent_rule is not None else suggestion.rule_mitre),
    )
    _example_warnings(plan, warnings)
    return plan


def _mitre_ids(values: Sequence[object]) -> tuple[str, ...]:
    """Valid ATT&CK technique ids (``T1110``, ``T1110.001``), deduplicated, at most 16."""
    out: list[str] = []
    for value in values or ():
        if isinstance(value, str) and _MITRE_ID.match(value) and value not in out:
            out.append(value)
    return tuple(out[:16])


# ---- XML building and verification ---------------------------------------------------------------------------------


def _build_xml(plans: Sequence[_Plan], level: int, created: date) -> str:
    header_lines = [
        render(M("wazuh.emit.header", version=__version__, created=created.isoformat()), lang) for lang in ("en", "es")
    ]
    root = ET.Element("group", {"name": "".join(f"{g}," for g in WRAPPER_GROUPS)})
    for plan in plans:
        root.append(ET.Comment(plan.comment))
        rule = ET.SubElement(root, "rule", {"id": str(plan.rule_id), "level": str(level)})
        ET.SubElement(rule, "if_sid").text = plan.parent
        for element in plan.elements:
            ET.SubElement(rule, element.tag, dict(element.attrs)).text = element.text
        ET.SubElement(rule, "description").text = plan.description
        if plan.mitre:
            mitre = ET.SubElement(rule, "mitre")
            for technique in plan.mitre:
                ET.SubElement(mitre, "id").text = technique
        for option in plan.options:
            ET.SubElement(rule, "options").text = option
        ET.SubElement(rule, "group").text = "".join(f"{g}," for g in plan.groups)
    ET.indent(root, space="  ")
    header = "\n".join(ET.tostring(ET.Comment(f" {line} "), encoding="unicode") for line in header_lines)
    return header + "\n" + ET.tostring(root, encoding="unicode") + "\n"


def _python_pattern(pattern: str) -> re.Pattern[bytes]:
    """Translate one of OUR patterns (ASCII + ``\\x{HH}`` escapes, ``\\z``) to an equivalent Python bytes regex
    (Python spells PCRE2's ``\\z`` as ``\\Z``)."""
    translated = _HEX_ESCAPE.sub(lambda m: b"\\x" + m.group(1), pattern.encode("ascii"))
    return re.compile(translated.replace(b"\\z", b"\\Z"))


def _self_test(element: _Element) -> str | None:
    """Return a problem description when a pattern does not match its own value or matches a neighbour."""
    if element.attrs.get("type") != "pcre2":
        return None
    try:
        compiled = _python_pattern(element.text)
    except (re.error, UnicodeEncodeError):
        return "pattern does not compile"
    if element.tag == "location":
        mapping = dict(zip(element.fields, element.values, strict=True))
        agent, path = mapping.get("agent.name"), mapping.get("location")
        tail = path if path is not None else "/var/log/syslog"
        if element.manager_only:
            positives = [tail]
            negatives = [f"(agent-x) any->{tail}", f"({tail}) any->{tail}"]
        elif agent is not None:
            positives = [f"({agent}) any->{tail}"]
            negatives = [f"({agent}x) any->{tail}", f"(x{agent}) any->{tail}", f"{agent}->{tail}"]
        else:
            positives = [tail, f"(agent-x) any->{tail}"]
            negatives = [f"(a>b) any->{tail}"]
        if path is not None:
            negatives += [p + suffix for p in positives for suffix in ("x", "\n", "\r\n")]
            negatives += [p.replace("->", "->x", 1) for p in positives if "->" in p] + ["x" + tail]
    else:
        value = element.values[0]
        positives = [value]
        negatives = [value + "x", "x" + value, value[:-1], value + "\n", "\n" + value, value.swapcase()]
    for subject in positives:
        if not compiled.search(subject.encode("utf-8", "surrogatepass")):
            return "pattern does not match its own value"
    accepted = {_collapse_backslashes(p) for p in positives}
    for subject in negatives:
        if _collapse_backslashes(subject) in accepted:  # same value up to backslash doubling: meant to match
            continue
        if compiled.search(subject.encode("utf-8", "surrogatepass")):
            return "pattern matches more than its value"
    return None


def _collapse_backslashes(text: str) -> str:
    return re.sub(r"\\+", r"\\", text)


def _verify(xml_text: str, plans: Sequence[_Plan], level: int, used: set[int]) -> None:
    """Refuse (EmitError) unless the XML is exactly what was planned and safe for Wazuh's parser."""

    def fail(detail: str) -> EmitError:
        return EmitError(M("wazuh.emit.err.verify", detail=detail))

    ids = [plan.rule_id for plan in plans]
    if len(set(ids)) != len(ids):
        raise EmitError(M("wazuh.emit.err.collision", rule=next(i for i in ids if ids.count(i) > 1)))
    for rule_id in ids:
        if rule_id in used:
            raise EmitError(M("wazuh.emit.err.collision", rule=rule_id))
    for body in _XML_COMMENT.findall(xml_text):
        if "--" in body or body.endswith("-") or "!>" in body:  # os_xml also ends a comment at "!>"
            raise fail("comment")
    outside = _XML_COMMENT.sub("", xml_text)
    if any(ord(ch) > 126 or (ord(ch) < 32 and ch != "\n") for ch in outside):
        raise fail("non-ASCII or control character outside comments")
    if "&" in outside or "<!" in outside:  # os_xml decodes no entity and reads any "<!" as a comment
        raise fail("entity, CDATA or declaration")
    if "$" in outside:  # os_xml substitutes $VARIABLES; our patterns end with \z, never "$"
        raise fail("'$' in the rules")
    if "\\<" in outside:  # os_xml: a backslash before "<" makes it content, so the closing tag is lost
        raise fail("backslash before '<'")
    try:
        tree = ET.fromstring(f"<verify>{xml_text}</verify>")  # noqa: S314 - our own output, no DTD possible
    except ET.ParseError as exc:
        raise fail(f"XML: {exc}") from None
    groups = tree.findall("group")
    if len(groups) != 1 or len(tree) != 1 or len(groups[0].findall("rule")) != len(plans):
        raise fail("unexpected structure")
    parsed = parse_rules_text(xml_text, file=XML_FILE, is_local=True)
    if parsed.errors or parsed.notes or parsed.duplicates or len(parsed.all_rules) != len(plans):
        raise fail("Wazuh-aware re-parse")
    for plan, rule in zip(plans, parsed.all_rules, strict=True):
        expected_conditions = [(e.tag, dict(e.attrs), e.text) for e in plan.elements]
        actual_conditions = [(c.tag, dict(c.attrs), c.text) for c in rule.conditions]
        if (
            rule.id != str(plan.rule_id)
            or rule.level != level
            or rule.if_sid != [plan.parent]
            or rule.if_group
            or rule.if_matched_sid
            or rule.if_matched_group
            or rule.options != plan.options
            or rule.mitre != plan.mitre
            or rule.overwrite
            or actual_conditions != expected_conditions
            or rule.groups != (*WRAPPER_GROUPS, *plan.groups)
            or rule.description != plan.description
            or not rule.valid
        ):
            raise fail(f"rule {plan.rule_id} differs from plan")
        for element in plan.elements:
            problem = _self_test(element)
            if problem is not None:
                raise fail(f"rule {plan.rule_id}: {problem}")


# ---- other outputs -------------------------------------------------------------------------------------------------


def _text_or_none(value: object) -> str | None:
    return None if value is None else str(value)


def _finite(value: object) -> float | int | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if isinstance(value, float) and not math.isfinite(value):
        return None
    return value


def _spec(
    plans: Sequence[_Plan],
    skipped: Sequence[tuple[str, str, Message]],
    warnings: Sequence[Message],
    *,
    level: int,
    created: date,
    id_range: tuple[int, int],
    volume: Sequence[Suggestion] = (),
) -> str:
    suppressions: list[dict[str, Any]] = []
    for plan in plans:
        s = plan.suggestion
        parent = plan.parent_rule
        suppressions.append(
            {
                "id": plan.rule_id,
                "parent_rule": plan.parent,
                "action": "demote" if level > 0 else "drop",
                "level": level,
                "fingerprint": plan.fingerprint,
                "verdict": s.verdict,
                "created": created.isoformat(),
                "expires": plan.expires.isoformat(),
                "review_required": plan.review,
                "conditions": [{"field": c.field, "value": c.value} for c in s.conditions],
                "wazuh": [{"tag": e.tag, "attributes": dict(e.attrs), "value": e.text} for e in plan.elements],
                "backtest": {
                    "hidden_total": _finite(s.hidden_total),
                    "hidden_per_day": _finite(s.hidden_per_day),
                    "hidden_analyst_facing": _finite(s.hidden_analyst_facing),
                    "share_of_rule": _finite(s.share_of_rule),
                },
                "dependents": [
                    {"rule": dep, "via": via, "correlation_preserved": kept} for dep, via, kept in plan.dependents
                ],
                "preempted_rules": [{"rule": rule_id, "level": lvl} for rule_id, lvl in plan.preempted],
                "parent_loads_after_this_file": plan.parent_after,
                "options": list(plan.options),
                "mitre": list(plan.mitre),
                "parent": {
                    "level": plan.parent_level,
                    "description": parent.description if parent is not None else _text_or_none(s.rule_description),
                    "groups": list(parent.groups) if parent is not None else [str(g) for g in s.rule_groups],
                    "mitre": list(parent.mitre) if parent is not None else [str(m) for m in s.rule_mitre],
                    "file": parent.file if parent is not None else None,
                },
                "reasons": [render(r, "en") for r in s.reasons],
                "logtest_samples": len(plan.samples),
            }
        )
    document = {
        "schema_version": SPEC_SCHEMA_VERSION,
        "generator": f"hushwatch {__version__}",
        "created": created.isoformat(),
        "profile": "wazuh4",
        "id_range": list(id_range),
        "level": level,
        "notice": {lang: render(M("wazuh.emit.notice"), lang) for lang in ("en", "es")},
        "suppressions": suppressions,
        "skipped": [
            {"rule": rule, "fingerprint": fp, "reason": {lang: render(msg, lang) for lang in ("en", "es")}}
            for rule, fp, msg in skipped
        ],
        "warnings": [{lang: render(w, lang) for lang in ("en", "es")} for w in warnings],
        "index_volume": [
            {
                "rule": _label(s.rule_id, 32),
                "fingerprint": _label(s.fingerprint, 64),
                "conditions": [{"field": c.field, "value": c.value} for c in s.conditions],
                "level": _finite(s.rule_level),
                "hidden_per_day": _finite(s.hidden_per_day),
                "rule_written": False,
            }
            for s in volume
        ],
    }
    return json.dumps(document, indent=2, ensure_ascii=True, allow_nan=False) + "\n"


def _validation(
    plans: Sequence[_Plan],
    sample_ranges: Sequence[tuple[int, int] | None],
    warnings: Sequence[Message],
    *,
    level: int,
    created: date,
    skipped: Sequence[tuple[str, str, Message]] = (),
    volume: Sequence[Suggestion] = (),
) -> str:
    stamp = created.strftime("%Y%m%d")
    commands = {
        "backup": f"tar -czpf /root/wazuh-etc-rules-{stamp}.tgz -C /var/ossec/etc rules",
        "copy": f"install -m 0640 -o wazuh -g wazuh {XML_FILE} /var/ossec/etc/rules/{XML_FILE}",
        "check": "/var/ossec/bin/wazuh-analysisd -t",
        "logtest": '/var/ossec/bin/wazuh-logtest -l "[001] (AGENT_NAME) any->/var/log/auth.log"',
        "restart": "systemctl restart wazuh-manager && systemctl --no-pager status wazuh-manager",
        "rollback": f"rm /var/ossec/etc/rules/{XML_FILE} && systemctl restart wazuh-manager",
    }
    title = " / ".join(render(M("wazuh.validation.title"), lang) for lang in ("en", "es"))
    lines: list[str] = [f"# {title}", ""]
    for lang, heading in (("en", "English"), ("es", "Español")):

        def t(key: str, _lang: str = lang, **params: Any) -> str:
            return render(M(key, **params), _lang)

        lines += [f"## {heading}", "", t("wazuh.validation.intro", created=created.isoformat()), ""]
        lines += [t("wazuh.validation.expiry"), ""]
        steps = [
            (t("wazuh.validation.step_backup"), commands["backup"]),
            (t("wazuh.validation.step_copy"), commands["copy"]),
            (t("wazuh.validation.step_check"), commands["check"]),
            (t("wazuh.validation.step_logtest", samples=SAMPLES_FILE, level=level), commands["logtest"]),
            (t("wazuh.validation.step_restart"), commands["restart"]),
            (t("wazuh.validation.step_watch", level=level, group=TUNED_GROUP), None),
            (t("wazuh.validation.step_rollback"), commands["rollback"]),
        ]
        for number, (text, command) in enumerate(steps, start=1):
            lines.append(f"{number}. {text}")
            if command is not None:
                lines += ["", "   ```sh", f"   {command}", "   ```"]
            lines.append("")
        lines += [f"### {t('wazuh.validation.rules_heading')}", ""]
        for plan, sample_range in zip(plans, sample_ranges, strict=True):
            if sample_range is None:
                samples = t("wazuh.validation.no_samples")
            elif sample_range[0] == sample_range[1]:
                samples = t("wazuh.validation.samples_line", line=sample_range[0])
            else:
                samples = t("wazuh.validation.samples_lines", first=sample_range[0], last=sample_range[1])
            fields = ", ".join(_label(f) for e in plan.elements for f in e.fields) or "-"
            lines.append(
                "- "
                + t(
                    "wazuh.validation.rule_line",
                    rule=str(plan.rule_id),
                    parent=plan.parent,
                    level=level,
                    fields=fields,
                    fingerprint=plan.fingerprint,
                    expires=plan.expires.isoformat(),
                    samples=samples,
                )
            )
            if plan.review:
                lines.append(f"  - **{t('wazuh.validation.review')}**")
            if plan.parent_after:
                lines.append(f"  - {t('wazuh.validation.parent_after', output=XML_FILE)}")
            for dep, via, kept in plan.dependents:
                key = "wazuh.validation.dependent_kept" if kept else "wazuh.validation.dependent_broken"
                lines.append(f"  - {t(key, rule=_label(dep, 12), via=via)}")
            for rule_id, rule_level in plan.preempted:
                lines.append(f"  - {t('wazuh.validation.preempted', rule=_label(rule_id, 12), level=rule_level)}")
        lines.append("")
        if volume:
            lines += [f"### {t('wazuh.validation.volume_heading')}", ""]
            lines += [_md_safe(t("wazuh.validation.volume_intro", level=level)), ""]
            for s in volume:
                fields = ", ".join(_label(c.field) for c in s.conditions) or "-"
                per_day = _finite(s.hidden_per_day)
                lines.append(
                    "- "
                    + t(
                        "wazuh.validation.volume_line",
                        parent=_label(s.rule_id, 32),
                        fields=fields,
                        fingerprint=_label(s.fingerprint, 64),
                        per_day=float(per_day) if per_day is not None else 0.0,
                        level=_label(s.rule_level if s.rule_level is not None else "?", 8),
                    )
                )
            lines.append("")
        if skipped:
            lines += [f"### {t('wazuh.validation.skipped_heading')}", ""]
            lines += [f"- {_md_safe(render(message, lang))}" for _rule, _fp, message in skipped]
            lines.append("")
        if warnings:
            lines += [f"### {t('wazuh.validation.warnings_heading')}", ""]
            lines += [f"- {_md_safe(render(w, lang))}" for w in warnings]
            lines.append("")
    return "\n".join(lines).rstrip("\n") + "\n"


_MD_ESCAPES = {"&": "&amp;", "<": "&lt;", ">": "&gt;", "`": "'", "[": "\\[", "]": "\\]", "*": "\\*", "|": "\\|"}


def _md_safe(text: str) -> str:
    """Neutralize markdown/HTML in rendered warning text (message params are already restricted labels, but
    paths are rendered as given)."""
    return "".join(
        "?" if unicodedata.category(ch).startswith("C") else _MD_ESCAPES.get(ch, ch) for ch in text.replace("\n", " ")
    )


# ---- writing -------------------------------------------------------------------------------------------------------


def _prepare_dir(out_dir: Path, targets: Sequence[Path], overwrite: bool, warnings: list[Message]) -> None:
    if out_dir.exists() and not out_dir.is_dir():
        raise EmitError(M("wazuh.emit.err.out_dir", path=Entity("file", str(out_dir))))
    if not overwrite:
        for target in targets:
            if target.exists() or target.is_symlink():
                raise EmitError(M("wazuh.emit.err.exists", path=Entity("file", str(target))))
    if not out_dir.exists():
        out_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(out_dir, 0o700)
    if os.name == "posix":
        # Whoever can write to the directory (or owns it) can swap the rules between now and the deployment;
        # that is an attacker-authored local_rules.xml. Refuse; only warn when others can merely look.
        info = out_dir.stat()
        if info.st_uid != _euid() or info.st_mode & 0o022:
            raise EmitError(M("wazuh.emit.err.out_dir_unsafe", path=Entity("file", str(out_dir))))
        if info.st_mode & 0o077:
            warnings.append(M("wazuh.emit.warn.dir_mode", path=Entity("file", str(out_dir))))


def _write_all(contents: Sequence[tuple[Path, str]], overwrite: bool) -> None:
    created: list[Path] = []
    try:
        for path, text in contents:
            data = text.encode("utf-8")
            if overwrite:
                fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=".hushwatch-", suffix=".tmp")
                try:
                    with os.fdopen(fd, "wb") as handle:
                        handle.write(data)
                        handle.flush()
                        os.fsync(handle.fileno())
                    os.chmod(tmp_name, 0o600)
                    os.replace(tmp_name, path)
                except BaseException:
                    Path(tmp_name).unlink(missing_ok=True)
                    raise
            else:
                flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
                try:
                    fd = os.open(path, flags, 0o600)
                except FileExistsError:
                    raise EmitError(M("wazuh.emit.err.exists", path=Entity("file", str(path)))) from None
                created.append(path)
                with os.fdopen(fd, "wb") as handle:
                    if hasattr(os, "fchmod"):
                        os.fchmod(handle.fileno(), 0o600)
                    handle.write(data)
                    handle.flush()
                    os.fsync(handle.fileno())
    except BaseException:
        for path in created:
            path.unlink(missing_ok=True)
        raise


# ---- entry point ---------------------------------------------------------------------------------------------------


def emit_suppressions(
    suggestions: Sequence[Suggestion],
    *,
    ruleset: Ruleset | None,
    id_range: tuple[int, int],
    out_dir: Path,
    now: date,
    level: int = 3,
    profile: str = "wazuh4",
    overwrite: bool = False,
    allow_level_zero: bool = False,
    allow_rule_wide: bool = False,
) -> EmitResult:
    """Write review-ready Wazuh 4.x suppression rules for ``suggestions`` into ``out_dir``.

    Only suggestions with verdict ``tune`` and profile ``wazuh4`` whose every condition maps exactly to a Wazuh
    element, and whose parent is above ``level``, are emitted; the others are listed in
    :attr:`EmitResult.skipped` with the reason (never in ``warnings``). Each becomes a child of its rule
    (``if_sid``) at ``level`` (DEMOTE: still indexed and measurable), copying the parent's groups, MITRE ids and
    output options plus ``hushwatch_tuned``. Index-volume-only suggestions (verdict ``watch``, impact
    ``index_volume``) are never written as rules: VALIDATION.md explains the real volume options and their
    trade-offs. Level 0 (DROP) requires ``allow_level_zero`` and is refused for rules that feed correlation;
    condition-less (whole-rule) suggestions require ``allow_rule_wide``.

    Raises :class:`EmitError` for profile ``wazuh5`` (or any non-4.x profile), an invalid level or id range, an
    exhausted range, an id collision, output that fails the re-parse/self-test, or existing files without
    ``overwrite``. Nothing is written on error, and nothing is written when no suggestion could be emitted.
    """
    suggestions = list(suggestions)  # may be a one-shot iterable; it is walked more than once
    if profile != "wazuh4" or any(getattr(s, "profile", None) == "wazuh5" for s in suggestions):
        shown = "wazuh5" if profile == "wazuh4" else profile
        raise EmitError(M("wazuh.emit.err.profile", profile=_label(shown, 32)))
    if isinstance(level, bool) or not isinstance(level, int) or not 0 <= level <= 16:
        raise EmitError(M("wazuh.emit.err.level", level=_label(level, 16)))
    if level == 0 and not allow_level_zero:
        raise EmitError(M("wazuh.emit.err.level", level=0))
    low, high = id_range
    if any(isinstance(v, bool) or not isinstance(v, int) for v in (low, high)) or not 1 <= low <= high <= 999_999:
        raise EmitError(M("wazuh.emit.err.range", low=_label(low, 12), high=_label(high, 12)))
    today = _as_date(now) or date.today()
    out_dir = Path(out_dir).expanduser()

    warnings: list[Message] = []
    result = EmitResult()
    if low < 100_000 or high > 120_000:
        warnings.append(M("wazuh.emit.warn.range", low=low, high=high))
    if level == 0:
        warnings.append(M("wazuh.emit.warn.level_zero"))
    has_stock = ruleset is not None and ruleset.has_stock
    if ruleset is None:
        warnings.append(M("wazuh.emit.warn.no_ruleset"))
    else:
        if ruleset.errors:
            warnings.append(M("wazuh.emit.warn.ruleset_errors", count=len(ruleset.errors)))
        if not has_stock:
            warnings.append(M("wazuh.emit.warn.no_stock"))

    plans: list[_Plan] = []
    skipped: list[tuple[str, str, Message]] = []
    volume: list[Suggestion] = []
    seen_scopes: dict[tuple[str, frozenset[tuple[str, str]]], str] = {}
    for suggestion in suggestions:
        if getattr(suggestion, "verdict", None) == "watch" and getattr(suggestion, "impact", "") == "index_volume":
            volume.append(suggestion)  # explained in VALIDATION.md, never written as a rule
            continue
        try:
            plan = _plan(
                suggestion,
                ruleset=ruleset,
                has_stock=has_stock,
                now=today,
                level=level,
                allow_rule_wide=allow_rule_wide,
                warnings=warnings,
            )
            scope = (plan.parent, frozenset((c.field, c.value) for c in suggestion.conditions))
            other = seen_scopes.get(scope)
            if other is not None:
                raise _Skip(M("wazuh.emit.skip.duplicate", fingerprint=plan.fingerprint, rule=plan.parent, other=other))
            seen_scopes[scope] = plan.fingerprint
        except _Skip as skip:
            fp = _label(getattr(suggestion, "fingerprint", ""), 64)
            skipped.append((_label(getattr(suggestion, "rule_id", ""), 32), fp, skip.message))
            result.skipped.append((fp, skip.message))  # skipped, not a warning: never counted twice
            continue
        plans.append(plan)
    result.index_volume = [_label(s.fingerprint, 64) for s in volume]

    if not plans:
        warnings.append(M("wazuh.emit.warn.nothing"))
        result.warnings = warnings
        return result

    used = ruleset.used_ids if ruleset is not None else set()
    taken = set(used)
    candidate = low
    for plan in plans:
        while candidate <= high and candidate in taken:
            candidate += 1
        if candidate > high:
            raise EmitError(M("wazuh.emit.err.exhausted", low=low, high=high, count=len(plans)))
        plan.rule_id = candidate
        taken.add(candidate)
        candidate += 1
        plan.description = _description(plan)
        plan.comment = _COMMENT_FORMAT.format(
            fingerprint=plan.fingerprint,
            created=today.isoformat(),
            expires=plan.expires.isoformat(),
            review="yes" if plan.review else "no",
        )

    xml_text = _build_xml(plans, level, today)
    _verify(xml_text, plans, level, used)

    sample_lines: list[str] = []
    sample_ranges: list[tuple[int, int] | None] = []
    for plan in plans:
        if plan.samples:
            first = len(sample_lines) + 1
            sample_lines.extend(plan.samples)
            sample_ranges.append((first, len(sample_lines)))
        else:
            sample_ranges.append(None)

    targets = [out_dir / name for name in (XML_FILE, SPEC_FILE, VALIDATION_FILE, SAMPLES_FILE)]
    _prepare_dir(out_dir, targets, overwrite, warnings)
    contents = [
        (targets[0], xml_text),
        (targets[1], _spec(plans, skipped, warnings, level=level, created=today, id_range=(low, high), volume=volume)),
        (
            targets[2],
            _validation(plans, sample_ranges, warnings, level=level, created=today, skipped=skipped, volume=volume),
        ),
        (targets[3], "".join(f"{line}\n" for line in sample_lines)),
    ]
    _write_all(contents, overwrite)
    result.paths = list(targets)
    result.rules = [(plan.rule_id, plan.fingerprint) for plan in plans]
    result.review_required = [plan.rule_id for plan in plans if plan.review]
    result.warnings = warnings
    return result


def _euid() -> int:
    """Effective uid on POSIX; -1 elsewhere (os.geteuid does not exist on Windows)."""
    geteuid = getattr(os, "geteuid", None)
    return int(geteuid()) if geteuid is not None else -1
