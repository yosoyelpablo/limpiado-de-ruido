"""Cron-mode state: finding lifecycle, hysteresis, flapping, reminders, the accept file and run heartbeats.

A monitoring tool that pages on every blip is muted within two weeks. :class:`StateStore` remembers what each
run found so that notifications go out only when something *changes*:

* **Lifecycle** ``new → open → resolved → regressed``. A finding opens after ``open_after`` consecutive runs
  that report it (hysteresis), except critical findings and the ``immediate_kinds`` (silence, tampering,
  global pipeline silence, incomplete assessment), which open on the first run. It resolves after
  ``resolve_after`` consecutive runs without it. A resolved finding that comes back is *regressed*.
* **Flapping**: ``flap_threshold`` lifecycle changes within ``flap_window`` flag the finding as flapping. One
  notification is sent; further changes are grouped until the finding has been stable for a whole window.
* **Reminders** for open critical findings every ``remind_every``.
* **Escalation**: an open finding that was already notified and becomes more severe (``low`` → ``critical``)
  is notified again (``escalated``), so a target filtering by minimum severity never misses it.
* **Accept / snooze file** (``hushwatch-accept.yml``): entries by fingerprint or by kind + subject glob, each
  with an owner, a reason and a MANDATORY expiry (at most 365 days ahead). Accepted findings are tracked but
  not notified; when an acceptance expires the owner is told once (``acceptance_expired``).
* **Delivery**: notifications that could not be delivered can be handed back with
  :meth:`StateStore.mark_undelivered` so the next run sends them again (at-least-once).

Privacy: the database stores fingerprints, kinds, a keyed hash of the subject, severities, timestamps,
counters and a *placeholder* summary of the title (entity values and free-text parameters replaced by
``[kind]`` markers). It never stores raw subjects, entity values or evidence.

The store is a single SQLite file in WAL mode (file 0600, directories created 0700; shared directories and
symlinks are refused). Every run is one ``BEGIN IMMEDIATE`` transaction with a busy timeout, so concurrent runs
on the same file serialize safely.

Integration note (never a false green): pass ``assessed`` to :meth:`StateStore.record_run` (the domains the
report did NOT mark ``not_assessed``). With the default, every domain counts as assessed unless the run reported
``assessment.incomplete``, so a run that only analysed noise would slowly resolve open silence findings.
"""

from __future__ import annotations

import contextlib
import difflib
import fnmatch
import hashlib
import hmac
import json
import logging
import math
import os
import re
import secrets
import sqlite3
import stat
import threading
import time
from collections.abc import Collection, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Any

import yaml

from .config import ConfigError
from .i18n import Entity, M, Message, register, render
from .models import DOMAINS, Finding, Severity, stable_hash
from .redact import Redactor
from .timeutil import UTC, iso, parse_ts

log = logging.getLogger("hushwatch.state")

STATE_FILENAME = "state.sqlite3"
ACCEPT_FILENAME = "hushwatch-accept.yml"
STATE_SCHEMA_VERSION = 2
ACCEPT_MAX_DAYS = 365
ACCEPT_MAX_BYTES = 1_000_000

DEFAULT_IMMEDIATE_KINDS: tuple[str, ...] = (
    "silence.tampering",
    "silence.silent",
    "pipeline.global_silence",
    "assessment.incomplete",
)

# Finding status stored per fingerprint.
NEW, OPEN, RESOLVED, REGRESSED = "new", "open", "resolved", "regressed"
STATUSES: tuple[str, ...] = (NEW, OPEN, RESOLVED, REGRESSED)
ACTIVE_STATUSES: frozenset[str] = frozenset({OPEN, REGRESSED})

# Transition (notification) types, in digest order.
OPENED, REGRESSED_T, RESOLVED_T = "opened", "regressed", "resolved"
REMINDER, FLAPPING, ACCEPTANCE_EXPIRED = "reminder", "flapping", "acceptance_expired"
ESCALATED = "escalated"  # an open finding already notified got MORE severe (e.g. low -> critical)
TRANSITION_TYPES: tuple[str, ...] = (
    OPENED,
    REGRESSED_T,
    ESCALATED,
    ACCEPTANCE_EXPIRED,
    FLAPPING,
    REMINDER,
    RESOLVED_T,
)
_TYPE_ORDER = {t: i for i, t in enumerate(TRANSITION_TYPES)}

_PHASE_ACTIVE, _PHASE_RESOLVED = "active", "resolved"
_LIFECYCLE_EVENTS = (OPENED, REGRESSED_T, RESOLVED_T)

register(
    {
        "state.accept.invalid": {
            "en": "Invalid accept file {path}:",
            "es": "Archivo de aceptaciones {path} no válido:",
        },
        "state.accept.unreadable": {
            "en": "Cannot read the accept file {path}: {error}",
            "es": "No se puede leer el archivo de aceptaciones {path}: {error}",
        },
        "state.accept.missing_file": {
            "en": "The accept file {path} does not exist",
            "es": "El archivo de aceptaciones {path} no existe",
        },
        "state.accept.insecure": {
            "en": "The accept file {path} can be modified by any local user, who could silence findings with it; "
            "make it writable only by its owner (chmod 644 or 600)",
            "es": "Cualquier usuario local puede modificar el archivo de aceptaciones {path} y silenciar hallazgos "
            "con él; haga que solo su propietario pueda escribirlo (chmod 644 o 600)",
        },
        "state.accept.too_large": {
            "en": "the file is larger than {limit} bytes",
            "es": "el archivo supera los {limit} bytes",
        },
        "state.accept.yaml": {
            "en": "not valid YAML ({error})",
            "es": "no es YAML válido ({error})",
        },
        "state.accept.top_level": {
            "en": "the top level must be a list of entries or a mapping with an 'accept' list",
            "es": "el nivel superior debe ser una lista de entradas o un mapa con una lista 'accept'",
        },
        "state.accept.unknown_top": {
            "en": "unknown top-level keys: {keys} (expected: version, accept)",
            "es": "claves de nivel superior desconocidas: {keys} (se esperaba: version, accept)",
        },
        "state.accept.version": {
            "en": "unsupported version {version} (this hushwatch reads version 1)",
            "es": "versión {version} no soportada (esta versión de hushwatch lee la versión 1)",
        },
        "state.accept.not_mapping": {
            "en": "entry {n}: must be a mapping of keys (fingerprint or kind + subject, owner, reason, expires)",
            "es": "entrada {n}: debe ser un mapa de claves (fingerprint o kind + subject, owner, reason, expires)",
        },
        "state.accept.unknown_key": {
            "en": "entry {n}: unknown key '{key}'",
            "es": "entrada {n}: clave desconocida '{key}'",
        },
        "state.accept.unknown_key_hint": {
            "en": "entry {n}: unknown key '{key}' (did you mean '{hint}'?)",
            "es": "entrada {n}: clave desconocida '{key}' (¿quiso decir '{hint}'?)",
        },
        "state.accept.required": {
            "en": "entry {n}: '{key}' is required",
            "es": "entrada {n}: '{key}' es obligatorio",
        },
        "state.accept.bad_text": {
            "en": "entry {n}: '{key}' must be non-empty text of at most {max} characters",
            "es": "entrada {n}: '{key}' debe ser un texto no vacío de {max} caracteres como máximo",
        },
        "state.accept.selector_missing": {
            "en": "entry {n}: say what is accepted with 'fingerprint', or with 'kind' and 'subject' together",
            "es": "entrada {n}: indique qué se acepta con 'fingerprint', o con 'kind' y 'subject' juntos",
        },
        "state.accept.selector_both": {
            "en": "entry {n}: use either 'fingerprint' or 'kind' + 'subject', not both",
            "es": "entrada {n}: use 'fingerprint' o 'kind' + 'subject', pero no ambos",
        },
        "state.accept.bad_fingerprint": {
            "en": "entry {n}: 'fingerprint' must be a hushwatch fingerprint (hexadecimal, as shown in reports)",
            "es": "entrada {n}: 'fingerprint' debe ser una huella de hushwatch (hexadecimal, como en los informes)",
        },
        "state.accept.bad_kind": {
            "en": "entry {n}: '{kind}' is not a finding kind (expected e.g. silence.silent or noise.tune)",
            "es": "entrada {n}: '{kind}' no es un tipo de hallazgo (se esperaba p. ej. silence.silent o noise.tune)",
        },
        "state.accept.expires_missing": {
            "en": "entry {n}: 'expires' is mandatory (YYYY-MM-DD, at most {max_days} days ahead): "
            "every acceptance must expire and be reviewed again",
            "es": "entrada {n}: 'expires' es obligatorio (AAAA-MM-DD, como máximo {max_days} días en el futuro): "
            "toda aceptación debe caducar y volver a revisarse",
        },
        "state.accept.expires_invalid": {
            "en": "entry {n}: 'expires' must be a date (YYYY-MM-DD) or an ISO-8601 timestamp",
            "es": "entrada {n}: 'expires' debe ser una fecha (AAAA-MM-DD) o una marca de tiempo ISO-8601",
        },
        "state.accept.expires_too_far": {
            "en": "entry {n}: 'expires' ({expires}) is more than {max_days} days ahead; "
            "acceptances must be reviewed at least once a year",
            "es": "entrada {n}: 'expires' ({expires}) está a más de {max_days} días; "
            "las aceptaciones deben revisarse al menos una vez al año",
        },
        "state.accept.expired_detail": {
            "en": "acceptance by {owner} expired on {expires}; this finding is reported again",
            "es": "la aceptación de {owner} caducó el {expires}; este hallazgo vuelve a notificarse",
        },
        "state.accept.expired_unmatched": {
            "en": "Accept entry #{index} (owner {owner}) expired on {expires} and matches no current finding: "
            "review it or remove it from the accept file",
            "es": "La entrada de aceptación n.º {index} (responsable {owner}) caducó el {expires} y no coincide "
            "con ningún hallazgo actual: revísela o elimínela del archivo de aceptaciones",
        },
        "state.flapping.detail": {
            "en": "keeps opening and resolving ({count} changes in {hours} h); further changes are grouped "
            "until it is stable",
            "es": "se abre y se resuelve repetidamente ({count} cambios en {hours} h); los siguientes cambios "
            "se agrupan hasta que se estabilice",
        },
        "state.error.open": {
            "en": "Cannot open the state database {path}: {error}",
            "es": "No se puede abrir la base de datos de estado {path}: {error}",
        },
        "state.error.newer": {
            "en": "The state database {path} has schema version {found}, newer than this hushwatch supports "
            "({supported}); upgrade hushwatch or use another state directory",
            "es": "La base de datos de estado {path} tiene la versión de esquema {found}, más nueva de lo que "
            "admite esta versión de hushwatch ({supported}); actualice hushwatch o use otro directorio de estado",
        },
        "state.error.db": {
            "en": "State database error in {path}: {error}",
            "es": "Error en la base de datos de estado {path}: {error}",
        },
        "state.error.shared_dir": {
            "en": "The state directory {path} can be written by other users, who could plant links there and "
            "hijack or read the state database; use a private directory (chmod 700)",
            "es": "Otros usuarios pueden escribir en el directorio de estado {path} y podrían colocar enlaces para "
            "suplantar o leer la base de datos de estado; use un directorio privado (chmod 700)",
        },
        "state.error.foreign_dir": {
            "en": "The state directory {path} belongs to another user; use a directory you own",
            "es": "El directorio de estado {path} pertenece a otro usuario; use un directorio propio",
        },
        "state.error.not_regular": {
            "en": "Refusing to use {path} as state: it is a symbolic link or not a regular file",
            "es": "No se usa {path} como estado: es un enlace simbólico o no es un archivo normal",
        },
    }
)


# ---- errors --------------------------------------------------------------------------------------------------


class StateError(RuntimeError):
    """The state database cannot be opened, is from a newer version, or failed mid-operation."""

    def __init__(self, message: Message) -> None:
        self.message = message
        super().__init__(render(message, "en"))

    def render(self, lang: str = "en") -> str:
        """The error in ``lang``."""
        return render(self.message, lang)


class AcceptFileError(ConfigError):
    """The accept file is unreadable or has invalid entries (maps to exit code 2, like any config error)."""

    def __init__(self, message: Message, problems: Sequence[Message] = ()) -> None:
        self.message = message
        self.problems: tuple[Message, ...] = tuple(problems)
        super().__init__(self.render("en"))

    def render(self, lang: str = "en") -> str:
        """The error and every problem found, one per line, in ``lang``."""
        head = render(self.message, lang)
        return head + "".join("\n  - " + render(problem, lang) for problem in self.problems)


# ---- accept file ---------------------------------------------------------------------------------------------

_ACCEPT_KEYS: tuple[str, ...] = ("fingerprint", "kind", "subject", "owner", "reason", "expires", "tenant")
_FINGERPRINT_RE = re.compile(r"^[0-9a-f]{12,64}$")
_KIND_RE = re.compile(r"^([a-z][a-z0-9_]*)\.[a-z0-9_]+(?:\.[a-z0-9_]+)*$")
_TEXT_LIMITS = {"owner": 128, "reason": 1000, "subject": 512, "tenant": 128, "kind": 64, "fingerprint": 64}


@dataclass(frozen=True, slots=True)
class AcceptEntry:
    """One accepted (snoozed) finding or family of findings.

    ``subject`` is a case-sensitive :mod:`fnmatch` glob over :attr:`Finding.subject` (``*``, ``?``,
    ``[seq]``). Case-sensitive on purpose: a pattern that does not match keeps notifying (fail loud), it never
    hides more than written. ``expires`` is an aware UTC datetime; a date in the file means "valid through the
    end of that day (UTC)".
    """

    owner: str
    reason: str
    expires: datetime
    fingerprint: str | None = None
    kind: str | None = None
    subject: str | None = None
    tenant: str | None = None
    index: int = 0  # 1-based position in the file (for messages)
    id: str = field(init=False, default="", compare=False)
    _pattern: re.Pattern[str] | None = field(init=False, default=None, compare=False, repr=False)

    def __post_init__(self) -> None:
        expires = self.expires if self.expires.tzinfo is not None else self.expires.replace(tzinfo=UTC)
        object.__setattr__(self, "expires", expires.astimezone(UTC))
        if not self.id:
            ident = stable_hash(
                "accept",
                self.fingerprint or "",
                self.kind or "",
                self.subject or "",
                self.tenant or "",
                self.expires.astimezone(UTC).isoformat(),
                self.owner,
                length=16,
            )
            object.__setattr__(self, "id", ident)
        if self.subject is not None:
            object.__setattr__(self, "_pattern", re.compile(fnmatch.translate(self.subject), re.DOTALL))

    def applies_to(self, tenant: str | None) -> bool:
        """True when the entry is global (no tenant) or scoped to ``tenant``."""
        return self.tenant is None or self.tenant == tenant

    def matches(self, finding: Finding, *, tenant: str | None = None) -> bool:
        """Selector match, ignoring expiry (see :meth:`is_expired`)."""
        if not self.applies_to(tenant if tenant is not None else finding.tenant):
            return False
        if self.fingerprint is not None:
            return finding.fingerprint.lower() == self.fingerprint
        if self.kind is None or self._pattern is None or finding.kind != self.kind:
            return False
        return self._pattern.match(finding.subject) is not None

    def is_expired(self, now: datetime) -> bool:
        """True once ``now`` reaches the expiry instant."""
        return now >= self.expires

    def expires_label(self) -> str:
        """``2026-12-31`` for end-of-day expiries, else the full ISO timestamp."""
        exp = self.expires.astimezone(UTC)
        if exp.hour == exp.minute == exp.second == 0 and exp.microsecond == 0:
            return (exp - timedelta(days=1)).date().isoformat()
        return iso(exp) or ""


class AcceptList:
    """Parsed ``hushwatch-accept.yml``. Look-ups are indexed by fingerprint and by kind."""

    def __init__(self, entries: Iterable[AcceptEntry] = (), *, source: Path | None = None) -> None:
        self.entries: tuple[AcceptEntry, ...] = tuple(entries)
        self.source = source
        self._by_fp: dict[str, list[AcceptEntry]] = {}
        self._by_kind: dict[str, list[AcceptEntry]] = {}
        for entry in self.entries:
            if entry.fingerprint is not None:
                self._by_fp.setdefault(entry.fingerprint, []).append(entry)
            elif entry.kind is not None:
                self._by_kind.setdefault(entry.kind, []).append(entry)

    def __len__(self) -> int:
        return len(self.entries)

    def __iter__(self) -> Iterator[AcceptEntry]:
        return iter(self.entries)

    def candidates(self, finding: Finding, *, tenant: str | None = None) -> list[AcceptEntry]:
        """Every entry whose selector matches ``finding`` (expired ones included), in file order."""
        found = self._by_fp.get(finding.fingerprint.lower(), []) + self._by_kind.get(finding.kind, [])
        found.sort(key=lambda e: e.index)
        return [e for e in found if e.matches(finding, tenant=tenant)]

    def is_accepted(self, finding: Finding, now: datetime, *, tenant: str | None = None) -> AcceptEntry | None:
        """The first non-expired entry accepting ``finding`` (for ``tenant``, default ``finding.tenant``)."""
        for entry in self.candidates(finding, tenant=tenant):
            if not entry.is_expired(now):
                return entry
        return None

    def expired(self, now: datetime, *, tenant: str | None = None) -> list[AcceptEntry]:
        """Entries applying to ``tenant`` whose expiry has passed."""
        return [e for e in self.entries if e.applies_to(tenant) and e.is_expired(now)]

    def active(self, now: datetime, *, tenant: str | None = None) -> list[AcceptEntry]:
        """Entries applying to ``tenant`` that are still valid."""
        return [e for e in self.entries if e.applies_to(tenant) and not e.is_expired(now)]


def load_accept_file(
    path: str | Path,
    *,
    now: datetime | None = None,
    missing_ok: bool = True,
    max_days: int = ACCEPT_MAX_DAYS,
) -> AcceptList:
    """Load and validate ``hushwatch-accept.yml`` (``yaml.safe_load`` only).

    Format (a bare list of entries is also accepted)::

        version: 1
        accept:
          - fingerprint: 3f2a9c0d1e2b3c4d5e6f      # or: kind + subject (glob)
            owner: soc-team
            reason: decommissioned host, change CHG-1234
            expires: 2026-12-31                   # MANDATORY, at most 365 days ahead
          - kind: silence.silent
            subject: "agent:lab-*|*"
            tenant: acme                          # optional
            owner: alice
            reason: lab machines are powered off at weekends
            expires: 2026-10-15

    Every problem is collected and raised together as :class:`AcceptFileError`. A missing file yields an
    empty list when ``missing_ok`` (the default), so a cron job without accept file notifies everything.
    """
    file_path = Path(path).expanduser()
    shown = Entity("file", str(file_path))
    try:
        st = file_path.stat()
    except FileNotFoundError:
        if missing_ok:
            return AcceptList((), source=file_path)
        raise AcceptFileError(M("state.accept.missing_file", path=shown)) from None
    except OSError as exc:
        raise AcceptFileError(M("state.accept.unreadable", path=shown, error=exc.strerror or "error")) from None
    if _writable_by_anyone(file_path, st):
        raise AcceptFileError(M("state.accept.insecure", path=shown))
    size = st.st_size
    if size > ACCEPT_MAX_BYTES:
        raise AcceptFileError(
            M("state.accept.invalid", path=shown), [M("state.accept.too_large", limit=ACCEPT_MAX_BYTES)]
        )
    try:
        with file_path.open("rb") as handle:
            data = handle.read(ACCEPT_MAX_BYTES + 1)
        text = data.decode("utf-8")
    except OSError as exc:
        raise AcceptFileError(M("state.accept.unreadable", path=shown, error=exc.strerror or "error")) from None
    except UnicodeDecodeError:
        raise AcceptFileError(M("state.accept.unreadable", path=shown, error="not UTF-8")) from None
    if len(data) > ACCEPT_MAX_BYTES:
        raise AcceptFileError(
            M("state.accept.invalid", path=shown), [M("state.accept.too_large", limit=ACCEPT_MAX_BYTES)]
        )
    return parse_accept(text, now=now, source=file_path, max_days=max_days)


def _writable_by_anyone(path: Path, st: os.stat_result) -> bool:
    """The accept file silences notifications: refuse one any local user could have written.

    That is a world-writable file, or a file owned by someone else (not root) inside a world-writable directory
    such as ``/tmp`` (anyone may create it there before its owner does)."""
    if os.name != "posix":
        return False
    if st.st_mode & stat.S_IWOTH:
        return True
    if st.st_uid in (os.geteuid(), 0):
        return False
    try:
        parent = os.stat(path.parent)
    except OSError:
        return False
    return bool(parent.st_mode & stat.S_IWOTH)


def parse_accept(
    text: str,
    *,
    now: datetime | None = None,
    source: Path | None = None,
    max_days: int = ACCEPT_MAX_DAYS,
) -> AcceptList:
    """Validate accept-file YAML text (see :func:`load_accept_file`)."""
    reference = _aware(now) if now is not None else datetime.now(UTC)
    shown = Entity("file", str(source) if source is not None else "<accept>")
    header = M("state.accept.invalid", path=shown)
    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise AcceptFileError(header, [M("state.accept.yaml", error=_short(str(exc), 300))]) from None
    except (ValueError, TypeError, OverflowError, RecursionError) as exc:  # e.g. an impossible date 2026-13-40
        raise AcceptFileError(
            header, [M("state.accept.yaml", error=_short(type(exc).__name__ + ": " + str(exc), 300))]
        ) from None
    problems: list[Message] = []
    items: list[Any]
    if raw is None:
        items = []
    elif isinstance(raw, list):
        items = raw
    elif isinstance(raw, dict):
        unknown = sorted(str(k) for k in raw if k not in ("version", "accept"))
        if unknown:
            problems.append(M("state.accept.unknown_top", keys=", ".join(unknown)))
        version = raw.get("version", 1)
        if version != 1 or isinstance(version, bool):
            problems.append(M("state.accept.version", version=_short(str(version), 20)))
        body = raw.get("accept")
        if body is None:
            items = []
        elif isinstance(body, list):
            items = body
        else:
            problems.append(M("state.accept.top_level"))
            items = []
    else:
        raise AcceptFileError(header, [M("state.accept.top_level")])
    entries: list[AcceptEntry] = []
    for number, item in enumerate(items, start=1):
        entry = _parse_entry(number, item, reference, max_days, problems)
        if entry is not None:
            entries.append(entry)
    if problems:
        raise AcceptFileError(header, problems)
    return AcceptList(entries, source=source)


def _parse_entry(n: int, item: Any, now: datetime, max_days: int, problems: list[Message]) -> AcceptEntry | None:
    if not isinstance(item, dict):
        problems.append(M("state.accept.not_mapping", n=n))
        return None
    start = len(problems)
    for key in item:
        name = str(key)
        if key not in _ACCEPT_KEYS:
            hint = difflib.get_close_matches(name.lower(), _ACCEPT_KEYS, n=1, cutoff=0.6)
            if hint or name.lower() in ("expiry", "expiration", "until", "expire"):
                problems.append(
                    M("state.accept.unknown_key_hint", n=n, key=_short(name, 40), hint=hint[0] if hint else "expires")
                )
            else:
                problems.append(M("state.accept.unknown_key", n=n, key=_short(name, 40)))
    fp = _text_field(n, item, "fingerprint", problems)
    kind = _text_field(n, item, "kind", problems)
    subject = _text_field(n, item, "subject", problems, strip=False)
    owner = _text_field(n, item, "owner", problems)
    reason = _text_field(n, item, "reason", problems)
    tenant = _text_field(n, item, "tenant", problems)
    for key, value in (("owner", owner), ("reason", reason)):
        if value is None and key not in item:
            problems.append(M("state.accept.required", n=n, key=key))
    has_fp = "fingerprint" in item
    has_selector = "kind" in item or "subject" in item
    if has_fp and has_selector:
        problems.append(M("state.accept.selector_both", n=n))
    elif not has_fp and not ("kind" in item and "subject" in item):
        problems.append(M("state.accept.selector_missing", n=n))
    if fp is not None:
        fp = fp.lower()
        if not _FINGERPRINT_RE.match(fp):
            problems.append(M("state.accept.bad_fingerprint", n=n))
    if kind is not None:
        match = _KIND_RE.match(kind)
        if match is None or match.group(1) not in DOMAINS:
            problems.append(M("state.accept.bad_kind", n=n, kind=_short(kind, 64)))
    expires = _expiry(n, item, now, max_days, problems)
    if len(problems) > start or expires is None or owner is None or reason is None:
        return None
    return AcceptEntry(
        owner=owner,
        reason=reason,
        expires=expires,
        fingerprint=fp,
        kind=kind if fp is None else None,
        subject=subject if fp is None else None,
        tenant=tenant,
        index=n,
    )


def _text_field(
    n: int, item: Mapping[Any, Any], key: str, problems: list[Message], *, strip: bool = True
) -> str | None:
    if key not in item:
        return None
    value = item[key]
    limit = _TEXT_LIMITS[key]
    allowed: tuple[type, ...] = (str, int) if key in ("owner", "reason", "tenant") else (str,)
    if isinstance(value, bool) or not isinstance(value, allowed):  # an all-digit fingerprint must be quoted
        problems.append(M("state.accept.bad_text", n=n, key=key, max=limit))
        return None
    text = str(value)
    text = text.strip() if strip else text
    if not text.strip() or len(text) > limit or _CONTROL_RE.search(text):
        problems.append(M("state.accept.bad_text", n=n, key=key, max=limit))
        return None
    return text


def _expiry(n: int, item: Mapping[Any, Any], now: datetime, max_days: int, problems: list[Message]) -> datetime | None:
    if "expires" not in item or item["expires"] is None or item["expires"] == "":
        problems.append(M("state.accept.expires_missing", n=n, max_days=max_days))
        return None
    value = item["expires"]
    day: date | None = None
    instant: datetime | None = None
    if isinstance(value, datetime):
        instant = value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
    elif isinstance(value, date):
        day = value
    elif isinstance(value, str) and not isinstance(value, bool):
        text = value.strip()
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}", text):
            try:
                day = date.fromisoformat(text)
            except ValueError:
                day = None
        elif re.match(r"^\d{4}-\d{2}-\d{2}[T ]", text):
            instant = parse_ts(text)
    if day is None and instant is None:
        problems.append(M("state.accept.expires_invalid", n=n))
        return None
    if day is not None:
        if day > (now.astimezone(UTC).date() + timedelta(days=max_days)):
            problems.append(M("state.accept.expires_too_far", n=n, expires=day.isoformat(), max_days=max_days))
            return None
        try:
            return datetime(day.year, day.month, day.day, tzinfo=UTC) + timedelta(days=1)
        except OverflowError:  # 9999-12-31 + 1 day
            problems.append(M("state.accept.expires_invalid", n=n))
            return None
    assert instant is not None
    if instant > now + timedelta(days=max_days):
        problems.append(M("state.accept.expires_too_far", n=n, expires=iso(instant) or "", max_days=max_days))
        return None
    return instant


# ---- lifecycle results ---------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Transition:
    """One notification-worthy change of one finding (or of one accept entry).

    ``summary`` is the finding title rebuilt from state with placeholders instead of entity values (use the
    live :class:`Finding` when you have it). ``detail`` explains flapping / acceptance expiry.
    """

    type: str  # opened | regressed | escalated | resolved | reminder | flapping | acceptance_expired
    fingerprint: str  # "" for an accept entry that matches no current finding
    kind: str
    domain: str
    severity: Severity
    status: str  # finding status after the run ("" for an unmatched accept entry)
    summary: Message | str
    first_seen: datetime | None = None
    opened_at: datetime | None = None
    resolved_at: datetime | None = None
    flapping: bool = False
    detail: Message | None = None
    accept_id: str | None = None
    accept_expires: datetime | None = None
    previous_severity: Severity | None = None  # ``escalated``: the severity last notified


@dataclass(slots=True)
class RunOutcome:
    """What one :meth:`StateStore.record_run` decided. ``transitions`` is what should be notified."""

    run_id: str
    tenant: str
    run_at: datetime
    transitions: list[Transition] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)
    stale: bool = False  # the run was older than the last recorded one: nothing changed

    def of_type(self, kind: str) -> list[Transition]:
        """Transitions of one type."""
        return [t for t in self.transitions if t.type == kind]

    @property
    def opened(self) -> list[Transition]:
        return self.of_type(OPENED)

    @property
    def resolved(self) -> list[Transition]:
        return self.of_type(RESOLVED_T)

    @property
    def regressed(self) -> list[Transition]:
        return self.of_type(REGRESSED_T)

    @property
    def escalated(self) -> list[Transition]:
        return self.of_type(ESCALATED)

    @property
    def reminders(self) -> list[Transition]:
        return self.of_type(REMINDER)

    @property
    def flapping(self) -> list[Transition]:
        return self.of_type(FLAPPING)

    @property
    def acceptance_expired(self) -> list[Transition]:
        return self.of_type(ACCEPTANCE_EXPIRED)

    @property
    def transition_counts(self) -> dict[str, int]:
        """Number of transitions per type (every type present, zero-filled)."""
        counts = dict.fromkeys(TRANSITION_TYPES, 0)
        for t in self.transitions:
            counts[t.type] = counts.get(t.type, 0) + 1
        return counts


@dataclass(frozen=True, slots=True)
class FindingState:
    """Stored lifecycle state of one fingerprint (no raw subject, no entity values)."""

    tenant: str
    fingerprint: str
    kind: str
    domain: str
    subject_hash: str
    severity: Severity
    status: str
    first_seen: datetime
    last_seen: datetime
    opened_at: datetime | None
    resolved_at: datetime | None
    consecutive_bad: int
    consecutive_good: int
    times_opened: int
    regressions: int
    flapping: bool
    last_notified_at: datetime | None
    accepted_until: datetime | None
    summary: Message | str


@dataclass(frozen=True, slots=True)
class RunRecord:
    run_id: str
    tenant: str
    run_at: datetime
    recorded_at: datetime
    counts: dict[str, int]


@dataclass(frozen=True, slots=True)
class HeartbeatRecord:
    tenant: str
    at: datetime
    ok: bool
    detail: str


# ---- the store -----------------------------------------------------------------------------------------------

_MIGRATIONS: tuple[tuple[int, str, tuple[str, ...]], ...] = (
    (
        1,
        "initial schema",
        (
            "CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
            """CREATE TABLE findings (
                tenant TEXT NOT NULL,
                fingerprint TEXT NOT NULL,
                kind TEXT NOT NULL,
                domain TEXT NOT NULL,
                subject_hash TEXT NOT NULL,
                severity TEXT NOT NULL,
                status TEXT NOT NULL CHECK (status IN ('new', 'open', 'resolved', 'regressed')),
                first_seen INTEGER NOT NULL,
                last_seen INTEGER NOT NULL,
                opened_at INTEGER,
                resolved_at INTEGER,
                consecutive_bad INTEGER NOT NULL DEFAULT 0,
                consecutive_good INTEGER NOT NULL DEFAULT 0,
                times_opened INTEGER NOT NULL DEFAULT 0,
                regressions INTEGER NOT NULL DEFAULT 0,
                flapping INTEGER NOT NULL DEFAULT 0,
                flap_notified INTEGER NOT NULL DEFAULT 0,
                notified_phase TEXT,
                last_notified_at INTEGER,
                accepted_entry TEXT,
                accepted_until INTEGER,
                summary TEXT NOT NULL DEFAULT '{}',
                PRIMARY KEY (tenant, fingerprint)
            ) WITHOUT ROWID""",
            """CREATE TABLE history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant TEXT NOT NULL,
                fingerprint TEXT NOT NULL,
                run_id TEXT NOT NULL,
                at INTEGER NOT NULL,
                event TEXT NOT NULL,
                from_status TEXT,
                to_status TEXT NOT NULL
            )""",
            "CREATE INDEX history_fp ON history (tenant, fingerprint, at)",
            "CREATE INDEX history_at ON history (tenant, at)",
            """CREATE TABLE notices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant TEXT NOT NULL,
                run_id TEXT NOT NULL,
                at INTEGER NOT NULL,
                fingerprint TEXT NOT NULL,
                type TEXT NOT NULL,
                accept_entry TEXT,
                prev_phase TEXT,
                prev_notified_at INTEGER,
                prev_flap_notified INTEGER NOT NULL DEFAULT 0,
                restore INTEGER NOT NULL DEFAULT 1
            )""",
            "CREATE INDEX notices_run ON notices (tenant, run_id)",
            "CREATE INDEX notices_at ON notices (tenant, at)",
            """CREATE TABLE accept_notices (
                tenant TEXT NOT NULL,
                entry_id TEXT NOT NULL,
                run_id TEXT NOT NULL,
                noticed_at INTEGER NOT NULL,
                PRIMARY KEY (tenant, entry_id)
            )""",
            """CREATE TABLE runs (
                run_id TEXT PRIMARY KEY,
                tenant TEXT NOT NULL,
                run_at INTEGER NOT NULL,
                recorded_at INTEGER NOT NULL,
                counts TEXT NOT NULL
            )""",
            "CREATE INDEX runs_tenant ON runs (tenant, run_at)",
            """CREATE TABLE heartbeats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant TEXT NOT NULL,
                at INTEGER NOT NULL,
                ok INTEGER NOT NULL,
                detail TEXT NOT NULL
            )""",
            "CREATE INDEX heartbeats_tenant ON heartbeats (tenant, at)",
        ),
    ),
    (
        2,
        "notified severity (escalation)",
        (
            "ALTER TABLE findings ADD COLUMN notified_severity TEXT",
            "UPDATE findings SET notified_severity = severity WHERE notified_phase IS NOT NULL",
            "ALTER TABLE notices ADD COLUMN prev_severity TEXT",
        ),
    ),
)

_COLUMNS: tuple[str, ...] = (
    "fingerprint",
    "kind",
    "domain",
    "subject_hash",
    "severity",
    "status",
    "first_seen",
    "last_seen",
    "opened_at",
    "resolved_at",
    "consecutive_bad",
    "consecutive_good",
    "times_opened",
    "regressions",
    "flapping",
    "flap_notified",
    "notified_phase",
    "last_notified_at",
    "accepted_entry",
    "accepted_until",
    "summary",
    "notified_severity",
)


@dataclass(slots=True)
class _Rec:
    fingerprint: str
    kind: str
    domain: str
    subject_hash: str
    severity: Severity
    status: str
    first_seen: int
    last_seen: int
    opened_at: int | None = None
    resolved_at: int | None = None
    consecutive_bad: int = 0
    consecutive_good: int = 0
    times_opened: int = 0
    regressions: int = 0
    flapping: bool = False
    flap_notified: bool = False
    notified_phase: str | None = None
    last_notified_at: int | None = None
    accepted_entry: str | None = None
    accepted_until: int | None = None
    summary: str = "{}"
    notified_severity: str | None = None  # severity carried by the last notification

    def row(self, tenant: str) -> tuple[Any, ...]:
        return (
            tenant,
            self.fingerprint,
            self.kind,
            self.domain,
            self.subject_hash,
            self.severity.value,
            self.status,
            self.first_seen,
            self.last_seen,
            self.opened_at,
            self.resolved_at,
            self.consecutive_bad,
            self.consecutive_good,
            self.times_opened,
            self.regressions,
            int(self.flapping),
            int(self.flap_notified),
            self.notified_phase,
            self.last_notified_at,
            self.accepted_entry,
            self.accepted_until,
            self.summary,
            self.notified_severity,
        )

    @classmethod
    def from_row(cls, row: Sequence[Any]) -> _Rec:
        values = dict(zip(_COLUMNS, row, strict=True))
        return cls(
            fingerprint=str(values["fingerprint"]),
            kind=str(values["kind"]),
            domain=str(values["domain"]),
            subject_hash=str(values["subject_hash"]),
            severity=_severity(values["severity"]),
            status=str(values["status"]),
            first_seen=int(values["first_seen"]),
            last_seen=int(values["last_seen"]),
            opened_at=_opt_int(values["opened_at"]),
            resolved_at=_opt_int(values["resolved_at"]),
            consecutive_bad=int(values["consecutive_bad"]),
            consecutive_good=int(values["consecutive_good"]),
            times_opened=int(values["times_opened"]),
            regressions=int(values["regressions"]),
            flapping=bool(values["flapping"]),
            flap_notified=bool(values["flap_notified"]),
            notified_phase=values["notified_phase"],
            last_notified_at=_opt_int(values["last_notified_at"]),
            accepted_entry=values["accepted_entry"],
            accepted_until=_opt_int(values["accepted_until"]),
            summary=str(values["summary"] or "{}"),
            notified_severity=values["notified_severity"],
        )


class StateStore:
    """Per-state-directory SQLite store of finding lifecycles, runs and heartbeats.

    ``path`` is the database file; an existing directory means ``<dir>/state.sqlite3``. Missing parent
    directories are created with mode 0700 and the database file with mode 0600 (an existing file readable by
    others is tightened). A directory other users can write to (or owned by another user) and symlinks in
    place of the database or its ``-wal``/``-shm``/``-journal`` files are refused with :class:`StateError`.
    Several stores (threads or processes) may use the same file: each run is one ``BEGIN IMMEDIATE``
    transaction and waits up to ``busy_timeout`` seconds for the lock.
    """

    def __init__(self, path: str | Path, *, busy_timeout: float = 30.0) -> None:
        db_path = Path(path).expanduser()
        if db_path.is_dir():
            db_path = db_path / STATE_FILENAME
        self.path = db_path
        self._lock = threading.RLock()
        self._busy_timeout = max(0.0, float(busy_timeout))
        shown = Entity("file", str(db_path))
        try:
            _ensure_private_dir(db_path.parent)
            _check_private_dir(db_path.parent)
            _ensure_private_file(db_path)
            for suffix in ("-wal", "-shm", "-journal"):
                _check_not_link(Path(str(db_path) + suffix))
        except OSError as exc:
            raise StateError(M("state.error.open", path=shown, error=exc.strerror or type(exc).__name__)) from None
        try:
            self._conn = sqlite3.connect(
                str(db_path),
                timeout=self._busy_timeout,
                isolation_level=None,
                check_same_thread=False,
            )
        except sqlite3.Error as exc:
            raise StateError(M("state.error.open", path=shown, error=str(exc))) from None
        try:
            self._configure()
            self._subject_key = self._migrate()
        except StateError:
            self._conn.close()
            raise
        except sqlite3.Error as exc:
            self._conn.close()
            raise StateError(M("state.error.open", path=shown, error=str(exc))) from None
        for suffix in ("-wal", "-shm"):
            _tighten(Path(str(db_path) + suffix))

    # ---- lifecycle ---------------------------------------------------------------------------------------

    def close(self) -> None:
        """Close the database connection (idempotent)."""
        with self._lock, contextlib.suppress(sqlite3.Error):
            self._conn.close()

    def __enter__(self) -> StateStore:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # ---- runs --------------------------------------------------------------------------------------------

    def record_run(
        self,
        tenant: str,
        findings: Sequence[Finding],
        *,
        now: datetime,
        open_after: int = 2,
        resolve_after: int = 2,
        immediate_kinds: Collection[str] = DEFAULT_IMMEDIATE_KINDS,
        critical_immediate: bool = True,
        accept: AcceptList | None = None,
        remind_every: timedelta = timedelta(hours=12),
        assessed: Collection[str] | None = None,
        flap_threshold: int = 3,
        flap_window: timedelta = timedelta(hours=24),
        retention: timedelta = timedelta(days=90),
    ) -> RunOutcome:
        """Apply one run's findings to the lifecycle and return what to notify.

        * ``findings`` — everything this run reported for ``tenant`` (duplicates by fingerprint are merged,
          keeping the highest severity). Findings whose ``tenant`` is set to another tenant are ignored.
        * ``now`` — the run's reference time (aware). A run older than the newest recorded run of the tenant
          is *stale*: nothing is changed and ``RunOutcome.stale`` is True (late concurrent runs never rewind
          the lifecycle). Runs whose ``now`` was more than an hour ahead of the wall clock when they were
          recorded (a future-dated event, a mistaken ``--now``) do not count for this check, so one bogus run
          cannot freeze notifications until that date.
        * ``assessed`` — domains this run fully assessed. A finding ABSENT from the run only counts toward
          resolution when its domain was assessed: an analysis that did not run proves nothing (never a false
          green). Default: every domain, except that when the run itself reported ``assessment.incomplete``
          only the ``assessment`` domain may recover. Pass the report's assessed domains to be precise.
        * ``accept`` — accepted findings are tracked but not notified (counted in ``counts["suppressed"]``);
          an expired entry produces one ``acceptance_expired`` transition.

        Returns the transitions (``opened``, ``regressed``, ``escalated``, ``resolved``, ``reminder``,
        ``flapping``, ``acceptance_expired``) and counts: ``findings`` (reported this run), ``open``
        (+ ``open.<severity>``), ``pending`` (waiting for hysteresis), ``accepted``, ``flapping``, ``suppressed``,
        ``not_assessed``, ``ignored``.
        """
        now_utc = _aware(now)
        if open_after < 1 or resolve_after < 1 or flap_threshold < 2:
            raise ValueError("open_after and resolve_after must be >= 1, flap_threshold >= 2")
        if remind_every <= timedelta(0) or flap_window <= timedelta(0):
            raise ValueError("remind_every and flap_window must be positive")
        now_s = int(now_utc.timestamp())
        remind_s = int(remind_every.total_seconds())
        window_s = int(flap_window.total_seconds())
        retention_s = max(int(retention.total_seconds()), window_s * 2)
        run_id = now_utc.strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(6)
        immediate = frozenset(immediate_kinds)

        present: dict[str, Finding] = {}
        ignored = 0
        for finding in findings:
            if finding.tenant is not None and finding.tenant != tenant:
                ignored += 1
                continue
            known = present.get(finding.fingerprint)
            if known is None or finding.severity.rank > known.severity.rank:
                present[finding.fingerprint] = finding
        if ignored:
            log.warning("state: ignored %d findings that belong to another tenant", ignored)
        if assessed is None:
            incomplete = any(f.kind == "assessment.incomplete" for f in present.values())
            assessed_set: frozenset[str] | None = frozenset({"assessment"}) if incomplete else None
        else:
            assessed_set = frozenset(assessed)

        with self._lock, self._transaction() as conn:
            row = conn.execute(
                "SELECT MAX(run_at) FROM runs WHERE tenant = ? AND run_at <= recorded_at + ?",
                (tenant, _FUTURE_TOLERANCE_S),
            ).fetchone()
            if row is not None and row[0] is not None and now_s < int(row[0]):
                log.warning("state: run for tenant %s is older than the last recorded run; ignored", tenant)
                return RunOutcome(run_id=run_id, tenant=tenant, run_at=now_utc, counts={"ignored": ignored}, stale=True)
            if now_s > time.time() + _FUTURE_TOLERANCE_S:
                log.warning("state: run for tenant %s is dated in the future; it will not block later runs", tenant)

            records = self._load(conn, tenant)
            events: list[tuple[str, str, str | None, str]] = []  # (fingerprint, event, from, to)
            accepted_now: dict[str, AcceptEntry] = {}

            # 1. findings reported by this run ---------------------------------------------------------------
            for fp, finding in present.items():
                rec = records.get(fp)
                if rec is None:
                    rec = _Rec(
                        fingerprint=fp,
                        kind=finding.kind,
                        domain=finding.domain,
                        subject_hash=self._subject_hash(tenant, finding.subject),
                        severity=finding.severity,
                        status=NEW,
                        first_seen=now_s,
                        last_seen=now_s,
                    )
                    records[fp] = rec
                rec.kind, rec.domain, rec.severity = finding.kind, finding.domain, finding.severity
                rec.summary = _summary_json(finding)
                rec.last_seen = now_s
                rec.consecutive_bad += 1
                rec.consecutive_good = 0
                opens_now = (
                    finding.kind in immediate
                    or (critical_immediate and finding.severity is Severity.CRITICAL)
                    or rec.consecutive_bad >= open_after
                )
                if rec.status == NEW and opens_now:
                    events.append((fp, OPENED, rec.status, OPEN))
                    rec.status, rec.opened_at, rec.resolved_at = OPEN, now_s, None
                    rec.times_opened += 1
                elif rec.status == RESOLVED and opens_now:
                    events.append((fp, REGRESSED_T, rec.status, REGRESSED))
                    rec.status, rec.opened_at = REGRESSED, now_s
                    rec.times_opened += 1
                    rec.regressions += 1
                entry = accept.is_accepted(finding, now_utc, tenant=tenant) if accept is not None else None
                if entry is not None:
                    accepted_now[fp] = entry
                    rec.accepted_entry, rec.accepted_until = entry.id, int(entry.expires.timestamp())
                else:
                    rec.accepted_entry = rec.accepted_until = None

            # 2. findings absent from this run ---------------------------------------------------------------
            valid_ids = {e.id for e in accept.active(now_utc, tenant=tenant)} if accept is not None else set()
            lapsed: dict[str, str] = {}  # absent fingerprint -> id of the acceptance that no longer covers it
            not_assessed = 0
            for fp, rec in records.items():
                if fp in present:
                    continue
                if rec.accepted_entry is not None and rec.accepted_entry not in valid_ids:
                    lapsed[fp] = rec.accepted_entry
                    rec.accepted_entry = rec.accepted_until = None
                if assessed_set is not None and rec.domain not in assessed_set:
                    if rec.status in ACTIVE_STATUSES or (rec.status == NEW and rec.consecutive_bad > 0):
                        not_assessed += 1  # open or pending findings this run could not re-check
                    continue
                rec.consecutive_bad = 0
                rec.consecutive_good += 1
                if rec.status in ACTIVE_STATUSES and rec.consecutive_good >= resolve_after:
                    events.append((fp, RESOLVED_T, rec.status, RESOLVED))
                    rec.status, rec.resolved_at = RESOLVED, now_s

            conn.executemany(
                "INSERT INTO history (tenant, fingerprint, run_id, at, event, from_status, to_status) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                [(tenant, fp, run_id, now_s, ev, src, dst) for fp, ev, src, dst in events],
            )

            # 3. flapping ----------------------------------------------------------------------------------
            changed = {fp for fp, _, _, _ in events}
            flap_counts: dict[str, int] = {}
            for fp, rec in records.items():
                if fp not in changed and not rec.flapping:
                    continue
                count = int(
                    conn.execute(
                        "SELECT COUNT(*) FROM history WHERE tenant = ? AND fingerprint = ? AND at > ? "
                        "AND event IN (?, ?, ?)",
                        (tenant, fp, now_s - window_s, *_LIFECYCLE_EVENTS),
                    ).fetchone()[0]
                )
                flap_counts[fp] = count
                if not rec.flapping and count >= flap_threshold:
                    rec.flapping, rec.flap_notified = True, False
                elif rec.flapping and count == 0:
                    rec.flapping, rec.flap_notified = False, False

            # 4. notifications ------------------------------------------------------------------------------
            transitions: list[Transition] = []
            notices: list[tuple[Any, ...]] = []
            handled: set[str] = set()

            def notify(
                rec: _Rec, kind: str, *, entry: AcceptEntry | None = None, detail: Message | None = None
            ) -> None:
                first = rec.fingerprint not in handled  # only the first notice of a run restores the finding
                notices.append(
                    (
                        tenant,
                        run_id,
                        now_s,
                        rec.fingerprint,
                        kind,
                        entry.id if entry is not None else None,
                        rec.notified_phase,
                        rec.last_notified_at,
                        int(rec.flap_notified),
                        int(first),
                        rec.notified_severity,
                    )
                )
                handled.add(rec.fingerprint)
                previous = _severity_or_none(rec.notified_severity) if kind == ESCALATED else None
                phase = _phase(rec.status)
                if kind == FLAPPING:
                    rec.flap_notified = True
                # every notification about a finding tells the receiver its current phase and severity
                # (a reminder says "still open" too, so a later resolution must be announced)
                if phase is not None:
                    rec.notified_phase = phase
                    rec.notified_severity = rec.severity.value
                rec.last_notified_at = now_s
                transitions.append(_transition(kind, rec, detail=detail, entry=entry, previous=previous))

            if accept is not None:
                noticed = {
                    str(r[0]) for r in conn.execute("SELECT entry_id FROM accept_notices WHERE tenant = ?", (tenant,))
                }
                for entry in accept.expired(now_utc, tenant=tenant):
                    if entry.id in noticed:
                        continue
                    noticed.add(entry.id)
                    conn.execute(
                        "INSERT OR REPLACE INTO accept_notices (tenant, entry_id, run_id, noticed_at) "
                        "VALUES (?, ?, ?, ?)",
                        (tenant, entry.id, run_id, now_s),
                    )
                    matched = [
                        records[fp]
                        for fp, finding in present.items()
                        if fp not in accepted_now and entry.matches(finding, tenant=tenant)
                    ]
                    matched += [records[fp] for fp, entry_id in lapsed.items() if entry_id == entry.id]
                    owner = Entity("user", entry.owner)
                    if matched:
                        lapsed_detail = M("state.accept.expired_detail", owner=owner, expires=entry.expires_label())
                        for rec in sorted(matched, key=lambda r: r.fingerprint):
                            notify(rec, ACCEPTANCE_EXPIRED, entry=entry, detail=lapsed_detail)
                    else:
                        notices.append(
                            (tenant, run_id, now_s, "", ACCEPTANCE_EXPIRED, entry.id, None, None, 0, 0, None)
                        )
                        transitions.append(_unmatched_acceptance(entry))

            suppressed = 0
            for fp, rec in records.items():
                if fp in handled:
                    continue
                phase = _phase(rec.status)
                wanted: str | None = None
                detail: Message | None = None
                if rec.flapping:
                    if not rec.flap_notified:
                        wanted = FLAPPING
                        detail = M(
                            "state.flapping.detail",
                            count=flap_counts.get(fp, flap_threshold),
                            hours=max(1, window_s // 3600),
                        )
                elif phase == _PHASE_ACTIVE and rec.notified_phase != _PHASE_ACTIVE:
                    wanted = REGRESSED_T if rec.status == REGRESSED else OPENED
                elif phase == _PHASE_RESOLVED and rec.notified_phase == _PHASE_ACTIVE and fp not in present:
                    # a deferred "resolved" (after flapping, an acceptance or a failed delivery) is never sent while
                    # this very run still reports the finding (it is only below the re-open threshold)
                    wanted = RESOLVED_T
                known_active = rec.notified_phase == _PHASE_ACTIVE or (rec.flapping and rec.flap_notified)
                if wanted is None and phase == _PHASE_ACTIVE and fp in present and known_active:
                    last_rank = _severity_rank(rec.notified_severity)
                    if last_rank is not None and rec.severity.rank > last_rank:
                        wanted = ESCALATED
                    elif (
                        rec.severity is Severity.CRITICAL
                        and now_s - (rec.last_notified_at if rec.last_notified_at is not None else now_s) >= remind_s
                    ):
                        wanted = REMINDER
                if wanted is None:
                    continue
                if rec.accepted_entry is not None:
                    suppressed += 1
                    continue
                notify(rec, wanted, detail=detail)

            conn.executemany(
                "INSERT INTO notices (tenant, run_id, at, fingerprint, type, accept_entry, prev_phase, "
                "prev_notified_at, prev_flap_notified, restore, prev_severity) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                notices,
            )

            # 5. persist ------------------------------------------------------------------------------------
            placeholders = ", ".join("?" * (len(_COLUMNS) + 1))
            conn.executemany(
                f"INSERT OR REPLACE INTO findings (tenant, {', '.join(_COLUMNS)}) VALUES ({placeholders})",  # noqa: S608 - constant column names
                [rec.row(tenant) for rec in records.values()],
            )
            cutoff = now_s - retention_s
            conn.execute(
                "DELETE FROM findings WHERE tenant = ? AND status IN ('new', 'resolved') AND last_seen < ? "
                "AND flapping = 0",
                (tenant, cutoff),
            )
            for table, column in (("history", "at"), ("notices", "at"), ("accept_notices", "noticed_at")):
                conn.execute(f"DELETE FROM {table} WHERE tenant = ? AND {column} < ?", (tenant, cutoff))  # noqa: S608
            conn.execute("DELETE FROM runs WHERE tenant = ? AND run_at < ?", (tenant, cutoff))
            conn.execute("DELETE FROM heartbeats WHERE tenant = ? AND at < ?", (tenant, cutoff))

            counts = _counts(records, present, accepted_now, suppressed, not_assessed, ignored)
            conn.execute(
                "INSERT INTO runs (run_id, tenant, run_at, recorded_at, counts) VALUES (?, ?, ?, ?, ?)",
                (run_id, tenant, now_s, int(time.time()), json.dumps(counts, sort_keys=True)),
            )

        transitions.sort(key=lambda t: (_TYPE_ORDER.get(t.type, 99), -t.severity.rank, t.kind, t.fingerprint))
        return RunOutcome(run_id=run_id, tenant=tenant, run_at=now_utc, transitions=transitions, counts=counts)

    def mark_undelivered(self, tenant: str, run_id: str, fingerprints: Iterable[str] | None = None) -> int:
        """Hand back notifications of ``run_id`` that could not be delivered, so the next run re-sends them.

        With ``fingerprints`` only those are handed back (``SendResult.fingerprints``). Opened / regressed /
        resolved / flapping notifications come back as the same change; reminders are simply due again;
        expired acceptances are announced again. Returns the number of notifications handed back. A finding
        notified again by a later run is left alone (the later notification wins).
        """
        wanted = None if fingerprints is None else set(fingerprints)
        with self._lock, self._transaction() as conn:
            rows = conn.execute(
                "SELECT id, at, fingerprint, accept_entry, prev_phase, prev_notified_at, prev_flap_notified, restore, "
                "prev_severity FROM notices WHERE tenant = ? AND run_id = ? ORDER BY id",
                (tenant, run_id),
            ).fetchall()
            removed: list[int] = []
            for notice_id, at, fp, entry_id, prev_phase, prev_at, prev_flap, restore, prev_sev in rows:
                if wanted is not None and fp not in wanted:
                    continue
                removed.append(int(notice_id))
                if fp and restore:
                    conn.execute(
                        "UPDATE findings SET notified_phase = ?, last_notified_at = ?, flap_notified = ?, "
                        "notified_severity = ? WHERE tenant = ? AND fingerprint = ? AND last_notified_at = ?",
                        (prev_phase, prev_at, prev_flap, prev_sev, tenant, fp, at),
                    )
                if entry_id:
                    conn.execute(
                        "DELETE FROM accept_notices WHERE tenant = ? AND entry_id = ? AND run_id = ?",
                        (tenant, entry_id, run_id),
                    )
            conn.executemany("DELETE FROM notices WHERE id = ?", [(i,) for i in removed])
        return len(removed)

    # ---- queries -----------------------------------------------------------------------------------------

    def last_run(self, tenant: str) -> RunRecord | None:
        """The most recent recorded (non-stale) run of ``tenant``."""
        with self._lock:
            row = self._query_one(
                "SELECT run_id, run_at, recorded_at, counts FROM runs WHERE tenant = ? "
                "ORDER BY rowid DESC LIMIT 1",  # stale runs are never recorded: insertion order is run order
                (tenant,),
            )
        if row is None:
            return None
        try:
            counts = {str(k): int(v) for k, v in json.loads(row[3]).items()}
        except (ValueError, TypeError, AttributeError):
            counts = {}
        return RunRecord(
            run_id=str(row[0]), tenant=tenant, run_at=_dt(int(row[1])), recorded_at=_dt(int(row[2])), counts=counts
        )

    def heartbeat(self, tenant: str, now: datetime, ok: bool, detail: Message | str = "") -> HeartbeatRecord:
        """Record that a run of ``tenant`` happened (``ok`` False: failed or incomplete).

        ``detail`` is scrubbed before storage (URL credentials/paths/queries, IPs, e-mails, home directories,
        entity values) and capped at 300 characters.
        """
        at = _aware(now)
        text = _scrub_detail(detail)
        at_s = int(at.timestamp())
        with self._lock, self._transaction() as conn:
            conn.execute(
                "INSERT INTO heartbeats (tenant, at, ok, detail) VALUES (?, ?, ?, ?)",
                (tenant, at_s, int(bool(ok)), text),
            )
            conn.execute("DELETE FROM heartbeats WHERE tenant = ? AND at < ?", (tenant, at_s - _HEARTBEAT_RETENTION_S))
        return HeartbeatRecord(tenant=tenant, at=_dt(int(at.timestamp())), ok=bool(ok), detail=text)

    def last_heartbeat(self, tenant: str, *, ok: bool | None = None) -> HeartbeatRecord | None:
        """The newest heartbeat of ``tenant`` (only successful / failed ones with ``ok``)."""
        sql = "SELECT at, ok, detail FROM heartbeats WHERE tenant = ?"
        params: tuple[Any, ...] = (tenant,)
        if ok is not None:
            sql += " AND ok = ?"
            params += (int(ok),)
        with self._lock:
            row = self._query_one(sql + " ORDER BY at DESC, id DESC LIMIT 1", params)
        if row is None:
            return None
        return HeartbeatRecord(tenant=tenant, at=_dt(int(row[0])), ok=bool(row[1]), detail=str(row[2]))

    def open_findings(self, tenant: str) -> list[FindingState]:
        """Findings currently open or regressed (accepted ones included), most severe first."""
        return self._states(tenant, ACTIVE_STATUSES)

    def findings(self, tenant: str, statuses: Collection[str] | None = None) -> list[FindingState]:
        """Every tracked finding of ``tenant`` (optionally only some statuses), most severe first."""
        return self._states(tenant, frozenset(statuses) if statuses is not None else None)

    def get(self, tenant: str, fingerprint: str) -> FindingState | None:
        """Stored state of one fingerprint."""
        with self._lock:
            row = self._query_one(
                f"SELECT {', '.join(_COLUMNS)} FROM findings WHERE tenant = ? AND fingerprint = ?",  # noqa: S608
                (tenant, fingerprint),
            )
        return None if row is None else _state(tenant, _Rec.from_row(row))

    def schema_version(self) -> int:
        """Highest applied migration."""
        with self._lock:
            row = self._query_one("SELECT MAX(version) FROM schema_migrations", ())
        return int(row[0]) if row is not None and row[0] is not None else 0

    # ---- internals ---------------------------------------------------------------------------------------

    def _states(self, tenant: str, statuses: frozenset[str] | None) -> list[FindingState]:
        with self._lock:
            try:
                rows = self._conn.execute(
                    f"SELECT {', '.join(_COLUMNS)} FROM findings WHERE tenant = ?",  # noqa: S608
                    (tenant,),
                ).fetchall()
            except sqlite3.Error as exc:
                raise self._db_error(exc) from None
        states = [_state(tenant, _Rec.from_row(r)) for r in rows]
        if statuses is not None:
            states = [s for s in states if s.status in statuses]
        states.sort(key=lambda s: (-s.severity.rank, s.opened_at or s.first_seen, s.fingerprint))
        return states

    def _query_one(self, sql: str, params: tuple[Any, ...]) -> Any:
        try:
            return self._conn.execute(sql, params).fetchone()
        except sqlite3.Error as exc:
            raise self._db_error(exc) from None

    def _db_error(self, exc: sqlite3.Error) -> StateError:
        return StateError(M("state.error.db", path=Entity("file", str(self.path)), error=str(exc)))

    @contextlib.contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        conn = self._conn
        try:
            conn.execute("BEGIN IMMEDIATE")
        except sqlite3.Error as exc:
            raise self._db_error(exc) from None
        try:
            yield conn
        except sqlite3.Error as exc:
            with contextlib.suppress(sqlite3.Error):
                conn.execute("ROLLBACK")
            raise self._db_error(exc) from None
        except BaseException:
            with contextlib.suppress(sqlite3.Error):
                conn.execute("ROLLBACK")
            raise
        else:
            try:
                conn.execute("COMMIT")
            except sqlite3.Error as exc:
                with contextlib.suppress(sqlite3.Error):
                    conn.execute("ROLLBACK")
                raise self._db_error(exc) from None

    def _configure(self) -> None:
        conn = self._conn
        conn.execute(f"PRAGMA busy_timeout = {int(self._busy_timeout * 1000)}")
        conn.execute("PRAGMA trusted_schema = OFF")
        conn.execute("PRAGMA foreign_keys = ON")
        deadline = time.monotonic() + self._busy_timeout
        while True:
            try:
                mode = conn.execute("PRAGMA journal_mode = WAL").fetchone()
                break
            except sqlite3.OperationalError as exc:
                if "locked" not in str(exc) and "busy" not in str(exc):
                    raise
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.05)
        if mode is None or str(mode[0]).lower() != "wal":
            log.warning("state: WAL journal mode unavailable for this file system; using %s", mode)
        conn.execute("PRAGMA synchronous = NORMAL")

    def _migrate(self) -> bytes:
        shown = Entity("file", str(self.path))
        with self._transaction() as conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS schema_migrations "
                "(version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at INTEGER NOT NULL)"
            )
            row = conn.execute("SELECT MAX(version) FROM schema_migrations").fetchone()
            current = int(row[0]) if row is not None and row[0] is not None else 0
            if current > STATE_SCHEMA_VERSION:
                raise StateError(M("state.error.newer", path=shown, found=current, supported=STATE_SCHEMA_VERSION))
            for version, name, statements in _MIGRATIONS:
                if version <= current:
                    continue
                for sql in statements:
                    conn.execute(sql)
                conn.execute(
                    "INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)",
                    (version, name, int(time.time())),
                )
            conn.execute(f"PRAGMA user_version = {STATE_SCHEMA_VERSION}")
            key_row = conn.execute("SELECT value FROM meta WHERE key = 'subject_key'").fetchone()
            if key_row is None:
                key_hex = secrets.token_hex(32)
                conn.execute("INSERT INTO meta (key, value) VALUES ('subject_key', ?)", (key_hex,))
            else:
                key_hex = str(key_row[0])
        try:
            return bytes.fromhex(key_hex)
        except ValueError:
            return key_hex.encode("utf-8", "replace")

    def _load(self, conn: sqlite3.Connection, tenant: str) -> dict[str, _Rec]:
        rows = conn.execute(
            f"SELECT {', '.join(_COLUMNS)} FROM findings WHERE tenant = ?",  # noqa: S608
            (tenant,),
        ).fetchall()
        return {str(r[0]): _Rec.from_row(r) for r in rows}

    def _subject_hash(self, tenant: str, subject: str) -> str:
        message = (tenant + "\x1f" + subject).encode("utf-8", "surrogatepass")
        return hmac.new(self._subject_key, message, hashlib.sha256).hexdigest()[:32]


# ---- helpers -------------------------------------------------------------------------------------------------

_CONTROL_RE = re.compile("[\x00-\x08\x0b-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]")
# user info runs to the LAST '@' before the path (a raw password may contain '@'), then host[:port]
_URL_RE = re.compile(r"(?i)\b([a-z][a-z0-9+.-]{1,15})://([^\s/?#]*@)?([^\s/?#@]+)[^\s]*")
_SAFE_STRING = re.compile(
    r"^(?:\d{1,12}"  # rule ids, event codes, counts as text
    r"|\d+(?:\.\d+)?\s?[smhdw](?:\s\d+[smhdw])*"  # durations ("3h", "1d 2h")
    r"|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$"  # rule UUIDs
)
_SUMMARY_MAX = 2048
_HEARTBEAT_RETENTION_S = 90 * 86400
_FUTURE_TOLERANCE_S = 3600  # a run dated further ahead of the wall clock never makes later runs stale


def _aware(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("datetimes must be timezone-aware")
    return value.astimezone(UTC)


def _dt(epoch: int) -> datetime:
    return datetime.fromtimestamp(epoch, tz=UTC)


def _opt_dt(epoch: int | None) -> datetime | None:
    return None if epoch is None else _dt(epoch)


def _opt_int(value: Any) -> int | None:
    return None if value is None else int(value)


def _severity(value: Any) -> Severity:
    try:
        return Severity(str(value))
    except ValueError:
        return Severity.MEDIUM


def _severity_or_none(value: Any) -> Severity | None:
    if value is None:
        return None
    try:
        return Severity(str(value))
    except ValueError:
        return None


def _severity_rank(value: Any) -> int | None:
    """Rank of a stored severity; None when unknown (never notified, or a row from before escalation tracking)."""
    severity = _severity_or_none(value)
    return None if severity is None else severity.rank


def _phase(status: str) -> str | None:
    if status in ACTIVE_STATUSES:
        return _PHASE_ACTIVE
    if status == RESOLVED:
        return _PHASE_RESOLVED
    return None


def _short(text: str, limit: int) -> str:
    cleaned = _CONTROL_RE.sub(" ", text)
    return cleaned if len(cleaned) <= limit else cleaned[: limit - 1] + "…"


def _counts(
    records: Mapping[str, _Rec],
    present: Mapping[str, Finding],
    accepted_now: Mapping[str, AcceptEntry],
    suppressed: int,
    not_assessed: int,
    ignored: int,
) -> dict[str, int]:
    counts: dict[str, int] = {
        "findings": len(present),
        "open": 0,
        "pending": 0,
        "accepted": len(accepted_now),
        "flapping": 0,
        "suppressed": suppressed,
        "not_assessed": not_assessed,
        "ignored": ignored,
    }
    for sev in Severity:
        counts["open." + sev.value] = 0
    for fp, rec in records.items():
        if rec.status in ACTIVE_STATUSES:
            counts["open"] += 1
            counts["open." + rec.severity.value] += 1
        elif rec.status == NEW and fp in present:
            counts["pending"] += 1
        if rec.flapping:
            counts["flapping"] += 1
    return counts


def _transition(
    kind: str, rec: _Rec, *, detail: Message | None, entry: AcceptEntry | None, previous: Severity | None = None
) -> Transition:
    return Transition(
        type=kind,
        fingerprint=rec.fingerprint,
        kind=rec.kind,
        domain=rec.domain,
        severity=rec.severity,
        status=rec.status,
        summary=_summary_message(rec.summary, rec.kind),
        first_seen=_dt(rec.first_seen),
        opened_at=_opt_dt(rec.opened_at),
        resolved_at=_opt_dt(rec.resolved_at),
        flapping=rec.flapping,
        detail=detail,
        accept_id=entry.id if entry is not None else None,
        accept_expires=entry.expires if entry is not None else None,
        previous_severity=previous,
    )


def _unmatched_acceptance(entry: AcceptEntry) -> Transition:
    kind = entry.kind or ""
    domain = kind.split(".", 1)[0] if kind.split(".", 1)[0] in DOMAINS else ""
    message = M(
        "state.accept.expired_unmatched",
        index=entry.index,
        owner=Entity("user", entry.owner),
        expires=entry.expires_label(),
    )
    return Transition(
        type=ACCEPTANCE_EXPIRED,
        fingerprint=entry.fingerprint or "",
        kind=kind,
        domain=domain,
        severity=Severity.MEDIUM,
        status="",
        summary=message,
        detail=None,
        accept_id=entry.id,
        accept_expires=entry.expires,
    )


def _state(tenant: str, rec: _Rec) -> FindingState:
    return FindingState(
        tenant=tenant,
        fingerprint=rec.fingerprint,
        kind=rec.kind,
        domain=rec.domain,
        subject_hash=rec.subject_hash,
        severity=rec.severity,
        status=rec.status,
        first_seen=_dt(rec.first_seen),
        last_seen=_dt(rec.last_seen),
        opened_at=_opt_dt(rec.opened_at),
        resolved_at=_opt_dt(rec.resolved_at),
        consecutive_bad=rec.consecutive_bad,
        consecutive_good=rec.consecutive_good,
        times_opened=rec.times_opened,
        regressions=rec.regressions,
        flapping=rec.flapping,
        last_notified_at=_opt_dt(rec.last_notified_at),
        accepted_until=_opt_dt(rec.accepted_until),
        summary=_summary_message(rec.summary, rec.kind),
    )


# ---- PII-free summaries --------------------------------------------------------------------------------------


def _safe_param(name: str, value: Any, depth: int) -> Any:
    """Keep only values that cannot identify anyone: numbers, booleans, ids/durations, nested templates."""
    if isinstance(value, Entity):
        return {"e": _short(re.sub(r"[^a-z_]", "", value.kind.lower()) or "val", 16)}
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, Message) and depth < 3:
        return {"m": _message_dict(value, depth + 1)}
    if isinstance(value, str) and _SAFE_STRING.match(value):
        return value
    return {"r": _short(re.sub(r"[^A-Za-z0-9_]", "", name) or "value", 32)}


def _message_dict(msg: Message, depth: int) -> dict[str, Any]:
    return {
        "k": msg.key[:128],
        "p": {str(k)[:32]: _safe_param(str(k), v, depth) for k, v in list(msg.params.items())[:16]},
        # the fallback template is code, but scrub it anyway: state must never hold an IP or e-mail
        "d": None if msg.default is None else _short(Redactor(secrets.token_bytes(32)).text(msg.default[:300]), 300),
    }


def _summary_json(finding: Finding) -> str:
    """Title template + safe parameters. Plain-string titles are not stored (they may embed raw values)."""
    title = finding.title
    data: dict[str, Any] = {"m": _message_dict(title, 0)} if isinstance(title, Message) else {"t": finding.kind}
    text = json.dumps(data, ensure_ascii=True, separators=(",", ":"), allow_nan=False)
    if len(text) > _SUMMARY_MAX and isinstance(title, Message):
        text = json.dumps({"m": {"k": title.key[:128], "p": {}, "d": None}}, separators=(",", ":"))
    return text


def _restore(value: Any, depth: int) -> Any:
    if isinstance(value, dict):
        if "e" in value:
            return "[" + str(value["e"]) + "]"
        if "r" in value:
            return "[" + str(value["r"]) + "]"
        if "m" in value and depth < 4:
            return _message_from_dict(value["m"], depth + 1)
        return "[…]"
    return value


def _message_from_dict(data: Any, depth: int = 0) -> Message | str:
    if not isinstance(data, dict) or not isinstance(data.get("k"), str):
        return "[…]"
    params = data.get("p") if isinstance(data.get("p"), dict) else {}
    default = data.get("d") if isinstance(data.get("d"), str) else None
    assert isinstance(params, dict)
    return Message(data["k"], {str(k): _restore(v, depth) for k, v in params.items()}, default)


def _summary_message(summary: str, kind: str) -> Message | str:
    """Rebuild the stored placeholder title (``[host] stopped sending…``); falls back to the kind."""
    try:
        data = json.loads(summary)
    except (ValueError, TypeError):
        return kind
    if isinstance(data, dict) and "m" in data:
        return _message_from_dict(data["m"])
    return kind


def _scrub_detail(detail: Message | str) -> str:
    """Heartbeat detail without secrets or identifiers."""
    text = render(detail, "en", lambda e: "[" + e.kind + "]") if isinstance(detail, Message) else str(detail)
    text = _URL_RE.sub(_url_origin, _CONTROL_RE.sub(" ", text))
    text = Redactor(secrets.token_bytes(32)).text(text)
    return _short(text, 300)


def _url_origin(match: re.Match[str]) -> str:
    """``https://user:pw@host:9200/path?token=x`` -> ``https://host:9200/…`` (credentials, path, query dropped)."""
    origin = match.group(1) + "://" + match.group(3)
    return origin + "/…" if len(match.group(0)) > len(origin) + len(match.group(2) or "") else origin


def _ensure_private_dir(directory: Path) -> None:
    """Create missing directories with mode 0700 (existing directories are left untouched)."""
    missing: list[Path] = []
    current = directory
    while not current.exists():
        missing.append(current)
        if current.parent == current:
            break
        current = current.parent
    for path in reversed(missing):
        try:
            path.mkdir(mode=0o700)
        except FileExistsError:
            continue
        os.chmod(path, 0o700)


def _check_private_dir(directory: Path) -> None:
    """Refuse a state directory other users can write to or that belongs to someone else.

    Whoever can create entries next to the database can plant a symlink named like the database or its
    ``-wal``/``-shm`` files and make hushwatch overwrite (or chmod) a file of their choosing, or read the state.
    The sticky bit does not help (it only protects deletion), so ``/tmp``-like directories are refused too.
    """
    if os.name != "posix":
        return
    st = os.stat(directory)
    shown = Entity("file", str(directory))
    if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise StateError(M("state.error.shared_dir", path=shown))
    uid = os.geteuid()
    if st.st_uid not in (uid, 0):
        raise StateError(M("state.error.foreign_dir", path=shown))


def _check_not_link(path: Path) -> None:
    """Refuse an existing symlink or non-regular file where SQLite will open or create a file."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return
    if not stat.S_ISREG(st.st_mode):
        raise StateError(M("state.error.not_regular", path=Entity("file", str(path))))


def _ensure_private_file(path: Path) -> None:
    """Create the database file 0600 (never through a symlink) or tighten an existing regular file."""
    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError:
        _check_not_link(path)
        _tighten(path)
        return
    try:
        _fchmod(fd, path, 0o600)
    finally:
        os.close(fd)


def _fchmod(fd: int, path: Path, mode: int) -> None:
    """chmod through the open descriptor (no symlink race); plain chmod where fchmod does not exist."""
    fchmod = getattr(os, "fchmod", None)
    if fchmod is not None:
        fchmod(fd, mode)
    else:  # pragma: no cover - Windows before Python 3.13
        os.chmod(path, mode)


def _tighten(path: Path) -> None:
    """chmod 0600 a regular file that is group/other accessible; never touches a symlink.

    Deliberately ``lstat`` + ``chmod`` and NOT open + ``fchmod``: closing any descriptor of a file drops every
    POSIX lock this process holds on it, and SQLite's locks on the database and its ``-shm`` would be lost (another
    process then re-initializes the shared WAL index under our feet: SIGBUS / corruption). The symlink-swap race
    between the two calls needs write access to the directory, which :func:`_check_private_dir` rules out.
    """
    try:
        st = os.lstat(path)
    except OSError:
        return
    if stat.S_ISREG(st.st_mode) and st.st_mode & 0o077:
        with contextlib.suppress(OSError):
            os.chmod(path, 0o600)


__all__ = [
    "ACCEPT_FILENAME",
    "DEFAULT_IMMEDIATE_KINDS",
    "STATE_FILENAME",
    "STATE_SCHEMA_VERSION",
    "TRANSITION_TYPES",
    "AcceptEntry",
    "AcceptFileError",
    "AcceptList",
    "FindingState",
    "HeartbeatRecord",
    "RunOutcome",
    "RunRecord",
    "StateError",
    "StateStore",
    "Transition",
    "load_accept_file",
    "parse_accept",
]
