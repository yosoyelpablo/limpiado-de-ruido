"""Coverage and agent health: the gaps that baseline learning can never see.

Silence detection only notices sources that used to work. This module finds what was never collected at all,
by comparing every host with its peers and with explicit telemetry contracts, and cross-checks the Wazuh API
agent inventory against the data:

* **Peer groups** — within a platform (and, with the Wazuh API, a platform + agent group) of at least
  ``MIN_PEER_GROUP`` reporting hosts, a log source sent by >= ``silence.peer_coverage`` of the peers but never by
  a host is a gap (``coverage.missing_source``). Distro-equivalent Linux sources (``/var/log/auth.log`` /
  ``/var/log/secure`` / ``journald``) count as the same source.
* **Expectation contracts** (``tenant.expectations``) — hosts matching ``platform`` / ``groups`` / ``name`` glob
  must send the listed log sources at >= ``min_events_per_day``; missing, stopped or thin sources are findings
  that name the contract.
* **Event types** — Windows Security 4624 flowing without 4688 (process-creation auditing off), Sysmon without
  EventID 1 / 3, PowerShell Operational without 4104 (``coverage.missing_event_type``). An event type that
  *stopped* while its channel keeps flowing is a possible audit-policy change (MITRE T1562.002).
* **Agent health** (Wazuh API) — disconnected beyond the tier SLA, never connected, connected but sending nothing
  (collection broken), plus agent-side buffer overflows seen in the data (Wazuh rules 202-204). These are
  ``pipeline.*`` findings. Agents disconnected for more than ``STALE_AGENT_DAYS`` are reported as probable stale
  enrollments (one severity step lower); agents enrolled less than one SLA ago get a grace period.

Everything is judged conservatively ("the tool must not become noise"): a host is flagged only when, at its peers'
typical (lower-quartile) rate, it would have sent at least ``MIN_EXPECTED_EVENTS`` events while it was reporting
other data *and* the peers were sending that source. Gaps are grouped by root cause (one finding per peer group x
source x tier; one finding per agent symptom x tier once ``AGENT_GROUP_MIN`` agents share it). A grouped finding
lists every host in its evidence, critical-tier hosts first and never cut. Whatever the data cannot support is listed
under ``not_assessed`` in the section, never reported as OK.

Absence is weak evidence on alerts-only data (events below the alert level are invisible) and on incomplete or
sampled input: there, gaps inferred from absence carry ``Confidence.LOW`` and never exceed MEDIUM, contract event
rates are not judged, and a source or event type only "stopped" if its own history makes the silence implausible.

The Wazuh manager itself (agent ``000``) and syslog devices relayed through it are excluded from peer groups and
agent-status checks: their log sources are decided by the relay path, not by host configuration. Contracts bind
relayed devices only when they select them by name or with ``platform: network``.
"""

from __future__ import annotations

import fnmatch
import functools
import math
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from ..config import Expectation, TenantConfig
from ..i18n import Entity, M, Message, register
from ..inventory import AgentInfo
from ..models import Confidence, DataBasis, Event, Finding, Severity, fingerprint, get_path, sort_findings
from ..timeutil import UTC, humanize, iso

__all__ = [
    "MIN_EXPECTED_EVENTS",
    "MIN_PEER_GROUP",
    "WATCH_CODES",
    "AgentStats",
    "CoverageCollector",
    "CoverageResult",
    "SourceStats",
    "analyze_coverage",
    "platform_family",
]

# ---- tunables ---------------------------------------------------------------------------------------------------

MIN_PEER_GROUP = 5  # hosts (including the one judged) a peer group needs before gaps are inferred
MIN_EXPECTED_EVENTS = 10.0  # a host must have been expected to send >= this many events of the missing source
STOPPED_MIN_EVENTS = 20  # an event type needs this much history before "it stopped" can be claimed
STOPPED_MIN_EXPECTED = 20.0  # ... and this many expected events in the gap
MIN_OBSERVED_DAYS = 1.0  # contract checks need a host observed for at least one full day
NEVER_SEEN_MIN_WINDOW_DAYS = 7.0  # alerts-only basis: an active agent silent for this long is worth a look
FRESH_KEEPALIVE_S = 3600.0  # "keepalive fresh" for the alive-but-no-data cross-check
API_DATA_MAX_SKEW_S = 2 * 3600.0  # data and API snapshot must describe the same moment for the cross-check
DAY_S = 86400.0
MAX_NAME_LEN = 256
MAX_LOG_SOURCE_LEN = 512
MAX_CODE_LEN = 16
MAX_PLATFORMS_PER_AGENT = 8
MAX_AGENT_IDS = 4
MAX_ACTIVE_DAYS = 400  # days of hour-activity masks kept per host (observation spans resist clock outliers)
MATRIX_MAX_ROWS = 300
MATRIX_MAX_COLUMNS = 40
EVIDENCE_MAX_HOSTS = 50
EVIDENCE_MAX_CRITICAL = 1000  # critical-tier hosts are never dropped from a grouped finding's evidence
MESSAGE_MAX_HOSTS = 10
SECTION_MAX_ITEMS = 100
AGENT_GROUP_MIN = 5  # this many agents with the same symptom (and tier) become one grouped finding
STALE_AGENT_DAYS = 30.0  # disconnected longer than this: decommissioned host or stale enrollment
MASS_DISCONNECT_SHARE = 0.5  # this share of the agents disconnected at once points to a shared cause
# Fallback when the tenant's ``sla`` mapping omits a tier (a partial override must never loosen a critical SLA).
DEFAULT_SLA: dict[str, timedelta] = {
    "critical": timedelta(hours=4),
    "standard": timedelta(hours=24),
    "low": timedelta(hours=72),
}

# Windows EventIDs / Sysmon EventIDs always tracked per (agent, log source), whatever the per-source cap.
WATCH_CODES: frozenset[str] = frozenset(
    {
        # Windows Security: logon, process, service, task, account, policy, log clearing
        "4624", "4625", "4634", "4648", "4672", "4688", "4689", "4697", "4698", "4702", "4719", "4720",
        "4722", "4724", "4726", "4728", "4732", "4738", "4740", "4756", "4768", "4769", "4771", "4776",
        "4906", "1100", "1102", "104", "7036", "7040", "7045",
        # PowerShell
        "4103", "4104", "400", "800",
        # Sysmon
        "1", "2", "3", "4", "5", "6", "7", "8", "10", "11", "12", "13", "15", "16", "17", "22", "23", "25",
    }
)  # fmt: skip

# Wazuh agent buffer (anti-flooding) rules: 202 = N% full, 203 = full (events lost), 204 = flooded.
FLOODING_RULES: frozenset[str] = frozenset({"202", "203", "204"})
_FLOODING_LOSS = frozenset({"203", "204"})

_TIER_RANK = {"critical": 0, "standard": 1, "low": 2}
# Missing / thin sources: a blind spot, but not an active outage.
_SEV_GAP = {"critical": Severity.HIGH, "standard": Severity.MEDIUM, "low": Severity.LOW}
# Something that worked and stopped, or an agent that is down: active blindness.
_SEV_BLIND = {"critical": Severity.CRITICAL, "standard": Severity.HIGH, "low": Severity.MEDIUM}

_LINUX_PLATFORMS = frozenset(
    {
        "linux", "ubuntu", "debian", "centos", "centos stream", "rhel", "redhat", "red hat", "fedora", "amzn",
        "amazon", "sles", "sled", "suse", "opensuse", "opensuse-leap", "opensuse-tumbleweed", "arch", "alpine",
        "ol", "oracle", "rocky", "almalinux", "alma", "gentoo", "raspbian", "kali", "linuxmint", "mint",
        "manjaro", "photon", "coreos", "rhcos", "clear-linux-os", "virtuozzo", "scientific", "cloudlinux",
        "slackware", "void", "nixos", "pop", "elementary", "zorin", "deepin", "mageia", "openeuler",
        "euleros", "kylin", "uos", "tencentos", "anolis", "bottlerocket", "flatcar",
    }
)  # fmt: skip
_DARWIN_PLATFORMS = frozenset({"darwin", "macos", "mac", "osx", "mac os x", "macosx", "mac os"})

# Distro-equivalent Linux sources: a host that sends any member satisfies the class.
_PEER_CLASSES: dict[str, tuple[str, ...]] = {
    "/var/log/auth.log": ("class:linux-auth",),
    "/var/log/secure": ("class:linux-auth",),
    "/var/log/syslog": ("class:linux-syslog",),
    "/var/log/messages": ("class:linux-syslog",),
    "journald": ("class:linux-auth", "class:linux-syslog"),
}
_CLASS_LABELS = {
    "class:linux-auth": "/var/log/auth.log | /var/log/secure | journald",
    "class:linux-syslog": "/var/log/syslog | /var/log/messages | journald",
}

register(
    {
        "coverage.tier.critical": {"en": "critical", "es": "crítico"},
        "coverage.tier.standard": {"en": "standard", "es": "estándar"},
        "coverage.tier.low": {"en": "low", "es": "bajo"},
        "coverage.reason.hosts": {"en": "Affected hosts: {hosts}.", "es": "Equipos afectados: {hosts}."},
        "coverage.reason.hosts_more": {
            "en": "Affected hosts: {hosts} and {more} more.",
            "es": "Equipos afectados: {hosts} y {more} más.",
        },
        "coverage.reason.alerts_basis": {
            "en": "Measured on alerts only: events that never trigger a rule at or above the alert level are "
            "invisible here, so confirm on the host before acting.",
            "es": "Medido solo sobre alertas: los eventos que nunca disparan una regla con nivel suficiente son "
            "invisibles aquí; confírmelo en el equipo antes de actuar.",
        },
        "coverage.reason.incomplete_basis": {
            "en": "The input is incomplete or sampled (partial failures, caps or sampling): the missing events may "
            "simply not have been read, so confirm on the host before acting.",
            "es": "La entrada está incompleta o muestreada (fallos parciales, límites o muestreo): puede que los "
            "eventos ausentes simplemente no se hayan leído; confírmelo en el equipo antes de actuar.",
        },
        "coverage.reason.critical_hosts": {
            "en": "Critical-tier hosts affected: {hosts}.",
            "es": "Equipos de nivel crítico afectados: {hosts}.",
        },
        # peer groups -------------------------------------------------------------------------------------------
        "coverage.peer.title.one": {
            "en": "{host} does not send {log_source}, which {share:.0%} of its {platform} peers send",
            "es": "{host} no envía {log_source}, que sí envía el {share:.0%} de sus pares {platform}",
        },
        "coverage.peer.title.many": {
            "en": "{log_source} is missing on {missing} {platform} hosts ({tier} tier) although their peers send it",
            "es": "Falta {log_source} en {missing} equipos {platform} (nivel {tier}) aunque sus pares lo envían",
        },
        "coverage.peer.reason.share": {
            "en": "{senders} of the {peers} other reporting hosts in peer group '{group}' send {log_source} "
            "({share:.0%}; threshold {threshold:.0%}).",
            "es": "{senders} de los otros {peers} equipos que reportan en el grupo de pares '{group}' envían "
            "{log_source} ({share:.0%}; umbral {threshold:.0%}).",
        },
        "coverage.peer.reason.expected": {
            "en": "At the peers' typical rate each affected host would have sent at least {expected:.0f} events "
            "from this source while it was reporting other data; it sent none.",
            "es": "Al ritmo habitual de sus pares, cada equipo afectado habría enviado al menos {expected:.0f} "
            "eventos de esta fuente mientras reportaba otros datos; no envió ninguno.",
        },
        "coverage.peer.recommendation": {
            "en": "Check that the source is installed and enabled on these hosts and that the agent configuration "
            "(localfile / agent group) collects it.",
            "es": "Verifique que la fuente esté instalada y habilitada en estos equipos y que la configuración del "
            "agente (localfile / grupo de agentes) la recolecte.",
        },
        # contracts ---------------------------------------------------------------------------------------------
        "coverage.contract.title.missing.one": {
            "en": "{host} does not send {log_source}, required by contract '{contract}'",
            "es": "{host} no envía {log_source}, exigido por el contrato '{contract}'",
        },
        "coverage.contract.title.missing.many": {
            "en": "Contract '{contract}': {log_source} missing on {missing} of {matched} hosts ({tier} tier)",
            "es": "Contrato '{contract}': falta {log_source} en {missing} de {matched} equipos (nivel {tier})",
        },
        "coverage.contract.title.silent.one": {
            "en": "{host} stopped sending {log_source} (contract '{contract}') while still sending other data",
            "es": "{host} dejó de enviar {log_source} (contrato '{contract}') aunque sigue enviando otros datos",
        },
        "coverage.contract.title.silent.many": {
            "en": "Contract '{contract}': {log_source} stopped on {missing} hosts that still send other data "
            "({tier} tier)",
            "es": "Contrato '{contract}': {log_source} se detuvo en {missing} equipos que siguen enviando otros "
            "datos (nivel {tier})",
        },
        "coverage.contract.title.low.one": {
            "en": "{host} sends {log_source} below the {min_rate} events/day required by contract '{contract}'",
            "es": "{host} envía {log_source} por debajo de los {min_rate} eventos/día que exige el contrato "
            "'{contract}'",
        },
        "coverage.contract.title.low.many": {
            "en": "Contract '{contract}': {log_source} below {min_rate} events/day on {missing} hosts ({tier} tier)",
            "es": "Contrato '{contract}': {log_source} por debajo de {min_rate} eventos/día en {missing} equipos "
            "(nivel {tier})",
        },
        "coverage.contract.reason.match": {
            "en": "Contract '{contract}' applies to {matched} hosts matching {criteria}.",
            "es": "El contrato '{contract}' se aplica a {matched} equipos que cumplen {criteria}.",
        },
        "coverage.contract.reason.names": {
            "en": "Host name patterns of the contract: {names}.",
            "es": "Patrones de nombre de equipo del contrato: {names}.",
        },
        "coverage.contract.reason.missing": {
            "en": "No event from {log_source} was seen although these hosts reported other data for at least a "
            "full day.",
            "es": "No se vio ningún evento de {log_source} aunque estos equipos reportaron otros datos durante al "
            "menos un día completo.",
        },
        "coverage.contract.reason.silent": {
            "en": "No {log_source} event for longer than {quiet} before the end of the data, while the hosts kept "
            "sending other events.",
            "es": "Ningún evento de {log_source} durante más de {quiet} antes del final de los datos, mientras "
            "los equipos seguían enviando otros eventos.",
        },
        "coverage.contract.reason.low": {
            "en": "Lowest observed rate {rate:.2f} events/day; the contract requires at least {min_rate}.",
            "es": "Tasa observada más baja: {rate:.2f} eventos/día; el contrato exige al menos {min_rate}.",
        },
        "coverage.contract.recommendation": {
            "en": "Enable collection of the required source on these hosts, or fix the contract if the expectation "
            "is wrong.",
            "es": "Habilite la recolección de la fuente exigida en estos equipos, o corrija el contrato si la "
            "expectativa es incorrecta.",
        },
        # event types -------------------------------------------------------------------------------------------
        "coverage.event_type.name.win_4688": {
            "en": "process creation (Security 4688)",
            "es": "creación de procesos (Security 4688)",
        },
        "coverage.event_type.name.sysmon_1": {
            "en": "Sysmon process creation (EventID 1)",
            "es": "creación de procesos de Sysmon (EventID 1)",
        },
        "coverage.event_type.name.sysmon_3": {
            "en": "Sysmon network connection (EventID 3)",
            "es": "conexión de red de Sysmon (EventID 3)",
        },
        "coverage.event_type.name.ps_4104": {
            "en": "PowerShell script block (4104)",
            "es": "bloque de script de PowerShell (4104)",
        },
        "coverage.event_type.title.one": {
            "en": "{host} sends no {event_type} events: its logging setting appears to be off",
            "es": "{host} no envía eventos de {event_type}: su configuración de registro parece desactivada",
        },
        "coverage.event_type.title.many": {
            "en": "{missing} Windows hosts ({tier} tier) send no {event_type} events: logging appears to be off",
            "es": "{missing} equipos Windows (nivel {tier}) no envían eventos de {event_type}: el registro parece "
            "desactivado",
        },
        "coverage.event_type.reason.win_4688": {
            "en": "Security logons (4624) arrive but process creation events (4688) never do, while {share:.0%} of "
            "{peers} comparable Windows peers send them. Rules that depend on 4688 are blind there.",
            "es": "Llegan inicios de sesión de Security (4624) pero nunca eventos de creación de procesos (4688), "
            "mientras que los envía el {share:.0%} de {peers} pares Windows comparables. Las reglas que dependen de "
            "4688 están ciegas allí.",
        },
        "coverage.event_type.reason.sysmon_1": {
            "en": "The Sysmon channel is collected but EventID 1 never appears, while {share:.0%} of {peers} peers "
            "with Sysmon send it: the Sysmon configuration probably excludes process creation.",
            "es": "El canal de Sysmon se recolecta pero el EventID 1 nunca aparece, mientras que lo envía el "
            "{share:.0%} de {peers} pares con Sysmon: la configuración de Sysmon probablemente excluye la "
            "creación de procesos.",
        },
        "coverage.event_type.reason.sysmon_3": {
            "en": "The Sysmon channel is collected but EventID 3 never appears, while {share:.0%} of {peers} peers "
            "with Sysmon send it: the Sysmon configuration probably excludes network connections.",
            "es": "El canal de Sysmon se recolecta pero el EventID 3 nunca aparece, mientras que lo envía el "
            "{share:.0%} de {peers} pares con Sysmon: la configuración de Sysmon probablemente excluye las "
            "conexiones de red.",
        },
        "coverage.event_type.reason.ps_4104": {
            "en": "The PowerShell Operational channel is collected but 4104 never appears, while {share:.0%} of "
            "{peers} peers send it: script block logging is probably off.",
            "es": "El canal PowerShell Operational se recolecta pero el 4104 nunca aparece, mientras que lo envía "
            "el {share:.0%} de {peers} pares: el registro de bloques de script probablemente está apagado.",
        },
        "coverage.event_type.recommendation.win_4688": {
            "en": "Enable 'Audit Process Creation' (Advanced Audit Policy > Detailed Tracking) and 'Include command "
            "line in process creation events' by GPO.",
            "es": "Habilite 'Auditar la creación de procesos' (Directiva de auditoría avanzada > Seguimiento "
            "detallado) e 'Incluir la línea de comandos en los eventos de creación de procesos' por GPO.",
        },
        "coverage.event_type.recommendation.sysmon_1": {
            "en": "Review the Sysmon configuration deployed on these hosts (ProcessCreate rules).",
            "es": "Revise la configuración de Sysmon desplegada en estos equipos (reglas ProcessCreate).",
        },
        "coverage.event_type.recommendation.sysmon_3": {
            "en": "Review the Sysmon configuration deployed on these hosts (NetworkConnect rules).",
            "es": "Revise la configuración de Sysmon desplegada en estos equipos (reglas NetworkConnect).",
        },
        "coverage.event_type.recommendation.ps_4104": {
            "en": "Enable 'Turn on PowerShell Script Block Logging' by GPO.",
            "es": "Habilite 'Activar el registro de bloques de script de PowerShell' por GPO.",
        },
        "coverage.event_type.stopped.title": {
            "en": "{host}: {event_type} events stopped {ago} before the end of the data while {channel} kept flowing",
            "es": "{host}: los eventos de {event_type} se detuvieron {ago} antes del final de los datos mientras "
            "{channel} seguía llegando",
        },
        "coverage.event_type.stopped.reason": {
            "en": "Before stopping it arrived at about {rate:.1f} events/day ({count} events), so about "
            "{expected:.0f} were expected since. A policy or Sysmon configuration change can be benign, but it is "
            "also how attackers blind defenders (MITRE T1562.002).",
            "es": "Antes de detenerse llegaba a unos {rate:.1f} eventos/día ({count} eventos), así que desde "
            "entonces se esperaban unos {expected:.0f}. Un cambio de directiva o de configuración de Sysmon puede "
            "ser legítimo, pero también es como un atacante ciega a los defensores (MITRE T1562.002).",
        },
        "coverage.event_type.stopped.alerts_caveat": {
            "en": "Measured on alerts only: a tuned, disabled or overwritten rule produces the same picture, so check "
            "recent ruleset changes too.",
            "es": "Medido solo sobre alertas: una regla ajustada, deshabilitada o sobrescrita produce el mismo "
            "cuadro, así que revise también los cambios recientes del ruleset.",
        },
        "coverage.event_type.stopped.fleet.title": {
            "en": "{event_type} events stopped on {count} of {total} hosts while their channels kept flowing",
            "es": "Los eventos de {event_type} se detuvieron en {count} de {total} equipos mientras sus canales "
            "seguían llegando",
        },
        "coverage.event_type.stopped.fleet.reason": {
            "en": "The same event type stopped on many hosts: a fleet-wide change (GPO, Sysmon configuration rollout, "
            "or a rule / decoder change) is more likely than host-level tampering, but it blinds every rule that "
            "depends on it. Last seen between {first} and {last}.",
            "es": "El mismo tipo de evento se detuvo en muchos equipos: es más probable un cambio global (GPO, "
            "despliegue de configuración de Sysmon, o un cambio de regla o decodificador) que una manipulación en "
            "cada equipo, pero deja ciegas todas las reglas que dependen de él. Visto por última vez entre {first} "
            "y {last}.",
        },
        "coverage.event_type.stopped.recommendation": {
            "en": "Confirm with the host owner whether the change was authorized; look for audit policy changes "
            "(4719), Sysmon configuration changes (Sysmon 16) and the GPO history.",
            "es": "Confirme con el responsable del equipo si el cambio estaba autorizado; busque cambios de "
            "directiva de auditoría (4719), cambios de configuración de Sysmon (Sysmon 16) y el historial de GPO.",
        },
        # agent health (pipeline domain) ----------------------------------------------------------------------
        "coverage.agent.disconnected.title": {
            "en": "Agent {host} has been disconnected for {duration} (SLA {sla})",
            "es": "El agente {host} lleva {duration} desconectado (SLA {sla})",
        },
        "coverage.agent.disconnected.title_unknown": {
            "en": "Agent {host} is disconnected (last keepalive unknown)",
            "es": "El agente {host} está desconectado (último keepalive desconocido)",
        },
        "coverage.agent.pending.title": {
            "en": "Agent {host} has been stuck in 'pending' for {duration} (SLA {sla})",
            "es": "El agente {host} lleva {duration} en estado 'pending' (SLA {sla})",
        },
        "coverage.agent.disconnected.reason": {
            "en": "The Wazuh API reports status '{status}'; last keepalive {last_keepalive}. Nothing from this host "
            "reaches the SIEM meanwhile.",
            "es": "La API de Wazuh informa el estado '{status}'; último keepalive {last_keepalive}. Mientras "
            "tanto, nada de este equipo llega al SIEM.",
        },
        "coverage.agent.disconnected.recommendation": {
            "en": "Check that the host is up, that the agent service is running and that it can reach the manager "
            "(1514/tcp); decommission the agent if the host is gone.",
            "es": "Verifique que el equipo esté encendido, que el servicio del agente esté corriendo y que llegue al "
            "manager (1514/tcp); dé de baja el agente si el equipo ya no existe.",
        },
        "coverage.agent.stale.title": {
            "en": "Agent {host} has been disconnected for {duration}: decommissioned host or stale enrollment?",
            "es": "El agente {host} lleva {duration} desconectado: ¿equipo dado de baja o registro obsoleto?",
        },
        "coverage.agent.stale.recommendation": {
            "en": "If the host was retired, remove its agent enrollment so the inventory stays trustworthy; if it "
            "still exists, it has been invisible to the SIEM for weeks: reconnect it.",
            "es": "Si el equipo se retiró, elimine el registro de su agente para que el inventario siga siendo "
            "fiable; si todavía existe, lleva semanas invisible para el SIEM: vuelva a conectarlo.",
        },
        "coverage.agent.group.disconnected.title": {
            "en": "{count} agents ({tier} tier) have been disconnected for longer than their SLA ({sla})",
            "es": "{count} agentes (nivel {tier}) llevan desconectados más tiempo que su SLA ({sla})",
        },
        "coverage.agent.group.stale.title": {
            "en": "{count} agents ({tier} tier) have been disconnected for more than {days} days: decommissioned "
            "hosts or stale enrollments?",
            "es": "{count} agentes (nivel {tier}) llevan más de {days} días desconectados: ¿equipos dados de baja o "
            "registros obsoletos?",
        },
        "coverage.agent.group.pending.title": {
            "en": "{count} agents ({tier} tier) have been stuck in 'pending' for longer than their SLA ({sla})",
            "es": "{count} agentes (nivel {tier}) llevan en estado 'pending' más tiempo que su SLA ({sla})",
        },
        "coverage.agent.group.never_connected.title": {
            "en": "{count} agents ({tier} tier) are enrolled but have never connected",
            "es": "{count} agentes (nivel {tier}) están registrados pero nunca se conectaron",
        },
        "coverage.agent.group.no_data.title": {
            "en": "{count} connected agents ({tier} tier) sent no events: collection appears broken",
            "es": "{count} agentes conectados (nivel {tier}) no enviaron eventos: la recolección parece rota",
        },
        "coverage.agent.group.never_seen.title": {
            "en": "{count} inventory assets ({tier} tier) sent no events in the analyzed data",
            "es": "{count} activos del inventario (nivel {tier}) no enviaron eventos en los datos analizados",
        },
        "coverage.agent.group.flood_loss.title": {
            "en": "{count} agents ({tier} tier) overflowed their event buffer: events were probably lost",
            "es": "{count} agentes (nivel {tier}) desbordaron su buffer de eventos: probablemente se perdieron eventos",
        },
        "coverage.agent.group.flood_warn.title": {
            "en": "{count} agents ({tier} tier) have event buffers filling up",
            "es": "{count} agentes (nivel {tier}) tienen el buffer de eventos llenándose",
        },
        "coverage.agent.group.reason": {
            "en": "{count} agents show the same symptom, so they are reported once; every host is listed in the "
            "evidence with its own details.",
            "es": "{count} agentes muestran el mismo síntoma, así que se informan una sola vez; cada equipo figura "
            "en la evidencia con su propio detalle.",
        },
        "coverage.agent.group.reason.mass": {
            "en": "{count} of the {total} agents that have ever connected are disconnected beyond their SLA at the "
            "same time: a manager, network, firewall or certificate problem is more likely than separate host "
            "failures.",
            "es": "{count} de los {total} agentes que alguna vez se conectaron están desconectados más allá de su "
            "SLA al mismo tiempo: es más probable un problema del manager, de red, de firewall o de certificados "
            "que fallos independientes de cada equipo.",
        },
        "coverage.agent.never_connected.title": {
            "en": "Agent {host} is enrolled but has never connected",
            "es": "El agente {host} está registrado pero nunca se conectó",
        },
        "coverage.agent.never_connected.reason": {
            "en": "Enrolled on {date_add}; the manager has never received anything from it.",
            "es": "Registrado el {date_add}; el manager nunca recibió nada de él.",
        },
        "coverage.agent.never_connected.recommendation": {
            "en": "Install and start the agent on the host, or remove the stale enrollment.",
            "es": "Instale e inicie el agente en el equipo, o elimine el registro obsoleto.",
        },
        "coverage.agent.no_data.title": {
            "en": "Agent {host} is connected but sent no events for {duration}: collection appears broken",
            "es": "El agente {host} está conectado pero no envió eventos en {duration}: la recolección parece rota",
        },
        "coverage.agent.no_data.title_never": {
            "en": "Agent {host} is connected but sent no events in the analyzed data ({duration})",
            "es": "El agente {host} está conectado pero no envió eventos en los datos analizados ({duration})",
        },
        "coverage.agent.no_data.reason": {
            "en": "Last keepalive {last_keepalive} (status active), last event: {last_event}. The agent is "
            "alive, so the problem is log collection (localfile configuration, permissions, agent "
            "buffer), not connectivity.",
            "es": "Último keepalive {last_keepalive} (estado activo), último evento: {last_event}. El agente "
            "está vivo, así que el problema es la recolección de logs (configuración localfile, "
            "permisos, buffer del agente), no la conectividad.",
        },
        "coverage.agent.no_events": {"en": "none in the analyzed data", "es": "ninguno en los datos analizados"},
        "coverage.agent.no_data.alerts_caveat": {
            "en": "Measured on alerts only: a quiet host may legitimately produce no alerts; confirm with archives "
            "or the agent's logcollector statistics.",
            "es": "Medido solo sobre alertas: un equipo tranquilo puede no producir alertas legítimamente; "
            "confírmelo con los archives o las estadísticas de logcollector del agente.",
        },
        "coverage.agent.no_data.recommendation": {
            "en": "Inspect the agent's ossec.log and logcollector statistics and confirm its localfile configuration.",
            "es": "Revise el ossec.log del agente y las estadísticas de logcollector, y confirme su configuración "
            "localfile.",
        },
        "coverage.inventory.never_seen.title": {
            "en": "{host} is in the inventory but sent no events in the analyzed data",
            "es": "{host} está en el inventario pero no envió eventos en los datos analizados",
        },
        "coverage.inventory.never_seen.reason": {
            "en": "Inventory status '{status}'; the data covers {window}.",
            "es": "Estado en el inventario: '{status}'; los datos cubren {window}.",
        },
        "coverage.inventory.never_seen.recommendation": {
            "en": "Confirm that an agent is installed on this asset and that it reports to this SIEM.",
            "es": "Confirme que este activo tiene un agente instalado y que reporta a este SIEM.",
        },
        "coverage.flooding.title.loss": {
            "en": "Agent {host} event buffer overflowed: events were probably lost",
            "es": "El buffer de eventos del agente {host} se desbordó: probablemente se perdieron eventos",
        },
        "coverage.flooding.title.warn": {
            "en": "Agent {host} event buffer is filling up",
            "es": "El buffer de eventos del agente {host} se está llenando",
        },
        "coverage.flooding.reason": {
            "en": "Wazuh agent buffer rules fired: {rules} (alerts: {count}; last at {last}). 203/204 mean the "
            "agent-side queue was full or flooded and events were dropped before reaching the manager.",
            "es": "Reglas de buffer del agente de Wazuh disparadas: {rules} (alertas: {count}; última vez: {last}). "
            "203/204 significan que la cola del agente estaba llena o saturada y se descartaron eventos antes de "
            "llegar al manager.",
        },
        "coverage.flooding.recommendation": {
            "en": "Raise the agent's client_buffer limits (events_per_second, queue_size) or reduce noisy localfile "
            "sources on this host.",
            "es": "Aumente los límites de client_buffer del agente (events_per_second, queue_size) o reduzca las "
            "fuentes localfile ruidosas de este equipo.",
        },
    }
)


# ---- collection -------------------------------------------------------------------------------------------------


@dataclass(slots=True)
class SourceStats:
    """Per (agent, log source) counters. ``codes`` maps an event code to ``[count, first, last]`` (epoch s)."""

    count: int = 0
    first: float = math.inf
    last: float = -math.inf
    codes: dict[str, list[float]] = field(default_factory=dict)
    codes_overflow: int = 0

    def merge(self, other: SourceStats, max_codes: int) -> int:
        """Fold ``other`` in; returns how many codes did not fit under ``max_codes``."""
        self.count += other.count
        self.first = min(self.first, other.first)
        self.last = max(self.last, other.last)
        self.codes_overflow += other.codes_overflow
        dropped = 0
        for code, (count, first, last) in other.codes.items():
            rec = self.codes.get(code)
            if rec is None:
                if code in WATCH_CODES or len(self.codes) < max_codes:
                    self.codes[code] = [count, first, last]
                else:
                    dropped += 1
            else:
                rec[0] += count
                rec[1] = min(rec[1], first)
                rec[2] = max(rec[2], last)
        self.codes_overflow += dropped
        return dropped


@dataclass(slots=True)
class AgentStats:
    """What one host (``Event.source``) sent during the analyzed window."""

    name: str
    count: int = 0
    first: float = math.inf
    last: float = -math.inf
    platforms: dict[str, int] = field(default_factory=dict)  # platform family -> events
    sources: dict[str, SourceStats] = field(default_factory=dict)
    sources_overflow: int = 0
    agent_ids: set[str] = field(default_factory=set)
    manager_events: int = 0  # events of the Wazuh manager itself (agent 000)
    relayed_events: int = 0  # syslog events relayed through agent 000 (predecoder.hostname)
    flooding: dict[str, list[float]] = field(default_factory=dict)  # rule id -> [count, first, last]
    hours: dict[int, int] = field(default_factory=dict)  # UTC day index -> 24-bit mask of hours with events
    last_hour: int = -(10**9)

    @property
    def observed_days(self) -> float:
        """How long the host demonstrably sent data, in days: its active hours / 24, never more than first-to-last.
        Consistent for rates and expectations, and one event with a wrong clock cannot stretch it."""
        if self.count == 0:
            return 0.0
        elapsed = max(0.0, (self.last - self.first) / DAY_S)
        if not self.hours:
            return elapsed
        return min(elapsed, sum(mask.bit_count() for mask in self.hours.values()) / 24.0)

    @property
    def calendar_days(self) -> float:
        """Calendar span for per-day rates: first-to-last event, never more than the number of days with events."""
        if self.count == 0:
            return 0.0
        elapsed = max(0.0, (self.last - self.first) / DAY_S)
        return min(elapsed, float(len(self.hours))) if self.hours else elapsed

    @property
    def platform(self) -> str | None:
        """Most frequent platform family inferred from the events (ties broken alphabetically)."""
        if not self.platforms:
            return None
        return min(self.platforms.items(), key=lambda item: (-item[1], item[0]))[0]

    @property
    def is_manager(self) -> bool:
        return self.manager_events * 2 > self.count

    @property
    def is_relayed(self) -> bool:
        return not self.is_manager and self.relayed_events * 2 > self.count


class CoverageCollector:
    """Single-pass collector: per agent, the platform, log sources (count / first / last seen) and the event codes
    seen per log source (bounded: the Windows/Sysmon codes in ``WATCH_CODES`` are always kept, others up to
    ``max_codes_per_source``). Caps are reported through :attr:`truncated`, never silently."""

    def __init__(
        self,
        tenant: TenantConfig,
        *,
        max_agents: int = 50_000,
        max_sources_per_agent: int = 256,
        max_codes_per_source: int = 64,
    ) -> None:
        self.tenant = tenant
        self.max_agents = max_agents
        self.max_sources_per_agent = max_sources_per_agent
        self.max_codes_per_source = max_codes_per_source
        self.agents: dict[str, AgentStats] = {}
        self.events = 0
        self.raw_events = 0  # events without a rule id: archives / raw logs (full fidelity)
        self.unattributed = 0  # events without a usable source host
        self.first = math.inf
        self.last = -math.inf
        self.agents_overflow = 0  # events dropped because max_agents was reached
        self.sources_overflow = 0
        self.codes_overflow = 0

    @property
    def truncated(self) -> bool:
        """True when a cap was hit (agents or log sources; code overflow only loses non-watched codes)."""
        return self.agents_overflow > 0 or self.sources_overflow > 0

    def add(self, event: Event) -> None:
        """Account one event."""
        self.events += 1
        if event.rule_id is None:
            self.raw_events += 1
        source = event.source
        if not isinstance(source, str) or not source:
            self.unattributed += 1
            return
        raw_source = source
        if len(source) > MAX_NAME_LEN:
            source = source[:MAX_NAME_LEN]
        try:
            ts = event.ts.timestamp()
        except (AttributeError, OverflowError, OSError, ValueError):
            self.unattributed += 1
            return
        stats = self.agents.get(source)
        if stats is None:
            if len(self.agents) >= self.max_agents:
                self.agents_overflow += 1
                return
            stats = self.agents[source] = AgentStats(source)
        if ts < self.first:
            self.first = ts
        if ts > self.last:
            self.last = ts
        stats.count += 1
        if ts < stats.first:
            stats.first = ts
        if ts > stats.last:
            stats.last = ts
        hour = int(ts // 3600.0)
        if hour != stats.last_hour:
            stats.last_hour = hour
            day, bit = divmod(hour, 24)
            mask = stats.hours.get(day)
            if mask is not None:
                stats.hours[day] = mask | (1 << bit)
            elif len(stats.hours) < MAX_ACTIVE_DAYS:
                stats.hours[day] = 1 << bit

        platform = event.os_platform
        if isinstance(platform, str) and platform:
            family = platform_family(platform)
            if family is not None and (family in stats.platforms or len(stats.platforms) < MAX_PLATFORMS_PER_AGENT):
                stats.platforms[family] = stats.platforms.get(family, 0) + 1

        fields = event.fields
        if fields:
            self._agent_identity(stats, fields, raw_source)

        log_source = event.log_source
        if isinstance(log_source, str) and log_source:
            if len(log_source) > MAX_LOG_SOURCE_LEN:
                log_source = log_source[:MAX_LOG_SOURCE_LEN]
            src = stats.sources.get(log_source)
            if src is None:
                if len(stats.sources) >= self.max_sources_per_agent:
                    stats.sources_overflow += 1
                    self.sources_overflow += 1
                else:
                    src = stats.sources[log_source] = SourceStats()
            if src is not None:
                src.count += 1
                if ts < src.first:
                    src.first = ts
                if ts > src.last:
                    src.last = ts
                code = _norm_code(event.event_code)
                if code is not None:
                    rec = src.codes.get(code)
                    if rec is None:
                        if code in WATCH_CODES or len(src.codes) < self.max_codes_per_source:
                            src.codes[code] = [1.0, ts, ts]
                        else:
                            src.codes_overflow += 1
                            self.codes_overflow += 1
                    else:
                        rec[0] += 1.0
                        if ts < rec[1]:
                            rec[1] = ts
                        if ts > rec[2]:
                            rec[2] = ts

        rule_id = event.rule_id
        if (
            isinstance(rule_id, str)
            and rule_id in FLOODING_RULES
            and (not event.rule_groups or "agent_flooding" in event.rule_groups)
        ):
            flood = stats.flooding.get(rule_id)
            if flood is None:
                stats.flooding[rule_id] = [1.0, ts, ts]
            else:
                flood[0] += 1.0
                flood[1] = min(flood[1], ts)
                flood[2] = max(flood[2], ts)

    @staticmethod
    def _agent_identity(stats: AgentStats, fields: Mapping[str, Any], source: str) -> None:
        agent_id = fields.get("agent.id")
        if agent_id is None:
            if "agent" not in fields:
                return
            agent_id = get_path(fields, "agent.id")
        if isinstance(agent_id, bool) or not isinstance(agent_id, (str, int)):
            return
        aid = str(agent_id)
        if aid == "000":
            # The manager's own events carry its hostname as agent.name; syslog relayed through the manager
            # carries the device hostname (predecoder.hostname) as the source instead.
            if _field(fields, "agent.name") == source:
                stats.manager_events += 1
            else:
                stats.relayed_events += 1
        elif len(stats.agent_ids) < MAX_AGENT_IDS and 0 < len(aid) <= 64:
            stats.agent_ids.add(aid)

    def merge(self, other: CoverageCollector) -> None:
        """Fold ``other`` (e.g. built in parallel from another file) into this collector."""
        self.events += other.events
        self.raw_events += other.raw_events
        self.unattributed += other.unattributed
        self.first = min(self.first, other.first)
        self.last = max(self.last, other.last)
        self.agents_overflow += other.agents_overflow
        self.sources_overflow += other.sources_overflow
        self.codes_overflow += other.codes_overflow
        for name, theirs in other.agents.items():
            mine = self.agents.get(name)
            if mine is None:
                if len(self.agents) >= self.max_agents:
                    self.agents_overflow += theirs.count
                    continue
                mine = self.agents[name] = AgentStats(name)
            mine.count += theirs.count
            mine.first = min(mine.first, theirs.first)
            mine.last = max(mine.last, theirs.last)
            mine.manager_events += theirs.manager_events
            mine.relayed_events += theirs.relayed_events
            for day, mask in theirs.hours.items():
                if day in mine.hours:
                    mine.hours[day] |= mask
                elif len(mine.hours) < MAX_ACTIVE_DAYS:
                    mine.hours[day] = mask
            for family, count in theirs.platforms.items():
                if family in mine.platforms or len(mine.platforms) < MAX_PLATFORMS_PER_AGENT:
                    mine.platforms[family] = mine.platforms.get(family, 0) + count
            for aid in theirs.agent_ids:
                if len(mine.agent_ids) < MAX_AGENT_IDS:
                    mine.agent_ids.add(aid)
            for rule_id, (hits, first, last) in theirs.flooding.items():
                rec = mine.flooding.get(rule_id)
                if rec is None:
                    mine.flooding[rule_id] = [hits, first, last]
                else:
                    rec[0] += hits
                    rec[1] = min(rec[1], first)
                    rec[2] = max(rec[2], last)
            mine.sources_overflow += theirs.sources_overflow
            for ls, src in theirs.sources.items():
                current = mine.sources.get(ls)
                if current is None:
                    if len(mine.sources) >= self.max_sources_per_agent:
                        mine.sources_overflow += src.count
                        self.sources_overflow += src.count
                        continue
                    current = mine.sources[ls] = SourceStats()
                self.codes_overflow += current.merge(src, self.max_codes_per_source)


# ---- analysis ---------------------------------------------------------------------------------------------------


@dataclass(slots=True)
class CoverageResult:
    findings: list[Finding]
    section: dict[str, Any]


@dataclass(slots=True)
class _Host:
    name: str
    data: AgentStats | None
    api: AgentInfo | None
    platform: str | None
    groups: tuple[str, ...]
    tier: str
    manager: bool = False
    relayed: bool = False
    keys: dict[str, list[float]] = field(default_factory=dict)  # peer key -> [count, first, last]

    @property
    def entity(self) -> Entity:
        return Entity("host", self.name)

    @property
    def span_days(self) -> float:
        """How long the host was observed sending anything (see :attr:`AgentStats.observed_days`)."""
        return self.data.observed_days if self.data is not None else 0.0

    @property
    def calendar_days(self) -> float:
        return self.data.calendar_days if self.data is not None else 0.0

    @property
    def comparable(self) -> bool:
        return self.data is not None and self.data.count > 0 and not self.manager and not self.relayed


@dataclass(slots=True)
class _Gap:
    host: _Host
    detail: dict[str, Any]


@dataclass(slots=True)
class _Context:
    tenant: TenantConfig
    now_ts: float
    api_now_ts: float
    basis_kind: str  # raw | alerts | unknown
    peer_coverage: float
    window_start: float
    incomplete: bool = False  # partial failures, truncation/caps or sampling: absence cannot be proven
    not_assessed: list[str] = field(default_factory=list)
    counters: dict[str, int] = field(default_factory=dict)
    # (platform, peer key) -> hosts of the platform-wide peer group that lack the key but could not be judged
    peer_unjudged: dict[tuple[str, str], int] = field(default_factory=dict)

    @property
    def weak(self) -> bool:
        """Absence in the data is weak evidence: alerts-only (events below the alert level are invisible) or an
        incomplete / sampled input."""
        return self.basis_kind == "alerts" or self.incomplete

    @property
    def strong(self) -> bool:
        """Full-fidelity, complete input: the only basis on which a gap is measured rather than inferred."""
        return self.basis_kind == "raw" and not self.incomplete

    def quiet_s(self, tier: str) -> float:
        """Longest tolerated quiet period for a tier: max(SLA, 24h)."""
        return max(self.sla(tier).total_seconds(), DAY_S)

    def sla(self, tier: str) -> timedelta:
        return _sla(self.tenant, tier)

    def confidence(self) -> Confidence:
        """Confidence of a finding inferred from the ABSENCE of data."""
        if self.weak:
            return Confidence.LOW
        return Confidence.HIGH if self.basis_kind == "raw" else Confidence.MEDIUM

    def change_confidence(self) -> Confidence:
        """Confidence of a finding about something that was flowing and STOPPED (its own history is evidence)."""
        return Confidence.HIGH if self.strong else Confidence.MEDIUM

    def absence_severity(self, severity: Severity) -> Severity:
        """On weak evidence (alerts-only / incomplete input) an absence never escalates beyond MEDIUM."""
        if self.weak and severity.rank > Severity.MEDIUM.rank:
            return Severity.MEDIUM
        return severity

    def caveats(self) -> list[Message | str]:
        out: list[Message | str] = []
        if self.basis_kind == "alerts":
            out.append(M("coverage.reason.alerts_basis"))
        if self.incomplete:
            out.append(M("coverage.reason.incomplete_basis"))
        return out

    def bump(self, key: str, amount: int = 1) -> None:
        self.counters[key] = self.counters.get(key, 0) + amount


def analyze_coverage(
    collector: CoverageCollector,
    *,
    tenant: TenantConfig,
    now: datetime,
    agents: list[AgentInfo] | None = None,
    basis: DataBasis | None = None,
    wallclock: datetime | None = None,
) -> CoverageResult:
    """Find coverage gaps and agent-health problems.

    ``now`` is the reference time of the data (end of the analyzed window). ``agents`` is the Wazuh API inventory
    (the manager, agent ``000``, is ignored). ``basis`` (optional) tells whether the data is alerts-only, which
    lowers confidence; without it the basis is inferred from the share of rule-less events. ``wallclock``
    (optional) is when the API was queried; without it it is estimated from the freshest keepalive of active
    agents. Returns findings (``coverage.*`` and agent-level ``pipeline.*``) and ``sections["coverage"]``.
    """
    now_ts = _aware(now).timestamp()
    api_agents = [a for a in (agents or []) if isinstance(a, AgentInfo)]
    incomplete = collector.truncated or (
        basis is not None and (bool(basis.partial_failures) or basis.truncated or basis.sampled)
    )
    ctx = _Context(
        tenant=tenant,
        now_ts=now_ts,
        api_now_ts=_api_now(api_agents, wallclock, now_ts),
        basis_kind=_basis_kind(basis, collector),
        peer_coverage=min(1.0, max(0.5, float(tenant.silence.peer_coverage))),
        window_start=collector.first if math.isfinite(collector.first) else now_ts,
        incomplete=incomplete,
    )
    hosts = _build_hosts(collector, api_agents, tenant)
    for host in hosts:
        host.keys = _peer_key_stats(host)

    findings: list[Finding] = []
    peer_buckets, peer_expected = _peer_gaps(hosts, ctx)
    contract_findings, contract_rows, contract_missing = _contract_checks(hosts, ctx)
    peer_findings, peer_rows = _peer_findings(_drop_contract_overlap(peer_buckets, contract_missing), ctx)
    findings.extend(peer_findings)
    findings.extend(contract_findings)
    event_findings, event_rows = _event_type_checks(hosts, ctx)
    findings.extend(event_findings)
    issues = _agent_health(hosts, ctx, api_agents, collector) + _flooding(hosts, ctx)
    findings.extend(_group_agent_issues(issues, ctx))
    for finding in findings:
        # fingerprints are tenant-scoped: recompute now that the tenant is known
        finding.tenant = tenant.name
        finding.fingerprint = fingerprint(tenant.name, finding.kind, finding.subject)

    section = _section(hosts, ctx, collector, findings, peer_expected, peer_rows, contract_rows, event_rows, api_agents)
    return CoverageResult(findings=sort_findings(findings), section=section)


# ---- inventory ----------------------------------------------------------------------------------------------------


def _build_hosts(collector: CoverageCollector, agents: Sequence[AgentInfo], tenant: TenantConfig) -> list[_Host]:
    manager_names: set[str] = set()
    api: dict[str, AgentInfo] = {}
    for agent in agents:
        name = _clean_name(agent.name)
        if name is None:
            continue
        if agent.is_manager:
            manager_names.add(name)
            continue
        previous = api.get(name)
        if previous is None or _keepalive_ts(agent) > _keepalive_ts(previous):
            api[name] = agent
    by_fold: dict[str, list[str]] = {}
    by_short: dict[str, list[str]] = {}
    for name in api:
        by_fold.setdefault(name.casefold(), []).append(name)
        by_short.setdefault(name.split(".", 1)[0].casefold(), []).append(name)

    hosts: list[_Host] = []
    # exact name matches first, so a fuzzy (case / short-name) join can never steal an exact partner
    joined: dict[str, str] = {name: name for name in collector.agents if name in api}
    used: set[str] = set(joined.values())
    for name in sorted(collector.agents):
        if name not in joined:
            candidate = _join(name, by_fold, by_short, used)
            if candidate is not None:
                joined[name] = candidate
                used.add(candidate)
    for name in sorted(collector.agents):
        stats = collector.agents[name]
        api_name = joined.get(name)
        matched = api[api_name] if api_name is not None else None
        display = api_name or name
        manager = stats.is_manager or (matched is None and name in manager_names)
        hosts.append(
            _Host(
                name=display,
                data=stats,
                api=matched,
                platform=_host_platform(matched, stats),
                groups=_groups(matched),
                tier=tenant.tier_for(display),
                manager=manager,
                relayed=stats.is_relayed,
            )
        )
    for api_name in sorted(set(api) - used):
        agent = api[api_name]
        hosts.append(
            _Host(
                name=api_name,
                data=None,
                api=agent,
                platform=_host_platform(agent, None),
                groups=_groups(agent),
                tier=tenant.tier_for(api_name),
            )
        )
    return hosts


def _join(name: str, by_fold: Mapping[str, list[str]], by_short: Mapping[str, list[str]], used: set[str]) -> str | None:
    """Fuzzy join of a data host name to an API agent name: case-insensitive, then unambiguous short name
    ("srv01" <-> "srv01.corp.example") when at least one side is a bare hostname."""
    candidates = [n for n in by_fold.get(name.casefold(), []) if n not in used]
    if len(candidates) == 1:
        return candidates[0]
    if candidates:
        return None
    short = [n for n in by_short.get(name.split(".", 1)[0].casefold(), []) if n not in used]
    if len(short) == 1 and ("." not in short[0] or "." not in name):
        return short[0]
    return None


def _host_platform(agent: AgentInfo | None, stats: AgentStats | None) -> str | None:
    if agent is not None:
        for value in (agent.platform, agent.os_name):
            if isinstance(value, str) and value:
                family = platform_family(value)
                if family is not None:
                    return family
    return stats.platform if stats is not None else None


def _groups(agent: AgentInfo | None) -> tuple[str, ...]:
    if agent is None or not isinstance(agent.groups, (list, tuple)):
        return ()
    out: list[str] = []
    for group in agent.groups:
        if isinstance(group, str) and 0 < len(group) <= 128 and group not in out:
            out.append(group)
    return tuple(out[:32])


def _peer_key_stats(host: _Host) -> dict[str, list[float]]:
    keys: dict[str, list[float]] = {}
    if host.data is None:
        return keys
    for name, src in host.data.sources.items():
        for key in _PEER_CLASSES.get(name, (name,)):
            rec = keys.get(key)
            if rec is None:
                keys[key] = [float(src.count), src.first, src.last]
            else:
                rec[0] += src.count
                rec[1] = min(rec[1], src.first)
                rec[2] = max(rec[2], src.last)
    return keys


# ---- peer groups --------------------------------------------------------------------------------------------------


_BucketKey = tuple[str, str | None, str, str]  # platform, agent group, peer key, tier


def _peer_gaps(hosts: Sequence[_Host], ctx: _Context) -> tuple[dict[_BucketKey, list[_Gap]], dict[str, list[str]]]:
    """Gaps grouped by (platform, agent group, peer key, tier), and the peer-expected keys per platform."""
    groups: dict[tuple[str, str | None], list[_Host]] = {}
    for host in hosts:
        if not host.comparable or host.platform is None:
            continue
        groups.setdefault((host.platform, None), []).append(host)
        for group in host.groups:
            groups.setdefault((host.platform, group), []).append(host)
    expected_by_platform: dict[str, list[str]] = {}
    flagged: set[tuple[str, str]] = set()
    buckets: dict[_BucketKey, list[_Gap]] = {}
    evaluated_any = False
    # platform-wide groups first (broadest root cause), then platform x agent-group
    for key in sorted(groups, key=lambda k: (k[1] is not None, k[0], k[1] or "")):
        members = groups[key]
        size = len(members)
        if size < MIN_PEER_GROUP:
            continue
        evaluated_any = True
        senders: dict[str, list[_Host]] = {}
        for host in members:
            for peer_key in host.keys:
                senders.setdefault(peer_key, []).append(host)
        for peer_key in sorted(senders):
            have = senders[peer_key]
            share = len(have) / (size - 1)
            if share < ctx.peer_coverage:
                continue
            if key[1] is None:
                expected_by_platform.setdefault(key[0], []).append(peer_key)
            missing_hosts = [h for h in members if peer_key not in h.keys]
            if not missing_hosts:
                continue
            rate = _quantile([h.keys[peer_key][0] / max(h.span_days, 1.0) for h in have], 0.25)
            # when the peers were sending it: a source rolled out after a host went quiet, or retired before a new
            # host joined, was never expected from that host
            period = _typical_period([(h.keys[peer_key][1], h.keys[peer_key][2]) for h in have])
            for host in missing_hosts:
                if (host.name, peer_key) in flagged:
                    continue
                if host.data is not None and host.data.sources_overflow:
                    ctx.bump("peer_gaps_not_assessed")  # the source may be among the ones beyond the cap
                    _count_unjudged(ctx, key, peer_key)
                    continue
                expected = rate * _active_days_within(host.data, host.span_days, period)
                if expected < MIN_EXPECTED_EVENTS:
                    ctx.bump("peer_gaps_not_assessed")
                    _count_unjudged(ctx, key, peer_key)
                    continue
                flagged.add((host.name, peer_key))
                bucket = buckets.setdefault((key[0], key[1], peer_key, host.tier), [])
                bucket.append(
                    _Gap(host, {"expected": expected, "share": share, "senders": len(have), "peers": size - 1})
                )
    if not evaluated_any:
        ctx.not_assessed.append("peer_groups_too_small")
    return buckets, expected_by_platform


def _count_unjudged(ctx: _Context, group: tuple[str, str | None], peer_key: str) -> None:
    if group[1] is None:  # the platform-wide group feeds the section's "expected sources" rows
        ctx.peer_unjudged[(group[0], peer_key)] = ctx.peer_unjudged.get((group[0], peer_key), 0) + 1


def _drop_contract_overlap(
    buckets: Mapping[_BucketKey, list[_Gap]], contract_missing: set[tuple[str, str]]
) -> dict[_BucketKey, list[_Gap]]:
    """A (host, source) pair already reported as missing by a contract is not reported again by the peer check."""
    by_host: dict[str, list[str]] = {}
    for host, pattern in contract_missing:
        by_host.setdefault(host, []).append(pattern)
    out: dict[_BucketKey, list[_Gap]] = {}
    for key, gaps in buckets.items():
        members = _class_members(key[2])
        kept = [g for g in gaps if not any(_ls_match(m, p) for p in by_host.get(g.host.name, ()) for m in members)]
        if kept:
            out[key] = kept
    return out


def _peer_findings(
    buckets: Mapping[_BucketKey, list[_Gap]], ctx: _Context
) -> tuple[list[Finding], list[dict[str, Any]]]:
    findings: list[Finding] = []
    rows: list[dict[str, Any]] = []
    for (platform, group, peer_key, tier), gaps in sorted(buckets.items(), key=lambda kv: _bucket_order(kv[0])):
        label = _CLASS_LABELS.get(peer_key, peer_key)
        group_label = platform if group is None else f"{platform}/{group}"
        share = min(g.detail["share"] for g in gaps)
        senders = min(g.detail["senders"] for g in gaps)
        peers = max(g.detail["peers"] for g in gaps)
        expected = min(g.detail["expected"] for g in gaps)
        reasons: list[Message | str] = [
            M(
                "coverage.peer.reason.share",
                senders=senders,
                peers=peers,
                group=group_label,
                log_source=label,
                share=share,
                threshold=ctx.peer_coverage,
            ),
            M("coverage.peer.reason.expected", expected=expected),
            _hosts_reason([g.host for g in gaps]),
            *ctx.caveats(),
        ]
        if len(gaps) == 1:
            title = M(
                "coverage.peer.title.one", host=gaps[0].host.entity, log_source=label, share=share, platform=platform
            )
        else:
            title = M(
                "coverage.peer.title.many",
                log_source=label,
                missing=len(gaps),
                platform=platform,
                tier=M(f"coverage.tier.{tier}"),
            )
        findings.append(
            Finding(
                kind="coverage.missing_source",
                domain="coverage",
                title=title,
                severity=ctx.absence_severity(_SEV_GAP.get(tier, Severity.MEDIUM)),
                subject=f"peers:{group_label}|ls:{peer_key}|tier:{tier}",
                reasons=reasons,
                evidence={
                    "check": "peer_group",
                    "peer_group": group_label,
                    "log_source": label,
                    "tier": tier,
                    "hosts": [g.host.entity for g in gaps[: _tier_cap(tier)]],
                    "hosts_total": len(gaps),
                    "peers": peers,
                    "senders": senders,
                    "share": round(share, 4),
                    "threshold": ctx.peer_coverage,
                    "min_expected_events": round(expected, 1),
                    "basis": ctx.basis_kind,
                },
                recommendation=M("coverage.peer.recommendation"),
                confidence=ctx.confidence(),
                score=float(len(gaps)),
            )
        )
        rows.append(
            {
                "peer_group": group_label,
                "log_source": label,
                "tier": tier,
                "missing": len(gaps),
                "share": round(share, 4),
            }
        )
    return findings, rows


def _bucket_order(key: _BucketKey) -> tuple[Any, ...]:
    platform, group, peer_key, tier = key
    return (_TIER_RANK.get(tier, 1), platform, group or "", peer_key)


# ---- contracts ----------------------------------------------------------------------------------------------------

_MATCH_KEYS = frozenset({"platform", "groups", "group", "name"})


def _contract_checks(
    hosts: Sequence[_Host], ctx: _Context
) -> tuple[list[Finding], list[dict[str, Any]], set[tuple[str, str]]]:
    """Returns findings, section rows and the (host, pattern) pairs reported as missing."""
    findings: list[Finding] = []
    rows: list[dict[str, Any]] = []
    missing_pairs: set[tuple[str, str]] = set()
    for contract in ctx.tenant.expectations:
        if not isinstance(contract, Expectation):
            continue
        match = contract.match if isinstance(contract.match, Mapping) else {}
        unknown = sorted(str(k) for k in match if k not in _MATCH_KEYS)
        patterns = [p for p in (contract.log_sources or []) if isinstance(p, str) and p.strip()]
        if unknown or not patterns:
            ctx.not_assessed.append(f"contract_invalid:{contract.name}")
            continue
        matched = [h for h in hosts if _contract_matches(match, h)]
        if not matched:
            ctx.not_assessed.append(f"contract_no_hosts:{contract.name}")  # 0 matched hosts is not "compliant"
        criteria = _Criteria(_criteria_text(match), _name_patterns(match))
        min_rate = contract.min_events_per_day if contract.min_events_per_day and contract.min_events_per_day > 0 else 1
        for pattern in patterns:
            buckets: dict[tuple[str, str], list[_Gap]] = {}
            # key order matters: tables show the first columns, and "not assessed" must never be the one cut off
            counts = {"matched": len(matched), "present": 0, "missing": 0, "silent": 0, "not_assessed": 0, "low": 0}
            unjudged: list[_Host] = []
            for host in matched:
                state, detail = _contract_state(host, pattern, min_rate, ctx)
                counts[state] = counts.get(state, 0) + 1
                if state in ("missing", "silent", "low"):
                    buckets.setdefault((state, host.tier), []).append(_Gap(host, detail))
                elif state == "not_assessed":
                    unjudged.append(host)
            rows.append(
                {
                    "name": contract.name,
                    "log_source": pattern,
                    **counts,
                    "min_events_per_day": min_rate,
                    # which hosts the row could not judge (e.g. a host that went quiet: silence owns it)
                    "not_assessed_hosts": [h.entity for h in unjudged[:MESSAGE_MAX_HOSTS]],
                }
            )
            for (state, tier), gaps in sorted(buckets.items(), key=lambda kv: (_TIER_RANK.get(kv[0][1], 1), kv[0][0])):
                findings.append(
                    _contract_finding(contract.name, pattern, state, tier, gaps, len(matched), min_rate, criteria, ctx)
                )
                if state == "missing":
                    missing_pairs.update((g.host.name, pattern) for g in gaps)
    return findings, rows, missing_pairs


@dataclass(frozen=True, slots=True)
class _Criteria:
    text: str  # platform / group criteria (configuration values, not entities)
    names: tuple[str, ...]  # host-name globs: may be literal host names, so rendered as entities


def _contract_matches(match: Mapping[str, Any], host: _Host) -> bool:
    if host.manager and "name" not in match:
        return False
    wanted: set[str | None] = set()
    if "platform" in match:
        wanted = {platform_family(p) for p in _as_list(match["platform"])}
        if host.platform is None or host.platform not in wanted:
            return False
    if host.relayed and "name" not in match and "network" not in wanted:
        # a syslog device relayed through the manager has no agent: its "platform" is inferred from the relay
        # path, so it is bound only by contracts that name it or explicitly target network devices
        return False
    group_values = _as_list(match.get("groups")) + _as_list(match.get("group"))
    if "groups" in match or "group" in match:
        have = {g.casefold() for g in host.groups}
        if not any(g.casefold() in have for g in group_values):
            return False
    if "name" in match:
        name = host.name.casefold()
        if not any(fnmatch.fnmatchcase(name, pattern.casefold()) for pattern in _as_list(match["name"])):
            return False
    return True


def _contract_state(host: _Host, pattern: str, min_rate: float, ctx: _Context) -> tuple[str, dict[str, Any]]:
    """present | missing | silent | low | not_assessed for one host and one contract source pattern.

    On weak evidence (alerts-only, incomplete or sampled input) the event rate a contract sets cannot be measured,
    and a pause of a source is only claimed when its own history makes the silence implausible.
    """
    data = host.data
    if data is None or data.count == 0:
        return "not_assessed", {}  # host-level findings (disconnected / no data / never seen) cover it
    quiet = ctx.quiet_s(host.tier)
    if ctx.now_ts - data.last > quiet:
        return "not_assessed", {}  # the whole host went quiet: silence / agent health own that
    sources = [src for name, src in data.sources.items() if _ls_match(name, pattern)]
    span = host.calendar_days
    if not sources:
        if span < MIN_OBSERVED_DAYS or span * min_rate < 1.0:
            return "not_assessed", {}
        if data.sources_overflow:
            ctx.bump("contract_not_assessed_source_cap")  # the source may be among those beyond the cap
            return "not_assessed", {}
        return "missing", {"observed_days": round(span, 2)}
    last = max(src.last for src in sources)
    gap = ctx.now_ts - last
    if gap > quiet:
        detail = {"last_seen": _iso(last), "quiet_hours": round(gap / 3600.0, 1)}
        if ctx.strong:
            return "silent", detail
        first = min(src.first for src in sources)
        history = last - first
        rate = sum(src.count for src in sources) / max(history / DAY_S, 1.0)
        if history >= max(quiet, gap) and rate * gap / DAY_S >= STOPPED_MIN_EXPECTED:
            return "silent", {**detail, "expected_since": round(rate * gap / DAY_S, 1)}
        ctx.bump("contract_silence_not_assessed")  # a pause of a sparse / bursty series of alerts proves nothing
        return "not_assessed", {}
    if span >= MIN_OBSERVED_DAYS:
        rate = sum(src.count for src in sources) / span
        if rate < min_rate:
            if not ctx.strong:
                ctx.bump("contract_rate_not_assessed")  # alerts / a sample undercount events by construction
                return "not_assessed", {}
            return "low", {"rate": round(rate, 3)}
    return "present", {}


def _contract_finding(
    contract: str, pattern: str, state: str, tier: str, gaps: list[_Gap], matched: int, min_rate: float,
    criteria: _Criteria, ctx: _Context,
) -> Finding:  # fmt: skip
    hosts = [g.host for g in gaps]
    if len(gaps) == 1:
        title = M(
            f"coverage.contract.title.{state}.one",
            host=hosts[0].entity,
            log_source=pattern,
            contract=contract,
            min_rate=min_rate,
        )
    else:
        title = M(
            f"coverage.contract.title.{state}.many",
            contract=contract,
            log_source=pattern,
            missing=len(gaps),
            matched=matched,
            min_rate=min_rate,
            tier=M(f"coverage.tier.{tier}"),
        )
    reasons: list[Message | str] = [
        M("coverage.contract.reason.match", contract=contract, matched=matched, criteria=criteria.text)
    ]
    if criteria.names:
        reasons.append(M("coverage.contract.reason.names", names=[Entity("host", n) for n in criteria.names]))
    evidence: dict[str, Any] = {
        "check": "contract",
        "contract": contract,
        "log_source": pattern,
        "state": state,
        "tier": tier,
        "hosts": [h.entity for h in hosts[: _tier_cap(tier)]],
        "hosts_total": len(hosts),
        "matched": matched,
        "criteria": criteria.text,
        "name_patterns": [Entity("host", n) for n in criteria.names],
        "min_events_per_day": min_rate,
        "basis": ctx.basis_kind,
    }
    confidence = ctx.confidence()
    if state == "missing":
        reasons.append(M("coverage.contract.reason.missing", log_source=pattern))
        severity = ctx.absence_severity(_SEV_GAP.get(tier, Severity.MEDIUM))
    elif state == "silent":
        reasons.append(
            M(
                "coverage.contract.reason.silent",
                log_source=pattern,
                quiet=humanize(timedelta(seconds=ctx.quiet_s(tier))),
            )
        )
        evidence["last_seen"] = [
            {"host": g.host.entity, "last_seen": g.detail.get("last_seen")} for g in gaps[: _tier_cap(tier)]
        ]
        severity = _SEV_BLIND.get(tier, Severity.HIGH)
        confidence = ctx.change_confidence()  # it flowed and stopped: its own history is the evidence
    else:
        lowest = min(float(g.detail.get("rate", 0.0)) for g in gaps)
        reasons.append(M("coverage.contract.reason.low", rate=lowest, min_rate=min_rate))
        evidence["rates"] = [{"host": g.host.entity, "rate": g.detail.get("rate")} for g in gaps[: _tier_cap(tier)]]
        severity = ctx.absence_severity(_SEV_GAP.get(tier, Severity.MEDIUM))
    reasons.append(_hosts_reason(hosts))
    reasons.extend(ctx.caveats())
    return Finding(
        kind="coverage.missing_source",
        domain="coverage",
        title=title,
        severity=severity,
        subject=f"contract:{contract}|ls:{pattern}|state:{state}|tier:{tier}",
        reasons=reasons,
        evidence=evidence,
        recommendation=M("coverage.contract.recommendation"),
        confidence=confidence,
        score=float(len(hosts)),
    )


# ---- event types --------------------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _EventTypeCheck:
    id: str
    family: str  # security | sysmon | powershell
    anchor: str | None  # code that must flow on the channel (None: any event of the channel)
    target: str


_EVENT_TYPE_CHECKS: tuple[_EventTypeCheck, ...] = (
    _EventTypeCheck("win_4688", "security", "4624", "4688"),
    _EventTypeCheck("sysmon_1", "sysmon", None, "1"),
    _EventTypeCheck("sysmon_3", "sysmon", None, "3"),
    _EventTypeCheck("ps_4104", "powershell", None, "4104"),
)


def _channel_family(name: str) -> str | None:
    lowered = name.casefold()
    if lowered in ("security", "system.security", "windows.security", "microsoft-windows-security-auditing"):
        return "security"
    if "sysmon" in lowered:
        return "sysmon"
    if lowered in (
        "microsoft-windows-powershell/operational",
        "windows.powershell_operational",
        "powershell_operational",
    ):
        return "powershell"
    return None


@dataclass(slots=True)
class _ChannelView:
    name: str
    count: float
    first: float
    last: float
    codes: dict[str, list[float]]


def _channel_view(host: _Host, family: str) -> _ChannelView | None:
    if host.data is None:
        return None
    matching = [(n, s) for n, s in host.data.sources.items() if _channel_family(n) == family]
    if not matching:
        return None
    matching.sort(key=lambda item: -item[1].count)
    codes: dict[str, list[float]] = {}
    for _, src in matching:
        for code, (count, first, last) in src.codes.items():
            rec = codes.get(code)
            if rec is None:
                codes[code] = [count, first, last]
            else:
                rec[0] += count
                rec[1] = min(rec[1], first)
                rec[2] = max(rec[2], last)
    return _ChannelView(
        name=matching[0][0],
        count=float(sum(s.count for _, s in matching)),
        first=min(s.first for _, s in matching),
        last=max(s.last for _, s in matching),
        codes=codes,
    )


def _event_type_checks(hosts: Sequence[_Host], ctx: _Context) -> tuple[list[Finding], list[dict[str, Any]]]:
    findings: list[Finding] = []
    rows: list[dict[str, Any]] = []
    comparable = [h for h in hosts if h.comparable]
    for check in _EVENT_TYPE_CHECKS:
        views: list[tuple[_Host, _ChannelView]] = []
        for host in comparable:
            view = _channel_view(host, check.family)
            if view is None:
                continue
            if check.anchor is not None and check.anchor not in view.codes:
                continue
            views.append((host, view))
        # "stopped": needs only the host's own history; many hosts at once is one fleet-wide root cause -------
        stopped_findings = [f for f in (_stopped_finding(check, h, v, ctx) for h, v in views) if f is not None]
        stopped = len(stopped_findings)
        if stopped >= MIN_PEER_GROUP and stopped * 2 >= len(views):
            findings.append(_stopped_fleet_finding(check, stopped_findings, len(views), ctx))
        else:
            findings.extend(stopped_findings)
        # "never": needs peers ---------------------------------------------------------------------------------
        row: dict[str, Any] = {
            "check": check.id,
            "code": check.target,
            "peers": len(views),
            "missing": 0,
            "stopped": stopped,
            "assessed": False,
        }
        rows.append(row)
        size = len(views)
        if size < MIN_PEER_GROUP:
            if views:
                ctx.not_assessed.append(f"event_type_peers_too_few:{check.id}")
            continue
        have = [(h, v) for h, v in views if check.target in v.codes]
        share = len(have) / (size - 1)
        row["assessed"] = True
        row["share"] = round(share, 4)
        if share < ctx.peer_coverage or len(have) == size:
            continue
        rate = _quantile([v.codes[check.target][0] / max(_view_span_days(h, v), 1.0) for h, v in have], 0.25)
        period = _typical_period([(v.codes[check.target][1], v.codes[check.target][2]) for _, v in have])
        buckets: dict[str, list[_Gap]] = {}
        for host, view in views:
            if check.target in view.codes:
                continue
            expected = rate * _active_days_within(view, _view_span_days(host, view), period)
            if expected < MIN_EXPECTED_EVENTS:
                ctx.bump("event_type_gaps_not_assessed")
                continue
            buckets.setdefault(host.tier, []).append(_Gap(host, {"expected": expected, "channel": view.name}))
        for tier, gaps in sorted(buckets.items(), key=lambda kv: _TIER_RANK.get(kv[0], 1)):
            row["missing"] += len(gaps)
            findings.append(_never_finding(check, tier, gaps, share, size - 1, ctx))
    return findings, rows


def _typical_period(spans: Sequence[tuple[float, float]]) -> tuple[float, float]:
    """The period during which senders typically sent something: median first-seen to median last-seen."""
    firsts = [first for first, _ in spans]
    lasts = [last for _, last in spans]
    return _quantile(firsts, 0.5), _quantile(lasts, 0.5)


def _active_days_within(
    observed: AgentStats | _ChannelView | None, active_days: float, period: tuple[float, float]
) -> float:
    """``active_days`` (how long the host / channel was observed) scaled to the part of its observation window that
    overlaps ``period``, assuming activity spread evenly over the window."""
    if observed is None or active_days <= 0.0:
        return 0.0
    first, last = observed.first, observed.last
    start, end = period
    if not (math.isfinite(first) and math.isfinite(last) and math.isfinite(start) and math.isfinite(end)):
        return 0.0
    elapsed = last - first
    overlap = min(last, end) - max(first, start)
    if overlap <= 0.0:
        return 0.0
    if elapsed <= 0.0:
        return active_days
    return active_days * min(1.0, overlap / elapsed)


def _view_span_days(host: _Host, view: _ChannelView) -> float:
    """How long the channel was observed on the host, bounded by the host's active days."""
    return min(max(0.0, (view.last - view.first) / DAY_S), host.span_days)


def _never_finding(
    check: _EventTypeCheck, tier: str, gaps: list[_Gap], share: float, peers: int, ctx: _Context
) -> Finding:
    hosts = [g.host for g in gaps]
    event_type = M(f"coverage.event_type.name.{check.id}")
    if len(gaps) == 1:
        title = M("coverage.event_type.title.one", host=hosts[0].entity, event_type=event_type)
    else:
        title = M(
            "coverage.event_type.title.many", event_type=event_type, missing=len(gaps), tier=M(f"coverage.tier.{tier}")
        )
    reasons: list[Message | str] = [
        M(f"coverage.event_type.reason.{check.id}", share=share, peers=peers),
        M("coverage.peer.reason.expected", expected=min(g.detail["expected"] for g in gaps)),
        _hosts_reason(hosts),
        *ctx.caveats(),
    ]
    return Finding(
        kind="coverage.missing_event_type",
        domain="coverage",
        title=title,
        severity=ctx.absence_severity(_SEV_GAP.get(tier, Severity.MEDIUM)),
        subject=f"event_type:{check.id}|never|tier:{tier}",
        reasons=reasons,
        evidence={
            "check": check.id,
            "variant": "never",
            "channel": gaps[0].detail["channel"],
            "code": check.target,
            "anchor_code": check.anchor,
            "tier": tier,
            "hosts": [h.entity for h in hosts[: _tier_cap(tier)]],
            "hosts_total": len(hosts),
            "peers": peers,
            "share": round(share, 4),
            "threshold": ctx.peer_coverage,
            "min_expected_events": round(min(g.detail["expected"] for g in gaps), 1),
            "basis": ctx.basis_kind,
        },
        recommendation=M(f"coverage.event_type.recommendation.{check.id}"),
        confidence=ctx.confidence(),
        score=float(len(hosts)),
    )


def _stopped_finding(check: _EventTypeCheck, host: _Host, view: _ChannelView, ctx: _Context) -> Finding | None:
    target = view.codes.get(check.target)
    if target is None:
        return None
    count, first, last = target
    if count < STOPPED_MIN_EVENTS:
        return None
    anchor_last = view.codes[check.anchor][2] if check.anchor is not None else view.last
    quiet = ctx.quiet_s(host.tier)
    gap = anchor_last - last
    if gap < quiet or ctx.now_ts - anchor_last > quiet:
        return None
    # Persistence: the event type must have flowed for a while before it can be said to have "stopped". Alerts are
    # bursty (a detection rule firing 40 times in one afternoon), so there it must have been seen for at least as
    # long as it has now been missing.
    if last - first < (quiet if ctx.strong else max(quiet, gap)):
        return None
    rate = count / max((last - first) / DAY_S, 1.0)
    expected = rate * gap / DAY_S
    if expected < STOPPED_MIN_EXPECTED:
        return None
    event_type = M(f"coverage.event_type.name.{check.id}")
    reasons: list[Message | str] = [
        M("coverage.event_type.stopped.reason", rate=rate, count=int(count), expected=expected)
    ]
    reasons.extend(_stopped_caveats(ctx))
    return Finding(
        kind="coverage.missing_event_type",
        domain="coverage",
        title=M(
            "coverage.event_type.stopped.title",
            host=host.entity,
            event_type=event_type,
            ago=humanize(timedelta(seconds=max(0.0, ctx.now_ts - last))),
            channel=view.name,
        ),
        severity=_SEV_BLIND.get(host.tier, Severity.HIGH),
        subject=f"agent:{host.name}|ls:{view.name}|code:{check.target}|stopped",
        reasons=reasons,
        evidence={
            "check": check.id,
            "variant": "stopped",
            "host": host.entity,
            "channel": view.name,
            "code": check.target,
            "tier": host.tier,
            "last_seen": _iso(last),
            "channel_last_seen": _iso(anchor_last),
            "count_before": int(count),
            "rate_per_day": round(rate, 2),
            "expected_since": round(expected, 1),
            "mitre": ["T1562.002"],
            "basis": ctx.basis_kind,
        },
        recommendation=M("coverage.event_type.stopped.recommendation"),
        confidence=ctx.change_confidence(),
        score=expected,
    )


def _stopped_fleet_finding(check: _EventTypeCheck, stopped: list[Finding], total: int, ctx: _Context) -> Finding:
    # critical hosts first: a grouped finding must never bury a critical host behind the evidence / message caps
    stopped = sorted(stopped, key=lambda f: (_TIER_RANK.get(str(f.evidence["tier"]), 1), f.subject))
    tiers = [str(f.evidence["tier"]) for f in stopped]
    worst_tier = min(tiers, key=lambda t: _TIER_RANK.get(t, 1))
    last_seen = sorted(str(f.evidence["last_seen"]) for f in stopped)
    hosts = [f.evidence["host"] for f in stopped]
    critical = [f.evidence["host"] for f in stopped if f.evidence["tier"] == "critical"]
    reasons: list[Message | str] = [
        M("coverage.event_type.stopped.fleet.reason", first=last_seen[0], last=last_seen[-1]),
    ]
    if critical:
        reasons.append(M("coverage.reason.critical_hosts", hosts=critical[:EVIDENCE_MAX_CRITICAL]))
    reasons.append(
        M("coverage.reason.hosts_more", hosts=hosts[:MESSAGE_MAX_HOSTS], more=len(hosts) - MESSAGE_MAX_HOSTS)
        if len(hosts) > MESSAGE_MAX_HOSTS
        else M("coverage.reason.hosts", hosts=hosts)
    )
    reasons.extend(_stopped_caveats(ctx))
    return Finding(
        kind="coverage.missing_event_type",
        domain="coverage",
        title=M(
            "coverage.event_type.stopped.fleet.title",
            event_type=M(f"coverage.event_type.name.{check.id}"),
            count=len(stopped),
            total=total,
        ),
        severity=_SEV_BLIND.get(worst_tier, Severity.HIGH),
        subject=f"event_type:{check.id}|stopped|fleet",
        reasons=reasons,
        evidence={
            "check": check.id,
            "variant": "stopped_fleet",
            "code": check.target,
            "hosts": _evidence_hosts(hosts, len(critical)),
            "hosts_total": len(hosts),
            "critical_hosts": critical[:EVIDENCE_MAX_CRITICAL],
            "hosts_with_channel": total,
            "last_seen_range": [last_seen[0], last_seen[-1]],
            "tiers": {t: tiers.count(t) for t in sorted(set(tiers))},
            "mitre": ["T1562.002"],
            "basis": ctx.basis_kind,
        },
        recommendation=M("coverage.event_type.stopped.recommendation"),
        confidence=Confidence.MEDIUM,
        score=float(len(hosts)),
    )


def _stopped_caveats(ctx: _Context) -> list[Message | str]:
    out: list[Message | str] = []
    if ctx.basis_kind != "raw":
        out.append(M("coverage.event_type.stopped.alerts_caveat"))
    if ctx.incomplete:
        out.append(M("coverage.reason.incomplete_basis"))
    return out


def _tier_cap(tier: str) -> int:
    """How many hosts a grouped finding of this tier lists in its evidence (critical hosts are never cut)."""
    return EVIDENCE_MAX_CRITICAL if tier == "critical" else EVIDENCE_MAX_HOSTS


def _evidence_hosts(hosts: Sequence[Any], critical: int) -> list[Any]:
    """Hosts for a grouped finding's evidence (callers order them critical first): capped, but never cutting a
    critical host."""
    return list(hosts[: max(EVIDENCE_MAX_HOSTS, min(critical, EVIDENCE_MAX_CRITICAL))])


# ---- agent health -------------------------------------------------------------------------------------------------


@dataclass(slots=True)
class _AgentIssue:
    """One host-level problem, kept as its own finding unless enough hosts share it (see _group_agent_issues)."""

    variant: str  # disconnected | stale | pending | never_connected | no_data | never_seen | flood_loss | flood_warn
    host: _Host
    finding: Finding
    order: float = 0.0  # larger first inside a group (age, silence, alert count)


_GROUP_RECOMMENDATION = {
    "disconnected": "coverage.agent.disconnected.recommendation",
    "stale": "coverage.agent.stale.recommendation",
    "pending": "coverage.agent.disconnected.recommendation",
    "never_connected": "coverage.agent.never_connected.recommendation",
    "no_data": "coverage.agent.no_data.recommendation",
    "never_seen": "coverage.inventory.never_seen.recommendation",
    "flood_loss": "coverage.flooding.recommendation",
    "flood_warn": "coverage.flooding.recommendation",
}
_CONFIDENCE_RANK = {Confidence.LOW: 0, Confidence.MEDIUM: 1, Confidence.HIGH: 2}
_CONNECTED_STATUSES = frozenset({"active", "disconnected", "pending"})


def _agent_health(
    hosts: Sequence[_Host], ctx: _Context, api_agents: Sequence[AgentInfo], collector: CoverageCollector
) -> list[_AgentIssue]:
    issues: list[_AgentIssue] = []
    if not api_agents:
        ctx.not_assessed.append("agent_status_no_api")
    data_current = abs(ctx.api_now_ts - ctx.now_ts) <= API_DATA_MAX_SKEW_S
    if api_agents and not data_current:
        ctx.not_assessed.append("api_cross_check_data_not_current")
    window_s = max(0.0, ctx.now_ts - ctx.window_start) if collector.events else 0.0
    connected_ever = 0
    for host in hosts:
        agent = host.api
        if agent is None or host.manager:
            continue
        status = (agent.status or "unknown").strip().casefold() if isinstance(agent.status, str) else "unknown"
        if status in _CONNECTED_STATUSES:
            connected_ever += 1
        issue: _AgentIssue | None = None
        if status == "never_connected":
            issue = _never_connected(host, agent, ctx)
        elif status in ("disconnected", "pending"):
            issue = _disconnected(host, agent, status, ctx)
        elif status == "active":
            if data_current:
                issue = _no_data(host, agent, ctx, window_s)
        elif host.data is None:
            issue = _never_seen(host, agent, status, ctx, window_s)
        if issue is not None:
            issues.append(issue)
    down = sum(1 for issue in issues if issue.variant == "disconnected")
    if down >= AGENT_GROUP_MIN and down >= MASS_DISCONNECT_SHARE * connected_ever:
        mass = M("coverage.agent.group.reason.mass", count=down, total=connected_ever)
        for issue in issues:
            if issue.variant == "disconnected":
                issue.finding.reasons.append(mass)
    return issues


def _enrolled_ts(agent: AgentInfo) -> float:
    return _dt_ts(agent.date_add)


def _never_connected(host: _Host, agent: AgentInfo, ctx: _Context) -> _AgentIssue | None:
    enrolled = _enrolled_ts(agent)
    if math.isfinite(enrolled) and ctx.api_now_ts - enrolled < ctx.sla(host.tier).total_seconds():
        ctx.bump("agents_never_connected_recent")  # just enrolled: the agent is probably being deployed
        return None
    finding = Finding(
        kind="pipeline.agent_disconnected",
        domain="pipeline",
        title=M("coverage.agent.never_connected.title", host=host.entity),
        severity=Severity.MEDIUM,
        subject=f"agent:{host.name}",
        reasons=[M("coverage.agent.never_connected.reason", date_add=_iso_dt(agent.date_add) or "?")],
        evidence={
            "host": host.entity,
            "status": "never_connected",
            "date_add": _iso_dt(agent.date_add),
            "tier": host.tier,
            "agent_id": _clean_id(agent.id),
        },
        recommendation=M("coverage.agent.never_connected.recommendation"),
        confidence=Confidence.HIGH,
    )
    return _AgentIssue("never_connected", host, finding, ctx.api_now_ts - enrolled if math.isfinite(enrolled) else 0.0)


def _disconnected(host: _Host, agent: AgentInfo, status: str, ctx: _Context) -> _AgentIssue | None:
    sla = ctx.sla(host.tier)
    reference = _keepalive_ts(agent)
    if not math.isfinite(reference) and host.data is not None and host.data.count:
        reference = host.data.last
    if not math.isfinite(reference) and status == "pending":
        reference = _enrolled_ts(agent)
    evidence: dict[str, Any] = {
        "host": host.entity,
        "status": status,
        "tier": host.tier,
        "sla_hours": round(sla.total_seconds() / 3600.0, 2),
        "last_keepalive": _iso_dt(agent.last_keepalive),
        "last_event": _iso(host.data.last) if host.data is not None and host.data.count else None,
        "agent_id": _clean_id(agent.id),
    }
    reason = M("coverage.agent.disconnected.reason", status=status, last_keepalive=_iso_dt(agent.last_keepalive) or "?")
    variant = status
    severity = _SEV_BLIND.get(host.tier, Severity.HIGH)
    recommendation = "coverage.agent.disconnected.recommendation"
    if math.isfinite(reference):
        age = ctx.api_now_ts - reference
        if age <= sla.total_seconds():
            ctx.bump(f"agents_{status}_within_sla")
            return None
        evidence["disconnected_hours"] = round(age / 3600.0, 1)
        duration = humanize(timedelta(seconds=age))
        if status == "pending":
            title = M("coverage.agent.pending.title", host=host.entity, duration=duration, sla=humanize(sla))
        elif age > STALE_AGENT_DAYS * DAY_S:
            # weeks without a keepalive: most often a retired host whose enrollment was never removed. Still a
            # finding (it may be a forgotten live host), but hygiene rather than an outage.
            variant = "stale"
            severity = _SEV_GAP.get(host.tier, Severity.MEDIUM)
            recommendation = "coverage.agent.stale.recommendation"
            title = M("coverage.agent.stale.title", host=host.entity, duration=duration)
        else:
            title = M("coverage.agent.disconnected.title", host=host.entity, duration=duration, sla=humanize(sla))
        score: float | None = age
    elif status == "pending":
        ctx.bump("agents_pending_unknown_age")
        return None
    else:
        title = M("coverage.agent.disconnected.title_unknown", host=host.entity)
        score = None
    finding = Finding(
        kind="pipeline.agent_disconnected",
        domain="pipeline",
        title=title,
        severity=severity,
        subject=f"agent:{host.name}",
        reasons=[reason],
        evidence=evidence,
        recommendation=M(recommendation),
        confidence=Confidence.HIGH,
        score=score,
    )
    return _AgentIssue(variant, host, finding, score or 0.0)


def _no_data(host: _Host, agent: AgentInfo, ctx: _Context, window_s: float) -> _AgentIssue | None:
    keepalive = _keepalive_ts(agent)
    if math.isfinite(keepalive) and ctx.api_now_ts - keepalive > FRESH_KEEPALIVE_S:
        return None  # status active with a stale keepalive: inconsistent snapshot, do not guess
    quiet = ctx.quiet_s(host.tier)
    data = host.data
    if data is not None and data.count:
        silent_for = ctx.now_ts - data.last
        if silent_for < quiet:
            return None
        # alerts: a quiet host may produce no alerts; only claim it when its own rate makes 0 implausible
        expected = data.count / max(data.calendar_days, 1.0) * silent_for / DAY_S
        if not ctx.strong and expected < MIN_EXPECTED_EVENTS:
            ctx.bump("no_data_not_assessed")
            return None
        title = M("coverage.agent.no_data.title", host=host.entity, duration=humanize(timedelta(seconds=silent_for)))
        last_event: str | None = _iso(data.last)
    else:
        silent_for = window_s
        enrolled = _enrolled_ts(agent)
        if math.isfinite(enrolled):
            silent_for = min(silent_for, max(0.0, ctx.now_ts - enrolled))  # it cannot have sent before enrollment
        needed = quiet if ctx.strong else max(quiet, NEVER_SEEN_MIN_WINDOW_DAYS * DAY_S)
        if silent_for < needed:
            ctx.bump("no_data_not_assessed")
            return None
        title = M(
            "coverage.agent.no_data.title_never", host=host.entity, duration=humanize(timedelta(seconds=silent_for))
        )
        last_event = None
    reasons: list[Message | str] = [
        M(
            "coverage.agent.no_data.reason",
            last_keepalive=_iso_dt(agent.last_keepalive) or "?",
            last_event=last_event or M("coverage.agent.no_events"),
        )
    ]
    reasons.extend(_no_data_caveats(ctx))
    if ctx.basis_kind == "raw":
        severity = ctx.absence_severity(_SEV_BLIND.get(host.tier, Severity.HIGH))
    else:
        severity = ctx.absence_severity(_SEV_GAP.get(host.tier, Severity.MEDIUM))
    finding = Finding(
        kind="pipeline.agent_no_data",
        domain="pipeline",
        title=title,
        severity=severity,
        subject=f"agent:{host.name}",
        reasons=reasons,
        evidence={
            "host": host.entity,
            "status": "active",
            "tier": host.tier,
            "last_keepalive": _iso_dt(agent.last_keepalive),
            "last_event": last_event,
            "silent_hours": round(silent_for / 3600.0, 1),
            "threshold_hours": round(quiet / 3600.0, 1),
            "agent_id": _clean_id(agent.id),
            "basis": ctx.basis_kind,
        },
        recommendation=M("coverage.agent.no_data.recommendation"),
        confidence=ctx.confidence(),
        score=silent_for,
    )
    return _AgentIssue("no_data", host, finding, silent_for)


def _no_data_caveats(ctx: _Context) -> list[Message | str]:
    out: list[Message | str] = []
    if ctx.basis_kind == "alerts":
        out.append(M("coverage.agent.no_data.alerts_caveat"))
    if ctx.incomplete:
        out.append(M("coverage.reason.incomplete_basis"))
    return out


def _never_seen(host: _Host, agent: AgentInfo, status: str, ctx: _Context, window_s: float) -> _AgentIssue | None:
    """An inventory asset with another status (unknown...) that sent nothing in the analyzed window."""
    enrolled = _enrolled_ts(agent)
    if math.isfinite(enrolled):
        window_s = min(window_s, max(0.0, ctx.now_ts - enrolled))
    quiet = ctx.quiet_s(host.tier)
    needed = quiet if ctx.strong else max(quiet, NEVER_SEEN_MIN_WINDOW_DAYS * DAY_S)
    if window_s < needed:
        ctx.bump("never_seen_not_assessed")
        return None
    finding = Finding(
        kind="coverage.missing_source",
        domain="coverage",
        title=M("coverage.inventory.never_seen.title", host=host.entity),
        severity=ctx.absence_severity(_SEV_GAP.get(host.tier, Severity.MEDIUM)),
        subject=f"agent:{host.name}|ls:*",
        reasons=[
            M("coverage.inventory.never_seen.reason", status=status, window=humanize(timedelta(seconds=window_s))),
            *ctx.caveats(),
        ],
        evidence={
            "check": "inventory",
            "host": host.entity,
            "status": status,
            "tier": host.tier,
            "window_hours": round(window_s / 3600.0, 1),
            "basis": ctx.basis_kind,
        },
        recommendation=M("coverage.inventory.never_seen.recommendation"),
        confidence=ctx.confidence(),
    )
    return _AgentIssue("never_seen", host, finding, window_s)


def _flooding(hosts: Sequence[_Host], ctx: _Context) -> list[_AgentIssue]:
    issues: list[_AgentIssue] = []
    for host in hosts:
        data = host.data
        if data is None or not data.flooding:
            continue
        rules = sorted(data.flooding)
        count = int(sum(rec[0] for rec in data.flooding.values()))
        last = max(rec[2] for rec in data.flooding.values())
        loss = any(rule in _FLOODING_LOSS for rule in rules)
        severity = (_SEV_BLIND if loss else _SEV_GAP).get(host.tier, Severity.MEDIUM)
        finding = Finding(
            kind="pipeline.manager_drops",
            domain="pipeline",
            title=M("coverage.flooding.title.loss" if loss else "coverage.flooding.title.warn", host=host.entity),
            severity=severity,
            subject=f"agent:{host.name}|agent_buffer",
            reasons=[M("coverage.flooding.reason", rules=", ".join(rules), count=count, last=_iso(last) or "?")],
            evidence={
                "check": "agent_buffer",
                "host": host.entity,
                "tier": host.tier,
                "rules": {rule: int(rec[0]) for rule, rec in sorted(data.flooding.items())},
                "first_seen": _iso(min(rec[1] for rec in data.flooding.values())),
                "last_seen": _iso(last),
                "events_lost": loss,
            },
            recommendation=M("coverage.flooding.recommendation"),
            confidence=Confidence.HIGH,
            score=float(count),
        )
        issues.append(_AgentIssue("flood_loss" if loss else "flood_warn", host, finding, float(count)))
    return issues


def _group_agent_issues(issues: Sequence[_AgentIssue], ctx: _Context) -> list[Finding]:
    """One finding per (symptom, tier) when at least AGENT_GROUP_MIN hosts share it ("one PIPELINE finding instead
    of 400"); smaller sets keep their per-host findings. Every grouped host stays listed in the evidence."""
    groups: dict[tuple[str, str], list[_AgentIssue]] = {}
    for issue in issues:
        groups.setdefault((issue.variant, issue.host.tier), []).append(issue)
    out: list[Finding] = []
    for (variant, tier), members in sorted(groups.items(), key=lambda kv: (_TIER_RANK.get(kv[0][1], 1), kv[0][0])):
        if len(members) < AGENT_GROUP_MIN:
            out.extend(m.finding for m in members)
        else:
            out.append(_agent_group_finding(variant, tier, members, ctx))
    return out


_GROUP_DETAIL_SKIP = frozenset({"tier", "basis", "check", "threshold_hours", "sla_hours"})


def _agent_group_finding(variant: str, tier: str, members: list[_AgentIssue], ctx: _Context) -> Finding:
    members = sorted(members, key=lambda m: (-m.order, m.host.name))
    cap = _tier_cap(tier)
    first = members[0].finding
    severity = max((m.finding.severity for m in members), key=lambda s: s.rank)
    confidence = min((m.finding.confidence for m in members), key=lambda c: _CONFIDENCE_RANK.get(c, 1))
    reasons: list[Message | str] = [
        M("coverage.agent.group.reason", count=len(members)),
        _hosts_reason([m.host for m in members]),
    ]
    if variant == "disconnected":
        mass = [r for r in first.reasons if isinstance(r, Message) and r.key == "coverage.agent.group.reason.mass"]
        reasons.extend(mass[:1])
    elif variant == "no_data":
        reasons.extend(_no_data_caveats(ctx))
    elif variant == "never_seen":
        reasons.extend(ctx.caveats())
    elif variant in ("flood_loss", "flood_warn"):
        rules: dict[str, int] = {}
        for m in members:
            for rule, hits in m.finding.evidence.get("rules", {}).items():
                rules[rule] = rules.get(rule, 0) + int(hits)
        last = max(str(m.finding.evidence.get("last_seen") or "") for m in members)
        reasons.append(
            M("coverage.flooding.reason", rules=", ".join(sorted(rules)), count=sum(rules.values()), last=last or "?")
        )
    details = [{k: v for k, v in m.finding.evidence.items() if k not in _GROUP_DETAIL_SKIP} for m in members[:cap]]
    return Finding(
        kind=first.kind,
        domain=first.domain,
        title=M(
            f"coverage.agent.group.{variant}.title",
            count=len(members),
            tier=M(f"coverage.tier.{tier}"),
            sla=humanize(ctx.sla(tier)),
            days=int(STALE_AGENT_DAYS),
        ),
        severity=severity,
        subject=f"agents:{variant}|tier:{tier}",
        reasons=reasons,
        evidence={
            "check": "agent_group",
            "variant": variant,
            "tier": tier,
            "hosts": [m.host.entity for m in members[:cap]],
            "hosts_total": len(members),
            "agents": details,
            "basis": ctx.basis_kind,
        },
        recommendation=M(_GROUP_RECOMMENDATION.get(variant, "coverage.agent.disconnected.recommendation")),
        confidence=confidence,
        score=float(len(members)),
    )


# ---- section ------------------------------------------------------------------------------------------------------


def _section(
    hosts: Sequence[_Host],
    ctx: _Context,
    collector: CoverageCollector,
    findings: Sequence[Finding],
    peer_expected: Mapping[str, list[str]],
    peer_rows: list[dict[str, Any]],
    contract_rows: list[dict[str, Any]],
    event_rows: list[dict[str, Any]],
    api_agents: Sequence[AgentInfo],
) -> dict[str, Any]:
    visible = [h for h in hosts if not h.manager]
    platforms: dict[str, dict[str, Any]] = {}
    for host in visible:
        key = host.platform or "unknown"
        entry = platforms.setdefault(
            key, {"hosts": 0, "reporting": 0, "peer_comparable": 0, "peer_group": False, "expected": []}
        )
        entry["hosts"] += 1
        if host.data is not None and host.data.count:
            entry["reporting"] += 1  # sending data, relayed syslog devices included
        if host.comparable:
            entry["peer_comparable"] += 1  # agents compared with their peers (relayed devices and the manager not)
    for platform, entry in platforms.items():
        entry["peer_group"] = platform != "unknown" and entry["peer_comparable"] >= MIN_PEER_GROUP
        entry["expected"] = [_CLASS_LABELS.get(k, k) for k in peer_expected.get(platform, [])][:MATRIX_MAX_COLUMNS]

    contracts_for = {h.name: _host_contract_patterns(h, ctx) for h in visible}
    matrix: list[dict[str, Any]] = []
    for host in visible:
        columns: dict[str, str] = {}
        for key in peer_expected.get(host.platform or "", []):
            columns[_CLASS_LABELS.get(key, key)] = _peer_cell(host, key, ctx)
        for pattern in contracts_for[host.name]:
            if pattern not in columns:
                columns[pattern] = _pattern_cell(host, pattern, ctx)
        if len(columns) > MATRIX_MAX_COLUMNS:
            columns = dict(list(columns.items())[:MATRIX_MAX_COLUMNS])
        data = host.data
        matrix.append(
            {
                "agent": host.entity,
                "platform": host.platform or "unknown",
                "tier": host.tier,
                "status": _status_of(host),
                "last_seen": _iso(data.last) if data is not None and data.count else None,
                "events": data.count if data is not None else 0,
                "log_sources": columns,
            }
        )
    matrix.sort(
        key=lambda row: (
            _TIER_RANK.get(row["tier"], 1),
            -sum(1 for state in row["log_sources"].values() if state != "present"),
            row["agent"].value,
        )
    )
    total_rows = len(matrix)

    by_status: dict[str, int] = {}
    for agent in api_agents:
        if agent.is_manager:
            continue
        status = agent.status if isinstance(agent.status, str) and len(agent.status) <= 32 else "unknown"
        by_status[status] = by_status.get(status, 0) + 1
    expected_sources: list[dict[str, Any]] = [{"basis": "contract", **row} for row in contract_rows]
    for platform in sorted(peer_expected):
        for key in peer_expected[platform]:
            present = sum(1 for h in visible if h.platform == platform and h.comparable and key in h.keys)
            comparable = platforms.get(platform, {}).get("peer_comparable", 0)
            unjudged = ctx.peer_unjudged.get((platform, key), 0)
            expected_sources.append(
                {
                    "basis": "peers",
                    "name": platform,
                    "log_source": _CLASS_LABELS.get(key, key),
                    "matched": comparable,
                    "present": present,
                    "missing": max(0, comparable - present - unjudged),
                    "silent": 0,  # the peer check compares what hosts ever sent; stopped sources are silence's
                    "not_assessed": unjudged,
                }
            )
    own = [f for f in findings if f.domain == "coverage"]
    assessed = (
        any(entry["peer_group"] for entry in platforms.values())
        or any(
            row.get("present", 0) + row.get("missing", 0) + row.get("silent", 0) + row.get("low", 0)
            for row in contract_rows
        )
        or any(row.get("assessed") for row in event_rows)
        or any(f.evidence.get("check") == "inventory" for f in own)
    )
    # Never a false green: "nothing is missing" needs enough history, and candidate gaps that could not be judged
    # (too little data, capped sources, sparse alerts) are an open question, not a pass.
    history_days = max(0.0, ctx.now_ts - ctx.window_start) / DAY_S if collector.events else 0.0
    min_days = max(0.0, float(ctx.tenant.silence.min_history_days))
    reasons: list[str] = []
    if history_days < min_days:
        reasons.append("short_history")
    unjudged = sum(v for k, v in ctx.counters.items() if k.endswith("_not_assessed"))
    unjudged += sum(1 for item in ctx.not_assessed if item.startswith(("contract_no_hosts:", "contract_invalid:")))
    if unjudged:
        reasons.append("gaps_not_assessed")
    if not visible or not assessed:
        status = "not_assessed"
    elif any(f.severity.rank >= Severity.HIGH.rank for f in own):
        status = "fail"
    elif any(f.severity.rank >= Severity.MEDIUM.rank for f in own):
        status = "warn"
    elif "short_history" in reasons:
        status = "not_assessed"  # no finding, but too little history to say nothing is missing
    elif unjudged:
        status = "warn"
    else:
        status = "ok"
    return {
        "status": status,
        "status_reasons": reasons,
        "history_days": round(history_days, 2),
        "min_history_days": min_days,
        "gaps_not_assessed": unjudged,
        "platforms": platforms,
        "matrix": matrix[:MATRIX_MAX_ROWS],
        "matrix_total": total_rows,
        "matrix_truncated": total_rows > MATRIX_MAX_ROWS,
        "expected_sources": expected_sources[:SECTION_MAX_ITEMS],
        "peer_gaps": peer_rows[:SECTION_MAX_ITEMS],
        "event_types": event_rows,
        "agents": {
            "inventory": len(visible),
            "api": sum(1 for h in visible if h.api is not None),
            "reporting": sum(1 for h in visible if h.data is not None and h.data.count),
            "api_only": sum(1 for h in visible if h.api is not None and h.data is None),
            "data_only": sum(1 for h in visible if h.api is None and h.data is not None),
            "relayed": sum(1 for h in visible if h.relayed),
            "by_status": by_status,
        },
        "basis": ctx.basis_kind,
        "peer_coverage": ctx.peer_coverage,
        "not_assessed": sorted(set(ctx.not_assessed)),
        "counters": dict(sorted(ctx.counters.items())),
        "truncated": collector.truncated,
        "unattributed_events": collector.unattributed,
    }


def _host_contract_patterns(host: _Host, ctx: _Context) -> list[str]:
    out: list[str] = []
    for contract in ctx.tenant.expectations:
        if not isinstance(contract, Expectation) or not isinstance(contract.match, Mapping):
            continue
        if any(k not in _MATCH_KEYS for k in contract.match) or not _contract_matches(contract.match, host):
            continue
        for pattern in contract.log_sources or []:
            if isinstance(pattern, str) and pattern.strip() and pattern not in out:
                out.append(pattern)
    return out


def _peer_cell(host: _Host, key: str, ctx: _Context) -> str:
    rec = host.keys.get(key)
    if rec is None:
        return "missing"
    return "silent" if ctx.now_ts - rec[2] > ctx.quiet_s(host.tier) else "present"


def _pattern_cell(host: _Host, pattern: str, ctx: _Context) -> str:
    if host.data is None:
        return "missing"
    lasts = [src.last for name, src in host.data.sources.items() if _ls_match(name, pattern)]
    if not lasts:
        return "missing"
    return "silent" if ctx.now_ts - max(lasts) > ctx.quiet_s(host.tier) else "present"


def _status_of(host: _Host) -> str:
    if host.api is not None and isinstance(host.api.status, str) and len(host.api.status) <= 32:
        return host.api.status
    if host.relayed:
        return "relayed"
    return "data_only" if host.data is not None else "unknown"


# ---- helpers ------------------------------------------------------------------------------------------------------


@functools.lru_cache(maxsize=512)
def platform_family(value: str | None) -> str | None:
    """Normalize an OS/platform string (Wazuh ``os.platform``, ``Event.os_platform``) to a family:
    ``windows``, ``linux``, ``darwin``, ``bsd``, ``solaris``, ``aix``, ``hpux``, ``network`` or a short
    sanitized token. Returns None for empty or unusable values."""
    if not isinstance(value, str):
        return None
    text = value.strip().casefold()
    if not text or len(text) > 64:
        return None
    if text.startswith("win") or "windows" in text:
        return "windows"
    if text in _DARWIN_PLATFORMS or "darwin" in text or text.startswith("macos"):
        return "darwin"
    if text in _LINUX_PLATFORMS or "linux" in text:
        return "linux"
    if "bsd" in text:
        return "bsd"
    if text in ("sunos", "solaris"):
        return "solaris"
    if text == "aix":
        return "aix"
    if text in ("hp-ux", "hpux"):
        return "hpux"
    token = "".join(ch for ch in text if ch.isascii() and (ch.isalnum() or ch in "._-"))[:32]
    return token or None


def _class_members(peer_key: str) -> list[str]:
    """Log source names a peer key stands for (a distro-equivalence class or the source itself)."""
    members = [name for name, keys in _PEER_CLASSES.items() if peer_key in keys]
    return members or [peer_key]


def _ls_match(name: str, pattern: str) -> bool:
    """Contract log-source match: case-insensitive, glob when the pattern has wildcards."""
    if any(ch in pattern for ch in "*?["):
        return fnmatch.fnmatchcase(name.casefold(), pattern.casefold())
    return name.casefold() == pattern.casefold()


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, Iterable) and not isinstance(value, (bytes, Mapping)):
        return [str(v) for v in value if isinstance(v, (str, int)) and not isinstance(v, bool)]
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return [str(value)]
    return []


def _criteria_text(match: Mapping[str, Any]) -> str:
    """Platform / group criteria as text. Host-name globs are left out: see :func:`_name_patterns`."""
    parts = []
    for key in sorted(match, key=str):
        if key == "name":
            continue
        values = _as_list(match[key])
        parts.append(f"{key}={'|'.join(values)[:120]}")
    if not parts:
        return "name=…" if "name" in match else "*"
    return ", ".join(parts)


def _name_patterns(match: Mapping[str, Any]) -> tuple[str, ...]:
    """Host-name globs of a contract (they can be literal host names, hence rendered as entities)."""
    return tuple(p[:MAX_NAME_LEN] for p in _as_list(match.get("name"))[:MESSAGE_MAX_HOSTS] if p)


def _hosts_reason(hosts: Sequence[_Host]) -> Message:
    shown = [h.entity for h in hosts[:MESSAGE_MAX_HOSTS]]
    more = len(hosts) - len(shown)
    if more > 0:
        return M("coverage.reason.hosts_more", hosts=shown, more=more)
    return M("coverage.reason.hosts", hosts=shown)


def _quantile(values: Sequence[float], q: float) -> float:
    """Linear-interpolation quantile of finite values (0.0 when there are none)."""
    clean = sorted(v for v in values if math.isfinite(v))
    if not clean:
        return 0.0
    pos = (len(clean) - 1) * min(1.0, max(0.0, q))
    lower = math.floor(pos)
    upper = min(lower + 1, len(clean) - 1)
    return clean[lower] + (clean[upper] - clean[lower]) * (pos - lower)


def _norm_code(code: Any) -> str | None:
    if code is None or isinstance(code, bool):
        return None
    if isinstance(code, int):
        return str(code) if 0 <= code < 10**9 else None
    if not isinstance(code, str):
        return None
    text = code.strip()
    if not text or len(text) > MAX_CODE_LEN:
        return None
    if text.isdigit():
        return str(int(text))
    return text


def _field(fields: Mapping[str, Any], path: str) -> Any:
    value = fields.get(path)
    if value is None and path.split(".", 1)[0] in fields:
        value = get_path(fields, path)
    return value


def _clean_name(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    return text[:MAX_NAME_LEN]


def _clean_id(value: Any) -> str | None:
    if isinstance(value, str) and 0 < len(value) <= 32:
        return value
    return None


def _aware(ts: datetime) -> datetime:
    return ts.replace(tzinfo=UTC) if ts.tzinfo is None else ts


def _sla(tenant: TenantConfig, tier: str) -> timedelta:
    """The tier's SLA; a tier missing from a partial ``sla`` override falls back to its built-in default (never to
    a laxer one)."""
    value = tenant.sla.get(tier) if isinstance(tenant.sla, Mapping) else None
    if isinstance(value, timedelta) and value.total_seconds() >= 0:
        return value
    return DEFAULT_SLA.get(tier, DEFAULT_SLA["standard"])


def _keepalive_ts(agent: AgentInfo) -> float:
    return _dt_ts(agent.last_keepalive)


def _dt_ts(value: Any) -> float:
    """Epoch seconds of an API datetime; -inf when missing, not a datetime, or a sentinel (9999-12-31)."""
    if not isinstance(value, datetime) or value.year >= 9000:
        return -math.inf
    try:
        return _aware(value).timestamp()
    except (OverflowError, OSError, ValueError):
        return -math.inf


def _api_now(agents: Sequence[AgentInfo], wallclock: datetime | None, now_ts: float) -> float:
    """When the API snapshot was taken: ``wallclock`` if given, else the freshest keepalive of an active agent."""
    if wallclock is not None:
        return _aware(wallclock).timestamp()
    freshest = max(
        (_keepalive_ts(a) for a in agents if not a.is_manager and isinstance(a.status, str) and a.status == "active"),
        default=-math.inf,
    )
    return freshest if math.isfinite(freshest) else now_ts


def _basis_kind(basis: DataBasis | None, collector: CoverageCollector) -> str:
    if basis is not None:
        kind = basis.input_kind
        if kind in ("archives", "indexer-archives"):
            return "raw"
        if kind in ("alerts", "indexer-alerts"):
            return "alerts"
    if collector.events:
        share = collector.raw_events / collector.events
        if share >= 0.5:
            return "raw"
        if collector.raw_events == 0:
            return "alerts"
    return "unknown"


def _iso(epoch: float) -> str | None:
    if not math.isfinite(epoch):
        return None
    try:
        return iso(datetime.fromtimestamp(epoch, tz=UTC))
    except (OverflowError, OSError, ValueError):
        return None


def _iso_dt(value: datetime | None) -> str | None:
    if not isinstance(value, datetime):
        return None
    try:
        return iso(_aware(value))
    except (OverflowError, ValueError):
        return None
