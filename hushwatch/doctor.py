"""``hushwatch doctor``: check that every configured tenant can actually be analyzed, and say how to fix it.

Most tools are abandoned at the "cannot connect" step. Each check prints OK / WARN / FAIL with the exact fix,
and steers users away from disabling TLS verification (the usual shortcut with Wazuh's self-signed certs).
Paths are shown resolved (relative paths in the config are relative to the config file), unset environment
variables are listed one by one with the ``export`` line that fixes them, and the text follows ``--lang``.
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.text import Text

from .config import Config, InputConfig, TenantConfig
from .i18n import M, Message, register, render
from .timeutil import UTC, humanize

register(
    {
        "doctor.title": {"en": "hushwatch doctor", "es": "hushwatch doctor"},
        "doctor.col.tenant": {"en": "tenant", "es": "cliente"},
        "doctor.col.check": {"en": "check", "es": "control"},
        "doctor.col.status": {"en": "status", "es": "estado"},
        "doctor.col.detail": {"en": "detail", "es": "detalle"},
        "doctor.col.fix": {"en": "how to fix", "es": "cómo corregirlo"},
        "doctor.status.ok": {"en": "OK", "es": "OK"},
        "doctor.status.warn": {"en": "WARN", "es": "AVISO"},
        "doctor.status.fail": {"en": "FAIL", "es": "FALLA"},
        "doctor.summary": {
            "en": "{checks} {checks:plural:check|checks}: {failed} failed, {warned} with {warned:plural:a "
            "warning|warnings}",
            "es": "{checks} {checks:plural:control|controles}: {failed} con falla, {warned} con aviso",
        },
        # check names
        "doctor.check.config": {"en": "config", "es": "configuración"},
        "doctor.check.config_perms": {"en": "config permissions", "es": "permisos de la configuración"},
        "doctor.check.credentials": {"en": "credentials", "es": "credenciales"},
        "doctor.check.env": {"en": "environment", "es": "entorno"},
        "doctor.check.inputs": {"en": "inputs", "es": "entradas"},
        "doctor.check.file_input": {"en": "file input", "es": "entrada de archivo"},
        "doctor.check.indexer": {"en": "indexer {index}", "es": "indexer {index}"},
        "doctor.check.api": {"en": "wazuh api", "es": "api de wazuh"},
        "doctor.check.ruleset": {"en": "ruleset", "es": "ruleset"},
        "doctor.check.dispositions": {"en": "dispositions", "es": "disposiciones"},
        "doctor.check.agents": {"en": "agents file", "es": "archivo de agentes"},
        "doctor.check.state": {"en": "state dir", "es": "directorio de estado"},
        "doctor.check.unexpected": {"en": "unexpected error", "es": "error inesperado"},
        "doctor.check.notify": {"en": "notify {type}", "es": "notificación {type}"},
        # details and fixes
        "doctor.config.none": {
            "en": "no config file: using built-in defaults (tenant 'default')",
            "es": "sin archivo de configuración: se usan los valores predeterminados (tenant 'default')",
        },
        "doctor.config.none_fix": {
            "en": "copy examples/hushwatch.yml and pass --config or set HUSHWATCH_CONFIG",
            "es": "copie examples/hushwatch.yml e indíquelo con --config o HUSHWATCH_CONFIG",
        },
        "doctor.config.stat": {"en": "cannot read {path}: {error}", "es": "no se puede leer {path}: {error}"},
        "doctor.config.perms": {
            "en": "{path} is accessible by group/others (mode {mode})",
            "es": "{path} es accesible para el grupo u otros usuarios (modo {mode})",
        },
        "doctor.config.ok": {
            "en": "{path} ({count} {count:plural:tenant|tenants})",
            "es": "{path} ({count} {count:plural:cliente|clientes})",
        },
        "doctor.config.literal": {
            "en": "literal credentials in the config: {places}",
            "es": "credenciales literales en la configuración: {places}",
        },
        "doctor.config.literal_fix": {
            "en": 'reference them as ${ENV_VAR} and export the variable (e.g. password: "${IDX_PASSWORD}")',
            "es": 'refiéralas como ${VARIABLE} y exporte la variable (p. ej. password: "${IDX_PASSWORD}")',
        },
        "doctor.env.missing": {
            "en": "environment variable {var} is not set (used in {where})",
            "es": "la variable de entorno {var} no está definida (se usa en {where})",
        },
        "doctor.env.fix": {"en": "export {var}=...", "es": "export {var}=..."},
        "doctor.env.skipped": {
            "en": "connectivity checks skipped until the variables are set",
            "es": "se omiten los controles de conectividad hasta que se definan las variables",
        },
        "doctor.inputs.none": {
            "en": "no inputs configured (only CLI paths will work)",
            "es": "no hay entradas configuradas (solo funcionarán las rutas indicadas en la línea de comandos)",
        },
        "doctor.inputs.none_fix": {
            "en": "add an 'inputs' entry (type: file or indexer)",
            "es": "agregue una entrada en 'inputs' (type: file o indexer)",
        },
        "doctor.file.error": {"en": "{error}", "es": "{error}"},
        "doctor.file.error_fix": {
            "en": "check the path (relative paths are relative to the config file); run hushwatch as a user in the "
            "'wazuh' group to read /var/ossec/logs",
            "es": "revise la ruta (las rutas relativas son relativas al archivo de configuración); ejecute hushwatch "
            "con un usuario del grupo 'wazuh' para leer /var/ossec/logs",
        },
        "doctor.file.empty": {"en": "{path}: no readable events", "es": "{path}: no hay eventos legibles"},
        "doctor.file.empty_fix": {"en": "point to alerts.json", "es": "indique alerts.json"},
        "doctor.file.ok": {"en": "{path}: profile {profile}, {kind}", "es": "{path}: perfil {profile}, {kind}"},
        "doctor.file.alerts_hint": {
            "en": "for full log-source silence detection, also enable logall_json and analyze archives.json",
            "es": "para detectar el silencio real de las fuentes, habilite también logall_json y analice archives.json",
        },
        "doctor.tls.fix": {
            "en": "set ca_cert to your indexer root CA (Wazuh: /etc/wazuh-indexer/certs/root-ca.pem); do not "
            "disable TLS",
            "es": "configure ca_cert con la CA raíz del indexer (Wazuh: /etc/wazuh-indexer/certs/root-ca.pem); no "
            "desactive TLS",
        },
        "doctor.tls.off": {
            "en": "TLS verification is DISABLED for this connection",
            "es": "la verificación TLS está DESACTIVADA para esta conexión",
        },
        "doctor.http.creds": {
            "en": "credentials are sent over plain http to {origin}",
            "es": "las credenciales se envían por http sin cifrar a {origin}",
        },
        "doctor.http.fix": {"en": "use an https:// URL", "es": "use una URL https://"},
        "doctor.indexer.ok": {
            "en": "{kind} {version}{wazuh}",
            "es": "{kind} {version}{wazuh}",
        },
        "doctor.indexer.wazuh": {"en": " (Wazuh indexer)", "es": " (indexer de Wazuh)"},
        "doctor.indexer.time_field": {
            "en": "time field {field} not found in {index}",
            "es": "no se encontró el campo de tiempo {field} en {index}",
        },
        "doctor.indexer.time_field_fix": {
            "en": "set time_field (Wazuh alerts: 'timestamp'; ECS: '@timestamp')",
            "es": "configure time_field (alertas de Wazuh: 'timestamp'; ECS: '@timestamp')",
        },
        "doctor.indexer.count": {
            "en": "{count} documents in the last 24h",
            "es": "{count} documentos en las últimas 24 h",
        },
        "doctor.indexer.count_fix": {
            "en": "check the index pattern and that data is still arriving",
            "es": "revise el patrón de índices y que los datos sigan llegando",
        },
        "doctor.indexer.alerts": {
            "en": "alerts index: silence findings will be alert-level",
            "es": "índice de alertas: el silencio detectado será de alertas",
        },
        "doctor.indexer.alerts_fix": {
            "en": "add a wazuh-archives-* input for full log-source silence detection",
            "es": "agregue una entrada wazuh-archives-* para detectar el silencio real de las fuentes",
        },
        "doctor.remote.fix": {
            "en": "check url, credentials (read-only role) and network",
            "es": "revise la URL, las credenciales (rol de solo lectura) y la red",
        },
        "doctor.api.tls_fix": {
            "en": "set ca_cert (the default Wazuh API cert is only valid for 'localhost')",
            "es": "configure ca_cert (el certificado predeterminado de la API de Wazuh solo es válido para "
            "'localhost')",
        },
        "doctor.api.fix": {
            "en": "check url (port 55000), credentials and RBAC (agents:read, rules:read, manager:read)",
            "es": "revise la URL (puerto 55000), las credenciales y el RBAC (agents:read, rules:read, manager:read)",
        },
        "doctor.api.ok": {
            "en": "API {version}; {count} {count:plural:agent|agents} ({summary})",
            "es": "API {version}; {count} {count:plural:agente|agentes} ({summary})",
        },
        "doctor.api.stale": {
            "en": "{count} {count:plural:agent|agents} without keepalive for more than {age}",
            "es": "{count} {count:plural:agente|agentes} sin keepalive desde hace más de {age}",
        },
        "doctor.api.stale_fix": {
            "en": "run 'hushwatch report' to see which and since when",
            "es": "ejecute 'hushwatch report' para ver cuáles y desde cuándo",
        },
        "doctor.api.no_stats": {
            "en": "manager daemon stats unavailable (event drop checks will be skipped)",
            "es": "estadísticas de los daemons del manager no disponibles (se omitirán los controles de eventos "
            "descartados)",
        },
        "doctor.api.no_stats_fix": {
            "en": "grant manager:read, or upgrade to a Wazuh version with /manager/daemons/stats",
            "es": "otorgue manager:read, o actualice a una versión de Wazuh con /manager/daemons/stats",
        },
        "doctor.ruleset.missing": {"en": "{path} not found", "es": "no se encontró {path}"},
        "doctor.ruleset.missing_fix": {
            "en": "fix ruleset_dirs (relative paths are relative to the config file)",
            "es": "corrija ruleset_dirs (las rutas relativas son relativas al archivo de configuración)",
        },
        "doctor.ruleset.ok": {
            "en": "{path}: {rules} {rules:plural:rule|rules}, {problems} parse {problems:plural:problem|problems}",
            "es": "{path}: {rules} {rules:plural:regla|reglas}, {problems} "
            "{problems:plural:problema|problemas} de lectura",
        },
        "doctor.ruleset.problems_fix": {
            "en": "see 'hushwatch audit' for details",
            "es": "vea 'hushwatch audit' para más detalles",
        },
        "doctor.path.missing": {"en": "{path} not found", "es": "no se encontró {path}"},
        "doctor.path.missing_fix": {
            "en": "fix the path (relative paths are relative to the config file)",
            "es": "corrija la ruta (las rutas relativas son relativas al archivo de configuración)",
        },
        "doctor.path.ok": {"en": "{path}", "es": "{path}"},
        "doctor.agents.ok": {
            "en": "{path}: {count} {count:plural:agent|agents}",
            "es": "{path}: {count} {count:plural:agente|agentes}",
        },
        "doctor.agents.bad": {"en": "{error}", "es": "{error}"},
        "doctor.agents.bad_fix": {
            "en": "export the Wazuh API GET /agents response as JSON (data.affected_items)",
            "es": "exporte como JSON la respuesta de GET /agents de la API de Wazuh (data.affected_items)",
        },
        "doctor.state.create": {
            "en": "{path} will be created (mode 0700)",
            "es": "{path} se creará (modo 0700)",
        },
        "doctor.state.unwritable": {"en": "{path} is not writable", "es": "no se puede escribir en {path}"},
        "doctor.state.fix": {
            "en": "set state_dir to a private directory you own (chmod 700)",
            "es": "configure state_dir con un directorio privado propio (chmod 700)",
        },
        "doctor.state.legacy_fix": {
            "en": "nothing to do: run 'hushwatch check' (or move the file yourself)",
            "es": "no hace falta nada: ejecute 'hushwatch check' (o mueva el archivo usted mismo)",
        },
        "doctor.notify.http": {"en": "webhook URL is not https", "es": "la URL del webhook no usa https"},
        "doctor.notify.ok": {
            "en": "https webhook configured (not sent)",
            "es": "webhook https configurado (no se envió nada)",
        },
    }
)


@dataclass(slots=True)
class Check:
    tenant: str
    name: Message | str
    status: str  # ok | warn | fail
    detail: Message | str
    fix: Message | str = ""


def run_doctor(cfg: Config, tenants: list[str], *, console: Console, lang: str = "en") -> bool:
    """Run every check for the named tenants, print a table, return True when nothing FAILED."""
    checks: list[Check] = []
    checks.extend(_config_checks(cfg))
    for name in tenants:
        try:
            checks.extend(_tenant_checks(cfg, name))
        except Exception as exc:  # one broken check must not hide the others (nor show a traceback)
            checks.append(Check(name, M("doctor.check.unexpected"), "fail", f"{type(exc).__name__}: {exc}"[:300]))
    table = Table(title=render(M("doctor.title"), lang), show_lines=False, expand=True)
    table.add_column(render(M("doctor.col.tenant"), lang), no_wrap=True)
    table.add_column(render(M("doctor.col.check"), lang), no_wrap=True)
    table.add_column(render(M("doctor.col.status"), lang), no_wrap=True)
    table.add_column(render(M("doctor.col.detail"), lang), overflow="fold", ratio=1)
    table.add_column(render(M("doctor.col.fix"), lang), overflow="fold", ratio=1)  # never cut short
    colors = {"ok": "green", "warn": "yellow", "fail": "red"}
    for c in checks:
        table.add_row(
            Text(c.tenant),
            Text(render(c.name, lang)),
            Text(render(M(f"doctor.status.{c.status}"), lang), style=f"bold {colors[c.status]}"),
            Text(render(c.detail, lang)),
            Text(render(c.fix, lang)),
        )
    console.print(table)
    failed = sum(c.status == "fail" for c in checks)
    warned = sum(c.status == "warn" for c in checks)
    console.print(Text(render(M("doctor.summary", checks=len(checks), failed=failed, warned=warned), lang)))
    return failed == 0


def _config_checks(cfg: Config) -> list[Check]:
    if cfg.path is None:
        return [Check("-", M("doctor.check.config"), "warn", M("doctor.config.none"), M("doctor.config.none_fix"))]
    out: list[Check] = []
    shown = str(cfg.path.expanduser().absolute())
    try:
        mode = cfg.path.stat().st_mode
    except OSError as exc:
        error = exc.strerror or type(exc).__name__
        return [Check("-", M("doctor.check.config"), "fail", M("doctor.config.stat", path=shown, error=error))]
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        out.append(
            Check(
                "-",
                M("doctor.check.config_perms"),
                "warn",
                M("doctor.config.perms", path=shown, mode=f"{stat.S_IMODE(mode):o}"),
                f"chmod 600 {shown}",
            )
        )
    else:
        out.append(
            Check("-", M("doctor.check.config"), "ok", M("doctor.config.ok", path=shown, count=len(cfg.tenants)))
        )
    if cfg.literal_secrets:
        places = ", ".join(cfg.literal_secrets[:5]) + (" …" if len(cfg.literal_secrets) > 5 else "")
        out.append(
            Check(
                "-",
                M("doctor.check.credentials"),
                "warn",
                M("doctor.config.literal", places=places),
                M("doctor.config.literal_fix"),
            )
        )
    return out


def _tenant_checks(cfg: Config, name: str) -> list[Check]:
    tenant = cfg.tenants[name]
    checks: list[Check] = []
    missing = cfg.missing_env.get(name, [])
    by_var: dict[str, list[str]] = {}
    for var, where in missing:
        by_var.setdefault(var, []).append(where)
    for var, places in sorted(by_var.items()):
        checks.append(
            Check(
                name,
                M("doctor.check.env"),
                "fail",
                M("doctor.env.missing", var=var, where=", ".join(places[:3])),
                M("doctor.env.fix", var=var),
            )
        )
    connect = not missing  # never try to log in with a "${VAR}" placeholder
    if not tenant.inputs:
        checks.append(
            Check(name, M("doctor.check.inputs"), "warn", M("doctor.inputs.none"), M("doctor.inputs.none_fix"))
        )
    for item in tenant.inputs:
        if item.type == "file":
            checks.append(_file_check(tenant, item))
        else:
            checks.extend(_indexer_checks(tenant, item, connect))
    if tenant.wazuh_api is not None:
        checks.extend(_api_checks(tenant, connect))
    for rs_dir in tenant.ruleset_dirs:
        checks.append(_ruleset_check(tenant, rs_dir))
    if tenant.dispositions:
        checks.append(_path_check(tenant, M("doctor.check.dispositions"), tenant.dispositions))
    if tenant.agents_file:
        checks.append(_agents_check(tenant, tenant.agents_file))
    checks.append(_state_check(tenant))
    for target in tenant.notify:
        label = M("doctor.check.notify", type=target.type)
        if "${" in target.url:
            continue  # reported as a missing environment variable
        if not target.url.startswith("https://"):
            checks.append(Check(name, label, "warn", M("doctor.notify.http"), M("doctor.http.fix")))
        else:
            checks.append(Check(name, label, "ok", M("doctor.notify.ok")))
    return checks


def _origin(url: str) -> str:
    from .net import safe_url

    return safe_url(url)


def _file_check(tenant: TenantConfig, item: InputConfig) -> Check:
    from .ingest import IngestError, detect_profile, iter_documents

    path = item.path or ""
    label = M("doctor.check.file_input")
    try:
        docs = []
        for doc, _label in iter_documents([path]):
            docs.append(doc)
            if len(docs) >= 50:
                break
    except (IngestError, OSError) as exc:
        message = getattr(exc, "message", None)
        error = message if isinstance(message, Message) else str(exc)
        return Check(
            tenant.name, label, "fail", M("doctor.file.error", path=path, error=error), M("doctor.file.error_fix")
        )
    if not docs:
        return Check(tenant.name, label, "fail", M("doctor.file.empty", path=path), M("doctor.file.empty_fix"))
    profile = detect_profile(docs) if item.profile == "auto" else item.profile
    has_rule = sum(1 for d in docs if isinstance(d.get("rule"), dict))
    kind = "alerts" if has_rule == len(docs) else ("archives" if has_rule == 0 else "mixed")
    hint: Message | str = M("doctor.file.alerts_hint") if kind == "alerts" else ""
    return Check(tenant.name, label, "ok", M("doctor.file.ok", path=path, profile=profile, kind=kind), hint)


def _indexer_checks(tenant: TenantConfig, item: InputConfig, connect: bool) -> list[Check]:
    from .ingest.opensearch import IndexerClient
    from .net import RemoteError

    name = M("doctor.check.indexer", index=item.index)
    checks: list[Check] = []
    if not item.verify_tls:
        checks.append(Check(tenant.name, name, "warn", M("doctor.tls.off"), M("doctor.tls.fix")))
    url = item.url or ""
    if url.startswith("http://") and (item.password or item.api_key or item.username):
        checks.append(
            Check(tenant.name, name, "warn", M("doctor.http.creds", origin=_origin(url)), M("doctor.http.fix"))
        )
    if not connect:
        checks.append(Check(tenant.name, name, "warn", M("doctor.env.skipped")))
        return checks
    try:
        with IndexerClient(item) as client:
            info = client.engine()
            version = ".".join(str(v) for v in info.version) if info.version else "?"
            wazuh = M("doctor.indexer.wazuh") if info.wazuh_indexer else ""
            checks.append(
                Check(tenant.name, name, "ok", M("doctor.indexer.ok", kind=info.kind, version=version, wazuh=wazuh))
            )
            caps = client.field_caps(item.index)
            if item.time_field not in caps:
                checks.append(
                    Check(
                        tenant.name,
                        name,
                        "fail",
                        M("doctor.indexer.time_field", field=repr(item.time_field), index=item.index),
                        M("doctor.indexer.time_field_fix"),
                    )
                )
            end = datetime.now(UTC)
            count = client.count(item.index, query=None, start=end - timedelta(hours=24), end=end)
            checks.append(
                Check(
                    tenant.name,
                    name,
                    "ok" if count > 0 else "warn",
                    M("doctor.indexer.count", count=count),
                    "" if count else M("doctor.indexer.count_fix"),
                )
            )
            if "archives" not in item.index:
                checks.append(
                    Check(tenant.name, name, "ok", M("doctor.indexer.alerts"), M("doctor.indexer.alerts_fix"))
                )
    except RemoteError as exc:
        fix = M("doctor.tls.fix") if getattr(exc, "kind", "") == "tls" else M("doctor.remote.fix")
        checks.append(Check(tenant.name, name, "fail", exc.message, fix))
    return checks


def _api_checks(tenant: TenantConfig, connect: bool) -> list[Check]:
    from .ingest.wazuh_api import WazuhAPI
    from .net import RemoteError

    api_cfg = tenant.wazuh_api
    assert api_cfg is not None
    label = M("doctor.check.api")
    checks: list[Check] = []
    if not api_cfg.verify_tls:
        checks.append(Check(tenant.name, label, "warn", M("doctor.tls.off"), M("doctor.api.tls_fix")))
    if api_cfg.url.startswith("http://") and (api_cfg.password or api_cfg.username):
        checks.append(
            Check(tenant.name, label, "warn", M("doctor.http.creds", origin=_origin(api_cfg.url)), M("doctor.http.fix"))
        )
    if not connect:
        checks.append(Check(tenant.name, label, "warn", M("doctor.env.skipped")))
        return checks
    try:
        with WazuhAPI(api_cfg) as api:
            info = api.info()
            agents = api.agents()
            try:
                stats = api.daemon_stats()
            except RemoteError:
                stats = None
    except RemoteError as exc:
        fix = M("doctor.api.tls_fix") if getattr(exc, "kind", "") == "tls" else M("doctor.api.fix")
        return [*checks, Check(tenant.name, label, "fail", exc.message, fix)]
    version = str(info.get("api_version", "?")) if isinstance(info, dict) else "?"
    by_status: dict[str, int] = {}
    stale = 0
    now = datetime.now(UTC)
    for agent in agents:
        by_status[agent.status] = by_status.get(agent.status, 0) + 1
        if agent.last_keepalive and now - agent.last_keepalive > timedelta(days=1) and not agent.is_manager:
            stale += 1
    summary = ", ".join(f"{k}: {v}" for k, v in sorted(by_status.items()))
    checks.append(
        Check(tenant.name, label, "ok", M("doctor.api.ok", version=version, count=len(agents), summary=summary))
    )
    if stale:
        checks.append(
            Check(
                tenant.name,
                label,
                "warn",
                M("doctor.api.stale", count=stale, age=humanize(timedelta(days=1))),
                M("doctor.api.stale_fix"),
            )
        )
    if stats is None:
        checks.append(Check(tenant.name, label, "warn", M("doctor.api.no_stats"), M("doctor.api.no_stats_fix")))
    return checks


def _ruleset_check(tenant: TenantConfig, rs_dir: str) -> Check:
    from .wazuh.ruleset import load_ruleset

    label = M("doctor.check.ruleset")
    if not Path(rs_dir).exists():
        return Check(
            tenant.name, label, "fail", M("doctor.ruleset.missing", path=rs_dir), M("doctor.ruleset.missing_fix")
        )
    rs = load_ruleset([rs_dir])
    status = "warn" if rs.errors else "ok"
    detail = M("doctor.ruleset.ok", path=rs_dir, rules=len(rs.rules), problems=len(rs.errors))
    return Check(tenant.name, label, status, detail, M("doctor.ruleset.problems_fix") if rs.errors else "")


def _path_check(tenant: TenantConfig, label: Message, path: str) -> Check:
    if not Path(path).is_file():
        return Check(tenant.name, label, "fail", M("doctor.path.missing", path=path), M("doctor.path.missing_fix"))
    if not os.access(path, os.R_OK):
        return Check(tenant.name, label, "fail", M("doctor.state.unwritable", path=path), M("doctor.path.missing_fix"))
    return Check(tenant.name, label, "ok", M("doctor.path.ok", path=path))


def _agents_check(tenant: TenantConfig, path: str) -> Check:
    from .config import ConfigError
    from .engine import load_agent_inventory

    label = M("doctor.check.agents")
    try:
        agents = load_agent_inventory(path)
    except ConfigError as exc:
        return Check(tenant.name, label, "fail", M("doctor.agents.bad", error=str(exc)), M("doctor.agents.bad_fix"))
    return Check(tenant.name, label, "ok", M("doctor.agents.ok", path=path, count=len(agents)))


def _state_check(tenant: TenantConfig) -> Check:
    from .state import state_dir_problem

    label = M("doctor.check.state")
    state_dir = tenant.resolved_state_dir().expanduser()
    problem = state_dir_problem(state_dir)
    if problem is not None:
        status, message = problem
        fix = M("doctor.state.legacy_fix") if status == "warn" else M("doctor.state.fix")
        return Check(tenant.name, label, status, message, fix)
    if not state_dir.exists():
        parent = state_dir.parent
        while not parent.exists() and parent != parent.parent:
            parent = parent.parent
        if not os.access(parent, os.W_OK | os.X_OK):
            return Check(
                tenant.name, label, "fail", M("doctor.state.unwritable", path=str(parent)), M("doctor.state.fix")
            )
        return Check(tenant.name, label, "ok", M("doctor.state.create", path=str(state_dir)))
    if not os.access(state_dir, os.W_OK | os.X_OK):
        return Check(
            tenant.name, label, "fail", M("doctor.state.unwritable", path=str(state_dir)), M("doctor.state.fix")
        )
    return Check(tenant.name, label, "ok", M("doctor.path.ok", path=str(state_dir)))
