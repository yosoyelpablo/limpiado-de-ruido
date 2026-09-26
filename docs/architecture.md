# hushwatch architecture (v0.1)

> **hush** the noise, **watch** the silence.
> hushwatch answers two questions for a SOC: *which alerts can we safely stop looking at?* and *which of our
> detections quietly stopped working?*

This document is the contract between modules. If you implement a module, read **§1 Rules for every module**
and your module's section. Everything is Python ≥3.10, stdlib + `pyyaml`, `rich`, `typer`, `httpx`.

---------------------------------------------------------------------------------------------------------------

## 0. Design principles (non-negotiable)

1. **Never recommend hiding an attack.** Volume, concentration, regularity and duplicates describe brute
   force, spraying, scanning and C2 beaconing as well as benign automation. Every tuning suggestion passes
   hard **safety gates** and a **backtest** (§5). When in doubt the verdict is `INVESTIGATE`, not `TUNE`.
2. **Never a false green.** Anything the input cannot support is `not_assessed` (grey), never OK. Partial
   results (shard failures, truncation, 0 events, auth errors) are findings in domain `assessment` and force
   exit code 3. Every report carries a **DataBasis** banner (§2.4).
3. **The tool must not become noise.** Silence detection is calibrated against an explicit **alarm budget**
   (expected false alarms per run), grouped by root cause (one PIPELINE finding instead of 400), with
   hysteresis in cron mode.
4. **Read-only.** hushwatch never writes to the SIEM. Suggestions are files for humans to review.
5. **Private by default.** No telemetry, no LLM, no network except the configured SIEM/webhooks.
   Redaction happens at the output boundary (§2.3). Test fixtures and demo data use only RFC 5737 / RFC 1918
   IPs, `example.com/.test` domains and obviously fake names.
6. **Logs are attacker-controlled input.** Every string from an event is escaped for its sink: XML/regex
   (Wazuh rules), HTML (report), Rich markup + control chars (console), Markdown, CSV formulas, Slack.
7. **Bounded memory.** Streaming single pass with sketches (Space-Saving, HyperLogLog, reservoirs) and caps
   that are *reported* when hit.
8. **Explainable.** Every finding has evidence numbers, plain reasons (EN/ES) and a reproduce hint.

## 1. Rules for every module

* Type hints everywhere; `mypy --strict` clean; `ruff check` clean (config in pyproject, line length 120).
* No `print`. Library code returns data; only `hushwatch/cli.py` and `hushwatch/report/console.py` write to
  the terminal.
* User-facing text is never an f-string: use `hushwatch.i18n.M(key, **params)` and register EN+ES text for
  every key your module uses with `hushwatch.i18n.register({...})` at module import time. Key prefix = your
  module (`noise.`, `silence.`, `coverage.`, `wazuh.`, `pipeline.`, `assessment.`, `report.`...).
* Any value that identifies a host, user, IP, URL, command line, file path or domain and goes into a
  `Message` param or a finding's `evidence` MUST be wrapped: `Entity("host", name)`. Kinds: `host`, `user`,
  `ip`, `url`, `cmd`, `file`, `domain`, `val`. Rule ids, levels, counts, log source names (channels, decoder
  names, file paths like `/var/log/auth.log`) are **not** entities.
* `Finding.subject` is a RAW stable identifier (e.g. `rule:5710|srcip:10.0.0.5`, `agent:dc01|ls:Security`).
* Times: all datetimes are timezone-aware UTC. Local-time bucketing uses `tenant.tz` (zoneinfo, DST-safe).
  Internally prefer integer epoch seconds / hour indexes for speed.
* Tests: pytest, in `tests/test_<module>.py`, no network (use `httpx.MockTransport` for HTTP), deterministic
  (seeded `random.Random`), synthetic data only (RFC 5737 / RFC 1918 IPs, `*.example` names).
* Do not edit files owned by another module. If you need a small shared helper that does not exist, put it
  in your own module (private) and mention it in your final report.

## 2. Shared core (already implemented — read the code)

* `hushwatch/models.py` — `Event`, `Finding`, `Severity`, `Confidence`, `DataBasis`, `Report`, `flatten`,
  `get_path`, `is_empty`, `stable_hash`, `fingerprint`, `sort_findings`, `iter_entities`, `DOMAINS`.
* `hushwatch/i18n.py` — `M`, `Message`, `Entity`, `register`, `render(msg, lang, entity_formatter)`,
  `entity_formatter(redactor)`.
* `hushwatch/redact.py` — `Redactor.for_tenant(tenant, state_dir)`, `.token(value, kind)`, `.text(str)`,
  `.learn([(kind, value)])`.
* `hushwatch/config.py` — `TenantConfig` (+ `NoiseSettings`, `SilenceSettings`, `InputConfig`, `ApiConfig`,
  `NotifyConfig`, `Expectation`, `CalendarEntry`), `load_config`, `parse_config`, `ConfigError`.
  Helpers: `tenant.tz`, `tenant.tier_for(agent)`, `tenant.is_internal(ip)`, `tenant.is_trusted(field, v)`,
  `tenant.in_calendar(date)`.
* `hushwatch/timeutil.py` — `parse_ts(value, naive_tz=, default_year=)`, `parse_duration`, `floor_to`,
  `iso`, `humanize`, `UTC`.
* `hushwatch/tuning.py` — `Condition(field, value)` (exact match on an ORIGINAL dotted path such as
  `agent.name`, `predecoder.hostname`, `location`, `data.srcip`, `data.win.eventdata.image`) and
  `Suggestion` (rule + conditions + verdict + backtest numbers). `Suggestion.matches(event)` is the single
  source of truth for semantics: the backtest counts with it, the Wazuh emitter must generate XML matching
  exactly the same events.
* `hushwatch/inventory.py` — `AgentInfo` (Wazuh API agent: id, name, status, last_keepalive, platform,
  groups, version...). Produced by `ingest/wazuh_api.py`, consumed by coverage/silence.

### 2.1 Finding kinds (registry)

| domain | kind | meaning |
|---|---|---|
| noise | `noise.tune` | safe, scoped tuning candidate (passed all gates + backtest) |
| noise | `noise.investigate` | noisy but NOT safe to tune (gate tripped: new, burst, sensitive, co-occurs with high alerts, external anchor, beacon-like) |
| noise | `noise.fix_at_source` | noise to fix outside the rule (FIM path ignore, exposed service, agent config) |
| noise | `noise.aggregate` | high-duplicate rule: aggregate (frequency/timeframe) instead of muting |
| noise | `noise.do_not_tune` | noisy rule blocked by hard rule (level ≥ max_tunable, TP disposition) — informational |
| noise | `noise.index_volume` | clean candidate with no analyst impact (already at/below the demote level or below triage_level): index/storage volume only — options: no_log child, level below log_alert_level, overwrite (with trade-offs) |
| noise | `noise.emit_skipped` | a tune suggestion was not written as a Wazuh rule (unsafe/unsupported value, non-Wazuh data) — informational |
| silence | `silence.silent` | a source that should be sending is not (P0 test) |
| silence | `silence.drop` | volume dropped far below expected (NB tail + effect size) |
| silence | `silence.decay` | slow sustained decline (recent 7d vs reference) |
| silence | `silence.rule_dark` | a heartbeat-like rule stopped firing while its source is alive |
| silence | `silence.field_lost` | a field present in ≥95% of a log source's events vanished |
| silence | `silence.tampering` | silence preceded by log-clearing / audit-policy / agent-stop events (possible T1070/T1562) |
| silence | `silence.unmonitorable` | a critical source too sparse to detect silence within its SLA |
| pipeline | `pipeline.global_silence` | many sources went silent together (collector/indexer/ingest problem) |
| pipeline | `pipeline.agent_disconnected` | Wazuh API reports agent disconnected / never_connected |
| pipeline | `pipeline.agent_no_data` | agent alive (keepalive fresh) but no events → collection broken |
| pipeline | `pipeline.lag` / `pipeline.clock_skew` | ingest lag / future timestamps |
| pipeline | `pipeline.manager_drops` | analysisd/remoted dropped events, agent flooding (rules 202-204) |
| coverage | `coverage.missing_source` | host lacks a log source its peers (≥90%) or its expectation contract send |
| coverage | `coverage.missing_event_type` | e.g. 4688 absent while 4624 flows (audit policy off) |
| tuning | `tuning.risky_suppression` | existing local rule that mutes too broadly / on attacker-controlled fields / breaks correlation |
| tuning | `tuning.expired` | suppression past its expiry |
| assessment | `assessment.incomplete` | part of the analysis could not run or saw partial data |
| assessment | `assessment.learning` | not enough history for a verdict |

Severity guidance: `critical` = likely active blindness on a critical source or possible tampering;
`high` = blind spot / risky suppression; `medium` = actionable hygiene; `low`/`info` = context.

### 2.2 Report sections (JSON-serializable dicts, Entities allowed as values)

Each analyzer returns its findings plus one section dict. Renderers know these shapes.

```text
sections["noise"] = {
  "status": "ok|warn|fail|not_assessed",
  "totals": {"alerts": int, "analyst_facing": int, "rules": int, "days": float,
             "clusters": int, "top5_share": float},
  "rules": [  # top N by analyst-facing volume
     {"rule_id": str, "description": str, "level": int, "total": int, "per_day": float,
      "analyst_facing": int, "share": float, "clusters": int, "days_active": int, "days": int,
      "top_anchor": {"field": str, "value": Entity, "share": float} | None,
      "verdict": "tune|investigate|fix_at_source|aggregate|do_not_tune|watch|learning",
      "daily": [int, ...]}   # sparkline
  ],
  "time_saved_minutes_per_day": [low, high] | None,   # UPPER-BOUND estimate, analyst-facing clusters only
  "suppressions_file": str | None,
}
sections["silence"] = {
  "status": ..., "alpha_eff": float, "keys_evaluated": int,
  "status_counts": {"ok": int, "silent": int, "drop": int, "learning": int, "unmonitorable": int, "explained": int},
  "sources": [ {"level": "tenant|log_source|agent|agent_log_source|rule", "key": {...Entities...},
                "status": str, "last_seen": iso, "observed": float, "expected": float,
                "p": float | None, "tier": str, "duty": "always_on|business_hours|intermittent|unknown",
                "daily": [int, ...]} ],     # only non-ok + critical ones, capped
  "monitorability": {"critical_total": int, "critical_monitorable": int},
}
sections["coverage"] = {"status": ..., "platforms": {...}, "matrix": [{"agent": Entity, "platform": str,
                         "log_sources": {name: "present|missing|silent"}}], "expected_sources": [...]}
sections["pipeline"] = {"status": ..., "agents": {"active": int, "disconnected": int, ...}, "checks": [...]}
sections["tuning"] = {"status": ..., "rules_parsed": int, "local_rules": int, "risky": int}
```

### 2.3 Redaction

Renderers receive `redactor: Redactor | None`. With a redactor they (a) call `redactor.learn()` with every
`Entity` in the report (`models.iter_entities`), (b) render entities with `i18n.entity_formatter(redactor)`,
(c) pass remaining free text through `redactor.text()`, (d) replace `Finding.subject` with
`redactor.token(subject, "val")`. Suppression files always contain real values (they must, to work): they are
written local-only with mode 0600 and a header saying so; `--redact` never applies to them.

### 2.4 DataBasis

The ingest layer fills `DataBasis` (input kind, profile, time range, `now` and where it came from, event
count, malformed lines, bad/future timestamps, sampled/truncated flags, partial failures). Input kinds:
Wazuh `alerts.json` / `wazuh-alerts-*` contain ONLY rule matches at or above `log_alert_level` (default 3).
Silence measured on alerts is *alert silence*, not *source silence*: silence findings computed from alerts
get `Confidence.LOW`/`MEDIUM` and the banner says so. Archives (`archives.json`, `wazuh-archives-*`) are
full-fidelity.

## 3. Ingest (`hushwatch/ingest/`)

`hushwatch/ingest/__init__.py` exposes:

```python
class EventSource(Protocol):
    basis: DataBasis
    def __iter__(self) -> Iterator[Event]: ...     # re-iterable (files are re-read) for the backtest pass

def open_files(paths: Sequence[str | Path], *, profile: str = "auto", tenant: TenantConfig,
               since: datetime | None = None, until: datetime | None = None,
               max_events: int | None = None, keep_fields: bool = True) -> EventSource
```

* `files.py`: NDJSON (Wazuh alerts.json/archives.json), JSON arrays, CSV (header row), `.gz`, directories
  (recursive), globs, Wazuh rotated layout `…/alerts/YYYY/Mon/ossec-alerts-DD.json.gz` (prune by path date
  when `since` given). Tolerate a partial last line; count malformed lines (never crash). Orders of magnitude:
  1 GB must stream with bounded memory. Use `orjson` if importable, else `json`.
* `profiles.py`: normalization profiles returning `Event`:
  * `wazuh4` — ts=`timestamp` (manager processing time, `+0000` offset), rule_id=`rule.id` (string),
    rule_name=`rule.description`, severity=`rule.level`, source=`agent.name` (for agent `000` with a
    `predecoder.hostname`, use that hostname: syslog devices arrive via the manager), log_source=
    `data.win.system.channel` if present else `location` (e.g. `/var/log/auth.log`, `EventChannel`,
    `journald`), rule_groups=`rule.groups`, tags=`rule.mitre.id`, mitre_tactics=`rule.mitre.tactic`,
    event_id=`id`, event_code=`data.win.system.eventID`, os_platform inferred (`windows` when
    `data.win` present or location `EventChannel`; `linux` for `/var/log/*`, `journald`, `audit`...).
    Entities: `src_ip`=`data.srcip`, `dst_ip`=`data.dstip`, `user`=`data.dstuser`|`data.srcuser`|
    `data.win.eventdata.targetUserName`, `host`=`agent.name`, `process`=`data.win.eventdata.image`,
    `parent_process`=`data.win.eventdata.parentImage`, `command_line`=`data.win.eventdata.commandLine`,
    `file`=`syscheck.path`, `url`=`data.url`. Archives documents have no `rule` object: rule fields None.
  * `wazuh5` — detected (e.g. `wazuh.*`/`event.original` shape, no `rule.id` string). Parse what is
    possible and add a DataBasis warning; suppression output is refused for 5.x.
  * `ecs` — ts=`event.ingested`|`@timestamp`, rule_id=`kibana.alert.rule.uuid`|`rule.id`,
    rule_name=`kibana.alert.rule.name`|`rule.name`, severity from `kibana.alert.severity`
    (low→3, medium→7, high→10, critical→13) or `event.severity`, source=`host.name`|`agent.name`,
    log_source=`data_stream.dataset`|`event.dataset`|`winlog.channel`, event_code=`event.code`,
    tags from `threat.technique.id`/`kibana.alert.rule.threat...`, dispositions via
    `kibana.alert.workflow_status`/`kibana.alert.workflow_reason`.
  * `generic` — `InputConfig.mapping` {our_field: dotted source path}.
  * `detect_profile(sample_docs) -> str` autodetects from the first N documents.
  * Time parsing via `timeutil.parse_ts(..., naive_tz=ZoneInfo(input.naive_timezone) or UTC,
    default_year=<file year>)`; count failures in `basis.bad_timestamps`, count ts > wallclock+5min in
    `basis.future_timestamps` (still yield them).
* `opensearch.py`: `IndexerClient(input_cfg)` for OpenSearch 1/2/3, Wazuh indexer, Elasticsearch 7/8/9.
  Engine detection (`GET /`: distribution/tagline/`X-elastic-product` header; Wazuh indexer masquerades as
  7.10.2). Methods: `stream(query, fields, start, end) -> Iterator[dict]` (PIT + search_after with
  per-backend differences; fallback to scroll on 403; always close PIT/scroll in `finally`; `_source`
  filtering), `composite(sources, query, start, end, interval, time_zone) -> Iterator[(key_dict, count)]`
  (after_key paging, `fixed_interval`, epoch-ms keys), `count(query)`, `field_caps(index)`.
  Every response: check `timed_out`, `_shards.failed`; record into `basis.partial_failures` (never treat
  as zero). TLS: build an `ssl.SSLContext` (system trust + optional `ca_cert`); `verify_tls: false` only
  from config, recorded as a DataBasis warning. Credentials never logged.
* `wazuh_api.py`: `WazuhAPI(api_cfg)`: `POST /security/user/authenticate?raw=true` (basic auth) → JWT kept
  in memory; refresh ~60 s before `exp` (decode payload) and once on 401; never call
  `DELETE /security/user/authenticate`. Rate-limit (max_requests_per_minute, back off on 429).
  `agents()` (paginate `limit=500`, `select=` fields, include `status`, `lastKeepAlive`, `os.platform`,
  `group`, `version`, exclude or flag `000`), `rules(ids=None)` (4.x only), `manager_info()`
  (`GET /`, `GET /manager/info`), `daemon_stats()` (`GET /manager/daemons/stats`, tolerate 404),
  `logcollector_stats(agent_id)` (tolerate 404/unsupported). All return plain dicts/dataclasses.

## 4. Collectors and the single pass (`hushwatch/engine.py`, integration)

One read of the input fans out to collectors, each with `add(event)`, then `finalize(...)`:
`NoiseCollector` (§5), `CubeCollector` (§6), `FieldCollector` (§6.6), `CoverageCollector` (§7). The
backtest (§5.5) re-iterates the source (second pass) only for the top candidates.

## 5. Noise (`hushwatch/analysis/noise.py`, `gates.py`, `backtest.py`, `sketches.py`, `dispositions.py`)

### 5.1 Unit of analysis
Candidates are **condition sets**, not rules: `(rule_id, [(field, value) × 1..2])`, e.g.
`rule 5710 ∧ data.srcip=10.20.0.15` or `rule 60106 ∧ agent=SRV-BACKUP-01 ∧ data.win.eventdata.subjectUserName=svc_backup`.
Whole-rule tuning (no field condition) is only proposed with `noise.allow_rule_wide`.

### 5.2 Stable anchor fields (allowlist; profile-specific paths)
`agent` (source host), `location`/log file (not `EventChannel`), `src_ip` **only if internal**
(`tenant.is_internal`), service accounts (`user` value matching `tenant.trusted_entities["user"]` or ending
with `$` machine accounts or `svc`/`service` prefixes — configurable), `parent_process`+`process` full paths,
`decoder.name`, `syscheck.path` (FIM → `fix_at_source`). **Attacker-controllable** fields (command line,
URL, user-agent, file names, usernames in *failed* logons, external IPs) may appear in a condition only
together with a stable anchor, never alone.

### 5.3 Streaming statistics (bounded)
Per rule: total, per-day counts (tenant local date), per-hour counts, level, description, groups, MITRE
ids/tactics, analyst-facing count (level ≥ `triage_level`), first/last seen, HyperLogLog of
`(fingerprint, floor(ts / cluster_gap))` for **clusters** (order-independent dedup), reservoir of 3 examples.
Per (rule, anchor field): Space-Saving top-k (k=`heavy_hitters`) of values, each entry with count, error,
first_seen, last_seen and a per-day presence set. Pairs (agent × other anchor) likewise. High-level alerts
(level ≥ `high_level`): per entity value → set of local dates (for co-occurrence).

### 5.4 Safety gates (hard; each failure is a reason)
For each candidate covering ≥ `min_share` of its rule's volume:
1. `learning`: < `min_history_days` of data → no verdict (`assessment.learning`).
2. `do_not_tune`: rule level > `max_tunable_level`; any TP disposition on the candidate scope in 90 d.
3. `investigate` when: **novel** (first seen after the first `novelty_fraction` of the window);
   **not persistent** (present < `persistence` of days); **burst** (any day ≥ `burst_factor` × median daily);
   **co-occurs** with a high-level alert sharing an entity value within ±`co_occurrence_window`;
   **sensitive tactic** (rule MITRE tactic in `sensitive_tactics`) unless the anchor is internal AND
   trusted/service-account AND disposition evidence says FP/BTP; **external anchor** (public src IP) →
   `fix_at_source` ("restrict exposure") instead; **beacon-like** (periodic hourly activity to/from an
   external address) → investigate.
4. `fix_at_source`: FIM/syscheck (`syscheck` group) path noise → `agent.conf` `<ignore>`; rootcheck/SCA.
5. `aggregate`: rule with duplicate ratio ≥ 0.9 (clusters/alerts ≤ 0.1) that failed another gate only for
   being sensitive → suggest frequency/timeframe aggregation instead of muting.
6. Correlation dependency (when the ruleset is known, §8): if the rule feeds `if_matched_sid`/
   `if_matched_group`/frequency rules, the suggestion is marked `review_required` with the dependent rule ids.

Dispositions (`dispositions.py`): CSV columns `alert_id` (Wazuh `id` / indexer `_id`) or `rule_id` plus
optional `field`/`value`, `verdict` ∈ {tp, fp, btp (benign true positive), duplicate, untriaged},
`closed_at`. FP rate uses the **Wilson lower bound** at `disposition_confidence` with n ≥
`min_dispositions`; shown as "FP ≥ 87% (n=42)"; `untriaged`/auto-closed never count as FP.

### 5.5 Backtest (second pass)
For each surviving candidate, replay its *exact* generated predicate (anchored, case-sensitive exact match
per field — the same semantics the Wazuh emitter produces) over the whole window: alerts hidden per day,
share of rule volume, share of analyst-facing volume, distinct agents affected, TP dispositions inside,
and 3 example events. A candidate whose backtest hides any event with level ≥ `high_level` or any TP is
downgraded to `investigate`.

### 5.5b Noisy threshold and beaconing
A rule is mined / called noisy only with ≥ `min_noisy_alerts` (50) alerts and ≥ `min_noisy_per_day` (5/day).
"Beaconing" requires outbound traffic to the address and regular inter-arrival times (a per-candidate gap
histogram; regularity ≥ 0.6); sustained but irregular public activity is labelled "sustained activity" and blocks
tuning just the same.

### 5.6 Ranking and output
Rank `tune` candidates by **analyst-facing clusters per day hidden** (impact) — never by a blended score.
Low severity and regularity are never evidence of benignity. Time saved = hidden analyst-facing clusters/day ×
`minutes_per_alert` range, labelled "upper-bound estimate".

## 6. Silence (`hushwatch/analysis/cube.py`, `silence.py`, `fields.py`)

### 6.1 Cube
`CubeCollector` keeps hourly counts (int epoch hour → count) for keys at levels `tenant`,
`log_source`, `agent`, `agent_log_source`, `rule` (heartbeat candidates), plus first/last seen per key and
event-code sets per `agent_log_source` (for coverage). Cap keys at `silence.max_keys` (report truncation).
The indexer path fills the same cube via composite aggregations.

### 6.2 Model (per key, calibrated)
* Reference `now`: max event ts for files (or `--now`); evaluation ends at `now - ingest_lag`.
* Baseline = `[end - baseline, end - window)`; require ≥ `min_history_days` of *covered* history
  (first_seen ≤ baseline start + slack) else `learning`. Exclude calendar days (`tenant.in_calendar`).
* Expected hourly rate `mu(t) = scale_key × shape_key(how(t))` where `how` = hour-of-day in tenant local
  time (hour-of-week when ≥ 21 days of baseline). `shape_key` = per-key normalized profile smoothed ±1 h and
  shrunk toward the peer-group profile (same level, e.g. all agents) with weight `m/(n_key+m)`, m=48.
  `scale_key` = 10% trimmed mean of daily totals.
* Overdispersion: negative binomial size `k` by method of moments on baseline hourly residuals
  (`k = Σmu² / Σ((c-mu)² - c)`), clipped to [0.5, 1000]; pooled for sparse keys.
* **SILENT** (also covers gaps and rule-dark): time since last event = gap. `P0 = Π_b (1 + mu_b/k)^(-k)`
  over hour buckets in the gap (partial buckets weighted). Alarm when `P0 < alpha_eff`, with
  `alpha_eff = alarm_budget / keys_evaluated`. Seasonality-aware by construction (night hours add little).
* **DROP**: window `W = window` (grown until expected ≥ 20); observed vs expected; NB lower tail with
  moment-matched size; alarm when `cdf < alpha_eff` AND `observed/expected < drop_ratio`.
* **DECAY**: sustained decline judged on event SUMS up to "now" (the partial current day pro-rated by the key's
  hourly profile): the last 2–6 days observed vs expected from an older reference (per-weekday expectations, up to
  28 days), ratio < 0.5. A log source whose loss is covered by a silent host is folded into that host's finding.
* **Duty class** from baseline: `always_on` (active ≥ 90% of hours), `business_hours`, `intermittent`.
* **Monitorability**: `t_min` hours of normal expected traffic needed so `P0 < alpha_eff`; critical keys with
  `t_min > sla[tier]` → `silence.unmonitorable` (recommend a heartbeat).
* Hierarchy: evaluate `tenant → log_source → agent → agent_log_source`; a child of a SILENT/DROP parent is
  `explained` (no finding, listed in `related`). If ≥ `global_fraction` of always-on agents went silent
  within the same 2 h → one `pipeline.global_silence` finding and children explained.
* Rule dark: rules active on ≥ `heartbeat_rule_days` of baseline days; P0 test on the rule key; only when
  the rule's sources (agents/log_sources it fired on) are alive; otherwise explained by the source finding.
* Tampering: for each SILENT/DROP on an agent or agent_log_source, look for precursor events on the same
  agent in `[silence_start - 2h, silence_start + 10min]`: Windows EventID 1102, 104, 1100, 4719, 4906, Sysmon
  EventID 4, 16; Wazuh rules 506 (agent stopped), 504, 202/203/204 (agent queue flooding); auditd config
  change. Found → escalate to `silence.tampering` (critical, T1070.001 / T1562.002 / T1562.001).
* Severity: critical tier + SILENT → critical; standard → high; low tier → medium. Alerts-only basis lowers
  confidence.

### 6.6 Field health (`fields.py`)
Per log_source, presence rate of each field (cap 300 fields per log_source, fields present in ≥ 5%)
in baseline vs recent window; `silence.field_lost` when presence ≥ `field_presence_before` → ≤
`field_presence_after` with ≥ `field_min_events` events in both windows. Treat `is_empty` values as absent.

## 6.7 Cross-domain correlation (`hushwatch/analysis/correlate.py`)
`link_findings()` turns one incident into one finding: tampering / silent / drop on a host explains
`pipeline.agent_no_data` and `silence.unmonitorable` on that host and a coverage "silent" contract gap for the same
source; `agent_disconnected` is kept over `silent`/`drop` on the same host. A finding is never folded into a less
severe one; the keeper lists what it explains in `related` and `evidence["explained"]`.

## 7. Coverage (`hushwatch/analysis/coverage.py`)
* Inventory = agents seen in data ∪ Wazuh API agents (with platform/groups) ∪ optional CSV.
* Peer check: within a platform peer group (≥ 5 hosts), a log source sent by ≥ `peer_coverage` of peers but
  never by host X → `coverage.missing_source`.
* Expectation contracts (`tenant.expectations`) → `coverage.missing_source` with the contract name.
* Event-type check (Windows Security): 4624 present but 4688 never seen on the host while seen on peers →
  `coverage.missing_event_type` (process creation auditing off). Similar for Sysmon EventID 1 / 3.
* API: `pipeline.agent_disconnected` (disconnected ≥ SLA, never_connected), `pipeline.agent_no_data`
  (keepalive fresh but no events in window).

## 8. Wazuh ruleset, suppression emitter and tuning audit (`hushwatch/wazuh/`)
* `ruleset.py`: parse Wazuh rule XML files (they have several top-level `<group>` elements and `<var>`s: wrap
  in a synthetic root; tolerate comments/entities). `Ruleset` with rules by id: level, description, groups,
  if_sid/if_group/if_matched_sid/if_matched_group/frequency/timeframe, match options, overwrite, file path.
  `dependents(rule_id)` = rules that correlate on it (if_matched_sid/if_matched_group via groups/frequency).
* `emitter.py`: build `local_rules` XML with `xml.etree.ElementTree` only (never string concatenation).
  Mapping of condition fields → XML: `data.srcip`→`<srcip>` (exact IP), `data.dstip`→`<dstip>`,
  `data.srcuser`/`data.dstuser`→`<user type="pcre2">^…$</user>`, agent→`<location type="pcre2">^\(name\) </location>`
  (rules see location as `(agent) ip->path`), log file→`<location type="pcre2">->/path$</location>`,
  Windows channel→`<field name="win.system.channel" type="pcre2">`, any other `data.X`→`<field name="X"
  type="pcre2">` (strip `data.`). NEVER `<field>` for static names (srcip, dstip, srcport, dstport, user,
  srcuser, dstuser, url, id, data, extra_data, status, protocol, system_name, action) or agent.*/rule.*/
  location/manager.*. PCRE2 value escaping: anchor `^…\z` (Wazuh compiles PCRE2 without options, so `$` would
  also match a trailing newline), every char outside `[A-Za-z0-9_]` → `\x{HH}` using UTF-8 bytes (so no regex
  metachar and no XML special char survives); Windows backslashes match `(?:\x{5c})+`.
  IDs allocated from `suppression_id_range`, skipping every id in the parsed ruleset(s). Action DEMOTE (default): child
  rule `level="3"` (configurable) copying the parent's groups + `hushwatch_tuned,` (so the alert stays indexed and
  searchable). **Correlation caveat (verified in Wazuh 4.14.8 source):** `if_matched_group` rules are linked only
  when the correlation rule itself loads, to rules already loaded; our child file loads after the stock files, so
  copying groups does NOT make stock correlation rules (e.g. 60204) count the demoted events. Any parent with
  dependents (if_matched_sid / if_matched_group / frequency chains) → REVIEW REQUIRED, listing the dependent
  rules; siblings the child preempts (Wazuh tries children by descending level) are listed as `preempted_rules`.
  Rules load in file-name order across all rule directories; a parent defined in a file that loads after
  `hushwatch_local_rules.xml` is flagged. Descriptions carry
  "hushwatch: <kind> <fingerprint> expires <date>" (no raw log values in XML comments). Wrap in
  `<group name="local,hushwatch,">`. Also write a README/validation checklist
  (`wazuh-analysisd -t`, `wazuh-logtest` samples, backup/rollback) and a JSON "suppression spec".
  Refuse for Wazuh 5.x data.
* `audit.py`: tuning audit of existing local rules: level-0/no_log children with only `if_sid`/`if_group`
  (whole-rule mute), unanchored `match`/`regex`/`field` (substring semantics), conditions only on
  attacker-controllable fields, overwrite lowering a stock rule's level, children of rules with dependents
  (breaks correlation), muted parents with level ≥ high_level or sensitive MITRE tactics, missing
  description, expired (`expires YYYY-MM-DD` in description), duplicate ids.

## 9. Reports (`hushwatch/report/`) and notifications
* `jsonout.py` (versioned `schema_version`), `markdown.py`, `console.py` (rich; escape markup, strip C0/C1
  control chars), `html.py` (single file, no external assets, CSP meta `default-src 'none'; style-src
  'unsafe-inline'; img-src data:`, inline SVG sparklines, every string `html.escape(quote=True)`, embedded
  JSON with `<` escaped, print CSS, EN/ES). Status per domain (ok/warn/fail/not_assessed) instead of any
  single "hygiene score". The DataBasis banner is always first.
* `notify.py`: generic JSON webhook (schema_version, tenant, run id, transitions; counts and ids only unless
  `include_entities`), Slack (escape `& < >`; no `@channel`), heartbeat each run. Timeouts, no retries storm.
* `state.py`: SQLite (WAL, file 0600) per state dir: findings lifecycle `new → open → resolved → regressed`,
  hysteresis (open after N bad runs; SILENT critical opens immediately), accept/snooze file
  (`hushwatch-accept.yml`: fingerprint or kind+subject glob, owner, reason, **mandatory expiry**), notify
  only on transitions + reminders for open critical findings, run heartbeat records.

## 10. CLI (`hushwatch/cli.py`, typer)
`hushwatch demo | noise | silence | report | check | audit | doctor | version`. Exit codes: 0 no findings at/above
`--fail-on`; 1 findings at/above; 2 usage/config error; 3 analysis incomplete.
