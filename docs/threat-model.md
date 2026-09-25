# Threat model

hushwatch processes **untrusted input** (log content an attacker can influence) and produces artifacts that
humans trust (reports) and that a SIEM executes (Wazuh rules). This page lists what we defend against.

| Threat | Example | Mitigation |
|---|---|---|
| Suppression poisoning | An attacker floods a noisy rule with a marker they control (a username, a user-agent, a public IP) so the tool proposes muting it, then attacks under the mute | Candidates must be anchored on stable, non-attacker-controlled fields (host, internal IP, service account); novelty, persistence, burst, co-occurrence and sensitive-tactic gates; external anchors become "fix at source"; every suggestion is backtested and downgraded if it would hide a high-level alert or a confirmed true positive; suggestions expire |
| Breaking correlation | A level-0 child of a base rule stops the brute-force frequency rule built on it | Default action is DEMOTE (non-zero level, groups copied), rules with dependents are flagged REVIEW REQUIRED, the tuning audit finds existing mutes that break correlation |
| Rule injection | A log value like `</field></rule><rule id="100999" level="0">` ends up in local_rules.xml | XML is built with ElementTree; values are anchored PCRE2 with every non-alphanumeric character hex-escaped; IPs are validated; the output is re-parsed and checked before writing |
| Taking the SIEM down | Invalid XML or a duplicate rule id stops wazuh-analysisd | Output is re-parsed, ids are allocated from a configured range avoiding every id in the loaded ruleset, and a validation checklist (`wazuh-analysisd -t`, `wazuh-logtest`, rollback) is generated |
| Report injection | `<script>`, Rich markup, ANSI escapes, CSV formulas or Slack `<!channel>` in log values | Context-specific escaping in every renderer, strict CSP in the HTML report (no scripts at all), control characters stripped in the terminal |
| False green | An expired token, a renamed index, partial shard failures or a truncated file make the report look clean | Partial results are `assessment.incomplete` findings with exit code 3; unassessed domains are grey, never green; every report starts with a data-basis banner |
| Data leakage | Reports or webhooks shared with third parties expose usernames, IPs, hostnames | `--redact` pseudonymizes at the output boundary with a per-tenant HMAC key; webhooks carry counts and ids unless `include_entities: true`; state stores no raw subjects; files are written 0600 |
| Credential exposure | Secrets in shell history or logs | Secrets only via `${ENV}` references; never logged; configs with literal secrets and loose permissions trigger a warning |
| Supply chain | A compromised dependency or release | Minimal dependencies (pyyaml, rich, typer, httpx), pinned CI actions recommended, no install-time code |
