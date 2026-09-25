# Security policy

hushwatch runs next to your SIEM, reads every alert and holds read-only credentials for your indexer and
Wazuh API. We treat its own security seriously.

## Supported versions

Security fixes land on the latest release.

## Reporting a vulnerability

Please **do not open a public issue** for security problems. Use GitHub's private vulnerability reporting:
*Security → Report a vulnerability* on this repository. We aim to acknowledge reports within 72 hours.

Please include the version, the command you ran, and a minimal reproduction using synthetic data only
(never real logs, hostnames or credentials).

## Design guarantees you can rely on

* hushwatch never writes to your SIEM. Suggested rules are local files for a human to review.
* No telemetry, no phone-home, no LLM calls. Network traffic goes only to the endpoints you configure.
* Credentials are read from environment variables (`${VAR}` in the config), never from command-line flags.
* TLS verification is on by default. Disabling it requires an explicit config setting and is printed as a
  warning on every report.
* Every value taken from logs is treated as attacker-controlled and escaped for its destination (Wazuh XML/
  PCRE2, HTML, terminal, Markdown, Slack). See [docs/threat-model.md](docs/threat-model.md).
