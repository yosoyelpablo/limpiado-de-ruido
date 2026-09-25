"""Wazuh 4.x ruleset support: parse rule files, emit SAFE suppression rules, audit existing tuning.

* :mod:`hushwatch.wazuh.ruleset` — parse ``ruleset/rules`` + ``etc/rules`` XML into a dependency-aware
  :class:`~hushwatch.wazuh.ruleset.Ruleset` (who correlates on whom, which ids are taken).
* :mod:`hushwatch.wazuh.emitter` — turn reviewed tuning suggestions into a ``local_rules`` file built with
  ElementTree only, with every attacker-controlled value escaped for PCRE2 and XML, plus a validation checklist.
* :mod:`hushwatch.wazuh.audit` — find risky suppressions already deployed (whole-rule mutes, broken
  correlation, substring matches, expired entries).

Submodules are imported lazily by their callers; importing this package has no side effects.
"""

from __future__ import annotations

__all__ = ["audit", "emitter", "ruleset"]
