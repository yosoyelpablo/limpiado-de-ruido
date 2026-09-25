"""Pseudonymization at the output boundary.

Reports, webhooks and exports can be shared (with a client, a vendor, a public issue) without leaking
usernames, IPs, hostnames or paths. Values become ``<kind>-<hmac>`` tokens; with the same key the mapping is
stable, so the same user is the same token across the whole report and across runs.

Redaction is applied ONLY when rendering. Fingerprints, baselines and state always use raw values, so turning
redaction on or off never changes what hushwatch detects.

Keys: one HMAC key per tenant (so pseudonyms cannot be linked across MSSP customers), taken from
``HUSHWATCH_REDACT_KEY`` or created once in the state directory with mode 0600.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
from collections.abc import Iterable
from pathlib import Path
from typing import Any

REDACT_KEY_ENV = "HUSHWATCH_REDACT_KEY"

_IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
# Conservative IPv6: at least two colons and hex groups; avoids times like 10:20:30.
_IPV6 = re.compile(
    r"(?<![\w:])"
    r"(?=[0-9A-Fa-f:]*[A-Fa-f][0-9A-Fa-f:]*|[0-9A-Fa-f:]*::)"  # needs a hex letter or '::' (not a clock time)
    r"(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}"
    r"(?![\w:])"
)
# Bounded quantifiers + a lookbehind keep these linear on hostile input such as "a.a.a.a..." (no ReDoS).
_EMAIL = re.compile(r"(?<![\w.+-])[\w.+-]{1,64}@[\w-]{1,63}(?:\.[\w-]{1,63}){1,8}(?![\w-])")
# Dotted host names ending in a common TLD or internal suffix (file names like x.exe / y.xml are left alone).
_HOST_SUFFIXES = (
    "com|net|org|io|gov|edu|mil|int|info|biz|cloud|dev|app|local|localdomain|lan|corp|internal|intranet|home|"
    "example|test|invalid|ar|cl|mx|br|co|pe|uy|py|bo|ec|ve|es|pt|us|uk|de|fr|it|nl|ca|au|in|jp"
)
_HOSTNAME = re.compile(
    r"(?<![\w.@/\\-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.){1,10}(?:" + _HOST_SUFFIXES + r")(?![\w.-])",
    re.IGNORECASE,
)
# Host part of a URL (after optional user:pass@), e.g. https://***@indexer.corp.example:9200/x -> host token
_URL_HOST = re.compile(
    r"(\b[a-zA-Z][a-zA-Z0-9+.-]{0,15}://)([^/@\s]{0,256}@)?([A-Za-z0-9](?:[A-Za-z0-9.-]{0,252}[A-Za-z0-9])?)"
)
_CASE_INSENSITIVE_KINDS = frozenset({"host", "domain"})
_DOMAIN_USER = re.compile(r"(?<![\\/:\w.-])[A-Za-z][\w.-]{0,30}\\\\?[A-Za-z0-9_.$-]{1,64}\b(?![\\/])")
_WIN_PROFILE = re.compile(r"(?i)([A-Z]:\\+(?:Users|Documents and Settings)\\+)([^\\/\s\"']+)")
_UNIX_HOME = re.compile(r"(/home/|/Users/)([^/\s\"']+)")
_UNC = re.compile(r"\\\\\\?([A-Za-z0-9_.-]+)")


_WELL_KNOWN_DOMAINS = frozenset(
    {"authority", "nt authority", "builtin", "nt service", "window manager", "font driver host"}
)
_WELL_KNOWN_ACCOUNTS = frozenset({"system", "local service", "network service", "localservice", "networkservice"})


class Redactor:
    """Deterministic HMAC-based pseudonymizer."""

    def __init__(self, key: bytes | None = None) -> None:
        env_key = os.environ.get(REDACT_KEY_ENV)
        if key is None and env_key:
            key = env_key.encode()
        self._key = key or secrets.token_bytes(32)
        self._cache: dict[tuple[str, str], str] = {}
        self._known: dict[str, str] = {}  # raw value -> kind, learned from structured entities
        self._known_re: re.Pattern[str] | None = None
        self._known_lower: dict[str, str] = {}

    @classmethod
    def for_tenant(cls, tenant: str, state_dir: Path | None) -> Redactor:
        """Per-tenant persistent key (env var wins). Without a state dir the key is random per run."""
        env_key = os.environ.get(REDACT_KEY_ENV)
        if env_key:
            return cls(hmac.new(env_key.encode(), tenant.encode(), hashlib.sha256).digest())
        if state_dir is None:
            return cls()
        key_path = Path(state_dir) / "keys" / f"{_safe_name(tenant)}.key"
        if key_path.exists():
            return cls(key_path.read_bytes())
        key_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        key = secrets.token_bytes(32)
        fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(key)
        return cls(key)

    def token(self, value: str, kind: str = "val") -> str:
        if kind in _CASE_INSENSITIVE_KINDS:  # DNS/NetBIOS names: DC01 and dc01 are the same machine
            value = value.lower()
        cache_key = (kind, value)
        cached = self._cache.get(cache_key)
        if cached is None:
            data = f"{kind}\x1f{value}".encode("utf-8", "surrogatepass")  # logs decoded with surrogateescape
            digest = hmac.new(self._key, data, hashlib.sha256).hexdigest()[:10]
            cached = f"{kind}-{digest}"
            self._cache[cache_key] = cached
        return cached

    def learn(self, values: Iterable[tuple[str, str]]) -> None:
        """Teach the redactor raw entity values (kind, value) so they are also caught inside free text."""
        changed = False
        for kind, value in values:
            if value and len(value) >= 3 and value not in self._known:
                self._known[value] = kind
                changed = True
        if changed:
            self._known_lower = {v.lower(): k for v, k in self._known.items() if k in _CASE_INSENSITIVE_KINDS}
            words = list(self._known) + list(self._known_lower)
            # whole-token matches only (a user "root" must not rewrite "rootcheck"); compiled as a trie so the
            # cost does not grow with the number of learned values (flat alternations are O(values) per position)
            self._known_re = re.compile(r"(?<!\w)(?:" + _trie_pattern(words) + r")(?!\w)")

    def text(self, value: str) -> str:
        """Redact identifiers embedded in free text (log lines, descriptions, paths)."""
        out = value
        if self._known_re is not None:
            out = self._known_re.sub(self._known_token, out)
        # URL credentials are always removed; the host becomes a pseudonym
        out = _URL_HOST.sub(lambda m: m.group(1) + ("***@" if m.group(2) else "") + self.token(m.group(3), "host"), out)
        out = _EMAIL.sub(lambda m: self.token(m.group(0), "user"), out)
        out = _WIN_PROFILE.sub(lambda m: m.group(1) + self.token(m.group(2), "user"), out)
        out = _UNIX_HOME.sub(lambda m: m.group(1) + self.token(m.group(2), "user"), out)
        out = _UNC.sub(lambda m: "\\\\" + self.token(m.group(1), "host"), out)
        out = _DOMAIN_USER.sub(self._domain_user, out)
        out = _IPV4.sub(lambda m: self.token(m.group(0), "ip") if _valid_ipv4(m.group(0)) else m.group(0), out)
        out = _IPV6.sub(lambda m: self.token(m.group(0), "ip"), out)
        out = _HOSTNAME.sub(lambda m: self.token(m.group(0).lower(), "host"), out)
        return out

    def _known_token(self, match: re.Match[str]) -> str:
        text = match.group(0)
        kind = self._known.get(text) or self._known_lower.get(text.lower()) or "val"
        return self.token(text, kind)

    def _domain_user(self, match: re.Match[str]) -> str:
        text = match.group(0)
        lowered = text.lower()
        if lowered.startswith(("hkey", "hklm", "hkcu", "hku\\", "system32", "windows")) or ":" in text:
            return text
        domain, _, account = lowered.replace("\\\\", "\\").partition("\\")
        if domain in _WELL_KNOWN_DOMAINS or account in _WELL_KNOWN_ACCOUNTS:
            return text
        return self.token(text, "user")


def _trie_pattern(words: Iterable[str]) -> str:
    """Regex alternation for ``words`` compiled as a prefix trie (longest match first at each branch)."""
    trie: dict[str, Any] = {}
    for word in words:
        node = trie
        for ch in word:
            node = node.setdefault(ch, {})
        node[""] = True

    def build(node: dict[str, Any]) -> str:
        end = "" in node
        branches = [re.escape(ch) + build(child) for ch, child in sorted(node.items()) if ch != ""]
        if not branches:
            return ""
        body = branches[0] if len(branches) == 1 else "(?:" + "|".join(branches) + ")"
        return f"(?:{body})?" if end else body

    return build(trie) or "(?!)"


def _valid_ipv4(text: str) -> bool:
    parts = text.split(".")
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def _safe_name(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "_", name)[:64] or "default"
