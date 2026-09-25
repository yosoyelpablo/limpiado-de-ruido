"""Tiny message catalog so every report can be rendered in English or Spanish.

Analyzers never build final strings. They emit :class:`Message` objects (a key plus parameters) and wrap any
value that identifies a person or a machine in :class:`Entity`. Renderers resolve messages for the chosen
language and, when redaction is on, replace entities with pseudonyms. Redaction therefore happens at the
output boundary only, and all internal state (fingerprints, dedup, baselines) keeps using raw values.

Each module registers its own catalog at import time::

    register({
        "silence.title.silent": {
            "en": "{source} stopped sending events {ago} ago",
            "es": "{source} dejó de enviar eventos hace {ago}",
        },
    })
"""

from __future__ import annotations

import string
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

LANGS: tuple[str, ...] = ("en", "es")
DEFAULT_LANG = "en"

_CATALOG: dict[str, dict[str, str]] = {}


@dataclass(frozen=True, slots=True)
class Entity:
    """A value that identifies a host, user, IP... Rendered raw or pseudonymized depending on redaction."""

    kind: str  # host | user | ip | url | cmd | file | domain | val
    value: str

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class Message:
    key: str
    params: Mapping[str, Any] = field(default_factory=dict)
    default: str | None = None  # English fallback when the key is not registered


def M(key: str, _default: str | None = None, /, **params: Any) -> Message:
    """Build a message: ``M("noise.reason.top_share", share=0.84, hosts=2)``."""
    return Message(key, params, _default)


def register(catalog: Mapping[str, Mapping[str, str]]) -> None:
    for key, translations in catalog.items():
        if "en" not in translations:
            raise ValueError(f"message {key!r} has no English text")
        _CATALOG[key] = dict(translations)


def has(key: str) -> bool:
    return key in _CATALOG


def keys() -> list[str]:
    return sorted(_CATALOG)


EntityFormatter = Callable[[Entity], str]


def _plain(entity: Entity) -> str:
    return entity.value


class _SafeFormatter(string.Formatter):
    """str.format that never raises on a missing key and never evaluates attribute/index access."""

    def get_field(self, field_name: str, args: Any, kwargs: Any) -> Any:
        if not field_name.isidentifier():
            return ("{" + field_name + "}", field_name)
        return (kwargs.get(field_name, "{" + field_name + "}"), field_name)


_FORMATTER = _SafeFormatter()


def render(
    msg: Message | str | None,
    lang: str = DEFAULT_LANG,
    entity: EntityFormatter = _plain,
) -> str:
    """Resolve a message (or pass a plain string through) in ``lang``.

    ``entity`` turns :class:`Entity` params into text; renderers pass the redactor here.
    Numbers are formatted per language (thousands separators, percentages via ``{x:.0%}``).
    """
    if msg is None:
        return ""
    if isinstance(msg, str):
        return msg
    translations = _CATALOG.get(msg.key)
    if translations is None:
        template = msg.default if msg.default is not None else msg.key
    else:
        template = translations.get(lang) or translations["en"]
    params = {k: _param(v, lang, entity) for k, v in msg.params.items()}
    try:
        return _FORMATTER.vformat(template, (), params)
    except (ValueError, TypeError):  # bad format spec for the given type: degrade, don't crash a report
        return template


def _param(value: Any, lang: str, entity: EntityFormatter) -> Any:
    if isinstance(value, Entity):
        return entity(value)
    if isinstance(value, Message):
        return render(value, lang, entity)
    if isinstance(value, (list, tuple)) and value and all(isinstance(v, (Entity, str)) for v in value):
        return ", ".join(entity(v) if isinstance(v, Entity) else v for v in value)
    if isinstance(value, bool):
        return _BOOL[lang if lang in _BOOL else "en"][value]
    if isinstance(value, int):
        return _LocalizedNumber(value, lang)
    if isinstance(value, float):
        return _LocalizedNumber(value, lang)
    return value


_BOOL = {"en": {True: "yes", False: "no"}, "es": {True: "sí", False: "no"}}


class _LocalizedNumber:
    """Formats like the wrapped number, then swaps separators for Spanish (1.234,5)."""

    __slots__ = ("lang", "value")

    def __init__(self, value: int | float, lang: str) -> None:
        self.value = value
        self.lang = lang

    def __format__(self, spec: str) -> str:
        if not spec:
            spec = ",d" if isinstance(self.value, int) else ",.1f"
        text = format(self.value, spec)
        if self.lang == "es":
            text = text.replace(",", "\x00").replace(".", ",").replace("\x00", ".")
        return text

    def __str__(self) -> str:
        return self.__format__("")


def entity_formatter(redactor: Any | None) -> EntityFormatter:
    """Adapter: a :class:`hushwatch.redact.Redactor` (or None) -> an entity formatter."""
    if redactor is None:
        return _plain
    return lambda e: str(redactor.token(e.value, e.kind))


# Shared vocabulary used by several modules and by every renderer.
register(
    {
        "severity.info": {"en": "info", "es": "info"},
        "severity.low": {"en": "low", "es": "baja"},
        "severity.medium": {"en": "medium", "es": "media"},
        "severity.high": {"en": "high", "es": "alta"},
        "severity.critical": {"en": "critical", "es": "crítica"},
        "confidence.high": {"en": "high confidence", "es": "confianza alta"},
        "confidence.medium": {"en": "medium confidence", "es": "confianza media"},
        "confidence.low": {"en": "low confidence", "es": "confianza baja"},
        "domain.noise": {"en": "Noise", "es": "Ruido"},
        "domain.silence": {"en": "Silence", "es": "Silencio"},
        "domain.pipeline": {"en": "Pipeline", "es": "Pipeline"},
        "domain.coverage": {"en": "Coverage", "es": "Cobertura"},
        "domain.tuning": {"en": "Tuning debt", "es": "Deuda de tuning"},
        "domain.assessment": {"en": "Assessment", "es": "Evaluación"},
        "status.ok": {"en": "OK", "es": "OK"},
        "status.warn": {"en": "Needs attention", "es": "Requiere atención"},
        "status.fail": {"en": "Problem", "es": "Problema"},
        "status.not_assessed": {"en": "Not assessed", "es": "No evaluado"},
    }
)
