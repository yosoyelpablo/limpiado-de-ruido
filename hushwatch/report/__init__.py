"""Report renderers: JSON, Markdown, console (rich) and single-file HTML, in English and Spanish.

Public API::

    render(report, fmt, *, lang="en", redactor=None) -> str           # fmt: json | md | html
    print_console(report, *, lang="en", redactor=None, console=None, verbose=False) -> None
    render_many(reports, fmt, *, lang="en", redactor=None) -> str     # multi-tenant fleet summary
    print_console_many(reports, *, lang="en", redactor=None, console=None) -> None

Every renderer starts with the DataBasis banner, shows one status per domain (never a single score), and
applies redaction at the output boundary when a :class:`~hushwatch.redact.Redactor` is given. For the fleet
functions ``redactor`` may also be a mapping ``{tenant name: Redactor}`` (per-tenant keys); a tenant missing from
the mapping is still pseudonymized (random key), and only an explicit ``None`` shows a tenant's real values.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from ..models import Report
from ..redact import Redactor
from .common import FORMATS
from .console import print_console, print_console_many
from .html import render_html, render_html_many
from .jsonout import render_json, render_json_many
from .markdown import render_markdown, render_markdown_many

__all__ = [
    "FORMATS",
    "print_console",
    "print_console_many",
    "render",
    "render_html",
    "render_json",
    "render_many",
    "render_markdown",
]

_ALIASES = {"json": "json", "md": "md", "markdown": "md", "html": "html", "htm": "html"}


def _format(fmt: str) -> str:
    key = _ALIASES.get(str(fmt).strip().lower())
    if key is None:
        raise ValueError(f"unknown report format {fmt!r}; expected one of: {', '.join(FORMATS)}")
    return key


def render(report: Report, fmt: str, *, lang: str = "en", redactor: Redactor | None = None) -> str:
    """Render ``report`` as ``json``, ``md`` (GitHub-flavoured Markdown) or ``html`` (self-contained page)."""
    kind = _format(fmt)
    if kind == "json":
        return render_json(report, lang=lang, redactor=redactor)
    if kind == "md":
        return render_markdown(report, lang=lang, redactor=redactor)
    return render_html(report, lang=lang, redactor=redactor)


def render_many(
    reports: Sequence[Report],
    fmt: str,
    *,
    lang: str = "en",
    redactor: Redactor | Mapping[str, Redactor | None] | None = None,
) -> str:
    """Multi-tenant fleet summary: one row per tenant with domain statuses and critical/high finding counts."""
    kind = _format(fmt)
    items = list(reports)
    if kind == "json":
        return render_json_many(items, lang=lang, redactor=redactor)
    if kind == "md":
        return render_markdown_many(items, lang=lang, redactor=redactor)
    return render_html_many(items, lang=lang, redactor=redactor)
