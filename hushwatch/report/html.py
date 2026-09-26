"""Single-file HTML report: self-contained, script-free, printable, light/dark, EN/ES.

* **Self-contained** — no external assets, fonts, images or scripts: inline CSS, inline SVG sparklines, meters
  and icons. A strict CSP meta (``default-src 'none'; style-src 'unsafe-inline'; img-src data:``, plus
  ``base-uri``/``form-action 'none'``) makes any injected markup inert even if escaping ever failed.
* **Escaped by construction** — the page is built with :func:`h`, which escapes every child and attribute value
  with ``html.escape(quote=True)`` unless it is a :class:`Safe` fragment produced by :func:`h` itself. Data
  never reaches ``<style>``, attribute names, tag names or URLs (the only links are in-page ``#`` anchors
  built from sanitized ids).
* **No JavaScript** — the optional embedded JSON (``embed_json=True``) is a ``type="application/json"`` data
  block, never executed, with ``<``, ``>``, ``&``, U+2028/U+2029 escaped as ``\\uXXXX``.
* **Accessible** — ``lang`` attribute, landmarks, a skip link, semantic tables with captions and ``scope``,
  text labels next to every colour, SVG with ``role="img"`` and labels, AA contrast in both themes.
"""

from __future__ import annotations

import html as _html
import json
import re
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from ..models import DOMAINS, Report
from ..redact import Redactor
from .common import (
    DomainCard,
    Fact,
    FindingView,
    KeyNumber,
    RecordTable,
    RenderContext,
    ReportView,
    TuneRow,
    build_view,
    finite_series,
    fleet_footer,
    fleet_rows,
    prepare_context,
)
from .jsonout import build_document

__all__ = ["CSP", "Safe", "h", "render_html", "render_html_many", "sparkline_svg"]

CSP = "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'"

_NAME = re.compile(r"^[a-z][a-z0-9-]*$")
_ATTR = re.compile(r"^[a-z][a-z0-9:-]*$")
_VOID = frozenset({"meta", "br", "hr", "img", "link", "col", "wbr"})
_CLASS_TOKEN = re.compile(r"[^a-z0-9_-]")


class Safe(str):
    """A fragment of HTML that is already escaped (only :func:`h` and trusted constants create these)."""

    __slots__ = ()


# A trusted constant (not built with h(): html.escape would turn the quotes into &#x27;, valid but ungreppable).
_CSP_META = Safe(f'<meta http-equiv="Content-Security-Policy" content="{CSP}">')


def esc(value: object) -> Safe:
    """Escape any value for HTML text or attribute context (``Safe`` passes through)."""
    if isinstance(value, Safe):
        return value
    return Safe(_html.escape(str(value), quote=True))


def _children(items: Iterable[object]) -> str:
    out: list[str] = []
    for item in items:
        if item is None or item is False:
            continue
        out.append(_children(item) if isinstance(item, (list, tuple)) else esc(item))
    return "".join(out)


def h(tag: str, attrs: Mapping[str, object] | None = None, *children: object) -> Safe:
    """Build an element. Tag/attribute names must be static identifiers; values and children are escaped."""
    if not _NAME.match(tag):
        raise ValueError(f"invalid tag name {tag!r}")
    parts = [f"<{tag}"]
    for name, value in (attrs or {}).items():
        if not _ATTR.match(name) or name.startswith("on"):
            raise ValueError(f"invalid attribute name {name!r}")
        if value is None or value is False:
            continue
        parts.append(f" {name}" if value is True else f' {name}="{esc(value)}"')
    parts.append(">")
    if tag in _VOID:
        return Safe("".join(parts))
    parts.append(_children(children))
    parts.append(f"</{tag}>")
    return Safe("".join(parts))


def _cls(*tokens: str) -> str:
    """Class attribute from fixed prefixes + normalized values (only ``[a-z0-9_-]`` survives)."""
    return " ".join(_CLASS_TOKEN.sub("", t.lower()) for t in tokens if t)


def _join(parts: Iterable[object]) -> Safe:
    return Safe(_children(parts))


# ---- icons & charts -------------------------------------------------------------------------------------------

_ICON_PATHS = {
    "ok": '<path d="M3.5 8.5l3 3 6-7"/>',
    "warn": '<path d="M8 3.5v5.2M8 12v.4"/>',
    "fail": '<path d="M4.5 4.5l7 7M11.5 4.5l-7 7"/>',
    "not_assessed": '<path d="M4.5 8h7"/>',
    "alert": '<path d="M8 2.3l6.2 11H1.8z"/><path d="M8 6.6v3M8 11.4v.3"/>',
    "info": '<circle cx="8" cy="8" r="6.2"/><path d="M8 7.3v3.9M8 4.9v.3"/>',
    "shield": '<path d="M8 1.8l5 1.9v3.9c0 3-2.1 5.4-5 6.6-2.9-1.2-5-3.6-5-6.6V3.7z"/>'
    '<path d="M5.8 8.2l1.6 1.6 3-3.2"/>',
    "arrow": '<path d="M2.8 8h9.4M8.6 4.4 12.2 8l-3.6 3.6"/>',
    "lock": '<rect x="3" y="7" width="10" height="7" rx="1.5"/><path d="M5.5 7V5a2.5 2.5 0 015 0v2"/>',
}


def _icon(name: str, cls: str = "ic") -> Safe:
    path = _ICON_PATHS.get(name, _ICON_PATHS["info"])
    return Safe(
        f'<svg class="{_cls(cls)}" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.8" '
        f'stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false">{path}</svg>'
    )


_LOGO = Safe(
    '<svg class="logo" viewBox="0 0 32 32" aria-hidden="true" focusable="false">'
    '<rect width="32" height="32" rx="8" fill="#14b8a6"/>'
    '<path d="M4.5 17h3.2l2.1-6 3.1 12 2.6-9 1.6 3h7.4" fill="none" stroke="#062a2a" stroke-width="2.3" '
    'stroke-linecap="round" stroke-linejoin="round"/><circle cx="26.6" cy="17" r="2.4" fill="#062a2a"/></svg>'
)


def sparkline_svg(values: Sequence[float], label: str, *, width: int = 120, height: int = 28) -> Safe:
    """Inline SVG sparkline (line + 10% area wash + end dot, red when the series ends at zero)."""
    points = finite_series(values)[-120:]
    if not points:
        return Safe("")
    pad = 3.0
    peak = max(points)
    span_x = width - 2 * pad
    span_y = height - 2 * pad
    step = span_x / (len(points) - 1) if len(points) > 1 else 0.0
    coords = [
        (pad + i * step if len(points) > 1 else width / 2, height - pad - (v / peak * span_y if peak > 0 else 0.0))
        for i, v in enumerate(points)
    ]
    line = " ".join(f"{x:.1f},{y:.1f}" for x, y in coords)
    base = height - pad
    area = f"M{coords[0][0]:.1f},{base:.1f} L" + " L".join(f"{x:.1f},{y:.1f}" for x, y in coords)
    area += f" L{coords[-1][0]:.1f},{base:.1f} Z"
    last_x, last_y = coords[-1]
    ends_silent = points[-1] <= 0 < peak
    shapes = [
        f'<path class="ar" d="{area}"/>' if len(points) > 1 else "",
        f'<polyline class="ln" points="{line}"/>' if len(points) > 1 else "",
        f'<circle class="pt{" z" if ends_silent else ""}" cx="{last_x:.1f}" cy="{last_y:.1f}" r="2.6"/>',
    ]
    return Safe(
        f'<svg class="spark" width="{width}" height="{height}" viewBox="0 0 {width} {height}" role="img" '
        f'aria-label="{esc(label)}"><title>{esc(label)}</title>{"".join(shapes)}</svg>'
    )


def _meter(value: float | None, *, width: int = 56, height: int = 6) -> Safe:
    if value is None:
        return Safe("")
    fill = max(0.0, min(1.0, value)) * width
    bar = f'<rect class="fl" width="{fill:.1f}" height="{height}" rx="{height / 2:.1f}"/>' if fill > 0 else ""
    return Safe(
        f'<svg class="meter" width="{width}" height="{height}" viewBox="0 0 {width} {height}" aria-hidden="true" '
        f'focusable="false"><rect class="tr" width="{width}" height="{height}" rx="{height / 2:.1f}"/>{bar}</svg>'
    )


# ---- stylesheet -----------------------------------------------------------------------------------------------

_CSS = """
:root{
--page:#f3f5f8;--surface:#fff;--surface-2:#f8fafc;--surface-3:#edf1f6;
--ink:#0f172a;--ink-2:#334155;--muted:#5b6b80;--line:#e2e8f0;--line-2:#cbd5e1;
--accent:#0d9488;--accent-ink:#0f766e;
--mast:#0a1120;--mast-2:#0f1b31;--mast-ink:#e6edf7;--mast-muted:#9aabc3;--mast-line:rgba(255,255,255,.09);
--series:#2a78d6;--series-wash:rgba(42,120,214,.13);--track:#dbe6f4;
--ok:#16a34a;--ok-bg:#e7f6ec;--ok-ink:#166534;
--warn:#d97706;--warn-bg:#fdf3dc;--warn-ink:#8a3b0b;
--fail:#dc2626;--fail-bg:#fdecec;--fail-ink:#991b1b;
--na:#94a3b8;--na-bg:#f1f4f8;--na-ink:#475569;--hatch:rgba(100,116,139,.11);
--crit-bg:#b91c1c;--crit-ink:#fff;
--high-bg:#ffedd5;--high-ink:#9a3412;--high-bar:#ea580c;
--med-bg:#fef3c7;--med-ink:#854d0e;--med-bar:#d99a06;
--low-bg:#e0f2fe;--low-ink:#075985;--low-bar:#0284c7;
--info-bg:#eef2f6;--info-ink:#475569;--info-bar:#94a3b8;
--shadow:0 1px 2px rgba(15,23,42,.04),0 2px 6px rgba(15,23,42,.05);
--radius:12px;
--sans:system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,"Noto Sans",sans-serif;
--mono:ui-monospace,SFMono-Regular,"SF Mono",Menlo,Consolas,"Liberation Mono",monospace;
color-scheme:light}
@media screen and (prefers-color-scheme:dark){:root{
--page:#0a0e17;--surface:#111827;--surface-2:#0e1523;--surface-3:#1a2335;
--ink:#e6eaf2;--ink-2:#c5ccd9;--muted:#93a0b4;--line:#1f2a3f;--line-2:#2c3a55;
--accent:#2dd4bf;--accent-ink:#5eead4;--mast:#05080f;--mast-2:#0b1323;
--series:#3987e5;--series-wash:rgba(57,135,229,.2);--track:#1d2c46;
--ok:#22c55e;--ok-bg:rgba(34,197,94,.13);--ok-ink:#86efac;
--warn:#f59e0b;--warn-bg:rgba(245,158,11,.13);--warn-ink:#fcd34d;
--fail:#f05252;--fail-bg:rgba(240,82,82,.14);--fail-ink:#fca5a5;
--na:#64748b;--na-bg:rgba(148,163,184,.08);--na-ink:#aeb8c8;--hatch:rgba(148,163,184,.075);
--crit-bg:#dc2626;--high-bg:rgba(234,88,12,.2);--high-ink:#fdba74;--high-bar:#f97316;
--med-bg:rgba(217,154,6,.2);--med-ink:#fcd34d;--med-bar:#eab308;
--low-bg:rgba(2,132,199,.2);--low-ink:#7dd3fc;--low-bar:#38bdf8;
--info-bg:rgba(148,163,184,.13);--info-ink:#cbd5e1;--info-bar:#64748b;
--shadow:none;color-scheme:dark}}
*,*::before,*::after{box-sizing:border-box}
html{-webkit-text-size-adjust:100%;text-size-adjust:100%}
body{margin:0;background:var(--page);color:var(--ink);font:14.5px/1.55 var(--sans);overflow-wrap:break-word}
.wrap{max-width:1200px;margin:0 auto;padding-left:28px;padding-right:28px}
a{color:var(--accent-ink);text-decoration:none}a:hover{text-decoration:underline}
a:focus-visible{outline:2px solid var(--accent);outline-offset:2px;border-radius:4px}
.skip{position:absolute;left:-9999px;top:8px}
.skip:focus{left:16px;z-index:20;background:var(--surface);color:var(--ink);padding:8px 12px;border-radius:8px}
.sr{position:absolute;width:1px;height:1px;margin:-1px;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap;border:0}
code,.mono{font-family:var(--mono);font-size:.86em}
.ic{width:16px;height:16px;flex:none}
.sub{display:block;color:var(--muted);font-size:12px;font-weight:400}
.callout>div,.reco>div,.alert>div,.caveat>span,.empty>span,.inv>li,.sg-h a,.sg-scope code,.lede,.hint,
.colophon p,.colophon .ro,.card,.kpi .v,.fact dd,.meta dd,.kv dt,.kv dd,.fh h4,.ff code,.fb li{min-width:0;
overflow-wrap:anywhere}
/* masthead */
.mast{color:var(--mast-ink);padding:26px 0 22px;
background:radial-gradient(900px 340px at 88% -30%,rgba(45,212,191,.2),transparent 62%),
linear-gradient(180deg,var(--mast),var(--mast-2))}
.brand{display:flex;align-items:center;gap:10px;font-weight:700;font-size:15px;letter-spacing:.01em}
.brand .logo{width:30px;height:30px}.brand b{color:#5eead4}
.eyebrow{margin-left:auto;font-size:11px;letter-spacing:.12em;text-transform:uppercase;color:var(--mast-muted)}
.mast h1{margin:18px 0 2px;font-size:30px;line-height:1.2;font-weight:750;letter-spacing:-.015em}
.mast .tag{margin:0;color:var(--mast-muted)}
.meta{display:flex;flex-wrap:wrap;gap:10px 30px;margin:18px 0 0;padding:14px 0 0;
border-top:1px solid var(--mast-line)}
.meta div{min-width:0}
.meta dt{font-size:10.5px;text-transform:uppercase;letter-spacing:.09em;color:var(--mast-muted);font-weight:600}
.meta dd{margin:2px 0 0;font-weight:600;overflow-wrap:anywhere}
.chip{display:inline-flex;align-items:center;gap:6px;padding:1px 10px;border-radius:999px;font-size:12px;
font-weight:650;
background:rgba(255,255,255,.08);border:1px solid rgba(255,255,255,.14)}
.chip.bad{background:#dc2626;border-color:#dc2626;color:#fff}
/* contents */
.toc{position:sticky;top:0;z-index:5;background:var(--page);border-bottom:1px solid var(--line)}
.toc ol{list-style:none;margin:0;padding:9px 0;display:flex;gap:4px;overflow-x:auto;scrollbar-width:none}
.toc ol::-webkit-scrollbar{display:none}
.toc a{display:block;padding:5px 11px;border-radius:999px;color:var(--ink-2);font-size:13px;white-space:nowrap}
.toc a:hover{background:var(--surface-3);text-decoration:none}
.toc .n{color:var(--muted);font:600 11px var(--mono);margin-right:5px}
/* sections */
main{padding:28px 0 36px}
section{margin:0 0 40px;scroll-margin-top:60px}
section>:last-child{margin-bottom:0}
.sh{display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin:0 0 14px}
.sh h2{margin:0;font-size:19px;line-height:1.3;font-weight:720;letter-spacing:-.01em}
.sh .n{font:600 11.5px/1 var(--mono);color:var(--muted);background:var(--surface-3);border-radius:6px;padding:5px 7px}
.sh .pill{margin-left:auto}
h3{font-size:14.5px;margin:24px 0 10px;font-weight:680;color:var(--ink)}
.lede{color:var(--ink-2);margin:0 0 14px}
.hint{color:var(--muted);font-size:13px;margin:4px 0 12px}
.empty{background:var(--surface);border:1px dashed var(--line-2);border-radius:var(--radius);padding:16px 18px;
color:var(--muted);display:flex;gap:10px;align-items:flex-start;margin:0 0 14px}
.empty.na{background-image:repeating-linear-gradient(135deg,var(--hatch) 0 6px,transparent 6px 12px);
color:var(--na-ink)}
.tw,.basis,.cards,.kpis,.inv,.sugg,.counts,.callout{margin:0 0 14px}
/* pills & badges */
.pill{display:inline-flex;align-items:center;gap:6px;padding:3px 11px 3px 7px;border-radius:999px;font-size:12.5px;
font-weight:680;white-space:nowrap;border:1px solid transparent}
.pill .ic{width:14px;height:14px}
.pill.st-ok{background:var(--ok-bg);color:var(--ok-ink)}.pill.st-warn{background:var(--warn-bg);color:var(--warn-ink)}
.pill.st-fail{background:var(--fail-bg);color:var(--fail-ink)}
.pill.st-not_assessed{background:var(--na-bg);color:var(--na-ink);border:1px dashed var(--line-2)}
.b{display:inline-flex;align-items:center;gap:5px;padding:1px 8px;border-radius:6px;font-size:11.5px;font-weight:700;
letter-spacing:.02em;white-space:nowrap;line-height:1.6;border:1px solid transparent}
.b .ic{width:12px;height:12px}
.b.sev-critical,.b.s-tampering{background:var(--crit-bg);color:var(--crit-ink)}
.b.sev-high{background:var(--high-bg);color:var(--high-ink)}.b.sev-medium{background:var(--med-bg);
color:var(--med-ink)}
.b.sev-low{background:var(--low-bg);color:var(--low-ink)}.b.sev-info{background:var(--info-bg);color:var(--info-ink)}
.b.v-tune,.b.ready,.b.s-ok{background:var(--ok-bg);color:var(--ok-ink)}
.b.v-investigate,.b.s-decay,.b.s-rule_dark,.b.s-field_lost,.b.s-unmonitorable{background:var(--warn-bg);
color:var(--warn-ink)}
.b.v-fix_at_source,.b.v-aggregate{background:var(--low-bg);color:var(--low-ink)}
.b.v-do_not_tune,.b.s-silent,.b.s-drop{background:var(--fail-bg);color:var(--fail-ink)}
.b.v-watch,.b.v-learning,.b.v-other,.b.s-learning,.b.s-not_evaluated,.b.s-explained,.b.s-other,.b.tier-standard,.b.tier-other{
background:var(--info-bg);color:var(--info-ink)}
.b.tier-critical{background:transparent;color:var(--fail-ink);border-color:currentColor}
.b.tier-low{background:var(--na-bg);color:var(--na-ink)}
.b.review{background:var(--warn-bg);color:var(--warn-ink);border-color:var(--warn)}
/* data basis */
.basis{background:var(--surface);border:1px solid var(--line);border-radius:var(--radius);box-shadow:var(--shadow);
overflow:hidden}
.alert{display:flex;gap:14px;padding:18px 22px;border-bottom:1px solid var(--line)}
.alert .ib{flex:none;width:38px;height:38px;border-radius:10px;display:grid;place-items:center;color:#fff}
.alert .ib .ic{width:20px;height:20px}
.alert h2{margin:0 0 3px;font-size:18px;line-height:1.3}
.alert p{margin:0;color:var(--ink-2)}
.alert ul{margin:8px 0 0;padding-left:18px}
.alert.bad{background:var(--fail-bg);box-shadow:inset 6px 0 0 var(--fail)}
.alert.bad .ib{background:var(--fail)}.alert.bad h2{color:var(--fail-ink);text-transform:uppercase;
letter-spacing:.03em}
.alert.good{padding:14px 22px}.alert.good .ib{background:var(--ok);width:32px;height:32px;border-radius:9px}
.caveat{display:flex;gap:10px;align-items:flex-start;padding:12px 22px;background:var(--warn-bg);
color:var(--warn-ink);
border-bottom:1px solid var(--line);font-size:13.5px}
.caveat .ic{margin-top:2px}
.facts{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));grid-auto-flow:row dense;
margin:0 -1px -1px 0}
.fact{padding:12px 22px;min-width:0;border-right:1px solid var(--line);border-bottom:1px solid var(--line)}
.fact.wide{grid-column:1/-1}.fact.w2{grid-column:span 2}
.fact dt{font-size:10.5px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);font-weight:650}
.fact dd{margin:3px 0 0;font-weight:620;overflow-wrap:anywhere}
.fact.warn dd{color:var(--warn-ink)}.fact.fail dd{color:var(--fail-ink)}
.fact .mk{display:inline-block;width:7px;height:7px;border-radius:50%;margin-right:7px;vertical-align:.1em}
.fact.warn .mk{background:var(--warn)}.fact.fail .mk{background:var(--fail)}
.fact ul{margin:6px 0 0;padding-left:17px;font-weight:450;font-size:13px;color:var(--ink-2)}
/* status cards */
.cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(178px,1fr));gap:12px}
.card{position:relative;background:var(--surface);border:1px solid var(--line);border-radius:var(--radius);
padding:14px 16px 14px 19px;box-shadow:var(--shadow);overflow:hidden;min-width:0}
.card::before{content:"";position:absolute;left:0;top:0;bottom:0;width:4px;background:var(--st)}
.st-ok{--st:var(--ok)}.st-warn{--st:var(--warn)}.st-fail{--st:var(--fail)}.st-not_assessed{--st:var(--na)}
.card.st-not_assessed{background-image:repeating-linear-gradient(135deg,var(--hatch) 0 6px,transparent 6px 12px)}
.card .d{font-size:11px;font-weight:650;color:var(--muted);text-transform:uppercase;letter-spacing:.08em}
.card .s{display:flex;align-items:center;gap:8px;margin:9px 0 6px;font-size:16.5px;font-weight:720;line-height:1.25}
.card.st-not_assessed .s{color:var(--na-ink)}
.card .c{font-size:12.5px;color:var(--ink-2)}
.card .c.note{margin-top:6px;color:var(--warn-ink,var(--ink-2));display:flex;gap:6px;align-items:flex-start}
.dot{width:22px;height:22px;border-radius:50%;display:inline-grid;place-items:center;background:var(--st);color:#fff;
flex:none}
.dot .ic{width:13px;height:13px;stroke-width:2.4}
/* key numbers */
.kpis{display:grid;grid-template-columns:repeat(auto-fill,minmax(212px,1fr));gap:12px}
.kpi{position:relative;background:var(--surface);border:1px solid var(--line);border-radius:var(--radius);
padding:14px 16px;box-shadow:var(--shadow);min-width:0}
.kpi .l{font-size:12.5px;color:var(--muted);font-weight:560;padding-right:14px;min-height:2.5em}
.kpi .v{font-size:28px;font-weight:720;letter-spacing:-.02em;line-height:1.15;margin-top:6px;overflow-wrap:anywhere}
.kpi .h{font-size:12px;color:var(--muted);margin-top:3px}
.kpi .tone{position:absolute;top:15px;right:15px;width:8px;height:8px;border-radius:50%}
.kpi.t-ok .tone{background:var(--ok)}.kpi.t-warn .tone{background:var(--warn)}.kpi.t-fail .tone{
background:var(--fail)}
.kpi.t-fail{border-color:var(--fail)}
.kpi.t-na{background-image:repeating-linear-gradient(135deg,var(--hatch) 0 6px,transparent 6px 12px)}
.kpi.t-na .v{color:var(--na-ink)}
/* tables */
.tw{position:relative;background:var(--surface);border:1px solid var(--line);border-radius:var(--radius);
box-shadow:var(--shadow);
overflow-x:auto;-webkit-overflow-scrolling:touch}
table{width:100%;border-collapse:collapse;font-size:13.5px}
caption{text-align:left;padding:12px 14px 2px;font-weight:680;color:var(--ink)}
th,td{padding:9px 12px;text-align:left;vertical-align:top;border-bottom:1px solid var(--line)}
thead th{font-size:10.5px;text-transform:uppercase;letter-spacing:.07em;color:var(--muted);font-weight:680;
background:var(--surface-2);white-space:nowrap}
tbody tr:last-child td,tbody tr:last-child th{border-bottom:0}
tbody tr:hover td,tbody tr:hover th{background:var(--surface-2)}
tbody th{font-weight:620}
.n{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}.nw{white-space:nowrap}
.txt{min-width:200px;max-width:440px;overflow-wrap:anywhere}
.rid{font:650 12.5px var(--mono);white-space:nowrap}
.share{display:inline-flex;align-items:center;gap:8px;justify-content:flex-end}
.meter .tr{fill:var(--track)}.meter .fl{fill:var(--series)}
.spark{display:block;overflow:visible}
.spark .ln{fill:none;stroke:var(--series);stroke-width:1.6;stroke-linejoin:round;stroke-linecap:round}
.spark .ar{fill:var(--series-wash)}.spark .pt{fill:var(--series);stroke:var(--surface);stroke-width:1.5}
.spark .pt.z{fill:var(--fail)}
.more td{color:var(--muted);font-style:italic;text-align:center}
th.c,td.c{text-align:center}
th .b{margin-left:8px;vertical-align:1px}th .sub .b{margin:0 6px 0 0}
.si{display:inline-flex;vertical-align:middle}.legend .dot{margin-right:2px}
.si.st-not_assessed .dot,.legend .st-not_assessed .dot{
background:transparent;color:var(--na-ink);border:1.5px dashed var(--na)}
/* noise */
.sugg{list-style:none;padding:0;display:grid;gap:10px}
.sg{background:var(--surface);border:1px solid var(--line);border-left:4px solid var(--ok);border-radius:10px;
padding:14px 18px;box-shadow:var(--shadow)}
.sg.rv{border-left-color:var(--warn)}
.sg-h{display:flex;gap:10px;align-items:flex-start;flex-wrap:wrap}
.sg-h a{flex:1 1 320px;font-weight:650;font-size:14.5px;overflow-wrap:anywhere}
.sg-scope{margin:8px 0 12px;font-size:13px;color:var(--muted)}
.sg-scope code{display:inline-block;margin-left:6px;color:var(--ink);background:var(--surface-3);padding:2px 8px;
border-radius:6px;overflow-wrap:anywhere;font-size:12.5px}
.sg-stats{display:flex;flex-wrap:wrap;gap:10px 30px;margin:0}
.sg-stats dt{font-size:10.5px;text-transform:uppercase;letter-spacing:.07em;color:var(--muted);font-weight:650}
.sg-stats dd{margin:3px 0 0;font-weight:680;font-variant-numeric:tabular-nums;display:flex;align-items:center;gap:8px}
.sg-note{margin:12px 0 0;font-size:13px;color:var(--warn-ink);display:flex;gap:8px;align-items:flex-start}
.sg-note .ic{margin-top:2px}
.callout{display:flex;gap:12px;align-items:flex-start;background:var(--surface);border:1px solid var(--line);
border-radius:var(--radius);padding:14px 16px;box-shadow:var(--shadow)}
.callout .ic{width:18px;height:18px;color:var(--accent);margin-top:2px}
.callout strong{display:block}
.callout .big{font-size:20px;font-weight:720;letter-spacing:-.01em}
.inv{list-style:none;padding:0;display:grid;gap:8px}
.inv>li{background:var(--surface);border:1px solid var(--line);border-radius:10px;padding:10px 14px}
.inv .t{display:flex;gap:8px;align-items:baseline;flex-wrap:wrap}
.inv ul{margin:6px 0 0;padding-left:18px;color:var(--ink-2);font-size:13px}
/* silence */
.counts{display:flex;flex-wrap:wrap;gap:8px;padding:0;list-style:none}
.counts li{background:var(--surface);border:1px solid var(--line);border-radius:10px;padding:8px 12px;min-width:104px}
.counts .k{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.07em;font-weight:650}
.counts .v{font-size:19px;font-weight:720;font-variant-numeric:tabular-nums}
.counts li.hot{border-color:var(--fail);background:var(--fail-bg)}.counts li.hot .v{color:var(--fail-ink)}
.mon{display:flex;align-items:center;gap:14px;flex-wrap:wrap}
.mon .meter .fl{fill:var(--ok)}
/* coverage matrix */
.tw.fit{display:inline-block;max-width:100%;vertical-align:top}table.matrix{width:auto}
.matrix th.vh{writing-mode:vertical-rl;transform:rotate(180deg);text-transform:none;letter-spacing:0;font-size:11.5px;
font-weight:600;padding:10px 6px;max-height:180px;overflow:hidden;text-overflow:ellipsis;vertical-align:bottom;
text-align:left}
.matrix td.m{text-align:center;padding:7px 6px;width:34px;vertical-align:middle}
.matrix tbody th,.matrix thead th:first-child{position:sticky;left:0;z-index:1;background:var(--surface)}
.matrix thead th:first-child{background:var(--surface-2)}
.m i,.lg i{display:inline-block;width:11px;height:11px;border-radius:50%;vertical-align:middle}
.m-present i{background:var(--ok)}
.m-silent i{border:2.5px solid var(--warn)}
.m-missing i{background:var(--fail);border-radius:2px;width:9px;height:9px;transform:rotate(45deg)}
.m-na i{width:4px;height:4px;background:var(--line-2)}
.legend{display:flex;flex-wrap:wrap;gap:6px 18px;margin:-4px 2px 14px;font-size:12.5px;color:var(--muted)}
.legend span{display:inline-flex;align-items:center;gap:6px}
/* findings */
.fcount{display:flex;flex-wrap:wrap;gap:8px;margin:0 0 6px}
.fgroup{margin-top:18px}
.fgroup h3{display:flex;align-items:center;gap:8px}
.fgroup h3 .c{font:600 11.5px var(--mono);color:var(--muted);background:var(--surface-3);padding:3px 7px;
border-radius:6px}
.finding{background:var(--surface);border:1px solid var(--line);border-left:4px solid var(--sev);border-radius:10px;
padding:14px 18px;margin:0 0 10px;box-shadow:var(--shadow);scroll-margin-top:60px}
.finding.sev-critical{--sev:var(--crit-bg)}.finding.sev-high{--sev:var(--high-bar)}
.finding.sev-medium{--sev:var(--med-bar)}.finding.sev-low{--sev:var(--low-bar)}.finding.sev-info{
--sev:var(--info-bar)}
.finding:target{outline:2px solid var(--accent);outline-offset:2px}
.many .finding{content-visibility:auto;contain-intrinsic-size:auto 320px}
.fh{display:flex;align-items:flex-start;gap:10px;flex-wrap:wrap}
.fh h4{margin:0;font-size:15px;font-weight:660;flex:1 1 300px;line-height:1.4;overflow-wrap:anywhere}
.fh .conf{font-size:12px;color:var(--muted);white-space:nowrap;padding-top:2px}
.fb{display:grid;grid-template-columns:minmax(0,1.1fr) minmax(0,1fr);gap:10px 28px;margin-top:12px}
.fb h5{margin:0 0 5px;font-size:10.5px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted)}
.fb ul{margin:0;padding-left:18px}.fb li{margin:2px 0;overflow-wrap:anywhere}
.kv{display:grid;grid-template-columns:fit-content(55%) minmax(0,1fr);gap:4px 14px;margin:0;font-size:13px}
.kv dt{color:var(--muted)}.kv dd{margin:0;overflow-wrap:break-word;font-variant-numeric:tabular-nums}
.kv dd.sp{display:flex;flex-wrap:wrap;align-items:center;gap:2px 10px}
.reco{grid-column:1/-1;display:flex;gap:10px;background:var(--surface-2);border:1px solid var(--line);
border-radius:8px;
padding:10px 12px}
.reco .ic{width:18px;height:18px;color:var(--accent);margin-top:2px}
.reco h5{margin-bottom:2px}
.ff{margin-top:12px;padding-top:9px;border-top:1px solid var(--line);font-size:12px;color:var(--muted);display:flex;
flex-wrap:wrap;gap:4px 18px}
.ff code{color:var(--ink-2);overflow-wrap:anywhere}
/* footer */
.colophon{border-top:1px solid var(--line);padding:22px 0 44px;color:var(--muted);font-size:12.5px}
.colophon .ro{display:flex;gap:8px;align-items:center;color:var(--ink);font-weight:650;font-size:13.5px;
margin-bottom:6px}
.colophon .ro .ic{color:var(--accent);width:18px;height:18px}
.colophon p{margin:3px 0}
@media (max-width:820px){.fb{grid-template-columns:minmax(0,1fr)}.fact.w2{grid-column:1/-1}}
@media (max-width:640px){
.wrap{padding-left:16px;padding-right:16px}.mast{padding:20px 0 18px}.mast h1{font-size:23px}.eyebrow{display:none}
.meta{gap:8px 20px}.sh h2{font-size:17px}
.cards,.kpis{grid-template-columns:repeat(2,minmax(0,1fr))}
.kpi .v{font-size:22px}.card .s{font-size:15px}
.fact,.alert,.caveat{padding-left:14px;padding-right:14px}
.finding,.sg{padding:12px 14px}.kv{grid-template-columns:minmax(0,2fr) minmax(0,3fr);gap:6px 12px}
.facts{grid-template-columns:repeat(2,minmax(0,1fr))}.fact{padding:10px 14px}.txt{min-width:150px}}
@media (forced-colors:active){.card::before,.dot,.m i,.kpi .tone,.fact .mk{forced-color-adjust:none}
.b,.pill{border:1px solid CanvasText}}
@media print{
@page{size:A4;margin:14mm 12mm}
*{-webkit-print-color-adjust:exact;print-color-adjust:exact}
body{background:#fff;font-size:11.5px}
.toc,.skip{display:none}
.mast{background:#fff;color:var(--ink);padding:0 0 12px;border-bottom:2px solid var(--ink)}
.mast .tag,.meta dt,.eyebrow{color:var(--muted)}.meta{border-top-color:var(--line)}.brand b{color:var(--accent-ink)}
.chip{background:transparent;border-color:var(--line-2)}.chip.bad{background:#dc2626;color:#fff}
.wrap{max-width:none;padding-left:0;padding-right:0}main{padding-top:16px}
.card,.kpi,.finding,.tw,.basis,.callout,.inv>li,.counts li,.sg{box-shadow:none;break-inside:avoid}
.tw{overflow:visible}table{font-size:10.5px}.many .finding{content-visibility:visible}
.sh,h3{break-after:avoid}tr,.fact{break-inside:avoid}
.matrix tbody th,.matrix thead th:first-child{position:static}
a{color:inherit}}
"""

# ---- page ---------------------------------------------------------------------------------------------------


_MANY_FINDINGS = 150

_TOC_LABELS = {
    "status": "report.toc.status",
    "noise": "domain.noise",
    "silence": "domain.silence",
    "coverage": "domain.coverage",
    "pipeline": "domain.pipeline",
    "tuning": "domain.tuning",
    "findings": "report.toc.findings",
}


class _Kit:
    """Page-building helpers bound to a render context."""

    def __init__(self, ctx: RenderContext) -> None:
        self.ctx = ctx
        self.toc: list[tuple[str, str, str]] = []

    def t(self, key: str, **params: object) -> str:
        values = {k: self.ctx.num(v) if isinstance(v, int) else v for k, v in params.items()}
        return self.ctx.t(key, **values)

    # -- small parts ---------------------------------------------------------------------------------------------
    def pill(self, status: str) -> Safe:
        return h("span", {"class": _cls("pill", f"st-{status}")}, _icon(status), self.t(f"status.{status}"))

    def status_icon(self, status: str, labelled: bool = True) -> Safe:
        """Compact status mark (coloured dot + icon); the label stays available to screen readers and tooltips."""
        label = self.t(f"status.{status}")
        return h(
            "span",
            {"class": _cls("si", f"st-{status}"), "title": label if labelled else None},
            h("span", {"class": "dot", "aria-hidden": "true"}, _icon(status)),
            h("span", {"class": "sr"}, label) if labelled else None,
        )

    def section(
        self, sid: str, title_key: str, body: Iterable[object], status: str | None = None, cls: str = ""
    ) -> Safe:
        number = f"{len(self.toc) + 1:02d}"
        title = self.t(title_key)
        self.toc.append((sid, number, self.t(_TOC_LABELS.get(sid, title_key))))
        head = h(
            "div",
            {"class": "sh"},
            h("span", {"class": "n", "aria-hidden": "true"}, number),
            h("h2", {"id": f"{sid}-h"}, title),
            self.pill(status) if status else None,
        )
        return h("section", {"id": sid, "class": cls or None, "aria-labelledby": f"{sid}-h"}, head, *body)

    def not_assessed(self) -> Safe:
        return h(
            "div", {"class": "empty na"}, _icon("not_assessed"), h("span", None, self.t("report.not_assessed.section"))
        )

    def empty(self, key: str) -> Safe:
        return h("div", {"class": "empty"}, _icon("info"), h("span", None, self.t(key)))

    def facts(self, facts: Sequence[Fact], wide_items: bool = True) -> Safe:
        items = []
        for fact in facts:
            wide = wide_items and bool(fact.items) and (len(fact.items) > 1 or len(fact.items[0]) > 60)
            value: list[object] = []
            if fact.level in ("warn", "fail"):
                value.append(h("span", {"class": "mk", "aria-hidden": "true"}))
            value.append(fact.value)
            if fact.items:
                entries = [h("li", None, item) for item in fact.items]
                if fact.more:
                    entries.append(h("li", None, self.t("report.more_items", n=fact.more)))
                value.append(h("ul", None, entries))
            items.append(
                h(
                    "div",
                    {
                        "class": _cls(
                            "fact",
                            fact.level if fact.level in ("warn", "fail") else "",
                            "wide" if wide else ("w2" if fact.span > 1 else ""),
                        )
                    },
                    h("dt", None, fact.label),
                    h("dd", None, value),
                )
            )
        return h("dl", {"class": "facts"}, items)

    def table(
        self,
        caption: str | None,
        headers: Sequence[tuple[str, str]],
        rows: Sequence[Sequence[object]],
        *,
        cls: str = "",
        more: int = 0,
    ) -> Safe:
        head = h(
            "thead", None, h("tr", None, [h("th", {"scope": "col", "class": c or None}, label) for label, c in headers])
        )
        body_rows = [h("tr", None, list(row)) for row in rows]
        if more:
            body_rows.append(
                h("tr", {"class": "more"}, h("td", {"colspan": str(len(headers))}, self.t("report.more_rows", n=more)))
            )
        return h(
            "div",
            {"class": "tw"},
            h(
                "table",
                {"class": cls or None},
                h("caption", None, caption) if caption else None,
                head,
                h("tbody", None, body_rows),
            ),
        )

    def record_table(self, caption: str, table: RecordTable) -> Safe:
        headers = [(column, "") for column in table.columns]
        rows = [[h("td", None, cell) for cell in row] for row in table.rows]
        return self.table(caption, headers, rows, more=table.more)

    def spark(self, values: Sequence[float], *, compact: bool = False) -> Safe:
        if not values:
            return Safe("")
        return sparkline_svg(values, self.ctx.spark_label(values), width=96 if compact else 120)


class _Page(_Kit):
    def __init__(self, ctx: RenderContext, view: ReportView) -> None:
        super().__init__(ctx)
        self.v = view

    def render(self) -> tuple[Safe, str]:
        v = self.v
        sections: list[Safe | None] = [self._basis(), self._status(), self._numbers()]
        if not v.audit:  # a ruleset audit has no events: only the tuning audit applies
            sections += [self._noise(), self._silence(), self._coverage(), self._pipeline()]
        sections += [self._tuning(), self._others(), self._findings()]
        body = _join(
            [
                h("a", {"class": "skip", "href": "#main"}, self.t("report.skip")),
                self._masthead(),
                self._toc(),
                h("main", {"id": "main", "class": "wrap"}, sections),
                self._footer(),
            ]
        )
        prefix = f"⚠ {self.t('report.basis.incomplete')} · " if v.incomplete else ""
        title = f"{prefix}{v.tenant} · {v.title} · hushwatch"
        return body, title

    def _masthead(self) -> Safe:
        v = self.v
        redaction = self.t("report.redaction.on" if v.redacted else "report.redaction.off")
        meta = [(self.t("report.tenant"), v.tenant)]
        if v.period:
            meta.append((self.t("report.period"), v.period))
        meta.append((self.t("report.generated"), v.generated_at))
        items = [h("div", None, h("dt", None, label), h("dd", None, value)) for label, value in meta]
        items.append(
            h(
                "div",
                None,
                h("dt", None, self.t("report.redaction")),
                h("dd", None, h("span", {"class": "chip"}, _icon("lock" if v.redacted else "info"), redaction)),
            )
        )
        status_key = "report.basis.incomplete" if v.incomplete else "report.basis.complete"
        items.append(
            h(
                "div",
                None,
                h("dt", None, self.t("report.col.data")),
                h(
                    "dd",
                    None,
                    h(
                        "span",
                        {"class": _cls("chip", "bad" if v.incomplete else "")},
                        _icon("alert" if v.incomplete else "ok"),
                        self.t(status_key),
                    ),
                ),
            )
        )
        return h(
            "header",
            {"class": "mast"},
            h(
                "div",
                {"class": "wrap"},
                h(
                    "div",
                    {"class": "brand"},
                    _LOGO,
                    h("span", None, "hush", h("b", None, "watch")),
                    h("span", {"class": "eyebrow"}, self.t("report.eyebrow")),
                ),
                h("h1", None, v.title),
                h("p", {"class": "tag"}, v.tagline),
                h("dl", {"class": "meta"}, items),
            ),
        )

    def _toc(self) -> Safe:
        links = [
            h("li", None, h("a", {"href": f"#{sid}"}, h("span", {"class": "n"}, number), title))
            for sid, number, title in self.toc
        ]
        return h(
            "nav",
            {"class": "toc", "aria-label": self.t("report.contents")},
            h("div", {"class": "wrap"}, h("ol", None, links)),
        )

    def _footer(self) -> Safe:
        v = self.v
        lines = [h("p", None, line) for line in v.footer[1:]]
        return h(
            "footer",
            {"class": "colophon"},
            h("div", {"class": "wrap"}, h("div", {"class": "ro"}, _icon("shield"), v.footer[0]), lines),
        )

    # -- sections ------------------------------------------------------------------------------------------------
    def _basis(self) -> Safe:
        basis = self.v.basis
        parts: list[object] = []
        if basis.complete:
            parts.append(
                h(
                    "div",
                    {"class": "alert good"},
                    h("div", {"class": "ib"}, _icon("ok")),
                    h(
                        "div",
                        None,
                        h("strong", None, self.t("report.basis.complete")),
                        h("p", None, self.t("report.basis.complete_body")),
                    ),
                )
            )
        else:
            parts.append(
                h(
                    "div",
                    {"class": "alert bad", "role": "alert"},
                    h("div", {"class": "ib"}, _icon("alert")),
                    h(
                        "div",
                        None,
                        h("h2", None, self.t("report.basis.incomplete")),
                        h("p", None, h("strong", None, self.t("report.basis.incomplete_body"))),
                        h("ul", None, [h("li", None, r) for r in basis.reasons]),
                    ),
                )
            )
        parts.extend(h("div", {"class": "caveat"}, _icon("info"), h("span", None, c)) for c in basis.caveats)
        parts.append(self.facts(basis.facts))
        return self.section("basis", "report.section.basis", [h("div", {"class": "basis"}, parts)])

    def _card(self, card: DomainCard) -> Safe:
        return h(
            "div",
            {"class": _cls("card", f"st-{card.status}")},
            h("div", {"class": "d"}, card.label),
            h("div", {"class": "s"}, h("span", {"class": "dot"}, _icon(card.status)), card.status_label),
            h("div", {"class": "c"}, card.detail),
            [h("div", {"class": "c note"}, _icon("info"), note) for note in card.notes],
        )

    def _status(self) -> Safe:
        return self.section(
            "status", "report.section.status", [h("div", {"class": "cards"}, [self._card(c) for c in self.v.cards])]
        )

    def _kpi(self, number: KeyNumber) -> Safe:
        return h(
            "div",
            {"class": _cls("kpi", f"t-{number.tone}")},
            h("span", {"class": "tone", "aria-hidden": "true"}),
            h("div", {"class": "l"}, number.label),
            h("div", {"class": "v"}, number.value),
            h("div", {"class": "h"}, number.hint) if number.hint else None,
        )

    def _numbers(self) -> Safe:
        return self.section(
            "numbers", "report.section.numbers", [h("div", {"class": "kpis"}, [self._kpi(n) for n in self.v.numbers])]
        )

    def _noise(self) -> Safe:
        n = self.v.noise
        body: list[object] = []
        if not n.assessed:
            return self.section("noise", "report.section.noise", [self.not_assessed()], n.status)
        if n.summary:
            body.append(h("p", {"class": "lede"}, n.summary))
        if n.rules:
            headers = [
                (self.t("report.col.rule"), ""),
                (self.t("report.col.description"), ""),
                (self.t("report.col.level"), "n"),
                (self.t("report.col.per_day"), "n"),
                (self.t("report.col.analyst_facing"), "n"),
                (self.t("report.col.share"), "n"),
                (self.t("report.col.clusters"), "n"),
                (self.t("report.col.verdict"), ""),
                (self.t("report.col.trend"), ""),
            ]
            rows = [
                [
                    h("th", {"scope": "row", "class": "rid"}, r.rule_id),
                    h(
                        "td",
                        {"class": "txt"},
                        r.description or self.t("report.dash"),
                        h("span", {"class": "sub"}, r.anchor)
                        if r.anchor and r.anchor != self.t("report.dash")
                        else None,
                    ),
                    h("td", {"class": "n"}, r.level),
                    h("td", {"class": "n"}, r.per_day),
                    h("td", {"class": "n"}, r.analyst_facing),
                    h("td", {"class": "n"}, h("span", {"class": "share"}, _meter(r.share_value), r.share)),
                    h("td", {"class": "n"}, r.clusters),
                    h("td", None, h("span", {"class": _cls("b", f"v-{r.verdict}")}, r.verdict_label)),
                    h("td", None, self.spark(r.daily, compact=True)),
                ]
                for r in n.rules
            ]
            body.append(self.table(self.t("report.noise.top_rules"), headers, rows, more=n.rules_more))
        else:
            body.append(self.empty("report.noise.no_rules"))
        body.append(h("h3", None, self.t("report.noise.suggestions")))
        if n.tune:
            body.append(h("ol", {"class": "sugg"}, [self._suggestion(item) for item in n.tune]))
        else:
            body.append(self.empty("report.noise.no_suggestions"))
        body.append(h("h3", None, self.t("report.noise.investigate")))
        body.append(h("p", {"class": "hint"}, self.t("report.noise.investigate_hint")))
        if n.investigate:
            items = [
                h(
                    "li",
                    None,
                    h(
                        "div",
                        {"class": "t"},
                        h("span", {"class": _cls("b", f"v-{i.verdict}")}, i.verdict_label),
                        h("span", {"class": _cls("b", f"sev-{i.severity}")}, i.severity_label),
                        h("a", {"href": f"#{i.anchor}"}, i.title),
                    ),
                    h("ul", None, [h("li", None, r) for r in i.reasons]) if i.reasons else None,
                )
                for i in n.investigate
            ]
            body.append(h("ul", {"class": "inv"}, items))
        else:
            body.append(self.empty("report.noise.none_investigate"))
        if n.index_volume:
            body.append(h("h3", None, self.t("report.noise.index_volume")))
            body.append(h("p", {"class": "hint"}, self.t("report.noise.index_volume_hint")))
            items = [
                h(
                    "li",
                    None,
                    h(
                        "div",
                        {"class": "t"},
                        h("span", {"class": _cls("b", "v-watch")}, i.verdict_label),
                        h("a", {"href": f"#{i.anchor}"}, i.title),
                    ),
                    h("ul", None, [h("li", None, r) for r in i.reasons[:3]]) if i.reasons else None,
                )
                for i in n.index_volume
            ]
            body.append(h("ul", {"class": "inv"}, items))
        if n.time_saved:
            body.append(
                h(
                    "div",
                    {"class": "callout"},
                    _icon("info"),
                    h(
                        "div",
                        None,
                        h("strong", None, self.t("report.noise.time_saved")),
                        h("span", {"class": "big"}, n.time_saved),
                        h("div", {"class": "hint"}, self.t("report.noise.time_saved_hint")),
                    ),
                )
            )
        if n.suppressions_file:
            body.append(
                h(
                    "div",
                    {"class": "callout"},
                    _icon("lock"),
                    h(
                        "div",
                        None,
                        h("strong", None, self.t("report.noise.suppressions_file")),
                        h("code", None, n.suppressions_file),
                    ),
                )
            )
        if n.extra:
            body += [h("h3", None, self.t("report.details")), h("div", {"class": "basis"}, self.facts(n.extra))]
        return self.section("noise", "report.section.noise", body, n.status)

    def _suggestion(self, s: TuneRow) -> Safe:
        badge = (
            h("span", {"class": "b review"}, _icon("warn"), self.t("report.noise.review_required"))
            if s.review_required
            else h("span", {"class": "b ready"}, _icon("ok"), self.t("report.noise.ready"))
        )
        stats = [
            ("report.col.hidden_per_day", [s.hidden_per_day]),
            ("report.col.share_of_rule", [_meter(s.share_value), s.share_of_rule]),
            ("report.col.af_hidden", [s.af_hidden]),
            ("report.col.agents", [s.agents]),
            ("report.col.expires", [s.expires]),
        ]
        return h(
            "li",
            {"class": _cls("sg", "rv" if s.review_required else "")},
            h("div", {"class": "sg-h"}, h("a", {"href": f"#{s.anchor}"}, s.title), badge),
            h("div", {"class": "sg-scope"}, self.t("report.col.scope") + ":", h("code", None, s.scope)),
            h(
                "dl",
                {"class": "sg-stats"},
                [h("div", None, h("dt", None, self.t(k)), h("dd", None, v)) for k, v in stats],
            ),
            h("p", {"class": "sg-note"}, _icon("warn"), self.t("report.noise.review_hint", rules=s.dependents))
            if s.dependents
            else None,
        )

    def _silence(self) -> Safe:
        s = self.v.silence
        if not s.assessed:
            return self.section("silence", "report.section.silence", [self.not_assessed()], s.status)
        body: list[object] = []
        if s.counts:
            hot = {"silent", "drop", "tampering"}
            body.append(
                h(
                    "ul",
                    {"class": "counts", "aria-label": self.t("report.silence.counts")},
                    [
                        h(
                            "li",
                            {"class": "hot" if key in hot and count else None},
                            h("div", {"class": "k"}, label),
                            h("div", {"class": "v"}, self.ctx.num(count)),
                        )
                        for key, label, count in s.counts
                    ],
                )
            )
        if s.monitorability:
            body.append(
                h(
                    "div",
                    {"class": "callout"},
                    _icon("shield"),
                    h(
                        "div",
                        None,
                        h("strong", None, self.t("report.silence.monitorability")),
                        h(
                            "div",
                            {"class": "mon"},
                            _meter(s.monitorability_value, width=180, height=8)
                            if s.monitorability_value is not None
                            else None,
                            h("span", {"class": "big"}, s.monitorability),
                        ),
                        h("div", {"class": "hint"}, s.alpha) if s.alpha else None,
                    ),
                )
            )
        elif s.alpha:
            body.append(h("p", {"class": "hint"}, s.alpha))
        if s.sources:
            headers = [
                (self.t("report.col.source"), ""),
                (self.t("report.col.status"), ""),
                (self.t("report.col.last_seen"), ""),
                (self.t("report.col.observed"), "n"),
                (self.t("report.col.expected"), "n"),
                (self.t("report.col.p"), "n"),
                (self.t("report.col.tier"), ""),
                (self.t("report.col.trend"), ""),
            ]
            rows = [
                [
                    h("th", {"scope": "row", "class": "txt"}, r.key, h("span", {"class": "sub"}, r.level_label)),
                    h("td", None, h("span", {"class": _cls("b", f"s-{r.status}")}, r.status_label)),
                    h(
                        "td",
                        None,
                        h("span", {"class": "nw"}, r.last_seen),
                        h("span", {"class": "sub"}, r.silent_for) if r.silent_for else None,
                    ),
                    h("td", {"class": "n"}, r.observed),
                    h("td", {"class": "n"}, r.expected),
                    h("td", {"class": "n"}, r.p),
                    h(
                        "td",
                        None,
                        h("span", {"class": _cls("b", f"tier-{r.tier}")}, r.tier_label),
                        h("span", {"class": "sub", "title": self.t("report.col.duty")}, r.duty_label),
                    ),
                    h("td", None, self.spark(r.daily, compact=True)),
                ]
                for r in s.sources
            ]
            body.append(self.table(self.t("report.silence.sources"), headers, rows, more=s.sources_more))
        else:
            body.append(self.empty("report.silence.no_sources"))
        if s.extra:
            body += [h("h3", None, self.t("report.details")), h("div", {"class": "basis"}, self.facts(s.extra))]
        return self.section("silence", "report.section.silence", body, s.status)

    def _coverage(self) -> Safe:
        c = self.v.coverage
        if not c.assessed:
            return self.section("coverage", "report.section.coverage", [self.not_assessed()], c.status)
        body: list[object] = []
        if c.platforms:
            body += [
                h("h3", None, self.t("report.coverage.platforms")),
                h("div", {"class": "basis"}, self.facts(c.platforms, False)),
            ]
        if c.expected:
            body.append(
                h(
                    "p",
                    {"class": "hint"},
                    h("strong", None, self.t("report.coverage.expected") + ": "),
                    ", ".join(c.expected),
                )
            )
        if c.expected_table is not None:
            body.append(self.record_table(self.t("report.coverage.expected"), c.expected_table))
        if c.rows and c.columns:
            labels = {k: self.t(f"report.coverage.{k}") for k in ("present", "missing", "silent", "na")}
            headers = [(self.t("report.col.agent"), ""), (self.t("report.col.platform"), "")]
            head_cells = [h("th", {"scope": "col"}, label) for label, _ in headers]
            head_cells += [h("th", {"scope": "col", "class": "vh", "title": col}, col) for col in c.columns]
            rows = [
                h(
                    "tr",
                    None,
                    h(
                        "th",
                        {"scope": "row"},
                        r.agent,
                        h("span", {"class": "sub"}, r.tier_label) if r.tier_label else None,
                    ),
                    h("td", None, r.platform),
                    [
                        h(
                            "td",
                            {"class": _cls("m", f"m-{cell}"), "title": labels.get(cell, "")},
                            h("i", {"aria-hidden": "true"}),
                            h("span", {"class": "sr"}, labels.get(cell, "")),
                        )
                        for cell in r.cells
                    ],
                )
                for r in c.rows
            ]
            if c.rows_more:
                rows.append(
                    h(
                        "tr",
                        {"class": "more"},
                        h("td", {"colspan": str(len(c.columns) + 2)}, self.t("report.more_rows", n=c.rows_more)),
                    )
                )
            table = h(
                "div",
                {"class": "tw fit"},
                h(
                    "table",
                    {"class": "matrix"},
                    h("caption", None, self.t("report.coverage.matrix")),
                    h("thead", None, h("tr", None, head_cells)),
                    h("tbody", None, rows),
                ),
            )
            legend = h(
                "div",
                {"class": "legend", "aria-hidden": "true"},
                [
                    h("span", {"class": _cls("lg", f"m-{k}")}, h("i", None), labels[k])
                    for k in ("present", "missing", "silent")
                ],
                h("span", None, self.t("report.coverage.more_cols", n=c.columns_more)) if c.columns_more else None,
            )
            body += [table, legend]
        else:
            body.append(self.empty("report.coverage.no_matrix"))
        if c.extra:
            body += [h("h3", None, self.t("report.details")), h("div", {"class": "basis"}, self.facts(c.extra))]
        return self.section("coverage", "report.section.coverage", body, c.status)

    def _pipeline(self) -> Safe:
        p = self.v.pipeline
        if not p.assessed:
            return self.section("pipeline", "report.section.pipeline", [self.not_assessed()], p.status)
        body: list[object] = []
        if p.agents:
            body += [
                h("h3", None, self.t("report.pipeline.agents")),
                h("div", {"class": "basis"}, self.facts(p.agents, False)),
            ]
        if p.checks:
            headers = [
                (self.t("report.col.check"), ""),
                (self.t("report.col.status"), ""),
                (self.t("report.col.detail"), ""),
            ]
            rows = [
                [
                    h("th", {"scope": "row", "class": "txt"}, check.name),
                    h("td", None, self.pill(check.status) if check.status else check.status_label),
                    h("td", {"class": "txt"}, check.detail),
                ]
                for check in p.checks
            ]
            body.append(self.table(self.t("report.pipeline.checks"), headers, rows))
        if p.extra:
            body += [h("h3", None, self.t("report.details")), h("div", {"class": "basis"}, self.facts(p.extra))]
        if not (p.agents or p.checks or p.extra):
            body.append(self.empty("report.no_details"))
        return self.section("pipeline", "report.section.pipeline", body, p.status)

    def _tuning(self) -> Safe:
        tv = self.v.tuning
        if not tv.assessed:
            return self.section("tuning", "report.section.tuning", [self.not_assessed()], tv.status)
        facts = [*tv.facts, *tv.extra]
        body = [h("div", {"class": "basis"}, self.facts(facts))] if facts else [self.empty("report.no_details")]
        return self.section("tuning", "report.section.tuning", body, tv.status)

    def _others(self) -> Safe | None:
        if not self.v.others:
            return None
        body: list[object] = []
        for name, facts in self.v.others:
            body += [
                h("h3", None, name),
                h("div", {"class": "basis"}, self.facts(facts)) if facts else self.empty("report.no_details"),
            ]
        return self.section("other", "report.section.other", body)

    def _findings(self) -> Safe:
        v = self.v
        if not v.groups:
            key = "report.findings.none_incomplete" if v.incomplete else "report.findings.none"
            return self.section("findings", "report.section.findings", [self.empty(key)])
        counts = h(
            "div",
            {"class": "fcount"},
            [
                h(
                    "span",
                    {"class": _cls("b", f"sev-{sev}")},
                    self.t("report.card.count", n=n, severity=self.t("severity." + sev)),
                )
                for sev, n in v.severity_counts.items()
                if n
            ],
        )
        groups = [
            h(
                "div",
                {"class": "fgroup", "id": f"findings-{_cls(g.domain)}"},
                h("h3", None, g.label, h("span", {"class": "c"}, self.ctx.num(len(g.findings)))),
                [self._finding(f) for f in g.findings],
            )
            for g in v.groups
        ]
        # Large reports: let the browser skip layout of off-screen finding cards (5,000 findings open in ~1.5 s
        # instead of ~8 s). Small reports keep plain rendering (some full-page screenshot tools skip such cards).
        many = "many" if v.total_findings > _MANY_FINDINGS else ""
        return self.section("findings", "report.section.findings", [counts, groups], cls=many)

    def _finding(self, f: FindingView) -> Safe:
        head = h(
            "div",
            {"class": "fh"},
            h("span", {"class": _cls("b", f"sev-{f.severity}")}, f.severity_label.upper()),
            h("h4", None, f.title),
            h("span", {"class": "b review"}, _icon("warn"), self.t("report.noise.review_required"))
            if f.review_required
            else None,
            h("span", {"class": "conf"}, f.confidence_label),
        )
        columns: list[object] = []
        if f.reasons:
            columns.append(
                h(
                    "div",
                    None,
                    h("h5", None, self.t("report.finding.why")),
                    h("ul", None, [h("li", None, r) for r in f.reasons]),
                )
            )
        if f.evidence:
            rows = []
            for row in f.evidence:
                if row.series:
                    dd = h("dd", {"class": "sp"}, self.spark(row.series), h("span", None, row.value))
                else:
                    dd = h("dd", None, row.value)
                rows += [h("dt", None, row.label), dd]
            columns.append(
                h("div", None, h("h5", None, self.t("report.finding.evidence")), h("dl", {"class": "kv"}, rows))
            )
        if f.explained:
            columns.append(
                h(
                    "div",
                    None,
                    h("h5", None, self.t("report.finding.explained")),
                    h("ul", None, [h("li", None, item) for item in f.explained]),
                )
            )
        if f.recommendation:
            columns.append(
                h(
                    "div",
                    {"class": "reco"},
                    _icon("arrow"),
                    h("div", None, h("h5", None, self.t("report.finding.recommendation")), f.recommendation),
                )
            )
        meta = [
            h("span", None, self.t("report.finding.kind") + ": ", h("code", None, f.kind)),
            h("span", None, self.t("report.finding.fingerprint") + ": ", h("code", None, f.fingerprint)),
            h("span", None, self.t("report.finding.subject") + ": ", h("code", None, f.subject)),
        ]
        return h(
            "article",
            {"class": _cls("finding", f"sev-{f.severity}"), "id": f.anchor},
            head,
            h("div", {"class": "fb"}, columns) if columns else None,
            h("div", {"class": "ff"}, meta),
        )


def _json_block(document: Mapping[str, Any]) -> Safe:
    text = json.dumps(document, sort_keys=True, ensure_ascii=False, allow_nan=False)
    for raw, escaped in (("<", "\\u003c"), (">", "\\u003e"), ("&", "\\u0026"), (" ", "\\u2028"), (" ", "\\u2029")):
        text = text.replace(raw, escaped)
    return Safe(f'<script type="application/json" id="hushwatch-data">{text}</script>')


def _document(lang: str, title: str, body: Safe, extra_head: Safe | None = None) -> str:
    head = _join(
        [
            Safe('<meta charset="utf-8">'),
            _CSP_META,
            h("meta", {"name": "viewport", "content": "width=device-width, initial-scale=1"}),
            h("meta", {"name": "referrer", "content": "no-referrer"}),
            h("meta", {"name": "color-scheme", "content": "light dark"}),
            h("meta", {"name": "robots", "content": "noindex, nofollow"}),
            h("meta", {"name": "generator", "content": "hushwatch"}),
            h("title", None, title),
            Safe(f"<style>{_CSS}</style>"),
            extra_head,
        ]
    )
    return f'<!doctype html>\n<html lang="{esc(lang)}">\n<head>{head}</head>\n<body>{body}</body>\n</html>\n'


def render_html(report: Report, *, lang: str = "en", redactor: Redactor | None = None, embed_json: bool = False) -> str:
    """Render one report as a self-contained, script-free HTML page.

    ``embed_json=True`` also embeds the JSON report as an inert ``application/json`` data block (off by
    default: some mail gateways strip or quarantine any ``<script>`` element).
    """
    ctx = prepare_context(report, lang, redactor)
    page = _Page(ctx, build_view(ctx, report))
    body, title = page.render()
    extra = _json_block(build_document(ctx, report)) if embed_json else Safe("")
    return _document(ctx.lang, title, body, extra)


def render_html_many(
    reports: Sequence[Report],
    *,
    lang: str = "en",
    redactor: Redactor | Mapping[str, Redactor | None] | None = None,
) -> str:
    """Multi-tenant fleet summary page: one row per tenant (domain statuses, critical/high counts)."""
    ctx, rows = fleet_rows(reports, lang, redactor)
    page = _Kit(ctx)
    t = page.t
    generated = max((r.generated_at_iso for r in rows if r.generated_at_iso), default=None)
    incomplete = sum(1 for r in rows if r.incomplete)
    meta = [
        h("div", None, h("dt", None, t("report.fleet.count")), h("dd", None, ctx.num(len(rows)))),
        h(
            "div",
            None,
            h("dt", None, t("report.generated")),
            h("dd", None, ctx.dt(generated) if generated else t("report.dash")),
        ),
        h(
            "div",
            None,
            h("dt", None, t("report.col.data")),
            h(
                "dd",
                None,
                h(
                    "span",
                    {"class": _cls("chip", "bad" if incomplete else "")},
                    _icon("alert" if incomplete else "ok"),
                    f"{ctx.num(incomplete)} {t('report.fleet.incomplete')}"
                    if incomplete
                    else t("report.fleet.complete"),
                ),
            ),
        ),
    ]
    mast = h(
        "header",
        {"class": "mast"},
        h(
            "div",
            {"class": "wrap"},
            h(
                "div",
                {"class": "brand"},
                _LOGO,
                h("span", None, "hush", h("b", None, "watch")),
                h("span", {"class": "eyebrow"}, t("report.fleet.title")),
            ),
            h("h1", None, t("report.fleet.title")),
            h("p", {"class": "tag"}, t("report.tagline")),
            h("dl", {"class": "meta"}, meta),
        ),
    )
    if rows:
        headers = [(t("report.col.tenant"), "")]
        headers += [(t(f"domain.{d}"), "c") for d in DOMAINS]
        headers += [
            (t("report.col.critical"), "n"),
            (t("report.col.high"), "n"),
            (t("report.col.findings"), "n"),
            (t("report.col.events"), "n"),
        ]
        table_rows = []
        for row in rows:
            worst = (
                h(
                    "span",
                    {"class": "sub"},
                    h("span", {"class": _cls("b", f"sev-{row.worst_severity}")}, t(f"severity.{row.worst_severity}")),
                    " ",
                    row.worst_title,
                )
                if row.worst_severity
                else None
            )
            cells: list[object] = [
                h(
                    "th",
                    {"scope": "row", "class": "txt"},
                    row.tenant,
                    h("span", {"class": "b sev-critical"}, _icon("alert"), t("report.data.incomplete"))
                    if row.incomplete
                    else None,
                    worst,
                )
            ]
            cells += [h("td", {"class": "c"}, page.status_icon(row.statuses[d])) for d in DOMAINS]
            cells += [
                h(
                    "td",
                    {"class": "n"},
                    h("span", {"class": "b sev-critical"}, ctx.num(row.critical)) if row.critical else "0",
                ),
                h("td", {"class": "n"}, h("span", {"class": "b sev-high"}, ctx.num(row.high)) if row.high else "0"),
                h("td", {"class": "n"}, ctx.num(row.total)),
                h("td", {"class": "n"}, ctx.num(row.events)),
            ]
            table_rows.append(cells)
        legend = h(
            "div",
            {"class": "legend"},
            [
                h("span", None, page.status_icon(st, labelled=False), t(f"status.{st}"))
                for st in ("ok", "warn", "fail", "not_assessed")
            ],
        )
        content = [
            h("p", {"class": "hint"}, t("report.fleet.order")),
            page.table(t("report.fleet.title"), headers, table_rows),
            legend,
        ]
    else:
        content = [page.empty("report.fleet.empty")]
    notice, *details = fleet_footer(ctx, reports)
    footer = h(
        "footer",
        {"class": "colophon"},
        h(
            "div",
            {"class": "wrap"},
            h("div", {"class": "ro"}, _icon("shield"), notice),
            [h("p", None, line) for line in details],
        ),
    )
    body = _join(
        [
            h("a", {"class": "skip", "href": "#main"}, t("report.skip")),
            mast,
            h("main", {"id": "main", "class": "wrap"}, content),
            footer,
        ]
    )
    return _document(ctx.lang, f"{t('report.fleet.title')} · hushwatch", body)
