"""Hostile-input suite for the report renderers.

Log values are attacker-controlled. Every value below ends up in titles, message params, entities, evidence
(keys and values), reasons, recommendations, subjects, the data basis and every section, and every renderer
must neutralize it for its own sink: no HTML/SVG tags or attributes, no Rich markup or ANSI escapes, no
Markdown links/images/tables breaks, strict JSON, bounded size and time, and no crash on mistyped data.
"""

from __future__ import annotations

import io
import json
import math
import re
import time
from datetime import datetime, timedelta, timezone
from html.parser import HTMLParser
from typing import Any

import pytest
from rich.console import Console
from test_report import build_full_report, parse_html, render_console

from hushwatch.i18n import Entity, M, Message, register
from hushwatch.models import Confidence, DataBasis, Finding, Report, Severity
from hushwatch.redact import Redactor
from hushwatch.report import FORMATS, print_console, print_console_many, render, render_many
from hushwatch.report.common import MAX_TEXT
from hushwatch.report.html import _CSS, CSP, render_html

UTC = timezone.utc
NOW = datetime(2026, 9, 25, 10, 0, tzinfo=UTC)
BIG = "A" * 1_000_000  # 1 MB log value

EVIL: tuple[str, ...] = (
    "<script>alert(1)</script>",
    '"><img src=x onerror=1>',
    "]]>",
    "-->",
    "<!-- c -->",
    "[bold red]x[/]",
    "[link=http://x]y[/link]",
    "[/]",
    "\x1b[2J",
    "\x07",
    "\x1b]8;;http://x\x1b\\click\x1b]8;;\x1b\\",
    '=HYPERLINK("http://x")',
    "|pipe|",
    "`code` ```block```",
    "![img](http://x)",
    "[click](javascript:alert(1))",
    "<http://x>",
    "../../etc/passwd",
    "‮evil‬",
    "nul\x00and\x9b31mcsi",
    "{bad} {0} {x.__class__} {y:>99999}",
    "$\\color{red}{fake}$",
    "' onmouseover='x",
    "&lt;script&gt;",
    "line1\nline2\r\n# heading\n> quote\n- item",
    "\udcff\ud800surrogates",
    "</style><script>alert(1)</script>",
    "</title><svg onload=alert(1)>",
    "javascript:alert(1)",
    "data:text/html,<b>x</b>",
    "@everyone alice@evil.example",
    "1. item",
    "- bullet",
    "\x1bP+q\x1b\\",
    "\r\x1b[1A\x1b[2Kfake line",
)

register(
    {
        "testsec.generic": {"en": "value {what}", "es": "valor {what}"},
        "testsec.badspec": {"en": "share {share:.0%} and {n:,d} and {missing}", "es": "{share:.0%} {n:,d}"},
    }
)

_KINDS = (
    ("noise.tune", "noise"),
    ("noise.investigate", "noise"),
    ("silence.silent", "silence"),
    ("pipeline.lag", "pipeline"),
    ("coverage.missing_source", "coverage"),
    ("tuning.risky_suppression", "tuning"),
    ("assessment.incomplete", "assessment"),
)


def evil_findings() -> list[Finding]:
    findings: list[Finding] = []
    for i, value in enumerate(EVIL):
        kind, domain = _KINDS[i % len(_KINDS)]
        findings.append(
            Finding(
                kind=kind,
                domain=domain,
                title=value if i % 2 else M("testsec.generic", what=Entity("host", value)),
                severity=list(Severity)[i % 5],
                subject=f"agent:{value}|user:{value}|ls:{value}",
                reasons=[value, M("testsec.generic", what=value), M("testsec.generic", what=Entity("user", value))],
                evidence={
                    value: value,
                    "cmd": Entity("cmd", value),
                    "nested": {value: [value, Entity("ip", value), {"deep": Entity("url", value)}]},
                    "conditions": [{"field": value, "value": Entity("host", value)}],
                    "daily": [1, 5, 3, 0, 9, 2, 0],
                    "last_seen": value,
                    "share": value,
                },
                recommendation=M("testsec.generic", what=Entity("url", value)),
                confidence=Confidence.LOW,
                tenant=value,
                related=[value],
            )
        )
    findings.append(
        Finding(
            kind="noise.tune",
            domain="noise",
            title=BIG,
            severity=Severity.CRITICAL,
            subject=BIG,
            reasons=[BIG, M("testsec.generic", what=BIG), M("testsec.generic", what=Entity("cmd", BIG))],
            evidence={BIG: BIG, "entity": Entity("cmd", BIG), "list": [BIG] * 50},
            recommendation=BIG,
        )
    )
    for i, value in enumerate(EVIL[::3]):  # hostile values in the fields analyzers normally control
        finding = Finding(
            kind="noise.tune",
            domain="noise",
            title=Message(value, {value[:8] or "k": value}, value),  # unregistered key, hostile default
            severity=Severity.HIGH,
            subject=value,
            reasons=[Message(value, {"p": Entity("host", value)}, value + " {p}")],
            evidence={value: {value: value}, "conditions": {value: value}},
            recommendation=value,
            tenant=value,
            fingerprint=value,
            related=[value, value],
        )
        finding.kind = value  # mutated after validation
        finding.domain = value if i % 2 else "noise"
        finding.confidence = value  # type: ignore[assignment]
        findings.append(finding)
    findings.append(
        Finding(
            kind="noise.investigate",
            domain="noise",
            title=M("testsec.badspec", share="not-a-number", n="x"),
            severity=Severity.HIGH,
            subject="badspec",
            reasons=[M("no.such.key"), M("no.such.key", "{unclosed", a=1), M("testsec.generic")],
        )
    )
    return findings


def evil_sections() -> dict[str, Any]:
    e = EVIL
    weird_daily = [float("nan"), float("inf"), -5, "x", None, True, 10**30, 3]
    return {
        "noise": {
            "status": e[0],
            "totals": {"alerts": e[1], "days": float("nan"), "top5_share": float("inf"), e[2]: e[3]},
            "rules": [
                {
                    "rule_id": value,
                    "description": value,
                    "level": value,
                    "per_day": float("nan"),
                    "share": 7.5,
                    "top_anchor": {"field": value, "value": Entity("host", value), "share": value},
                    "verdict": value,
                    "daily": weird_daily,
                }
                for value in e
            ]
            + [{"rule_id": BIG, "description": BIG, "daily": list(range(400))}, "not a dict", None],
            "time_saved_minutes_per_day": [e[0], e[1]],
            "suppressions_file": e[0],
            e[4]: {e[5]: e[6]},
        },
        "silence": {
            "status": "fail",
            "alpha_eff": e[7],
            "status_counts": {value: i for i, value in enumerate(e)},
            "sources": [
                {
                    "level": value,
                    "key": {value: Entity("host", value)},
                    "status": value,
                    "last_seen": value,
                    "tier": value,
                    "duty": value,
                    "observed": value,
                    "p": value,
                    "daily": weird_daily,
                }
                for value in e
            ]
            + [{"key": BIG, "last_seen": BIG}, 42],
            "monitorability": {"critical_total": 0, "critical_monitorable": e[0]},
            "fields": [e[0], {e[1]: e[2]}],
        },
        "coverage": {
            "status": "warn",
            "platforms": {value: value for value in e},
            "matrix": [
                {
                    "agent": Entity("host", value),
                    "platform": value,
                    "log_sources": {value: "present", BIG: "missing", e[0]: value},
                }
                for value in e
            ],
            "expected_sources": [*e, {"name": e[0]}],
        },
        "pipeline": {
            "status": "warn",
            "agents": {value: value for value in e},
            "checks": [{"name": value, "status": value, value: value} for value in e] + [e[0], None, 5],
        },
        "tuning": {"status": "warn", "rules_parsed": e[0], "risky": e[1], "expired": list(e), e[2]: e[3]},
        e[0]: {e[1]: e[2], "big": BIG},
        "listy": ["not", "a", "dict"],  # wrong type on purpose
    }


def build_evil_report() -> Report:
    basis = DataBasis(
        input_kind=EVIL[0],
        profile=EVIL[5],
        sources=[*EVIL, BIG],
        start=NOW - timedelta(days=21),
        end=NOW,
        now=NOW,
        now_origin=EVIL[8],
        events=10,
        partial_failures=list(EVIL),
        warnings=[*EVIL, *(M("testsec.generic", what=v) for v in EVIL), M("testsec.generic", what=Entity("ip", BIG))],
        not_evaluated=list(EVIL),
    )
    return Report(
        tenant=EVIL[0],
        generated_at=NOW,
        tool_version=EVIL[1],
        data_basis=basis,
        findings=evil_findings(),
        sections=evil_sections(),
        assessment={domain: EVIL[i] for i, domain in enumerate(("noise", "silence", "pipeline", "coverage"))},
    )


@pytest.fixture(scope="module")
def evil_report() -> Report:
    return build_evil_report()


@pytest.fixture(scope="module")
def evil_outputs(evil_report: Report) -> dict[str, str]:
    out: dict[str, str] = {}
    for lang in ("en", "es"):
        for fmt in FORMATS:
            out[f"{fmt}-{lang}"] = render(evil_report, fmt, lang=lang)
        out[f"console-{lang}"] = render_console(evil_report, lang=lang, verbose=True)
    out["html-embed"] = render_html(evil_report, embed_json=True)
    return out


# ---- HTML -------------------------------------------------------------------------------------------------------

_ALLOWED_TAGS = frozenset(
    [
        "html",
        "head",
        "meta",
        "title",
        "style",
        "body",
        "a",
        "header",
        "nav",
        "main",
        "section",
        "footer",
        "div",
        "span",
        "p",
        "strong",
        "b",
        "code",
        "ul",
        "ol",
        "li",
        "dl",
        "dt",
        "dd",
        "h1",
        "h2",
        "h3",
        "h4",
        "h5",
        "table",
        "caption",
        "thead",
        "tbody",
        "tr",
        "th",
        "td",
        "article",
        "i",
        "svg",
        "path",
        "circle",
        "rect",
        "polyline",
        "br",
    ]
)
_ALLOWED_ATTRS = frozenset(
    [
        "class",
        "id",
        "href",
        "lang",
        "charset",
        "http-equiv",
        "content",
        "name",
        "role",
        "aria-label",
        "aria-labelledby",
        "aria-hidden",
        "title",
        "scope",
        "colspan",
        "viewbox",
        "fill",
        "stroke",
        "stroke-width",
        "stroke-linecap",
        "stroke-linejoin",
        "focusable",
        "d",
        "points",
        "cx",
        "cy",
        "r",
        "width",
        "height",
        "rx",
        "x",
        "y",
    ]
)


class _StyleGrabber(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.in_style = False
        self.styles: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.in_style = tag == "style"

    def handle_endtag(self, tag: str) -> None:
        self.in_style = False

    def handle_data(self, data: str) -> None:
        if self.in_style:
            self.styles.append(data)


@pytest.mark.parametrize("key", ["html-en", "html-es"])
def test_html_hostile_values_are_inert_text(evil_outputs: dict[str, str], key: str) -> None:
    html = evil_outputs[key]
    parsed = parse_html(html)  # also asserts every tag is balanced
    for tag, attrs in parsed.tags:
        assert tag in _ALLOWED_TAGS, tag
        for name, value in attrs.items():
            assert name in _ALLOWED_ATTRS, (tag, name)
            assert not name.startswith("on")
            if name == "href":
                assert value is not None and re.fullmatch(r"#[A-Za-z0-9_-]+", value), value
            if name == "id":
                assert value is not None and re.fullmatch(r"[A-Za-z0-9_-]+", value), value
            if name == "class":
                assert value is not None and re.fullmatch(r"[a-z0-9_ -]+", value), value
    for needle in ("<script", "<img", "<iframe", "<!--", "-->", "]]>", "\x1b", "\x07", "\x00"):
        assert needle not in html, needle
    grabber = _StyleGrabber()
    grabber.feed(html)
    assert grabber.styles == [_CSS]  # data never reaches the stylesheet
    assert f'content="{CSP}"' in html
    text = " ".join(parsed.text)
    assert "<script>alert(1)</script>" in text  # shown to the reader, as text
    assert '"><img src=x onerror=1>' in text
    assert "‮" not in html and "\udcff" not in html
    html.encode("utf-8")  # no lone surrogates


def test_html_embedded_json_cannot_break_out(evil_outputs: dict[str, str]) -> None:
    html = evil_outputs["html-embed"]
    assert html.count("<script") == 1 and html.count("</script>") == 1
    match = re.search(r'<script type="application/json" id="hushwatch-data">(.*?)</script>', html, re.S)
    assert match is not None
    block = match.group(1)
    assert "<" not in block and ">" not in block and "&" not in block
    doc = json.loads(block)
    titles = [f["title"]["text"] for f in doc["findings"]]
    assert any("<script>alert(1)</script>" in t for t in titles)


def test_html_attribute_values_escaped() -> None:
    report = build_full_report()
    report.sections["coverage"]["matrix"][0]["log_sources"] = {'x" onload="alert(1)': "present"}
    html = render(report, "html")
    assert 'onload="alert(1)' not in html
    assert 'title="x&quot; onload=&quot;alert(1)"' in html
    parse_html(html)


# ---- console ------------------------------------------------------------------------------------------------------


@pytest.mark.parametrize("key", ["console-en", "console-es"])
def test_console_hostile_values_plain(evil_outputs: dict[str, str], key: str) -> None:
    out = evil_outputs[key]
    for char in ("\x1b", "\x07", "\x00", "\x9b", "‮"):
        assert char not in out, repr(char)
    assert "[bold red]x[/]" in out  # printed literally, never interpreted as markup
    assert "[link=http://x]y[/link]" in out


def test_console_hostile_values_with_colors(evil_report: Report) -> None:
    out = render_console(evil_report, color=True, width=100, verbose=True)
    assert "\x1b[2J" not in out and "\x07" not in out and "\x1b]8;" not in out
    assert "\x1b[" in out  # rich's own styling is still there
    for width in (40, 80, 200):
        render_console(evil_report, width=width)


def test_console_many_hostile(evil_report: Report) -> None:
    buffer = io.StringIO()
    print_console_many([evil_report, build_full_report()], console=Console(file=buffer, width=120, color_system=None))
    out = buffer.getvalue()
    assert "\x1b" not in out and "\x07" not in out
    assert "<script>al" in out  # the hostile tenant name is printed as plain text


# ---- Markdown -----------------------------------------------------------------------------------------------------


def _unescaped_pipes(line: str) -> int:
    return len(re.findall(r"(?<!\\)\|", line.replace("\\\\", "")))


@pytest.mark.parametrize("key", ["md-en", "md-es"])
def test_markdown_hostile_values_escaped(evil_outputs: dict[str, str], key: str) -> None:
    md = evil_outputs[key]
    for needle in ("<script", "<img", "<!--", "-->", "<http", "http://x", "\x1b", "\x07"):
        assert needle not in md, needle
    assert not re.search(r"(?<!\\)\]\(", md)  # no link/image syntax: every "](" has an escaped bracket
    assert "\\|pipe\\|" in md
    assert "!\\[img\\](http\\[:\\]//x)" in md
    assert "\\`code\\`" in md
    assert "\\$\\\\color{red}{fake}\\$" in md
    assert "&amp;lt;script&amp;gt;" in md  # entity text is displayed, never decoded into markup
    assert "\\[bold red\\]x\\[/\\]" in md
    # every table keeps its shape: the number of real cell separators is constant within a table
    block: list[str] = []
    for line in [*md.splitlines(), ""]:
        if line.startswith("|"):
            block.append(line)
            continue
        if block:
            counts = {_unescaped_pipes(row) for row in block}
            assert len(counts) == 1, (counts, block[:3])
            block = []
    # no data line starts a Markdown block (heading/quote/list) by itself
    for line in md.splitlines():
        if line.startswith("> ") and not line.startswith(("> [!", "> **", "> - ")):
            assert line.startswith("> ") and "quote" not in line


# ---- JSON ---------------------------------------------------------------------------------------------------------


def _walk(value: Any) -> Any:
    if isinstance(value, dict):
        for k, v in value.items():
            yield k
            yield from _walk(v)
    elif isinstance(value, list):
        for v in value:
            yield from _walk(v)
    else:
        yield value


@pytest.mark.parametrize("key", ["json-en", "json-es"])
def test_json_hostile_values_strict_and_clean(evil_outputs: dict[str, str], key: str) -> None:
    text = evil_outputs[key]
    doc = json.loads(text, parse_constant=lambda c: pytest.fail(f"non-standard JSON constant {c}"))
    control = re.compile("[\x00-\x08\x0b-\x1f\x7f-\x9f‪-‮⁦-⁩\ud800-\udfff]")
    for item in _walk(doc):
        if isinstance(item, str):
            assert not control.search(item), repr(item[:80])
            assert len(item) <= MAX_TEXT + 64, len(item)
        if isinstance(item, float):
            assert math.isfinite(item)
    assert doc["incomplete"] is True
    assert any(
        "more characters]" in f["title"]["text"] or "caracteres más]" in f["title"]["text"] for f in doc["findings"]
    )
    assert doc["tenant"] == "<script>alert(1)</script>"


# ---- size, time, encoding, robustness -----------------------------------------------------------------------------


def test_one_megabyte_values_are_bounded_in_size_and_time() -> None:
    report = build_evil_report()
    started = time.perf_counter()
    outputs = {fmt: render(report, fmt) for fmt in FORMATS}
    outputs["console"] = render_console(report, verbose=True)
    elapsed = time.perf_counter() - started
    assert elapsed < 60, elapsed
    for fmt, text in outputs.items():
        assert len(text) < 3_000_000, (fmt, len(text))
        assert BIG[: MAX_TEXT + 10] not in text, fmt


def test_redaction_of_adversarial_periodic_strings_is_fast() -> None:
    """``a.a.a.…`` makes Redactor.text super-linear; chunking + the cap keep a report fast."""
    nasty = "a." * 500_000
    report = build_full_report()
    report.findings[0].reasons.append(nasty)
    report.sections["noise"]["rules"][0]["description"] = nasty
    started = time.perf_counter()
    for fmt in FORMATS:
        render(report, fmt, redactor=Redactor(b"k" * 32))
    assert time.perf_counter() - started < 20


def test_outputs_always_encode_as_utf8(evil_outputs: dict[str, str]) -> None:
    for text in evil_outputs.values():
        text.encode("utf-8")


def test_redacted_hostile_report_renders_and_tokenizes(evil_report: Report) -> None:
    redactor = Redactor(b"k" * 32)
    for fmt in FORMATS:
        text = render(evil_report, fmt, redactor=redactor)
        assert redactor.token("<script>alert(1)</script>", "host") in text
        assert "../../etc/passwd" not in text  # an entity value (learned), so also redacted inside free text
    render_console(evil_report, redactor=redactor)


class _Boom:
    def __str__(self) -> str:
        raise RuntimeError("boom")


def test_mistyped_and_hostile_structures_never_crash() -> None:
    deep: dict[str, Any] = {}
    cursor = deep
    for _ in range(200):
        cursor["x"] = {}
        cursor = cursor["x"]
    finding = Finding(kind="pipeline.lag", domain="pipeline", title="t", severity=Severity.LOW, subject="s")
    finding.severity = "bogus"  # type: ignore[assignment]
    finding.confidence = None  # type: ignore[assignment]
    finding.reasons = "a single string"  # type: ignore[assignment]
    finding.score = "high"  # type: ignore[assignment]
    finding.evidence = {"deep": deep, "boom": _Boom(), "set": {3, 1, 2}, "nan": float("nan"), 7: "int key"}
    finding.recommendation = Message("x", {"p": _Boom(), "deep": deep})
    report = Report(
        tenant="t",
        generated_at=NOW,
        tool_version="0",
        data_basis=DataBasis(events="12", malformed=None, sources="not-a-list"),  # type: ignore[arg-type]
        findings=[finding],
        sections={"noise": "not a dict", "silence": {"sources": "nope", "status_counts": [1, 2]}},  # type: ignore[dict-item]
        assessment="nonsense",  # type: ignore[arg-type]
    )
    for fmt in FORMATS:
        text = render(report, fmt)
        assert "a single string" in text
    render_console(report, verbose=True)
    render_many([report, build_evil_report()], "html")


def test_fleet_hostile_all_formats(evil_report: Report) -> None:
    other = build_full_report()
    for fmt in FORMATS:
        text = render_many([evil_report, other], fmt, redactor={"acme": Redactor(b"k" * 32)})
        if fmt == "html":
            parsed = parse_html(text)
            assert all(tag in _ALLOWED_TAGS for tag, _ in parsed.tags)
            assert "<script" not in text
        if fmt == "md":
            assert "<script" not in text
        if fmt == "json":
            json.loads(text)


def test_print_console_default_console_writes_to_stdout(capsys: pytest.CaptureFixture[str]) -> None:
    print_console(build_evil_report())
    captured = capsys.readouterr().out
    assert "\x1b[2J" not in captured and "[bold red]x[/]" in captured
