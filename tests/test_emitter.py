"""Tests for hushwatch.wazuh.emitter: safe Wazuh suppression rules from (hostile) suggestion values."""

from __future__ import annotations

import json
import os
import random
import re
import stat
import xml.etree.ElementTree as ET
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from hushwatch import __version__
from hushwatch.i18n import M, render
from hushwatch.tuning import Condition, Suggestion
from hushwatch.wazuh import emitter
from hushwatch.wazuh.audit import audit_ruleset
from hushwatch.wazuh.emitter import (
    MAX_PATTERN_CHARS,
    SAMPLES_FILE,
    SPEC_FILE,
    VALIDATION_FILE,
    XML_FILE,
    EmitError,
    emit_suppressions,
    pcre2_escape,
    pcre2_exact,
)
from hushwatch.wazuh.ruleset import Ruleset, load_ruleset, parse_rules_text

FIXTURES = Path(__file__).parent / "fixtures" / "wazuh"
NOW = date(2026, 9, 25)
EXPIRES = date(2026, 12, 24)
RANGE = (110000, 119999)


@pytest.fixture(scope="module")
def rs() -> Ruleset:
    return load_ruleset([FIXTURES / "ruleset" / "rules", FIXTURES / "etc" / "rules"])


def sug(rule_id: str = "5503", *conditions: tuple[str, str], **kwargs: Any) -> Suggestion:
    params: dict[str, Any] = {"verdict": "tune", "fingerprint": "fp0001", "expires": EXPIRES}
    params.update(kwargs)
    return Suggestion(rule_id=rule_id, conditions=tuple(Condition(f, v) for f, v in conditions), **params)


def emit(tmp_path: Path, suggestions: list[Suggestion], ruleset: Ruleset | None, **kwargs: Any) -> emitter.EmitResult:
    params: dict[str, Any] = {"ruleset": ruleset, "id_range": RANGE, "out_dir": tmp_path / "out", "now": NOW}
    params.update(kwargs)
    return emit_suppressions(suggestions, **params)


def rules_of(result: emitter.EmitResult) -> list[ET.Element]:
    tree = ET.fromstring(f"<root>{result.paths[0].read_text(encoding='utf-8')}</root>")
    groups = tree.findall("group")
    assert len(groups) == 1
    return groups[0].findall("rule")


def to_python(pattern: str) -> re.Pattern[bytes]:
    """PCRE2 (as we emit it) -> Python bytes regex: \\x{HH} becomes \\xHH and PCRE2's end-of-subject \\z is
    Python's \\Z (a close approximation; PCRE2 and Python agree that "$" also matches before a final newline)."""
    assert all(int(h, 16) <= 0xFF for h in re.findall(r"\\x\{([0-9a-fA-F]+)\}", pattern))
    translated = re.sub(rb"\\x\{([0-9a-f]{2})\}", rb"\\x\1", pattern.encode("ascii"))
    return re.compile(translated.replace(b"\\z", b"\\Z"))


def matches(pattern: str, value: str) -> bool:
    return to_python(pattern).search(value.encode("utf-8", "surrogatepass")) is not None


def collapse(value: str) -> str:
    return re.sub(r"\\+", r"\\", value)


# ---- golden output --------------------------------------------------------------------------------------------------


def golden_suggestions() -> list[Suggestion]:
    return [
        sug(
            "5710",
            ("agent.name", "srv-web-01.example"),
            ("data.srcip", "10.20.0.15"),
            fingerprint="0f1e2d3c4b5a69788796",
            examples=[
                {
                    "full_log": "Sep 25 10:15:31 srv-web-01 sshd[2211]: Invalid user admin from 10.20.0.15 port 51234",
                    "agent": {"id": "001", "name": "srv-web-01.example"},
                }
            ],
        ),
        sug(
            "60106",
            ("agent.name", "dc01"),
            ("data.win.eventdata.targetUserName", "svc_backup"),
            fingerprint="a1b2c3d4e5f607182930",
        ),
        sug(
            "5501",
            ("predecoder.hostname", "srv-backup-01.example"),
            ("data.dstuser", "svc_backup"),
            fingerprint="b2c3d4e5f60718293041",
        ),
        sug(
            "60106",
            ("location", "EventChannel"),
            ("data.win.eventdata.image", "C:\\\\Program Files\\\\Veeam\\\\agent.exe"),
            fingerprint="c3d4e5f6071829304152",
        ),
    ]


def test_golden_output(tmp_path: Path, rs: Ruleset) -> None:
    result = emit(tmp_path, golden_suggestions(), rs, id_range=(100000, 100999))
    expected = (FIXTURES / "golden" / "hushwatch_local_rules.xml").read_text(encoding="utf-8")
    assert result.paths[0].read_text(encoding="utf-8") == expected.replace("@VERSION@", __version__)
    assert result.rules == [
        (100000, "0f1e2d3c4b5a69788796"),
        (100004, "a1b2c3d4e5f607182930"),
        (100007, "b2c3d4e5f60718293041"),
        (100008, "c3d4e5f6071829304152"),
    ]
    assert result.review_required == [100000]
    assert [p.name for p in result.paths] == [XML_FILE, SPEC_FILE, VALIDATION_FILE, SAMPLES_FILE]


def test_output_is_deterministic(tmp_path: Path, rs: Ruleset) -> None:
    first = emit(tmp_path / "a", golden_suggestions(), rs)
    second = emit(tmp_path / "b", golden_suggestions(), rs)
    for left, right in zip(first.paths, second.paths, strict=True):
        assert left.read_bytes() == right.read_bytes()


def test_emitted_file_loads_cleanly_with_the_ruleset(tmp_path: Path, rs: Ruleset) -> None:
    result = emit(tmp_path, golden_suggestions(), rs, id_range=(100000, 100999))
    combined = load_ruleset([FIXTURES / "ruleset" / "rules", FIXTURES / "etc" / "rules", result.paths[0]])
    assert combined.errors == [] and len(combined.duplicates) == len(rs.duplicates)
    assert not [n for n in combined.notes if XML_FILE in n.file]
    for rule_id, _ in result.rules:
        rule = combined.get(rule_id)
        assert rule is not None and rule.is_local and rule.level == 3
    # The child copies 5710's groups (authentication_failed...), yet stock 60204 loaded before it and never counts
    # it; the parent keeps its correlation rules.
    assert combined.dependents(100000) == ()
    assert combined.dependents("5710") == ("5712", "60204")
    assert "100000" in combined.children("5710")
    audit = audit_ruleset(combined, tenant=_tenant(), now=NOW)
    flagged = {f.evidence.get("rule_id") for f in audit.findings if f.kind == "tuning.risky_suppression"}
    assert "100004" not in flagged and "100007" not in flagged and "100008" not in flagged  # level not lowered


def _tenant() -> Any:
    from hushwatch.config import TenantConfig

    return TenantConfig()


# ---- id allocation --------------------------------------------------------------------------------------------------


def test_id_allocation_skips_every_used_id(tmp_path: Path, rs: Ruleset) -> None:
    suggestions = [sug("5503", ("agent.name", f"srv-app-{i:02d}.example"), fingerprint=f"fp{i}") for i in range(12)]
    result = emit(tmp_path, suggestions, rs, id_range=(100000, 100999))
    ids = [rule_id for rule_id, _ in result.rules]
    assert len(ids) == len(set(ids)) == 12
    assert not set(ids) & rs.used_ids
    assert ids == sorted(ids)
    assert ids[:4] == [100000, 100004, 100007, 100008]


def test_id_allocation_avoids_salvaged_ids(tmp_path: Path) -> None:
    broken = load_ruleset([FIXTURES / "broken" / "unclosed_rules.xml", FIXTURES / "ruleset" / "rules"])
    result = emit(
        tmp_path,
        [sug("5503", ("agent.name", "a")), sug("5503", ("agent.name", "b"))],
        broken,
        id_range=(100400, 100410),
    )
    assert [i for i, _ in result.rules] == [100403, 100404]
    assert any(w.key == "wazuh.emit.warn.ruleset_errors" for w in result.warnings)


def test_id_range_exhausted(tmp_path: Path, rs: Ruleset) -> None:
    with pytest.raises(EmitError) as excinfo:
        emit(
            tmp_path,
            [sug("5503", ("agent.name", "a")), sug("5503", ("agent.name", "b"))],
            rs,
            id_range=(100010, 100013),
        )
    assert excinfo.value.message.key == "wazuh.emit.err.exhausted"
    assert not (tmp_path / "out").exists()


@pytest.mark.parametrize("bad_range", [(0, 5), (120000, 110000), (1, 1_000_000), (True, 5)])
def test_invalid_id_range(tmp_path: Path, rs: Ruleset, bad_range: tuple[int, int]) -> None:
    with pytest.raises(EmitError):
        emit(tmp_path, [sug("5503", ("agent.name", "a"))], rs, id_range=bad_range)


def test_range_outside_custom_range_warns(tmp_path: Path, rs: Ruleset) -> None:
    result = emit(tmp_path, [sug("5503", ("agent.name", "a"))], rs, id_range=(900000, 900010))
    assert any(w.key == "wazuh.emit.warn.range" for w in result.warnings)


def test_collision_is_refused_by_the_final_check(rs: Ruleset) -> None:
    plan = emitter._Plan(
        suggestion=sug("5503", ("agent.name", "a")),
        fingerprint="fp",
        parent="5503",
        expires=EXPIRES,
        elements=[],
        groups=("hushwatch_tuned",),
        dependents=[],
        review=False,
        parent_level=5,
        parent_rule=None,
        rule_id=100001,
    )
    with pytest.raises(EmitError) as excinfo:
        emitter._verify("<group name='local,hushwatch,'></group>", [plan], 3, rs.used_ids)
    assert excinfo.value.message.key == "wazuh.emit.err.collision"
    with pytest.raises(EmitError):
        emitter._verify("", [plan, plan], 3, set())


# ---- refusals -------------------------------------------------------------------------------------------------------


@pytest.mark.parametrize("profile", ["wazuh5", "ecs", "generic", ""])
def test_non_wazuh4_profiles_are_refused(tmp_path: Path, rs: Ruleset, profile: str) -> None:
    with pytest.raises(EmitError) as excinfo:
        emit(tmp_path, [sug("5503", ("agent.name", "a"))], rs, profile=profile)
    assert excinfo.value.message.key == "wazuh.emit.err.profile"
    assert not (tmp_path / "out").exists()


def test_wazuh5_suggestion_is_refused(tmp_path: Path, rs: Ruleset) -> None:
    with pytest.raises(EmitError):
        emit(tmp_path, [sug("5503", ("agent.name", "a"), profile="wazuh5")], rs)
    assert "Wazuh 4.x" in str(EmitError(M("wazuh.emit.err.profile", profile="wazuh5")))


def test_reparse_failure_writes_nothing(tmp_path: Path, rs: Ruleset, monkeypatch: pytest.MonkeyPatch) -> None:
    real_build = emitter._build_xml

    def broken(*args: Any) -> str:
        return real_build(*args).replace("</group>", "")

    monkeypatch.setattr(emitter, "_build_xml", broken)
    with pytest.raises(EmitError) as excinfo:
        emit(tmp_path, [sug("5503", ("agent.name", "a"))], rs)
    assert excinfo.value.message.key == "wazuh.emit.err.verify"
    assert not (tmp_path / "out").exists()


@pytest.mark.parametrize(
    ("needle", "replacement"),
    [
        ("</rule>", '</rule><rule id="100999" level="0"><if_sid>1</if_sid><description>x</description></rule>'),
        ('level="3"', 'level="0"'),
        ("<if_sid>5503</if_sid>", "<if_sid>1</if_sid>"),
        ("hushwatch_tuned,", "other,"),
        ("^\\x{28}a", "^\\x{28}.*a"),
        ("</description>", "$HOME</description>"),
        ("<!-- hushwatch", "<!-- -- hushwatch"),
        ("<!-- hushwatch", "<!-- !> hushwatch"),  # os_xml also closes a comment at "!>"
        ("<description>", "<description>\x01"),
        ("</description>", "\\</description>"),  # os_xml: a backslash turns the next "<" into content
        ("</location>", "$</location>"),  # "$" is never written (os_xml variables; trailing-newline match)
        ("</description>", "<![CDATA[x]]></description>"),
    ],
)
def test_tampered_output_is_refused(
    tmp_path: Path, rs: Ruleset, monkeypatch: pytest.MonkeyPatch, needle: str, replacement: str
) -> None:
    real_build = emitter._build_xml

    def tampered(*args: Any) -> str:
        text = real_build(*args)
        assert needle in text
        return text.replace(needle, replacement, 1)

    monkeypatch.setattr(emitter, "_build_xml", tampered)
    with pytest.raises(EmitError):
        emit(tmp_path, [sug("5503", ("agent.name", "a"))], rs)
    assert not (tmp_path / "out").exists()


@pytest.mark.parametrize("level", [-1, 17, True, 3.0])
def test_invalid_level(tmp_path: Path, rs: Ruleset, level: Any) -> None:
    with pytest.raises(EmitError):
        emit(tmp_path, [sug("5503", ("agent.name", "a"))], rs, level=level)


def test_level_zero_needs_explicit_flag_and_no_dependents(tmp_path: Path, rs: Ruleset) -> None:
    with pytest.raises(EmitError):
        emit(tmp_path, [sug("5502", ("agent.name", "a"))], rs, level=0)
    result = emit(
        tmp_path,
        [sug("5502", ("agent.name", "a"), fingerprint="ok"), sug("5503", ("agent.name", "a"), fingerprint="dep")],
        rs,
        level=0,
        allow_level_zero=True,
    )
    assert [fp for _, fp in result.rules] == ["ok"]
    assert [fp for fp, _ in result.skipped] == ["dep"]
    assert result.skipped[0][1].key == "wazuh.emit.skip.level_zero"
    assert any(w.key == "wazuh.emit.warn.level_zero" for w in result.warnings)
    assert rules_of(result)[0].get("level") == "0"


def test_nothing_emittable_writes_nothing(tmp_path: Path, rs: Ruleset) -> None:
    result = emit(tmp_path, [sug("5503", ("agent.id", "001")), sug("5503", verdict="investigate")], rs)
    assert result.paths == [] and result.rules == []
    assert result.warnings[-1].key == "wazuh.emit.warn.nothing"
    assert not (tmp_path / "out").exists()
    assert emit(tmp_path, [], rs).paths == []


# ---- files ----------------------------------------------------------------------------------------------------------


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions")
def test_file_and_directory_modes(tmp_path: Path, rs: Ruleset) -> None:
    old = os.umask(0)
    try:
        result = emit(tmp_path, [sug("5503", ("agent.name", "a"))], rs)
    finally:
        os.umask(old)
    assert stat.S_IMODE((tmp_path / "out").stat().st_mode) == 0o700
    for path in result.paths:
        assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_never_overwrites_without_flag(tmp_path: Path, rs: Ruleset) -> None:
    first = emit(tmp_path, [sug("5503", ("agent.name", "a"))], rs)
    before = first.paths[0].read_text()
    with pytest.raises(EmitError) as excinfo:
        emit(tmp_path, [sug("5503", ("agent.name", "b"))], rs)
    assert excinfo.value.message.key == "wazuh.emit.err.exists"
    assert first.paths[0].read_text() == before
    second = emit(tmp_path, [sug("5503", ("agent.name", "b"))], rs, overwrite=True)
    assert "\\x{28}b\\x{29}" in second.paths[0].read_text()
    if os.name == "posix":
        assert stat.S_IMODE(second.paths[0].stat().st_mode) == 0o600
    assert not list((tmp_path / "out").glob(".hushwatch-*"))


@pytest.mark.skipif(os.name != "posix", reason="symlinks")
def test_symlink_at_target_is_not_followed(tmp_path: Path, rs: Ruleset) -> None:
    out = tmp_path / "out"
    out.mkdir(mode=0o700)
    victim = tmp_path / "victim.txt"
    victim.write_text("precious")
    (out / XML_FILE).symlink_to(victim)
    with pytest.raises(EmitError):
        emit(tmp_path, [sug("5503", ("agent.name", "a"))], rs)
    emit(tmp_path, [sug("5503", ("agent.name", "a"))], rs, overwrite=True)
    assert victim.read_text() == "precious"
    assert not (out / XML_FILE).is_symlink()


def test_out_dir_that_is_a_file(tmp_path: Path, rs: Ruleset) -> None:
    (tmp_path / "out").write_text("x")
    with pytest.raises(EmitError) as excinfo:
        emit(tmp_path, [sug("5503", ("agent.name", "a"))], rs)
    assert excinfo.value.message.key == "wazuh.emit.err.out_dir"


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions")
def test_directory_writable_by_others_is_refused(tmp_path: Path, rs: Ruleset) -> None:
    # Anyone who can write there could swap the rules before an admin deploys them.
    out = tmp_path / "out"
    out.mkdir()
    out.chmod(0o777)
    with pytest.raises(EmitError) as excinfo:
        emit(tmp_path, [sug("5503", ("agent.name", "a"))], rs)
    assert excinfo.value.message.key == "wazuh.emit.err.out_dir_unsafe"
    assert list(out.iterdir()) == []


@pytest.mark.skipif(not hasattr(os, "geteuid") or os.geteuid() != 0, reason="needs root to chown")
def test_directory_owned_by_another_user_is_refused(tmp_path: Path, rs: Ruleset) -> None:
    out = tmp_path / "out"
    out.mkdir(mode=0o700)
    os.chown(out, 65534, 65534)
    with pytest.raises(EmitError) as excinfo:
        emit(tmp_path, [sug("5503", ("agent.name", "a"))], rs)
    assert excinfo.value.message.key == "wazuh.emit.err.out_dir_unsafe"


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions")
def test_shared_directory_warns(tmp_path: Path, rs: Ruleset) -> None:
    out = tmp_path / "out"
    out.mkdir()
    out.chmod(0o755)
    result = emit(tmp_path, [sug("5503", ("agent.name", "a"))], rs)
    assert any(w.key == "wazuh.emit.warn.dir_mode" for w in result.warnings)


# ---- condition mapping (§8 table) ----------------------------------------------------------------------------------


def only_condition(result: emitter.EmitResult) -> ET.Element:
    rule = rules_of(result)[0]
    conditions = [c for c in rule if c.tag not in ("if_sid", "description", "group")]
    assert len(conditions) == 1
    return conditions[0]


@pytest.mark.parametrize(
    ("field", "value", "tag", "attrs", "text"),
    [
        ("agent.name", "srv-web-01", "location", {"type": "pcre2"}, "^\\x{28}srv\\x{2d}web\\x{2d}01\\x{29}\\x{20}"),
        (
            "location",
            "/var/log/auth.log",
            "location",
            {"type": "pcre2"},
            "^(?:\\x{28}[^\\x{29}\\x{3e}]*\\x{29}\\x{20}[^\\x{20}\\x{3e}]*\\x{2d}\\x{3e})?"
            "\\x{2f}var\\x{2f}log\\x{2f}auth\\x{2e}log\\z",
        ),
        ("data.srcip", "10.0.0.5", "srcip", {}, "10.0.0.5"),
        ("data.dstip", "2001:DB8:0::1", "dstip", {}, "2001:db8::1"),
        ("data.srcuser", "alice", "user", {"type": "pcre2"}, "^alice\\z"),
        ("data.dstuser", "svc_backup", "user", {"type": "pcre2"}, "^svc_backup\\z"),
        (
            "data.win.system.channel",
            "Security",
            "field",
            {"name": "win.system.channel", "type": "pcre2"},
            "^Security\\z",
        ),
        (
            "data.aws.requestParameters.bucketName",
            "b1",
            "field",
            {"name": "aws.requestParameters.bucketName", "type": "pcre2"},
            "^b1\\z",
        ),
        (
            "data.win.eventdata.product Name",
            "x",
            "field",
            {"name": "win.eventdata.product Name", "type": "pcre2"},
            "^x\\z",
        ),
    ],
)
def test_condition_mapping(
    tmp_path: Path, rs: Ruleset, field: str, value: str, tag: str, attrs: dict[str, str], text: str
) -> None:
    result = emit(tmp_path, [sug("5503", (field, value))], rs)
    element = only_condition(result)
    assert (element.tag, element.attrib, element.text) == (tag, attrs, text)


def test_predecoder_hostname_only_covers_manager_side_events(tmp_path: Path, rs: Ruleset) -> None:
    # For agent events analysisd puts the AGENT name in <hostname> (cleanevent.c): a bare <hostname> would hide
    # every event of an agent that happens to carry that name (e.g. a syslog relay), which the backtest never saw.
    result = emit(tmp_path, [sug("5503", ("predecoder.hostname", "fw-01"))], rs)
    rule = rules_of(result)[0]
    location, hostname = rule.find("location"), rule.find("hostname")
    assert location is not None and hostname is not None
    assert (hostname.attrib, hostname.text) == ({"type": "pcre2"}, "^fw\\x{2d}01\\z")
    assert location.text == "^(?!\\x{28})"
    assert matches(location.text, "192.0.2.10") and matches(location.text, "/var/log/messages")
    assert not matches(location.text, "(fw-01) any->/var/log/messages")
    assert "predecoder.hostname=fw-01" in (rule.findtext("description") or "")
    with_path = emit(tmp_path / "b", [sug("5503", ("predecoder.hostname", "fw-01"), ("location", "/var/log/fw"))], rs)
    path_pattern = rules_of(with_path)[0].findtext("location") or ""
    assert matches(path_pattern, "/var/log/fw")
    for other in ("(fw-01) any->/var/log/fw", "/var/log/fw\n", "/var/log/fwx"):
        assert not matches(path_pattern, other), other
    pair = emit(tmp_path / "c", [sug("5503", ("predecoder.hostname", "fw-01"), ("agent.name", "relay01"))], rs)
    assert pair.rules == [] and pair.skipped[0][1].key == "wazuh.emit.skip.host_pair"


def test_agent_and_location_merge_into_one_location(tmp_path: Path, rs: Ruleset) -> None:
    result = emit(tmp_path, [sug("5503", ("agent.name", "web01"), ("location", "/var/log/secure"))], rs)
    element = only_condition(result)
    assert element.tag == "location"
    pattern = element.text or ""
    assert matches(pattern, "(web01) any->/var/log/secure")
    assert matches(pattern, "(web01) 192.0.2.20->/var/log/secure")
    for other in (
        "(web01) any->/var/log/secure.1",
        "(web02) any->/var/log/secure",
        "(web011) any->/var/log/secure",
        "(web01) any->x/var/log/secure",
        "/var/log/secure",
        "(web01) any->/var/log/secure/x",
        "(web01) any->/var/log/secure\n",
        "web01->/var/log/secure",
    ):
        assert not matches(pattern, other), other


def test_location_path_matches_agent_and_manager_forms_exactly(tmp_path: Path, rs: Ruleset) -> None:
    pattern = only_condition(emit(tmp_path, [sug("5503", ("location", "/var/log/auth.log"))], rs)).text or ""
    for good in ("/var/log/auth.log", "(srv-web-01) any->/var/log/auth.log", "(a) 10.0.0.1->/var/log/auth.log"):
        assert matches(pattern, good)
    for bad in (
        "/var/log/auth.log.1",
        "x/var/log/auth.log",
        "(a) any->/var/log/auth.logx",
        "(a) any->x->/var/log/auth.log",
        "host->/var/log/auth.log",
        "/var/log/authxlog",
        "/var/log/auth.log\n",
        "(a) any->/var/log/auth.log\n",
        "(a>b) any->/var/log/auth.log",  # the alert JSON would say "location": "b) any->/var/log/auth.log"
    ):
        assert not matches(pattern, bad), bad


@pytest.mark.parametrize(
    "field",
    [
        "agent.id",
        "agent.ip",
        "agent.labels.team",
        "rule.level",
        "rule.id",
        "manager.name",
        "cluster.node",
        "decoder.name",
        "predecoder.program_name",
        "syscheck.path",
        "full_log",
        "location.extra",
        "id",
        "timestamp",
        "data.srcport",
        "data.dstport",
        "data.url",
        "data.id",
        "data.status",
        "data.protocol",
        "data.action",
        "data.system_name",
        "data.extra_data",
        "data.data",
        "data.SRCIP",
        "data.user",
        "data.",
        "data.a..b",
        'data.x"y',
        "data.x$y",
        "data.x,y",
        "data.<x>",
        "data." + "a" * 200,
    ],
)
def test_unmappable_fields_skip_the_whole_suggestion(tmp_path: Path, rs: Ruleset, field: str) -> None:
    result = emit(tmp_path, [sug("5503", ("agent.name", "web01"), (field, "v"))], rs)
    assert result.rules == [] and result.paths == []
    assert result.skipped[0][1].key in (
        "wazuh.emit.skip.field",
        "wazuh.emit.skip.static_field",
        "wazuh.emit.skip.field_name",
    )


@pytest.mark.parametrize(
    "value",
    ["10.0.0.5/24", "999.1.1.1", "10.0.0.5 ", " 10.0.0.5", "fe80::1%eth0", "not-an-ip", "010.000.000.001", "any", ""],
)
def test_srcip_must_be_a_single_ip(tmp_path: Path, rs: Ruleset, value: str) -> None:
    result = emit(tmp_path, [sug("5503", ("data.srcip", value))], rs)
    assert result.rules == []
    assert result.skipped[0][1].key in ("wazuh.emit.skip.ip", "wazuh.emit.skip.value")


def test_conflicting_duplicate_and_combined_user_conditions(tmp_path: Path, rs: Ruleset) -> None:
    result = emit(
        tmp_path,
        [
            sug("5503", ("data.srcip", "10.0.0.1"), ("data.srcip", "10.0.0.2"), fingerprint="conflict"),
            sug("5503", ("data.srcuser", "a"), ("data.dstuser", "a"), fingerprint="users"),
            sug("5503", ("data.srcip", "10.0.0.3"), ("data.srcip", "10.0.0.3"), fingerprint="same"),
        ],
        rs,
    )
    assert {fp: m.key for fp, m in result.skipped} == {
        "conflict": "wazuh.emit.skip.conflict",
        "users": "wazuh.emit.skip.users",
    }
    assert [fp for _, fp in result.rules] == ["same"]
    assert [e.tag for e in rules_of(result)[0]].count("srcip") == 1


def test_non_string_values_are_refused(tmp_path: Path, rs: Ruleset) -> None:
    bad = Suggestion("5503", (Condition("data.srcuser", 5),), "tune", "fp", EXPIRES)  # type: ignore[arg-type]
    result = emit(tmp_path, [bad], rs)
    assert result.skipped[0][1].key == "wazuh.emit.skip.value"


def test_rule_wide_needs_explicit_flag(tmp_path: Path, rs: Ruleset) -> None:
    result = emit(tmp_path, [sug("5502")], rs)
    assert result.skipped[0][1].key == "wazuh.emit.skip.rule_wide"
    allowed = emit(tmp_path / "b", [sug("5502")], rs, allow_rule_wide=True)
    rule = rules_of(allowed)[0]
    assert [c.tag for c in rule] == ["if_sid", "description", "group"]
    assert "for all events" in (rule.findtext("description") or "")


@pytest.mark.parametrize(
    ("suggestion", "key"),
    [
        (sug("5503", ("agent.name", "a"), verdict="investigate"), "wazuh.emit.skip.verdict"),
        (sug("5503", ("agent.name", "a"), profile="ecs"), "wazuh.emit.skip.profile"),
        (sug("rule-uuid-1", ("agent.name", "a")), "wazuh.emit.skip.rule_id"),
        (sug("1234567", ("agent.name", "a")), "wazuh.emit.skip.rule_id"),
        (sug("0", ("agent.name", "a")), "wazuh.emit.skip.rule_id"),
        (sug("5503", ("agent.name", "a"), expires=date(2026, 9, 24)), "wazuh.emit.skip.expires"),
        (sug("5503", ("agent.name", "a"), expires="2027-01-01"), "wazuh.emit.skip.expires"),
        (sug("424242", ("agent.name", "a")), "wazuh.emit.skip.parent_missing"),
        (sug("1002", ("agent.name", "a")), "wazuh.emit.skip.raises"),
    ],
)
def test_skipped_suggestions(tmp_path: Path, rs: Ruleset, suggestion: Suggestion, key: str) -> None:
    result = emit(tmp_path, [suggestion], rs)
    assert result.rules == []
    assert result.skipped[0][1].key == key


def test_parent_unverified_when_only_local_rules_are_loaded(tmp_path: Path) -> None:
    local_only = load_ruleset([FIXTURES / "etc" / "rules"])
    result = emit(tmp_path, [sug("424242", ("agent.name", "a"), rule_groups=("sshd",))], local_only)
    assert len(result.rules) == 1 and result.review_required == [result.rules[0][0]]
    assert any(w.key == "wazuh.emit.warn.parent_unverified" for w in result.warnings)


def test_no_ruleset_forces_review_and_uses_suggestion_metadata(tmp_path: Path) -> None:
    result = emit(
        tmp_path,
        [
            sug(
                "5710",
                ("agent.name", "a"),
                rule_groups=("syslog", "sshd", "bad group!"),
                rule_level=5,
                dependents=("5712",),
            )
        ],
        None,
    )
    assert result.review_required == [result.rules[0][0]]
    keys = [w.key for w in result.warnings]
    assert "wazuh.emit.warn.no_ruleset" in keys and "wazuh.emit.warn.group_dropped" in keys
    assert rules_of(result)[0].findtext("group") == "syslog,sshd,hushwatch_tuned,"
    spec = json.loads(result.paths[1].read_text())
    assert spec["suppressions"][0]["dependents"] == [
        {"rule": "5712", "via": "reported", "correlation_preserved": False}
    ]


def test_unknown_groups_force_review(tmp_path: Path) -> None:
    result = emit(tmp_path, [sug("5710", ("agent.name", "a"))], None)
    assert any(w.key == "wazuh.emit.warn.groups_unknown" for w in result.warnings)
    assert rules_of(result)[0].findtext("group") == "hushwatch_tuned,"


def test_correlation_dependents_follow_analysisd_semantics(tmp_path: Path, rs: Ruleset) -> None:
    result = emit(tmp_path, [sug("5503", ("agent.name", "a"))], rs)
    rule = rules_of(result)[0]
    assert rule.findtext("group") == "pam,syslog,authentication_failed,hushwatch_tuned,"
    spec = json.loads(result.paths[1].read_text())
    dependents = spec["suppressions"][0]["dependents"]
    # 5557 (frequency, if_sid 5503, level 10) is tried before the level-3 child and counts every recent event.
    assert {"rule": "5557", "via": "frequency_if_sid", "correlation_preserved": True} in dependents
    # 60204 wired its if_matched_group list when IT loaded (0580-...xml), before hushwatch_local_rules.xml: the
    # copied groups do NOT make it count the child (OS_MarkGroup only visits rules already loaded).
    assert {"rule": "60204", "via": "if_matched_group", "correlation_preserved": False} in dependents
    validation = result.paths[2].read_text()
    assert "5557" in validation and "60204" in validation and "REVIEW REQUIRED" in validation
    assert "60204 (if_matched_group) will NOT count" in validation


def test_group_correlation_is_kept_only_by_rules_loaded_after_the_output(tmp_path: Path) -> None:
    stock = parse_rules_text(
        '<group name="app,"><rule id="1000" level="5"><description>p</description><group>login_failed,</group>'
        "</rule></group>",
        file="/var/ossec/ruleset/rules/0500-app_rules.xml",
        is_local=False,
    )
    correlation = (
        '<group name="c,"><rule id="{id}" level="10" frequency="5"><if_matched_group>login_failed</if_matched_group>'
        "<description>c</description></rule></group>"
    )
    parse_rules_text(correlation.format(id=100001), file="/var/ossec/etc/rules/0600-corr.xml", into=stock)
    parse_rules_text(correlation.format(id=100002), file="/var/ossec/etc/rules/local_rules.xml", into=stock)
    result = emit(tmp_path, [sug("1000", ("agent.name", "a"))], stock)
    dependents = json.loads(result.paths[1].read_text())["suppressions"][0]["dependents"]
    assert dependents == [
        {"rule": "100001", "via": "if_matched_group", "correlation_preserved": False},
        {"rule": "100002", "via": "if_matched_group", "correlation_preserved": True},
    ]
    dropped = emit(tmp_path / "zero", [sug("1000", ("agent.name", "a"))], stock, level=0, allow_level_zero=True)
    assert dropped.skipped[0][1].key == "wazuh.emit.skip.level_zero"


def test_frequency_rule_tried_after_the_child_is_broken(tmp_path: Path) -> None:
    text = (
        '<group name="app,"><rule id="1000" level="5"><description>p</description></rule>'
        '<rule id="1001" level="2" frequency="5"><if_sid>1000</if_sid><description>low freq</description></rule>'
        "</group>"
    )
    ruleset = parse_rules_text(text, file="/var/ossec/ruleset/rules/0500-app_rules.xml", is_local=False)
    result = emit(tmp_path, [sug("1000", ("agent.name", "a"))], ruleset)
    dependents = json.loads(result.paths[1].read_text())["suppressions"][0]["dependents"]
    assert dependents == [{"rule": "1001", "via": "frequency_if_sid", "correlation_preserved": False}]


def test_siblings_tried_after_the_child_are_reported(tmp_path: Path) -> None:
    # analysisd tries children by descending level: the level-3 child wins over a level-2 grouping sibling, and
    # the level-12 detection below that sibling never fires for the demoted events.
    text = (
        '<group name="app,"><rule id="1000" level="5"><description>p</description></rule>'
        '<rule id="1001" level="2"><if_sid>1000</if_sid><match>admin</match><description>g</description></rule>'
        '<rule id="1002" level="12"><if_sid>1001</if_sid><match>root</match><description>d</description></rule>'
        '<rule id="1003" level="8"><if_sid>1000</if_sid><match>x</match><description>h</description></rule>'
        "</group>"
    )
    ruleset = parse_rules_text(text, file="/var/ossec/ruleset/rules/0500-app_rules.xml", is_local=False)
    result = emit(tmp_path, [sug("1000", ("agent.name", "a"))], ruleset)
    assert result.review_required == [result.rules[0][0]]
    entry = json.loads(result.paths[1].read_text())["suppressions"][0]
    assert entry["preempted_rules"] == [{"rule": "1002", "level": 12}]  # 1003 (level 8) is tried first
    validation = result.paths[2].read_text()
    assert "Rule 1002 (level 12)" in validation and "La regla 1002 (nivel 12)" in validation
    dropped = emit(tmp_path / "zero", [sug("1000", ("agent.name", "a"))], ruleset, level=0, allow_level_zero=True)
    assert dropped.skipped[0][1].key == "wazuh.emit.skip.level_zero"
    assert dropped.skipped[0][1].params["dependents"] == "1002, 1003, 1001"


def test_parent_defined_in_a_file_loading_after_the_output(tmp_path: Path, rs: Ruleset) -> None:
    result = emit(tmp_path, [sug("100200", ("agent.name", "a"))], rs)  # zz_more_local.xml loads after us
    assert result.review_required == [result.rules[0][0]]
    assert any(w.key == "wazuh.emit.warn.parent_after" for w in result.warnings)
    entry = json.loads(result.paths[1].read_text())["suppressions"][0]
    assert entry["parent_loads_after_this_file"] is True
    assert "add this rule to that file" in result.paths[2].read_text()


def test_group_list_longer_than_analysisd_accepts_is_refused(tmp_path: Path) -> None:
    # analysisd concatenates the <group name> attribute and every <group> element with loadmemory(), which
    # refuses to append once the list holds more than 2048 bytes: splitting into several elements does not help.
    groups = tuple(f"compliance_group_number_{i:03d}" for i in range(120))
    result = emit(tmp_path, [sug("5503", ("agent.name", "a"), rule_groups=groups)], None)
    assert result.rules == [] and result.skipped[0][1].key == "wazuh.emit.skip.groups_too_long"
    fitting = groups[:60]
    ok = emit(tmp_path / "b", [sug("5503", ("agent.name", "a"), rule_groups=fitting)], None)
    elements = rules_of(ok)[0].findall("group")
    assert len(elements) == 1 and elements[0].text == "".join(f"{g}," for g in fitting) + "hushwatch_tuned,"
    assert len("local,hushwatch," + (elements[0].text or "")) <= emitter.MAX_GROUP_STRING


def test_duplicate_suggestions_are_emitted_once(tmp_path: Path, rs: Ruleset) -> None:
    result = emit(
        tmp_path,
        [sug("5503", ("agent.name", "a"), fingerprint="one"), sug("5503", ("agent.name", "a"), fingerprint="two")],
        rs,
    )
    assert [fp for _, fp in result.rules] == ["one"]
    assert result.skipped[0][1].key == "wazuh.emit.skip.duplicate"


def test_unsafe_fingerprint_is_replaced(tmp_path: Path, rs: Ruleset) -> None:
    result = emit(tmp_path, [sug("5503", ("agent.name", "a"), fingerprint="x -- <!-- $y")], rs)
    fingerprint = result.rules[0][1]
    assert re.fullmatch(r"h[0-9a-f]{19}", fingerprint)
    assert any(w.key == "wazuh.emit.warn.fingerprint" for w in result.warnings)


def test_datetime_inputs_are_normalized(tmp_path: Path, rs: Ruleset) -> None:
    result = emit(
        tmp_path,
        [sug("5503", ("agent.name", "a"), expires=datetime(2026, 12, 24, 23, 0, tzinfo=timezone.utc))],
        rs,
        now=datetime(2026, 9, 25, 10, 0, tzinfo=timezone.utc),
    )
    assert "expires 2026-12-24)" in (rules_of(result)[0].findtext("description") or "")


# ---- descriptions, comments, samples, spec, checklist -------------------------------------------------------------


def test_description_and_comments(tmp_path: Path, rs: Ruleset) -> None:
    hostile = "</description><rule id='1'>" + "é" * 50 + "$(win.eventdata.image) --> ]]>"
    result = emit(tmp_path, [sug("5503", ("data.srcuser", hostile), fingerprint="fp-a1")], rs)
    text = result.paths[0].read_text(encoding="utf-8")
    description = rules_of(result)[0].findtext("description") or ""
    assert description.startswith("hushwatch: demote 5503 for data.srcuser=")
    assert "(fp:fp-a1, expires 2026-12-24) REVIEW REQUIRED" in description
    assert len(description) <= 400
    assert re.fullmatch(r"[A-Za-z0-9_ .:/@\\\-=,()?]*", description), description
    comments = re.findall(r"<!--(.*?)-->", text, re.DOTALL)
    assert comments[2:] == [" hushwatch fingerprint=fp-a1 created=2026-09-25 expires=2026-12-24 review_required=yes "]
    for comment in comments:
        assert "--" not in comment and "rule id" not in comment and "win.eventdata" not in comment


def test_long_values_are_truncated_in_the_description(tmp_path: Path, rs: Ruleset) -> None:
    value = "a" * 300
    result = emit(tmp_path, [sug("5503", ("data.srcuser", value), ("agent.name", "b" * 250))], rs)
    description = rules_of(result)[0].findtext("description") or ""
    assert len(description) <= 400 and "..." in description and "expires 2026-12-24" in description
    user = rules_of(result)[0].find("user")
    assert user is not None and user.text == f"^{value}\\z"


def test_logtest_samples_and_validation_mapping(tmp_path: Path, rs: Ruleset) -> None:
    examples = [
        {"full_log": "Sep 25 10:00:01 srv-app-01 sshd[1]: pam_unix(sshd:auth): authentication failure; user=alice"},
        {"full_log": "line with\nnewline"},
        {"full_log": "ansi \x1b[2J clear"},
        {"full_log": "bidi \u202e spoof"},
        {"full_log": ""},
        {"full_log": 42},
        "not a mapping",
        {"full_log": "Sep 25 10:00:01 srv-app-01 sshd[1]: pam_unix(sshd:auth): authentication failure; user=alice"},
        {"full_log": "Sep 25 10:00:02 srv-app-01 sshd[2]: second"},
    ]
    result = emit(
        tmp_path,
        [
            sug("5503", ("agent.name", "a"), fingerprint="fp1", examples=examples),
            sug("5503", ("agent.name", "b"), fingerprint="fp2"),
            sug("5503", ("agent.name", "c"), fingerprint="fp3", examples=[{"full_log": "third sample"}]),
        ],
        rs,
    )
    samples = result.paths[3].read_text(encoding="utf-8").splitlines()
    assert samples == [
        "Sep 25 10:00:01 srv-app-01 sshd[1]: pam_unix(sshd:auth): authentication failure; user=alice",
        "Sep 25 10:00:02 srv-app-01 sshd[2]: second",
        "third sample",
    ]
    validation = result.paths[2].read_text(encoding="utf-8")
    assert "lines 1-2" in validation and "line 3" in validation and "líneas 1-2" in validation


def test_validation_checklist_is_bilingual_and_complete(tmp_path: Path, rs: Ruleset) -> None:
    result = emit(tmp_path, golden_suggestions(), rs)
    text = result.paths[2].read_text(encoding="utf-8")
    for needle in (
        "## English",
        "## Español",
        "/var/ossec/bin/wazuh-analysisd -t",
        "/var/ossec/bin/wazuh-logtest",
        "tar -czpf",
        "systemctl restart wazuh-manager",
        f"rm /var/ossec/etc/rules/{XML_FILE}",
        "Rollback",
        "Marcha atrás",
        "REVIEW REQUIRED",
        "REVISIÓN OBLIGATORIA",
        "5712",
    ):
        assert needle in text, needle
    assert "svc_backup" not in text and "10.20.0.15" not in text  # values live in the XML/JSON only


def test_spec_json(tmp_path: Path, rs: Ruleset) -> None:
    suggestion = sug(
        "5710",
        ("data.srcip", "10.20.0.15"),
        hidden_total=120,
        hidden_per_day=float("nan"),
        hidden_analyst_facing=7,
        share_of_rule=float("inf"),
        reasons=["plain reason"],
    )
    result = emit(tmp_path, [suggestion, sug("5503", ("agent.id", "1"), fingerprint="skipme")], rs)
    spec = json.loads(result.paths[1].read_text(encoding="ascii"))
    assert spec["schema_version"] == "1" and spec["profile"] == "wazuh4" and spec["level"] == 3
    entry = spec["suppressions"][0]
    assert entry["id"] == result.rules[0][0] and entry["parent_rule"] == "5710" and entry["verdict"] == "tune"
    assert entry["conditions"] == [{"field": "data.srcip", "value": "10.20.0.15"}]
    assert entry["wazuh"] == [{"tag": "srcip", "attributes": {}, "value": "10.20.0.15"}]
    assert entry["backtest"] == {
        "hidden_total": 120,
        "hidden_per_day": None,
        "hidden_analyst_facing": 7,
        "share_of_rule": None,
    }
    assert entry["review_required"] is True and entry["expires"] == "2026-12-24"
    assert entry["parent"]["level"] == 5 and "invalid_login" in entry["parent"]["groups"]
    assert entry["reasons"] == ["plain reason"]
    assert spec["skipped"][0]["fingerprint"] == "skipme" and spec["skipped"][0]["reason"]["es"]
    assert set(spec["notice"]) == {"en", "es"}


def test_example_based_warnings(tmp_path: Path, rs: Ruleset) -> None:
    result = emit(
        tmp_path,
        [
            sug("5503", ("agent.name", "wazuh-manager"), fingerprint="m", examples=[{"agent": {"id": "000"}}]),
            sug("5503", ("predecoder.hostname", "fw01"), fingerprint="h", examples=[{"agent.id": "001"}]),
            sug(
                "5503",
                ("data.srcuser", "alice"),
                fingerprint="u",
                examples=[{"data": {"srcuser": "alice", "dstuser": "bob"}}],
            ),
        ],
        rs,
    )
    keys = [w.key for w in result.warnings]
    assert {"wazuh.emit.warn.manager_agent", "wazuh.emit.warn.hostname_agent", "wazuh.emit.warn.user_semantics"} <= set(
        keys
    )


def test_warnings_render_in_both_languages(tmp_path: Path, rs: Ruleset) -> None:
    result = emit(tmp_path, [sug("5503", ("agent.id", "1")), sug("5501", ("agent.name", "a"))], rs)
    assert result.warnings
    for warning in result.warnings:
        english, spanish = render(warning, "en"), render(warning, "es")
        assert english != spanish and "{" not in english and "{" not in spanish


# ---- escaping -----------------------------------------------------------------------------------------------------

HOSTILE = [
    '</field></rule><rule id="100999" level="0"><if_sid>1</if_sid>',
    '</user></rule><rule id="100999" level="0">',
    "]]>",
    "<![CDATA[x]]>",
    "-->",
    "<!-- x -->",
    "&",
    "&amp;",
    "&lt;script&gt;",
    '"',
    "'",
    "\"'`",
    ".*",
    "|",
    "a|b",
    "()[]{}^$\\",
    "^admin$",
    "(?i)admin",
    "\\Q.*\\E",
    "a\nb",
    "trailing\r\n",
    "nul\x00byte",
    "\x01\x02\x1b[2J",
    "\x7f\x85\u2028",
    "right\u202eleft",
    "caf\u00e9",
    "\u65e5\u672c\u8a9e",
    "emoji \U0001f600",
    "surrogate \ud800",
    "$SCANNER_NET",
    "$(win.eventdata.image)",
    "%s%n%x",
    "${jndi:ldap://x}",
    "../../etc/passwd",
    "\\\\server\\share\\x",
    "C:\\Windows\\System32\\cmd.exe",
    " leading space",
    "trailing space ",
    "admin",
    "administrator",
    "Admin",
    "x" * 300,
    "\\" * 50,
    "-" * 40,
    "x" * 10_000,
]
TARGETS = [
    ("data.srcuser", "user"),
    ("data.win.eventdata.commandLine", "field"),
    ("predecoder.hostname", "hostname"),
    ("location", "location"),
    ("agent.name", "location"),
]


def _subjects(field: str, value: str) -> list[str]:
    if field == "agent.name":
        return [f"({value}) any->/var/log/auth.log"]
    if field == "location":
        return [value, f"(web01) any->{value}"]
    return [value]


def test_injection_fuzz(tmp_path: Path, rs: Ruleset) -> None:
    suggestions = []
    for t_index, (field, _) in enumerate(TARGETS):
        for v_index, value in enumerate(HOSTILE):
            suggestions.append(sug("5501", (field, value), fingerprint=f"f{t_index}v{v_index}"))
    result = emit(tmp_path, suggestions, rs)
    text = result.paths[0].read_text(encoding="utf-8")

    # 1. Well-formed XML with exactly the intended rules, all children of 5501, at level 3.
    elements = rules_of(result)
    emitted = {fp for _, fp in result.rules}
    skipped = {fp: message.key for fp, message in result.skipped}
    assert len(elements) == len(result.rules) == len(emitted)
    assert emitted | set(skipped) == {s.fingerprint for s in suggestions}
    assert set(skipped.values()) == {"wazuh.emit.skip.too_long"}
    assert {fp for fp in skipped} == {f"f{t}v{len(HOSTILE) - 1}" for t in range(len(TARGETS))}
    assert [int(e.get("id", "0")) for e in elements] == [rule_id for rule_id, _ in result.rules]
    assert all(e.findtext("if_sid") == "5501" and e.get("level") == "3" for e in elements)
    assert "100999" not in {e.get("id") for e in elements}
    by_fp = {s.fingerprint: s for s in suggestions}
    tags = dict(TARGETS)
    for (_, fp), element in zip(result.rules, elements, strict=True):
        field = by_fp[fp].conditions[0].field
        middle = ["location", "hostname"] if field == "predecoder.hostname" else [tags[field]]
        assert [c.tag for c in element] == ["if_sid", *middle, "description", "group"]

    # 2. Nothing but ASCII and escapes outside comments; no entity, no stray '$', no CDATA.
    body = re.sub(r"<!--.*?-->", "", text, flags=re.DOTALL)
    assert all(32 <= ord(ch) < 127 or ch == "\n" for ch in body)
    assert "&" not in body and "<![CDATA[" not in body
    assert all(body.startswith("</", m.end()) for m in re.finditer(r"\$", body))

    # 3. The Wazuh-aware parser agrees, with no repair needed.
    parsed = parse_rules_text(text)
    assert parsed.errors == [] and parsed.notes == [] and len(parsed.all_rules) == len(elements)

    # 4. Each pattern matches exactly its own value and nothing else from the corpus.
    for (_, fp), element in zip(result.rules, elements, strict=True):
        suggestion = by_fp[fp]
        field, value = suggestion.conditions[0].field, suggestion.conditions[0].value
        condition = element.find(tags[field])
        assert condition is not None
        pattern = condition.text or ""
        assert len(pattern) <= MAX_PATTERN_CHARS
        for subject in _subjects(field, value):
            assert matches(pattern, subject), (field, value)
        for other in HOSTILE:
            if collapse(other) == collapse(value):
                continue
            for subject in _subjects(field, other):
                assert not matches(pattern, subject), (field, value, other)
        if field != "agent.name":
            for subject in _subjects(field, value):
                # PCRE2's "$" would also accept a trailing newline: the patterns end with \z instead.
                assert not matches(pattern, subject + "\n") and not matches(pattern, subject + "\r\n")
                assert not matches(pattern, "\n" + subject)
            if "\\" not in value[-1:]:
                assert not matches(pattern, value + "x") and not matches(pattern, "x" + value)
        if len(value) > 1 and collapse(value[:-1]) != collapse(value):
            assert not matches(pattern, value[:-1])
        if value.swapcase() != value and collapse(value.swapcase()) != collapse(value):
            assert not any(matches(pattern, subject) for subject in _subjects(field, value.swapcase()))


def test_pcre2_escape_random_strings_roundtrip() -> None:
    rng = random.Random(1337)
    alphabet = "aZ09_ .*+?|()[]{}^$\\/<>&\"'-:;,\t\n\r\x00\x7f\u00e9\u00df\u4e2d\U0001f600"
    allowed = re.compile(r"^[A-Za-z0-9_\\{}()?:+^$x]*$")
    for _ in range(500):
        value = "".join(rng.choice(alphabet) for _ in range(rng.randint(1, 40)))
        pattern = pcre2_exact(value)
        assert allowed.match(pattern), pattern
        assert matches(pattern, value)
        mutated = value + rng.choice(["a", ".", "\\", "\n", "\r\n"])
        if collapse(mutated) != collapse(value):
            assert not matches(pattern, mutated)
        assert not matches(pattern, "\n" + value)
    assert pcre2_escape("") == ""
    assert pcre2_escape("abc_XYZ_019") == "abc_XYZ_019"
    assert pcre2_escape("\u00e9") == "\\x{c3}\\x{a9}"
    assert pcre2_escape("\U0001f600") == "\\x{f0}\\x{9f}\\x{98}\\x{80}"


def test_windows_backslash_doubling(tmp_path: Path, rs: Ruleset) -> None:
    doubled = "C:\\\\Windows\\\\System32\\\\svchost.exe"  # how eventchannel values arrive
    single = "C:\\Windows\\System32\\svchost.exe"
    result = emit(tmp_path, [sug("60106", ("data.win.eventdata.image", doubled))], rs)
    pattern = only_condition(result).text or ""
    assert pattern == "^C\\x{3a}(?:\\x{5c})+Windows(?:\\x{5c})+System32(?:\\x{5c})+svchost\\x{2e}exe\\z"
    assert matches(pattern, doubled) and matches(pattern, single)
    for other in (
        "C:\\Windows\\System32\\svchost.exe.bak",
        "D:\\Windows\\System32\\svchost.exe",
        "C:\\Windows\\SysWOW64\\svchost.exe",
        "C:/Windows/System32/svchost.exe",
        "C:WindowsSystem32svchost.exe",
        "C:\\Windows\\System32\\evil\\svchost.exe",
    ):
        assert not matches(pattern, other), other
    assert pcre2_escape("a\\\\\\b") == "a(?:\\x{5c})+b"


def test_self_test_rejects_patterns_that_overmatch() -> None:
    element = emitter._Element("user", {"type": "pcre2"}, "^adm", ("data.srcuser",), ("adm",))
    assert emitter._self_test(element) == "pattern matches more than its value"
    element = emitter._Element("user", {"type": "pcre2"}, "^xyz$", ("data.srcuser",), ("abc",))
    assert emitter._self_test(element) == "pattern does not match its own value"
    element = emitter._Element("user", {"type": "pcre2"}, "^(abc$", ("data.srcuser",), ("abc",))
    assert emitter._self_test(element) == "pattern does not compile"


def test_one_shot_iterables_and_odd_metadata(tmp_path: Path, rs: Ruleset) -> None:
    generator = (s for s in [sug("5503", ("agent.name", "a"), rule_description=float("nan"), rule_mitre=("T1110",))])
    result = emit_suppressions(generator, ruleset=None, id_range=RANGE, out_dir=tmp_path / "out", now=NOW)  # type: ignore[arg-type]
    assert len(result.rules) == 1
    spec = json.loads(result.paths[1].read_text())
    assert spec["suppressions"][0]["parent"]["description"] == "nan"
    assert spec["suppressions"][0]["parent"]["mitre"] == ["T1110"]
