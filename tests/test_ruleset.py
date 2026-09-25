"""Tests for hushwatch.wazuh.ruleset: parsing synthetic Wazuh rule files and the correlation graph."""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from hushwatch.i18n import Entity, render
from hushwatch.wazuh import ruleset as ruleset_module
from hushwatch.wazuh.ruleset import (
    RuleCondition,
    Ruleset,
    is_static_field,
    load_ruleset,
    osmatch,
    parse_rules_text,
)

FIXTURES = Path(__file__).parent / "fixtures" / "wazuh"
BROKEN = FIXTURES / "broken"


@pytest.fixture(scope="module")
def rs() -> Ruleset:
    return load_ruleset([FIXTURES])


def _element(rs: Ruleset, rule_id: str, file_part: str) -> ruleset_module.WazuhRule:
    matches = [r for r in rs.all_rules if r.id == rule_id and file_part in r.file]
    assert len(matches) == 1, matches
    return matches[0]


# ---- loading the synthetic ruleset --------------------------------------------------------------------------------


def test_fixture_ruleset_loads_without_errors(rs: Ruleset) -> None:
    assert rs.errors == []
    names = [Path(f).name for f in rs.files]
    assert names == [
        "0010-hw_rules_config.xml",
        "0085-hw_pam_rules.xml",
        "0095-hw_sshd_rules.xml",
        "0580-hw_win_security_rules.xml",
        "local_rules.xml",
        "zz_more_local.xml",
    ]
    assert [Path(f).name for f in rs.local_files] == ["local_rules.xml", "zz_more_local.xml"]
    assert {"5700", "5710", "5712", "60204", "100001", "100200"} <= set(rs.rules)
    assert all(not r.is_local for r in rs.all_rules if "ruleset" in r.file)
    assert all(r.is_local for r in rs.all_rules if "etc" in Path(r.file).parts)


def test_stock_files_load_before_local_even_if_given_later() -> None:
    reversed_rs = load_ruleset([FIXTURES / "etc" / "rules", FIXTURES / "ruleset" / "rules"])
    assert Path(reversed_rs.files[0]).name.startswith("0010")
    effective = reversed_rs.get("5712")
    assert effective is not None and effective.original is not None  # the overwrite still applies


def test_variables_are_substituted_in_attributes_and_text(rs: Ruleset) -> None:
    stock_5712 = _element(rs, "5712", "0095")
    assert stock_5712.frequency == 8 and stock_5712.attributes["frequency"] == "8"
    assert rs.get("60204").frequency == 8  # type: ignore[union-attr]
    assert rs.get("1002").conditions[0].text == "segfault|panic|out of memory|i/o error"  # type: ignore[union-attr]
    local_scanner = rs.get("100003")
    assert local_scanner is not None
    assert local_scanner.conditions == [RuleCondition("srcip", {}, "10.20.0.0/24")]


def test_entities_and_char_refs(rs: Ruleset) -> None:
    assert "&" in (rs.get("5710").description or "")  # type: ignore[union-attr]
    assert "Attempt burst" in (_element(rs, "5712", "0095").description or "")
    assert rs.get("5716").conditions[0].text == "^Failed password|^error: PAM: Authentication failure"  # type: ignore[union-attr]


def test_cdata_is_read_but_reported_as_an_error() -> None:
    # os_xml (Wazuh's XML parser) treats "<!" as a comment start that only "-->" or "!>" closes: CDATA breaks
    # the file for analysisd even though it is valid XML.
    rs = load_ruleset([BROKEN / "cdata_rules.xml"])
    assert [e.message.key for e in rs.errors] == ["wazuh.err.cdata"]
    assert rs.get("100600").conditions[1].text == "^Failed <password>"  # type: ignore[union-attr]


def test_unterminated_comment_is_an_error() -> None:
    text = '<group name="g,"><rule id="1" level="3"><description>x</description></rule></group>\n<!-- never closed'
    rs = parse_rules_text(text)
    assert [e.message.key for e in rs.errors] == ["wazuh.err.comment"]
    assert rs.get("1") is not None


def test_bom_file_parses_strictly(rs: Ruleset) -> None:
    assert (FIXTURES / "ruleset" / "rules" / "0095-hw_sshd_rules.xml").read_bytes().startswith(b"\xef\xbb\xbf")
    assert not [n for n in rs.notes if "0095" in n.file]
    assert rs.get("5700") is not None


def test_rule_fields(rs: Ruleset) -> None:
    rule = rs.get("5710")
    assert rule is not None
    assert rule.level == 5
    assert rule.groups == ("syslog", "sshd", "authentication_failed", "invalid_login", "pci_dss_10.2.4")
    assert rule.if_sid == ["5700"]
    assert rule.mitre == ("T1110.001", "T1021.004")
    assert rule.conditions == [RuleCondition("match", {}, "illegal user|invalid user")]
    assert rule.line is not None and rule.line > 1
    assert rs.get("5760").if_sid == ["5700", "5716"]  # type: ignore[union-attr]
    assert rs.get("5700").noalert is True  # type: ignore[union-attr]
    stock_5712 = _element(rs, "5712", "0095")
    assert stock_5712.if_matched_sid == ["5710"]
    assert stock_5712.timeframe == 120 and stock_5712.ignore == 60
    assert stock_5712.correlation == ("same_source_ip",)
    assert stock_5712.is_correlation
    assert rs.get("60204").correlation == ("same_field:win.eventdata.ipAddress",)  # type: ignore[union-attr]
    assert rs.get("60001").options == ("no_full_log",)  # type: ignore[union-attr]
    field = rs.get("60001").conditions[0]  # type: ignore[union-attr]
    assert field.tag == "field" and field.attrs == {"name": "win.system.channel"} and field.text == "^Security$"


# ---- correlation graph ------------------------------------------------------------------------------------------


def test_dependents_frequency_rule_on_base_rule(rs: Ruleset) -> None:
    assert rs.dependents("5710") == ("5712", "60204")
    assert rs.dependents_detail("5710") == (("5712", "if_matched_sid"), ("60204", "if_matched_group"))
    assert rs.dependents("5716") == ("5720", "60204")


def test_dependents_via_frequency_if_sid_and_groups(rs: Ruleset) -> None:
    assert ("5557", "frequency_if_sid") in rs.dependents_detail("5503")
    assert rs.dependents("60122") == ("60204",)  # if_matched_group authentication_failed
    assert rs.dependents("60106") == ()  # authentication_success feeds nothing
    assert rs.dependents("999999") == ()


def test_dependents_accepts_int_and_padded_ids(rs: Ruleset) -> None:
    assert rs.dependents(5710) == rs.dependents("05710") == rs.dependents("5710")
    assert rs.get(5710) is rs.get(" 5710 ")


def test_dependents_exclude_self() -> None:
    text = """<group name="x,"><rule id="100" level="5" frequency="3"><if_matched_group>x</if_matched_group>
    <description>self</description></rule></group>"""
    assert parse_rules_text(text).dependents("100") == ()


def test_children(rs: Ruleset) -> None:
    assert rs.children("5700") == ("5710", "5715", "5716", "5760")
    assert rs.children("5710") == ("5712", "100001", "100003")  # if_matched_sid without if_sid is a child
    assert set(rs.children("5715")) >= {"100030", "100050"}  # if_group authentication_success
    assert rs.children("424242") == ()


def test_files_load_in_analysisd_order_by_basename(tmp_path: Path) -> None:
    # rules-config.c sorts every rule file of every rule_dir together by FILE NAME.
    stock = tmp_path / "ruleset" / "rules"
    local = tmp_path / "etc" / "rules"
    stock.mkdir(parents=True)
    local.mkdir(parents=True)
    (stock / "0100-a_rules.xml").write_text(
        '<group name="g,"><rule id="1" level="3"><description>x</description></rule></group>'
    )
    correlation = (
        '<group name="c,"><rule id="{id}" level="10" frequency="4"><if_matched_group>g</if_matched_group>'
        "<description>c</description></rule></group>"
    )
    (local / "0050-custom_rules.xml").write_text(correlation.format(id=100000))
    (local / "local_rules.xml").write_text(correlation.format(id=100001))
    rs = load_ruleset([tmp_path])
    assert [Path(f).name for f in rs.files] == ["0050-custom_rules.xml", "0100-a_rules.xml", "local_rules.xml"]
    assert rs.dependents("1") == ("100001",)  # 100000 loaded before rule 1: its group list never sees it
    assert rs.position("100000") == 0 and rs.position("1") == 1 and rs.position("424242") is None


def test_links_need_the_target_loaded_first() -> None:
    text = """
    <group name="g,">
      <rule id="10" level="10" frequency="4"><if_sid>20</if_sid><description>freq before its parent</description></rule>
      <rule id="20" level="3"><description>parent</description></rule>
      <rule id="30" level="10" frequency="4"><if_sid>20</if_sid><description>freq after</description></rule>
      <rule id="40" level="3"><if_group>g</if_group><description>child by group</description></rule>
    </group>"""
    rs = parse_rules_text(text)
    assert rs.dependents("20") == ("30",)
    assert rs.children("20") == ("30", "40")
    assert rs.children("40") == ()  # 40 does not attach to itself nor to rules loaded after it


def test_evaluation_order_and_descendants() -> None:
    text = """
    <group name="p,">
      <rule id="1" level="5"><description>parent</description></rule>
      <rule id="2" level="10"><if_sid>1</if_sid><description>higher sibling</description></rule>
      <rule id="3" level="2"><if_sid>1</if_sid><description>lower sibling</description></rule>
      <rule id="4" level="12"><if_sid>3</if_sid><description>grandchild</description></rule>
      <rule id="5" level="0"><if_sid>1</if_sid><description>ignore rule</description></rule>
      <rule id="6" level="3"><if_sid>1</if_sid><description>the demote</description></rule>
      <rule id="7" level="3"><if_sid>1</if_sid><description>same level, later</description></rule>
      <rule id="8" level="3" accuracy="0"><if_sid>1</if_sid><description>no x100</description></rule>
    </group>"""
    rs = parse_rules_text(text)
    demote = rs.get("6")
    assert demote is not None
    assert rs.evaluated_after("1", demote) == ("3", "7", "8")
    assert rs.descendants("1") == ("2", "3", "4", "5", "6", "7", "8")
    assert rs.descendants("3") == ("4",)
    level_zero = rs.get("5")
    assert level_zero is not None and rs.evaluated_after("1", level_zero) == ("2", "3", "6", "7", "8")


def test_used_ids(rs: Ruleset) -> None:
    ids = rs.used_ids
    assert {5700, 5710, 5712, 100001, 100012, 100200} <= ids
    assert all(isinstance(i, int) for i in ids)


# ---- overwrite and duplicates ----------------------------------------------------------------------------------


def test_overwrite_merges_like_analysisd(rs: Ruleset) -> None:
    effective = rs.get("5712")
    assert effective is not None
    assert effective.level == 6 and effective.frequency == 30 and effective.ignore == 600
    assert effective.is_local and effective.overwrite
    assert effective.original is not None and effective.original.level == 10
    assert effective.if_matched_sid == ["5710"]
    assert [(a.level, b.level) for a, b in rs.overwrites] == [(10, 6)]


def test_overwrite_never_replaces_if_links() -> None:
    text = """
    <group name="a,"><rule id="10" level="3"><if_sid>1</if_sid><description>orig</description></rule></group>
    <group name="b,"><rule id="10" level="1" overwrite="yes"><if_sid>2</if_sid>
      <description>new</description></rule></group>
    """
    rs = parse_rules_text(text)
    rule = rs.get("10")
    assert rule is not None and rule.if_sid == ["1"] and rule.level == 1 and rule.groups == ("b",)


def test_overwrite_of_missing_rule_is_added_with_note() -> None:
    rs = parse_rules_text(
        '<group name="a,"><rule id="7" level="3" overwrite="yes"><description>x</description></rule></group>'
    )
    assert rs.get("7") is not None
    assert any(n.message.key == "wazuh.note.overwrite_missing" for n in rs.notes)


def test_duplicate_ids_first_wins(rs: Ruleset) -> None:
    assert len(rs.duplicates) == 1
    rule_id, kept, skipped = rs.duplicates[0]
    assert rule_id == "100012" and kept.endswith("local_rules.xml") and skipped.endswith("zz_more_local.xml")
    assert rs.get("100012").level == 0  # type: ignore[union-attr]
    assert len([r for r in rs.all_rules if r.id == "100012"]) == 2


# ---- tolerance of broken input -----------------------------------------------------------------------------------


def test_lenient_file_is_repaired() -> None:
    rs = load_ruleset([BROKEN / "lenient_rules.xml"])
    assert rs.errors == []
    assert sorted(rs.rules) == ["31100", "31101", "31102"]
    assert [n.message.key for n in rs.notes] == ["wazuh.note.repaired"]
    assert rs.get("31102").conditions[0].text == r"\.(?:jpg|png)$|<\w+>"  # type: ignore[union-attr]
    assert rs.get("31100").description == "Synthetic: access log messages grouped & tagged."  # type: ignore[union-attr]


def test_unparseable_block_is_isolated_and_its_ids_reserved() -> None:
    rs = load_ruleset([BROKEN / "unclosed_rules.xml"])
    assert sorted(rs.rules) == ["100400", "100402"]
    assert len(rs.errors) == 1 and rs.errors[0].line == 13 and rs.errors[0].message.key == "wazuh.err.xml"
    assert rs.salvaged_ids == {100401}
    assert 100401 in rs.used_ids


def test_semantic_errors_are_recorded_not_raised() -> None:
    rs = load_ruleset([BROKEN / "bad_semantics.xml"])
    keys = [e.message.key for e in rs.errors]
    for key in (
        "wazuh.err.level",
        "wazuh.err.attribute",
        "wazuh.err.field_static",
        "wazuh.err.options_value",
        "wazuh.err.ip",
        "wazuh.err.option",
        "wazuh.err.rule_id",
        "wazuh.err.attr_value",
        "wazuh.err.sid_list",
        "wazuh.err.empty_group",
        "wazuh.err.root_element",
    ):
        assert key in keys, key
    assert all(not r.valid for r in rs.all_rules)
    assert "abc" not in rs.rules
    assert rs.get("100303").options == ("no_log", "no_email_alert")  # type: ignore[union-attr]
    level_error = next(e for e in rs.errors if e.message.key == "wazuh.err.level")
    assert level_error.rule_id == "100300" and level_error.line == 3
    assert "100300" in str(level_error)


def test_doctype_and_entities_are_never_expanded() -> None:
    rs = load_ruleset([BROKEN / "doctype_rules.xml"])
    rule = rs.get("100500")
    assert rule is not None
    assert rule.description == "Synthetic entity bomb: &lol4; &ext;"
    assert any(e.message.key == "wazuh.err.dtd" for e in rs.errors)


def test_inline_entity_bomb_is_not_expanded() -> None:
    text = '<!DOCTYPE x [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">]>' + (
        '<group name="g,"><rule id="1" level="3"><description>&b;&b;&b;</description></rule></group>'
    )
    rule = parse_rules_text(text).get("1")
    assert rule is not None and rule.description == "&b;&b;&b;"


def test_missing_path_and_empty_directory_are_errors(tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    rs = load_ruleset([tmp_path / "nope", empty])
    assert [e.message.key for e in rs.errors] == ["wazuh.err.not_found", "wazuh.err.no_files"]
    assert isinstance(rs.errors[0].message.params["file"], Entity)
    assert rs.rules == {}


def test_single_string_path_is_accepted() -> None:
    rs = load_ruleset(str(FIXTURES / "ruleset" / "rules" / "0085-hw_pam_rules.xml"))
    assert "5501" in rs.rules


def test_same_file_twice_is_loaded_once() -> None:
    path = FIXTURES / "ruleset" / "rules" / "0085-hw_pam_rules.xml"
    rs = load_ruleset([path, path, path.parent])
    assert rs.duplicates == []
    assert len([f for f in rs.files if f.endswith("0085-hw_pam_rules.xml")]) == 1


def test_file_too_large_is_skipped(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "local_rules.xml"
    path.write_text('<group name="g,"><rule id="5" level="3"><description>x</description></rule></group>')
    monkeypatch.setattr(ruleset_module, "MAX_FILE_BYTES", 10)
    rs = load_ruleset([path])
    assert [e.message.key for e in rs.errors] == ["wazuh.err.too_large"]


def test_invalid_utf8_and_utf16(tmp_path: Path) -> None:
    body = '<group name="g,"><rule id="5" level="3"><description>café</description></rule></group>'
    latin = tmp_path / "latin_local.xml"
    latin.write_bytes(body.encode("latin-1"))
    utf16 = tmp_path / "utf16_local.xml"
    utf16.write_bytes(body.replace('"5"', '"6"').encode("utf-16"))
    rs = load_ruleset([latin, utf16])
    assert rs.get("5") is not None and rs.get("6") is not None
    assert rs.get("6").description == "café"  # type: ignore[union-attr]
    assert any(n.message.key == "wazuh.note.encoding" for n in rs.notes)


@pytest.mark.parametrize(
    "text",
    [
        "<!DOCTYPE " + "[]" * 60,  # was exponential (catastrophic backtracking): hours for 120 bytes
        "<!DOCTYPE x [" + "<!ENTITY a 'b'>" * 20000,
        "<group name='a'>" * 40000,  # unclosed blocks: each used to rescan the rest of the file
        "<!--" * 100000,
        "<group name='a'>" + "<rule " * 40000,
        "<![CDATA[" * 60000,
        "<var name='x'>1</var>\n" * 30000 + "<group>",  # many blocks, each used to be re-prefixed with newlines
    ],
)
def test_pathological_files_parse_in_linear_time(text: str) -> None:
    started = time.perf_counter()
    rs = parse_rules_text(text, file="hostile.xml")
    assert time.perf_counter() - started < 10
    assert rs.errors  # recorded, never raised


def test_block_fallback_keeps_line_numbers() -> None:
    text = "<var name='v'>1</var>\n" * 3 + "<group name='g,'>\n<rule id='1' level='3'>\n</group>\n<group>"
    rs = parse_rules_text(text)
    assert [e.line for e in rs.errors if e.message.key == "wazuh.err.xml"] == [6]


def test_deeply_nested_input_does_not_crash() -> None:
    nested = '<group name="a,">' * 30 + '<rule id="9" level="3"><description>x</description></rule>' + "</group>" * 30
    rs = parse_rules_text(nested)
    assert any(e.message.key == "wazuh.err.too_deep" for e in rs.errors)
    deep = '<group name="a,"><rule id="1" level="3">' + "<x>" * 20000 + "</x>" * 20000 + "</rule></group>"
    rs2 = parse_rules_text(deep)
    assert rs2.get("1") is not None and not rs2.get("1").valid  # type: ignore[union-attr]


def test_nested_groups_inherit_names() -> None:
    text = (
        '<group name="outer,"><group name="inner,"><rule id="3" level="3"><description>x</description></rule>'
        "</group></group>"
    )
    rs = parse_rules_text(text)
    assert rs.get("3").groups == ("outer", "inner")  # type: ignore[union-attr]
    assert any(n.message.key == "wazuh.note.nested_group" for n in rs.notes)


def test_variables_are_case_insensitive_and_file_scoped(tmp_path: Path) -> None:
    (tmp_path / "a_local.xml").write_text(
        '<var name="Freq">5</var><group name="g,"><rule id="11" level="9" frequency="$FREQ">'
        "<if_matched_sid>1</if_matched_sid><description>x</description></rule></group>"
    )
    (tmp_path / "b_local.xml").write_text(
        '<group name="g,"><rule id="12" level="9" frequency="$FREQ"><if_matched_sid>1</if_matched_sid>'
        "<description>x</description></rule></group>"
    )
    rs = load_ruleset([tmp_path])
    assert rs.get("11").frequency == 5  # type: ignore[union-attr]
    assert rs.get("12").frequency is None  # type: ignore[union-attr]  # not defined in that file
    assert any(e.rule_id == "12" and e.message.key == "wazuh.err.attr_value" for e in rs.errors)
    assert rs.get("12").is_correlation  # type: ignore[union-attr]


def test_xml_declaration_and_case_insensitive_tags() -> None:
    text = (
        '<?xml version="1.0" encoding="UTF-8"?>\n<GROUP name="g,"><Rule ID="21" Level="4"><If_Sid>5</If_Sid>'
        "<Description>d</Description></Rule></GROUP>"
    )
    rule = parse_rules_text(text).get("21")
    assert rule is not None and rule.level == 4 and rule.if_sid == ["5"] and rule.description == "d"


def test_line_numbers_survive_repairs() -> None:
    text = "<!-- a -- b\n\n -->\n<group name='g,'>\n<rule id='1' level='3'><match>a & b</match></rule></group>"
    rule = parse_rules_text(text).get("1")
    assert rule is not None and rule.line == 5


def test_layout_of_a_wazuh_install(tmp_path: Path) -> None:
    (tmp_path / "ruleset" / "rules").mkdir(parents=True)
    (tmp_path / "etc" / "rules").mkdir(parents=True)
    (tmp_path / "ruleset" / "rules" / "0001-x_rules.xml").write_text(
        '<group name="g,"><rule id="1" level="3"><description>x</description></rule></group>'
    )
    (tmp_path / "etc" / "rules" / "local_rules.xml").write_text(
        '<group name="g,"><rule id="100000" level="0"><if_sid>1</if_sid><description>x</description></rule></group>'
    )
    rs = load_ruleset([tmp_path])
    assert [r.id for r in rs.all_rules] == ["1", "100000"]
    assert [r.is_local for r in rs.all_rules] == [False, True]


@pytest.mark.parametrize(
    ("relative", "expected"),
    [
        ("var/ossec/ruleset/rules/0095-sshd_rules.xml", False),
        ("var/ossec/etc/rules/local_rules.xml", True),
        ("var/ossec/etc/rules/0100-custom_rules.xml", True),
        ("somewhere/local_rules.xml", True),
        ("somewhere/0095-sshd_rules.xml", False),
        ("somewhere/custom.xml", True),
        ("somewhere/hushwatch_local_rules.xml", True),
    ],
)
def test_local_classification(tmp_path: Path, relative: str, expected: bool) -> None:
    path = tmp_path / relative
    path.parent.mkdir(parents=True)
    path.write_text('<group name="g,"><rule id="1" level="3"><description>x</description></rule></group>')
    assert load_ruleset([path]).all_rules[0].is_local is expected


def test_local_paths_override(tmp_path: Path) -> None:
    path = tmp_path / "0095-sshd_rules.xml"
    path.write_text('<group name="g,"><rule id="1" level="3"><description>x</description></rule></group>')
    assert load_ruleset([path], local_paths=[path]).all_rules[0].is_local is True


# ---- helpers --------------------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("pattern", "text", "expected"),
    [
        ("authentication_failed", "syslog,sshd,authentication_failed,", True),
        ("authentication_failed", "syslog,authentication_failures,", False),
        ("AUTHENTICATION_FAILED", "authentication_failed,", True),
        ("^syslog", "syslog,sshd,", True),
        ("^sshd", "syslog,sshd,", False),
        ("sshd,$", "syslog,sshd,", True),
        ("web|sshd", "syslog,sshd,", True),
        ("!sshd", "syslog,sshd,", False),
        ("", "anything", False),
    ],
)
def test_osmatch(pattern: str, text: str, expected: bool) -> None:
    assert osmatch(pattern, text) is expected


def test_static_fields() -> None:
    assert is_static_field("srcip") and is_static_field(" DstUser ")
    assert not is_static_field("win.eventdata.srcip")


def test_error_messages_render_in_both_languages() -> None:
    rs = load_ruleset([BROKEN / "bad_semantics.xml"])
    for error in rs.errors:
        english = render(error.message, "en")
        spanish = render(error.message, "es")
        assert english and spanish and english != spanish
        assert "{" not in english and "{" not in spanish


def test_parse_performance_large_ruleset() -> None:
    parts = ['<var name="F">8</var>']
    for block in range(60):
        rules = []
        for i in range(100):
            rid = 200000 + block * 100 + i
            parent = rid - 1 if i else 1
            rules.append(
                f'<rule id="{rid}" level="{i % 12}"><if_sid>{parent}</if_sid><match>pattern {rid}</match>'
                f"<description>rule {rid}</description><group>g{block},</group></rule>"
            )
            if i % 10 == 0:
                rules.append(
                    f'<rule id="{rid + 500000}" level="10" frequency="$F"><if_matched_group>g{block}</if_matched_group>'
                    f"<description>corr</description></rule>"
                )
        parts.append(f'<group name="perf{block},">' + "".join(rules) + "</group>")
    text = "\n".join(parts)
    started = time.perf_counter()
    rs = parse_rules_text(text, is_local=False)
    for rule_key in list(rs.rules)[:2000]:
        rs.dependents(rule_key)
    elapsed = time.perf_counter() - started
    assert len(rs.rules) == 6600
    # 700100 is defined BEFORE 200105: analysisd wires correlation lists when the correlation rule loads, so a
    # rule loaded later never feeds it.
    assert rs.dependents("200105") == (
        "700110",
        "700120",
        "700130",
        "700140",
        "700150",
        "700160",
        "700170",
        "700180",
        "700190",
    )
    assert elapsed < 10


def test_text_with_lone_surrogates_is_parsed() -> None:
    rule = parse_rules_text(
        '<group name="g,"><rule id="4" level="3"><description>a\ud800b</description></rule></group>'
    ).get("4")
    assert rule is not None and rule.description == "a�b"
