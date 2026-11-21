"""Bộ chuyển đổi Snort 2 -> Snort 3 (nids/tools/snort2_convert.py) và các file rules/community-*.rules sinh ra từ nó."""
from pathlib import Path

import pytest

from nids.engine.detector import DetectionEngine
from nids.engine.rule_manager import RuleManager
from tools.rules import snort2_convert as conv
from test_diverse_rules_engine import make_http_packet

ROOT = Path(__file__).resolve().parents[3]
VARIABLES = {"HTTP_PORTS": "80", "HOME_NET": "any", "EXTERNAL_NET": "any"}


@pytest.fixture(scope="module")
def manager():
    return RuleManager("data/rules", variables=VARIABLES)


def convert(options: str, manager, header="alert tcp any any -> any 80"):
    return conv.convert_line(f"{header} ({options})", manager)[2]


def engine_for(rule: str, tmp_path):
    (tmp_path / "t.rules").write_text(rule + "\n", encoding="utf-8")
    rule_manager = RuleManager(str(tmp_path), variables=VARIABLES)
    assert rule_manager.load_all_rules() == 1
    return DetectionEngine(rule_manager, enable_threshold=False)


def test_content_modifiers_are_folded_into_the_content(manager):
    rule = convert('msg:"X"; flow:to_server,established; content:"abcd"; nocase; offset:2; depth:10; '
                   'fast_pattern:only; classtype:attempted-admin; sid:5; rev:3;', manager)
    assert 'content:"abcd",nocase,offset 2,depth 10,fast_pattern;' in rule
    assert "priority:1;" in rule and "sid:5; rev:3;" in rule


def test_http_buffer_modifier_becomes_a_sticky_buffer(manager, tmp_path):
    rule = convert('msg:"X"; flow:to_server,established; content:"/evil.php"; http_uri; '
                   'classtype:web-application-attack; sid:6; rev:1;', manager)
    assert 'http_uri; content:"/evil.php";' in rule and "service:http;" in rule
    engine = engine_for(rule, tmp_path)
    assert engine.evaluate_packet(make_http_packet(uri="/evil.php?a=1"))
    # chuỗi chỉ nằm trong body thì không phải URI nên không được bắn
    assert not engine.evaluate_packet(make_http_packet(uri="/ok", body="/evil.php"))


def test_cookie_and_header_modifiers(manager):
    cookie = convert('msg:"X"; content:"sid=1"; http_cookie; classtype:misc-activity; sid:7; rev:1;', manager)
    assert 'http_header:field cookie; content:"sid=1";' in cookie and "priority:3;" in cookie
    header = convert('msg:"X"; content:"curl"; nocase; http_header; sid:8; rev:1;', manager)
    assert 'http_header; content:"curl",nocase;' in header and "priority:3;" in header


def test_pcre_buffer_flags_move_into_sticky_buffer(manager, tmp_path):
    rule = convert('msg:"X"; flow:to_server,established; content:"id="; http_uri; pcre:"/id=\\d{3}/Ui"; '
                   'classtype:attempted-recon; sid:9; rev:1;', manager)
    assert 'pcre:"/id=\\d{3}/i";' in rule and rule.count("http_uri;") == 1
    engine = engine_for(rule, tmp_path)
    assert engine.evaluate_packet(make_http_packet(uri="/x?id=123"))
    assert not engine.evaluate_packet(make_http_packet(uri="/x", body="id=123"))


def test_unknown_classtype_and_missing_flow_get_defaults(manager):
    rule = convert('msg:"X"; content:"zzzz"; classtype:something-new; sid:10; rev:1;', manager)
    assert "priority:3;" in rule and "flow:" not in rule


@pytest.mark.parametrize("options, reason", [
    ('msg:"X"; content:"a"; byte_test:1,>,2,0; sid:11; rev:1;', "byte_test"),
    ('msg:"X"; content:"a"; http_uri; content:"b"; distance:0; sid:12; rev:1;', "distance/within"),
    ('msg:"X"; flags:S; sid:13; rev:1;', "không có content"),
    ('msg:"X"; content:"a"; pcre:"/b/R"; sid:14; rev:1;', "pcre R"),
    ('msg:"X"; content:"a"; sid:1000001; rev:1;', "dải rule tự viết"),
    ('msg:"X"; content:"a"; depth:size; sid:15; rev:1;', "biến"),
    ('msg:"X"; content:"a"; flowbits:set,x; sid:16; rev:1;', "flowbits"),
])
def test_unsupported_rules_are_skipped(manager, options, reason):
    with pytest.raises(conv.Skip) as info:
        convert(options, manager)
    assert reason in str(info.value)


def test_target_file_groups_by_message_prefix():
    assert conv.target_file("SERVER-WEBAPP foo") == "community-web"
    assert conv.target_file("MALWARE-CNC foo") == "community-malware"
    assert conv.target_file("SQL injection foo") == "community-server"
    assert conv.target_file("PROTOCOL-FTP foo") == "community-protocol"


def test_deny_sids_are_dropped(manager, tmp_path, monkeypatch):
    source = tmp_path / "src.rules"
    source.write_text('alert tcp any any -> any 80 (msg:"X"; content:"abcd"; sid:20; rev:1;)\n', encoding="utf-8")
    monkeypatch.setitem(conv.DENY_SIDS, 20, "thử nghiệm")
    result, skipped = conv.convert_file(source, manager)
    assert not any(result.values()) and skipped["nằm trong DENY_SIDS"] == 1


# ── FILE SINH RA TRONG REPO ──────────────────────────────────────────

def test_committed_community_files_match_the_converter():
    result, _ = conv.convert_file(ROOT / conv.DEFAULT_SOURCE, RuleManager("data/rules"))
    for name in conv.OUTPUT_FILES:
        committed = (ROOT / "data" / "rules" / f"{name}.rules").read_text(encoding="utf-8")
        assert committed == conv.render(name, result[name]), f"{name}.rules bị sửa tay, hãy sinh lại bằng bộ chuyển đổi"


def test_community_rules_load_clean_and_enabled():
    loaded = RuleManager("data/rules")
    loaded.load_all_rules()
    community = [r for r in loaded.all_rules() if r.category.startswith("community-")]
    assert len(community) >= 2000
    assert all(not r.unsupported_options for r in community)
    assert all(r.sid < conv.CUSTOM_SID_MIN for r in community)
    assert any(r.enabled for r in community)
