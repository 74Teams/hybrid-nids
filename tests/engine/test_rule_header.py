import logging
import re
from pathlib import Path

import pytest
from scapy.all import Ether, IP, Raw, TCP

import nids.engine.decoder as decoder
from nids import config
from nids.engine.decoder import PacketDecoder
from nids.engine.detector import DetectionEngine
from nids.engine.packet import DecodedPacket
from nids.engine.rule_header import (ANY_ADDRS, ANY_PORTS, DEFAULT_RULE_VARIABLES, http_ports, parse_addrs,
                                     parse_ports)
from nids.engine.rule_manager import RuleManager

ROOT = Path(__file__).resolve().parents[2]
VARS = dict(DEFAULT_RULE_VARIABLES)


def ports(text, **overrides):
    return parse_ports(text, {**VARS, **overrides})


def addrs(text, **overrides):
    return parse_addrs(text, {**VARS, **overrides})


# ── CỔNG (#17) ───────────────────────────────────────────────────────

@pytest.mark.parametrize("spec, yes, no", [
    ("any", [0, 80, 65535], []),
    ("80", [80], [79, 81, 8080]),
    ("1:1024", [1, 80, 1024], [0, 1025]),
    (":1024", [0, 80, 1024], [1025]),
    ("1024:", [1024, 65535], [80, 1023]),
    ("[80,443]", [80, 443], [81, 8080]),
    ("[80,443,8000:8080]", [80, 443, 8000, 8080, 8043], [8081, 7999]),
    ("!80", [79, 81, 443], [80]),
    ("![80,443]", [81, 8080], [80, 443]),
    ("[1:1024,!80]", [1, 443, 1024], [80, 1025]),
    ("[[80,81],[443]]", [80, 81, 443], [82]),
    ("[80, 443]", [80, 443], [81]),
])
def test_port_forms(spec, yes, no):
    parsed = ports(spec)
    assert all(parsed.matches(p) for p in yes), spec
    assert not any(parsed.matches(p) for p in no), spec


def test_in_operator_works_like_a_set():
    http = ports("$HTTP_PORTS")
    assert 80 in http and 443 not in http and None not in http


def test_icmp_without_port_matches_only_any():
    assert ports("any").matches(None)
    assert not ports("80").matches(None)
    assert not ports("!80").matches(None)
    assert not ports("1:1024").matches(None)


@pytest.mark.parametrize("bad", ["[80", "80]", "[]", "[80,]", "[,80]", "99999", "-1", "abc", "5:1", "1:2:3", "!", "",
                                 "[80]x", "!any", "![any]", "$NOPE"])
def test_bad_port_forms_raise(bad):
    with pytest.raises(ValueError):
        ports(bad)


# ── IP (#18) ─────────────────────────────────────────────────────────

@pytest.mark.parametrize("spec, yes, no", [
    ("any", ["1.2.3.4", "::1"], []),
    ("10.0.0.1", ["10.0.0.1"], ["10.0.0.2"]),
    ("10.0.0.0/8", ["10.0.0.1", "10.255.255.255"], ["11.0.0.1", "192.168.1.1"]),
    ("192.168.1.1/24", ["192.168.1.77"], ["192.168.2.1"]),  # chấp nhận host bit
    ("[10.0.0.0/8,192.168.1.1]", ["10.1.2.3", "192.168.1.1"], ["192.168.1.2"]),
    ("!10.0.0.1", ["10.0.0.2", "8.8.8.8"], ["10.0.0.1"]),
    ("![10.0.0.0/8,1.1.1.1]", ["8.8.8.8"], ["10.1.1.1", "1.1.1.1"]),
    ("[10.0.0.0/8,!10.0.0.5]", ["10.0.0.4"], ["10.0.0.5", "8.8.8.8"]),
    ("2001:db8::/32", ["2001:db8::1"], ["2001:db9::1", "10.0.0.1"]),
])
def test_address_forms(spec, yes, no):
    parsed = addrs(spec)
    assert all(parsed.matches(ip) for ip in yes), spec
    assert not any(parsed.matches(ip) for ip in no), spec


@pytest.mark.parametrize("value", ["", None, "abc", "10.0.0.300"])
def test_invalid_packet_ip_never_raises_and_matches_only_any(value):
    assert addrs("any").matches(value)
    assert not addrs("10.0.0.0/8").matches(value)
    assert not addrs("!10.0.0.1").matches(value)


@pytest.mark.parametrize("bad", ["10.0.0.300", "10.0.0.0/33", "[10.0.0.1", "[]", "abc", "!any", "[10.0.0.1,]", "$NOPE"])
def test_bad_address_forms_raise(bad):
    with pytest.raises(ValueError):
        addrs(bad)


def test_ip_cache_is_bounded():
    from nids.engine.rule_header import IP_CACHE_SIZE, _parse_ip
    spec = addrs("10.0.0.0/8")
    for i in range(IP_CACHE_SIZE + 500):
        spec.matches(f"10.{i // 65536}.{(i // 256) % 256}.{i % 256}")
    assert _parse_ip.cache_info().currsize <= IP_CACHE_SIZE


# ── BIẾN (#20) ───────────────────────────────────────────────────────

def test_variables_expand_in_lists_and_with_negation():
    assert ports("[$HTTP_PORTS,8443]").matches(8443) and ports("[$HTTP_PORTS,8443]").matches(80)
    home = addrs("$HOME_NET", HOME_NET="10.0.0.0/8,192.168.0.0/16")
    assert home.matches("192.168.5.5") and not home.matches("8.8.8.8")
    outside = addrs("!$HOME_NET", HOME_NET="10.0.0.0/8,192.168.0.0/16")
    assert outside.matches("8.8.8.8") and not outside.matches("10.1.1.1")
    ext = addrs("$EXTERNAL_NET", HOME_NET="10.0.0.0/8", EXTERNAL_NET="!$HOME_NET")
    assert ext.matches("8.8.8.8") and not ext.matches("10.0.0.1")


def test_negating_a_variable_that_is_any_is_an_error_naming_the_variable():
    with pytest.raises(ValueError, match="any"):
        addrs("!$HOME_NET")        # HOME_NET mặc định là any
    with pytest.raises(ValueError):
        addrs("$EXTERNAL_NET", EXTERNAL_NET="!$HOME_NET")


def test_variable_cycle_and_unknown_variable_are_errors():
    with pytest.raises(ValueError, match="vòng"):
        ports("$A", A="$B", B="$A")
    with pytest.raises(ValueError, match="NOPE"):
        ports("$NOPE")


def test_get_rule_variables_merges_defaults_and_settings(monkeypatch):
    monkeypatch.setattr(config, "SETTINGS", {"detection": {"variables": {
        "HTTP_PORTS": [80, 9090], "HOME_NET": "172.28.0.0/16", "SSH_PORTS": 2222}}})
    got = config.get_rule_variables()
    assert got["HTTP_PORTS"] == "80,9090" and got["HOME_NET"] == "172.28.0.0/16" and got["SSH_PORTS"] == "2222"
    assert got["EXTERNAL_NET"] == DEFAULT_RULE_VARIABLES["EXTERNAL_NET"]
    assert ports("$HTTP_PORTS", **got).matches(9090)


@pytest.mark.parametrize("settings", [{}, {"detection": {}}, {"detection": {"variables": None}}])
def test_get_rule_variables_without_configuration(monkeypatch, settings):
    monkeypatch.setattr(config, "SETTINGS", settings)
    assert config.get_rule_variables() == DEFAULT_RULE_VARIABLES


def test_http_ports_falls_back_to_default_and_logs_an_error_when_config_is_invalid(caplog):
    with caplog.at_level(logging.ERROR, logger="nids.rules"):
        got = http_ports({**VARS, "HTTP_PORTS": "[80"})
    assert 80 in got and 8080 in got and 443 not in got
    assert "HTTP_PORTS" in caplog.text


def test_decoder_ports_come_from_the_same_variable_as_the_rules():
    assert decoder.HTTP_PORTS == http_ports(config.get_rule_variables())
    assert 443 not in decoder.HTTP_PORTS and 8080 in decoder.HTTP_PORTS


def test_decoder_parses_http_on_a_port_added_by_configuration(monkeypatch):
    request = b"GET /?q=1 HTTP/1.1\r\nHost: x\r\n\r\n"
    scapy_packet = Ether() / IP() / TCP(sport=40000, dport=9090, flags="PA") / Raw(request)
    assert PacketDecoder.decode(scapy_packet).http_data is None
    monkeypatch.setattr(decoder, "HTTP_PORTS", http_ports({**VARS, "HTTP_PORTS": "80,9090"}))
    assert PacketDecoder.decode(scapy_packet).http_data.uri == "/?q=1"


# ── RULE THẬT QUA DETECTOR ───────────────────────────────────────────

def packet(src="192.168.1.10", dst="10.0.0.5", sport=50000, dport=80, payload=b"attack-marker", protocol="TCP"):
    flags = {"SYN": False, "ACK": True, "FIN": False, "RST": False, "PSH": True, "URG": False, "raw_flags": "PA"}
    return DecodedPacket(timestamp=1.0, src_ip=src, dst_ip=dst, src_port=sport, dst_port=dport, protocol=protocol,
                         tcp_flags=flags if protocol == "TCP" else {}, raw_payload=payload)


def engine_for(tmp_path, header, variables=None):
    (tmp_path / "t.rules").write_text(
        f'alert {header} (msg:"t"; content:"attack-marker"; sid:5000001; rev:1;)\n', encoding="utf-8")
    manager = RuleManager(str(tmp_path), variables={**VARS, **(variables or {})})
    assert manager.load_all_rules() == 1, "rule không nạp được"
    return DetectionEngine(manager, enable_threshold=False)


def fires(engine, pkt):
    return bool(engine.evaluate_packet(pkt))


@pytest.mark.parametrize("header, yes, no", [
    ("tcp any any -> any [80,443]", {"dport": 443}, {"dport": 8080}),
    ("tcp any any -> any 1:1024", {"dport": 22}, {"dport": 8080}),
    ("tcp any any -> any !80", {"dport": 8080}, {"dport": 80}),
    ("tcp any [40000:50000] -> any any", {"sport": 45000}, {"sport": 51000}),
    ("tcp 192.168.1.0/24 any -> any any", {"src": "192.168.1.200"}, {"src": "192.168.2.1"}),
    ("tcp any any -> 10.0.0.5 any", {"dst": "10.0.0.5"}, {"dst": "10.0.0.6"}),
    ("tcp ![192.168.1.10,1.1.1.1] any -> any any", {"src": "9.9.9.9"}, {"src": "192.168.1.10"}),
    ("tcp [192.168.1.0/24,!192.168.1.10] any -> any any", {"src": "192.168.1.11"}, {"src": "192.168.1.10"}),
    ("tcp $HOME_NET any -> $EXTERNAL_NET any", {"src": "10.1.1.1", "dst": "8.8.8.8"},
     {"src": "10.1.1.1", "dst": "10.2.2.2"}),
])
def test_header_decides_whether_the_rule_fires(tmp_path, header, yes, no):
    engine = engine_for(tmp_path, header, {"HOME_NET": "10.0.0.0/8", "EXTERNAL_NET": "!$HOME_NET"})
    assert fires(engine, packet(**yes)), header
    assert not fires(engine, packet(**no)), header


def test_bidirectional_rule_matches_both_directions(tmp_path):
    engine = engine_for(tmp_path, "tcp 10.0.0.5 any <> 192.168.1.10 80")
    assert fires(engine, packet(src="10.0.0.5", dst="192.168.1.10", dport=80))
    assert fires(engine, packet(src="192.168.1.10", dst="10.0.0.5", sport=80, dport=50000))
    assert not fires(engine, packet(src="192.168.1.10", dst="10.0.0.5", dport=80))


def test_unidirectional_rule_does_not_match_the_reverse(tmp_path):
    engine = engine_for(tmp_path, "tcp 10.0.0.5 any -> 192.168.1.10 80")
    assert not fires(engine, packet(src="192.168.1.10", dst="10.0.0.5", sport=80, dport=50000))


def test_icmp_rules_ignore_ports_only_when_any(tmp_path):
    (tmp_path / "t.rules").write_text(
        'alert icmp any any -> any any (msg:"a"; itype:8; sid:5000001; rev:1;)\n'
        'alert icmp any any -> any 80 (msg:"b"; itype:8; sid:5000002; rev:1;)\n', encoding="utf-8")
    manager = RuleManager(str(tmp_path), variables=VARS)
    manager.load_all_rules()
    echo = DecodedPacket(timestamp=1.0, src_ip="1.1.1.1", dst_ip="2.2.2.2", src_port=None, dst_port=None,
                         protocol="ICMP", icmp_type=8, icmp_code=0)
    assert [r.sid for r in DetectionEngine(manager, enable_threshold=False).evaluate_packet(echo)] == [5000001]


def test_adding_an_http_port_only_needs_the_variable(tmp_path):
    with_port = engine_for(tmp_path, "tcp any any -> any $HTTP_PORTS", {"HTTP_PORTS": "80,9090"})
    assert fires(with_port, packet(dport=9090))
    without = engine_for(tmp_path, "tcp any any -> any $HTTP_PORTS")
    assert not fires(without, packet(dport=9090))


def test_rule_with_bad_header_is_dropped_with_a_warning_and_does_not_match_everything(tmp_path, caplog):
    (tmp_path / "t.rules").write_text(
        'alert tcp any any -> any [80 (msg:"bad"; content:"attack-marker"; sid:5000001; rev:1;)\n'
        'alert tcp any any -> any 80 (msg:"good"; content:"attack-marker"; sid:5000002; rev:1;)\n', encoding="utf-8")
    manager = RuleManager(str(tmp_path), variables=VARS)
    with caplog.at_level(logging.WARNING, logger="nids.rules"):
        assert manager.load_all_rules() == 1
    assert "dòng 1" in caplog.text and "thiếu dấu ']'" in caplog.text
    assert [r.sid for r in DetectionEngine(manager, enable_threshold=False).evaluate_packet(packet(dport=22))] == []


@pytest.mark.parametrize("header", ["tcp any any <- any 80", "tcp any any => any 80", "tcp any any any 80"])
def test_bad_direction_is_an_error(header):
    manager = RuleManager(variables=VARS)
    with pytest.raises(ValueError):
        manager.parse_rule_line(f'alert {header} (msg:"x"; sid:1; rev:1;)')


def test_custom_rules_validation_reports_header_errors_by_line(tmp_path):
    manager = RuleManager(str(tmp_path), variables=VARS)
    errors, _ = manager.validate_custom(
        'alert tcp any any -> any 80 (msg:"ok"; sid:2000001; rev:1;)\n'
        'alert tcp any any -> any 99999 (msg:"bad"; sid:2000002; rev:1;)\n')
    assert [(e["line"], "99999" in e["error"]) for e in errors] == [(2, True)]


# ── RULE VENDOR VÀ RULE ĐANG BẬT ─────────────────────────────────────

def test_every_vendor_header_is_understood():
    manager = RuleManager(variables=config.get_rule_variables())
    header = re.compile(r"#?\s*((?:alert|log|pass|drop|reject|sdrop)\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+)\s*\(")
    failures, total = [], 0
    for number, line in enumerate((ROOT / "rules/vendor/community.rules").read_text(encoding="utf-8").splitlines(), 1):
        match = header.match(line)
        if not match:
            continue
        total += 1
        tokens = match.group(1).split()
        try:
            parse_addrs(tokens[2], manager.variables), parse_ports(tokens[3], manager.variables)
            parse_addrs(tokens[5], manager.variables), parse_ports(tokens[6], manager.variables)
            assert tokens[4] in ("->", "<>")
        except (ValueError, AssertionError) as e:
            failures.append((number, str(e)))
    assert total > 3000 and failures == []


def test_enabled_rules_keep_their_default_header_meaning():
    manager = RuleManager("rules")
    manager.load_all_rules()
    assert len(manager.rules) == 67
    assert all(r.src_addrs.wildcard and r.dst_addrs.wildcard and r.src_ports.wildcard for r in manager.rules)
    assert ANY_PORTS.wildcard and ANY_ADDRS.wildcard
