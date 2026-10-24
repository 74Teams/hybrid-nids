import time
import pytest
from services.ingestion import DecodedPacket, ParsedHTTPRequest
from services.detection.manager_rules import RuleManager
from services.detection.ids_realtime import DetectionEngine


def parse(rule_text):
    return RuleManager().parse_rule_line(rule_text)


def engine_with(*rule_texts):
    manager = RuleManager()
    for text in rule_texts:
        rule = manager.parse_rule_line(text)
        manager.rules.append(rule)
        manager.rules_by_sid[rule.sid] = rule
    return DetectionEngine(manager, enable_threshold=False)


def tcp_packet(payload=b"", flags="PA", dport=80, http_data=None):
    return DecodedPacket(
        timestamp=time.time(),
        src_ip="192.168.1.100",
        dst_ip="10.0.0.5",
        src_port=50000,
        dst_port=dport,
        protocol="TCP",
        tcp_flags={"raw_flags": flags},
        raw_payload=payload,
        http_data=http_data,
    )


# ── PARSER ──────────────────────────────────────────────────────────────────

def test_semicolon_and_quote_inside_strings_do_not_split_options():
    rule = parse(
        r'alert tcp any any -> any any (msg:"a; b \"c\""; content:"x\;y"; '
        r'pcre:"/a;b\"/i"; sid:1; rev:1;)'
    )
    assert rule.msg == 'a; b "c"'
    assert rule.contents[0].pattern == "x;y"
    assert rule.pcres[0].regex.search('A;B"')


def test_content_modifiers_and_hex():
    rule = parse(
        'alert udp any any -> any 161 (content:"|04 06|public",depth 16,nocase; '
        'content:!"private",distance 0,within 10; sid:2; rev:1;)'
    )
    first, second = rule.contents
    assert first.pattern == "\x04\x06public"
    assert first.depth == 16 and first.nocase
    assert second.negated and second.distance == 0 and second.within == 10


def test_sticky_buffer_applies_to_following_contents():
    rule = parse(
        'alert tcp any any -> any 80 (http_method; content:"POST"; '
        'http_header:field user-agent; content:"sqlmap",nocase; '
        'pkt_data; content:"raw"; sid:3; rev:1;)'
    )
    assert [(c.buffer, c.field) for c in rule.contents] == [
        ("http_method", None),
        ("http_header", "user-agent"),
        ("pkt_data", None),
    ]


def test_priority_flow_and_detection_filter():
    rule = parse(
        "alert tcp any any -> any 80 (flow:to_server,established; flags:S,CE; "
        "detection_filter:track by_dst, count 10, seconds 1; priority:1; sid:4; rev:1;)"
    )
    assert rule.severity == 1
    assert rule.flow == ["to_server", "established"]
    assert rule.flags == "S,CE"
    df = rule.detection_filter
    assert (df.track, df.count, df.seconds) == ("by_dst", 10, 1)


def test_snort2_syntax_is_not_silently_accepted():
    with pytest.raises(ValueError):
        parse('alert tcp any any -> any 80 (http_method:"POST"; content:"x"; sid:5; rev:1;)')
    rule = parse('alert tcp any any -> any any (content:"x"; nocase; sid:6; rev:1;)')
    assert rule.unsupported_options == ["nocase"]
    rule = parse('alert tcp any any -> any any (content:"x"; severity:1; sid:7; rev:1;)')
    assert rule.unsupported_options == ["severity"]


def test_unknown_option_is_recorded():
    rule = parse('alert tcp any any -> any any (content:"x"; byte_test:1,>,5,0; sid:6; rev:1;)')
    assert rule.unsupported_options == ["byte_test"]


@pytest.mark.parametrize("bad_rule", [
    'alert tcp any any -> any any (content:"x"; sid:7; rev:1)',          # thiếu ';' cuối
    'alert tcp any any -> any any (content:"x; sid:7; rev:1;)',          # thiếu ngoặc kép
    'alert tcp any any -> any any (content:"x"; rev:1;)',                # thiếu sid
    'alert tcp any any -> any any (pcre:"/x/R"; sid:7; rev:1;)',         # flag pcre không hỗ trợ
    'alert tcp any -> any any (content:"x"; sid:7; rev:1;)',             # header thiếu thành phần
])
def test_invalid_rules_raise(bad_rule):
    with pytest.raises(ValueError):
        parse(bad_rule)


# ── ENGINE SEMANTICS ────────────────────────────────────────────────────────

@pytest.mark.parametrize("rule_flags, packet_flags, expected", [
    ("S", "S", True),
    ("S", "SA", False),
    ("S+", "SA", True),
    ("SF*", "F", True),
    ("!F", "PA", True),
    ("!F", "FA", False),
    ("0", "", True),
    ("S,CE", "SE", True),
])
def test_flags_semantics(rule_flags, packet_flags, expected):
    assert DetectionEngine._match_flags({"raw_flags": packet_flags}, rule_flags) is expected


def test_offset_depth_distance_within():
    engine = engine_with(
        'alert tcp any any -> any any (content:"GET",depth 3; content:"admin",distance 0,within 10; sid:10; rev:1;)'
    )
    assert engine.evaluate_packet(tcp_packet(b"GET /admin HTTP/1.1"))
    assert not engine.evaluate_packet(tcp_packet(b"xGET /admin"))                       # GET ngoài depth 3
    assert not engine.evaluate_packet(tcp_packet(b"GET /aaaaaaaaaaaaaaaa/admin"))       # admin ngoài within 10


def test_negated_content():
    engine = engine_with('alert tcp any any -> any any (content:"login"; content:!"token"; sid:11; rev:1;)')
    assert engine.evaluate_packet(tcp_packet(b"login user=a"))
    assert not engine.evaluate_packet(tcp_packet(b"login token=abc"))


def test_http_header_field_only_matches_that_header():
    engine = engine_with(
        'alert tcp any any -> any 80 (http_header:field user-agent; content:"sqlmap",nocase; sid:12; rev:1;)'
    )
    ua = ParsedHTTPRequest(method="GET", uri="/", headers={"user-agent": "sqlmap/1.7"})
    referer = ParsedHTTPRequest(method="GET", uri="/", headers={"referer": "http://sqlmap.org"})
    assert engine.evaluate_packet(tcp_packet(b"GET /", http_data=ua))
    assert not engine.evaluate_packet(tcp_packet(b"GET /", http_data=referer))


def test_flow_established_rejects_syn():
    engine = engine_with('alert tcp any any -> any any (flow:to_server,established; content:"x"; sid:13; rev:1;)')
    assert engine.evaluate_packet(tcp_packet(b"x", flags="PA"))
    assert not engine.evaluate_packet(tcp_packet(b"x", flags="S"))
