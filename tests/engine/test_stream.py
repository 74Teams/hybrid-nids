from collections import Counter
from pathlib import Path

import pytest
from scapy.all import Ether, IP, Raw, TCP, UDP, wrpcap
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import nids.db as database
import nids.engine.main as main
from nids.db.models import Base, EventModel, FlowModel
from nids.engine.decoder import HTTP_PORTS, PacketDecoder
from nids.engine.detector import DetectionEngine
from nids.engine.http_parser import HTTPParser
from nids.engine.main import evaluate_with_stream
from nids.engine.packet import DecodedPacket
from nids.engine.rule_manager import RuleManager
from nids.engine.stream import SEQ_SPACE, StreamReassembler

ROOT = Path(__file__).resolve().parents[2]
CLIENT = ("10.0.0.5", 50000)
SERVER = ("10.0.0.9", 80)
SQLI_SID = 1000001
XXE_SID = 1000041
MIMIKATZ_SID = 1000409


def seg(seq, payload=b"", flags="PA", src=CLIENT, dst=SERVER, ts=0.0):
    """Dựng một TCP segment có sequence number; gói tới cổng HTTP được parse giống decoder."""
    tcp_flags = {"SYN": "S" in flags, "ACK": "A" in flags, "FIN": "F" in flags, "RST": "R" in flags,
                 "PSH": "P" in flags, "URG": "U" in flags, "raw_flags": flags}
    http_data = HTTPParser.parse_payload(payload) if dst[1] in HTTP_PORTS else None
    return DecodedPacket(timestamp=ts, src_ip=src[0], dst_ip=dst[0], src_port=src[1], dst_port=dst[1],
                         protocol="TCP", tcp_flags=tcp_flags, raw_payload=payload, tcp_seq=seq, http_data=http_data)


def split(payload, *cuts, start=1001):
    """Chia payload tại các vị trí `cuts` thành các segment liên tiếp."""
    edges = [0, *cuts, len(payload)]
    return [seg(start + a, payload[a:b]) for a, b in zip(edges, edges[1:])]


def feed_all(reassembler, packets):
    """Trả về payload đã ghép của từng gói (None nếu gói đó không tạo gói ảo)."""
    views = [reassembler.feed(p) for p in packets]
    return [v.packet.raw_payload if v else None for v in views]


@pytest.fixture(scope="module")
def engine():
    manager = RuleManager(str(ROOT / "rules"))
    manager.load_all_rules()
    return DetectionEngine(manager, enable_threshold=False)


def run(engine, packets, reassembler=None):
    """Chạy các gói qua đúng đường của worker; trả về Counter số lần mỗi SID bắn."""
    reassembler = reassembler or StreamReassembler()
    fired = Counter()
    for p in packets:
        fired.update(rule.sid for rule in evaluate_with_stream(engine, reassembler, p))
    return fired


# ── GHÉP DỮ LIỆU ─────────────────────────────────────────────────────

def test_decoder_fills_tcp_seq():
    decoded = PacketDecoder.decode(Ether() / IP() / TCP(seq=4242))
    assert decoded.tcp_seq == 4242
    assert PacketDecoder.decode(Ether() / IP() / UDP()).tcp_seq is None


def test_single_segment_produces_no_view():
    assert StreamReassembler().feed(seg(1001, b"hello")) is None


def test_consecutive_segments_are_joined():
    payloads = feed_all(StreamReassembler(), [seg(1000, b"", "S"), seg(1001, b"abc"), seg(1004, b"def"), seg(1007, b"g")])
    assert payloads == [None, None, b"abcdef", b"abcdefg"]


def test_view_is_marked_and_copies_packet_fields():
    r = StreamReassembler()
    r.feed(seg(1001, b"abc"))
    view = r.feed(seg(1004, b"def", ts=5.0))
    assert view.packet.reassembled and view.packet.timestamp == 5.0
    assert (view.packet.src_ip, view.packet.dst_port) == (CLIENT[0], SERVER[1])


def test_out_of_order_segments_are_reordered_when_syn_was_seen():
    payloads = feed_all(StreamReassembler(), [seg(1000, b"", "S"), seg(1004, b"def"), seg(1001, b"abc")])
    assert payloads == [None, None, b"abcdef"]


def test_retransmission_is_ignored_and_overlap_keeps_first_data():
    payloads = feed_all(StreamReassembler(), [seg(1001, b"abc"), seg(1001, b"abc"), seg(1002, b"XYZ"), seg(1005, b"e")])
    assert payloads == [None, None, b"abcZ", b"abcZe"]


def test_sequence_number_wraps_around():
    start = SEQ_SPACE - 2
    payloads = feed_all(StreamReassembler(), [seg(start, b"abcd"), seg(2, b"ef")])
    assert payloads == [None, b"abcdef"]


def test_exceeding_depth_stops_reassembly_of_that_stream():
    r = StreamReassembler(depth=6)
    assert feed_all(r, [seg(1001, b"abc"), seg(1004, b"def"), seg(1007, b"g"), seg(1008, b"h")]) == [
        None, b"abcdef", None, None]
    assert r.total_bytes == 0


def test_total_memory_limit_evicts_the_oldest_stream():
    r = StreamReassembler(max_total_bytes=10)
    r.feed(seg(1, b"a" * 6, src=("1.1.1.1", 40000)))
    r.feed(seg(1, b"b" * 6, src=("2.2.2.2", 40000)))
    assert len(r) == 1 and r.total_bytes == 6


def test_max_streams_is_never_exceeded():
    r = StreamReassembler(max_streams=2)
    for i in range(5):
        r.feed(seg(1, b"", "S", src=(f"1.1.1.{i}", 40000)))
    assert len(r) == 2


def test_unfilled_gap_resyncs_after_too_many_pending_segments():
    r = StreamReassembler(max_pending_segments=2)
    packets = [seg(1000, b"", "S"), seg(2000, b"a"), seg(3000, b"b"), seg(4000, b"c"), seg(4001, b"d")]
    assert feed_all(r, packets)[-1] == b"cd"


def test_fin_and_rst_remove_the_stream_after_taking_its_payload():
    for flags in ("FA", "RA"):
        r = StreamReassembler()
        r.feed(seg(1001, b"abc"))
        assert r.feed(seg(1004, b"def", flags)).packet.raw_payload == b"abcdef"
        assert len(r) == 0 and r.total_bytes == 0


def test_fin_from_server_removes_the_stream():
    r = StreamReassembler()
    r.feed(seg(1001, b"abc"))
    r.feed(seg(9000, b"", "FA", src=SERVER, dst=CLIENT))
    assert len(r) == 0


def test_idle_stream_is_expired_by_packet_time():
    r = StreamReassembler(idle_timeout=30)
    r.feed(seg(1001, b"abc", ts=0))
    r.feed(seg(1, b"x", src=("2.2.2.2", 40000), ts=40))
    assert len(r) == 1 and r.total_bytes == 1


def test_new_syn_replaces_the_old_stream():
    r = StreamReassembler()
    r.feed(seg(1001, b"abc"))
    r.feed(seg(5000, b"", "S"))
    assert r.feed(seg(5001, b"def")) is None
    assert r.total_bytes == 3


def test_server_direction_is_not_reassembled():
    r = StreamReassembler()
    packets = [seg(1000, b"", "S"), seg(9000, b"", "SA", src=SERVER, dst=CLIENT),
               seg(9001, b"abc", src=SERVER, dst=CLIENT), seg(9004, b"def", src=SERVER, dst=CLIENT)]
    assert feed_all(r, packets) == [None] * 4
    assert r.total_bytes == 0


def test_packets_without_seq_and_non_tcp_are_ignored():
    r = StreamReassembler()
    no_seq = seg(None, b"abc")
    udp = DecodedPacket(timestamp=0, src_ip="1.1.1.1", dst_ip="2.2.2.2", src_port=5, dst_port=53, protocol="UDP")
    assert r.feed(no_seq) is None and r.feed(udp) is None
    assert len(r) == 0


def test_lab_packets_with_repeated_seq_zero_produce_no_view():
    """Gói dựng bằng Scapy trong lab đều có seq=0: bị coi là gửi lại, không sinh gói ảo."""
    assert feed_all(StreamReassembler(), [seg(0, b"attack"), seg(0, b"attack"), seg(0, b"attack")]) == [None] * 3


def test_large_stream_is_scanned_a_limited_number_of_times():
    """Quét lại ở mọi segment thì chi phí tăng theo bậc hai, upload lớn sẽ làm engine rớt gói."""
    packets = [seg(1 + i * 1400, b"A" * 1400, dst=("10.0.0.9", 4444)) for i in range(45)]
    views = [v for v in feed_all(StreamReassembler(), packets) if v]
    assert 2 <= len(views) <= 8
    sizes = [len(v) for v in views]
    assert sizes == sorted(sizes)


def test_data_not_yet_scanned_is_scanned_when_the_stream_closes():
    dst = ("10.0.0.9", 4444)
    packets = [seg(1 + i * 1400, b"A" * 1400, dst=dst) for i in range(5)]
    r = StreamReassembler()
    feed_all(r, packets)
    view = r.feed(seg(1 + 5 * 1400, b"", "FA", dst=dst))
    assert len(view.packet.raw_payload) == 7000


def test_buffer_is_scanned_one_last_time_before_depth_is_exceeded():
    dst = ("10.0.0.9", 4444)
    packets = [seg(1 + i * 1400, b"A" * 1400, dst=dst) for i in range(7)]
    payloads = [p for p in feed_all(StreamReassembler(depth=9000), packets) if p]
    assert len(payloads[-1]) == 8400


def test_complete_http_request_is_cut_from_the_buffer():
    r = StreamReassembler()
    request = b"POST /x HTTP/1.1\r\nContent-Length: 4\r\n\r\nabcd"
    feed_all(r, split(request, 10))
    assert r.total_bytes == 0


def test_incomplete_http_body_stays_in_the_buffer():
    r = StreamReassembler()
    request = b"POST /x HTTP/1.1\r\nContent-Length: 100\r\n\r\nabcd"
    feed_all(r, split(request, 10))
    assert r.total_bytes == len(request)


# ── SO KHỚP VỚI RULE THẬT ────────────────────────────────────────────

def test_sqli_split_across_two_packets_fires_the_right_sid(engine):
    """Điều kiện 'xong khi' của issue #16."""
    packets = split(b"GET /?q=union+select+1 HTTP/1.1\r\nHost: victim\r\n\r\n", 14)
    assert not any(SQLI_SID == r.sid for p in packets for r in engine.evaluate_packet(p))  # từng gói không khớp
    assert run(engine, packets)[SQLI_SID] == 1


def test_stream_disabled_keeps_the_old_behaviour(engine):
    packets = split(b"GET /?q=union+select+1 HTTP/1.1\r\nHost: victim\r\n\r\n", 14)
    fired = Counter(r.sid for p in packets for r in evaluate_with_stream(engine, None, p))
    assert fired[SQLI_SID] == 0


def test_out_of_order_sqli_is_detected(engine):
    syn = seg(1000, b"", "S")
    first, second = split(b"GET /?q=union+select+1 HTTP/1.1\r\nHost: victim\r\n\r\n", 14)
    assert run(engine, [syn, second, first])[SQLI_SID] == 1


def test_pkt_data_split_fires_once_even_with_more_data_after_it(engine):
    client_to_c2 = dict(dst=("10.0.0.9", 4444))
    packets = [seg(1001, b"echo sekurlsa::", **client_to_c2), seg(1016, b"logonpasswords", **client_to_c2),
               seg(1030, b" more", **client_to_c2)]
    assert run(engine, packets)[MIMIKATZ_SID] == 1


def test_split_post_body_matches_http_client_body(engine):
    body = b'<!ENTITY xxe SYSTEM "file:///etc/passwd">'
    head = f"POST /upload HTTP/1.1\r\nHost: victim\r\nContent-Length: {len(body)}\r\n\r\n".encode()
    packets = split(head + body, len(head) + 5)
    assert run(engine, packets)[XXE_SID] == 1


def test_attack_at_the_end_of_a_large_body_is_found_when_the_request_completes(engine):
    body = b"A" * 30000 + b'<!ENTITY xxe SYSTEM "file:///etc/passwd">'
    head = f"POST /upload HTTP/1.1\r\nHost: victim\r\nContent-Length: {len(body)}\r\n\r\n".encode()
    data = head + body
    assert run(engine, split(data, *range(1400, len(data), 1400)))[XXE_SID] == 1


def test_benign_request_split_fires_nothing(engine):
    packets = split(b"GET /index.html HTTP/1.1\r\nHost: victim\r\nUser-Agent: Mozilla/5.0\r\n\r\n", 12)
    assert run(engine, packets) == Counter()


def test_rule_matched_on_a_single_packet_does_not_fire_again_on_the_stream(engine):
    client_to_c2 = dict(dst=("10.0.0.9", 4444))
    packets = [seg(1001, b"sekurlsa::logonpasswords", **client_to_c2), seg(1025, b" more", **client_to_c2)]
    assert run(engine, packets)[MIMIKATZ_SID] == 1


def test_two_split_attacks_on_one_keep_alive_connection_fire_twice(engine):
    request = b"GET /?q=union+select+1 HTTP/1.1\r\nHost: victim\r\n\r\n"
    packets = split(request, 14) + split(request, 14, start=1001 + len(request))
    assert run(engine, packets)[SQLI_SID] == 2


def test_unsplit_keep_alive_requests_are_not_reported_again(engine):
    """Request cũ đã nằm gọn trong một gói phải được cắt khỏi buffer, nếu không sẽ bị so khớp lại."""
    attack = b"GET /?q=union+select+1 HTTP/1.1\r\nHost: victim\r\n\r\n"
    benign = b"GET /index.html HTTP/1.1\r\nHost: victim\r\n\r\n"
    seq, packets = 1001, []
    for request in (attack, attack, benign, benign):
        packets.append(seg(seq, request))
        seq += len(request)
    assert run(engine, packets)[SQLI_SID] == 2


@pytest.mark.parametrize("option", ["dsize:>1;", "flags:PA;", "detection_filter:track by_src, count 1, seconds 60;"])
def test_rules_tied_to_a_real_packet_are_skipped_on_the_stream(tmp_path, option):
    (tmp_path / "local.rules").write_text(
        f'alert tcp any any -> any any (msg:"T"; content:"split-me"; {option} sid:2000001; rev:1;)\n', encoding="utf-8")
    manager = RuleManager(str(tmp_path))
    manager.load_all_rules()
    detector = DetectionEngine(manager, enable_threshold=False)
    assert run(detector, split(b"xx split-me yy", 8)) == Counter()


def test_reassembly_error_keeps_the_per_packet_result(engine):
    class Broken(StreamReassembler):
        def feed(self, packet, matched=()):
            raise ValueError("lỗi")

    packet = seg(1001, b"sekurlsa::logonpasswords", dst=("10.0.0.9", 4444))
    assert run(engine, [packet], Broken())[MIMIKATZ_SID] == 1


def test_replaying_a_pcap_with_split_attack_alerts_and_marks_the_flow(monkeypatch, tmp_path):
    db_engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(db_engine)
    factory = sessionmaker(bind=db_engine)
    monkeypatch.setattr(database, "SessionLocal", factory)

    def tcp(src, sport, dst, dport, flags, seq, t, payload=b""):
        p = Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags, seq=seq)
        p = p / Raw(payload) if payload else p
        p.time = 1700000000 + t
        return p

    first, second = b"GET /?q=union+se", b"lect+1 HTTP/1.1\r\nHost: victim\r\n\r\n"
    client, server = ("10.0.0.5", 50000), ("10.0.0.9", 80)
    packets = [
        tcp(*client, *server, "S", 1000, 0), tcp(*server, *client, "SA", 9000, 0.01),
        tcp(*client, *server, "A", 1001, 0.02), tcp(*client, *server, "PA", 1001, 0.03, first),
        tcp(*client, *server, "PA", 1001 + len(first), 0.04, second),
    ]
    pcap = tmp_path / "split.pcap"
    wrpcap(str(pcap), packets)

    monkeypatch.setattr(main, "init_db", lambda: None)
    monkeypatch.setattr(main, "SETTINGS", {
        "network": {"capture_mode": "offline", "pcap_file": str(pcap), "bpf_filter": "ip"},
        "detection": {"rules_dir": str(ROOT / "rules")},
        "flow": {"retention_hours": 0},
    })
    main.main()

    session = factory()
    try:
        sids = [e.sid for e in session.query(EventModel).all()]
        flows = session.query(FlowModel).all()
    finally:
        session.close()
    assert sids.count(SQLI_SID) == 1
    assert len(flows) == 1 and flows[0].alert_count >= 1
