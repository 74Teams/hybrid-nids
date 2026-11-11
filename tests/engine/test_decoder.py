"""PacketDecoder phải trả đúng byte payload L4, kể cả khi Scapy tự bóc tiếp tầng ứng dụng."""
from pathlib import Path

from scapy.all import DNS, DNSQR, Ether, IP, Padding, Raw, TCP, UDP

from nids.engine.decoder import PacketDecoder
from nids.engine.detector import DetectionEngine
from nids.engine.rule_manager import RuleManager

ROOT = Path(__file__).resolve().parents[2]

# Header SMB1 Trans2 (DoublePulsar ping) lấy từ pcap Shadow Brokers, 82 byte
SMB1_TRANS2_PING = bytes.fromhex(
    "0000004eff534d4232000000001807c00000000000000000000000000008fffe000841000f0c00000001"
    "000000000000005886450000000c00420000004e0001000e000d0000000000000000000000000000"
)


def _on_the_wire(pkt) -> Ether:
    """Dựng gói, đưa qua byte rồi dissect lại như khi bắt từ mạng hoặc đọc pcap."""
    return Ether(bytes(pkt))


def test_smb_payload_keeps_netbios_and_smb_header():
    wire = _on_the_wire(Ether() / IP(dst="10.0.0.5") / TCP(sport=40000, dport=445, flags="PA") / Raw(SMB1_TRANS2_PING))
    assert not wire.haslayer(Raw) or len(wire[Raw].load) < len(SMB1_TRANS2_PING)  # Scapy đã bóc NBTSession/SMB
    assert PacketDecoder.decode(wire).raw_payload == SMB1_TRANS2_PING


def test_dns_payload_is_full_udp_payload():
    query = bytes(DNS(rd=1, qd=DNSQR(qname="example.com", qtype=255)))
    wire = _on_the_wire(Ether() / IP(dst="10.0.0.5") / UDP(sport=40001, dport=53) / Raw(query))
    assert wire.haslayer(DNS)
    assert PacketDecoder.decode(wire).raw_payload == query


def test_ethernet_padding_is_not_part_of_payload():
    wire = _on_the_wire(Ether() / IP(dst="10.0.0.5") / TCP(sport=40000, dport=4444, flags="PA") / Raw(b"id") / Padding(b"\x00" * 20))
    assert PacketDecoder.decode(wire).raw_payload == b"id"


def test_hand_built_packet_without_original_bytes():
    pkt = IP(dst="10.0.0.5") / TCP(sport=40000, dport=4444, flags="PA") / Raw(b"/bin/bash -i")
    assert PacketDecoder.decode(pkt).raw_payload == b"/bin/bash -i"
    assert PacketDecoder.decode(IP(dst="10.0.0.5") / TCP(dport=80, flags="S")).raw_payload == b""


def test_icmp_payload_unchanged():
    from scapy.all import ICMP

    wire = _on_the_wire(Ether() / IP(dst="10.0.0.5") / ICMP(type=8) / Raw(b"A" * 1000))
    assert PacketDecoder.decode(wire).raw_payload == b"A" * 1000


def test_http_still_parsed_on_http_port():
    request = b"GET /a?b=1 HTTP/1.1\r\nHost: victim\r\n\r\n"
    wire = _on_the_wire(Ether() / IP(dst="10.0.0.5") / TCP(sport=40000, dport=80, flags="PA") / Raw(request))
    decoded = PacketDecoder.decode(wire)
    assert decoded.raw_payload == request
    assert decoded.http_data is not None and decoded.http_data.uri == "/a?b=1"


def test_real_dns_any_query_fires_its_rule_through_the_decoder():
    """Trước khi sửa, gói DNS thật qua decoder có payload rỗng nên SID 1000207 không bao giờ bắn ngoài test."""
    manager = RuleManager("rules")
    manager.load_all_rules()
    engine = DetectionEngine(manager, enable_threshold=False)
    pkt = Ether() / IP(src="10.0.0.5", dst="8.8.8.8") / UDP(sport=4000, dport=53) / DNS(rd=1, qd=DNSQR(qname="example.com", qtype=255))
    assert 1000207 in {r.sid for r in engine.evaluate_packet(PacketDecoder.decode(_on_the_wire(pkt)))}


# ── Lọc tầng Scapy (PLAN-009 T7): decode phải giống hệt khi không lọc ───────

def _decoded_fields(packet):
    d = PacketDecoder.decode(packet)
    if d is None:
        return None
    h = d.http_data
    return (d.src_ip, d.dst_ip, d.src_port, d.dst_port, d.protocol, sorted(d.tcp_flags.items()), d.icmp_type,
            d.icmp_code, d.raw_payload, d.tcp_seq,
            None if h is None else (h.method, h.uri, h.headers, h.body))


def _regression_packets():
    from scapy.all import ICMP, IPv6, Dot1Q, IPv6ExtHdrHopByHop, ICMPv6EchoRequest, rdpcap

    built = [
        Ether() / IP(src="10.0.0.1", dst="10.0.0.5") / TCP(sport=40000, dport=80, flags="PA")
        / Raw(b"GET /a?b=1 HTTP/1.1\r\nHost: victim\r\n\r\n"),
        Ether() / IP(src="10.0.0.1", dst="8.8.8.8") / UDP(sport=4000, dport=53) / DNS(rd=1, qd=DNSQR(qname="example.com")),
        Ether() / Dot1Q(vlan=10) / IP(src="10.0.0.1", dst="10.0.0.5") / TCP(sport=1, dport=445, flags="S"),
        Ether() / IPv6(src="fe80::1", dst="ff02::1:2") / IPv6ExtHdrHopByHop() / UDP(sport=546, dport=547) / Raw(b"\x01" * 8),
        Ether() / IPv6(src="fe80::1", dst="fe80::2") / ICMPv6EchoRequest(data=b"ping"),
        Ether() / IP(src="10.0.0.9", dst="10.0.0.1") / ICMP(type=3, code=3) / IP(src="10.0.0.1", dst="10.0.0.9")
        / UDP(sport=5000, dport=6000),
        Ether() / IP(src="10.0.0.9", dst="10.0.0.1") / ICMP(type=3, code=1) / IP(src="10.0.0.1", dst="10.0.0.9")
        / TCP(sport=5000, dport=80, flags="S"),
        Ether() / IP(src="10.0.0.1", dst="10.0.0.5") / UDP(sport=137, dport=137) / Raw(b"\x00" * 50),
    ]
    wire = [bytes(p) for p in built]
    wire += [bytes(p) for p in rdpcap(str(ROOT / "pcap" / "ipv4frags.pcap"))]
    return wire


def test_layer_filter_keeps_decode_identical():
    from nids.engine.capture import apply_layer_filter, reset_layer_filter

    wire = _regression_packets()
    expected = [_decoded_fields(Ether(raw)) for raw in wire]
    try:
        apply_layer_filter()
        filtered = [_decoded_fields(Ether(raw)) for raw in wire]
        raw_packets = [PacketDecoder.decode(Ether(raw)) for raw in wire]
    finally:
        reset_layer_filter()
    assert filtered == expected
    # có lọc thì bytes(gói) luôn là byte gốc trên dây (không bị Scapy dựng lại)
    assert all(d is None or d.raw_packet == raw for d, raw in zip(raw_packets, wire))


def test_reset_layer_filter_restores_full_dissection():
    from nids.engine.capture import apply_layer_filter, reset_layer_filter

    raw = bytes(Ether() / IP(dst="8.8.8.8") / UDP(sport=4000, dport=53) / DNS(qd=DNSQR(qname="a.b")))
    try:
        apply_layer_filter()
        assert not Ether(raw).haslayer(DNS)       # có lọc: phần sau UDP là Raw
    finally:
        reset_layer_filter()
    assert Ether(raw).haslayer(DNS)
