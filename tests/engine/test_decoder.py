"""PacketDecoder phải trả đúng byte payload L4, kể cả khi Scapy tự bóc tiếp tầng ứng dụng."""
from scapy.all import DNS, DNSQR, Ether, IP, Padding, Raw, TCP, UDP

from nids.engine.decoder import PacketDecoder
from nids.engine.detector import DetectionEngine
from nids.engine.rule_manager import RuleManager

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
