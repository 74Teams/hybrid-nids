"""Payload do PacketDecoder trích ra: phải là mọi byte sau header L4, kể cả khi Scapy đã bóc thành lớp giao thức."""
from scapy.all import DNS, DNSQR, ICMP, IP, TCP, UDP, Ether, Raw

from nids.engine.decoder import PacketDecoder
from nids.engine.detector import DetectionEngine
from nids.engine.rule_manager import RuleManager


def decode(pkt):
    # Dựng lại từ byte để Scapy tự bóc lớp như khi bắt gói thật (cổng 53 thành DNS, frame ngắn có Padding)
    return PacketDecoder.decode(pkt.__class__(bytes(pkt)))


def test_dns_query_payload_is_kept_although_scapy_dissects_it_as_dns():
    dns = DNS(rd=1, qd=DNSQR(qname="example.com", qtype=255))
    d = decode(Ether() / IP(src="10.0.0.5", dst="8.8.8.8") / UDP(sport=4000, dport=53) / dns)
    assert d.raw_payload == bytes(dns)
    assert b"\x00\x00\xff\x00\x01" in d.raw_payload


def test_ethernet_padding_is_not_payload():
    syn = Ether() / IP(src="10.0.0.5", dst="10.0.0.9") / TCP(sport=40000, dport=80, flags="S")
    assert len(bytes(syn)) < 60
    d = decode(Ether(bytes(syn) + b"\x00" * (60 - len(bytes(syn)))))
    assert d.raw_payload == b""


def test_raw_tcp_payload_is_unchanged():
    req = b"GET /?id=1 HTTP/1.1\r\nHost: victim\r\n\r\n"
    d = decode(Ether() / IP(src="10.0.0.5", dst="10.0.0.9") / TCP(sport=40000, dport=80, flags="PA") / Raw(req))
    assert d.raw_payload == req
    assert d.http_data is not None and d.http_data.uri == "/?id=1"


def test_icmp_echo_payload():
    d = decode(Ether() / IP(src="10.0.0.5", dst="10.0.0.9") / ICMP(type=8) / Raw(b"A" * 900))
    assert d.raw_payload == b"A" * 900


def test_real_dns_any_query_fires_its_rule_through_the_decoder():
    """Trước khi sửa, gói DNS thật qua decoder có payload rỗng nên SID 1000207 không bao giờ bắn ngoài test."""
    manager = RuleManager("rules")
    manager.load_all_rules()
    engine = DetectionEngine(manager, enable_threshold=False)
    pkt = Ether() / IP(src="10.0.0.5", dst="8.8.8.8") / UDP(sport=4000, dport=53) / DNS(rd=1, qd=DNSQR(qname="example.com", qtype=255))
    assert 1000207 in {r.sid for r in engine.evaluate_packet(decode(pkt))}
