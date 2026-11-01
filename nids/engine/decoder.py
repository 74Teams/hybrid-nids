import time
from typing import Optional
from scapy.all import IP, IPv6, TCP, UDP, ICMP, Raw
from scapy.packet import Packet

from nids.engine.packet import DecodedPacket
from nids.engine.http_parser import HTTPParser

# Tập hợp các port HTTP phổ biến, dùng để quyết định có cần parse HTTP hay không
HTTP_PORTS = {80, 8080, 8000, 3000, 5000, 443}


class PacketDecoder:
    """
    Module chuyên trách duy nhất: giải mã gói tin thô (Scapy Packet) thành DecodedPacket.

    Trách nhiệm:
    - Bóc tách các tầng L3 (IP/IPv6), L4 (TCP/UDP/ICMP).
    - Trích xuất cờ TCP (SYN, ACK, FIN, RST, PSH, URG) và payload thô.
    - Điều phối chuyển payload sang HTTPParser nếu phát hiện traffic Web (HTTP Ports).

    Nguyên tắc:
    - Class này KHÔNG biết cách bắt gói tin, đó là việc của PacketCapture.
    - Class này KHÔNG lưu vào Database hay kích hoạt Alert, đó là việc của Detection Engine.
    """

    @staticmethod
    def decode(scapy_pkt: Packet) -> Optional[DecodedPacket]:
        """
        Giải mã 1 gói tin Scapy thô thành DecodedPacket có cấu trúc.

        Args:
            scapy_pkt: Gói tin thô từ Scapy (do PacketCapture truyền vào).

        Returns:
            DecodedPacket nếu giải mã thành công, None nếu gói tin không phải IP.
        """
        timestamp = float(getattr(scapy_pkt, "time", time.time()))

        # Tầng L3: giải mã địa chỉ IP nguồn / IP đích
        src_ip, dst_ip = "", ""
        if scapy_pkt.haslayer(IP):
            src_ip = scapy_pkt[IP].src
            dst_ip = scapy_pkt[IP].dst
        elif scapy_pkt.haslayer(IPv6):
            src_ip = scapy_pkt[IPv6].src
            dst_ip = scapy_pkt[IPv6].dst
        else:
            # Không phải IP (ARP, LLDP...) nên bỏ qua
            return None

        # Tầng L4: giải mã protocol, port và cờ TCP
        protocol = "UNKNOWN"
        src_port: Optional[int] = None
        dst_port: Optional[int] = None
        tcp_flags: dict = {}
        tcp_seq: Optional[int] = None
        icmp_type: Optional[int] = None
        icmp_code: Optional[int] = None

        if scapy_pkt.haslayer(TCP):
            protocol = "TCP"
            tcp = scapy_pkt[TCP]
            src_port = tcp.sport
            dst_port = tcp.dport
            tcp_seq = tcp.seq
            flags = str(tcp.flags)  # Scapy trả về chuỗi: "S", "SA", "PA", "FUP"...
            tcp_flags = {
                "SYN": "S" in flags,
                "ACK": "A" in flags,
                "FIN": "F" in flags,
                "RST": "R" in flags,
                "PSH": "P" in flags,
                "URG": "U" in flags,
                "raw_flags": flags,  # Chuỗi thô để Rule Engine so khớp cờ (ví dụ: flags:FUP)
            }

        elif scapy_pkt.haslayer(UDP):
            protocol = "UDP"
            udp = scapy_pkt[UDP]
            src_port = udp.sport
            dst_port = udp.dport

        elif scapy_pkt.haslayer(ICMP):
            protocol = "ICMP"
            icmp_type = scapy_pkt[ICMP].type
            icmp_code = scapy_pkt[ICMP].code

        # Payload thô (bytes)
        raw_payload = bytes(scapy_pkt[Raw].load) if scapy_pkt.haslayer(Raw) else b""

        # Tạo DecodedPacket cơ bản
        decoded = DecodedPacket(
            timestamp=timestamp,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            tcp_flags=tcp_flags,
            icmp_type=icmp_type,
            icmp_code=icmp_code,
            raw_payload=raw_payload,
            raw_packet=bytes(scapy_pkt),
            tcp_seq=tcp_seq,
        )

        # Tầng L7: parse HTTP nếu là traffic Web
        # Kiểm tra port để quyết định có cần parse HTTP hay không
        is_http_traffic = (
            raw_payload
            and (
                dst_port in HTTP_PORTS
                or src_port in HTTP_PORTS
            )
        )
        if is_http_traffic:
            decoded.http_data = HTTPParser.parse_payload(raw_payload)

        return decoded
