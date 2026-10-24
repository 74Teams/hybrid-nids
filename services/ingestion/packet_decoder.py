import time
from typing import Optional
from scapy.all import IP, IPv6, TCP, UDP, ICMP, Raw
from scapy.packet import Packet

from services.ingestion import DecodedPacket
from services.ingestion.http_parser import HTTPParser

# Tap hop cac port HTTP pho bien - dung de quyet dinh co can parse HTTP hay khong
HTTP_PORTS = {80, 8080, 8000, 3000, 5000, 443}


class PacketDecoder:
    """
    Module chuyen trach duy nhat: Giai ma goi tin tho (Scapy Packet) thanh DecodedPacket.

    Trach nhiem:
    - Boc tach cac tang L3 (IP/IPv6), L4 (TCP/UDP/ICMP).
    - Trich xuat co TCP (SYN, ACK, FIN, RST, PSH, URG) va payload tho.
    - Dieu phoi chuyen payload sang HTTPParser neu phat hien traffic Web (HTTP Ports).

    Nguyen tac:
    - Class nay KHONG biet cach bat goi tin - do la viec cua PacketCapture.
    - Class nay KHONG luu vao Database hay kich hoat Alert - do la viec cua Detection Engine.
    """

    @staticmethod
    def decode(scapy_pkt: Packet) -> Optional[DecodedPacket]:
        """
        Giai ma 1 goi tin Scapy tho thanh DecodedPacket co cau truc.

        Args:
            scapy_pkt: Goi tin tho tu Scapy (do PacketCapture truyen vao).

        Returns:
            DecodedPacket neu giai ma thanh cong, None neu goi tin khong phai IP.
        """
        timestamp = float(getattr(scapy_pkt, "time", time.time()))

        # Tang L3: Giai ma dia chi IP nguon / IP dich
        src_ip, dst_ip = "", ""
        if scapy_pkt.haslayer(IP):
            src_ip = scapy_pkt[IP].src
            dst_ip = scapy_pkt[IP].dst
        elif scapy_pkt.haslayer(IPv6):
            src_ip = scapy_pkt[IPv6].src
            dst_ip = scapy_pkt[IPv6].dst
        else:
            # Khong phai IP (ARP, LLDP...) -> bo qua
            return None

        # Tang L4: Giai ma Protocol, Port va Co TCP
        protocol = "UNKNOWN"
        src_port: Optional[int] = None
        dst_port: Optional[int] = None
        tcp_flags: dict = {}
        icmp_type: Optional[int] = None
        icmp_code: Optional[int] = None

        if scapy_pkt.haslayer(TCP):
            protocol = "TCP"
            tcp = scapy_pkt[TCP]
            src_port = tcp.sport
            dst_port = tcp.dport
            flags = str(tcp.flags)  # Scapy tra ve chuoi: "S", "SA", "PA", "FUP"...
            tcp_flags = {
                "SYN": "S" in flags,
                "ACK": "A" in flags,
                "FIN": "F" in flags,
                "RST": "R" in flags,
                "PSH": "P" in flags,
                "URG": "U" in flags,
                "raw_flags": flags,  # Chuoi tho de Rule Engine so khop co (vi du: flags:FUP)
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

        # Payload tho (bytes)
        raw_payload = bytes(scapy_pkt[Raw].load) if scapy_pkt.haslayer(Raw) else b""

        # Tao DecodedPacket co ban
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
        )

        # Tang L7: Parse HTTP neu la traffic Web
        # Kiem tra port de quyet dinh co can parse HTTP hay khong
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
