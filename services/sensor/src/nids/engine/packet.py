from dataclasses import dataclass, field
from typing import Optional, Dict

@dataclass
class DecodedPacket:
    """Đại diện cho gói tin sau khi được bóc tách từ tầng L2-L4."""
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: str  # TCP, UDP, ICMP
    tcp_flags: Dict[str, bool] = field(default_factory=dict)
    icmp_type: Optional[int] = None
    icmp_code: Optional[int] = None
    raw_payload: bytes = b""
    raw_packet: bytes = b""
    tcp_seq: Optional[int] = None  # Sequence number của TCP; None nếu không phải TCP hoặc gói tự dựng trong test

    # Trường do HTTP Parser điền bổ sung (L7)
    http_data: Optional["ParsedHTTPRequest"] = None

    # True nếu đây là gói ảo chứa payload đã ghép từ nhiều segment (xem stream.py)
    reassembled: bool = False

@dataclass
class ParsedHTTPRequest:
    """Dữ liệu tầng ứng dụng HTTP được bóc tách bởi http_parser.py."""
    method: str = ""
    uri: str = ""
    path: str = ""
    query_params: str = ""
    version: str = "HTTP/1.1"
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
