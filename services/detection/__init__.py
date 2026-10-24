import re
from dataclasses import dataclass, field
from typing import List, Optional

# Các buffer mà content/pcre có thể gắn vào (sticky buffer kiểu Snort 3).
# pkt_data = payload thô; các buffer http_* chỉ có khi gói tin được parse thành HTTP.
BUFFER_PKT_DATA = "pkt_data"
HTTP_BUFFERS = {"http_uri", "http_header", "http_client_body", "http_method"}
STICKY_BUFFERS = HTTP_BUFFERS | {BUFFER_PKT_DATA}


@dataclass
class ContentMatch:
    """Một option content:"..." cùng các modifier của nó (nocase, offset, depth, distance, within...)."""
    pattern: str                 # Chuỗi đã giải mã (hex |..| và escape \" \; \\)
    buffer: str = BUFFER_PKT_DATA
    field: Optional[str] = None  # Tên header khi dùng http_header:field <name>
    nocase: bool = False
    negated: bool = False        # content:!"..."
    fast_pattern: bool = False
    offset: Optional[int] = None
    depth: Optional[int] = None
    distance: Optional[int] = None
    within: Optional[int] = None


@dataclass
class PcreMatch:
    """Một option pcre:"/.../flags" đã biên dịch, gắn vào buffer hiện hành."""
    pattern: str                 # Chuỗi gốc "/.../flags"
    regex: re.Pattern = field(repr=False, compare=False)
    buffer: str = BUFFER_PKT_DATA
    field: Optional[str] = None


@dataclass
class DetectionFilter:
    """detection_filter:track by_src|by_dst, count N, seconds S;"""
    track: str                   # "by_src" hoặc "by_dst"
    count: int
    seconds: int


@dataclass
class SnortRule:
    """Mô hình dữ liệu của một Rule đã được phân tích cú pháp."""
    action: str                  # alert, log, drop
    protocol: str                # tcp, udp, icmp, ip
    src_ip: str
    src_port: str
    direction: str               # -> hoặc <>
    dst_ip: str
    dst_port: str

    # Options phổ biến
    msg: str = ""
    sid: int = 0
    rev: int = 1
    classtype: str = ""
    severity: int = 2            # Lấy từ option priority: 1: High, 2: Med, 3: Low

    # Payload patterns (theo thứ tự xuất hiện trong rule)
    contents: List[ContentMatch] = field(default_factory=list)
    pcres: List[PcreMatch] = field(default_factory=list)

    # Non-payload options
    flags: Optional[str] = None          # TCP flags: S, FUP, 0, S+, SF*...
    flow: List[str] = field(default_factory=list)  # to_server, established, stateless...
    dsize: Optional[str] = None          # >800, <10, 100<>200
    itype: Optional[str] = None
    icode: Optional[str] = None
    detection_filter: Optional[DetectionFilter] = None

    # Option hợp lệ trong Snort nhưng engine không xử lý (để cảnh báo khi nạp)
    unsupported_options: List[str] = field(default_factory=list)

    raw_rule: str = ""
    is_enabled: bool = True
