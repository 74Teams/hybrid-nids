"""
Biên dịch phần header của rule Snort (IP và cổng) thành đối tượng so khớp.

Hiểu các dạng: `any`, giá trị đơn (`80`, `10.0.0.1`), dải cổng (`1:1024`, `:1024`, `1024:`), mạng CIDR
(`10.0.0.0/8`), danh sách lồng nhau (`[80,443,8000:8080]`), phủ định (`!80`, `![80,443]`) và biến
(`$HTTP_PORTS`, `!$HOME_NET`). Dạng không hiểu được ném `ValueError` ngay lúc nạp rule, để rule sai bị bỏ
kèm cảnh báo thay vì âm thầm khớp mọi gói.

Module thuần: không đọc cấu hình, biến được truyền vào từ bên ngoài.
"""
import ipaddress
import logging
import re
from dataclasses import dataclass
from functools import lru_cache
from typing import Dict, Optional, Tuple, Union

logger = logging.getLogger("nids.rules")

# Biến mặc định khi settings.yaml không khai báo (giá trị chuẩn của Snort, rút gọn cho lab)
DEFAULT_RULE_VARIABLES: Dict[str, str] = {
    "HOME_NET": "any",
    "EXTERNAL_NET": "any",
    "HTTP_SERVERS": "$HOME_NET",
    "SQL_SERVERS": "$HOME_NET",
    "SMTP_SERVERS": "$HOME_NET",
    "TELNET_SERVERS": "$HOME_NET",
    "SIP_SERVERS": "$HOME_NET",
    "HTTP_PORTS": "80,8080,8000,3000,5000",
    "ORACLE_PORTS": "1521",
    "SIP_PORTS": "5060,5061",
    "SSH_PORTS": "22",
    "FTP_PORTS": "21",
    "FILE_DATA_PORTS": "$HTTP_PORTS,110,143",
}

MAX_PORT = 65535
IP_CACHE_SIZE = 4096  # IP nguồn do attacker kiểm soát nên bộ nhớ đệm phải có giới hạn

_VARIABLE = re.compile(r"\$([A-Za-z_][A-Za-z0-9_]*)")

Item = Union[Tuple[int, int], "ipaddress.IPv4Network", "ipaddress.IPv6Network"]


@dataclass(frozen=True)
class _Node:
    """Một nút của biểu thức: `any`, một giá trị (dải cổng hoặc mạng), hoặc danh sách các nút con.

    `positives`/`negatives` được tính sẵn lúc dựng nút để `test` không cấp phát gì trên đường nóng.
    """
    kind: str                       # "any", "item" hoặc "list"
    negated: bool = False
    item: Optional[Item] = None
    children: Tuple["_Node", ...] = ()
    positives: Tuple["_Node", ...] = ()
    negatives: Tuple["_Node", ...] = ()

    def test(self, value) -> bool:
        """Khớp chưa tính phủ định của chính nút này."""
        if self.kind == "any":
            return True
        if self.kind == "item":
            return _item_contains(self.item, value)
        if self.positives and not any(c.test(value) for c in self.positives):
            return False
        return not any(c.test(value) for c in self.negatives)

    def always(self) -> bool:
        """Nút khớp mọi giá trị (trước khi tính phủ định)."""
        if self.kind == "any":
            return True
        if self.kind == "item":
            return False
        return not self.negatives and (not self.positives or any(c.always() for c in self.positives))


def _list_node(negated: bool, children: Tuple[_Node, ...]) -> _Node:
    return _Node("list", negated, children=children,
                 positives=tuple(c for c in children if not c.negated),
                 negatives=tuple(c for c in children if c.negated))


def _item_contains(item: Item, value) -> bool:
    if isinstance(item, tuple):
        return item[0] <= value <= item[1]
    return value in item


# ── TÁCH VÀ PARSE ────────────────────────────────────────

def _matching_close(text: str) -> int:
    """Vị trí dấu `]` đóng dấu `[` đầu chuỗi; -1 nếu không có."""
    depth = 0
    for i, ch in enumerate(text):
        if ch == "[":
            depth += 1
        elif ch == "]":
            depth -= 1
            if depth == 0:
                return i
    return -1


def _split_list(inner: str):
    """Tách theo dấu phẩy nằm ngoài mọi cặp ngoặc."""
    parts, depth, start = [], 0, 0
    for i, ch in enumerate(inner):
        if ch == "[":
            depth += 1
        elif ch == "]":
            depth -= 1
            if depth < 0:
                raise ValueError(f"thừa dấu ']' trong: {inner}")
        elif ch == "," and depth == 0:
            parts.append(inner[start:i])
            start = i + 1
    if depth != 0:
        raise ValueError(f"thiếu dấu ']' trong: {inner}")
    parts.append(inner[start:])
    return parts


def _substitute(text: str, variables: Dict[str, str], stack: Tuple[str, ...] = ()) -> str:
    """Thay `$BIEN` bằng `[giá trị]`, đệ quy; bọc ngoặc để phủ định `!$BIEN` áp dụng cho cả giá trị."""
    def replace(match):
        name = match.group(1)
        if name in stack:
            raise ValueError(f"biến tham chiếu vòng: {' -> '.join(stack + (name,))}")
        if name not in variables:
            raise ValueError(f"biến chưa khai báo: ${name}")
        return "[" + _substitute(variables[name], variables, stack + (name,)) + "]"
    return _VARIABLE.sub(replace, text)


def _parse_node(text: str, parse_atom, source: str) -> _Node:
    text = text.strip()
    negated = text.startswith("!")
    if negated:
        text = text[1:].strip()
    if not text:
        raise ValueError(f"giá trị rỗng trong: {source}")
    if text.startswith("["):
        close = _matching_close(text)
        if close == -1:
            raise ValueError(f"thiếu dấu ']' trong: {source}")
        if close != len(text) - 1:
            raise ValueError(f"ký tự thừa sau dấu ']' trong: {source}")
        parts = _split_list(text[1:-1])
        if any(not p.strip() for p in parts):
            raise ValueError(f"danh sách có phần tử rỗng trong: {source}")
        node = _list_node(negated, tuple(_parse_node(p, parse_atom, source) for p in parts))
    elif text.lower() == "any":
        node = _Node("any", negated)
    else:
        node = _Node("item", negated, item=parse_atom(text))
    if node.negated and node.always():
        raise ValueError(f"'!any' không khớp gói nào (viết nhầm hoặc biến có giá trị any): {source}")
    return node


def _parse_port_atom(text: str) -> Tuple[int, int]:
    low_text, sep, high_text = text.partition(":")
    try:
        low = int(low_text) if low_text else 0
        high = int(high_text) if high_text else MAX_PORT
        if not sep:
            high = low
    except ValueError:
        raise ValueError(f"cổng không hợp lệ: {text}") from None
    if not (0 <= low <= MAX_PORT and 0 <= high <= MAX_PORT):
        raise ValueError(f"cổng nằm ngoài 0-{MAX_PORT}: {text}")
    if low > high:
        raise ValueError(f"dải cổng bị ngược: {text}")
    return low, high


def _parse_addr_atom(text: str):
    try:
        return ipaddress.ip_network(text, strict=False)  # chấp nhận 192.168.1.1/24
    except ValueError:
        raise ValueError(f"địa chỉ IP không hợp lệ: {text}") from None


@lru_cache(maxsize=IP_CACHE_SIZE)
def _parse_ip(text: str):
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        return None


# ── ĐỐI TƯỢNG SO KHỚP ────────────────────────────────────

_ALL_PORTS = (1 << (MAX_PORT + 1)) - 1
_PORT_TABLES: Dict[str, bytes] = {}  # biểu thức cổng đã thay biến -> bảng bit; rule giống nhau dùng chung một bảng


def _port_mask(node: _Node) -> int:
    """Tập cổng khớp dưới dạng số nguyên 65536 bit, chưa tính phủ định của chính nút."""
    if node.kind == "any":
        return _ALL_PORTS
    if node.kind == "item":
        low, high = node.item
        return ((1 << (high - low + 1)) - 1) << low
    mask = _ALL_PORTS
    if node.positives:
        mask = 0
        for child in node.positives:
            mask |= _port_mask(child)
    for child in node.negatives:
        mask &= ~_port_mask(child)
    return mask


def _port_table(expanded: str, root: _Node) -> bytes:
    table = _PORT_TABLES.get(expanded)
    if table is None:
        mask = _port_mask(root)
        if root.negated:
            mask ^= _ALL_PORTS
        table = _PORT_TABLES[expanded] = mask.to_bytes((MAX_PORT + 1) // 8, "little")
    return table


@dataclass(frozen=True)
class PortSpec:
    """Biểu thức cổng đã biên dịch thành bảng bit, nên `matches` là một phép tra O(1) trên đường nóng.

    `port in spec` tương đương `spec.matches(port)`.
    """
    text: str
    root: _Node
    wildcard: bool = False
    table: bytes = b""

    def matches(self, port: Optional[int]) -> bool:
        """Cổng None (ICMP không có cổng) chỉ khớp biểu thức `any`, kể cả khi viết `!80`."""
        if self.wildcard:
            return True
        if port is None or not 0 <= port <= MAX_PORT:
            return False
        return bool(self.table[port >> 3] >> (port & 7) & 1)

    def __contains__(self, port) -> bool:
        return self.matches(port)


@dataclass(frozen=True)
class AddrSpec:
    """Biểu thức IP đã biên dịch."""
    text: str
    root: _Node
    wildcard: bool = False

    def matches(self, ip: Optional[str]) -> bool:
        """IP rỗng hoặc sai định dạng chỉ khớp `any`: hàm này chạy trên worker thread nên không được ném lỗi."""
        if self.wildcard:
            return True
        address = _parse_ip(ip) if ip else None
        if address is None:
            return False
        return self.root.test(address) != self.root.negated

    def __contains__(self, ip) -> bool:
        return self.matches(ip)


def parse_ports(text: str, variables: Optional[Dict[str, str]] = None) -> PortSpec:
    """Biên dịch biểu thức cổng; ném ValueError nếu không hiểu được."""
    expanded = _substitute(text, variables or {})
    root = _parse_node(expanded, _parse_port_atom, text)
    wildcard = not root.negated and root.always()
    return PortSpec(text, root, wildcard, b"" if wildcard else _port_table(expanded, root))


def parse_addrs(text: str, variables: Optional[Dict[str, str]] = None) -> AddrSpec:
    """Biên dịch biểu thức IP; ném ValueError nếu không hiểu được."""
    expanded = _substitute(text, variables or {})
    root = _parse_node(expanded, _parse_addr_atom, text)
    return AddrSpec(text, root, not root.negated and root.always())


def http_ports(variables: Dict[str, str]) -> PortSpec:
    """Tập cổng HTTP cho decoder. Cấu hình sai thì ghi lỗi và dùng mặc định thay vì làm sập engine lúc import."""
    try:
        return parse_ports("$HTTP_PORTS", variables)
    except ValueError as e:
        logger.error("HTTP_PORTS trong cấu hình không hợp lệ (%s), dùng mặc định %s",
                     e, DEFAULT_RULE_VARIABLES["HTTP_PORTS"])
        return parse_ports("$HTTP_PORTS", DEFAULT_RULE_VARIABLES)  # qua biến để chuỗi "80,8080" được bọc thành danh sách


ANY_PORTS = parse_ports("any")
ANY_ADDRS = parse_addrs("any")
