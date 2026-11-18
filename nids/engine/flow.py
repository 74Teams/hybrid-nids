"""
Gom gói tin thành flow (cuộc trao đổi hai chiều giữa hai đầu mút).

Module này chỉ chứa logic gom flow, không biết CSDL hay cấu hình, để các phần khác
(flow log, đặc trưng AI) dùng lại được. Mọi mốc thời gian lấy từ `packet.timestamp`,
nên đọc lại cùng một file pcap luôn cho cùng kết quả.
"""
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from nids.engine.packet import DecodedPacket

FlowKey = Tuple[str, Tuple[str, int], Tuple[str, int]]

# Lý do một flow được xuất ra
END_FIN = "fin"
END_RST = "rst"
END_IDLE = "idle"
END_ACTIVE = "active"
END_EVICTED = "evicted"
END_SHUTDOWN = "shutdown"

# Quét timeout toàn bảng tối đa một lần mỗi ngần này giây (theo giờ của gói)
SWEEP_INTERVAL = 1.0


@dataclass
class Flow:
    """Một flow: bên gửi gói đầu tiên là nguồn (src), trừ khi gói đầu là SYN-ACK."""
    protocol: str
    src_ip: str
    src_port: Optional[int]
    dst_ip: str
    dst_port: Optional[int]
    first_seen: float
    last_seen: float
    fwd_packets: int = 0
    bwd_packets: int = 0
    fwd_bytes: int = 0
    bwd_bytes: int = 0
    tcp_flags: str = ""
    alert_count: int = 0
    end_reason: str = ""

    # Bộ đếm cho đặc trưng AI (nids/ai/features.py); chỉ là số cộng dồn, không lưu từng gói
    fwd_len_min: int = 0
    fwd_len_max: int = 0
    fwd_len_sq: float = 0.0          # tổng bình phương độ dài gói chiều đi, để tính độ lệch chuẩn
    bwd_len_min: int = 0
    bwd_len_max: int = 0
    bwd_len_sq: float = 0.0
    fwd_payload_bytes: int = 0
    bwd_payload_bytes: int = 0
    iat_sum: float = 0.0             # IAT: khoảng thời gian giữa hai gói liên tiếp của flow
    iat_sq: float = 0.0
    iat_min: float = 0.0
    iat_max: float = 0.0
    fwd_iat_sum: float = 0.0
    bwd_iat_sum: float = 0.0
    syn_count: int = 0
    ack_count: int = 0
    fin_count: int = 0
    rst_count: int = 0
    psh_count: int = 0
    urg_count: int = 0

    # Trạng thái nội bộ để nhận biết flow TCP đang đóng
    _fin_fwd: bool = field(default=False, repr=False, compare=False)
    _fin_bwd: bool = field(default=False, repr=False, compare=False)
    _closing_since: Optional[float] = field(default=None, repr=False, compare=False)

    _last_fwd_ts: Optional[float] = field(default=None, repr=False, compare=False)
    _last_bwd_ts: Optional[float] = field(default=None, repr=False, compare=False)
    @property
    def duration(self) -> float:
        return max(0.0, self.last_seen - self.first_seen)


def flow_key(packet: DecodedPacket) -> FlowKey:
    """Khoá chuẩn hoá hai chiều: gói đi và gói về của cùng một flow có cùng khoá."""
    a = (packet.src_ip, packet.src_port or 0)
    b = (packet.dst_ip, packet.dst_port or 0)
    return (packet.protocol, *sorted((a, b)))


def _is_syn_only(packet: DecodedPacket) -> bool:
    flags = packet.tcp_flags
    return bool(flags.get("SYN")) and not flags.get("ACK")


def _is_syn_ack(packet: DecodedPacket) -> bool:
    flags = packet.tcp_flags
    return bool(flags.get("SYN")) and bool(flags.get("ACK"))


class FlowTracker:
    """Bảng flow đang mở. Chỉ một thread được gọi vào đối tượng này (worker thread của engine)."""

    def __init__(self, idle_timeout: float = 30.0, active_timeout: float = 120.0,
                 closing_timeout: float = 2.0, max_flows: int = 100000):
        self.idle_timeout = idle_timeout
        self.active_timeout = active_timeout
        self.closing_timeout = closing_timeout
        self.max_flows = max_flows
        # Sắp theo thời điểm cập nhật gần nhất: flow lâu nhất không có gói nằm đầu bảng
        self._flows: "OrderedDict[FlowKey, Flow]" = OrderedDict()
        self._last_sweep: Optional[float] = None

    def __len__(self) -> int:
        return len(self._flows)

    def update(self, packet: DecodedPacket, alert_count: int = 0) -> List[Flow]:
        """Cộng gói vào flow của nó; trả về các flow vừa kết thúc (có thể rỗng)."""
        now = packet.timestamp
        finished: List[Flow] = []
        if self._last_sweep is None or now - self._last_sweep >= SWEEP_INTERVAL:
            finished += self.expire(now)

        key = flow_key(packet)
        flow = self._flows.get(key)
        if flow is not None:
            reason = self._expired_reason(flow, now)
            # SYN mới trên flow đang đóng nghĩa là cổng được dùng lại cho kết nối khác
            if reason is None and flow._closing_since is not None and _is_syn_only(packet):
                reason = flow.end_reason
            if reason is not None:
                finished.append(self._finish(key, reason))
                flow = None

        if flow is None:
            if len(self._flows) >= self.max_flows:
                oldest = next(iter(self._flows))
                finished.append(self._finish(oldest, END_EVICTED))
            flow = self._new_flow(packet)
            self._flows[key] = flow
        else:
            self._flows.move_to_end(key)

        self._account(flow, packet, alert_count)
        return finished

    def expire(self, now: float) -> List[Flow]:
        """Xuất các flow hết hạn (idle, active, hoặc đã đóng đủ `closing_timeout`) tính đến `now`."""
        self._last_sweep = now
        expired = []
        for key, flow in self._flows.items():
            reason = self._expired_reason(flow, now)
            if reason is not None:
                expired.append((key, reason))
        return [self._finish(key, reason) for key, reason in expired]

    def flush(self) -> List[Flow]:
        """Xuất mọi flow còn mở (khi engine dừng hoặc đọc hết pcap)."""
        finished = []
        for key in list(self._flows):
            finished.append(self._finish(key, END_SHUTDOWN))
        return finished

    def _expired_reason(self, flow: Flow, now: float) -> Optional[str]:
        if flow._closing_since is not None and now - flow._closing_since >= self.closing_timeout:
            return flow.end_reason
        if now - flow.last_seen >= self.idle_timeout:
            return END_IDLE
        if now - flow.first_seen >= self.active_timeout:
            return END_ACTIVE
        return None

    def _finish(self, key: FlowKey, reason: str) -> Flow:
        flow = self._flows.pop(key)
        flow.end_reason = flow.end_reason or reason
        return flow

    @staticmethod
    def _new_flow(packet: DecodedPacket) -> Flow:
        src = (packet.src_ip, packet.src_port)
        dst = (packet.dst_ip, packet.dst_port)
        if packet.protocol == "TCP" and _is_syn_ack(packet):
            src, dst = dst, src  # bắt được giữa chừng: client là bên đã gửi SYN trước đó
        return Flow(protocol=packet.protocol, src_ip=src[0], src_port=src[1],
                    dst_ip=dst[0], dst_port=dst[1],
                    first_seen=packet.timestamp, last_seen=packet.timestamp)

    @staticmethod
    def _account(flow: Flow, packet: DecodedPacket, alert_count: int) -> None:
        ts = packet.timestamp
        before = flow.fwd_packets + flow.bwd_packets
        if before > 0:                                   # AI: IAT tính từ gói thứ hai
            iat = max(0.0, ts - flow.last_seen)          # gói đến trễ thứ tự thì coi IAT = 0
            flow.iat_sum += iat
            flow.iat_sq += iat * iat
            flow.iat_min = iat if before == 1 else min(flow.iat_min, iat)
            flow.iat_max = max(flow.iat_max, iat)

        forward = packet.src_ip == flow.src_ip and (packet.src_port or 0) == (flow.src_port or 0)
        size = len(packet.raw_packet) or len(packet.raw_payload)
        payload = len(packet.raw_payload)
        if forward:
            flow.fwd_len_min = size if flow.fwd_packets == 0 else min(flow.fwd_len_min, size)   # AI
            flow.fwd_len_max = max(flow.fwd_len_max, size)
            flow.fwd_len_sq += size * size
            flow.fwd_payload_bytes += payload
            if flow._last_fwd_ts is not None:
                flow.fwd_iat_sum += max(0.0, ts - flow._last_fwd_ts)
            flow._last_fwd_ts = ts
            flow.fwd_packets += 1
            flow.fwd_bytes += size
        else:
            flow.bwd_len_min = size if flow.bwd_packets == 0 else min(flow.bwd_len_min, size)   # AI
            flow.bwd_len_max = max(flow.bwd_len_max, size)
            flow.bwd_len_sq += size * size
            flow.bwd_payload_bytes += payload
            if flow._last_bwd_ts is not None:
                flow.bwd_iat_sum += max(0.0, ts - flow._last_bwd_ts)
            flow._last_bwd_ts = ts
            flow.bwd_packets += 1
            flow.bwd_bytes += size
        flow.last_seen = max(flow.last_seen, ts)
        flow.alert_count += alert_count

        if packet.protocol != "TCP":
            return
        flags = packet.tcp_flags
        flow.syn_count += bool(flags.get("SYN"))         # AI: True cộng như 1, False như 0
        flow.ack_count += bool(flags.get("ACK"))
        flow.fin_count += bool(flags.get("FIN"))
        flow.rst_count += bool(flags.get("RST"))
        flow.psh_count += bool(flags.get("PSH"))
        flow.urg_count += bool(flags.get("URG"))
        raw_flags = flags.get("raw_flags", "")
        flow.tcp_flags = "".join(sorted(set(flow.tcp_flags) | set(raw_flags)))
        if packet.tcp_flags.get("RST") and flow._closing_since is None:
            flow.end_reason, flow._closing_since = END_RST, packet.timestamp
        elif packet.tcp_flags.get("FIN"):
            if forward:
                flow._fin_fwd = True
            else:
                flow._fin_bwd = True
            if flow._fin_fwd and flow._fin_bwd and flow._closing_since is None:
                flow.end_reason, flow._closing_since = END_FIN, packet.timestamp
