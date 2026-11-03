"""
Phát hiện bất thường theo ngưỡng thống kê cho tấn công chưa có rule (#42): quét cổng/quét host, flood, cổng hiếm.

Module thuần như `flow.py`: không biết CSDL hay cấu hình, chỉ worker thread của engine gọi `observe`.
Cửa sổ thời gian tính theo `packet.timestamp`, nên đọc lại cùng một pcap luôn cho cùng kết quả.
"""
from collections import Counter, OrderedDict, deque
from typing import Any, Callable, Dict, Optional

from nids.engine.packet import DecodedPacket
from nids.engine.threshold import ThresholdManager

DEFAULTS: Dict[str, Any] = {
    "suppress_seconds": 60,
    "max_tracked": 10000,
    "scan": {"window": 5, "ports": 15, "hosts": 10},
    "flood": {"window": 1, "packets": 500, "syn": 100},
    "common_ports": [20, 21, 22, 23, 25, 53, 67, 68, 80, 110, 123, 143, 161, 443, 445, 993, 995,
                     2222, 3000, 3306, 3389, 5000, 6379, 8000, 8080],
}
COMMON_ICMP_TYPES = {0, 3, 8, 11}   # echo reply, unreachable, echo request, time exceeded
MAX_EVENTS_PER_SOURCE = 10000       # trần số gói nhớ cho một IP trong cửa sổ scan, để flood từ một IP không phình RAM
SWEEP_INTERVAL = 1.0


class _ScanWindow:
    """Các đích (IP, cổng) một nguồn đã mở kết nối tới trong cửa sổ; đếm số đích và số host khác nhau với chi phí O(1)."""

    def __init__(self):
        self.events: deque = deque()
        self.targets: Counter = Counter()
        self.hosts: Counter = Counter()
        self.last_seen = 0.0

    def add(self, ts: float, target, window: float) -> None:
        self.events.append((ts, target))
        self.targets[target] += 1
        self.hosts[target[0]] += 1
        self.last_seen = ts
        while self.events and (ts - self.events[0][0] > window or len(self.events) > MAX_EVENTS_PER_SOURCE):
            _, old = self.events.popleft()
            for counter, key in ((self.targets, old), (self.hosts, old[0])):
                counter[key] -= 1
                if not counter[key]:
                    del counter[key]


class AnomalyDetector:
    """Gói vượt ngưỡng sinh cảnh báo `source_type="ANOMALY"` (`sid=None`) qua `alert_callback`, đã chặn bớt."""

    def __init__(self, cfg: Optional[Dict[str, Any]] = None, alert_callback: Optional[Callable[[dict], None]] = None):
        cfg = cfg or {}
        self.scan = {**DEFAULTS["scan"], **(cfg.get("scan") or {})}
        self.flood = {**DEFAULTS["flood"], **(cfg.get("flood") or {})}
        self.common_ports = set(cfg.get("common_ports") or DEFAULTS["common_ports"])
        self.max_tracked = int(cfg.get("max_tracked", DEFAULTS["max_tracked"]))
        self.alert_callback = alert_callback
        # shortcut: ThresholdManager tính cửa sổ chặn theo giờ hệ thống, replay pcap dài chỉ ra một cảnh báo mỗi loại; đổi sang giờ gói nếu cần đếm chính xác khi replay
        self.threshold = ThresholdManager(default_window_seconds=float(cfg.get("suppress_seconds", DEFAULTS["suppress_seconds"])))
        self._scans: "OrderedDict[str, _ScanWindow]" = OrderedDict()
        self._floods: "OrderedDict[str, tuple]" = OrderedDict()   # dst_ip -> (deque mọi gói, deque SYN)
        self._scanning: Dict[str, float] = {}                      # src_ip -> lần cuối bị đánh dấu scan
        self._last_sweep: Optional[float] = None

    def __len__(self) -> int:
        return len(self._scans) + len(self._floods)

    def observe(self, packet: DecodedPacket) -> None:
        ts = packet.timestamp
        if self._last_sweep is None or ts - self._last_sweep >= SWEEP_INTERVAL:
            self._sweep(ts)
        syn = packet.protocol == "TCP" and bool(packet.tcp_flags.get("SYN")) and not packet.tcp_flags.get("ACK")
        self._check_flood(packet, syn)
        opens = self._opens_connection(packet, syn)
        if opens:
            self._check_scan(packet)
        if opens or packet.protocol == "ICMP":   # type ICMP lạ (timestamp, address mask...) không phải echo nhưng vẫn cần xét
            self._check_rare(packet, syn)

    def _opens_connection(self, packet: DecodedPacket, syn: bool) -> bool:
        """Gói mở kết nối: SYN không ACK, ICMP echo, UDP không xuất phát từ cổng dịch vụ (loại trừ trả lời của server)."""
        if packet.protocol == "TCP":
            return syn
        if packet.protocol == "UDP":
            return packet.src_port not in self.common_ports
        return packet.protocol == "ICMP" and packet.icmp_type == 8

    def _check_scan(self, packet: DecodedPacket) -> None:
        win = self._touch(self._scans, packet.src_ip, _ScanWindow)
        win.add(packet.timestamp, (packet.dst_ip, packet.dst_port), self.scan["window"])
        ports, hosts = len(win.targets), len(win.hosts)
        if ports < self.scan["ports"] and hosts < self.scan["hosts"]:
            return
        self._scanning[packet.src_ip] = packet.timestamp
        if hosts >= self.scan["hosts"]:
            kind, msg = "host_sweep", "ANOMALY Host sweep (one source probing many hosts)"
            evidence = f"{hosts} host trong {self.scan['window']}s: " + ", ".join(sorted(win.hosts)[:20])
        else:
            kind, msg = "port_scan", "ANOMALY Port scan (one source probing many ports)"
            port_list = sorted({p for _, p in win.targets if p is not None})
            evidence = f"{ports} cổng/đích trong {self.scan['window']}s: " + ",".join(map(str, port_list[:30]))
        self._emit(kind, packet, msg, 2, "attempted-recon", evidence, packet.src_ip, "", None)

    def _check_flood(self, packet: DecodedPacket, syn: bool) -> None:
        window = self.flood["window"]
        all_pkts, syns = self._touch(self._floods, packet.dst_ip,
                                     lambda: (deque(maxlen=self.flood["packets"]), deque(maxlen=self.flood["syn"])))
        for hits, hit in ((all_pkts, True), (syns, syn)):
            if hit:
                hits.append(packet.timestamp)
            while hits and packet.timestamp - hits[0] > window:
                hits.popleft()
        if syn and len(syns) >= self.flood["syn"]:
            self._emit("syn_flood", packet, "ANOMALY SYN flood (high SYN rate to one target)", 1, "denial-of-service",
                       f"{len(syns)} SYN trong {window}s tới {packet.dst_ip}", "", packet.dst_ip, None)
        elif len(all_pkts) >= self.flood["packets"]:
            self._emit("packet_flood", packet, "ANOMALY Packet flood (high packet rate to one target)", 1, "denial-of-service",
                       f"{len(all_pkts)} gói trong {window}s tới {packet.dst_ip}", "", packet.dst_ip, None)

    def _check_rare(self, packet: DecodedPacket, syn: bool) -> None:
        last_scan = self._scanning.get(packet.src_ip)
        if last_scan is not None and packet.timestamp - last_scan <= self.scan["window"]:
            return   # đang quét thì mọi cổng đều "hiếm"; cảnh báo scan đã nói đủ
        if packet.protocol == "ICMP":
            rare = packet.icmp_type not in COMMON_ICMP_TYPES
            evidence = f"ICMP type {packet.icmp_type}"
        else:
            port = packet.dst_port
            rare = port is not None and port not in self.common_ports and (syn or port < 1024)
            evidence = f"{packet.protocol} tới cổng {port} (ngoài common_ports)"
        if rare:
            # Chặn theo nguồn: trước khi đủ ngưỡng scan, các cổng đầu của một lượt quét chỉ ra một cảnh báo P3
            self._emit("rare", packet, "ANOMALY Rare port/ICMP type", 3, "misc-activity", evidence, packet.src_ip, "", None)

    def _emit(self, kind: str, packet: DecodedPacket, msg: str, severity: int, classtype: str, evidence: str,
              key_src: str, key_dst: str, key_port: Optional[int]) -> None:
        allow, _ = self.threshold.should_alert(sid=kind, src_ip=key_src, dst_ip=key_dst, dst_port=key_port)
        if not allow or self.alert_callback is None:
            return
        self.alert_callback({
            "timestamp": packet.timestamp, "sid": None, "source_type": "ANOMALY", "msg": msg, "severity": severity,
            "classtype": classtype, "src_ip": packet.src_ip, "src_port": packet.src_port, "dst_ip": packet.dst_ip,
            "dst_port": packet.dst_port, "protocol": packet.protocol, "matched_content": evidence,
        })

    def _touch(self, table: OrderedDict, key: str, factory):
        """Lấy (hoặc tạo) trạng thái của `key`, đưa về cuối bảng; bảng đầy thì bỏ mục lâu nhất không có gói."""
        if key in table:
            table.move_to_end(key)
            return table[key]
        if len(table) >= self.max_tracked:
            table.popitem(last=False)
        table[key] = factory()
        return table[key]

    def _sweep(self, now: float) -> None:
        """Bỏ trạng thái của IP không có gói trong cửa sổ dài nhất (đầu bảng là mục cũ nhất)."""
        self._last_sweep = now
        horizon = max(self.scan["window"], self.flood["window"])
        while self._scans and now - next(iter(self._scans.values())).last_seen > horizon:
            self._scans.popitem(last=False)
        while self._floods:
            all_pkts, _ = next(iter(self._floods.values()))
            if all_pkts and now - all_pkts[-1] <= horizon:
                break
            self._floods.popitem(last=False)
        self._scanning = {ip: t for ip, t in self._scanning.items() if now - t <= self.scan["window"]}
