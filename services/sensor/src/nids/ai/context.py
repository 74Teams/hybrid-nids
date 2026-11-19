"""
Đặc trưng ngữ cảnh nhiều flow cho AI (PLAN-011 mục 6.3).

Một flow quét cổng chỉ có 2 gói (SYN đi, RST về), giống hệt một kết nối nhầm cổng bị từ chối. Dấu hiệu thật là
"một IP gõ hàng trăm cổng trong vài giây", chỉ thấy được khi nhìn nhiều flow. `FlowContext` nhớ các flow vừa kết
thúc theo IP nguồn và IP đích trong hai cửa sổ thời gian, rồi trả về các số đếm cho flow đang xét:

- cửa sổ dài (60 giây): số đếm lớn, cho biết "IP này đã làm gì trong cả phút qua";
- cửa sổ ngắn (5 giây): cho biết **tốc độ** hiện tại. Cột 60 giây chỉ đầy sau khoảng 20 giây kể từ lúc đợt quét
  bắt đầu, nên 20 giây đầu của mỗi đợt trông như ít hoạt động; cửa sổ ngắn đầy sau vài giây nên không có vùng mù đó.

Module thuần (không biết CSDL hay `SETTINGS`), dùng chung cho `tools/ai/build_dataset.py` (lúc học) và
`AITrafficWorker` (lúc chạy) để hai bên cho cùng kết quả.

Quy ước (đổi là phải dựng lại dataset và học lại):

- Đồng hồ không bao giờ lùi: `đồng hồ = max(đồng hồ, flow.last_seen)`. `FlowTracker` xuất flow không theo thứ
  tự `last_seen` (flow RST ra sau 2 giây, flow idle sau 30 giây), nên mỗi flow được ghi với **mốc = giá trị đồng hồ
  lúc nhận**, không phải `last_seen` của riêng nó. Nhờ đó mốc luôn tăng dần và hàng đợi dọn đúng. Vì vậy cửa sổ
  ngắn đo "số flow được xuất trong 5 giây vừa qua", không phải số flow bắt đầu trong 5 giây đó.
- Cửa sổ gồm các mục có mốc > đồng hồ − `window`, tính cả flow đang xét (bộ đếm nhỏ nhất là 1).
- Cửa sổ dài phải lớn hơn `idle_timeout` cộng khoảng quét của `FlowTracker`, nếu không flow idle ra trễ không còn
  nằm cùng cửa sổ với các flow cùng thời. Module này không tự kiểm được; nơi tạo `FlowTracker` phải kiểm.
- Thứ tự gọi `update` là thứ tự `FlowTracker` xuất flow. Thứ tự này là một phần của hợp đồng với mô hình.
"""
from collections import Counter, OrderedDict, deque
from typing import Deque, Dict, Optional, Tuple

from nids.engine.flow import Flow

DEFAULT_WINDOW = 60.0
DEFAULT_SHORT_WINDOW = 5.0
DEFAULT_MAX_TRACKED = 50000
DEFAULT_MAX_PER_IP = 20000
SHORT_FLOW_PACKETS = 2        # flow có không quá ngần này gói được coi là "gõ cửa"

CONTEXT_FEATURE_NAMES = ["src_flows_60s", "src_dst_ports_60s", "src_dst_hosts_60s", "src_short_ratio_60s",
                         "dst_flows_60s"]
SHORT_CONTEXT_FEATURE_NAMES = ["src_flows_5s", "src_dst_ports_5s", "src_dst_hosts_5s", "src_port_diversity_5s",
                               "dst_flows_5s"]

Entry = Tuple[float, str, int, bool]      # (mốc, IP đích, cổng đích, flow ngắn)


class _SrcState:
    """Các flow gần đây của một IP nguồn, kèm bộ đếm để mỗi lần cập nhật là O(1) trung bình."""

    def __init__(self) -> None:
        self.entries: Deque[Entry] = deque()
        self.ports: Counter = Counter()
        self.hosts: Counter = Counter()
        self.short = 0

    def add(self, entry: Entry) -> None:
        self.entries.append(entry)
        _, host, port, short = entry
        self.ports[port] += 1
        self.hosts[host] += 1
        self.short += short

    def pop_oldest(self) -> None:
        _, host, port, short = self.entries.popleft()
        for counter, key in ((self.ports, port), (self.hosts, host)):
            counter[key] -= 1
            if counter[key] <= 0:
                del counter[key]
        self.short -= short

    def prune(self, cutoff: float, max_entries: int) -> None:
        while self.entries and (self.entries[0][0] <= cutoff or len(self.entries) > max_entries):
            self.pop_oldest()


class _Window:
    """Một cửa sổ thời gian: bảng theo IP nguồn và theo IP đích."""

    def __init__(self, window: float, max_tracked: int, max_per_ip: int):
        self.window = window
        self.max_tracked = max_tracked
        self.max_per_ip = max_per_ip
        self.last_sweep: Optional[float] = None
        # Sắp theo lần cập nhật gần nhất: IP lâu nhất không có flow nằm đầu bảng
        self.src: "OrderedDict[str, _SrcState]" = OrderedDict()
        self.dst: "OrderedDict[str, Deque[float]]" = OrderedDict()

    def add(self, clock: float, flow: Flow, short: bool) -> Tuple[_SrcState, int]:
        """Ghi flow vào cửa sổ; trả về trạng thái của IP nguồn và số flow tới IP đích (đã tính flow này)."""
        cutoff = clock - self.window
        if self.last_sweep is None or clock - self.last_sweep >= self.window:
            self._sweep(cutoff)
            self.last_sweep = clock

        entry: Entry = (clock, flow.dst_ip, flow.dst_port or 0, short)
        src = self.src.get(flow.src_ip)
        if src is None:
            if len(self.src) >= self.max_tracked:
                self.src.popitem(last=False)           # bỏ IP lâu nhất không có flow
            src = self.src[flow.src_ip] = _SrcState()
        else:
            self.src.move_to_end(flow.src_ip)
        src.prune(cutoff, self.max_per_ip - 1)
        src.add(entry)

        marks = self.dst.get(flow.dst_ip)
        if marks is None:
            if len(self.dst) >= self.max_tracked:
                self.dst.popitem(last=False)
            marks = self.dst[flow.dst_ip] = deque()
        else:
            self.dst.move_to_end(flow.dst_ip)
        while marks and (marks[0] <= cutoff or len(marks) >= self.max_per_ip):
            marks.popleft()
        marks.append(clock)
        return src, len(marks)

    def _sweep(self, cutoff: float) -> None:
        """Bỏ IP không còn flow nào trong cửa sổ. Bảng sắp theo lần cập nhật nên chỉ cần duyệt từ đầu."""
        for table, last_mark in ((self.src, lambda s: s.entries[-1][0] if s.entries else float("-inf")),
                                 (self.dst, lambda d: d[-1] if d else float("-inf"))):
            while table:
                oldest = next(iter(table))
                if last_mark(table[oldest]) > cutoff:
                    break
                del table[oldest]


class FlowContext:
    def __init__(self, window: float = DEFAULT_WINDOW, max_tracked: int = DEFAULT_MAX_TRACKED,
                 max_per_ip: int = DEFAULT_MAX_PER_IP, short_window: float = DEFAULT_SHORT_WINDOW):
        self.window = window
        self.short_window = short_window
        self.max_tracked = max_tracked
        self.max_per_ip = max_per_ip
        self._clock: Optional[float] = None
        self._long = _Window(window, max_tracked, max_per_ip)
        self._short = _Window(short_window, max_tracked, max_per_ip)

    def __len__(self) -> int:
        return len(self._long.src)

    def update(self, flow: Flow) -> Dict[str, float]:
        """Ghi nhận flow vừa kết thúc, trả về đặc trưng ngữ cảnh của chính flow đó (đã tính cả nó)."""
        if self._clock is None or flow.last_seen > self._clock:
            self._clock = flow.last_seen
        clock = self._clock
        short = (flow.fwd_packets + flow.bwd_packets) <= SHORT_FLOW_PACKETS

        src, dst_count = self._long.add(clock, flow, short)
        count = len(src.entries)
        result = {
            "src_flows_60s": float(count),
            "src_dst_ports_60s": float(len(src.ports)),
            "src_dst_hosts_60s": float(len(src.hosts)),
            "src_short_ratio_60s": src.short / count,
            "dst_flows_60s": float(dst_count),
        }
        src, dst_count = self._short.add(clock, flow, short)
        count = len(src.entries)
        result.update({
            "src_flows_5s": float(count),
            "src_dst_ports_5s": float(len(src.ports)),
            "src_dst_hosts_5s": float(len(src.hosts)),
            # Số cổng khác nhau trên mỗi flow: gần 1 khi mỗi flow gõ một cổng khác (quét cổng), nhỏ khi nhiều
            # flow tới cùng cổng (duyệt web). Không phụ thuộc tốc độ nên đúng ngay từ những giây đầu của đợt quét.
            "src_port_diversity_5s": len(src.ports) / count,
            "dst_flows_5s": float(dst_count),
        })
        return result
