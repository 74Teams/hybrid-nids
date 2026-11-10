"""
Đọc nhãn CIC-IDS2017 và gắn nhãn cho flow của engine.

Nguồn nhãn là các file CSV trong thư mục `TrafficLabelling_` của CIC-IDS2017: mỗi dòng là một flow do
CICFlowMeter tính, có IP, cổng, protocol, giờ và cột `Label`. Module này dựng lại khoá flow giống hệt
`nids.engine.flow.flow_key`, nên flow do engine gom từ pcap gốc tra được nhãn của chính nó.

Hai bẫy của cột `Timestamp`:
- Kiểu 12 giờ nhưng không có AM/PM: `7/7/2017 2:09` là 14:09. Giờ làm việc của dataset là 8h-17h,
  nên giờ 1..7 luôn là buổi chiều.
- Là giờ ADT (UTC-3). File thứ Hai có cả giây (`03/07/2017 08:55:58`), các file khác chỉ tới phút.
"""
import logging
import re
from bisect import bisect_left, bisect_right
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Sequence, Tuple, Union

import pandas as pd

from nids.engine.flow import Flow, FlowKey

logger = logging.getLogger("nids.eval")

ADT = timezone(timedelta(hours=-3))
PROTOCOLS = {6: "TCP", 17: "UDP", 1: "ICMP"}

BENIGN = "BENIGN"
UNLABELED = "UNLABELED"

# Máy điều khiển botnet Ares. Các máy nhiễm gọi về IP này cả ngoài khung giờ Bot của CSV, và những flow đó
# bị gắn BENIGN (Engelen và cộng sự, "Troubleshooting an Intrusion Detection Dataset: the CICIDS2017 Case
# Study", IEEE SPW 2021; kiểm tra ngày 10/11/2026: 42 flow tới IP này lúc 14:09-14:19 thứ Sáu đều là BENIGN).
C2_IP = "205.174.165.73"

# Nhãn gốc (đã chuẩn hoá bằng `_normalize_raw`) → lớp gộp dùng để đo và huấn luyện
GROUPS = {
    "BENIGN": BENIGN,
    "PortScan": "PortScan",
    "DDoS": "DDoS",
    "Bot": "Bot",
    "DoS Hulk": "DoS",
    "DoS GoldenEye": "DoS",
    "DoS slowloris": "DoS",
    "DoS Slowhttptest": "DoS",
    "FTP-Patator": "BruteForce",
    "SSH-Patator": "BruteForce",
    "Web Attack Brute Force": "WebAttack",
    "Web Attack XSS": "WebAttack",
    "Web Attack Sql Injection": "WebAttack",
    "Heartbleed": "Heartbleed",
    "Infiltration": "Infiltration",
}

# Dung sai khi so giờ của flow với giờ trong CSV (CSV chỉ chính xác tới phút)
DEFAULT_TOLERANCE = 120.0
# Hai lần xuất hiện cùng nhãn cách nhau quá ngần này giây thì coi là hai đợt tấn công khác nhau
EPISODE_GAP = 300.0

CSV_COLUMNS = ("Source IP", "Source Port", "Destination IP", "Destination Port", "Protocol", "Timestamp", "Label")

_TIMESTAMP = re.compile(
    r"^\s*(\d{1,2})/(\d{1,2})/(\d{4})\s+(\d{1,2}):(\d{2})(?::(\d{2}))?\s*([AaPp][Mm])?\s*$"
)


def parse_cic_timestamp(text: str) -> float:
    """`d/m/yyyy h:mm[:ss]` theo giờ ADT của CIC-IDS2017 → epoch (giây, UTC).

    Không có AM/PM thì giờ 1..7 được hiểu là buổi chiều. Có AM/PM (phòng khi dùng bản CSV khác) thì theo AM/PM.
    """
    match = _TIMESTAMP.match(str(text))
    if not match:
        raise ValueError(f"Timestamp CIC không đúng định dạng: {text!r}")
    day, month, year, hour, minute = (int(match.group(i)) for i in range(1, 6))
    second = int(match.group(6) or 0)
    meridiem = (match.group(7) or "").upper()
    if meridiem == "PM" and hour < 12:
        hour += 12
    elif meridiem == "AM" and hour == 12:
        hour = 0
    elif not meridiem and hour < 8:
        hour += 12
    return datetime(year, month, day, hour, minute, second, tzinfo=ADT).timestamp()


def _port(value) -> int:
    """Cổng trong CSV có thể là số thực (80.0) hoặc rỗng (NaN); rỗng coi như 0, giống `flow_key`."""
    if value is None:
        return 0
    try:
        number = float(value)
    except (TypeError, ValueError):
        return 0
    return 0 if number != number else int(number)  # NaN khác chính nó


def cic_flow_key(src_ip, src_port, dst_ip, dst_port, protocol_number) -> FlowKey:
    """Khoá flow hai chiều dựng từ một dòng CSV, giống hệt `nids.engine.flow.flow_key`."""
    protocol = PROTOCOLS.get(_port(protocol_number), "UNKNOWN")
    a = (str(src_ip).strip(), _port(src_port))
    b = (str(dst_ip).strip(), _port(dst_port))
    return (protocol, *sorted((a, b)))


def flow_key_of(flow: Flow) -> FlowKey:
    """Khoá của một `Flow` do `FlowTracker` xuất ra (cùng công thức với `flow_key` của gói)."""
    a = (flow.src_ip, flow.src_port or 0)
    b = (flow.dst_ip, flow.dst_port or 0)
    return (flow.protocol, *sorted((a, b)))


def _normalize_raw(raw: str) -> str:
    """Bỏ ký tự lỗi mã hoá ('Web Attack \\x96 Brute Force' khi đọc bằng latin-1) và khoảng trắng thừa."""
    cleaned = re.sub(r"[^A-Za-z0-9\- ]", " ", str(raw))
    return " ".join(cleaned.split())


def group_label(raw: str) -> str:
    """Nhãn gốc → lớp gộp. Nhãn chưa biết thì giữ nguyên (đã chuẩn hoá)."""
    normalized = _normalize_raw(raw)
    return GROUPS.get(normalized, normalized)


@dataclass(frozen=True)
class LabelRecord:
    """Một dòng nhãn: giờ (epoch UTC), lớp đã gộp và sửa, nhãn gốc trong CSV (đã chuẩn hoá)."""
    ts: float
    label: str
    label_raw: str


class LabelIndex:
    """Tra nhãn theo khoá flow và khoảng thời gian."""

    def __init__(self, records: Dict[FlowKey, List[LabelRecord]]):
        self._records: Dict[FlowKey, List[LabelRecord]] = {}
        self._times: Dict[FlowKey, List[float]] = {}
        for key, items in records.items():
            ordered = sorted(items, key=lambda r: r.ts)
            self._records[key] = ordered
            self._times[key] = [r.ts for r in ordered]

    def __len__(self) -> int:
        return sum(len(items) for items in self._records.values())

    def keys(self) -> Iterable[FlowKey]:
        return self._records.keys()

    def records(self) -> Iterator[Tuple[FlowKey, LabelRecord]]:
        for key, items in self._records.items():
            for record in items:
                yield key, record

    def lookup(self, key: FlowKey, first_seen: float, last_seen: float,
               tolerance: float = DEFAULT_TOLERANCE) -> Tuple[str, str]:
        """Trả về `(label, label_raw)` của flow có khoá `key` sống trong `[first_seen, last_seen]`.

        Xét các dòng cùng khoá có giờ trong khoảng đó nới thêm `tolerance` giây hai đầu. Có dòng tấn công thì
        lấy lớp tấn công xuất hiện nhiều nhất; chỉ có BENIGN thì là BENIGN; không có dòng nào thì UNLABELED.
        """
        times = self._times.get(key)
        if not times:
            return UNLABELED, UNLABELED
        lo = bisect_left(times, first_seen - tolerance)
        hi = bisect_right(times, last_seen + tolerance)
        window = self._records[key][lo:hi]
        if not window:
            return UNLABELED, UNLABELED
        attacks = [r for r in window if r.label != BENIGN]
        if not attacks:
            return BENIGN, BENIGN
        label = Counter(r.label for r in attacks).most_common(1)[0][0]
        raw = Counter(r.label_raw for r in attacks if r.label == label).most_common(1)[0][0]
        return label, raw

    def lookup_flow(self, flow: Flow, tolerance: float = DEFAULT_TOLERANCE) -> Tuple[str, str]:
        return self.lookup(flow_key_of(flow), flow.first_seen, flow.last_seen, tolerance)

    def attack_windows(self, label: str, gap: float = EPISODE_GAP) -> List[Tuple[float, float]]:
        """Các đợt của một lớp: những khoảng giờ liên tục có dòng mang lớp đó, cách nhau quá `gap` giây thì tách.

        Giờ CSV chỉ tới phút nên điểm cuối mỗi đợt được cộng thêm 60 giây.
        """
        times = sorted({r.ts for _, r in self.records() if r.label == label})
        if not times:
            return []
        windows = []
        start = previous = times[0]
        for ts in times[1:]:
            if ts - previous > gap:
                windows.append((start, previous + 60.0))
                start = ts
            previous = ts
        windows.append((start, previous + 60.0))
        return windows


def _read_csv(path: Path) -> pd.DataFrame:
    frame = pd.read_csv(
        path,
        encoding="latin-1",            # file WebAttacks có byte không phải UTF-8
        low_memory=False,
        usecols=lambda column: column.strip() in CSV_COLUMNS,
    )
    frame.columns = [c.strip() for c in frame.columns]
    missing = [c for c in CSV_COLUMNS if c not in frame.columns]
    if missing:
        raise ValueError(f"{path}: thiếu cột {missing}")
    return frame.dropna(subset=["Timestamp", "Source IP", "Destination IP"])


def load_labels(csv_paths: Sequence[Union[str, Path]]) -> LabelIndex:
    """Đọc các file CSV `TrafficLabelling_` và dựng `LabelIndex`."""
    records: Dict[FlowKey, List[LabelRecord]] = {}
    total = corrected = 0
    for path in (Path(p) for p in csv_paths):
        frame = _read_csv(path)
        # Giờ và nhãn chỉ có ít giá trị khác nhau, nên tính trên giá trị duy nhất rồi map lại cho nhanh
        stamps = {value: parse_cic_timestamp(value) for value in frame["Timestamp"].unique()}
        raws = {value: _normalize_raw(value) for value in frame["Label"].unique()}
        columns = zip(frame["Source IP"], frame["Source Port"], frame["Destination IP"],
                      frame["Destination Port"], frame["Protocol"], frame["Timestamp"], frame["Label"])
        count = 0
        for src_ip, src_port, dst_ip, dst_port, protocol, stamp, raw_value in columns:
            raw = raws[raw_value]
            label = GROUPS.get(raw, raw)
            if C2_IP in (str(src_ip).strip(), str(dst_ip).strip()) and label != "Bot":
                label = "Bot"
                corrected += 1
            key = cic_flow_key(src_ip, src_port, dst_ip, dst_port, protocol)
            records.setdefault(key, []).append(LabelRecord(stamps[stamp], label, raw))
            count += 1
        unknown = sorted({r for r in raws.values() if r not in GROUPS})
        if unknown:
            logger.warning("%s: nhãn chưa có trong GROUPS, giữ nguyên: %s", path.name, unknown)
        logger.info("Đã đọc %d dòng nhãn từ %s", count, path.name)
        total += count
    logger.info("Tổng %d dòng nhãn, %d khoá flow, %d dòng được sửa thành Bot (IP %s)",
                total, len(records), corrected, C2_IP)
    return LabelIndex(records)


def find_label_files(labels_dir: Union[str, Path], day: Optional[str] = None) -> List[Path]:
    """Các file CSV trong thư mục nhãn; `day` (ví dụ "friday") lọc theo tên file, không phân biệt hoa thường."""
    files = sorted(Path(labels_dir).glob("*.csv"))
    if day:
        files = [f for f in files if f.name.lower().startswith(day.lower())]
    if not files:
        raise FileNotFoundError(f"Không tìm thấy file CSV nhãn trong {labels_dir} (day={day!r})")
    return files
