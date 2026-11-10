"""
Danh sách chunk pcap 10 phút của một ngày CIC-IDS2017 và cách chia dev/test (PLAN-009 mục 6.3).

Đầu vào là thư mục pcap đã cắt bằng `editcap -i 600` và thư mục nhãn `TrafficLabelling_`. Đầu ra:
- JSON (mặc định `data/cic/<day>_manifest.json`, không commit) để `tools/eval` và `tools/ai` đọc.
- Bảng Markdown (mặc định `docs/eval/manifest.md`, được commit) để cả nhóm dùng cùng một cách chia.

Kết quả tất định: cùng thư mục pcap và cùng CSV luôn cho cùng manifest (không ghi giờ chạy vào file).

Chạy:
    python -m tools.cic.manifest --split-dir D:\\Tools\\PBL4\\split --labels-dir D:\\Temp\\Temp\\TrafficLabelling_
"""
import argparse
import ipaddress
import json
import logging
import sys
from bisect import bisect_right
from collections import Counter, defaultdict
from concurrent.futures import ProcessPoolExecutor
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence

from scapy.utils import RawPcapReader

from nids.logger import setup_logging
from tools.cic.labels import ADT, BENIGN, C2_IP, LabelIndex, find_label_files, load_labels

logger = logging.getLogger("nids.eval")

# Giờ bắt đầu (ADT) của các chunk thuộc tập test của thứ Sáu, theo PLAN-009 mục 6.3:
# PortScan 14:59/15:09/15:19, DDoS 16:09, hai chunk ngoài đợt PortScan và DDoS 09:09/16:29
FRIDAY_TEST_STARTS = ("09:09", "14:59", "15:09", "15:19", "16:09", "16:29")
FRIDAY_PACKETS = 9_997_874          # số gói của Friday-WorkingHours.pcap gốc
BOT_TEST_HOST_COUNT = 2
CHUNK_SECONDS = 600
CLASSES = (BENIGN, "PortScan", "DDoS", "Bot")


class ManifestError(Exception):
    """Thư mục pcap không dùng được (thiếu gói, file chồng nhau...)."""


@dataclass
class ChunkInfo:
    index: int
    file: str
    packets: int
    first_ts: float
    last_ts: float
    start_adt: str = ""
    end_adt: str = ""
    start_utc: str = ""
    set: str = ""
    labels: Dict[str, int] = field(default_factory=dict)
    bot_by_host: Dict[str, int] = field(default_factory=dict)


def _packet_ts(meta, nano: bool) -> float:
    """Giờ của một gói từ metadata của RawPcapReader (pcap) hoặc RawPcapNgReader (pcapng)."""
    if hasattr(meta, "tshigh"):
        return ((meta.tshigh << 32) | meta.tslow) / meta.tsresol
    return meta.sec + meta.usec / (1e9 if nano else 1e6)


def scan_pcap(path: str) -> dict:
    """Đếm gói và lấy giờ gói đầu, gói cuối. Đọc byte thô, không bóc giao thức nên nhanh."""
    count = 0
    first = last = None
    with RawPcapReader(path) as reader:
        nano = bool(getattr(reader, "nano", False))
        for _data, meta in reader:
            ts = _packet_ts(meta, nano)
            if first is None:
                first = ts
            last = ts
            count += 1
    return {"file": Path(path).name, "packets": count, "first_ts": first, "last_ts": last}


def adt_clock(ts: float) -> str:
    return datetime.fromtimestamp(ts, ADT).strftime("%H:%M")


def utc_iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def chunk_set(start_adt: str, test_starts: Iterable[str]) -> str:
    return "test" if start_adt in set(test_starts) else "dev"


def pick_bot_test_hosts(hosts: Iterable[str], count: int = BOT_TEST_HOST_COUNT) -> List[str]:
    """Chọn tất định `count` máy nhiễm có IP nhỏ nhất (so theo số, không theo chuỗi)."""
    return sorted(set(hosts), key=ipaddress.ip_address)[:count]


def check_chunks(chunks: Sequence[ChunkInfo], expect_packets: Optional[int]) -> None:
    """Chặn các thư mục cắt sai: file rỗng, file dài quá 10 phút, file chồng thời gian, tổng gói lệch."""
    if not chunks:
        raise ManifestError("Không có file pcap nào")
    for chunk in chunks:
        if chunk.packets == 0:
            raise ManifestError(f"{chunk.file}: không có gói nào")
        if chunk.last_ts - chunk.first_ts > CHUNK_SECONDS + 1:
            raise ManifestError(f"{chunk.file}: dài {chunk.last_ts - chunk.first_ts:.0f} giây, quá {CHUNK_SECONDS} giây; "
                                "có phải bộ cắt theo số gói thay vì theo thời gian không?")
    ordered = sorted(chunks, key=lambda c: c.first_ts)
    for previous, current in zip(ordered, ordered[1:]):
        if current.first_ts < previous.last_ts:
            raise ManifestError(f"{previous.file} và {current.file} chồng thời gian: thư mục có hai bộ cắt khác nhau?")
    total = sum(c.packets for c in chunks)
    if expect_packets is not None and total != expect_packets:
        raise ManifestError(f"Tổng {total} gói, khác {expect_packets} gói của file gốc")


def _bucket(starts: List[float], ts: float) -> Optional[int]:
    """Vị trí chunk chứa giờ `ts` (chunk i chứa [starts[i], starts[i+1])), None nếu trước chunk đầu."""
    position = bisect_right(starts, ts) - 1
    return position if position >= 0 else None


def bot_hosts(index: LabelIndex) -> List[str]:
    """IP nội bộ có flow tới hoặc từ máy điều khiển botnet."""
    hosts = set()
    for key in index.keys():
        ips = {key[1][0], key[2][0]}
        if C2_IP in ips:
            for ip in ips - {C2_IP}:
                try:
                    if ipaddress.ip_address(ip).is_private:
                        hosts.add(ip)
                except ValueError:
                    continue
    return sorted(hosts, key=ipaddress.ip_address)


def attach_label_counts(chunks: List[ChunkInfo], index: LabelIndex) -> None:
    """Đếm dòng nhãn (lớp đã sửa) và flow Bot theo máy cho từng chunk.

    Giờ CSV chỉ tới phút nên dòng được tính vào chunk chứa giữa phút đó (`ts + 30`); số đếm là gần đúng,
    chỉ để xem phân bố, không dùng để tính số liệu đánh giá.
    """
    starts = [c.first_ts for c in chunks]
    end = chunks[-1].last_ts
    labels = defaultdict(Counter)
    bots = defaultdict(Counter)
    for key, record in index.records():
        moment = record.ts + 30
        if moment > end + 60:
            continue
        position = _bucket(starts, moment)
        if position is None:
            continue
        labels[position][record.label] += 1
        if record.label == "Bot":
            for ip in (key[1][0], key[2][0]):
                if ip != C2_IP:
                    bots[position][ip] += 1
    for position, chunk in enumerate(chunks):
        chunk.labels = {name: labels[position].get(name, 0) for name in CLASSES}
        others = {k: v for k, v in labels[position].items() if k not in CLASSES}
        chunk.labels.update(sorted(others.items()))
        chunk.bot_by_host = dict(sorted(bots[position].items(), key=lambda kv: ipaddress.ip_address(kv[0])))


def build_manifest(split_dir: Path, index: LabelIndex, day: str, test_starts: Sequence[str],
                   expect_packets: Optional[int], jobs: int = 4) -> dict:
    files = sorted(str(p) for p in Path(split_dir).glob("*.pcap*"))
    if not files:
        raise ManifestError(f"Không có file pcap trong {split_dir}")
    logger.info("Đọc %d file pcap trong %s (%d tiến trình)", len(files), split_dir, jobs)
    if jobs > 1:
        with ProcessPoolExecutor(max_workers=jobs) as pool:
            scanned = list(pool.map(scan_pcap, files))
    else:
        scanned = [scan_pcap(f) for f in files]
    empty = [s["file"] for s in scanned if not s["packets"]]
    if empty:
        raise ManifestError(f"File không có gói nào: {empty}")
    ordered = sorted(scanned, key=lambda s: s["first_ts"])
    chunks = [ChunkInfo(index=i, file=s["file"], packets=s["packets"], first_ts=s["first_ts"], last_ts=s["last_ts"])
              for i, s in enumerate(ordered)]
    check_chunks(chunks, expect_packets)

    for chunk in chunks:
        chunk.start_adt = adt_clock(chunk.first_ts)
        chunk.end_adt = adt_clock(chunk.last_ts)
        chunk.start_utc = utc_iso(chunk.first_ts)
        chunk.set = chunk_set(chunk.start_adt, test_starts)
    attach_label_counts(chunks, index)

    hosts = bot_hosts(index)
    test_hosts = pick_bot_test_hosts(hosts)
    unknown_starts = sorted(set(test_starts) - {c.start_adt for c in chunks})
    if unknown_starts:
        logger.warning("Giờ test không khớp chunk nào: %s", unknown_starts)
    return {
        "day": day,
        "split_dir": str(split_dir),
        "total_packets": sum(c.packets for c in chunks),
        "test_starts": list(test_starts),
        "bot_c2_ip": C2_IP,
        "bot_hosts": hosts,
        "bot_test_hosts": test_hosts,
        "chunks": [asdict(c) for c in chunks],
    }


def _thousands(number: int) -> str:
    """9997874 -> '9.997.874' (dấu chấm phân cách hàng nghìn như tiếng Việt)."""
    return f"{number:,}".replace(",", ".")


def render_markdown(manifest: dict) -> str:
    """Bảng tóm tắt manifest để commit vào `docs/eval/`."""
    test_hosts = manifest["bot_test_hosts"]
    chunks = manifest["chunks"]
    extra = sorted({k for c in chunks for k in c["labels"]} - set(CLASSES))
    lines = [
        f"# Manifest CIC-IDS2017: {manifest['day']}",
        "",
        "File này do `python -m tools.cic.manifest` sinh ra, đừng sửa tay. Cách chia dev/test theo PLAN-009 mục 6.3.",
        "",
        f"- Số chunk: {len(chunks)} (dev {sum(c['set'] == 'dev' for c in chunks)}, "
        f"test {sum(c['set'] == 'test' for c in chunks)}); tổng {_thousands(manifest['total_packets'])} gói",
        f"- Giờ bắt đầu chunk test (ADT): {', '.join(manifest['test_starts'])}",
        f"- Máy điều khiển botnet: `{manifest['bot_c2_ip']}`; máy nhiễm: {', '.join(f'`{h}`' for h in manifest['bot_hosts']) or 'không có'}",
        f"- Máy nhiễm dùng để thi (test): {', '.join(f'`{h}`' for h in test_hosts) or 'không có'}",
        "- Số nhãn là số dòng CSV (flow của CICFlowMeter) rơi vào chunk, tính theo phút nên chỉ gần đúng.",
        "",
        "| # | Bắt đầu (ADT) | Kết thúc (ADT) | Tập | Số gói | " + " | ".join(CLASSES + tuple(extra))
        + " | Bot của máy test |",
        "| -: | :-- | :-- | :-- | --: | " + " | ".join("--:" for _ in CLASSES + tuple(extra)) + " | --: |",
    ]
    for c in chunks:
        bot_test = sum(c["bot_by_host"].get(h, 0) for h in test_hosts)
        counts = " | ".join(str(c["labels"].get(name, 0)) for name in CLASSES + tuple(extra))
        mark = "**test**" if c["set"] == "test" else "dev"
        lines.append(f"| {c['index']} | {c['start_adt']} | {c['end_adt']} | {mark} | {_thousands(c['packets'])} | "
                     f"{counts} | {bot_test} |")
    lines.append("")
    return "\n".join(lines)


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Lập manifest chunk pcap CIC-IDS2017 và chia dev/test")
    parser.add_argument("--split-dir", required=True, help="Thư mục pcap đã cắt bằng editcap -i 600")
    parser.add_argument("--labels-dir", required=True, help="Thư mục CSV TrafficLabelling_")
    parser.add_argument("--day", default="friday", help="Ngày của dataset, dùng để lọc file CSV (mặc định friday)")
    parser.add_argument("--expect-packets", type=int, default=None,
                        help=f"Tổng số gói phải có (thứ Sáu mặc định {FRIDAY_PACKETS}); 0 để bỏ kiểm tra")
    parser.add_argument("--test-starts", default=None,
                        help="Giờ bắt đầu (ADT) của chunk test, cách nhau bằng dấu phẩy; thứ Sáu có mặc định")
    parser.add_argument("--out", default=None, help="File JSON đầu ra (mặc định data/cic/<day>_manifest.json)")
    parser.add_argument("--summary", default=None, help="File Markdown đầu ra (mặc định docs/eval/manifest.md)")
    parser.add_argument("--jobs", type=int, default=4, help="Số tiến trình đọc pcap song song")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    setup_logging("INFO")
    day = args.day.lower()
    if args.test_starts:
        test_starts = tuple(s.strip() for s in args.test_starts.split(",") if s.strip())
    elif day == "friday":
        test_starts = FRIDAY_TEST_STARTS
    else:
        logger.error("Ngày %s chưa có danh sách chunk test mặc định, hãy truyền --test-starts", day)
        return 2
    expect = args.expect_packets
    if expect is None and day == "friday":
        expect = FRIDAY_PACKETS
    if expect == 0:
        expect = None

    try:
        index = load_labels(find_label_files(args.labels_dir, day))
        manifest = build_manifest(Path(args.split_dir), index, day, test_starts, expect, jobs=max(1, args.jobs))
    except (ManifestError, FileNotFoundError, ValueError) as e:
        logger.error("Không lập được manifest: %s", e)
        return 1

    out = Path(args.out or f"data/cic/{day}_manifest.json")
    summary = Path(args.summary or "docs/eval/manifest.md")
    out.parent.mkdir(parents=True, exist_ok=True)
    summary.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    summary.write_text(render_markdown(manifest), encoding="utf-8")
    sets = Counter(c["set"] for c in manifest["chunks"])
    logger.info("Đã ghi %s và %s: %d chunk (dev %d, test %d), %d gói, máy Bot test %s",
                out, summary, len(manifest["chunks"]), sets["dev"], sets["test"],
                manifest["total_packets"], manifest["bot_test_hosts"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
