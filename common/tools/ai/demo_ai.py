"""
Demo mô hình AI theo flow (PLAN-011), chạy ngoài engine: đưa lưu lượng qua đúng chuỗi xử lý của engine
(gom flow, tính đặc trưng, nạp mô hình) rồi in máy nào bị coi là tấn công và từ lúc nào.

    python -m tools.ai.demo_ai --scenario scan             # quét cổng giả lập kiểu nmap, trộn với người dùng thường
    python -m tools.ai.demo_ai --scenario scan --slow 10    # kẻ quét chậm hơn 10 lần
    python -m tools.ai.demo_ai --pcap D:\\path\\file.pcap --limit 300000

Kịch bản `scan` dựng bằng code (không phải dữ liệu CIC-IDS2017), nên mô hình chưa từng thấy đúng chuỗi gói này.
Chú ý: script này gọi mô hình trực tiếp, không qua sensor; sensor chạy cùng mô hình qua `AITrafficWorker`.
"""
import argparse
import logging
import random
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

import joblib
import numpy as np

from nids.ai.context import FlowContext
from nids.ai.features import FEATURE_NAMES, extract_features
from nids.engine.flow import Flow, FlowTracker
from nids.engine.packet import DecodedPacket
from nids.logger import setup_logging

logger = logging.getLogger("nids.ai")

ATTACKER = "172.16.0.1"
VICTIM = "192.168.10.50"
TYPO_USER = "192.168.10.20"           # người dùng gõ nhầm cổng: cũng sinh flow 2 gói SYN rồi RST
WEB_USERS = ("192.168.10.11", "192.168.10.12", "192.168.10.13")


# ---------------------------------------------------------------- dựng lưu lượng giả

def _tcp(ts: float, src: str, sport: int, dst: str, dport: int, flags: str, size: int, payload: int = 0) -> DecodedPacket:
    return DecodedPacket(
        timestamp=ts, src_ip=src, dst_ip=dst, src_port=sport, dst_port=dport, protocol="TCP",
        tcp_flags={"SYN": "S" in flags, "ACK": "A" in flags, "FIN": "F" in flags, "RST": "R" in flags,
                   "PSH": "P" in flags, "URG": "U" in flags, "raw_flags": flags},
        raw_packet=b"x" * size, raw_payload=b"x" * payload)


def probe_flow(ts: float, src: str, sport: int, dst: str, dport: int) -> List[DecodedPacket]:
    """Một lần gõ cửa bị từ chối: SYN đi, RST về. Quét cổng và gõ nhầm cổng đều sinh đúng flow này."""
    return [_tcp(ts, src, sport, dst, dport, "S", 60), _tcp(ts + 0.0002, dst, dport, src, sport, "RA", 60)]


def web_flow(ts: float, src: str, sport: int, dst: str, dport: int, rng: random.Random) -> List[DecodedPacket]:
    """Một lượt duyệt web bình thường: bắt tay ba bước, gửi yêu cầu, nhận trang, đóng kết nối."""
    rtt = 0.01 + rng.random() * 0.02
    body = rng.randint(800, 1400)
    return [
        _tcp(ts, src, sport, dst, dport, "S", 60),
        _tcp(ts + rtt, dst, dport, src, sport, "SA", 60),
        _tcp(ts + 2 * rtt, src, sport, dst, dport, "A", 54),
        _tcp(ts + 3 * rtt, src, sport, dst, dport, "PA", 400, 346),
        _tcp(ts + 4 * rtt, dst, dport, src, sport, "PA", body + 54, body),
        _tcp(ts + 5 * rtt, src, sport, dst, dport, "A", 54),
        _tcp(ts + 6 * rtt, dst, dport, src, sport, "FA", 54),
        _tcp(ts + 7 * rtt, src, sport, dst, dport, "FA", 54),
        _tcp(ts + 8 * rtt, dst, dport, src, sport, "A", 54),
    ]


def scan_scenario(seconds: float = 25.0, rate: float = 800.0, scan_start: float = 5.0, seed: int = 7) -> List[DecodedPacket]:
    """Kẻ quét gõ ~1.000 cổng với tốc độ `rate` flow mỗi giây, trong lúc 3 người dùng duyệt web và một người gõ nhầm cổng."""
    rng = random.Random(seed)
    packets: List[DecodedPacket] = []
    ports = rng.sample(range(1, 65536), 1000)
    t, index = scan_start, 0
    while t < scan_start + seconds - 5:
        packets += probe_flow(t, ATTACKER, 40000 + rng.randint(0, 20000), VICTIM, ports[index % len(ports)])
        index += 1
        t += 1.0 / rate
    for user in WEB_USERS:                                           # mỗi người mở một trang mỗi ~1,5 giây
        clock = rng.random()
        while clock < seconds:
            packets += web_flow(clock, user, rng.randint(40000, 60000), VICTIM, rng.choice((80, 80, 443)), rng)
            clock += 1.0 + rng.random()
    for clock in (3.0, 11.0, 19.0):                                  # gõ nhầm cổng 8081 (đóng): SYN rồi RST
        packets += probe_flow(clock, TYPO_USER, rng.randint(40000, 60000), VICTIM, 8081)
    return sorted(packets, key=lambda p: p.timestamp)


def slow_scenario(factor: float) -> List[DecodedPacket]:
    return scan_scenario(seconds=25.0 * 3, rate=800.0 / factor)


# ---------------------------------------------------------------- chuỗi xử lý giống engine

def load_bundle(path: str) -> dict:
    bundle = joblib.load(path)
    if bundle["feature_names"] != FEATURE_NAMES:
        raise ValueError("Mô hình học với danh sách đặc trưng khác `FEATURE_NAMES` hiện tại: cần học lại")
    return bundle


def classify(packets: Sequence[DecodedPacket], bundle: dict) -> List[Tuple[Flow, str]]:
    """Gói → flow (FlowTracker) → đặc trưng (extract_features + FlowContext) → nhãn (mô hình + ngưỡng)."""
    tracker = FlowTracker()
    settings = bundle["context"]
    context = FlowContext(window=settings["window"], short_window=settings["short_window"],
                          max_tracked=settings["max_tracked"], max_per_ip=settings["max_per_ip"])
    flows: List[Flow] = []
    rows: List[List[float]] = []

    def take(finished: List[Flow]) -> None:
        for flow in finished:
            features = extract_features(flow, context.update(flow))
            rows.append([features[name] for name in FEATURE_NAMES])
            flows.append(flow)

    for packet in packets:
        take(tracker.update(packet))
    take(tracker.flush())
    if not flows:
        return []
    proba = bundle["rf"].predict_proba(np.array(rows, dtype="float64"))
    classes = np.array(bundle["rf"].classes_)
    best = proba.argmax(axis=1)
    per_class = bundle["thresholds"]["per_class"]
    labels = []
    for i, index in enumerate(best):
        label = str(classes[index])
        if label != "BENIGN" and proba[i, index] < per_class.get(label, 0.5):
            label = "BENIGN"
        labels.append(label)
    return list(zip(flows, labels))


# ---------------------------------------------------------------- báo cáo

def report(results: List[Tuple[Flow, str]], bin_seconds: float = 2.0, show_bins: int = 8) -> str:
    by_src: Dict[str, List[Tuple[Flow, str]]] = defaultdict(list)
    for item in results:
        by_src[item[0].src_ip].append(item)
    lines = ["", "KẾT QUẢ THEO TỪNG MÁY (máy nguồn của flow; 'Báo sau' tính từ flow đầu tiên của chính máy đó):", "",
             f"{'Máy':<16}{'Số flow':>9}{'Bị báo tấn công':>17}{'Loại':>12}{'Báo sau (giây)':>16}"]
    for src, items in sorted(by_src.items(), key=lambda kv: -len(kv[1])):
        flagged = [(f, label) for f, label in items if label != "BENIGN"]
        kinds = ",".join(sorted({label for _, label in flagged})) or "-"
        first = f"{min(f.first_seen for f, _ in flagged) - min(f.first_seen for f, _ in items):.1f}" if flagged else "-"
        lines.append(f"{src:<16}{len(items):>9}{len(flagged):>17}{kinds:>12}{first:>16}")
    scan = by_src.get(ATTACKER)
    if scan:
        first_seen = min(f.first_seen for f, _ in scan)
        bins: Dict[int, List[str]] = defaultdict(list)
        for flow, label in scan:
            bins[int((flow.first_seen - first_seen) // bin_seconds)].append(label)
        lines += ["", f"KẺ QUÉT {ATTACKER}, theo từng {bin_seconds:.0f} giây kể từ lúc bắt đầu quét:", "",
                  f"{'Giây':>6}{'Số flow':>10}{'Bị báo':>9}{'Tỷ lệ':>8}"]
        for index in sorted(bins)[:show_bins]:
            labels = bins[index]
            flagged = sum(label != "BENIGN" for label in labels)
            lines.append(f"{index * bin_seconds:>6.0f}{len(labels):>10}{flagged:>9}{flagged / len(labels):>8.0%}")
    typo = by_src.get(TYPO_USER)
    if typo and scan:
        flagged_scan = sum(label != "BENIGN" for _, label in scan)
        flagged_typo = sum(label != "BENIGN" for _, label in typo)
        lines += ["", f"SO SÁNH: flow gõ nhầm cổng của {TYPO_USER} và flow quét của {ATTACKER} đều là 'SYN rồi RST, 60 byte'.",
                  f"  người gõ nhầm: {flagged_typo}/{len(typo)} flow bị báo | kẻ quét: {flagged_scan}/{len(scan)} flow bị báo"]
    return "\n".join(lines)


def read_pcap(path: str, limit: Optional[int]) -> List[DecodedPacket]:
    from scapy.utils import PcapReader
    from nids.engine.decoder import PacketDecoder
    packets: List[DecodedPacket] = []
    with PcapReader(path) as reader:
        for raw in reader:
            decoded = PacketDecoder.decode(raw)
            if decoded is not None:
                packets.append(decoded)
            if limit and len(packets) >= limit:
                break
    return packets


def main(argv=None) -> int:
    setup_logging("INFO")
    parser = argparse.ArgumentParser(description="Demo mô hình AI theo flow")
    parser.add_argument("--model", default="data/models/flow_model.joblib")
    parser.add_argument("--scenario", choices=("scan",), help="lưu lượng giả lập dựng bằng code")
    parser.add_argument("--slow", type=float, default=1.0, help="kẻ quét chậm hơn bao nhiêu lần (cùng --scenario scan)")
    parser.add_argument("--pcap", help="đọc một file pcap thật thay vì giả lập")
    parser.add_argument("--limit", type=int, help="chỉ đọc ngần này gói đầu của pcap")
    args = parser.parse_args(argv)
    if not args.scenario and not args.pcap:
        logger.error("Chọn --scenario scan hoặc --pcap <file>")
        return 2
    if not Path(args.model).exists():
        logger.error("Chưa có mô hình %s: chạy tools.ai.train trước", args.model)
        return 2
    try:
        bundle = load_bundle(args.model)
    except ValueError as error:
        logger.error("%s", error)
        return 2
    if args.pcap:
        packets = read_pcap(args.pcap, args.limit)
        title = f"pcap {args.pcap}"
    else:
        packets = slow_scenario(args.slow) if args.slow != 1.0 else scan_scenario()
        title = f"quét cổng giả lập (kẻ quét {'chậm hơn %.0f lần' % args.slow if args.slow != 1.0 else 'tốc độ thường'})"
    logger.info("Nguồn: %s, %d gói. Mô hình %s (phiên bản %s)", title, len(packets), args.model, bundle.get("version"))
    results = classify(packets, bundle)
    if not results:
        logger.error("Không có flow nào để đoán")
        return 2
    logger.info("%s", report(results))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
