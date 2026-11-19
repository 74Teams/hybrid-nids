"""
Dựng dataset cho AI: mỗi chunk pcap trong manifest → một file csv.gz (mỗi dòng một flow, có nhãn).

    python -m tools.ai.build_dataset --labels-dir D:\\Temp\\Temp\\TrafficLabelling_ --jobs 11
    python -m tools.ai.build_dataset --labels-dir ... --days friday --chunks 10:09,14:09
"""
import argparse
import json
import logging
import time
from multiprocessing import Pool
from pathlib import Path
from typing import List, Optional, Sequence

import pandas as pd
from scapy.utils import PcapReader

from nids.ai.context import DEFAULT_WINDOW, FlowContext
from nids.ai.features import FEATURE_NAMES, extract_features
from nids.engine.capture import apply_layer_filter
from nids.engine.decoder import PacketDecoder
from nids.engine.flow import SWEEP_INTERVAL, FlowTracker
from nids.logger import setup_logging
from tools.cic.labels import find_label_files, load_labels
from tools.eval.metrics import evaluation_label
from tools.eval.runner import default_config

logger = logging.getLogger("nids.ai")
ALL_DAYS = ("monday", "tuesday", "wednesday", "thursday", "friday")
# Cột thông tin: để lọc, chia tập và gỡ lỗi; KHÔNG bao giờ đưa vào mô hình
INFO_COLUMNS = ["day", "chunk", "split", "first_seen", "src_ip", "src_port", "dst_ip", "label", "label_raw",
                "eval_label"]

_INDEX = None   # bảng nhãn của ngày đang xử lý, nạp một lần cho mỗi tiến trình con


def _load_index(labels_dir: str, day: str) -> None:
    global _INDEX
    setup_logging("WARNING")
    apply_layer_filter()     # Scapy chỉ bóc tới L4, giống engine; gọi lần hai trong cùng tiến trình sẽ lỗi
    _INDEX = load_labels(find_label_files(labels_dir, day))


def build_chunk(task: dict) -> dict:
    """Một chunk pcap → file csv.gz. Chạy trong tiến trình con."""
    started = time.perf_counter()
    flow_cfg = default_config().flow     # cùng tham số flow với bộ đo (config/settings.example.yaml)
    tracker = FlowTracker(idle_timeout=flow_cfg.get("idle_timeout", 30),
                          active_timeout=flow_cfg.get("active_timeout", 120),
                          closing_timeout=flow_cfg.get("closing_timeout", 2),
                          max_flows=flow_cfg.get("max_flows", 100000))
    flows = []
    with PcapReader(task["pcap"]) as reader:
        for pkt in reader:
            packet = PacketDecoder.decode(pkt)
            if packet is not None:
                flows.extend(tracker.update(packet))
    flows.extend(tracker.flush())

    # Đúng thứ tự FlowTracker xuất flow: thứ tự này là một phần hợp đồng với mô hình (PLAN-011 mục 6.3)
    context = FlowContext()
    rows = []
    for flow in flows:
        flow_context = context.update(flow)
        label, raw = _INDEX.lookup_flow(flow)
        info = {"src_ip": flow.src_ip, "src_port": flow.src_port, "dst_ip": flow.dst_ip,
                "dst_port": flow.dst_port, "protocol": flow.protocol}
        row = extract_features(flow, flow_context)
        row.update(day=task["day"], chunk=task["chunk"], split=task["split"], first_seen=flow.first_seen,
                   src_ip=flow.src_ip, src_port=flow.src_port, dst_ip=flow.dst_ip, label=label, label_raw=raw,
                   eval_label=evaluation_label(label, info, task["split"], task["test_hosts"]))
        rows.append(row)
    frame = pd.DataFrame(rows, columns=INFO_COLUMNS + FEATURE_NAMES)
    out = Path(task["out"])
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_suffix(".tmp")
    frame.to_csv(tmp, index=False, compression="gzip")
    tmp.replace(out)          # ghi xong mới đổi tên: dừng giữa chừng không để lại file dở
    return {"chunk": task["chunk"], "flows": len(frame), "seconds": time.perf_counter() - started}


def tasks_for_day(day: str, out_dir: Path, only: Optional[Sequence[str]]) -> List[dict]:
    manifest = json.loads(Path(f"data/cic/{day}_manifest.json").read_text(encoding="utf-8"))
    tasks = []
    for chunk in manifest["chunks"]:
        if only and chunk["start_adt"] not in only:
            continue
        out = out_dir / day / f"{chunk['start_adt'].replace(':', '')}.csv.gz"
        if out.exists():
            continue          # đã làm ở lần chạy trước
        tasks.append({"day": day, "chunk": chunk["start_adt"], "split": chunk["set"],
                      "pcap": str(Path(manifest["split_dir"]) / chunk["file"]),
                      "test_hosts": manifest.get("bot_test_hosts", []), "out": str(out)})
    return tasks


def main(argv=None) -> int:
    setup_logging("INFO")
    parser = argparse.ArgumentParser(description="pcap CIC-IDS2017 → bảng đặc trưng flow có nhãn")
    parser.add_argument("--labels-dir", required=True)
    parser.add_argument("--days", default=",".join(ALL_DAYS))
    parser.add_argument("--chunks", help="chỉ làm vài chunk, ví dụ 10:09,14:09")
    parser.add_argument("--out-dir", default="data/ai/features")
    parser.add_argument("--jobs", type=int, default=4)
    args = parser.parse_args(argv)
    only = args.chunks.split(",") if args.chunks else None
    flow_cfg = default_config().flow
    if DEFAULT_WINDOW <= flow_cfg.get("idle_timeout", 30) + SWEEP_INTERVAL:
        logger.error("Cửa sổ ngữ cảnh %.0f giây phải lớn hơn idle_timeout cộng %.0f giây quét", DEFAULT_WINDOW, SWEEP_INTERVAL)
        return 2

    for day in args.days.split(","):
        tasks = tasks_for_day(day, Path(args.out_dir), only)
        if not tasks:
            logger.info("%s: không còn chunk nào phải làm", day)
            continue
        logger.info("%s: %d chunk, %d tiến trình", day, len(tasks), args.jobs)
        with Pool(args.jobs, initializer=_load_index, initargs=(args.labels_dir, day)) as pool:
            for result in pool.imap_unordered(build_chunk, tasks):
                logger.info("%s %s: %d flow, %.0f giây", day, result["chunk"], result["flows"], result["seconds"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())