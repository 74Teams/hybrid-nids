"""
Tính lại các cột ngữ cảnh (nids/ai/context.py) từ dataset CSV đã có, không đọc lại pcap.

Mỗi dòng CSV là một flow, được ghi đúng thứ tự `FlowTracker` xuất flow, và có đủ trường mà `FlowContext` cần
(IP, cổng, giờ bắt đầu, độ dài, số gói). Nên đưa lại từng dòng qua một `FlowContext` mới (mỗi chunk một cái, giống
`build_dataset`) cho đúng kết quả như dựng từ pcap, trong vài phút thay vì 50 phút.

    python -m tools.ai.add_context --src data/work/ai/features-v2 --dst data/work/ai/features-v3 --jobs 8
    python -m tools.ai.add_context --src data/work/ai/features-v2 --dst data/work/ai/features-v3 --check-only

`--check-only` tính lại rồi so với các cột ngữ cảnh đang có trong file nguồn (phải trùng) mà không ghi gì.
"""
import argparse
import logging
import time
from multiprocessing import Pool
from pathlib import Path
from typing import Dict, List, Optional

import numpy as np
import pandas as pd

from nids.ai.context import CONTEXT_FEATURE_NAMES, SHORT_CONTEXT_FEATURE_NAMES, FlowContext
from nids.engine.flow import Flow
from nids.logger import setup_logging

logger = logging.getLogger("nids.ai")
ALL_CONTEXT_COLUMNS = CONTEXT_FEATURE_NAMES + SHORT_CONTEXT_FEATURE_NAMES


def _port(value) -> Optional[int]:
    return None if value != value else int(value)


def compute_context(frame: pd.DataFrame) -> pd.DataFrame:
    """Đưa các dòng (đúng thứ tự file) qua một `FlowContext` mới; trả về các cột ngữ cảnh, cùng index."""
    context = FlowContext()
    records: List[Dict[str, float]] = []
    columns = ["protocol", "src_ip", "src_port", "dst_ip", "dst_port", "first_seen", "flow_duration",
               "fwd_packets", "bwd_packets"]
    for protocol, src_ip, src_port, dst_ip, dst_port, first_seen, duration, fwd, bwd in frame[columns].itertuples(index=False):
        flow = Flow(protocol=protocol, src_ip=src_ip, src_port=_port(src_port), dst_ip=dst_ip, dst_port=_port(dst_port),
                    first_seen=first_seen, last_seen=first_seen + duration, fwd_packets=int(fwd), bwd_packets=int(bwd))
        records.append(context.update(flow))
    return pd.DataFrame(records, columns=ALL_CONTEXT_COLUMNS, index=frame.index)


def process_file(task: dict) -> dict:
    started = time.perf_counter()
    frame = pd.read_csv(task["src"])
    fresh = compute_context(frame)
    mismatch = {}
    for name in CONTEXT_FEATURE_NAMES:
        if name in frame.columns:
            mismatch[name] = int((~np.isclose(frame[name].to_numpy(), fresh[name].to_numpy(), rtol=1e-9, atol=1e-9)).sum())
    if not task["check_only"]:
        for name in ALL_CONTEXT_COLUMNS:
            frame[name] = fresh[name]
        out = Path(task["dst"])
        out.parent.mkdir(parents=True, exist_ok=True)
        tmp = out.with_suffix(".tmp")
        frame.to_csv(tmp, index=False, compression="gzip")
        tmp.replace(out)
    return {"file": task["name"], "rows": len(frame), "mismatch": mismatch, "seconds": time.perf_counter() - started}


def main(argv=None) -> int:
    setup_logging("INFO")
    parser = argparse.ArgumentParser(description="Tính lại cột ngữ cảnh từ dataset CSV có sẵn")
    parser.add_argument("--src", required=True)
    parser.add_argument("--dst")
    parser.add_argument("--jobs", type=int, default=4)
    parser.add_argument("--check-only", action="store_true")
    args = parser.parse_args(argv)
    if not args.check_only and not args.dst:
        logger.error("Cần --dst (hoặc --check-only)")
        return 2
    files = sorted(Path(args.src).glob("*/*.csv.gz"))
    if not files:
        logger.error("Không có file .csv.gz nào trong %s", args.src)
        return 2
    tasks = [{"src": str(f), "dst": str(Path(args.dst or ".") / f.parent.name / f.name), "check_only": args.check_only,
              "name": f"{f.parent.name}/{f.name}"} for f in files]
    total = {name: 0 for name in CONTEXT_FEATURE_NAMES}
    rows = 0
    with Pool(args.jobs) as pool:
        for result in pool.imap_unordered(process_file, tasks):
            rows += result["rows"]
            for name, count in result["mismatch"].items():
                total[name] += count
            if any(result["mismatch"].values()):
                logger.warning("%s: cột lệch %s", result["file"], {k: v for k, v in result["mismatch"].items() if v})
    logger.info("Xong %d file, %d flow. Số dòng lệch so với cột cũ: %s", len(files), rows, total)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
