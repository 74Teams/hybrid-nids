"""
Bộ đo có nhãn: chạy pipeline engine trên các chunk pcap CIC-IDS2017 rồi so với nhãn (PLAN-009 mục 6.4).

Chạy (từ thư mục gốc repo):
    python -m tools.eval.evaluate --labels-dir D:\\Temp\\Temp\\TrafficLabelling_ --set dev ^
        --set-var HOME_NET=192.168.10.0/24 --name baseline

Đầu ra: `docs/eval/<name>.md` (bảng, được commit) và `data/eval/<name>.json` (số liệu để so sánh, không commit).
Tập test chỉ chạy ở các mốc đã định trong plan, nên phải thêm `--allow-test`.
"""
import argparse
import json
import logging
import os
import subprocess
import sys
import time
from collections import Counter
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Optional, Sequence

from nids.logger import setup_logging
from tools.cic.labels import find_label_files, load_labels
from tools.eval import metrics
from tools.eval.report import render
from tools.eval.runner import RuleLoadError, RunConfig, default_config, load_rules, run_chunk

logger = logging.getLogger("nids.eval")

BASELINE_NOTE = (
    "Số cảnh báo (sau threshold) của engine trước PR1 phụ thuộc tốc độ chạy, vì `ThresholdManager` chặn theo "
    "giờ máy (`time.time()`); chạy lại có thể ra số hơi khác. Cột \"Khớp trước threshold\", số flow và nhãn "
    "flow thì không phụ thuộc tốc độ."
)


def parse_overrides(items: Sequence[str]) -> Dict[str, str]:
    overrides = {}
    for item in items or ():
        name, sep, value = item.partition("=")
        if not sep or not name.strip():
            raise ValueError(f"--set-var phải có dạng TÊN=GIÁ_TRỊ, nhận được {item!r}")
        overrides[name.strip()] = value.strip()
    return overrides


def select_chunks(manifest: dict, chunk_set: str, starts: Optional[Sequence[str]]) -> List[dict]:
    chunks = manifest["chunks"]
    if starts:
        wanted = set(starts)
        chosen = [c for c in chunks if c["start_adt"] in wanted]
        missing = wanted - {c["start_adt"] for c in chosen}
        if missing:
            raise ValueError(f"Không có chunk bắt đầu lúc {sorted(missing)}")
        return chosen
    if chunk_set == "all":
        return list(chunks)
    return [c for c in chunks if c["set"] == chunk_set]


def git_version() -> str:
    try:
        commit = subprocess.run(["git", "rev-parse", "--short", "HEAD"], capture_output=True, text=True,
                                timeout=10).stdout.strip()
        dirty = subprocess.run(["git", "status", "--porcelain", "--untracked-files=no"], capture_output=True,
                               text=True, timeout=10).stdout.strip()
        return f"{commit}{' (có thay đổi chưa commit)' if dirty else ''}" if commit else "?"
    except (OSError, subprocess.SubprocessError):
        return "?"


def _init_worker() -> None:
    setup_logging("WARNING")


def run_chunks(paths: Dict[str, str], config: RunConfig, jobs: int) -> Dict[str, dict]:
    """Chạy các chunk (song song nếu `jobs` > 1); khoá kết quả là tên file."""
    results = {}
    started = time.perf_counter()
    if jobs <= 1:
        for i, (name, path) in enumerate(paths.items(), 1):
            results[name] = run_chunk(path, config)
            logger.info("Xong %s (%d/%d)", name, i, len(paths))
        return results
    with ProcessPoolExecutor(max_workers=jobs, initializer=_init_worker) as pool:
        futures = {pool.submit(run_chunk, path, config): name for name, path in paths.items()}
        for done, future in enumerate(as_completed(futures), 1):
            name = futures[future]
            results[name] = future.result()
            logger.info("Xong %s (%d/%d) sau %.0f giây", name, done, len(paths), time.perf_counter() - started)
    return results


def evaluate(manifest: dict, chunks: List[dict], index, config: RunConfig, jobs: int) -> dict:
    split_dir = Path(manifest["split_dir"])
    # chunk lớn chạy trước để các tiến trình xong cùng lúc
    ordered = sorted(chunks, key=lambda c: -c["packets"])
    paths = {c["file"]: str(split_dir / c["file"]) for c in ordered}
    missing = [p for p in paths.values() if not Path(p).exists()]
    if missing:
        raise FileNotFoundError(f"Thiếu file pcap: {missing[:3]}")

    started = time.perf_counter()
    results = run_chunks(paths, config, jobs)
    wall = time.perf_counter() - started

    test_hosts = manifest.get("bot_test_hosts", [])
    all_flows, all_alerts = [], []
    funnel, timing, matches = Counter(), Counter(), Counter()
    rules_loaded = 0
    for chunk in sorted(chunks, key=lambda c: c["first_ts"]):
        result = results[chunk["file"]]
        flows, alerts = result["flows"], result["alerts"]
        metrics.label_flows(flows, index, chunk["set"], test_hosts)
        metrics.attach_alerts(flows, alerts, chunk["set"], test_hosts)
        offset = len(all_flows)
        for alert in alerts:
            if alert["flow"] is not None:
                alert["flow"] += offset
        all_flows += flows
        all_alerts += alerts
        funnel.update(result["counts"])
        timing.update(result["timing"])
        matches.update({int(k): v for k, v in result["matches_by_sid"].items()})
        rules_loaded = result["rules_loaded"]

    sets = {c["set"] for c in chunks}
    if sets == {"test"}:
        bot_hosts = test_hosts
    elif sets == {"dev"}:
        bot_hosts = [h for h in manifest.get("bot_hosts", []) if h not in test_hosts]
    else:
        bot_hosts = manifest.get("bot_hosts", [])
    ranges = [(c["first_ts"], c["last_ts"]) for c in sorted(chunks, key=lambda c: c["first_ts"])]
    analysed_time = sum(timing.values())
    return {
        "run": {"chunks": [c["start_adt"] for c in sorted(chunks, key=lambda c: c["first_ts"])],
                "files": [c["file"] for c in chunks], "rules_loaded": rules_loaded, "wall_seconds": wall,
                "jobs": jobs, "bot_test_hosts": test_hosts, "variables": config.variables},
        "funnel": dict(funnel),
        "timing": dict(timing),
        "packets_per_second": funnel["total"] / analysed_time if analysed_time else None,
        "classes": metrics.class_metrics(all_flows),
        "sources": metrics.source_metrics(all_alerts),
        "sids": metrics.sid_metrics(all_alerts, matches),
        "episodes": metrics.episode_metrics(index, all_alerts, all_flows, ranges, bot_hosts),
        "skipped": dict(Counter(f["eval_label"] for f in all_flows if f["eval_label"] in metrics.SKIPPED)),
        "unmatched_alerts": sum(1 for a in all_alerts if a["label"] == metrics.UNMATCHED),
        "per_chunk": {c["start_adt"]: {"packets": results[c["file"]]["counts"].get("total", 0),
                                       "flows": len(results[c["file"]]["flows"]),
                                       "alerts": len(results[c["file"]]["alerts"]),
                                       "raw_matches": results[c["file"]]["counts"].get("raw_matches", 0),
                                       "seconds": results[c["file"]]["elapsed"]}
                      for c in chunks},
    }


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Đo engine trên pcap CIC-IDS2017 có nhãn")
    parser.add_argument("--manifest", default="data/cic/friday_manifest.json", help="File JSON do tools.cic.manifest sinh")
    parser.add_argument("--labels-dir", required=True, help="Thư mục CSV TrafficLabelling_")
    parser.add_argument("--split-dir", default=None, help="Thư mục pcap đã cắt (mặc định lấy từ manifest)")
    parser.add_argument("--set", dest="chunk_set", choices=("dev", "test", "all"), default="dev")
    parser.add_argument("--chunks", default=None, help="Chỉ chạy các chunk có giờ bắt đầu (ADT) này, ví dụ 14:09,15:59")
    parser.add_argument("--allow-test", action="store_true", help="Cho phép chạy chunk thuộc tập test")
    parser.add_argument("--set-var", action="append", default=[], help="Ghi đè biến header rule, ví dụ HOME_NET=10.0.0.0/8")
    parser.add_argument("--rules-dir", default="rules")
    parser.add_argument("--use-state", action="store_true", help="Dùng rules/state.yaml của máy này (mặc định bỏ qua)")
    parser.add_argument("--name", required=True, help="Tên lượt đo, dùng làm tên file kết quả")
    parser.add_argument("--jobs", type=int, default=max(1, min(12, (os.cpu_count() or 2) - 2)))
    parser.add_argument("--report-dir", default="docs/eval")
    parser.add_argument("--data-dir", default="data/eval")
    parser.add_argument("--note", default=None, help="Ghi chú thêm vào cuối báo cáo")
    parser.add_argument("--baseline-note", action="store_true", help="Thêm ghi chú về threshold theo giờ máy của code cũ")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    setup_logging("INFO")
    try:
        manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
        if args.split_dir:
            manifest["split_dir"] = args.split_dir
        starts = [s.strip() for s in args.chunks.split(",") if s.strip()] if args.chunks else None
        chunks = select_chunks(manifest, args.chunk_set, starts)
        overrides = parse_overrides(args.set_var)
    except (OSError, ValueError, KeyError) as e:
        logger.error("Không đọc được manifest hoặc tham số: %s", e)
        return 2
    if not chunks:
        logger.error("Không có chunk nào để chạy")
        return 2
    if any(c["set"] == "test" for c in chunks) and not args.allow_test:
        logger.error("Có chunk thuộc tập test; tập test chỉ chạy ở mốc đã định (PLAN-009 mục 6.3). "
                     "Thêm --allow-test nếu đúng là lúc đó.")
        return 2

    config = default_config(overrides, rules_dir=args.rules_dir, use_state=args.use_state)
    try:
        load_rules(config.rules_dir, config.variables, config.use_state)   # kiểm tra rule trước khi chạy lâu
        index = load_labels(find_label_files(args.labels_dir, manifest.get("day")))
        logger.info("Chạy %d chunk (%s) với %d tiến trình", len(chunks), args.chunk_set, args.jobs)
        result = evaluate(manifest, chunks, index, config, max(1, args.jobs))
    except RuleLoadError as e:
        logger.error("Nạp rule có cảnh báo, dừng đo: %s", e)
        return 1
    except FileNotFoundError as e:
        logger.error("%s", e)
        return 1

    result["run"].update({"name": args.name, "set": args.chunk_set if not starts else "chọn tay",
                          "overrides": overrides, "git": git_version(),
                          "note": " ".join(filter(None, [BASELINE_NOTE if args.baseline_note else None, args.note]))})
    report_path = Path(args.report_dir) / f"{args.name}.md"
    data_path = Path(args.data_dir) / f"{args.name}.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    data_path.parent.mkdir(parents=True, exist_ok=True)
    data_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    report_path.write_text(render(result), encoding="utf-8")
    benign = result["classes"].get("BENIGN", {})
    rule = result["sources"].get("RULE_ENGINE", {})
    logger.info("Đã ghi %s và %s. FPR flow BENIGN: %s; độ chính xác cảnh báo rule: %s",
                report_path, data_path, _fmt(benign.get("rate")), _fmt(rule.get("precision")))
    return 0


def _fmt(value: Optional[float]) -> str:
    return "–" if value is None else f"{value:.1%}"


if __name__ == "__main__":
    sys.exit(main())
