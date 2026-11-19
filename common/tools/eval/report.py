"""In kết quả một lượt đo thành bảng Markdown (đưa vào `docs/eval/`)."""
from datetime import datetime
from typing import Optional

from tools.cic.labels import ADT

STEP_NAMES = {"read": "Scapy đọc và bóc gói", "decode": "Decode", "rules": "Rule + tái hợp TCP",
              "flow": "Gom flow", "anomaly": "ANOMALY"}


def _pct(value: Optional[float]) -> str:
    return "–" if value is None else f"{value * 100:.1f}%".replace(".", ",")


def _num(value) -> str:
    if value is None:
        return "–"
    if isinstance(value, float):
        return f"{value:,.1f}".replace(",", "_").replace(".", ",").replace("_", ".")
    return f"{value:,}".replace(",", ".")


def _clock(ts: Optional[float]) -> str:
    return "–" if ts is None else datetime.fromtimestamp(ts, ADT).strftime("%H:%M:%S")


def render(result: dict) -> str:
    run = result["run"]
    funnel = result["funnel"]
    lines = [
        f"# Kết quả đo: {run['name']}",
        "",
        "File này do `python -m tools.eval.evaluate` sinh ra. Cách đọc số liệu: `docs/eval/README.md`.",
        "",
        f"- Tập: **{run['set']}**, {len(run['chunks'])} chunk ({', '.join(run['chunks'])})",
        f"- Code: `{run['git']}`; rule nạp: {run['rules_loaded']}; biến ghi đè: "
        + (", ".join(f"`{k}={v}`" for k, v in run["overrides"].items()) or "không có"),
        f"- Máy Bot dùng để thi: {', '.join(f'`{h}`' for h in run['bot_test_hosts']) or 'không có'}",
        f"- Thời gian chạy: {_num(run['wall_seconds'])} giây với {run['jobs']} tiến trình",
        "",
        "## Phễu gói",
        "",
        "| Bước | Số gói |",
        "| :-- | --: |",
        f"| Có trong pcap | {_num(funnel.get('total', 0))} |",
        f"| Bị bỏ vì không phải IP | {_num(funnel.get('not_ip', 0))} |",
        f"| Vào phân tích | {_num(funnel.get('analyzed', 0))} |",
        f"| Lỗi khi so khớp | {_num(funnel.get('errors', 0))} |",
        f"| Số lần rule khớp trước threshold | {_num(funnel.get('raw_matches', 0))} |",
        "",
        "## Thời gian từng bước (cộng mọi chunk, một tiến trình)",
        "",
        "| Bước | Giây | Tỉ lệ |",
        "| :-- | --: | --: |",
    ]
    timing = result["timing"]
    total_time = sum(timing.values()) or 1.0
    for key, name in STEP_NAMES.items():
        lines.append(f"| {name} | {_num(timing.get(key, 0.0))} | {_pct(timing.get(key, 0.0) / total_time)} |")
    lines += [
        f"| **Tốc độ** | {_num(result['packets_per_second'])} gói/giây | |",
        "",
        "## Theo lớp (flow)",
        "",
        "Flow bị rule báo: có ít nhất một rule khớp. Với lớp tấn công tỉ lệ này là độ phủ (recall), "
        "với BENIGN là tỉ lệ báo nhầm (FPR).",
        "",
        "| Lớp | Số flow | Bị rule báo | Tỉ lệ |",
        "| :-- | --: | --: | --: |",
    ]
    for label, row in result["classes"].items():
        lines.append(f"| {label} | {_num(row['flows'])} | {_num(row['rule_flagged'])} | {_pct(row['rate'])} |")
    lines += [
        "",
        "## Theo tầng phát hiện (cảnh báo)",
        "",
        "Độ chính xác = cảnh báo rơi vào flow tấn công / (cảnh báo rơi vào flow tấn công + cảnh báo rơi vào BENIGN).",
        "",
        "| Tầng | Cảnh báo | Bắt đúng | Báo nhầm | Bỏ qua | Độ chính xác |",
        "| :-- | --: | --: | --: | --: | --: |",
    ]
    for source, row in result["sources"].items():
        lines.append(f"| {source} | {_num(row['alerts'])} | {_num(row['tp'])} | {_num(row['fp'])} | "
                     f"{_num(row['skipped'])} | {_pct(row['precision'])} |")
    lines += [
        "",
        "## Theo rule",
        "",
        "| SID | Tên | Khớp trước threshold | Cảnh báo | Bắt đúng | Báo nhầm | Độ chính xác | Báo nhầm nhiều nhất |",
        "| :-- | :-- | --: | --: | --: | --: | --: | :-- |",
    ]
    for row in result["sids"]:
        sid = row["sid"] if row["sid"] is not None else "ANOMALY"
        top = "; ".join(f"{pair} ({count})" for pair, count in row["top_fp"]) or ""
        lines.append(f"| {sid} | {row['name']} | {_num(row['raw_matches'])} | {_num(row['alerts'])} | "
                     f"{_num(row['tp'])} | {_num(row['fp'])} | {_pct(row['precision'])} | {top} |")
    lines += [
        "",
        "## Theo đợt tấn công",
        "",
        "| Lớp | Đợt | Bắt đầu (ADT) | Kết thúc (ADT) | Phát hiện | Cảnh báo | Theo tầng | Thời gian tới cảnh báo đầu |",
        "| :-- | :-- | :-- | :-- | :-- | --: | :-- | --: |",
    ]
    for row in result["episodes"]:
        sources = ", ".join(f"{k} {v}" for k, v in sorted(row["by_source"].items())) or ""
        ttd = "–" if row["time_to_detect"] is None else f"{_num(float(row['time_to_detect']))} giây"
        lines.append(f"| {row['label']} | {row['name']} | {_clock(row['start'])} | {_clock(row['end'])} | "
                     f"{'có' if row['detected'] else '**không**'} | {_num(row['alerts'])} | {sources} | {ttd} |")
    skipped = result["skipped"]
    lines += [
        "",
        "## Flow không tính vào số liệu",
        "",
        f"- UNLABELED (không có dòng CSV tương ứng): {_num(skipped.get('UNLABELED', 0))}",
        f"- EXCLUDED (quy tắc chia máy Bot): {_num(skipped.get('EXCLUDED', 0))}",
        f"- Cảnh báo rule không tìm được flow: {_num(result['unmatched_alerts'])}",
        "",
    ]
    if run.get("note"):
        lines += ["## Ghi chú", "", run["note"], ""]
    return "\n".join(lines)
