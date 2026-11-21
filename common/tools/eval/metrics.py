"""
Gắn nhãn cho flow và cảnh báo của một lượt đo, rồi tính số liệu (PLAN-009 mục 6.3, 6.4).

Thuật ngữ:
- TP (bắt đúng): cảnh báo rơi vào flow tấn công. FP (báo nhầm): cảnh báo rơi vào flow BENIGN.
- Flow "bị rule báo": `alert_count > 0`, tức có ít nhất một rule khớp (tính cả lần bị threshold chặn).
- Nhãn `EXCLUDED` (bị loại khỏi phép tính):
  - chunk test: flow Bot của máy nhiễm không phải máy test;
  - chunk dev: mọi flow của máy test (để máy test thật sự "chưa thấy" khi chỉnh rule và huấn luyện).
- Nhãn `UNLABELED`: không tìm thấy dòng CSV tương ứng. Cả hai loại đều không tính vào precision/recall.
"""
from bisect import bisect_right
from collections import Counter, defaultdict
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from tools.cic.labels import BENIGN, C2_IP, UNLABELED, LabelIndex

EXCLUDED = "EXCLUDED"
UNMATCHED = "UNMATCHED"            # cảnh báo rule không tìm được flow chứa nó
SKIPPED = (UNLABELED, EXCLUDED, UNMATCHED)

ANOMALY_WINDOW = 60.0              # cảnh báo ANOMALY được ghép với flow tấn công trong ±60 giây
ALERT_FLOW_SLACK = 1.0             # nới giờ flow 1 giây khi ghép cảnh báo rule


def row_key(src_ip, src_port, dst_ip, dst_port, protocol):
    """Khoá flow hai chiều, cùng công thức với `nids.engine.flow.flow_key`."""
    a = (src_ip, src_port or 0)
    b = (dst_ip, dst_port or 0)
    return (protocol, *sorted((a, b)))


def flow_key_row(flow: dict):
    return row_key(flow["src_ip"], flow["src_port"], flow["dst_ip"], flow["dst_port"], flow["protocol"])


def bot_host(flow: dict) -> Optional[str]:
    """Máy nội bộ của flow nói chuyện với máy điều khiển botnet, None nếu flow không dính máy đó."""
    if flow["src_ip"] == C2_IP:
        return flow["dst_ip"]
    if flow["dst_ip"] == C2_IP:
        return flow["src_ip"]
    return None


def evaluation_label(label: str, flow: dict, chunk_set: str, test_hosts: Sequence[str]) -> str:
    """Nhãn dùng để tính số liệu: nhãn tra từ CSV, hoặc EXCLUDED theo quy tắc chia máy Bot."""
    hosts = set(test_hosts)
    if chunk_set == "test" and label == "Bot" and bot_host(flow) not in hosts:
        return EXCLUDED
    if chunk_set == "dev" and (flow["src_ip"] in hosts or flow["dst_ip"] in hosts):
        return EXCLUDED
    return label


def label_flows(flows: List[dict], index: LabelIndex, chunk_set: str, test_hosts: Sequence[str]) -> None:
    """Thêm `label`, `label_raw`, `eval_label` vào từng flow (sửa tại chỗ)."""
    for flow in flows:
        label, raw = index.lookup(flow_key_row(flow), flow["first_seen"], flow["last_seen"])
        flow["label"] = label
        flow["label_raw"] = raw
        flow["eval_label"] = evaluation_label(label, flow, chunk_set, test_hosts)


def attach_alerts(flows: List[dict], alerts: List[dict], chunk_set: str = "dev",
                  test_hosts: Sequence[str] = ()) -> None:
    """Thêm `label` cho từng cảnh báo (sửa tại chỗ). Cần gọi `label_flows` trước.

    - Cảnh báo rule: tìm flow cùng khoá có `first_seen ≤ timestamp ≤ last_seen` (nới 1 giây).
    - Cảnh báo ANOMALY: không gắn với một flow cụ thể, nên đúng nếu trong ±60 giây có flow tấn công cùng cặp IP
      (nguồn, đích) với gói đã kích hoạt cảnh báo. Chỉ so một IP thì sai: máy nhiễm Bot vẫn có traffic bình
      thường, cảnh báo về traffic đó sẽ bị tính nhầm là bắt được Bot.
    """
    by_key: Dict[tuple, List[int]] = defaultdict(list)
    for i, flow in enumerate(flows):
        by_key[flow_key_row(flow)].append(i)
    starts: Dict[tuple, List[float]] = {}
    for key, positions in by_key.items():
        positions.sort(key=lambda i: flows[i]["first_seen"])
        starts[key] = [flows[i]["first_seen"] for i in positions]

    attack_by_pair: Dict[frozenset, List[Tuple[float, float, str]]] = defaultdict(list)
    for flow in flows:
        if flow["eval_label"] not in (BENIGN,) + SKIPPED:
            pair = frozenset((flow["src_ip"], flow["dst_ip"]))
            attack_by_pair[pair].append((flow["first_seen"], flow["last_seen"], flow["eval_label"]))
    excluded_hosts = set(test_hosts) if chunk_set == "dev" else set()

    for alert in alerts:
        if alert["source_type"] == "ANOMALY":
            alert["label"] = _anomaly_label(alert, attack_by_pair, excluded_hosts)
            alert["flow"] = None
            continue
        key = row_key(alert["src_ip"], alert["src_port"], alert["dst_ip"], alert["dst_port"], alert["protocol"])
        position = _find_flow(flows, by_key.get(key, []), starts.get(key, []), alert["timestamp"])
        alert["flow"] = position
        alert["label"] = flows[position]["eval_label"] if position is not None else UNMATCHED


def _find_flow(flows, positions, starts, ts) -> Optional[int]:
    if not positions:
        return None
    k = bisect_right(starts, ts + ALERT_FLOW_SLACK) - 1
    for j in range(k, -1, -1):   # flow mở gần nhất trước cảnh báo, lùi dần nếu nó đã kết thúc trước đó
        flow = flows[positions[j]]
        if flow["first_seen"] - ALERT_FLOW_SLACK <= ts <= flow["last_seen"] + ALERT_FLOW_SLACK:
            return positions[j]
        if flow["last_seen"] + ALERT_FLOW_SLACK < ts - 3600:
            break
    return None


def _anomaly_label(alert, attack_by_pair, excluded_hosts) -> str:
    ips = [ip for ip in (alert.get("src_ip"), alert.get("dst_ip")) if ip]
    if any(ip in excluded_hosts for ip in ips):
        return EXCLUDED
    ts = alert["timestamp"]
    found = Counter()
    for first, last, label in attack_by_pair.get(frozenset(ips), ()):
        if first - ANOMALY_WINDOW <= ts <= last + ANOMALY_WINDOW:
            found[label] += 1
    return found.most_common(1)[0][0] if found else BENIGN


# ── Tính số liệu ────────────────────────────────────────────────────────────

def _ratio(numerator: int, denominator: int) -> Optional[float]:
    return numerator / denominator if denominator else None


def class_metrics(flows: Iterable[dict]) -> Dict[str, dict]:
    """Theo lớp: số flow, số flow bị rule báo, tỉ lệ (recall với lớp tấn công, FPR với BENIGN)."""
    totals, flagged = Counter(), Counter()
    for flow in flows:
        totals[flow["eval_label"]] += 1
        if flow["alert_count"] > 0:
            flagged[flow["eval_label"]] += 1
    return {label: {"flows": totals[label], "rule_flagged": flagged[label],
                    "rate": _ratio(flagged[label], totals[label])}
            for label in sorted(totals, key=lambda name: (name in SKIPPED, name != BENIGN, name))}


def _alert_summary(alerts: Sequence[dict]) -> dict:
    tp = sum(1 for a in alerts if a["label"] not in (BENIGN,) + SKIPPED)
    fp = sum(1 for a in alerts if a["label"] == BENIGN)
    return {"alerts": len(alerts), "tp": tp, "fp": fp, "skipped": len(alerts) - tp - fp,
            "precision": _ratio(tp, tp + fp)}


def source_metrics(alerts: Sequence[dict]) -> Dict[str, dict]:
    groups = defaultdict(list)
    for alert in alerts:
        groups[alert["source_type"]].append(alert)
    return {source: _alert_summary(items) for source, items in sorted(groups.items())}


def sid_metrics(alerts: Sequence[dict], matches_by_sid: Dict[int, int]) -> List[dict]:
    """Theo SID (rule) và theo loại ANOMALY: số cảnh báo, TP, FP, precision, 3 cặp IP báo nhầm nhiều nhất."""
    groups = defaultdict(list)
    for alert in alerts:
        name = alert["sid"] if alert["sid"] is not None else alert["msg"]
        groups[name].append(alert)
    rows = []
    for name, items in groups.items():
        summary = _alert_summary(items)
        fp_pairs = Counter(f"{a['src_ip']} → {a['dst_ip']}:{a['dst_port']}" for a in items if a["label"] == BENIGN)
        rows.append({"sid": name if isinstance(name, int) else None, "name": items[0]["msg"],
                     "source_type": items[0]["source_type"],
                     "raw_matches": matches_by_sid.get(name, 0) if isinstance(name, int) else None,
                     "labels": dict(Counter(a["label"] for a in items)),
                     "top_fp": fp_pairs.most_common(3), **summary})
    rows.sort(key=lambda r: -r["alerts"])
    return rows


def _clip(window: Tuple[float, float], ranges: Sequence[Tuple[float, float]]) -> List[Tuple[float, float]]:
    pieces = []
    for lo, hi in ranges:
        a, b = max(window[0], lo), min(window[1], hi)
        if a < b:
            pieces.append((a, b))
    if not pieces:
        return []
    merged = [pieces[0]]
    for a, b in pieces[1:]:
        if a <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], b))
        else:
            merged.append((a, b))
    return merged


def episode_metrics(index: LabelIndex, alerts: Sequence[dict], flows: Sequence[dict],
                    chunk_ranges: Sequence[Tuple[float, float]], bot_hosts: Sequence[str]) -> List[dict]:
    """Phát hiện theo đợt.

    - PortScan, DDoS: mỗi khoảng giờ liên tục trong CSV là một đợt, cắt theo các chunk của lượt đo.
      Đợt được phát hiện nếu có cảnh báo mang nhãn lớp đó trong đợt (nới 60 giây hai đầu).
    - Bot: mỗi máy nhiễm (thuộc tập đang đo) là một đợt, phát hiện nếu có cảnh báo nhãn Bot dính IP máy đó.
    """
    rows = []
    for label in ("PortScan", "DDoS"):
        number = 0
        for window in index.attack_windows(label):
            for start, end in _clip(window, chunk_ranges):
                number += 1
                hits = [a for a in alerts if a["label"] == label and start - 60 <= a["timestamp"] <= end + 60]
                rows.append(_episode_row(label, f"đợt {number}", start, end, hits))
    host_alerts = defaultdict(list)
    for alert in alerts:
        if alert["label"] != "Bot":
            continue
        if alert["flow"] is not None:
            host = bot_host(flows[alert["flow"]])
            if host:
                host_alerts[host].append(alert)
        else:
            for ip in (alert.get("src_ip"), alert.get("dst_ip")):
                host_alerts[ip].append(alert)
    for host in bot_hosts:
        bot_flows = [f for f in flows if f["eval_label"] == "Bot" and bot_host(f) == host]
        if not bot_flows:
            continue
        start = min(f["first_seen"] for f in bot_flows)
        end = max(f["last_seen"] for f in bot_flows)
        rows.append(_episode_row("Bot", host, start, end, host_alerts.get(host, [])))
    return rows


def _episode_row(label: str, name: str, start: float, end: float, hits: Sequence[dict]) -> dict:
    by_source = Counter(a["source_type"] for a in hits)
    first = min((a["timestamp"] for a in hits), default=None)
    # cảnh báo đầu có thể sớm hơn mốc bắt đầu một chút (giờ CSV chỉ tới phút), khi đó coi như 0 giây
    return {"label": label, "name": name, "start": start, "end": end, "detected": bool(hits),
            "alerts": len(hits), "by_source": dict(by_source),
            "time_to_detect": max(0.0, first - start) if first is not None else None}
