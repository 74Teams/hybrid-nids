"""
Chạy đúng pipeline của engine trên một file pcap, không ghi CSDL và không có queue.

Mỗi gói đi qua: `PacketDecoder.decode` → `evaluate_with_stream` (rule + tái hợp TCP) → `FlowTracker` →
`AnomalyDetector`, giống worker thread trong `nids/engine/main.py`. Cảnh báo được gom vào bộ nhớ.

Kết quả không phụ thuộc máy chạy:
- Bộ biến header rule = `DEFAULT_RULE_VARIABLES` + giá trị ghi đè truyền vào, không đọc `settings.yaml`.
  (`RuleManager(variables=...)` thay hẳn bộ biến, nên phải gộp với mặc định, nếu không rule `$HTTP_PORTS` bị bỏ.)
- `decoder.HTTP_PORTS` được đặt lại theo đúng bộ biến đó trước khi decode.
- Tham số `stream`, `flow`, `anomaly` lấy từ `config/settings.example.yaml` (file được commit).
- Mặc định bỏ qua `rules/state.yaml` (trạng thái bật/tắt rule local của từng máy).
"""
import logging
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from scapy.utils import PcapReader

import nids.engine.decoder as decoder
from nids.config import EXAMPLE_SETTINGS_PATH, load_settings
from nids.engine.anomaly import AnomalyDetector
from nids.engine.decoder import PacketDecoder
from nids.engine.detector import DetectionEngine
from nids.engine.flow import Flow, FlowTracker
from nids.engine.main import evaluate_with_stream, observe_anomaly
from nids.engine.rule_header import DEFAULT_RULE_VARIABLES, http_ports
from nids.engine.rule_manager import RuleManager
from nids.engine.stream import StreamReassembler

logger = logging.getLogger("nids.eval")

FLOW_FIELDS = ("protocol", "src_ip", "src_port", "dst_ip", "dst_port", "first_seen", "last_seen", "fwd_packets",
               "bwd_packets", "fwd_bytes", "bwd_bytes", "tcp_flags", "alert_count", "end_reason")
ALERT_FIELDS = ("timestamp", "sid", "source_type", "msg", "severity", "src_ip", "src_port", "dst_ip", "dst_port",
                "protocol")


class RuleLoadError(Exception):
    """Nạp rule có cảnh báo (rule lỗi, biến thiếu...), nên kết quả đo không đáng tin."""


@dataclass
class RunConfig:
    rules_dir: str = "rules"
    variables: Dict[str, str] = field(default_factory=lambda: dict(DEFAULT_RULE_VARIABLES))
    stream: dict = field(default_factory=dict)
    flow: dict = field(default_factory=dict)
    anomaly: dict = field(default_factory=dict)
    use_state: bool = False


def build_variables(overrides: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """Biến mặc định của dự án, chồng bởi giá trị ghi đè (ví dụ HOME_NET của CIC)."""
    return {**DEFAULT_RULE_VARIABLES, **(overrides or {})}


def default_config(overrides: Optional[Dict[str, str]] = None, rules_dir: str = "rules",
                   use_state: bool = False) -> RunConfig:
    settings = load_settings(EXAMPLE_SETTINGS_PATH)
    return RunConfig(rules_dir=rules_dir, variables=build_variables(overrides),
                     stream=dict(settings.get("stream") or {}), flow=dict(settings.get("flow") or {}),
                     anomaly=dict(settings.get("anomaly") or {}), use_state=use_state)


class _ListHandler(logging.Handler):
    def __init__(self):
        super().__init__(level=logging.WARNING)
        self.messages: List[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.messages.append(record.getMessage())


def load_rules(rules_dir: str, variables: Dict[str, str], use_state: bool = False) -> RuleManager:
    """Nạp rule với bộ biến cho trước; có bất kỳ dòng `WARNING rules` nào thì ném `RuleLoadError`."""
    manager = RuleManager(rules_dir, variables=variables)
    if not use_state:
        manager.load_state = lambda: {}   # bỏ qua rules/state.yaml của máy này
    handler = _ListHandler()
    rules_logger = logging.getLogger("nids.rules")
    rules_logger.addHandler(handler)
    try:
        manager.load_all_rules()
    finally:
        rules_logger.removeHandler(handler)
    if handler.messages:
        raise RuleLoadError("; ".join(handler.messages[:5]))
    return manager


def _flow_row(flow: Flow) -> dict:
    return {name: getattr(flow, name) for name in FLOW_FIELDS}


def _alert_row(alert: dict) -> dict:
    row = {name: alert.get(name) for name in ALERT_FIELDS}
    row["source_type"] = row["source_type"] or "RULE_ENGINE"
    return row


def run_chunk(path: str, config: RunConfig) -> dict:
    """Chạy pipeline engine trên một file pcap; trả về flow, cảnh báo, phễu gói và thời gian từng bước."""
    started = time.perf_counter()
    old_http_ports = decoder.HTTP_PORTS
    decoder.HTTP_PORTS = http_ports(config.variables)
    try:
        manager = load_rules(config.rules_dir, config.variables, config.use_state)
        alerts: List[dict] = []
        engine = DetectionEngine(manager, alert_callback=alerts.append)
        stream_cfg = config.stream
        reassembler = None
        if stream_cfg.get("enabled", True):
            reassembler = StreamReassembler(
                depth=stream_cfg.get("depth", 65536), max_total_bytes=stream_cfg.get("max_total_bytes", 67108864),
                max_streams=stream_cfg.get("max_streams", 50000), idle_timeout=stream_cfg.get("idle_timeout", 30),
                max_pending_segments=stream_cfg.get("max_pending_segments", 32),
            )
        flow_cfg = config.flow
        tracker = FlowTracker(idle_timeout=flow_cfg.get("idle_timeout", 30),
                              active_timeout=flow_cfg.get("active_timeout", 120),
                              closing_timeout=flow_cfg.get("closing_timeout", 2),
                              max_flows=flow_cfg.get("max_flows", 100000))
        anomaly = None
        if config.anomaly.get("enabled", True):
            anomaly = AnomalyDetector(config.anomaly, alert_callback=alerts.append)

        timing: Counter = Counter()
        counts: Counter = Counter()
        matches_by_sid: Counter = Counter()
        flows: List[Flow] = []
        with PcapReader(str(path)) as reader:
            iterator = iter(reader)
            while True:
                t0 = time.perf_counter()
                try:
                    pkt = next(iterator)
                except StopIteration:
                    break
                t1 = time.perf_counter()
                timing["read"] += t1 - t0
                counts["total"] += 1
                packet = PacketDecoder.decode(pkt)
                t2 = time.perf_counter()
                timing["decode"] += t2 - t1
                if packet is None:
                    counts["not_ip"] += 1
                    continue
                counts["analyzed"] += 1
                try:
                    matched = evaluate_with_stream(engine, reassembler, packet)
                except Exception as e:   # một gói lỗi không được làm hỏng cả lượt đo
                    counts["errors"] += 1
                    if counts["errors"] <= 3:
                        logger.error("%s: lỗi khi so khớp gói %d: %s", Path(path).name, counts["total"], e)
                    matched = []
                t3 = time.perf_counter()
                timing["rules"] += t3 - t2
                counts["raw_matches"] += len(matched)
                matches_by_sid.update(rule.sid for rule in matched)
                flows.extend(tracker.update(packet, len(matched)))
                t4 = time.perf_counter()
                timing["flow"] += t4 - t3
                observe_anomaly(anomaly, packet)
                timing["anomaly"] += time.perf_counter() - t4
        flows.extend(tracker.flush())
    finally:
        decoder.HTTP_PORTS = old_http_ports
    return {
        "file": Path(path).name,
        "rules_loaded": len(manager.rules),
        "flows": [_flow_row(f) for f in flows],
        "alerts": [_alert_row(a) for a in alerts],
        "counts": dict(counts),
        "matches_by_sid": {int(k): v for k, v in matches_by_sid.items()},
        "timing": dict(timing),
        "elapsed": time.perf_counter() - started,
    }
