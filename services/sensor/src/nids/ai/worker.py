"""
Bộ phân tích AI của sensor: chấm từng flow đã kết thúc bằng mô hình Random Forest rồi gộp thành một cảnh báo cho mỗi đợt.

Luồng gói chỉ gọi `submit` (đẩy flow vào hàng đợi, không chờ). Luồng nền của worker nhận flow đúng thứ tự `FlowTracker`
xuất, cập nhật ngữ cảnh theo IP, tính 40 đặc trưng, chấm theo lô và áp ngưỡng riêng cho từng lớp.
Mô hình thiếu, lệch đặc trưng hay thiếu thư viện thì `from_settings` trả `None`: AI tắt, phần còn lại của sensor vẫn chạy.
"""
import logging
import queue
import threading
import time
from collections import OrderedDict
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from nids.engine.flow import Flow

logger = logging.getLogger("nids.ai")

DEFAULTS: Dict[str, Any] = {
    "enabled": True,
    "model_path": "data/models/flow_model.joblib",
    "batch_size": 256,
    "batch_wait": 1.0,            # giây chờ thêm để gom đủ lô khi flow đến thưa
    "queue_max_size": 20000,
    "suppress_seconds": 60,       # mỗi cặp (IP nguồn, loại tấn công) chỉ báo một lần trong ngần này giây (theo giờ của flow)
    "max_tracked": 10000,         # số cặp giữ trạng thái chặn lặp
    "ignore_ips": [],             # flow có IP nguồn nằm trong danh sách này không bị chấm
}
BENIGN = "BENIGN"

# Mức độ nặng theo nhãn (số nhỏ = nặng, cùng thang với rule); nhãn lạ mặc định P2
SEVERITY: Dict[str, int] = {"DDoS": 1, "DoS": 1, "Bot": 1, "PortScan": 2, "BruteForce": 2}
EXAMPLE_TARGETS = 5


def load_bundle(path: str) -> Dict[str, Any]:
    """Nạp mô hình và kiểm tra khớp với `FEATURE_NAMES` hiện tại. Lỗi thì ném ngoại lệ để người gọi tắt AI."""
    import joblib
    from nids.ai.features import FEATURE_NAMES

    bundle = joblib.load(path)
    for key in ("rf", "feature_names", "thresholds", "context"):
        if key not in bundle:
            raise ValueError(f"mô hình thiếu trường '{key}'")
    if list(bundle["feature_names"]) != FEATURE_NAMES:
        raise ValueError("mô hình học với danh sách đặc trưng khác bản hiện tại, cần học lại")
    trained = bundle.get("sklearn_version")
    if trained:
        import sklearn
        if sklearn.__version__ != trained:
            logger.warning("Mô hình học bằng scikit-learn %s nhưng đang chạy %s: kết quả có thể sai", trained,
                           sklearn.__version__)
    return bundle


class AITrafficWorker:
    """Chấm flow theo lô ở luồng nền và gọi `alert_callback` một lần cho mỗi đợt tấn công."""

    def __init__(self, bundle: Dict[str, Any], alert_callback: Optional[Callable[[dict], None]] = None,
                 config: Optional[Dict[str, Any]] = None):
        from nids.ai.context import FlowContext

        cfg = {**DEFAULTS, **(config or {})}
        self.alert_callback = alert_callback
        self.batch_size = max(1, int(cfg["batch_size"]))
        self.batch_wait = float(cfg["batch_wait"])
        self.suppress_seconds = float(cfg["suppress_seconds"])
        self.max_tracked = int(cfg["max_tracked"])
        self.ignore_ips = set(cfg["ignore_ips"] or [])
        self.rf = bundle["rf"]
        self.classes: List[str] = [str(c) for c in self.rf.classes_]
        self.per_class: Dict[str, float] = dict(bundle["thresholds"].get("per_class", {}))
        settings = bundle["context"]
        self.context = FlowContext(window=settings["window"], short_window=settings["short_window"],
                                   max_tracked=settings["max_tracked"], max_per_ip=settings["max_per_ip"])
        self._queue: queue.Queue = queue.Queue(maxsize=int(cfg["queue_max_size"]))
        self._last_alert: "OrderedDict[Tuple[str, str], float]" = OrderedDict()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.dropped = 0
        self._last_drop_log = 0.0
        self.scored = 0
        self.flagged = 0

    @classmethod
    def from_settings(cls, config: Optional[Dict[str, Any]],
                      alert_callback: Optional[Callable[[dict], None]] = None) -> Optional["AITrafficWorker"]:
        """Dựng worker từ mục `ai` của cấu hình; tắt hoặc lỗi thì trả `None` (ghi log một lần, không làm sập sensor)."""
        cfg = {**DEFAULTS, **(config or {})}
        if not cfg["enabled"]:
            logger.info("AI đang tắt (ai.enabled = false)")
            return None
        path = Path(cfg["model_path"])
        if not path.is_file():
            logger.warning("Không thấy mô hình AI tại %s: AI tắt, sensor vẫn chạy", path)
            return None
        try:
            bundle = load_bundle(str(path))
            worker = cls(bundle, alert_callback, cfg)
        except Exception as e:
            logger.error("Không nạp được mô hình AI (%s): AI tắt, sensor vẫn chạy", e)
            return None
        logger.info("Đã nạp mô hình AI %s (lớp: %s)", bundle.get("version", "?"), ", ".join(worker.classes))
        return worker

    # ------------------------------------------------------------------ vòng đời

    def start(self) -> "AITrafficWorker":
        self._thread = threading.Thread(target=self._run, name="ai-worker", daemon=True)
        self._thread.start()
        return self

    def alive(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def submit(self, flows: List[Flow]) -> None:
        """Gọi từ luồng gói: đẩy flow vào hàng đợi, không bao giờ chờ. Đầy thì bỏ flow và đếm."""
        for flow in flows:
            try:
                self._queue.put_nowait(flow)
            except queue.Full:
                self.dropped += 1
                now = time.monotonic()
                if now - self._last_drop_log >= 5.0:
                    self._last_drop_log = now
                    logger.warning("Hàng đợi AI đầy, đã bỏ %d flow (tổng)", self.dropped)

    def close(self, timeout: float = 10.0) -> None:
        """Chấm nốt flow còn trong hàng đợi rồi dừng luồng nền. Gọi nhiều lần không sao."""
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout)
            if self._thread.is_alive():
                logger.warning("Luồng AI chưa dừng sau %.0fs, còn %d flow chưa chấm", timeout, self._queue.qsize())

    # ------------------------------------------------------------------ luồng nền

    def _run(self) -> None:
        while True:
            batch = self._take_batch()
            if batch:
                try:
                    self._process(batch)
                except Exception as e:
                    logger.error("Lỗi khi chấm lô %d flow, đã bỏ lô này: %s", len(batch), e)
            elif self._stop.is_set():
                return

    def _take_batch(self) -> List[Flow]:
        batch: List[Flow] = []
        deadline = time.monotonic() + self.batch_wait
        while len(batch) < self.batch_size:
            try:
                if self._stop.is_set():
                    batch.append(self._queue.get_nowait())
                else:
                    batch.append(self._queue.get(timeout=max(0.01, deadline - time.monotonic())))
            except queue.Empty:
                break
            if not self._stop.is_set() and time.monotonic() >= deadline:
                break
        return batch

    def _process(self, flows: List[Flow]) -> None:
        import numpy as np
        from nids.ai.features import FEATURE_NAMES, extract_features

        if self.ignore_ips:
            flows = [f for f in flows if f.src_ip not in self.ignore_ips]
        if not flows:
            return
        rows = []
        for flow in flows:   # đúng thứ tự xuất của tracker: ngữ cảnh phụ thuộc thứ tự
            features = extract_features(flow, self.context.update(flow))
            rows.append([features[name] for name in FEATURE_NAMES])
        proba = self.rf.predict_proba(np.array(rows, dtype="float64"))
        best = proba.argmax(axis=1)
        self.scored += len(flows)
        groups: "OrderedDict[Tuple[str, str], List[Tuple[Flow, float]]]" = OrderedDict()
        for flow, index, row in zip(flows, best, proba):
            label = self.classes[index]
            if label == BENIGN or row[index] < self.per_class.get(label, 0.5):
                continue
            groups.setdefault((flow.src_ip, label), []).append((flow, float(row[index])))
        for (src_ip, label), items in groups.items():
            self.flagged += len(items)
            self._alert(src_ip, label, items)

    def _alert(self, src_ip: str, label: str, items: List[Tuple[Flow, float]]) -> None:
        first = items[0][0]
        key = (src_ip, label)
        last = self._last_alert.get(key)
        if last is not None and first.first_seen - last < self.suppress_seconds:
            return
        self._last_alert[key] = first.first_seen
        self._last_alert.move_to_end(key)
        while len(self._last_alert) > self.max_tracked:
            self._last_alert.popitem(last=False)
        if self.alert_callback is None:
            return
        targets = list(OrderedDict.fromkeys(f"{f.dst_ip}:{f.dst_port}" if f.dst_port is not None else f.dst_ip
                                            for f, _ in items))
        extra = f" (+{len(targets) - EXAMPLE_TARGETS})" if len(targets) > EXAMPLE_TARGETS else ""
        evidence = (f"{len(items)} flow bị chấm là {label}, xác suất cao nhất {max(p for _, p in items):.2f}; "
                    f"đích: {', '.join(targets[:EXAMPLE_TARGETS])}{extra}")
        try:
            self.alert_callback({
                "timestamp": first.first_seen, "sid": None, "source_type": "AI_ENGINE",
                "msg": f"AI: {label} từ {src_ip}", "severity": SEVERITY.get(label, 2), "classtype": label,
                "src_ip": src_ip, "src_port": first.src_port, "dst_ip": first.dst_ip, "dst_port": first.dst_port,
                "protocol": first.protocol, "matched_content": evidence,
            })
        except Exception as e:
            logger.error("Không gửi được cảnh báo AI: %s", e)
