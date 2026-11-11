import logging
import queue
import threading
import time
from collections import Counter
from datetime import timedelta
from typing import List, Optional

from nids.config import SETTINGS
from nids.logger import setup_logging
from nids.db import init_db
from nids.db.models import utc_now
from nids.db.repository import EventRepository
from nids.engine.decoder import PacketDecoder
from nids.engine.flow import Flow, FlowTracker
from nids.engine.alert_writer import AlertWriter
from nids.engine.capture import PacketCapture, apply_layer_filter
from nids.engine.rule import SnortRule
from nids.engine.rule_manager import RuleManager
from nids.engine.detector import DetectionEngine
from nids.engine.stream import StreamReassembler
from nids.ai import AITrafficWorker
from nids.engine.anomaly import AnomalyDetector

logger = logging.getLogger("nids.engine")
alert_logger = logging.getLogger("nids.alert")
capture_logger = logging.getLogger("nids.capture")

# Số cảnh báo đã phát theo priority, dùng cho dòng tổng kết cuối lượt replay pcap
alert_counts: Counter = Counter()


def _endpoint(ip: str, port: Optional[int]) -> str:
    return f"{ip}:{port}" if port is not None else str(ip)


def format_alert(alert_data: dict) -> str:
    """Dựng dòng cảnh báo một dòng: priority, SID, tên tấn công, nguồn → đích."""
    sid = alert_data.get("sid")
    if sid is not None:
        label = f"SID {sid}"
    else:
        label = "ANOMALY" if alert_data.get("source_type") == "ANOMALY" else "AI-ANOMALY"
    src = _endpoint(alert_data.get("src_ip"), alert_data.get("src_port"))
    dst = _endpoint(alert_data.get("dst_ip"), alert_data.get("dst_port"))
    return f"[P{alert_data.get('severity', 2)}] {label}  {alert_data.get('msg')}  {src} → {dst}"


def format_summary(total_packets: int, by_priority: Counter, elapsed: Optional[float] = None) -> str:
    """Dựng dòng tổng kết: luôn có P1, P2, P3; priority khác (nếu có) nối thêm theo thứ tự tăng dần.

    Có `elapsed` (giây) thì nối thêm thời gian chạy và tốc độ, để đo thông lượng của engine.
    """
    keys = [1, 2, 3] + sorted(k for k in by_priority if k not in (1, 2, 3))
    detail = ", ".join(f"P{k}: {by_priority.get(k, 0)}" for k in keys)
    line = f"Hoàn tất: {total_packets} gói, {sum(by_priority.values())} cảnh báo ({detail})"
    if elapsed is not None and elapsed > 0:
        line += f" trong {elapsed:.1f} giây ({total_packets / elapsed:.0f} gói/giây)"
    return line


class DropCounter:
    """Gộp các lần drop gói để chỉ báo tối đa một lần mỗi `interval` giây."""

    def __init__(self, interval: float = 5.0):
        self.interval = interval
        self._pending = 0
        self.total = 0  # Tổng số gói đã drop, gồm cả các lần chưa được báo
        self._last_report: Optional[float] = None

    def record(self, now: float) -> Optional[int]:
        """Trả về số gói đã drop dồn lại nếu đến lúc báo, ngược lại trả về None."""
        self._pending += 1
        self.total += 1
        if self._last_report is None or now - self._last_report >= self.interval:
            dropped, self._pending = self._pending, 0
            self._last_report = now
            return dropped
        return None


# Thời gian chờ mỗi lượt khi hàng đợi đầy ở chế độ offline. Có timeout thì Ctrl+C trên Windows vẫn ngắt được
# và thread đọc pcap kịp nhận ra worker đã dừng, thay vì treo mãi.
OFFLINE_PUT_TIMEOUT = 0.5


def enqueue_packet(packet_queue: queue.Queue, packet, live: bool, stop_event: threading.Event,
                   worker_alive, drops: DropCounter) -> bool:
    """Đưa gói vào hàng đợi phân tích; trả về True nếu gói đã vào hàng đợi.

    - Live: hàng đợi đầy thì bỏ gói và đếm vào `drops` (bắt gói trực tiếp không thể chờ).
    - Offline: đọc file không cần vội, nên hàng đợi đầy thì chờ chỗ trống, không bỏ gói. Ngừng chờ khi
      `stop_event` được đặt hoặc `worker_alive()` trả về False; khi worker đã dừng thì tự đặt `stop_event`
      để việc đọc pcap dừng theo.
    """
    if live:
        try:
            packet_queue.put_nowait(packet)
            return True
        except queue.Full:
            dropped = drops.record(time.monotonic())
            if dropped:
                logger.warning("Queue đầy, đã bỏ %d gói", dropped)
            return False
    while not stop_event.is_set():
        try:
            packet_queue.put(packet, timeout=OFFLINE_PUT_TIMEOUT)
            return True
        except queue.Full:
            if not worker_alive():
                logger.error("Worker thread đã dừng, ngừng đọc pcap")
                stop_event.set()
    return False


def wait_until_processed(packet_queue: queue.Queue, worker_alive, poll: float = 0.5) -> bool:
    """Chờ worker xử lý hết các gói đã đưa vào hàng đợi; trả về False nếu worker dừng trước khi xong.

    Thay cho `packet_queue.join()`: hàm đó chờ mãi khi worker đã chết và không còn ai gọi `task_done()`.
    """
    with packet_queue.all_tasks_done:
        while packet_queue.unfinished_tasks:
            if not worker_alive():
                return False
            packet_queue.all_tasks_done.wait(poll)
    return True


class RuleReloader:
    """Nạp lại rule khi file .rules hoặc state.yaml đổi (web ghi từ process API), kiểm tra tối đa mỗi `interval` giây.

    Gọi từ chính worker thread nên không cần khoá: không có gói nào được đánh giá trong lúc dựng lại index.
    """

    def __init__(self, rule_manager: RuleManager, engine: DetectionEngine, interval: float = 2.0):
        self.rule_manager = rule_manager
        self.engine = engine
        self.interval = interval
        self._signature = rule_manager.signature()
        self._checked_at = time.monotonic()

    def check(self, now: float) -> bool:
        if now - self._checked_at < self.interval:
            return False
        self._checked_at = now
        try:
            signature = self.rule_manager.signature()
            if signature == self._signature:
                return False
            self._signature = signature
            self.rule_manager.load_all_rules()
            self.engine.rebuild_index()
        except Exception as e:
            logger.error("Không nạp lại được rule, giữ tập rule cũ: %s", e)
            return False
        logger.info("Rule đã thay đổi, đã nạp lại %d rule", len(self.rule_manager.rules))
        return True


class FlowLog:
    """Gom gói thành flow và ghi flow đã kết thúc vào CSDL theo lô (không ghi từng gói).

    Gọi từ chính worker thread nên không cần khoá. Lỗi CSDL chỉ được log, không làm sập engine.
    """

    CLEANUP_INTERVAL = 3600.0

    def __init__(self, tracker: FlowTracker, batch_size: int = 500, flush_interval: float = 5.0,
                 retention_hours: float = 24.0):
        self.tracker = tracker
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self.retention_hours = retention_hours
        self._pending: List[Flow] = []
        self._last_flush = time.monotonic()
        self._last_cleanup: Optional[float] = None

    def on_packet(self, packet, alert_count: int = 0) -> None:
        """Cộng gói vào flow; `alert_count` là số rule vừa khớp gói này."""
        try:
            self._pending += self.tracker.update(packet, alert_count)
        except Exception as e:
            logger.error("Không gom được flow: %s", e)
        self._maybe_flush()

    def tick(self, now: float) -> None:
        """Cho flow hết hạn khi không có gói mới (mạng yên lặng); `now` là epoch."""
        try:
            self._pending += self.tracker.expire(now)
        except Exception as e:
            logger.error("Không xử lý được timeout flow: %s", e)
        self._maybe_flush()

    def close(self) -> None:
        """Xuất mọi flow còn mở rồi ghi nốt, gọi khi engine dừng hoặc đọc hết pcap."""
        self._pending += self.tracker.flush()
        self._write()

    def _maybe_flush(self) -> None:
        if self._pending and (len(self._pending) >= self.batch_size
                              or time.monotonic() - self._last_flush >= self.flush_interval):
            self._write()

    def _write(self) -> None:
        batch, self._pending = self._pending, []
        self._last_flush = time.monotonic()
        if batch:
            try:
                EventRepository.save_flows(batch)
            except Exception as e:
                logger.error("Không thể lưu %d flow vào CSDL: %s", len(batch), e)
        self._cleanup()

    def _cleanup(self) -> None:
        if self.retention_hours <= 0:
            return
        now = time.monotonic()
        if self._last_cleanup is not None and now - self._last_cleanup < self.CLEANUP_INTERVAL:
            return
        self._last_cleanup = now
        try:
            deleted = EventRepository.delete_flows_before(utc_now() - timedelta(hours=self.retention_hours))
            if deleted:
                logger.info("Đã dọn %d flow cũ hơn %s giờ", deleted, self.retention_hours)
        except Exception as e:
            logger.error("Không dọn được flow cũ: %s", e)


def evaluate_with_stream(engine: DetectionEngine, reassembler: Optional[StreamReassembler], packet) -> List[SnortRule]:
    """So khớp gói tin như cũ rồi so khớp thêm dữ liệu đã ghép (nếu có); lỗi khi ghép không làm mất kết quả từng gói."""
    matched = engine.evaluate_packet(packet)
    if reassembler is None:
        return matched
    try:
        view = reassembler.feed(packet, matched)
        if view is not None:
            matched = matched + engine.evaluate_stream(view)
    except Exception as e:
        logger.error("Không tái hợp được luồng TCP: %s", e)
    return matched


def observe_anomaly(detector: Optional[AnomalyDetector], packet) -> None:
    """Đưa gói cho lớp phát hiện bất thường; lỗi chỉ được log để không dừng worker thread."""
    if detector is None:
        return
    try:
        detector.observe(packet)
    except Exception as e:
        logger.error("Lớp phát hiện bất thường gặp lỗi: %s", e)


class HoneypotIPCache:
    """Tập IP đã chạm honeypot, làm mới từ CSDL tối đa một lần mỗi `ttl` giây (honeypot ghi từ process khác)."""

    def __init__(self, ttl: float = 5.0):
        self.ttl = ttl
        self._ips: set = set()
        self._loaded_at: Optional[float] = None

    def __contains__(self, ip: str) -> bool:
        now = time.monotonic()
        if self._loaded_at is None or now - self._loaded_at >= self.ttl:
            self._loaded_at = now  # đặt trước khi truy vấn để CSDL lỗi cũng không bị gọi lại mỗi gói
            try:
                self._ips = EventRepository.honeypot_attacker_ips()
            except Exception as e:
                logger.error("Không đọc được danh sách IP honeypot: %s", e)
        return ip in self._ips


honeypot_ips = HoneypotIPCache()


def enrich_alert(alert_data: dict) -> dict:
    """IP đã chạm honeypot chắc chắn là attacker: nâng một bậc priority (tối đa P1) và gắn nhãn."""
    if alert_data.get("source_type", "RULE_ENGINE") != "RULE_ENGINE" or alert_data.get("src_ip") not in honeypot_ips:
        return alert_data
    return {
        **alert_data,
        "severity": max(1, alert_data.get("severity", 2) - 1),
        "msg": f"{alert_data.get('msg')} [honeypot-confirmed]",
    }


def handle_alert(alert_data: dict) -> None:
    """Callback khi phát hiện vi phạm: hiện cảnh báo trên terminal rồi lưu vào CSDL."""
    alert_data = enrich_alert(alert_data)
    severity = alert_data.get("severity", 2)
    alert_counts[severity] += 1
    # Hiện cảnh báo trước khi lưu DB để lỗi CSDL không làm mất cảnh báo trên màn hình
    alert_logger.warning(format_alert(alert_data), extra={"priority": severity})
    if alert_writer is not None:
        # Engine đang chạy: ghi theo lô ở thread riêng, worker không phải chờ CSDL
        alert_writer.submit(alert_data)
        return
    try:
        EventRepository.save_alert(alert_data)
    except Exception as e:
        logger.error("Không thể lưu cảnh báo vào CSDL: %s", e)


# Bộ ghi cảnh báo theo lô của engine đang chạy; None khi chưa chạy main() (ví dụ test gọi handle_alert trực tiếp)
alert_writer: Optional[AlertWriter] = None


def main():
    global alert_writer
    setup_logging(SETTINGS.get("system", {}).get("log_level", "INFO"))
    capture_mode = SETTINGS.get("network", {}).get("capture_mode", "live")
    live = capture_mode != "offline"
    logger.info("Khởi động Hybrid NIDS (chế độ: %s)", capture_mode)

    init_db()
    # Offline thì chờ chứ không bỏ cảnh báo (đọc file dùng để đo, không được mất dữ liệu); live thì bỏ và đếm
    alert_writer = AlertWriter(EventRepository.save_alerts, block=not live).start()

    # Nạp rule từ thư mục rules/ (RuleManager tự ghi log số rule đã nạp)
    rules_dir = SETTINGS.get("detection", {}).get("rules_dir", "rules")
    rule_manager = RuleManager(rules_dir)
    rule_manager.load_all_rules()

    detection_engine = DetectionEngine(rule_manager, alert_callback=handle_alert)
    ai_worker = AITrafficWorker(alert_callback=handle_alert)
    anomaly_cfg = SETTINGS.get("anomaly") or {}
    anomaly = AnomalyDetector(anomaly_cfg, alert_callback=handle_alert) if anomaly_cfg.get("enabled", True) else None

    stream_cfg = SETTINGS.get("stream", {})
    reassembler = None
    if stream_cfg.get("enabled", True):
        reassembler = StreamReassembler(
            depth=stream_cfg.get("depth", 65536), max_total_bytes=stream_cfg.get("max_total_bytes", 67108864),
            max_streams=stream_cfg.get("max_streams", 50000), idle_timeout=stream_cfg.get("idle_timeout", 30),
            max_pending_segments=stream_cfg.get("max_pending_segments", 32),
        )

    flow_cfg = SETTINGS.get("flow", {})
    flow_log = FlowLog(
        FlowTracker(idle_timeout=flow_cfg.get("idle_timeout", 30), active_timeout=flow_cfg.get("active_timeout", 120),
                    closing_timeout=flow_cfg.get("closing_timeout", 2), max_flows=flow_cfg.get("max_flows", 100000)),
        batch_size=flow_cfg.get("batch_size", 500), flush_interval=flow_cfg.get("flush_interval", 5),
        retention_hours=flow_cfg.get("retention_hours", 24),
    )

    # Hàng đợi đệm bất đồng bộ giữa luồng bắt gói và luồng phân tích, chống rớt gói
    packet_queue = queue.Queue(maxsize=SETTINGS.get("detection", {}).get("queue_max_size", 10000))
    drops = DropCounter()
    analysis_errors = DropCounter()
    stats = {"packets": 0}
    stop_event = threading.Event()

    def worker_alive() -> bool:
        return worker_thread.is_alive()

    def on_raw_packet(scapy_pkt):
        """Callback từ PacketCapture: giải mã gói tin thô rồi đẩy vào hàng đợi."""
        decoded = PacketDecoder.decode(scapy_pkt)
        if decoded is None:
            return  # Bỏ qua gói tin không phải IP
        if enqueue_packet(packet_queue, decoded, live, stop_event, worker_alive, drops):
            stats["packets"] += 1  # Chỉ đếm gói thực sự được đưa vào phân tích

    reloader = RuleReloader(rule_manager, detection_engine)

    # Luồng worker xử lý phân tích
    def worker_loop():
        while not stop_event.is_set():
            reloader.check(time.monotonic())
            try:
                packet = packet_queue.get(timeout=1.0)
            except queue.Empty:
                if live:
                    flow_log.tick(time.time())  # mạng yên lặng vẫn phải cho flow hết hạn
                continue
            try:
                matched = evaluate_with_stream(detection_engine, reassembler, packet)
                ai_worker.analyze_packet(packet)
                flow_log.on_packet(packet, len(matched))  # sau evaluate_packet để biết gói có khớp rule
                observe_anomaly(anomaly, packet)
            except Exception as e:
                # Một gói lỗi không được làm dừng worker: ghi log (gộp đếm) rồi xử lý gói tiếp theo
                failed = analysis_errors.record(time.monotonic())
                if failed:
                    logger.error("Lỗi khi phân tích gói, đã bỏ qua %d gói: %s", failed, e)
            finally:
                packet_queue.task_done()
        flow_log.close()  # thread này là nơi duy nhất đụng vào bảng flow nên đóng ở đây

    worker_thread = threading.Thread(target=worker_loop, daemon=True)
    worker_thread.start()

    # Khởi chạy bắt gói tin
    bpf = SETTINGS.get("network", {}).get("bpf_filter", "ip")
    iface = SETTINGS.get("network", {}).get("interface", None) or None
    capturer = PacketCapture(raw_callback=on_raw_packet, bpf_filter=bpf)
    apply_layer_filter()   # Scapy chỉ bóc tới L4: nhanh hơn và raw_packet đúng byte gốc

    try:
        if capture_mode == "offline":
            pcap_file = SETTINGS.get("network", {}).get("pcap_file", "")
            capture_logger.info("Đọc file PCAP: %s", pcap_file)
            started = time.perf_counter()
            # stop_filter: worker dừng giữa chừng thì enqueue_packet đặt stop_event và việc đọc pcap dừng theo
            capturer.start_offline(pcap_file, stop_filter=lambda _pkt: stop_event.is_set())
            # Đợi worker xử lý hết các gói còn trong hàng đợi
            if not wait_until_processed(packet_queue, worker_alive):
                logger.error("Worker thread đã dừng trước khi xử lý hết hàng đợi, kết quả có thể thiếu")
            # Thứ tự kết thúc: dừng worker (ghi nốt flow) → ghi nốt cảnh báo → mới in tổng kết,
            # để ai đọc CSDL ngay sau khi engine dừng cũng thấy đủ dữ liệu
            stop_event.set()
            worker_thread.join(timeout=10)
            alert_writer.close()
            elapsed = time.perf_counter() - started
            if analysis_errors.total:
                logger.warning("Tổng cộng %d gói bị bỏ qua vì lỗi khi phân tích", analysis_errors.total)
            if drops.total:
                logger.warning("Tổng cộng %d gói bị bỏ do queue đầy, kết quả có thể thiếu cảnh báo", drops.total)
            logger.info(format_summary(stats["packets"], alert_counts, elapsed))
            logger.info("Xem cảnh báo tại http://localhost:8000/api/alerts/")
        else:
            capture_logger.info("Lắng nghe trực tiếp trên card mạng (BPF: '%s', nhấn Ctrl+C để dừng)", bpf)
            capturer.start_live(iface)
    except KeyboardInterrupt:
        logger.info("Dừng hệ thống NIDS")
    except Exception as e:
        logger.error("Lỗi khi bắt gói tin: %s", e)
    finally:
        # sniff có thể nuốt Ctrl+C và trả về bình thường nên phải dừng worker ở đây để flow còn mở được ghi nốt
        stop_event.set()
        worker_thread.join(timeout=10)
        alert_writer.close()   # gọi lần hai (sau nhánh offline) không làm gì
        alert_writer = None


if __name__ == "__main__":
    main()
