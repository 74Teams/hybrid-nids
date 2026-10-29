import logging
import queue
import threading
import time
from collections import Counter
from typing import Optional

from nids.config import SETTINGS
from nids.logger import setup_logging
from nids.db import init_db
from nids.db.repository import EventRepository
from nids.engine.decoder import PacketDecoder
from nids.engine.capture import PacketCapture
from nids.engine.rule_manager import RuleManager
from nids.engine.detector import DetectionEngine
from nids.ai import AITrafficWorker

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
    label = f"SID {sid}" if sid is not None else "AI-ANOMALY"
    src = _endpoint(alert_data.get("src_ip"), alert_data.get("src_port"))
    dst = _endpoint(alert_data.get("dst_ip"), alert_data.get("dst_port"))
    return f"[P{alert_data.get('severity', 2)}] {label}  {alert_data.get('msg')}  {src} → {dst}"


def format_summary(total_packets: int, by_priority: Counter) -> str:
    """Dựng dòng tổng kết: luôn có P1, P2, P3; priority khác (nếu có) nối thêm theo thứ tự tăng dần."""
    keys = [1, 2, 3] + sorted(k for k in by_priority if k not in (1, 2, 3))
    detail = ", ".join(f"P{k}: {by_priority.get(k, 0)}" for k in keys)
    return f"Hoàn tất: {total_packets} gói, {sum(by_priority.values())} cảnh báo ({detail})"


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
    try:
        EventRepository.save_alert(alert_data)
    except Exception as e:
        logger.error("Không thể lưu cảnh báo vào CSDL: %s", e)


def main():
    setup_logging(SETTINGS.get("system", {}).get("log_level", "INFO"))
    capture_mode = SETTINGS.get("network", {}).get("capture_mode", "live")
    logger.info("Khởi động Hybrid NIDS (chế độ: %s)", capture_mode)

    init_db()

    # Nạp rule từ thư mục rules/ (RuleManager tự ghi log số rule đã nạp)
    rules_dir = SETTINGS.get("detection", {}).get("rules_dir", "rules")
    rule_manager = RuleManager(rules_dir)
    rule_manager.load_all_rules()

    detection_engine = DetectionEngine(rule_manager, alert_callback=handle_alert)
    ai_worker = AITrafficWorker(alert_callback=handle_alert)

    # Hàng đợi đệm bất đồng bộ giữa luồng bắt gói và luồng phân tích, chống rớt gói
    packet_queue = queue.Queue(maxsize=SETTINGS.get("detection", {}).get("queue_max_size", 10000))
    drops = DropCounter()
    stats = {"packets": 0}

    def on_raw_packet(scapy_pkt):
        """Callback từ PacketCapture: giải mã gói tin thô rồi đẩy vào hàng đợi."""
        decoded = PacketDecoder.decode(scapy_pkt)
        if decoded is None:
            return  # Bỏ qua gói tin không phải IP
        try:
            packet_queue.put_nowait(decoded)
            stats["packets"] += 1  # Chỉ đếm gói thực sự được đưa vào phân tích
        except queue.Full:
            dropped = drops.record(time.monotonic())
            if dropped:
                logger.warning("Queue đầy, đã bỏ %d gói", dropped)

    reloader = RuleReloader(rule_manager, detection_engine)

    # Luồng worker xử lý phân tích
    def worker_loop():
        while True:
            reloader.check(time.monotonic())
            try:
                packet = packet_queue.get(timeout=1.0)
                detection_engine.evaluate_packet(packet)
                ai_worker.analyze_packet(packet)
                packet_queue.task_done()
            except queue.Empty:
                continue

    worker_thread = threading.Thread(target=worker_loop, daemon=True)
    worker_thread.start()

    # Khởi chạy bắt gói tin
    bpf = SETTINGS.get("network", {}).get("bpf_filter", "ip")
    iface = SETTINGS.get("network", {}).get("interface", None) or None
    capturer = PacketCapture(raw_callback=on_raw_packet, bpf_filter=bpf)

    try:
        if capture_mode == "offline":
            pcap_file = SETTINGS.get("network", {}).get("pcap_file", "")
            capture_logger.info("Đọc file PCAP: %s", pcap_file)
            capturer.start_offline(pcap_file)
            # Đợi worker xử lý hết các gói còn trong hàng đợi
            packet_queue.join()
            time.sleep(0.5)  # Chờ các cảnh báo cuối cùng được ghi xong
            if drops.total:
                logger.warning("Tổng cộng %d gói bị bỏ do queue đầy, kết quả có thể thiếu cảnh báo", drops.total)
            logger.info(format_summary(stats["packets"], alert_counts))
            logger.info("Xem cảnh báo tại http://localhost:8000/api/alerts/")
        else:
            capture_logger.info("Lắng nghe trực tiếp trên card mạng (BPF: '%s', nhấn Ctrl+C để dừng)", bpf)
            capturer.start_live(iface)
    except KeyboardInterrupt:
        logger.info("Dừng hệ thống NIDS")
    except Exception as e:
        logger.error("Lỗi khi bắt gói tin: %s", e)


if __name__ == "__main__":
    main()
