"""Vòng lặp chọn IP đáng ngờ từ bảng events rồi chuyển hướng sang honeypot, hết TTL thì gỡ.

Lỗi iptables hoặc CSDL trong một chu kỳ chỉ được log; chu kỳ sau thử lại. Redirector không ghi bảng events.
"""
import ipaddress
import logging
import threading
from typing import List, Optional, Set

from nids.config import RedirectSettings
from nids.db.repository import EventRepository
from nids.redirector.firewall import FirewallError, IptablesFirewall

logger = logging.getLogger("nids.redirector")


class RedirectPolicy:
    """IP nào được phép bị chuyển hướng: mọi IPv4 hợp lệ ngoài allowlist."""

    def __init__(self, allowlist: List[str]):
        self.networks = [ipaddress.ip_network(entry, strict=False) for entry in allowlist]

    def allows(self, ip: str) -> bool:
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return address.version == 4 and not any(address in network for network in self.networks)


class Redirector:
    def __init__(self, settings: RedirectSettings, firewall: IptablesFirewall, stop_event: Optional[threading.Event] = None):
        self.settings = settings
        self.firewall = firewall
        self.policy = RedirectPolicy(settings.allowlist)
        self.stop_event = stop_event or threading.Event()
        self._pending_removal: Set[str] = set()   # IP đã hết hạn nhưng gỡ rule thất bại, thử lại ở chu kỳ sau

    def start(self) -> None:
        """Kiểm tra iptables dùng được, dựng chain, xoá rule cũ. Ném `FirewallError` nếu iptables không dùng được."""
        self.firewall.check_available()
        self.firewall.ensure_setup()
        self.firewall.flush()
        try:
            EventRepository.expire_redirects()   # lượt đã hết hạn lúc redirector tắt; rule vừa bị xoá cả rồi
        except Exception as e:
            logger.error("Không đọc được danh sách chuyển hướng cũ: %s", e)
        logger.info("Redirector sẵn sàng (cổng %s, ngưỡng %d cảnh báo P%d trong %ds, TTL %ds)",
                    self.settings.ports, self.settings.min_alerts, self.settings.max_priority,
                    self.settings.window_seconds, self.settings.ttl_seconds)

    def run_once(self) -> None:
        """Một chu kỳ; không bao giờ ném lỗi."""
        self._expire()
        active = self._reassert()
        self._select_new(active)

    def _expire(self) -> None:
        try:
            self._pending_removal.update(EventRepository.expire_redirects())
        except Exception as e:
            logger.error("Không gỡ được chuyển hướng hết hạn khỏi CSDL: %s", e)
        for ip in sorted(self._pending_removal):
            try:
                self.firewall.remove(ip)
            except FirewallError as e:
                logger.error("Không gỡ được rule của %s, sẽ thử lại: %s", ip, e)
            else:
                self._pending_removal.discard(ip)
                logger.info("Hết hạn chuyển hướng %s, đã gỡ rule", ip)

    def _reassert(self) -> Set[str]:
        """Đảm bảo chain, jump và rule của mọi lượt đang hiệu lực còn tồn tại (có thể bị xoá từ bên ngoài)."""
        try:
            active = {row.ip for row in EventRepository.active_redirects()}
        except Exception as e:
            logger.error("Không đọc được danh sách chuyển hướng: %s", e)
            return set()
        try:
            self.firewall.ensure_setup()
            for ip in sorted(active):
                self.firewall.add(ip)
        except FirewallError as e:
            logger.error("Không đảm bảo được rule chuyển hướng: %s", e)
        return active

    def _select_new(self, active: Set[str]) -> None:
        s = self.settings
        try:
            candidates = EventRepository.suspicious_ips(s.window_seconds, s.min_alerts, s.max_priority)
        except Exception as e:
            logger.error("Không truy vấn được IP đáng ngờ: %s", e)
            return
        for ip, count in candidates:
            if ip in active or ip in self._pending_removal:
                continue
            if not self.policy.allows(ip):
                logger.info("Bỏ qua %s (%d cảnh báo): nằm trong allowlist hoặc không phải IPv4", ip, count)
                continue
            reason = f"{count} cảnh báo P{s.max_priority} trở lên trong {s.window_seconds}s"
            try:
                # Ghi CSDL trước: nếu thêm rule lỗi thì _reassert thử lại ở chu kỳ sau
                EventRepository.add_redirect(ip, s.ttl_seconds, alert_count=count, reason=reason)
            except Exception as e:
                logger.error("Không ghi được chuyển hướng %s vào CSDL: %s", ip, e)
                continue
            logger.warning("Chuyển hướng %s sang honeypot trong %ds (%s)", ip, s.ttl_seconds, reason)
            try:
                self.firewall.add(ip)
            except FirewallError as e:
                logger.error("Không thêm được rule cho %s, sẽ thử lại ở chu kỳ sau: %s", ip, e)

    def run(self) -> None:
        """Chạy tới khi `stop_event` được đặt, rồi dọn."""
        try:
            while not self.stop_event.is_set():
                self.run_once()
                self.stop_event.wait(self.settings.poll_interval)
        finally:
            self.stop()

    def stop(self) -> None:
        """Xoá mọi rule và đánh dấu các lượt đang hiệu lực là đã gỡ."""
        try:
            self.firewall.flush()
        except FirewallError as e:
            logger.error("Không xoá được rule khi dừng: %s", e)
        try:
            EventRepository.release_redirects()
        except Exception as e:
            logger.error("Không cập nhật CSDL khi dừng: %s", e)
        logger.info("Redirector đã dừng")
