import time
from typing import Dict, Tuple, Optional, Any

class ThresholdManager:
    """
    Quản lý trạng thái và kiểm soát tần suất cảnh báo (Rate Limiting & Deduplication).
    Ngăn chặn bão cảnh báo (Alert Storm) khi xảy ra tấn công lặp lại tần suất cao (DoS, Scan, Brute Force).

    Giờ dùng để tính cửa sổ chặn là giờ của gói (`now` truyền vào), không phải giờ máy: replay một pcap bao nhiêu
    lần, nhanh hay chậm, cũng ra cùng số cảnh báo. Không truyền `now` thì dùng giờ máy như trước.
    """

    def __init__(self, default_window_seconds: float = 10.0):
        self.default_window_seconds = default_window_seconds
        # key: xem _key() -> (last_alert_timestamp, suppressed_count)
        self._cache: Dict[Tuple[Any, Optional[str], Optional[str], Optional[int]], Tuple[float, int]] = {}
        # Đặt theo lần gọi đầu tiên: giờ của gói (năm 2017 khi replay CIC) có thể nhỏ hơn giờ máy rất nhiều
        self._last_cleanup: Optional[float] = None

    @staticmethod
    def _key(sid, src_ip: str, dst_ip: str, dst_port: Optional[int], track: Optional[str]):
        """Khoá chặn theo kiểu đếm của rule.

        Rule có `detection_filter: track by_dst` (flood) chặn theo đích, `by_src` (scan, brute force) theo nguồn.
        Nếu vẫn gộp cả cổng đích như rule thường, gói trả lời DNS có cổng ngẫu nhiên sẽ thành khoá mới mỗi gói
        và không bị chặn (rule 1000205 từng bắn 2.145 lần trong 10 phút vì vậy).
        """
        if track == "by_dst":
            return (sid, None, dst_ip, None)
        if track == "by_src":
            return (sid, src_ip, None, None)
        return (sid, src_ip, dst_ip, dst_port)

    def should_alert(
        self,
        sid: int,
        src_ip: str,
        dst_ip: str,
        dst_port: Optional[int],
        window_seconds: Optional[float] = None,
        now: Optional[float] = None,
        track: Optional[str] = None,
    ) -> Tuple[bool, int]:
        """
        Kiểm tra xem cảnh báo có được phép phát ra hay bị dồn (suppressed).

        Args:
            now:   giờ của gói (epoch giây); None thì dùng giờ máy.
            track: "by_src" / "by_dst" theo `detection_filter` của rule; None với rule thường.

        Returns:
            (allow_alert: bool, previous_suppressed_count: int)
        """
        now = time.time() if now is None else now
        self._periodic_cleanup(now)

        window = window_seconds if window_seconds is not None else self.default_window_seconds
        key = self._key(sid, src_ip, dst_ip, dst_port, track)

        if key in self._cache:
            last_time, count = self._cache[key]
            if now - last_time < window:
                # Vẫn trong cửa sổ giới hạn -> Tăng biến đếm và chặn phát cảnh báo
                self._cache[key] = (last_time, count + 1)
                return False, count + 1
            else:
                # Đã hết cửa sổ giới hạn -> Cho phép phát cảnh báo mới và trả về số lượng đã dồn
                self._cache[key] = (now, 0)
                return True, count
        else:
            # Chưa từng xuất hiện -> Cho phép phát cảnh báo lần đầu
            self._cache[key] = (now, 0)
            return True, 0

    def _periodic_cleanup(self, now: float) -> None:
        """Dọn dẹp các mục đã quá hạn để giải phóng bộ nhớ RAM (mỗi 60 giây theo giờ đang dùng)."""
        if self._last_cleanup is None or now < self._last_cleanup:
            # lần đầu, hoặc giờ lùi lại (chuyển sang pcap khác): chỉ đặt lại mốc
            self._last_cleanup = now
            return
        if now - self._last_cleanup < 60.0:
            return
        self._last_cleanup = now
        expired_keys = [
            k for k, (last_time, _) in self._cache.items()
            if now - last_time > (self.default_window_seconds * 3)
        ]
        for k in expired_keys:
            del self._cache[k]

    def clear(self) -> None:
        """Xóa toàn bộ bộ đệm trạng thái."""
        self._cache.clear()
