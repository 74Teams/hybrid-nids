import time
from typing import Dict, Tuple, Optional, Any

class ThresholdManager:
    """
    Quản lý trạng thái và kiểm soát tần suất cảnh báo (Rate Limiting & Deduplication).
    Ngăn chặn bão cảnh báo (Alert Storm) khi xảy ra tấn công lặp lại tần suất cao (DoS, Scan, Brute Force).
    """

    def __init__(self, default_window_seconds: float = 10.0):
        self.default_window_seconds = default_window_seconds
        # key: (sid, src_ip, dst_ip, dst_port) -> (last_alert_timestamp, suppressed_count)
        self._cache: Dict[Tuple[int, str, str, Optional[int]], Tuple[float, int]] = {}
        self._last_cleanup = time.time()

    def should_alert(
        self,
        sid: int,
        src_ip: str,
        dst_ip: str,
        dst_port: Optional[int],
        window_seconds: Optional[float] = None,
    ) -> Tuple[bool, int]:
        """
        Kiểm tra xem cảnh báo có được phép phát ra hay bị dồn (suppressed).
        
        Returns:
            (allow_alert: bool, previous_suppressed_count: int)
        """
        now = time.time()
        self._periodic_cleanup(now)

        window = window_seconds if window_seconds is not None else self.default_window_seconds
        key = (sid, src_ip, dst_ip, dst_port)

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
        """Dọn dẹp các mục đã quá hạn để giải phóng bộ nhớ RAM."""
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

