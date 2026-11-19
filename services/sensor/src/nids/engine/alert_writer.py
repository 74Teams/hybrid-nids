"""
Ghi cảnh báo vào CSDL theo lô ở một thread riêng (PLAN-009 mục 6.5).

Trước đây worker thread gọi `EventRepository.save_alert` cho từng cảnh báo: mỗi cảnh báo một session, một
`commit`, khoảng 11 ms với SQLite. Khi tấn công dồn dập, worker mải ghi CSDL nên hàng đợi gói tràn.
Giờ worker chỉ đưa cảnh báo vào hàng đợi của `AlertWriter`; thread `alert-writer` gom tối đa `batch_size`
cảnh báo (hoặc chờ tối đa `flush_interval` giây) rồi ghi một lần.

- Live (`block=False`): hàng đợi cảnh báo đầy thì bỏ cảnh báo và đếm, worker không bao giờ phải chờ.
- Offline (`block=True`): chờ chỗ trống (có timeout), không bỏ cảnh báo; thread ghi đã chết thì bỏ và báo lỗi.
- Lỗi CSDL chỉ được log, lô đó bị bỏ, thread vẫn chạy (quy tắc "lỗi CSDL không làm sập sensor").
"""
import logging
import queue
import threading
import time
from typing import Callable, Dict, List, Optional

logger = logging.getLogger("nids.engine")

_STOP = object()


class _Counter:
    """Gộp các lần bỏ cảnh báo để chỉ báo tối đa một lần mỗi `interval` giây (giống DropCounter của main)."""

    def __init__(self, interval: float = 5.0):
        self.interval = interval
        self.total = 0
        self._pending = 0
        self._last: Optional[float] = None

    def record(self) -> Optional[int]:
        self.total += 1
        self._pending += 1
        now = time.monotonic()
        if self._last is None or now - self._last >= self.interval:
            count, self._pending, self._last = self._pending, 0, now
            return count
        return None


class AlertWriter:
    """Gom cảnh báo và ghi CSDL theo lô ở thread `alert-writer`."""

    def __init__(self, save_batch: Callable[[List[Dict]], object], batch_size: int = 200,
                 flush_interval: float = 1.0, max_queue: int = 50000, block: bool = False,
                 put_timeout: float = 0.5):
        self.save_batch = save_batch
        self.batch_size = max(1, batch_size)
        self.flush_interval = flush_interval
        self.block = block
        self.put_timeout = put_timeout
        self.dropped = _Counter()
        self.written = 0
        self.failed_batches = 0
        self._queue: "queue.Queue" = queue.Queue(maxsize=max_queue)
        self._thread: Optional[threading.Thread] = None
        self._closed = False

    def start(self) -> "AlertWriter":
        self._thread = threading.Thread(target=self._run, name="alert-writer", daemon=True)
        self._thread.start()
        return self

    def alive(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def submit(self, alert_data: Dict) -> bool:
        """Đưa một cảnh báo vào hàng đợi ghi; trả về False nếu cảnh báo bị bỏ."""
        if self._closed:
            return self._drop("bộ ghi cảnh báo đã đóng")
        if not self.block:
            try:
                self._queue.put_nowait(alert_data)
                return True
            except queue.Full:
                return self._drop("hàng đợi cảnh báo đầy")
        while True:
            if not self.alive():
                return self._drop("thread ghi cảnh báo đã dừng", level=logging.ERROR)
            try:
                self._queue.put(alert_data, timeout=self.put_timeout)
                return True
            except queue.Full:
                continue

    def close(self, timeout: float = 10.0) -> None:
        """Ghi nốt cảnh báo còn trong hàng đợi rồi dừng thread. Gọi nhiều lần vẫn an toàn."""
        if self._closed:
            return
        self._closed = True
        if self.alive():
            while True:
                try:
                    self._queue.put(_STOP, timeout=self.put_timeout)
                    break
                except queue.Full:
                    if not self.alive():
                        break
            self._thread.join(timeout)
            if self._thread.is_alive():
                logger.error("Bộ ghi cảnh báo chưa ghi xong sau %.0f giây, còn %d cảnh báo trong hàng đợi",
                             timeout, self._queue.qsize())
        if self.dropped.total:
            logger.warning("Tổng cộng %d cảnh báo không được ghi vào CSDL (hàng đợi đầy hoặc bộ ghi đã dừng)",
                           self.dropped.total)

    def _drop(self, reason: str, level: int = logging.WARNING) -> bool:
        count = self.dropped.record()
        if count:
            logger.log(level, "Bỏ %d cảnh báo không ghi vào CSDL: %s", count, reason)
        return False

    def _run(self) -> None:
        batch: List[Dict] = []
        deadline: Optional[float] = None
        while True:
            timeout = None if deadline is None else max(0.0, deadline - time.monotonic())
            try:
                item = self._queue.get(timeout=timeout)
            except queue.Empty:
                item = None
            if item is _STOP:
                self._write(batch)
                return
            if item is not None:
                batch.append(item)
                if deadline is None:
                    deadline = time.monotonic() + self.flush_interval
            if batch and (len(batch) >= self.batch_size or time.monotonic() >= deadline):
                self._write(batch)
                batch = []
                deadline = None

    def _write(self, batch: List[Dict]) -> None:
        if not batch:
            return
        try:
            self.save_batch(batch)
            self.written += len(batch)
        except Exception as e:
            self.failed_batches += 1
            logger.error("Không thể lưu %d cảnh báo vào CSDL: %s", len(batch), e)
