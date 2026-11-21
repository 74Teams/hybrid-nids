"""
Đẩy tín hiệu "có cảnh báo mới" từ engine/honeypot sang process API qua Redis pub/sub.

Tin nhắn chỉ chứa id của cảnh báo; dữ liệu vẫn nằm trong CSDL và trình duyệt lấy qua REST. Redis chỉ là
phụ trợ: tắt (settings `redis.host` rỗng), chết hay thiếu thư viện đều không được làm chậm hay làm sập sensor,
nên publish chạy ở thread nền với hàng đợi có giới hạn và `publish_alert` không bao giờ ném lỗi.
"""
import logging
import queue
import threading
import time
from typing import Any, Dict, Optional

from nids.config import get_redis_settings

logger = logging.getLogger("nids.realtime")

CHANNEL = "nids:alerts"
QUEUE_SIZE = 1000
RETRY_SECONDS = 5

_queue: "queue.Queue[int]" = queue.Queue(maxsize=QUEUE_SIZE)
_lock = threading.Lock()
_thread: Optional[threading.Thread] = None


def _sync_client(cfg: Dict[str, Any]):
    """Client đồng bộ cho thread publish; timeout ngắn và không retry (retry mặc định có thể chờ hơn 13 giây)."""
    import redis
    from redis.backoff import NoBackoff
    from redis.retry import Retry
    return redis.Redis(host=cfg["host"], port=cfg["port"], password=cfg["password"],
                       socket_connect_timeout=1, socket_timeout=1, retry=Retry(NoBackoff(), 0))


def async_client(cfg: Dict[str, Any]):
    """Client async cho API. Không đặt socket_timeout vì `listen()` phải chờ được lâu khi không có cảnh báo."""
    import redis.asyncio as aioredis
    from redis.asyncio.retry import Retry
    from redis.backoff import NoBackoff
    return aioredis.Redis(host=cfg["host"], port=cfg["port"], password=cfg["password"], decode_responses=True,
                          socket_connect_timeout=1, retry=Retry(NoBackoff(), 0))


def _run(events: "queue.Queue[int]", cfg: Dict[str, Any]) -> None:
    client = None
    while True:
        event_id = events.get()
        try:
            if client is None:
                client = _sync_client(cfg)
            client.publish(CHANNEL, event_id)
        except Exception as e:
            logger.warning("Không đẩy được tín hiệu cảnh báo qua Redis: %s", e)
            client = None
            # Tin chỉ là gợi ý "có thay đổi": bỏ backlog cũ thay vì thử lại từng tin (mỗi tin lỗi tốn thêm RETRY_SECONDS)
            while not events.empty():
                try:
                    events.get_nowait()
                except queue.Empty:
                    break
            time.sleep(RETRY_SECONDS)


def publish_alert(event_id: int) -> None:
    """Báo "có cảnh báo mới" cho API. Không chặn và không bao giờ ném lỗi (gọi sau khi đã commit CSDL)."""
    global _thread
    try:
        cfg = get_redis_settings()
        if cfg is None:
            return
        with _lock:
            if _thread is None:
                _thread = threading.Thread(target=_run, args=(_queue, cfg), name="redis-publish", daemon=True)
                _thread.start()
        _queue.put_nowait(event_id)
    except queue.Full:
        logger.debug("Hàng đợi tín hiệu cảnh báo đầy, bỏ qua tin %s", event_id)
    except Exception as e:
        logger.warning("Không đưa được tín hiệu cảnh báo vào hàng đợi: %s", e)
