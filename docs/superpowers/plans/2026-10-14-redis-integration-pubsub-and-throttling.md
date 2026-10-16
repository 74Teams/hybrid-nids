# Redis Integration: Pub/Sub Decoupling, Alert Throttling & Telemetry Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Tích hợp Redis làm Message Broker và In-memory Cache cho Hybrid NIDS: Giải quyết bài toán giao tiếp liên tiến trình (IPC) giữa Core Engine (`main.py`) và API Server (`api/main.py`) qua Redis Pub/Sub, cơ chế chống bão cảnh báo (Alert Throttling/De-duplication) bảo vệ MySQL, và bảng xếp hạng Top Attackers qua Redis Sorted Sets.

**Architecture:** Xây dựng `RedisManager` tại `services/cache/redis_client.py` hỗ trợ cơ chế Plug-and-Play (tự động fallback về In-Memory RAM nếu Redis server không khả dụng). Khi Engine phát hiện vi phạm, `throttle_alert` kiểm tra key có TTL để chống spam DB, sau đó `publish` vào channel `nids:alerts`. Phía FastAPI, một async worker `redis_listener.py` lắng nghe kênh này và đẩy trực tiếp tới các client WebSocket.

**Tech Stack:** Python 3.10+, Redis (redis-py 5.0+), FastAPI, Asyncio, Unittest.

---

## Global Constraints

- **Graceful Fallback (Không phụ thuộc cứng):** Hệ thống phải chạy được 100% các tính năng hiện tại ngay cả khi máy tính chưa cài đặt hoặc tắt Redis service (tự fallback sang local RAM dictionary).
- **Zero Alert Storm:** Khi xảy ra tấn công SYN Flood hoặc Scan (hàng nghìn gói/giây), MySQL chỉ ghi nhận tối đa 1 alert trong mỗi cửa sổ thời gian (ví dụ: 3 giây) cho cùng 1 cặp `(src_ip, sid)`.
- **Python Binary:** Sử dụng `C:\Users\LOQ\AppData\Local\Programs\Python\Python310\python.exe` để cài đặt thư viện và chạy các script kiểm thử.
- Không sử dụng các placeholder `TODO` hay `pass` trong code triển khai.

---

## File Structure

```text
config/
└── settings.yaml              # Bổ sung cấu hình redis: host, port, db, throttle_window_sec

services/cache/
├── __init__.py                # Export RedisManager và global_redis_client
└── redis_client.py            # Client quản lý kết nối, Throttling và Pub/Sub (có Fallback)

api/
├── redis_listener.py          # Background async listener đọc Redis channel nids:alerts
└── routes/
    └── telemetry.py           # Endpoint: GET /api/telemetry/top-attackers

tests/test_cache/
└── test_redis_client.py       # Unittest kiểm thử Throttling và cơ chế Fallback In-memory
```

---

### Task 1: Cấu hình Redis & Cài đặt Thư viện

**Files:**
- Modify: `requirements.txt`
- Modify: `config/settings.yaml`
- Modify: `config/config.py`

- [ ] **Step 1: Cập nhật `requirements.txt` thêm thư viện `redis`**

Thêm `redis>=5.0.1` vào `requirements.txt`:

```text
# Redis Message Broker & In-Memory Cache
redis>=5.0.1
```

- [ ] **Step 2: Cài đặt thư viện `redis`**

Run: `& "C:\Users\LOQ\AppData\Local\Programs\Python\Python310\python.exe" -m pip install "redis>=5.0.1"`  
Expected: `Successfully installed redis...`

- [ ] **Step 3: Cập nhật `config/settings.yaml`**

Bổ sung block cấu hình `redis`:

```yaml
redis:
  enabled: true
  host: "localhost"
  port: 6379
  db: 0
  password: ""
  throttle_window_sec: 3
```

- [ ] **Step 4: Commit task**

```bash
git add requirements.txt config/settings.yaml
git commit -m "chore(config): add redis configuration and dependency"
```

---

### Task 2: Hiện thực hóa RedisManager với Fallback & Alert Throttling

**Files:**
- Create: `services/cache/__init__.py`
- Create: `services/cache/redis_client.py`
- Test: `tests/test_cache/test_redis_client.py`

**Interfaces:**
- Consumes: `settings.yaml`
- Produces: `RedisManager` với các phương thức:
  - `throttle_alert(src_ip: str, sid: Optional[int], window_sec: int = 3) -> bool`: Trả về `True` nếu được phép lưu/bắn alert; `False` nếu bị chặn do spam.
  - `publish(channel: str, message: dict) -> bool`
  - `record_top_attacker(src_ip: str) -> None`
  - `get_top_attackers(limit: int = 5) -> List[Dict[str, Any]]`

- [ ] **Step 1: Viết failing test cho `RedisManager`**

Tạo file `tests/test_cache/test_redis_client.py`:

```python
import unittest
import time
from services.cache.redis_client import RedisManager


class TestRedisManager(unittest.TestCase):
    def setUp(self):
        # Khởi tạo client ở chế độ In-memory Fallback (bằng cách truyền port không tồn tại hoặc enabled=False)
        self.manager = RedisManager(enabled=False)

    def test_alert_throttling_suppresses_rapid_duplicate_alerts(self):
        # Lần 1: Được phép emit
        allowed_1 = self.manager.throttle_alert("192.168.1.100", sid=1000001, window_sec=2)
        self.assertTrue(allowed_1)

        # Lần 2 (ngay lập tức): Bị chặn (suppressed)
        allowed_2 = self.manager.throttle_alert("192.168.1.100", sid=1000001, window_sec=2)
        self.assertFalse(allowed_2)

        # IP khác hoặc SID khác: Vẫn được phép emit
        allowed_other = self.manager.throttle_alert("192.168.1.100", sid=1000002, window_sec=2)
        self.assertTrue(allowed_other)

    def test_record_and_get_top_attackers(self):
        self.manager.record_top_attacker("192.168.1.50")
        self.manager.record_top_attacker("192.168.1.50")
        self.manager.record_top_attacker("10.0.0.99")

        top = self.manager.get_top_attackers(limit=2)
        self.assertGreaterEqual(len(top), 1)
        self.assertEqual(top[0]["ip"], "192.168.1.50")
        self.assertEqual(top[0]["count"], 2)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Chạy test để xác nhận test thất bại**

Run: `& "C:\Users\LOQ\AppData\Local\Programs\Python\Python310\python.exe" -m unittest tests/test_cache/test_redis_client.py`  
Expected: `ModuleNotFoundError: No module named 'services.cache'`

- [ ] **Step 3: Hiện thực hóa `RedisManager`**

Tạo file `services/cache/redis_client.py`:

```python
import json
import time
import logging
from typing import Optional, Dict, Any, List
from config.config import SETTINGS

logger = logging.getLogger("nids.redis")

try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False


class RedisManager:
    """
    Quản lý kết nối Redis, hỗ trợ Pub/Sub, Alert Throttling và Top Attackers.
    Tự động chuyển sang chế độ In-memory Fallback nếu không kết nối được Redis.
    """

    def __init__(
        self,
        enabled: Optional[bool] = None,
        host: Optional[str] = None,
        port: Optional[int] = None,
        db: int = 0,
        password: Optional[str] = None,
    ):
        cfg = SETTINGS.get("redis", {})
        self.enabled = cfg.get("enabled", True) if enabled is None else enabled
        self.host = host or cfg.get("host", "localhost")
        self.port = port or cfg.get("port", 6379)
        self.db = db or cfg.get("db", 0)
        self.password = password or cfg.get("password", "") or None

        self._client: Optional[Any] = None
        self.is_connected = False

        # Fallback local in-memory dictionaries
        self._local_throttle: Dict[str, float] = {}
        self._local_top_attackers: Dict[str, int] = {}

        if self.enabled and REDIS_AVAILABLE:
            self._try_connect()

    def _try_connect(self) -> None:
        try:
            r = redis.Redis(
                host=self.host,
                port=self.port,
                db=self.db,
                password=self.password,
                socket_connect_timeout=1.0,
                decode_responses=True,
            )
            r.ping()
            self._client = r
            self.is_connected = True
            logger.info(f"[Redis] Ket noi thanh cong toi {self.host}:{self.port}")
        except Exception as e:
            self.is_connected = False
            self._client = None
            logger.warning(f"[Redis] Khong the ket noi toi Redis ({e}). Chuyen sang che do In-memory Fallback.")

    def throttle_alert(self, src_ip: str, sid: Optional[int], window_sec: int = 3) -> bool:
        """
        Kiểm tra xem cảnh báo có được phép lưu/phát hay bị chặn do gửi quá nhanh.
        - Trả về True: Cho phép emit (lần đầu tiên trong window_sec).
        - Trả về False: Chặn (spam lặp lại).
        """
        key = f"throttle:{src_ip}:{sid or 'ai'}"
        
        # 1. Nếu có Redis
        if self.is_connected and self._client:
            try:
                # set nx=True, ex=window_sec: chỉ set nếu key chưa tồn tại
                acquired = self._client.set(key, "1", nx=True, ex=window_sec)
                return bool(acquired)
            except Exception:
                pass  # Fallback sang RAM nếu Redis gặp sự cố đột ngột

        # 2. In-memory Fallback
        now = time.time()
        last_time = self._local_throttle.get(key, 0.0)
        if now - last_time >= window_sec:
            self._local_throttle[key] = now
            return True
        return False

    def publish(self, channel: str, message: Dict[str, Any]) -> bool:
        """Phát message dạng JSON lên Redis channel."""
        payload_str = json.dumps(message)
        if self.is_connected and self._client:
            try:
                self._client.publish(channel, payload_str)
                return True
            except Exception as e:
                logger.warning(f"[Redis] Publish failed: {e}")
        return False

    def record_top_attacker(self, src_ip: str) -> None:
        """Tăng số lần tấn công của một IP nguồn."""
        if not src_ip:
            return
        if self.is_connected and self._client:
            try:
                self._client.zincrby("top_attackers", 1, src_ip)
                return
            except Exception:
                pass

        # Fallback RAM
        self._local_top_attackers[src_ip] = self._local_top_attackers.get(src_ip, 0) + 1

    def get_top_attackers(self, limit: int = 5) -> List[Dict[str, Any]]:
        """Lấy danh sách Top IP tấn công nhiều nhất."""
        if self.is_connected and self._client:
            try:
                raw = self._client.zrevrange("top_attackers", 0, limit - 1, withscores=True)
                return [{"ip": item[0], "count": int(item[1])} for item in raw]
            except Exception:
                pass

        # Fallback RAM
        sorted_items = sorted(self._local_top_attackers.items(), key=lambda x: x[1], reverse=True)[:limit]
        return [{"ip": k, "count": v} for k, v in sorted_items]


# Singleton toàn cục
global_redis_client = RedisManager()
```

Tạo file `services/cache/__init__.py`:

```python
from services.cache.redis_client import RedisManager, global_redis_client

__all__ = ["RedisManager", "global_redis_client"]
```

- [ ] **Step 4: Chạy test để xác nhận test vượt qua**

Run: `& "C:\Users\LOQ\AppData\Local\Programs\Python\Python310\python.exe" -m unittest tests/test_cache/test_redis_client.py`  
Expected: `Ran 2 tests ... OK`

- [ ] **Step 5: Commit task**

```bash
git add services/cache/ tests/test_cache/
git commit -m "feat(cache): implement redis manager with alert throttling and in-memory fallback"
```

---

### Task 3: Redis Pub/Sub Listener cho FastAPI WebSocket

**Files:**
- Create: `api/redis_listener.py`
- Modify: `api/main.py`

**Interfaces:**
- Consumes: Channel `nids:alerts` từ Redis
- Produces: Gọi `global_ws_manager.broadcast_json("alerts", alert_event)`

- [ ] **Step 1: Tạo `api/redis_listener.py`**

Tạo file `api/redis_listener.py`:

```python
import asyncio
import json
import logging
from config.config import SETTINGS
from api.websocket_manager import global_ws_manager

logger = logging.getLogger("nids.redis_listener")


async def start_redis_alert_listener():
    """
    Task bất đồng bộ: Lắng nghe kênh Redis 'nids:alerts' và phát lại vào WebSocket server.
    Giúp tiến trình main.py và api/main.py giao tiếp hoàn toàn không đồng bộ.
    """
    try:
        import redis.asyncio as aioredis
    except ImportError:
        logger.warning("[RedisListener] redis-py khong ho tro asyncio. Bo qua Redis listener.")
        return

    cfg = SETTINGS.get("redis", {})
    if not cfg.get("enabled", True):
        return

    host = cfg.get("host", "localhost")
    port = cfg.get("port", 6379)
    password = cfg.get("password", "") or None

    while True:
        try:
            r = aioredis.Redis(host=host, port=port, password=password, decode_responses=True)
            pubsub = r.pubsub()
            await pubsub.subscribe("nids:alerts")
            logger.info(f"[RedisListener] Da subscribe kenh 'nids:alerts' tai {host}:{port}")

            async for message in pubsub.listen():
                if message and message["type"] == "message":
                    try:
                        data = json.loads(message["data"])
                        await global_ws_manager.broadcast_json("alerts", data)
                    except Exception as parse_err:
                        logger.error(f"[RedisListener] Parse error: {parse_err}")
        except asyncio.CancelledError:
            break
        except Exception as conn_err:
            logger.warning(f"[RedisListener] Khong ket noi duoc Redis ({conn_err}). Thu lai sau 5 giay...")
            await asyncio.sleep(5.0)
```

- [ ] **Step 2: Đăng ký listener vào `lifespan` trong `api/main.py`**

Trong `api/main.py`:

```python
from api.redis_listener import start_redis_alert_listener

# Trong lifespan(app: FastAPI):
    # Khởi chạy background redis listener
    listener_task = asyncio.create_task(start_redis_alert_listener())

    yield

    listener_task.cancel()
```

- [ ] **Step 3: Commit task**

```bash
git add api/redis_listener.py api/main.py
git commit -m "feat(api): integrate redis pubsub listener with websocket broadcast"
```

---

### Task 4: Tích hợp Throttling & Pub/Sub vào Pipeline Bắt Gói (`main.py`)

**Files:**
- Modify: `main.py`

**Interfaces:**
- In `handle_alert(alert_data)`:
  1. Kiểm tra `global_redis_client.throttle_alert(src_ip, sid, window_sec=3)`.
  2. Nếu bị chặn $\rightarrow$ log cảnh báo throttled, bỏ qua ghi DB.
  3. Nếu được duyệt $\rightarrow$ lưu MySQL qua `EventRepository.save_alert(alert_data)`.
  4. Ghi nhận `global_redis_client.record_top_attacker(src_ip)`.
  5. `global_redis_client.publish("nids:alerts", ws_payload)`.

- [ ] **Step 1: Cập nhật hàm `handle_alert` trong `main.py`**

```python
from services.cache.redis_client import global_redis_client

def handle_alert(alert_data: dict):
    """Callback luu canh bao vao database voi co che chong bao alert bang Redis."""
    src_ip = alert_data.get("src_ip", "")
    sid = alert_data.get("sid")

    # 1. Kiem tra chong bao Alert (Rate Limit / Throttling)
    throttle_window = SETTINGS.get("redis", {}).get("throttle_window_sec", 3)
    if not global_redis_client.throttle_alert(src_ip, sid, window_sec=throttle_window):
        # Bị chặn do lặp lại quá nhanh trong vòng 3 giây
        return

    try:
        # 2. Luu vao MySQL Database
        event = EventRepository.save_alert(alert_data)
        sid_str = f"SID:{sid}" if sid else "AI-ANOMALY"
        print(f"[ALERT #{event.id}] [{sid_str}] {alert_data.get('msg')} | {src_ip} -> {alert_data.get('dst_ip')}:{alert_data.get('dst_port')}")

        # 3. Ghi nhan Top Attacker vao Redis Sorted Set
        global_redis_client.record_top_attacker(src_ip)

        # 4. Phat su kien len Redis Pub/Sub channel 'nids:alerts'
        ws_payload = {
            "type": "alert",
            "data": {
                "id": event.id,
                "timestamp": event.timestamp.isoformat() if event.timestamp else time.time(),
                "sid": sid,
                "source_type": alert_data.get("source_type", "RULE_ENGINE"),
                "classtype": alert_data.get("classtype"),
                "severity": alert_data.get("severity", 2),
                "src_ip": src_ip,
                "src_port": alert_data.get("src_port"),
                "dst_ip": alert_data.get("dst_ip"),
                "dst_port": alert_data.get("dst_port"),
                "protocol": alert_data.get("protocol"),
                "http_method": alert_data.get("http_method"),
                "http_uri": alert_data.get("http_uri"),
                "msg": alert_data.get("msg"),
            }
        }
        global_redis_client.publish("nids:alerts", ws_payload)
        
        # Dong thoi van goi broadcast local phong truong hop khong dung Redis
        global_ws_manager.broadcast_from_thread("alerts", ws_payload)

    except Exception as e:
        print(f"[AlertError] Khong the luu hoac publish alert: {e}")
```

- [ ] **Step 2: Commit task**

```bash
git add main.py
git commit -m "feat(engine): apply redis alert throttling and pubsub publishing"
```

---

### Task 5: API Đo lường Telemetry & Kiểm thử Tích hợp

**Files:**
- Create: `api/routes/telemetry.py`
- Modify: `api/main.py`
- Test: `tests/test_api/test_telemetry.py`

- [ ] **Step 1: Tạo route `api/routes/telemetry.py`**

```python
from fastapi import APIRouter
from services.cache.redis_client import global_redis_client

router = APIRouter(prefix="/api/telemetry", tags=["Telemetry & Analytics"])

@router.get("/top-attackers", summary="Lay danh sach Top IP tan cong nhieu nhat")
def get_top_attackers(limit: int = 5):
    """Truy xuất Top IP tấn công từ Redis Sorted Set (tốc độ cao trên RAM)."""
    return {
        "source": "redis" if global_redis_client.is_connected else "in_memory_fallback",
        "top_attackers": global_redis_client.get_top_attackers(limit=limit)
    }

@router.get("/status", summary="Kiem tra trang thai Redis va Throttling")
def get_telemetry_status():
    """Kiểm tra trạng thái kết nối tới Redis."""
    return {
        "redis_enabled": global_redis_client.enabled,
        "redis_connected": global_redis_client.is_connected,
        "host": global_redis_client.host,
        "port": global_redis_client.port
    }
```

- [ ] **Step 2: Mount `telemetry.router` trong `api/main.py`**

```python
from api.routes import telemetry as telemetry_router

app.include_router(telemetry_router.router)
```

- [ ] **Step 3: Viết test cho Telemetry Endpoint**

Tạo `tests/test_api/test_telemetry.py`:

```python
import unittest
from fastapi.testclient import TestClient
from api.main import app

class TestTelemetryAPI(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def test_get_top_attackers_endpoint(self):
        res = self.client.get("/api/telemetry/top-attackers")
        self.assertEqual(res.status_code, 200)
        self.assertIn("top_attackers", res.json())

    def test_get_telemetry_status_endpoint(self):
        res = self.client.get("/api/telemetry/status")
        self.assertEqual(res.status_code, 200)
        self.assertIn("redis_enabled", res.json())

if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 4: Chạy test để xác nhận test vượt qua**

Run: `& "C:\Users\LOQ\AppData\Local\Programs\Python\Python310\python.exe" -m unittest tests/test_api/test_telemetry.py`  
Expected: `Ran 2 tests ... OK`

- [ ] **Step 5: Commit hoàn thành tính năng Redis**

```bash
git add api/routes/telemetry.py api/main.py tests/test_api/test_telemetry.py
git commit -m "feat(api): add telemetry endpoints for redis top attackers and system status"
```

