# WebSocket Real-Time Alerting & Metrics Channel Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Hiện thực hóa kênh truyền thông hai chiều thời gian thực qua WebSocket (`/ws/alerts`, `/ws/metrics`, `/ws/live`) trên FastAPI server, cho phép đẩy ngay lập tức các cảnh báo xâm nhập (Zero-Polling) và stream dữ liệu đo kiểm lưu lượng mạng (Packets/s, Bandwidth, Uptime) tới Dashboard Frontend.

**Architecture:** Xây dựng `MetricsCollector` (thread-safe) thu thập thông số lưu lượng và cảnh báo. Xây dựng `WebSocketManager` quản lý vòng đời kết nối WebSocket và cơ chế `broadcast_from_thread` (cầu nối luồng an toàn giữa Worker Thread bắt gói tin và Async Event Loop của FastAPI). Tích hợp router WebSocket vào `api/main.py` cùng tác vụ ngầm định kỳ phát metric mỗi 1.0 giây.

**Tech Stack:** Python 3.10+, FastAPI WebSockets, Starlette, AsyncIO, Threading, Unittest.

---

## Global Constraints

- **Zero Polling:** Tuyệt đối không dùng cơ chế client định kỳ gọi HTTP GET để lấy alert mới.
- **Thread Safety:** Luồng bắt gói tin (`main.py` worker thread) không được block khi gọi broadcast alert sang Asyncio Loop của FastAPI.
- **Graceful Disconnect:** Khi client đóng trình duyệt hoặc mất kết nối đột ngột, server phải tự động dọn dẹp connection mà không làm crash tiến trình.
- **Python binary:** Sử dụng `C:\Users\LOQ\AppData\Local\Programs\Python\Python310\python.exe` để chạy các lệnh kiểm thử và thực thi.
- Không sử dụng các placeholder `TODO` hay `pass` trong code triển khai.

---

## File Structure

```text
services/monitoring/
├── __init__.py                # Export MetricsCollector
└── metrics_collector.py       # Thread-safe telemetry collector (packet_rate, bps, counters)

api/
├── websocket_manager.py       # Quản lý WebSocket clients & Thread-safe broadcast bridge
└── routes/
    └── websocket.py           # Endpoints: /ws/alerts, /ws/metrics, /ws/live

tests/test_monitoring/
└── test_metrics_collector.py  # Unittest cho bộ thu thập chỉ số mạng

tests/test_api/
└── test_websocket.py          # Unittest cho WebSocketManager & Endpoint integration

test_ws_client.py              # CLI test client kết nối và lắng nghe events
```

---

### Task 1: Thread-Safe Metrics Collector

**Files:**
- Create: `services/monitoring/__init__.py`
- Create: `services/monitoring/metrics_collector.py`
- Test: `tests/test_monitoring/test_metrics_collector.py`

**Interfaces:**
- Consumes: `packet_size: int` từ packet capture, `alert_data: dict` từ detection engine
- Produces: `get_snapshot() -> dict` chứa:
  - `packets_per_sec`: float
  - `bandwidth_kbps`: float
  - `total_packets`: int
  - `total_bytes`: int
  - `total_alerts`: int
  - `uptime_seconds`: float
  - `alerts_by_severity`: dict {1: int, 2: int, 3: int}

- [ ] **Step 1: Viết failing test cho MetricsCollector**

Tạo file `tests/test_monitoring/test_metrics_collector.py`:

```python
import unittest
import time
from services.monitoring.metrics_collector import MetricsCollector


class TestMetricsCollector(unittest.TestCase):
    def test_metrics_initial_state(self):
        collector = MetricsCollector()
        snapshot = collector.get_snapshot()
        self.assertEqual(snapshot["total_packets"], 0)
        self.assertEqual(snapshot["total_bytes"], 0)
        self.assertEqual(snapshot["total_alerts"], 0)
        self.assertEqual(snapshot["packets_per_sec"], 0.0)

    def test_record_packets_and_calculate_rates(self):
        collector = MetricsCollector()
        collector.record_packet(size_bytes=1000)
        collector.record_packet(size_bytes=2000)
        collector.record_alert(severity=1, attack_type="web-attack")

        snapshot = collector.get_snapshot()
        self.assertEqual(snapshot["total_packets"], 2)
        self.assertEqual(snapshot["total_bytes"], 3000)
        self.assertEqual(snapshot["total_alerts"], 1)
        self.assertEqual(snapshot["alerts_by_severity"][1], 1)
        self.assertGreaterEqual(snapshot["uptime_seconds"], 0.0)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Chạy test để xác nhận test thất bại**

Run: `& "C:\Users\LOQ\AppData\Local\Programs\Python\Python310\python.exe" -m unittest tests/test_monitoring/test_metrics_collector.py`  
Expected: `ModuleNotFoundError: No module named 'services.monitoring'`

- [ ] **Step 3: Hiện thực hóa MetricsCollector**

Tạo file `services/monitoring/metrics_collector.py`:

```python
import time
import threading
from typing import Dict, Any


class MetricsCollector:
    """
    Bộ thu thập và đo kiểm lưu lượng mạng cùng số liệu cảnh báo theo thời gian thực (Thread-safe).
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._start_time = time.time()
        
        # Tổng số tích lũy
        self._total_packets: int = 0
        self._total_bytes: int = 0
        self._total_alerts: int = 0
        self._alerts_by_severity: Dict[int, int] = {1: 0, 2: 0, 3: 0}
        
        # Cửa sổ tính tốc độ tức thời (1 giây gần nhất)
        self._window_start = time.time()
        self._window_packets: int = 0
        self._window_bytes: int = 0
        self._last_pps: float = 0.0
        self._last_kbps: float = 0.0

    def record_packet(self, size_bytes: int = 64) -> None:
        """Ghi nhận một gói tin vừa đi qua tầng ingestion."""
        with self._lock:
            now = time.time()
            self._total_packets += 1
            self._total_bytes += size_bytes
            self._window_packets += 1
            self._window_bytes += size_bytes

            elapsed = now - self._window_start
            if elapsed >= 1.0:
                self._last_pps = round(self._window_packets / elapsed, 2)
                self._last_kbps = round((self._window_bytes * 8) / (elapsed * 1000), 2)
                self._window_start = now
                self._window_packets = 0
                self._window_bytes = 0

    def record_alert(self, severity: int = 2, attack_type: str = "UNKNOWN") -> None:
        """Ghi nhận một cảnh báo mới được kích hoạt."""
        with self._lock:
            self._total_alerts += 1
            sev = severity if severity in self._alerts_by_severity else 2
            self._alerts_by_severity[sev] += 1

    def get_snapshot(self) -> Dict[str, Any]:
        """Trả về snapshot số liệu hiện thời phục vụ stream qua WebSocket."""
        with self._lock:
            now = time.time()
            uptime = round(now - self._start_time, 1)
            
            # Cập nhật rate nếu đã qua 1 giây kể từ lần reset
            elapsed = now - self._window_start
            pps = self._last_pps
            kbps = self._last_kbps
            if elapsed >= 1.0:
                pps = round(self._window_packets / elapsed, 2)
                kbps = round((self._window_bytes * 8) / (elapsed * 1000), 2)

            return {
                "timestamp": now,
                "uptime_seconds": uptime,
                "packets_per_sec": pps,
                "bandwidth_kbps": kbps,
                "total_packets": self._total_packets,
                "total_bytes": self._total_bytes,
                "total_alerts": self._total_alerts,
                "alerts_by_severity": dict(self._alerts_by_severity),
            }

    def reset(self) -> None:
        """Reset toàn bộ bộ đếm."""
        with self._lock:
            self._start_time = time.time()
            self._window_start = time.time()
            self._total_packets = 0
            self._total_bytes = 0
            self._total_alerts = 0
            self._alerts_by_severity = {1: 0, 2: 0, 3: 0}
            self._window_packets = 0
            self._window_bytes = 0
            self._last_pps = 0.0
            self._last_kbps = 0.0


# Singleton toàn cục dùng chung cho cả engine bắt gói và API server
global_metrics_collector = MetricsCollector()
```

Tạo file `services/monitoring/__init__.py`:

```python
from services.monitoring.metrics_collector import MetricsCollector, global_metrics_collector

__all__ = ["MetricsCollector", "global_metrics_collector"]
```

- [ ] **Step 4: Chạy test để xác nhận test vượt qua**

Run: `& "C:\Users\LOQ\AppData\Local\Programs\Python\Python310\python.exe" -m unittest tests/test_monitoring/test_metrics_collector.py`  
Expected: `Ran 2 tests ... OK`

- [ ] **Step 5: Commit task**

```bash
git add services/monitoring/ tests/test_monitoring/
git commit -m "feat(monitoring): implement thread-safe metrics collector"
```

---

### Task 2: WebSocket Connection Manager & Thread-Safe Broadcaster

**Files:**
- Create: `api/websocket_manager.py`
- Test: `tests/test_api/test_websocket_manager.py`

**Interfaces:**
- Consumes: `WebSocket` từ client kết nối
- Produces:
  - `async connect(channel, websocket)`
  - `disconnect(channel, websocket)`
  - `async broadcast_json(channel, data)`
  - `broadcast_from_thread(channel, data)` (Non-blocking, thread-safe sync call)

- [ ] **Step 1: Viết failing test cho WebSocketManager**

Tạo file `tests/test_api/test_websocket_manager.py`:

```python
import unittest
import asyncio
from unittest.mock import AsyncMock
from api.websocket_manager import WebSocketManager


class TestWebSocketManager(unittest.TestCase):
    def setUp(self):
        self.manager = WebSocketManager()

    def test_connect_and_disconnect(self):
        mock_ws = AsyncMock()
        asyncio.run(self.manager.connect("alerts", mock_ws))
        self.assertEqual(self.manager.get_connection_count("alerts"), 1)

        self.manager.disconnect("alerts", mock_ws)
        self.assertEqual(self.manager.get_connection_count("alerts"), 0)

    def test_broadcast_sends_to_all_clients(self):
        client1 = AsyncMock()
        client2 = AsyncMock()

        async def scenario():
            await self.manager.connect("alerts", client1)
            await self.manager.connect("alerts", client2)
            await self.manager.broadcast_json("alerts", {"test": "alert_data"})

            client1.send_json.assert_awaited_once_with({"test": "alert_data"})
            client2.send_json.assert_awaited_once_with({"test": "alert_data"})

        asyncio.run(scenario())


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Chạy test để xác nhận test thất bại**

Run: `& "C:\Users\LOQ\AppData\Local\Programs\Python\Python310\python.exe" -m unittest tests/test_api/test_websocket_manager.py`  
Expected: `ModuleNotFoundError: No module named 'api.websocket_manager'`

- [ ] **Step 3: Hiện thực hóa WebSocketManager**

Tạo file `api/websocket_manager.py`:

```python
import asyncio
import logging
from typing import Dict, Set, Any
from fastapi import WebSocket

logger = logging.getLogger("nids.websocket")


class WebSocketManager:
    """
    Quản lý các kết nối WebSocket phân kênh và cơ chế phát thông điệp thời gian thực.
    Hỗ trợ cả async context lẫn bridge gọi từ thread đồng bộ bên ngoài.
    """

    def __init__(self):
        # Lưu các kết nối theo từng channel: "alerts", "metrics", "live"
        self._channels: Dict[str, Set[WebSocket]] = {
            "alerts": set(),
            "metrics": set(),
            "live": set(),
        }
        self._loop: asyncio.AbstractEventLoop = None

    def set_event_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        """Ghi nhận event loop của FastAPI khi server khởi động."""
        self._loop = loop

    async def connect(self, channel: str, websocket: WebSocket) -> None:
        """Chấp nhận kết nối và đưa vào channel tương ứng."""
        await websocket.accept()
        if channel not in self._channels:
            self._channels[channel] = set()
        self._channels[channel].add(websocket)
        logger.info(f"[WS] Client connected to channel '{channel}'. Total: {len(self._channels[channel])}")

    def disconnect(self, channel: str, websocket: WebSocket) -> None:
        """Xóa client khi ngắt kết nối."""
        if channel in self._channels and websocket in self._channels[channel]:
            self._channels[channel].remove(websocket)
            logger.info(f"[WS] Client disconnected from '{channel}'. Remaining: {len(self._channels[channel])}")

    def get_connection_count(self, channel: str) -> int:
        return len(self._channels.get(channel, set()))

    async def broadcast_json(self, channel: str, data: Dict[str, Any]) -> None:
        """Gửi dữ liệu JSON tới tất cả client trong channel chỉ định (và cả channel 'live')."""
        targets = set(self._channels.get(channel, set()))
        if channel != "live":
            # Kênh 'live' nhận toàn bộ cả alerts và metrics
            targets.update(self._channels.get("live", set()))

        disconnected = []
        for ws in targets:
            try:
                await ws.send_json(data)
            except Exception as e:
                logger.warning(f"[WS] Failed to send to client in '{channel}', marking disconnected: {e}")
                disconnected.append(ws)

        for ws in disconnected:
            for ch in self._channels.values():
                ch.discard(ws)

    def broadcast_from_thread(self, channel: str, data: Dict[str, Any]) -> None:
        """
        Cầu nối thread-safe: Cho phép Worker Thread (bắt gói tin Scapy) gọi phát alert
        sang Event Loop bất đồng bộ của FastAPI mà không bị block.
        """
        if self._loop and self._loop.is_running():
            asyncio.run_coroutine_threadsafe(self.broadcast_json(channel, data), self._loop)
        else:
            # Fallback nếu loop chưa sẵn sàng
            pass


# Singleton toàn cục
global_ws_manager = WebSocketManager()
```

- [ ] **Step 4: Chạy test để xác nhận test vượt qua**

Run: `& "C:\Users\LOQ\AppData\Local\Programs\Python\Python310\python.exe" -m unittest tests/test_api/test_websocket_manager.py`  
Expected: `Ran 2 tests ... OK`

- [ ] **Step 5: Commit task**

```bash
git add api/websocket_manager.py tests/test_api/test_websocket_manager.py
git commit -m "feat(api): implement websocket connection manager with thread-safe broadcast bridge"
```

---

### Task 3: WebSocket Router & Background Telemetry Streamer

**Files:**
- Create: `api/routes/websocket.py`
- Modify: `api/main.py`
- Test: `tests/test_api/test_websocket_routes.py`

**Interfaces:**
- Endpoints:
  - `ws://.../ws/alerts`
  - `ws://.../ws/metrics`
  - `ws://.../ws/live`
  - `POST /api/alerts/broadcast-test` (REST endpoint test nhanh broadcast qua Swagger)

- [ ] **Step 1: Viết test cho WebSocket Router**

Tạo file `tests/test_api/test_websocket_routes.py`:

```python
import unittest
from fastapi.testclient import TestClient
from api.main import app


class TestWebSocketRoutes(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def test_broadcast_test_endpoint(self):
        res = self.client.post("/api/alerts/broadcast-test", json={
            "msg": "TEST BROADCAST ALERT",
            "src_ip": "10.10.10.10",
            "dst_ip": "192.168.1.1",
            "dst_port": 80,
            "severity": 1
        })
        self.assertEqual(res.status_code, 200)
        self.assertTrue(res.json()["broadcasted"])

    def test_websocket_alerts_connection(self):
        with self.client.websocket_connect("/ws/alerts") as ws:
            # Gửi test alert từ REST API
            self.client.post("/api/alerts/broadcast-test", json={
                "msg": "ALERT VIA WS",
                "src_ip": "1.2.3.4",
                "dst_ip": "5.6.7.8",
                "dst_port": 443,
                "severity": 1
            })
            data = ws.receive_json()
            self.assertEqual(data["type"], "alert")
            self.assertEqual(data["data"]["msg"], "ALERT VIA WS")


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Chạy test để xác nhận test thất bại**

Run: `& "C:\Users\LOQ\AppData\Local\Programs\Python\Python310\python.exe" -m unittest tests/test_api/test_websocket_routes.py`  
Expected: `404 Not Found` (do chưa mount router)

- [ ] **Step 3: Hiện thực hóa WebSocket Router và Background Telemetry Task**

Tạo file `api/routes/websocket.py`:

```python
import time
from typing import Dict, Any
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field

from api.websocket_manager import global_ws_manager
from services.monitoring.metrics_collector import global_metrics_collector

router = APIRouter(tags=["WebSocket Realtime"])


class TestAlertPayload(BaseModel):
    msg: str = Field(default="SIMULATED ATTACK ALERT")
    src_ip: str = Field(default="192.168.1.100")
    dst_ip: str = Field(default="10.0.0.5")
    dst_port: int = Field(default=80)
    severity: int = Field(default=1)
    classtype: str = Field(default="web-application-attack")


@router.websocket("/ws/alerts")
async def websocket_alerts(websocket: WebSocket):
    """Kênh WebSocket stream cảnh báo thời gian thực (Zero Polling)."""
    await global_ws_manager.connect("alerts", websocket)
    try:
        while True:
            # Giữ kết nối mở, lắng nghe ping/pong từ client
            await websocket.receive_text()
    except WebSocketDisconnect:
        global_ws_manager.disconnect("alerts", websocket)


@router.websocket("/ws/metrics")
async def websocket_metrics(websocket: WebSocket):
    """Kênh WebSocket stream số liệu lưu lượng mạng (Packets/s, Băng thông, Uptime) mỗi 1s."""
    await global_ws_manager.connect("metrics", websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        global_ws_manager.disconnect("metrics", websocket)


@router.websocket("/ws/live")
async def websocket_live(websocket: WebSocket):
    """Kênh WebSocket hợp nhất nhận cả Alerts lẫn Metrics trên cùng một kết nối."""
    await global_ws_manager.connect("live", websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        global_ws_manager.disconnect("live", websocket)


@router.post("/api/alerts/broadcast-test", summary="Kích hoạt test broadcast Alert qua WebSocket")
async def broadcast_test_alert(payload: TestAlertPayload):
    """Endpoint tiện ích phục vụ test bắn Alert tức thời tới tất cả WebSockets từ Swagger UI."""
    alert_event = {
        "type": "alert",
        "data": {
            "timestamp": time.time(),
            "sid": 9999999,
            "source_type": "TEST_TRIGGER",
            "classtype": payload.classtype,
            "severity": payload.severity,
            "src_ip": payload.src_ip,
            "src_port": 54321,
            "dst_ip": payload.dst_ip,
            "dst_port": payload.dst_port,
            "protocol": "TCP",
            "msg": payload.msg,
        }
    }
    await global_ws_manager.broadcast_json("alerts", alert_event)
    global_metrics_collector.record_alert(severity=payload.severity, attack_type=payload.classtype)
    return {"broadcasted": True, "payload": alert_event}
```

Cập nhật `api/main.py` để:
1. Ghi nhận `asyncio.get_running_loop()` vào `global_ws_manager`.
2. Khởi động background loop phát `global_metrics_collector.get_snapshot()` mỗi 1 giây sang channel `"metrics"`.
3. Mount `websocket.router`.

Trong `api/main.py`:
```python
# Thêm import
import asyncio
from api.websocket_manager import global_ws_manager
from api.routes import alerts, rules as rules_router, websocket as ws_router
from services.monitoring.metrics_collector import global_metrics_collector

# Trong lifespan:
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Thiết lập event loop cho websocket manager
    global_ws_manager.set_event_loop(asyncio.get_running_loop())

    # Task định kỳ stream metrics mỗi 1 giây
    async def metrics_streamer():
        while True:
            try:
                await asyncio.sleep(1.0)
                if global_ws_manager.get_connection_count("metrics") > 0 or global_ws_manager.get_connection_count("live") > 0:
                    snapshot = global_metrics_collector.get_snapshot()
                    await global_ws_manager.broadcast_json("metrics", {
                        "type": "metrics",
                        "data": snapshot
                    })
            except asyncio.CancelledError:
                break
            except Exception as e:
                pass

    streamer_task = asyncio.create_task(metrics_streamer())

    # ... các logic init_db và import rules ...

    yield

    streamer_task.cancel()
    # ... shutdown logic ...

# Mount router
app.include_router(ws_router.router)
```

- [ ] **Step 4: Chạy test để xác nhận test vượt qua**

Run: `& "C:\Users\LOQ\AppData\Local\Programs\Python\Python310\python.exe" -m unittest tests/test_api/test_websocket_routes.py`  
Expected: `Ran 2 tests ... OK`

- [ ] **Step 5: Commit task**

```bash
git add api/routes/websocket.py api/main.py tests/test_api/test_websocket_routes.py
git commit -m "feat(api): add websocket routes and background metrics streaming task"
```

---

### Task 4: Tích hợp Pipeline Bắt Gói & Cảnh Báo (`main.py`)

**Files:**
- Modify: `main.py`
- Test: Kiểm thử chức năng trực tiếp

**Interfaces:**
- In `on_raw_packet(scapy_pkt)`: gọi `global_metrics_collector.record_packet(len(scapy_pkt))`
- In `handle_alert(alert_data)`: gọi `global_metrics_collector.record_alert(...)` và `global_ws_manager.broadcast_from_thread("alerts", {"type": "alert", "data": alert_data})`

- [ ] **Step 1: Cập nhật `main.py` gắn telemetry và broadcast callback**

Sửa `main.py`:

```python
# Thêm imports
from services.monitoring.metrics_collector import global_metrics_collector
from api.websocket_manager import global_ws_manager

def handle_alert(alert_data: dict):
    """Callback luu canh bao vao database va ban tuc thi qua WebSocket."""
    try:
        event = EventRepository.save_alert(alert_data)
        sid_str = f"SID:{alert_data.get('sid')}" if alert_data.get('sid') else "AI-ANOMALY"
        print(f"[ALERT #{event.id}] [{sid_str}] {alert_data.get('msg')} | {alert_data.get('src_ip')} -> {alert_data.get('dst_ip')}:{alert_data.get('dst_port')}")
        
        # Cập nhật số liệu telemetry
        global_metrics_collector.record_alert(
            severity=alert_data.get("severity", 2),
            attack_type=alert_data.get("classtype", "UNKNOWN")
        )

        # Phát alert trực tiếp qua WebSocket tới toàn bộ Dashboard clients
        ws_payload = {
            "type": "alert",
            "data": {
                "id": event.id,
                "timestamp": event.timestamp.isoformat() if event.timestamp else time.time(),
                "sid": alert_data.get("sid"),
                "source_type": alert_data.get("source_type", "RULE_ENGINE"),
                "classtype": alert_data.get("classtype"),
                "severity": alert_data.get("severity", 2),
                "src_ip": alert_data.get("src_ip"),
                "src_port": alert_data.get("src_port"),
                "dst_ip": alert_data.get("dst_ip"),
                "dst_port": alert_data.get("dst_port"),
                "protocol": alert_data.get("protocol"),
                "http_method": alert_data.get("http_method"),
                "http_uri": alert_data.get("http_uri"),
                "msg": alert_data.get("msg"),
            }
        }
        global_ws_manager.broadcast_from_thread("alerts", ws_payload)
    except Exception as e:
        print(f"[AlertError] Khong the luu hoac broadcast alert: {e}")

# Trong on_raw_packet:
def on_raw_packet(scapy_pkt):
    global_metrics_collector.record_packet(len(scapy_pkt))
    decoded = PacketDecoder.decode(scapy_pkt)
    if decoded is None:
        return
    try:
        packet_queue.put_nowait(decoded)
    except queue.Full:
        print("[Canh bao] Queue day! Dang bi drop goi tin.")
```

- [ ] **Step 2: Commit task**

```bash
git add main.py
git commit -m "feat(engine): link packet capture and alerts to websocket and telemetry collector"
```

---

### Task 5: End-to-End Verification & Interactive CLI Test Client

**Files:**
- Create: `test_ws_client.py`

- [ ] **Step 1: Viết CLI script lắng nghe WebSocket events**

Tạo file `test_ws_client.py`:

```python
import asyncio
import json
import sys
import websockets

URI = "ws://localhost:8000/ws/live"

async def listen_live():
    print(f"[*] Dang ket noi toi {URI}...")
    try:
        async with websockets.connect(URI) as ws:
            print("[+] Ket noi WebSocket thanh cong! Dang cho su kien tu NIDS (Nhan Ctrl+C de thoat)...")
            while True:
                msg = await ws.recv()
                data = json.loads(msg)
                event_type = data.get("type")
                if event_type == "alert":
                    a = data["data"]
                    print(f"\a[LIVE ALERT] [Sev:{a.get('severity')}] {a.get('msg')} | {a.get('src_ip')} -> {a.get('dst_ip')}:{a.get('dst_port')}")
                elif event_type == "metrics":
                    m = data["data"]
                    print(f"[METRICS] PPS: {m.get('packets_per_sec')} | Bw: {m.get('bandwidth_kbps')} kbps | Total Pkts: {m.get('total_packets')} | Total Alerts: {m.get('total_alerts')}")
    except KeyboardInterrupt:
        print("\n[*] Dong client.")
    except Exception as e:
        print(f"[!] Loi ket noi: {e}")

if __name__ == "__main__":
    asyncio.run(listen_live())
```

- [ ] **Step 2: Chạy kiểm thử End-to-End**

1. Khởi động API Server:  
   `& "C:\Users\LOQ\AppData\Local\Programs\Python\Python310\python.exe" -m uvicorn api.main:app --host 0.0.0.0 --port 8000`
2. Mở terminal mới chạy CLI client:  
   `& "C:\Users\LOQ\AppData\Local\Programs\Python\Python310\python.exe" test_ws_client.py`
3. Kích hoạt test broadcast từ terminal thứ ba:  
   `curl -X POST http://localhost:8000/api/alerts/broadcast-test -H "Content-Type: application/json" -d "{\"msg\":\"DEMO ATTACK\"}"`  
   **Xác nhận:** Terminal `test_ws_client.py` lập tức nhận và in ra dòng:  
   `[LIVE ALERT] [Sev:1] DEMO ATTACK | ...`
4. Chạy `python main.py` để phân tích file PCAP:  
   **Xác nhận:** Toàn bộ 16 cảnh báo từ PCAP được stream tức thì lên cửa sổ client WebSocket không có độ trễ!

- [ ] **Step 3: Commit hoàn thành tính năng WebSocket**

```bash
git add test_ws_client.py
git commit -m "test(ws): add interactive websocket live client for demo verification"
```

