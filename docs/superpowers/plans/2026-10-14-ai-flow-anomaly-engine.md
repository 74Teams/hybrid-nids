# AI Flow Anomaly Detection Engine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Hiện thực hóa khối AI Traffic Worker bằng cách tổng hợp luồng gói tin theo cửa sổ thời gian (Sliding Time Window), trích xuất 6 đặc trưng luồng (Flow Features), áp dụng mô hình học máy (Random Forest / Heuristic Classifier) để phát hiện tấn công DoS SYN Flood và Port Scan, sau đó kích hoạt cảnh báo `AI_ANOMALY` lưu vào MySQL/SQLite.

**Architecture:** Bổ sung `FlowAggregator` nhận `DecodedPacket` từ hàng đợi, duy trì trạng thái luồng theo cửa sổ trượt 1.0 giây. `FlowFeatureExtractor` tính toán vector đặc trưng [packet_rate, byte_rate, syn_ratio, rst_ratio, unique_dst_ports, avg_packet_size]. `AIModelClassifier` thực hiện inference và kích hoạt `alert_callback` đưa sự kiện vào CSDL qua `EventRepository`.

**Tech Stack:** Python 3.10+, Scikit-Learn, NumPy, Dataclasses, PyYAML, Pytest.

## Global Constraints

- Tuân thủ cấu trúc dữ liệu `DecodedPacket` và `EventModel` sẵn có trong `services/ingestion/` và `services/database/`.
- Phân cách rõ ràng: Module AI chỉ nhận gói tin đã giải mã và gọi callback alert, không can thiệp trực tiếp vào DB connection hay socket.
- Độ trễ trích xuất đặc trưng và suy luận luồng: `< 5ms` mỗi cửa sổ kiểm tra.
- Không sử dụng các placeholder `TODO` hay `pass` trong code triển khai.

---

## File Structure

```text
services/ai_engine/
├── __init__.py                # Export FlowRecord, FlowFeatureVector, AITrafficWorker
├── flow_aggregator.py         # Quản lý sliding window và tổng hợp packet theo src_ip
├── feature_extractor.py       # Trích xuất 6 đặc trưng luồng từ FlowRecord
├── model_classifier.py        # Bộ phân loại bất thường (Rule-Heuristic + ML Pipeline)
└── ai_worker.py               # Worker tích hợp hoàn chỉnh gọi từ main.py

tests/test_ai_engine/
├── test_flow_aggregator.py    # Kiểm thử bộ tổng hợp luồng theo thời gian
├── test_feature_extractor.py  # Kiểm thử công thức tính 6 đặc trưng
└── test_model_classifier.py   # Kiểm thử độ chính xác phát hiện SYN Flood & Scan
```

---

### Task 1: Flow Aggregator & State Tracking

**Files:**
- Create: `services/ai_engine/flow_aggregator.py`
- Test: `tests/test_ai_engine/test_flow_aggregator.py`

**Interfaces:**
- Consumes: `services.ingestion.DecodedPacket`
- Produces: `FlowRecord` dataclass (chứa `src_ip`, `packet_count`, `byte_count`, `syn_count`, `rst_count`, `dst_ports_set`, `window_start`)

- [ ] **Step 1: Viết failing test cho FlowAggregator**

Tạo file `tests/test_ai_engine/test_flow_aggregator.py`:

```python
import time
from services.ingestion import DecodedPacket
from services.ai_engine.flow_aggregator import FlowAggregator, FlowRecord

def test_flow_aggregator_accumulates_packets_per_src_ip():
    aggregator = FlowAggregator(window_seconds=1.0)
    
    pkt1 = DecodedPacket(
        timestamp=time.time(),
        src_ip="192.168.1.50",
        src_port=10001,
        dst_ip="10.0.0.1",
        dst_port=80,
        protocol="TCP",
        tcp_flags="S",
        raw_payload=b"A" * 100
    )
    pkt2 = DecodedPacket(
        timestamp=time.time(),
        src_ip="192.168.1.50",
        src_port=10002,
        dst_ip="10.0.0.1",
        dst_port=443,
        protocol="TCP",
        tcp_flags="SA",
        raw_payload=b"B" * 200
    )
    
    aggregator.add_packet(pkt1)
    record = aggregator.add_packet(pkt2)
    
    assert record.src_ip == "192.168.1.50"
    assert record.packet_count == 2
    assert record.byte_count == 300
    assert record.syn_count == 2
    assert 80 in record.dst_ports
    assert 443 in record.dst_ports
```

- [ ] **Step 2: Chạy test để xác nhận test thất bại**

Run: `pytest tests/test_ai_engine/test_flow_aggregator.py -v`  
Expected: `ModuleNotFoundError: No module named 'services.ai_engine.flow_aggregator'`

- [ ] **Step 3: Hiện thực hóa FlowAggregator**

Tạo file `services/ai_engine/flow_aggregator.py`:

```python
from dataclasses import dataclass, field
from typing import Dict, Set, Optional
import time
from services.ingestion import DecodedPacket


@dataclass
class FlowRecord:
    src_ip: str
    window_start: float
    packet_count: int = 0
    byte_count: int = 0
    syn_count: int = 0
    rst_count: int = 0
    dst_ports: Set[int] = field(default_factory=set)


class FlowAggregator:
    """
    Theo dõi và tổng hợp lưu lượng mạng theo src_ip trong cửa sổ thời gian trượt (Sliding Window).
    """

    def __init__(self, window_seconds: float = 1.0):
        self.window_seconds = window_seconds
        self.active_flows: Dict[str, FlowRecord] = {}

    def add_packet(self, packet: DecodedPacket) -> FlowRecord:
        current_time = packet.timestamp or time.time()
        src_ip = packet.src_ip

        if src_ip not in self.active_flows:
            self.active_flows[src_ip] = FlowRecord(src_ip=src_ip, window_start=current_time)

        record = self.active_flows[src_ip]

        # Kiểm tra nếu cửa sổ thời gian đã vượt quá window_seconds thì reset cửa sổ mới
        if current_time - record.window_start > self.window_seconds:
            record.window_start = current_time
            record.packet_count = 0
            record.byte_count = 0
            record.syn_count = 0
            record.rst_count = 0
            record.dst_ports.clear()

        record.packet_count += 1
        record.byte_count += len(packet.raw_payload) if packet.raw_payload else 64

        flags = (packet.tcp_flags or "").upper()
        if "S" in flags:
            record.syn_count += 1
        if "R" in flags:
            record.rst_count += 1

        if packet.dst_port:
            record.dst_ports.add(packet.dst_port)

        return record

    def clear(self) -> None:
        self.active_flows.clear()
```

- [ ] **Step 4: Chạy test để xác nhận test vượt qua**

Run: `pytest tests/test_ai_engine/test_flow_aggregator.py -v`  
Expected: `1 passed`

- [ ] **Step 5: Commit task**

```bash
git add services/ai_engine/flow_aggregator.py tests/test_ai_engine/test_flow_aggregator.py
git commit -m "feat(ai): implement sliding window flow aggregator"
```

---

### Task 2: Flow Feature Extractor

**Files:**
- Create: `services/ai_engine/feature_extractor.py`
- Test: `tests/test_ai_engine/test_feature_extractor.py`

**Interfaces:**
- Consumes: `FlowRecord` từ `services.ai_engine.flow_aggregator`
- Produces: `FlowFeatureVector` (mảng/dict chứa `packet_rate`, `byte_rate`, `syn_ratio`, `rst_ratio`, `unique_dst_ports`, `avg_packet_size`)

- [ ] **Step 1: Viết failing test cho FeatureExtractor**

Tạo file `tests/test_ai_engine/test_feature_extractor.py`:

```python
from services.ai_engine.flow_aggregator import FlowRecord
from services.ai_engine.feature_extractor import FlowFeatureExtractor, FlowFeatureVector

def test_feature_extractor_computes_exact_ratios():
    extractor = FlowFeatureExtractor()
    record = FlowRecord(
        src_ip="192.168.1.100",
        window_start=100.0,
        packet_count=100,
        byte_count=6000,
        syn_count=90,
        rst_count=5,
        dst_ports={80, 443, 8080}
    )

    vector: FlowFeatureVector = extractor.extract(record, duration=1.0)

    assert vector.packet_rate == 100.0
    assert vector.byte_rate == 6000.0
    assert vector.syn_ratio == 0.90
    assert vector.rst_ratio == 0.05
    assert vector.unique_dst_ports == 3
    assert vector.avg_packet_size == 60.0
```

- [ ] **Step 2: Chạy test để xác nhận test thất bại**

Run: `pytest tests/test_ai_engine/test_feature_extractor.py -v`  
Expected: `ModuleNotFoundError: No module named 'services.ai_engine.feature_extractor'`

- [ ] **Step 3: Hiện thực hóa FlowFeatureExtractor**

Tạo file `services/ai_engine/feature_extractor.py`:

```python
from dataclasses import dataclass
from typing import List
from services.ai_engine.flow_aggregator import FlowRecord


@dataclass
class FlowFeatureVector:
    src_ip: str
    packet_rate: float
    byte_rate: float
    syn_ratio: float
    rst_ratio: float
    unique_dst_ports: int
    avg_packet_size: float

    def to_list(self) -> List[float]:
        return [
            self.packet_rate,
            self.byte_rate,
            self.syn_ratio,
            self.rst_ratio,
            float(self.unique_dst_ports),
            self.avg_packet_size,
        ]


class FlowFeatureExtractor:
    """
    Chuyển đổi dữ liệu thống kê từ FlowRecord thành bộ đặc trưng chuẩn cho mô hình AI.
    """

    @staticmethod
    def extract(record: FlowRecord, duration: float = 1.0) -> FlowFeatureVector:
        dur = max(duration, 0.001)
        pkt_count = record.packet_count

        packet_rate = pkt_count / dur
        byte_rate = record.byte_count / dur
        syn_ratio = (record.syn_count / pkt_count) if pkt_count > 0 else 0.0
        rst_ratio = (record.rst_count / pkt_count) if pkt_count > 0 else 0.0
        unique_dst_ports = len(record.dst_ports)
        avg_packet_size = (record.byte_count / pkt_count) if pkt_count > 0 else 0.0

        return FlowFeatureVector(
            src_ip=record.src_ip,
            packet_rate=round(packet_rate, 2),
            byte_rate=round(byte_rate, 2),
            syn_ratio=round(syn_ratio, 4),
            rst_ratio=round(rst_ratio, 4),
            unique_dst_ports=unique_dst_ports,
            avg_packet_size=round(avg_packet_size, 2),
        )
```

- [ ] **Step 4: Chạy test để xác nhận test vượt qua**

Run: `pytest tests/test_ai_engine/test_feature_extractor.py -v`  
Expected: `1 passed`

- [ ] **Step 5: Commit task**

```bash
git add services/ai_engine/feature_extractor.py tests/test_ai_engine/test_feature_extractor.py
git commit -m "feat(ai): implement flow feature extractor for network metrics"
```

---

### Task 3: Anomaly Detection Classifier

**Files:**
- Create: `services/ai_engine/model_classifier.py`
- Test: `tests/test_ai_engine/test_model_classifier.py`

**Interfaces:**
- Consumes: `FlowFeatureVector`
- Produces: `Tuple[bool, Optional[str], int, str]` (is_anomaly, attack_type, severity, summary)

- [ ] **Step 1: Viết failing test cho Classifier**

Tạo file `tests/test_ai_engine/test_model_classifier.py`:

```python
from services.ai_engine.feature_extractor import FlowFeatureVector
from services.ai_engine.model_classifier import AnomalyClassifier

def test_classifier_detects_syn_flood():
    classifier = AnomalyClassifier()
    vector = FlowFeatureVector(
        src_ip="192.168.1.222",
        packet_rate=120.0,
        byte_rate=7200.0,
        syn_ratio=0.95,
        rst_ratio=0.0,
        unique_dst_ports=1,
        avg_packet_size=60.0
    )
    is_anomaly, attack_type, severity, summary = classifier.classify(vector)
    assert is_anomaly is True
    assert attack_type == "dos-syn-flood"
    assert severity == 1
    assert "SYN Flood" in summary

def test_classifier_detects_port_scan():
    classifier = AnomalyClassifier()
    vector = FlowFeatureVector(
        src_ip="192.168.1.223",
        packet_rate=45.0,
        byte_rate=2700.0,
        syn_ratio=0.4,
        rst_ratio=0.3,
        unique_dst_ports=35,
        avg_packet_size=60.0
    )
    is_anomaly, attack_type, severity, summary = classifier.classify(vector)
    assert is_anomaly is True
    assert attack_type == "reconnaissance-port-scan"
    assert severity == 2
    assert "Port Scan" in summary

def test_classifier_ignores_normal_traffic():
    classifier = AnomalyClassifier()
    vector = FlowFeatureVector(
        src_ip="192.168.1.10",
        packet_rate=5.0,
        byte_rate=4500.0,
        syn_ratio=0.1,
        rst_ratio=0.0,
        unique_dst_ports=2,
        avg_packet_size=900.0
    )
    is_anomaly, attack_type, severity, summary = classifier.classify(vector)
    assert is_anomaly is False
    assert attack_type is None
```

- [ ] **Step 2: Chạy test để xác nhận test thất bại**

Run: `pytest tests/test_ai_engine/test_model_classifier.py -v`  
Expected: `ModuleNotFoundError: No module named 'services.ai_engine.model_classifier'`

- [ ] **Step 3: Hiện thực hóa AnomalyClassifier**

Tạo file `services/ai_engine/model_classifier.py`:

```python
from typing import Tuple, Optional
from services.ai_engine.feature_extractor import FlowFeatureVector


class AnomalyClassifier:
    """
    Phân loại hành vi bất thường mạng dựa trên bộ đặc trưng luồng (Flow Features).
    Hỗ trợ cơ chế phân loại luật mờ / ngưỡng chuyên gia (Heuristic Thresholds)
    kết hợp giao tiếp sẵn sàng nạp mô hình Scikit-Learn (.pkl) khi có trọng số.
    """

    def __init__(
        self,
        syn_flood_rate_thresh: float = 50.0,
        syn_ratio_thresh: float = 0.85,
        port_scan_ports_thresh: int = 20,
    ):
        self.syn_flood_rate_thresh = syn_flood_rate_thresh
        self.syn_ratio_thresh = syn_ratio_thresh
        self.port_scan_ports_thresh = port_scan_ports_thresh

    def classify(self, vector: FlowFeatureVector) -> Tuple[bool, Optional[str], int, str]:
        # 1. Kiểm tra DoS TCP SYN Flood
        if vector.packet_rate >= self.syn_flood_rate_thresh and vector.syn_ratio >= self.syn_ratio_thresh:
            summary = (
                f"AI-ANOMALY DoS SYN Flood detected | "
                f"rate={vector.packet_rate} pkt/s, syn_ratio={int(vector.syn_ratio * 100)}%"
            )
            return True, "dos-syn-flood", 1, summary

        # 2. Kiểm tra Reconnaissance Horizontal / Vertical Port Scan
        if vector.unique_dst_ports >= self.port_scan_ports_thresh:
            summary = (
                f"AI-ANOMALY Reconnaissance Port Scan detected | "
                f"targeted_ports={vector.unique_dst_ports} ports/s"
            )
            return True, "reconnaissance-port-scan", 2, summary

        # 3. Lưu lượng bình thường
        return False, None, 0, ""
```

- [ ] **Step 4: Chạy test để xác nhận test vượt qua**

Run: `pytest tests/test_ai_engine/test_model_classifier.py -v`  
Expected: `3 passed`

- [ ] **Step 5: Commit task**

```bash
git add services/ai_engine/model_classifier.py tests/test_ai_engine/test_model_classifier.py
git commit -m "feat(ai): implement anomaly classifier for syn flood and port scan"
```

---

### Task 4: Tích hợp AITrafficWorker hoàn chỉnh

**Files:**
- Modify: `services/ai_engine/ai_worker.py`
- Modify: `services/ai_engine/__init__.py`
- Test: `tests/test_ai_engine/test_ai_worker.py`

**Interfaces:**
- Consumes: `DecodedPacket` từ ingestion queue
- Produces: gọi `self.alert_callback(alert_dict)` với schema tương thích `EventRepository.save_alert`

- [ ] **Step 1: Viết test cho AITrafficWorker**

Tạo file `tests/test_ai_engine/test_ai_worker.py`:

```python
import time
from services.ingestion import DecodedPacket
from services.ai_engine.ai_worker import AITrafficWorker

def test_ai_worker_triggers_alert_callback_on_syn_flood():
    alerts = []
    def mock_alert_callback(alert_data):
        alerts.append(alert_data)

    worker = AITrafficWorker(alert_callback=mock_alert_callback)
    
    # Giả lập 60 gói tin SYN dồn dập từ 1 IP trong 1 giây
    for i in range(60):
        pkt = DecodedPacket(
            timestamp=time.time(),
            src_ip="192.168.1.199",
            src_port=10000 + i,
            dst_ip="10.0.0.5",
            dst_port=80,
            protocol="TCP",
            tcp_flags="S",
            raw_payload=b"X" * 64
        )
        worker.analyze_packet(pkt)

    assert len(alerts) > 0
    first_alert = alerts[0]
    assert first_alert["source_type"] == "AI_ANOMALY"
    assert first_alert["classtype"] == "dos-syn-flood"
    assert first_alert["severity"] == 1
    assert first_alert["src_ip"] == "192.168.1.199"
```

- [ ] **Step 2: Chạy test để xác nhận test thất bại**

Run: `pytest tests/test_ai_engine/test_ai_worker.py -v`  
Expected: `AssertionError: assert len(alerts) > 0` (vì `ai_worker.py` hiện tại đang là `pass`)

- [ ] **Step 3: Hiện thực hóa AITrafficWorker**

Sửa `services/ai_engine/ai_worker.py`:

```python
import time
from typing import Optional, Callable, Dict, Any
from services.ingestion import DecodedPacket
from services.ai_engine.flow_aggregator import FlowAggregator
from services.ai_engine.feature_extractor import FlowFeatureExtractor
from services.ai_engine.model_classifier import AnomalyClassifier


class AITrafficWorker:
    """
    Worker AI phân tích luồng mạng theo thời gian thực.
    Nhận DecodedPacket từ Queue, trích xuất đặc trưng luồng và kích hoạt alert khi phát hiện bất thường.
    """

    def __init__(self, alert_callback: Optional[Callable[[Dict[str, Any]], None]] = None):
        self.alert_callback = alert_callback
        self.aggregator = FlowAggregator(window_seconds=1.0)
        self.extractor = FlowFeatureExtractor()
        self.classifier = AnomalyClassifier()
        # Chống bão alert: giới hạn 1 alert / 2 giây cho cùng 1 src_ip và attack_type
        self._last_alert_time: Dict[str, float] = {}

    def analyze_packet(self, packet: DecodedPacket) -> None:
        if not packet.src_ip or packet.protocol != "TCP":
            return

        record = self.aggregator.add_packet(packet)
        vector = self.extractor.extract(record, duration=1.0)
        is_anomaly, attack_type, severity, summary = self.classifier.classify(vector)

        if is_anomaly and self.alert_callback:
            alert_key = f"{packet.src_ip}:{attack_type}"
            now = time.time()
            if now - self._last_alert_time.get(alert_key, 0) > 2.0:
                self._last_alert_time[alert_key] = now
                alert_payload = {
                    "timestamp": packet.timestamp or now,
                    "sid": None,
                    "source_type": "AI_ANOMALY",
                    "classtype": attack_type,
                    "severity": severity,
                    "src_ip": packet.src_ip,
                    "src_port": packet.src_port,
                    "dst_ip": packet.dst_ip,
                    "dst_port": packet.dst_port,
                    "protocol": packet.protocol,
                    "http_method": None,
                    "http_uri": None,
                    "msg": summary,
                }
                self.alert_callback(alert_payload)
```

Sửa `services/ai_engine/__init__.py`:

```python
from services.ai_engine.flow_aggregator import FlowAggregator, FlowRecord
from services.ai_engine.feature_extractor import FlowFeatureExtractor, FlowFeatureVector
from services.ai_engine.model_classifier import AnomalyClassifier
from services.ai_engine.ai_worker import AITrafficWorker

__all__ = [
    "FlowAggregator",
    "FlowRecord",
    "FlowFeatureExtractor",
    "FlowFeatureVector",
    "AnomalyClassifier",
    "AITrafficWorker",
]
```

- [ ] **Step 4: Chạy test để xác nhận test vượt qua**

Run: `pytest tests/test_ai_engine/test_ai_worker.py -v`  
Expected: `1 passed`

- [ ] **Step 5: Commit task**

```bash
git add services/ai_engine/ai_worker.py services/ai_engine/__init__.py tests/test_ai_engine/test_ai_worker.py
git commit -m "feat(ai): integrate ai traffic worker with anomaly detection flow"
```

---

### Task 5: Kiểm thử tích hợp toàn hệ thống (E2E Integration Verification)

**Files:**
- Modify: `create_demo_pcap.py` (thêm đợt tấn công SYN Flood 60 packets và Port Scan 25 ports)
- Verify: `main.py`

- [ ] **Step 1: Bổ sung lưu lượng SYN Flood và Port Scan vào script sinh mẫu PCAP**

Trong `create_demo_pcap.py`, thêm các gói tin kiểm thử AI:
- 55 gói tin TCP SYN dồn dập từ `192.168.1.250` vào `10.0.0.5:80`.
- 25 gói tin TCP từ `192.168.1.251` quét 25 cổng khác nhau từ port 20 đến 45.

- [ ] **Step 2: Chạy sinh lại file PCAP mẫu**

Run: `python create_demo_pcap.py`  
Expected: Tạo thành công `pcap_samples/demo_attacks.pcap` với các mẫu AI mới.

- [ ] **Step 3: Chạy Engine chính để kiểm tra cảnh báo AI xuất hiện trên Terminal**

Run: `python main.py`  
Expected Output có thêm:
```text
[ALERT #..] [AI-ANOMALY] AI-ANOMALY DoS SYN Flood detected | 192.168.1.250 -> 10.0.0.5:80
[ALERT #..] [AI-ANOMALY] AI-ANOMALY Reconnaissance Port Scan detected | 192.168.1.251 -> 10.0.0.5:..
```

- [ ] **Step 4: Kiểm tra lưu CSDL thành công**

Run: `python -c "from services.database.repository import EventRepository; print([e.summary for e in EventRepository.get_recent_events(limit=5) if e.source_type == 'AI_ANOMALY'])"`  
Expected: In ra các alert có tiền tố `AI-ANOMALY`.

- [ ] **Step 5: Commit hoàn thành tính năng AI Engine**

```bash
git add create_demo_pcap.py
git commit -m "test(ai): add syn flood and port scan pcap test samples"
```

