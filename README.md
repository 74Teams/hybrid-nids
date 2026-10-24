# Hybrid NIDS – Rule-based & AI-driven Network Intrusion Detection System

> **Đồ án PBL4 – Khoa Công nghệ Thông tin, Trường Đại học Bách Khoa – ĐHĐN**  
> Hệ thống phát hiện xâm nhập mạng thời gian thực kết hợp kiểm tra luật tĩnh (Snort-compatible) và phát hiện bất thường qua trí tuệ nhân tạo (AI Flow Worker).

---

## Mục lục

1. [Tổng quan hệ thống](#1-tổng-quan-hệ-thống)
2. [Kiến trúc kỹ thuật](#2-kiến-trúc-kỹ-thuật)
3. [Cấu trúc thư mục](#3-cấu-trúc-thư-mục)
4. [Cài đặt & Cấu hình](#4-cài-đặt--cấu-hình)
5. [Hướng dẫn chạy & Demo](#5-hướng-dẫn-chạy--demo)
6. [Tập luật phát hiện (Detection Rules)](#6-tập-luật-phát-hiện-detection-rules)
7. [Hệ thống REST API](#7-hệ-thống-rest-api)
8. [Cơ chế Hot-Reload Engine](#8-cơ-chế-hot-reload-engine)
9. [Trạng thái phát triển](#9-trạng-thái-phát-triển)

---

## 1. Tổng quan hệ thống

Hybrid NIDS được xây dựng nhằm giám sát và phân tích lưu lượng mạng thời gian thực với độ trễ thấp, bóc tách gói tin từ tầng L2 đến L7 và phát hiện các đòn tấn công mạng thông qua mô hình lai (Hybrid):

```
                       GÓI TIN MẠNG (Live Sniff / PCAP Replay)
                                         │
                                         ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│  Traffic Ingestion (packet_capture.py)                                          │
│  - Thu nhận gói tin qua Scapy (promiscuous mode hoặc đọc file .pcap)            │
│  - Chuyển tiếp ngay lập tức vào Async Buffer Queue (Zero Packet Loss)          │
└────────────────────────────────────────┬────────────────────────────────────────┘
                                         │ Scapy Packet
                                         ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│  Packet Decoding (packet_decoder.py & http_parser.py)                           │
│  - Giải mã L2 - L4: IP nguồn/đích, Protocol, Port, TCP Flags (SYN, FIN, URG...) │
│  - Bóc tách L7 HTTP: Method, URI, Query parameters, Headers, Request Body       │
└────────────────────────────────────────┬────────────────────────────────────────┘
                                         │ DecodedPacket
                                         ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│  Detection Analysis Engine (ids_realtime.py)                                    │
│  - Multi-pattern Matching: Thuật toán Aho-Corasick tìm chuỗi trong O(N)         │
│  - Detailed Evaluation: So khớp TCP flags, PCRE Regex, HTTP modifier            │
│  - AI Traffic Worker (Giai đoạn 2): Phân tích đặc trưng luồng (Flow Anomaly)    │
└───────────────────┬─────────────────────────────────────────┬───────────────────┘
                    │ Alert Event                             │ Hot-Reload Rules
                    ▼                                         ▼
┌─────────────────────────────────────────┐       ┌───────────────────────────────┐
│  Storage Layer (SQLAlchemy ORM)         │       │  Rule Manager                 │
│  - MySQL (Production) / SQLite (Dev)    │◀──────│  - Nạp rules từ DB vào RAM    │
│  - Tables: rules, events, event_payloads│       │  - Quản lý 14+ Snort rules    │
└───────────────────┬─────────────────────┘       └───────────────▲───────────────┘
                    │                                             │
                    ▼                                             │ CRUD Sync
┌─────────────────────────────────────────────────────────────────┴───────────────┐
│  FastAPI Server (api/main.py)                                                   │
│  - Alerts API: Tra cứu sự kiện, thống kê cảnh báo                               │
│  - Rules Management API: CRUD tập luật, Bật/Tắt rule, đồng bộ tức thì           │
│  - Swagger UI: http://localhost:8000/docs                                       │
└─────────────────────────────────────────────────────────────────────────────────┘
```

**Kết quả thực nghiệm trên bộ dữ liệu giả lập (`demo_attacks.pcap`):**
- Phát hiện thành công **16 cảnh báo** từ 18 gói tin kiểm thử.
- Bao phủ: SQL Injection, Cross-Site Scripting (XSS), Path Traversal / LFI, Command Injection, Nmap Port Scans (Xmas, Null, FIN, SYN-FIN).
- **0 cảnh báo sai (Zero False Positive)** trên lưu lượng thông thường (HTTP, DNS, ICMP, TCP Handshake).

---

## 2. Kiến trúc kỹ thuật

| Thành phần | Module / File | Công nghệ & Thư viện | Nhiệm vụ |
|---|---|---|---|
| **Packet Capture** | `packet_capture.py` | `scapy` | Bắt gói tin trực tiếp từ card mạng hoặc đọc replay file `.pcap` |
| **Packet Decoder** | `packet_decoder.py` | `scapy.layers` | Giải mã tầng L2–L4 (IP, TCP/UDP/ICMP, Flags) |
| **HTTP Parser** | `http_parser.py` | Python native | Bóc tách chuyên sâu HTTP L7: URI, Headers, POST Body |
| **Pattern Matcher** | `pattern_matcher.py` | `pyahocorasick` | So khớp đa mẫu đồng thời trong $O(N)$ độc lập với số lượng rule |
| **Realtime IDS** | `ids_realtime.py` | `re`, `threading` | Động cơ so khớp luật thời gian thực qua Queue bất đồng bộ |
| **Rule Manager** | `manager_rules.py` | Python native | Parse cú pháp Snort-compatible, nạp & hot-reload rules từ CSDL |
| **Database & ORM** | `models.py`, `repository.py` | `sqlalchemy 2.0`, `pymysql` | Quản lý schema & thao tác CRUD với MySQL / SQLite |
| **REST API Server** | `api/main.py`, `routes/` | `fastapi`, `uvicorn`, `pydantic` | Cung cấp RESTful API cho Dashboard và quản lý Rules |
| **Configuration** | `config.py`, `settings.yaml` | `pyyaml` | Quản lý tham số card mạng, chế độ capture và kết nối CSDL |

---

## 3. Cấu trúc thư mục

```text
App/
├── config/
│   ├── config.py                  # Helper load YAML & tự động sinh db_url
│   └── settings.yaml              # File cấu hình: Network, Database, Detection, API
│
├── rules/
│   └── local.rules                # Toàn bộ 30 rule tự định nghĩa (cú pháp Snort 3)
│
├── services/
│   ├── ingestion/                 # Khối thu nhận & tiền xử lý gói tin
│   │   ├── __init__.py            # Dataclass: DecodedPacket, ParsedHTTPRequest
│   │   ├── packet_capture.py      # Bắt gói tin (Live sniff hoặc Offline PCAP replay)
│   │   ├── packet_decoder.py      # Giải mã cấu trúc L2-L4 và điều hướng L7
│   │   └── http_parser.py         # Phân giải vùng ứng dụng HTTP L7
│   │
│   ├── detection/                 # Khối phân tích & phát hiện xâm nhập
│   │   ├── __init__.py            # Dataclass: SnortRule, RuleOption
│   │   ├── ids_realtime.py        # Core Engine so khớp luật thời gian thực
│   │   ├── manager_rules.py       # Quản lý rules: nạp từ file/DB, hot-reload RAM
│   │   └── pattern_matcher.py     # Cài đặt Aho-Corasick multi-pattern matcher
│   │
│   ├── ai_engine/                 # Khối AI phát hiện bất thường (Giai đoạn 2)
│   │   └── ai_worker.py           # Worker AI phân loại lưu lượng bất thường
│   │
│   └── database/                  # Khối lưu trữ dữ liệu
│       ├── __init__.py            # Khởi tạo Engine, SessionLocal, get_db() generator
│       ├── models.py              # ORM Models: RuleModel, EventModel, EventPayloadModel
│       ├── schemas.py             # Pydantic Schemas: RuleCreate, RuleUpdate, RuleResponse
│       └── repository.py          # CRUD Data Access: EventRepository, RuleRepository
│
├── api/                           # Backend API phục vụ Dashboard
│   ├── main.py                    # FastAPI app, Lifespan startup, CORS & Engine singleton
│   ├── dependencies.py            # Dependency Injection: session get_db
│   └── routes/
│       ├── alerts.py              # API xem & lọc danh sách Alerts vi phạm
│       └── rules.py               # API CRUD đầy đủ: thêm, sửa, xóa, bật/tắt rules
│
├── pcap_samples/
│   └── demo_attacks.pcap          # File PCAP mẫu gồm 18 gói tin tấn công và bình thường
│
├── main.py                        # Điểm khởi chạy toàn bộ tiến trình NIDS
├── create_demo_pcap.py            # Script sinh gói tin PCAP mẫu phục vụ kiểm thử
├── requirements.txt               # Danh sách thư viện phụ thuộc
├── .gitignore                     # Bỏ qua tệp cache, file CSDL local
└── README.md
```

---

## 4. Cài đặt & Cấu hình

### 4.1. Yêu cầu môi trường

- **Python:** Phiên bản 3.10 trở lên.
- **Windows (chế độ Live Capture):** Cần cài đặt driver [Npcap](https://npcap.com/#download) (chọn _"Install Npcap in WinPcap API-compatible Mode"_).
- **Linux:** Cần thư viện pcap:
  ```bash
  sudo apt update && sudo apt install -y libpcap-dev
  ```

### 4.2. Cài đặt thư viện Python

```bash
pip install -r requirements.txt
```

### 4.3. Cấu hình hệ thống (`config/settings.yaml`)

Hệ thống hỗ trợ linh hoạt cả **MySQL** (môi trường chính) và **SQLite** (môi trường kiểm thử nhanh):

```yaml
network:
  interface: ""                              # Để trống để tự động chọn card mặc định
  bpf_filter: "ip"                           # Bộ lọc Berkeley Packet Filter
  promiscuous: true                          # Chế độ bắt toàn bộ gói tin
  capture_mode: "offline"                    # "offline" (file pcap) hoặc "live" (card mạng)
  pcap_file: "pcap_samples/demo_attacks.pcap"

detection:
  rules_dir: "rules"
  enable_rule_engine: true
  enable_ai_worker: true
  queue_max_size: 10000

database:
  # Cấu hình MySQL (Khuyên dùng khi chạy chính thức)
  type: "mysql"
  host: "localhost"
  port: 3306
  user: "root"
  password: "your_password"
  name: "nids_db"

  # Fallback SQLite (tự động sử dụng khi type: "sqlite")
  db_url: "sqlite:///nids_events.db"

api:
  host: "0.0.0.0"
  port: 8000
```

> **Lưu ý khi dùng MySQL:** Hãy tạo trước cơ sở dữ liệu `nids_db`:
> ```sql
> CREATE DATABASE nids_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
> ```

---

## 5. Hướng dẫn chạy & Demo

### Cách 1: Demo Offline bằng PCAP giả lập (Khuyến nghị – Không cần quyền Admin)

**Bước 1 – Sinh dữ liệu kiểm thử PCAP:**
```bash
python create_demo_pcap.py
```
> Tạo tệp `pcap_samples/demo_attacks.pcap` với 18 gói tin tấn công và bình thường.

**Bước 2 – Khởi chạy Core Detection Engine:**
```bash
python main.py
```
*Engine sẽ nạp rules vào RAM, đọc gói tin từ PCAP và đẩy các vi phạm vào CSDL.*

**Bước 3 – Khởi động API Server (mở terminal mới):**
```bash
uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload
```
- Truy cập Swagger UI: [http://localhost:8000/docs](http://localhost:8000/docs)
- Xem danh sách Alerts: [http://localhost:8000/api/alerts/](http://localhost:8000/api/alerts/)
- Xem danh sách Rules: [http://localhost:8000/api/rules/](http://localhost:8000/api/rules/)

### Cách 2: Chạy Live Sniffing trên card mạng thật

1. Mở `config/settings.yaml`, sửa `capture_mode: "live"`.
2. Mở Command Prompt / PowerShell bằng quyền **Run as Administrator**.
3. Chạy lệnh:
   ```bash
   python main.py
   ```

---

## 6. Tập luật phát hiện (Detection Rules)

Toàn bộ rule nằm trong một file duy nhất `rules/local.rules`, viết theo cú pháp **Snort 3** (sticky buffer, modifier của content viết sau dấu phẩy, `priority`). Quy tắc viết rule chi tiết nằm ở [`.claude/rules/snort-rules.md`](.claude/rules/snort-rules.md).

```text
alert tcp any any -> any $HTTP_PORTS (msg:"WEB-ATTACK SQL Injection - UNION SELECT detected"; flow:to_server,established; http_uri; content:"union",nocase; content:"select",nocase,distance 0; service:http; classtype:web-application-attack; priority:1; sid:1000001; rev:2;)
```

| Dải SID | Nhóm | Số rule | Kỹ thuật tiêu biểu |
|---|---|---|---|
| `10000xx` | WEB-ATTACK: SQLi, XSS, Path Traversal, Command Injection | 10 | `http_uri`, `http_client_body`, `pcre`, `distance` |
| `10001xx` | SCAN: Nmap Xmas, Null, FIN, SYN-FIN | 4 | `flow:stateless`, `flags` |
| `10002xx` | DOS: SYN Flood, Slowloris, Large ICMP, NTP monlist | 4 | `detection_filter`, `itype`, `dsize`, content hex |
| `10003xx` | AUTH: SSH, FTP anonymous, HTTP Basic, admin login | 4 | `depth`, `http_header:field`, `http_method` |
| `10004xx` | MALWARE, C2: webshell, reverse shell, sqlmap, nikto | 5 | `flow:established`, `http_header:field user-agent` |
| `10005xx` | RECON: SNMP public, DNS tunneling, ICMP timestamp | 3 | content hex `\|04 06\|`, `itype`, `icode` |

---

## 7. Hệ thống REST API

FastAPI cung cấp tài liệu API tự động chuẩn OpenAPI tại `http://localhost:8000/docs`.

### 7.1. Nhóm API Quản lý Rules (`/api/rules`)

Hệ thống cung cấp đầy đủ chức năng CRUD với cơ chế đồng bộ CSDL và hot-reload:

| Method | Endpoint | Mô tả |
|---|---|---|
| `GET` | `/api/rules/` | Lấy danh sách rules kèm thống kê (`enabled_only=true` để lọc) |
| `GET` | `/api/rules/{sid}` | Lấy thông tin chi tiết một rule theo SID |
| `POST` | `/api/rules/` | Tạo rule mới (tự sinh SID, tự build chuỗi `raw_rule` Snort) |
| `PUT` | `/api/rules/{sid}` | Cập nhật rule (partial update, tự động tăng `rev`) |
| `DELETE` | `/api/rules/{sid}` | Xóa vĩnh viễn rule khỏi CSDL và RAM Engine |
| `PATCH` | `/api/rules/{sid}/toggle` | Bật/Tắt nhanh một rule (vô hiệu hóa không cần xóa) |

#### Ví dụ Request tạo Rule mới (`POST /api/rules/`):
```json
{
  "action": "alert",
  "protocol": "tcp",
  "src_ip": "any",
  "src_port": "any",
  "direction": "->",
  "dst_ip": "any",
  "dst_port": "80",
  "msg": "WEB-ATTACK SQL Injection - DROP TABLE attempt",
  "classtype": "web-application-attack",
  "severity": 1,
  "contents": ["DROP TABLE"],
  "http_uri": true,
  "nocase": true
}
```

#### Ví dụ Response (`201 Created`):
```json
{
  "id": 15,
  "sid": 1000104,
  "rev": 1,
  "action": "alert",
  "protocol": "tcp",
  "src_ip": "any",
  "src_port": "any",
  "direction": "->",
  "dst_ip": "any",
  "dst_port": "80",
  "msg": "WEB-ATTACK SQL Injection - DROP TABLE attempt",
  "classtype": "web-application-attack",
  "severity": 1,
  "raw_rule": "alert tcp any any -> any 80 (msg:\"WEB-ATTACK SQL Injection - DROP TABLE attempt\"; http_uri; content:\"DROP TABLE\",nocase; classtype:web-application-attack; priority:1; sid:1000104; rev:1;)",
  "is_enabled": true,
  "created_at": "2026-10-13T04:29:30.123456",
  "updated_at": "2026-10-13T04:29:30.123456"
}
```

### 7.2. Nhóm API Cảnh báo & Giám sát (`/api/alerts`)

| Method | Endpoint | Mô tả |
|---|---|---|
| `GET` | `/health` | Kiểm tra trạng thái hoạt động của API và Detection Engine |
| `GET` | `/api/alerts/?limit=50` | Lấy danh sách sự kiện xâm nhập gần nhất |

---

## 8. Cơ chế Hot-Reload Engine

Một trong những tính năng nổi bật của hệ thống là khả năng **cập nhật tập luật theo thời gian thực (Zero-Downtime Hot-Reload)** mà không cần khởi động lại tiến trình:

1. **Khởi động:** Server đọc `rules/local.rules` và import vào MySQL/SQLite: rule chưa có thì thêm mới, rule đã có chỉ bị ghi đè khi `rev` trong file lớn hơn `rev` trong CSDL.
2. **Nguồn sự thật duy nhất (Single Source of Truth):** Sau khi khởi động, CSDL trở thành trung tâm quản lý.
3. **Hot-Reload tức thì:** Mỗi khi người dùng gọi API tạo mới, chỉnh sửa, xóa hoặc bật/tắt rule (`POST/PUT/DELETE/PATCH`), hệ thống sẽ gọi phương thức `RuleManager.reload_rules_from_db()`:
   - Dọn sạch tập luật cũ trong RAM.
   - Nạp lại toàn bộ rules có trạng thái `is_enabled = True` từ CSDL.
   - Xây dựng lại cây chỉ mục Aho-Corasick.
   - Rule mới có hiệu lực ngay trong gói tin tiếp theo được phân tích!

---

## 9. Trạng thái phát triển

| Hạng mục / Tính năng | Trạng thái | Ghi chú |
|---|:---:|---|
| Bắt gói tin trực tiếp (Live Packet Capture) | ✅ Hoàn thành | Scapy Promiscuous mode |
| Đọc & phân tích tệp PCAP offline | ✅ Hoàn thành | Hỗ trợ Windows fallback không cần tcpdump |
| Giải mã gói tin L2 - L4 (IP, TCP, UDP, ICMP, Flags) | ✅ Hoàn thành | Bóc tách đầy đủ cờ TCP cho đòn Nmap scan |
| Bóc tách giao thức tầng ứng dụng HTTP L7 | ✅ Hoàn thành | Phân tách Method, URI, Headers, POST Body |
| So khớp quy tắc tốc độ cao Aho-Corasick | ✅ Hoàn thành | Tìm kiếm đa mẫu đồng thời trong $O(N)$ |
| Hỗ trợ Modifier Snort: `http_uri`, `http_client_body`, `pcre` | ✅ Hoàn thành | Đáp ứng các rule Web Application Attack |
| Cơ sở dữ liệu ORM MySQL & SQLite | ✅ Hoàn thành | SQLAlchemy 2.0, tự động tạo schema |
| **Hệ thống Rule Management API (CRUD đầy đủ)** | ✅ Hoàn thành | 6 REST endpoints, validate qua Pydantic |
| **Cơ chế Hot-Reload Detection Engine** | ✅ Hoàn thành | Cập nhật luật trong RAM tức thì không cần restart |
| API tra cứu cảnh báo (`/api/alerts/`) | ✅ Hoàn thành | Trả về thông tin IP, port, severity, payload evidence |
| Script tạo mẫu kiểm thử PCAP (`create_demo_pcap.py`) | ✅ Hoàn thành | 18 gói tin mẫu, 0% False Positive |
| Kênh WebSocket bắn Alert thời gian thực | 🔄 Giai đoạn 2 | Đang phát triển |
| Trích xuất đặc trưng luồng (Flow Feature Extractor) | 🔄 Giai đoạn 2 | Trích xuất packet rate, duration, byte count |
| AI Traffic Worker (ML Anomaly Detection) | 🔄 Giai đoạn 2 | Mô hình Random Forest / XGBoost phát hiện DoS |
| Dashboard giao diện người dùng (Frontend Web) | 🔄 Giai đoạn 2 | Trực quan hóa bản đồ mạng và biểu đồ tấn công |

---

*Đồ án PBL4 – Khoa Công nghệ Thông tin, Trường Đại học Bách Khoa – Đại học Đà Nẵng.*
