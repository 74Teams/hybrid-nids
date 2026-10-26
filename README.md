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
8. [Trạng thái phát triển](#8-trạng-thái-phát-triển)

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
                    │ Alert Event
                    ▼
┌─────────────────────────────────────────┐
│  Storage Layer (SQLAlchemy ORM)         │
│  - MySQL (Production) / SQLite (Dev)    │
│  - Tables: events, event_payloads       │
└───────────────────┬─────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│  FastAPI Server (api/main.py)                                                   │
│  - Alerts API: Tra cứu sự kiện, thống kê cảnh báo                               │
│  - Swagger UI: http://localhost:8000/docs                                       │
└─────────────────────────────────────────────────────────────────────────────────┘

Rule: engine đọc rules/local.rules lúc khởi động (RuleManager.load_all_rules).
```

**Kết quả thực nghiệm trên bộ dữ liệu giả lập (`demo_attacks.pcap`):**
- Phát hiện thành công **25 cảnh báo** từ 39 gói tin kiểm thử.
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
| **Rule Manager** | `manager_rules.py` | Python native | Parse cú pháp Snort 3 và nạp rules từ file `rules/local.rules` |
| **Database & ORM** | `models.py`, `repository.py` | `sqlalchemy 2.0`, `pymysql` | Lưu và truy vấn sự kiện cảnh báo trên MySQL / SQLite |
| **REST API Server** | `api/main.py`, `routes/` | `fastapi`, `uvicorn`, `pydantic` | Cung cấp RESTful API tra cứu cảnh báo cho Dashboard |
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
│   └── local.rules                # Toàn bộ 67 rule tự định nghĩa (cú pháp Snort 3)
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
│   │   ├── manager_rules.py       # Quản lý rules: parse và nạp từ file `rules/local.rules`
│   │   └── pattern_matcher.py     # Cài đặt Aho-Corasick multi-pattern matcher
│   │
│   ├── ai_engine/                 # Khối AI phát hiện bất thường (Giai đoạn 2)
│   │   └── ai_worker.py           # Worker AI phân loại lưu lượng bất thường
│   │
│   └── database/                  # Khối lưu trữ dữ liệu
│       ├── __init__.py            # Khởi tạo Engine, SessionLocal, get_db() generator
│       ├── models.py              # ORM Models: EventModel, EventPayloadModel
│       └── repository.py          # Data Access: EventRepository
│
├── api/                           # Backend API phục vụ Dashboard
│   ├── main.py                    # FastAPI app, Lifespan startup, CORS, phục vụ dashboard tại `/`
│   ├── static/
│   │   └── dashboard.html         # Dashboard theo dõi cảnh báo (tự làm mới mỗi 2 giây)
│   └── routes/
│       └── alerts.py              # API xem, thống kê và xoá Alerts
│
├── attacker/
│   └── attack_demo.py             # Kịch bản tấn công demo (chạy trong container attacker)
│
├── docs/demo/
│   └── kich-ban-demo.md           # Kịch bản thuyết trình và Q&A
│
├── pcap_samples/
│   └── demo_attacks.pcap          # File PCAP mẫu gồm 39 gói tin tấn công và bình thường
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
system:
  log_level: "INFO"                          # "DEBUG" để xem chi tiết kỹ thuật (từng rule, từng bước)

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

> **Log trên terminal:** mỗi dòng có dạng `giờ  mức độ  khu vực  nội dung`; cảnh báo được tô màu theo priority (P1 đỏ, P2 vàng, P3 xanh dương). Màu tự tắt khi đầu ra bị chuyển hướng vào file; đặt biến môi trường `NO_COLOR=1` để tắt màu thủ công.

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
> Tạo tệp `pcap_samples/demo_attacks.pcap` với 39 gói tin tấn công và bình thường.

**Bước 2 – Khởi chạy Core Detection Engine:**
```bash
python main.py
```
*Engine sẽ nạp rules từ `rules/local.rules` vào RAM, đọc gói tin từ PCAP và đẩy các vi phạm vào CSDL.*

**Bước 3 – Khởi động API Server (mở terminal mới):**
```bash
uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload
```
- Truy cập Swagger UI: [http://localhost:8000/docs](http://localhost:8000/docs)
- Xem danh sách Alerts: [http://localhost:8000/api/alerts/](http://localhost:8000/api/alerts/)

### Cách 2: Demo trực tiếp bằng Docker (tấn công thật trong mạng cô lập)

```bash
docker compose up --build -d
```
Mở dashboard tại [http://localhost:8000/](http://localhost:8000/), rồi tấn công từ container `attacker`:
```bash
docker exec -it nids_attacker python attacker/attack_demo.py all      # toàn bộ 67 rule
docker exec -it nids_attacker python attacker/attack_demo.py web      # hoặc: scan | dos | auth | malware | recon
docker logs -f nids_engine                                            # xem cảnh báo có màu theo priority
```
Chi tiết từng bước và câu hỏi thường gặp: [`docs/demo/kich-ban-demo.md`](docs/demo/kich-ban-demo.md).

### Cách 3: Chạy Live Sniffing trên card mạng thật

1. Mở `config/settings.yaml`, sửa `capture_mode: "live"`.
2. Mở Command Prompt / PowerShell bằng quyền **Run as Administrator**.
3. Chạy lệnh:
   ```bash
   python main.py
   ```

---

### Honeypot kết hợp

Container `honeypot_ssh` (cổng 2222) và `honeypot_http` (cổng 8080) chạy chung network với victim. Mọi kết nối vào honeypot được ghi vào bảng `events` với `source_type = HONEYPOT`; cảnh báo của rule engine từ IP đã chạm honeypot được nâng một bậc priority và gắn `[honeypot-confirmed]`. Demo: `docker exec -it nids_attacker python attacker/attack_demo.py honeypot`. Dashboard có bảng "Top IP tấn công", API có `/api/alerts/attackers` và `/api/alerts/?source_type=HONEYPOT`.

---

## 6. Tập luật phát hiện (Detection Rules)

Toàn bộ rule nằm trong một file duy nhất `rules/local.rules`, viết theo cú pháp **Snort 3** (sticky buffer, modifier của content viết sau dấu phẩy, `priority`). Quy tắc viết rule chi tiết nằm ở [`.claude/rules/snort-rules.md`](.claude/rules/snort-rules.md).

```text
alert tcp any any -> any $HTTP_PORTS (msg:"WEB-ATTACK SQL Injection - UNION SELECT detected"; flow:to_server,established; http_uri; content:"union",nocase; content:"select",nocase,distance 0; service:http; classtype:web-application-attack; priority:1; sid:1000001; rev:2;)
```

| Dải SID | Nhóm | Số rule | Kỹ thuật tiêu biểu |
|---|---|---|---|
| `10000xx` | WEB-ATTACK: SQLi, XSS, Path Traversal/LFI/RFI, Command Injection, Log4Shell, Shellshock, XXE, SSRF | 24 | `http_uri`, `http_client_body`, `pcre`, `distance` |
| `10001xx` | SCAN: Nmap Xmas, Null, FIN, SYN-FIN, SYN-RST, quét cổng, User-Agent scanner | 8 | `flow:stateless`, `flags`, `detection_filter` |
| `10002xx` | DOS: SYN/UDP/ICMP/HTTP flood, Slowloris, Large ICMP, NTP/DNS/Memcached khuếch đại | 9 | `detection_filter`, `itype`, `dsize`, content hex |
| `10003xx` | AUTH: SSH/FTP/Web brute force, FTP anonymous, HTTP Basic, admin login | 7 | `depth`, `http_header:field`, `http_method` |
| `10004xx` | MALWARE, C2: webshell, reverse shell, Mimikatz, EICAR, cryptominer, sqlmap, nikto | 11 | `flow:established`, `http_header:field user-agent` |
| `10005xx` | RECON: SNMP public, DNS tunneling/AXFR/version.bind, ICMP, NetBIOS, SSDP | 8 | content hex `\|04 06\|`, `itype`, `icode` |

---

## 7. Hệ thống REST API

FastAPI cung cấp tài liệu API tự động chuẩn OpenAPI tại `http://localhost:8000/docs`.

Rule không quản lý qua API: chúng nằm ở `rules/local.rules`. Muốn đổi rule, sửa file rồi khởi động lại engine (`python main.py`).

### Nhóm API Cảnh báo & Giám sát (`/api/alerts`)

| Method | Endpoint | Mô tả |
|---|---|---|
| `GET` | `/health` | Kiểm tra trạng thái hoạt động của API |
| `GET` | `/` | Dashboard theo dõi cảnh báo thời gian thực |
| `GET` | `/api/alerts/?limit=50` | Lấy danh sách sự kiện xâm nhập gần nhất |
| `GET` | `/api/alerts/stats` | Thống kê: tổng, theo priority, top loại tấn công |
| `DELETE` | `/api/alerts/` | Xoá toàn bộ cảnh báo (reset trước lượt demo mới) |

---

## 8. Trạng thái phát triển

| Hạng mục / Tính năng | Trạng thái | Ghi chú |
|---|:---:|---|
| Bắt gói tin trực tiếp (Live Packet Capture) | ✅ Hoàn thành | Scapy Promiscuous mode |
| Đọc & phân tích tệp PCAP offline | ✅ Hoàn thành | Hỗ trợ Windows fallback không cần tcpdump |
| Giải mã gói tin L2 - L4 (IP, TCP, UDP, ICMP, Flags) | ✅ Hoàn thành | Bóc tách đầy đủ cờ TCP cho đòn Nmap scan |
| Bóc tách giao thức tầng ứng dụng HTTP L7 | ✅ Hoàn thành | Phân tách Method, URI, Headers, POST Body |
| So khớp quy tắc tốc độ cao Aho-Corasick | ✅ Hoàn thành | Tìm kiếm đa mẫu đồng thời trong $O(N)$ |
| Hỗ trợ Modifier Snort: `http_uri`, `http_client_body`, `pcre` | ✅ Hoàn thành | Đáp ứng các rule Web Application Attack |
| Cơ sở dữ liệu ORM MySQL & SQLite | ✅ Hoàn thành | SQLAlchemy 2.0, tự động tạo schema |
| API tra cứu cảnh báo (`/api/alerts/`) | ✅ Hoàn thành | Trả về thông tin IP, port, severity, payload evidence |
| Script tạo mẫu kiểm thử PCAP (`create_demo_pcap.py`) | ✅ Hoàn thành | 39 gói tin mẫu, 25 cảnh báo |
| Kênh WebSocket bắn Alert thời gian thực | 🔄 Giai đoạn 2 | Đang phát triển |
| Trích xuất đặc trưng luồng (Flow Feature Extractor) | 🔄 Giai đoạn 2 | Trích xuất packet rate, duration, byte count |
| AI Traffic Worker (ML Anomaly Detection) | 🔄 Giai đoạn 2 | Mô hình Random Forest / XGBoost phát hiện DoS |
| Dashboard giao diện người dùng (Frontend Web) | 🔄 Giai đoạn 2 | Trực quan hóa bản đồ mạng và biểu đồ tấn công |

---

*Đồ án PBL4 – Khoa Công nghệ Thông tin, Trường Đại học Bách Khoa – Đại học Đà Nẵng.*
