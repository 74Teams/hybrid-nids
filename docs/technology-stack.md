# Công nghệ sử dụng

## 1. Tổng quan theo tầng

| Tầng | Công nghệ | Vai trò |
|---|---|---|
| Ngôn ngữ | Python 3.10+ | Toàn bộ engine, honeypot, API, công cụ |
| Bắt và giải mã gói | Scapy ≥ 2.5 | Sniff live (Npcap/libpcap) hoặc đọc pcap; decode L2–L4 |
| So khớp mẫu | pyahocorasick ≥ 2.1, `re` | Prefilter Aho-Corasick nhiều mẫu một lượt; `pcre` của rule |
| Cú pháp rule | Snort 3 (tập con) | Rule đọc từ file `data/rules/*.rules` |
| Lưu trữ | SQLAlchemy 2.0, MySQL 8 (PyMySQL), SQLite | MySQL trong Docker, SQLite khi chạy local |
| API và dashboard | FastAPI, Uvicorn, Pydantic | REST API, WebSocket, phục vụ trang tĩnh |
| Giao diện | HTML, CSS, JavaScript thuần | Biểu đồ SVG tự vẽ, không có bước build |
| Realtime | Redis 7 + redis-py ≥ 8.1 | Pub/sub báo id cảnh báo mới cho WebSocket (tuỳ chọn) |
| Honeypot | paramiko ≥ 3.4 (SSH), Flask ≥ 3.0 + waitress ≥ 3.0 (HTTP), pydantic-settings | Bẫy SSH với shell giả, bẫy trang đăng nhập WordPress |
| Phản ứng | iptables (`REDIRECT`) | Chuyển IP đáng ngờ sang honeypot |
| Học máy | numpy, pandas, scikit-learn, joblib | Dựng dataset, huấn luyện Random Forest, lưu mô hình |
| Cấu hình | YAML (`common/config/settings.yaml`), biến môi trường | Biến môi trường ghi đè YAML |
| Môi trường lab | Docker Compose, Kali Linux, nginx | Attacker, victim, toàn bộ service trên mạng cô lập |
| Kiểm thử | pytest, FastAPI TestClient, GitHub Actions | CI chạy pytest cho mỗi pull request vào `main` |

## 2. Lý do chọn

| Lựa chọn | Lý do | Đánh đổi |
|---|---|---|
| **Python + Scapy** thay vì C/libpcap | Nhóm viết và giải thích được toàn bộ pipeline; Scapy decode đủ giao thức | Chậm: khoảng 2.300–3.200 gói/giây. Scapy chiếm hơn một nửa thời gian xử lý ([performance-metrics.md](performance-metrics.md)) |
| **Cú pháp Snort 3** | Chuẩn công nghiệp, dùng lại được bộ rule community | Engine chỉ hiểu một tập con option ([detection-engine.md](detection-engine.md)) |
| **Aho-Corasick** | Tìm mọi mẫu trong một lần duyệt payload, chi phí không tăng theo số rule | Cần một matcher riêng cho mỗi buffer (URI, header, body, raw) |
| **MySQL + SQLite** | MySQL chịu nhiều process ghi đồng thời trong lab; SQLite không cần cài khi phát triển | SQLite dễ khoá khi nhiều process ghi; đã bật WAL và timeout 30 giây |
| **Redis pub/sub chỉ mang id** | Cảnh báo lên dashboard dưới 1 giây; tin không chứa nội dung tấn công | Redis tắt thì dashboard quay về poll 2 giây |
| **Frontend thuần** | Không cần Node, không có bước build, API phục vụ luôn file tĩnh | Tự vẽ biểu đồ SVG |
| **Random Forest** | Dữ liệu dạng bảng; không cần chuẩn hoá; nhanh trên CPU; có feature importance để giải thích | Không học tăng dần; phải huấn luyện lại khi đổi đặc trưng |
| **Docker Compose** | Một lệnh dựng đủ attacker, victim và 8 service; mạng cô lập an toàn để tấn công thật | Engine phải dùng chung namespace mạng với victim để sniff được |

## 3. Phiên bản cần lưu ý

- `data/models/flow_model.joblib` được huấn luyện bằng **scikit-learn 1.9.1**. Nạp bằng bản khác sẽ có `InconsistentVersionWarning` và có thể cho kết quả sai. Mô hình lưu bản sklearn ở `bundle["sklearn_version"]`.
- Image sensor dùng `python:3.12-slim` (scikit-learn 1.9.1 cần Python 3.11+); các image còn lại dùng `python:3.10-slim`.
- Redis yêu cầu mật khẩu (`NIDS_REDIS_PASSWORD` trong `.env`), không publish cổng ra máy host.
