---
paths:
  - "config/**"
  - "nids/config.py"
  - "nids/db/**"
  - "docker-compose.yml"
  - "Dockerfile"
---

# Cấu hình, database và Docker

## Cấu hình

- `config/settings.yaml` được load một lần lúc import vào `nids.config.SETTINGS`.
- `get_db_url()` dựng URL từ mục `database`; các biến môi trường `NIDS_DB_HOST/PORT/NAME/USER/PASSWORD` ghi đè (docker-compose dựa vào điều này). `type: sqlite` dùng `db_url`.
- File mẫu `settings.example.yaml` được commit; `settings.yaml` là file local bị ignore (thiếu thì dùng file mẫu), mật khẩu Docker nằm ở `.env`. Mặc định của file mẫu dùng `capture_mode: "live"`, interface `eth0` và IP MySQL của Docker. Khi chạy local thì chuyển sang `sqlite` (và `offline` kèm `pcap_file` nếu có file pcap riêng).

## Database

- Ba bảng: `events`, `event_payloads`, `flows`. Engine và honeypot cùng ghi vào `events`, phân biệt bằng `source_type` (`RULE_ENGINE` / `HONEYPOT`).
- `flows` là flow log của engine: mỗi dòng là một flow đã kết thúc (số gói/byte hai chiều, cờ TCP, `end_reason`, `alert_count`; `alert_count = 0` nghĩa là không khớp rule nào). Engine ghi theo lô và tự xoá flow cũ hơn `flow.retention_hours` theo cột `created_at` (thời điểm ghi, không phải giờ của gói). Cấu hình ở mục `flow` trong `settings.yaml`.
- Mọi cột thời gian (`events.timestamp`, `flows.*`) luôn lưu **UTC naive** (không kèm múi giờ), bất kể múi giờ của máy chạy engine hay API. Dùng `nids.db.models.utc_now()` để lấy giờ hiện tại và `utc_from_epoch(ts)` để đổi epoch; không dùng `datetime.now()`, `datetime.utcnow()` hay `fromtimestamp` không có `tz`.
- Mục `detection.variables` khai báo biến header rule (`HTTP_PORTS`, `HOME_NET`...), đọc qua `get_rule_variables()`; đổi xong phải khởi động lại engine và API, và quote mọi giá trị trong YAML (`!$HOME_NET` không quote là YAML tag).
- Mục `redis` (`host`, `port`, `password`) cấu hình kênh đẩy cảnh báo realtime; `host` rỗng = tắt. Biến `NIDS_REDIS_HOST/PORT/PASSWORD` ghi đè (compose dựa vào đây), đọc qua `get_redis_settings()`. Mật khẩu Redis ở `.env` (`NIDS_REDIS_PASSWORD`), file mẫu để trống.
- `init_db()` thử lại tối đa 15 lần, mỗi lần cách 2s, vì MySQL khởi động chậm trong Docker.

## Docker

- Service `redis` (`redis:7-alpine`, `172.28.0.30`) chỉ nằm trong mạng lab, không publish cổng ra host, bắt buộc mật khẩu, không lưu bền. Engine, honeypot và API không `depends_on` nó vì Redis chỉ là phụ trợ.
- `docker compose up --build` khởi động MySQL, Redis, một nginx "victim", NIDS engine, honeypot, API và container attacker trên mạng bridge cô lập (172.28.0.0/16).
- `nids_engine` dùng `network_mode: service:victim_app` để sniff traffic của victim, và mount repo vào `/app`.
- `honeypot_ssh` và `honeypot_http` cũng dùng `network_mode: service:victim_app` (cổng 2222 và 8080; 8080 nằm trong `HTTP_PORTS` nên rule web áp dụng luôn), nên cùng một đòn vừa sinh cảnh báo rule vừa sinh sự kiện honeypot.
- `nids_api` (API + dashboard) cố ý chạy ở network riêng để request của dashboard (poll dự phòng, WebSocket) không bị engine sniff nhầm.
- `network.bpf_filter` loại port 3306: engine thấy cả kết nối ghi alert vào MySQL, nếu không loại thì câu INSERT chứa chuỗi tấn công sẽ sinh alert mới (vòng lặp). Cùng lý do, loại thêm `host 172.28.0.30 and port 6379` (Redis của lab); không loại cả cổng 6379.
