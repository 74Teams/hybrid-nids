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

- Chỉ có hai bảng: `events`, `event_payloads`. Engine và honeypot cùng ghi vào `events`, phân biệt bằng `source_type` (`RULE_ENGINE` / `HONEYPOT`).
- `init_db()` thử lại tối đa 15 lần, mỗi lần cách 2s, vì MySQL khởi động chậm trong Docker.

## Docker

- `docker compose up --build` khởi động MySQL, một nginx "victim", NIDS engine, honeypot, API và container attacker trên mạng bridge cô lập (172.28.0.0/16).
- `nids_engine` dùng `network_mode: service:victim_app` để sniff traffic của victim, và mount repo vào `/app`.
- `honeypot_ssh` và `honeypot_http` cũng dùng `network_mode: service:victim_app` (cổng 2222 và 8080; 8080 nằm trong `HTTP_PORTS` nên rule web áp dụng luôn), nên cùng một đòn vừa sinh cảnh báo rule vừa sinh sự kiện honeypot.
- `nids_api` (API + dashboard) cố ý chạy ở network riêng để request poll của dashboard không bị engine sniff nhầm.
- `network.bpf_filter` loại port 3306: engine thấy cả kết nối ghi alert vào MySQL, nếu không loại thì câu INSERT chứa chuỗi tấn công sẽ sinh alert mới (vòng lặp).
