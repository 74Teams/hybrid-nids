---
paths:
  - "nids/honeypot/**"
  - "tests/honeypot/**"
---

# Honeypot (`nids/honeypot/`)

- Honeypot SSH (`ssh_honeypot.py`, paramiko, nhận mọi mật khẩu, shell giả) và HTTP (`web_honeypot.py`, Flask, trang login WordPress giả), chạy bằng `python -m nids.honeypot ssh|http`.
- Cấu hình qua biến môi trường `HONEYPY_*` (`settings.py`). Host key SSH tự sinh vào `data/` ở gốc repo (gitignore).
- Sensor chỉ thu thập: `store.py::log_event` ghi vào bảng `events` chung với `source_type="HONEYPOT"` (`attack_type` = event type như `ssh.auth.attempt`, dữ liệu thô vào `event_payloads`).
- Lỗi ghi CSDL không được làm sập sensor.
- Không bao giờ thực thi input của attacker. Shell giả chỉ trả chuỗi dựng sẵn.
- Honeypot được gộp từ dự án HONEYPY cũ (repo `74Teams/my_honeypot`, còn giữ lịch sử).
- Sự kiện SSH mang HASSH (fingerprint công cụ client, tính từ KEXINIT trong `HasshTransport`) và tên công cụ (`KNOWN_HASSH`, không có thì lấy banner client), lưu trong `matched_content` dạng `hassh=<md5> | tool=<tên>`. Tên công cụ cũng nằm trong `msg`. HASSH theo thư viện và phiên bản: công cụ mới hoặc bản mới thì đo trong lab rồi thêm vào `KNOWN_HASSH`.
- Brute force: `BruteForceTracker` đếm `ssh.auth.attempt` theo cặp IP + HASSH (trong bộ nhớ process), chạm `HONEYPY_SSH_BRUTEFORCE_THRESHOLD` lần (mặc định 5, mỗi lần cách nhau không quá `HONEYPY_SSH_BRUTEFORCE_WINDOW` = 60 giây) thì ghi một sự kiện `ssh.bruteforce` (P2) cho cả đợt.
- Session: mỗi kết nối SSH là một phiên, `client_handle` đặt `session_id` (`uuid4().hex`) vào `conn` nên mọi sự kiện của kết nối đều có. HTTP dùng cookie `wordpress_sess` do `web_honeypot` cấp; cookie sai định dạng thì cấp id mới, client không giữ cookie thì mỗi request là một phiên. `ssh.bruteforce` chỉ gắn với phiên chạm ngưỡng.
- Giới hạn tài nguyên (PLAN-006, tất cả qua `HONEYPY_*`, 0 = tắt): SSH dùng `ConnectionLimiter` (`SSH_MAX_CONNECTIONS` 100 tổng, `SSH_MAX_CONNECTIONS_PER_IP` 20) trong `accept_connection`, kết nối thừa bị đóng ngay và log WARNING (tối đa 1 dòng/10 giây/IP); `SSH_HANDSHAKE_TIMEOUT` 30 (kex), `SSH_AUTH_TIMEOUT` 90 (tới khi mở channel), `SSH_IDLE_TIMEOUT` 120 và `SSH_SESSION_MAX_SECONDS` 600 trong shell, `SSH_MAX_COMMAND_BYTES` 4096 (vượt thì đóng phiên). HTTP chạy bằng `waitress.serve` (`HTTP_THREADS` 8, `HTTP_MAX_CONNECTIONS` 100, `HTTP_REQUEST_TIMEOUT` = `channel_timeout` 30, `HTTP_MAX_BODY_BYTES` 16 KB, quá thì 413), nên route mới tự được giới hạn. `log_event` cắt trường do attacker chọn (`MAX_FIELD_LEN`, `MAX_EVIDENCE_LEN`, `MAX_IP_LEN`). `dst_ip` của sự kiện HTTP lấy từ header `Host`, vì waitress đặt `SERVER_NAME` theo cấu hình server.
- Chưa làm: route catch-all ghi mọi request HTTP (nên đặt header `Server:` qua `ident` của waitress khi làm), shell giả sâu hơn.
- Chuyển hướng IP đáng ngờ sang honeypot do process `nids.redirector` làm, honeypot không đổi gì: xem `redirector.md`.
