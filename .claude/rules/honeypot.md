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
- Chưa làm: session theo kết nối, route catch-all ghi mọi request HTTP, giới hạn tài nguyên (cap kết nối, timeout idle), shell giả sâu hơn, chuyển hướng traffic đáng ngờ sang honeypot.
