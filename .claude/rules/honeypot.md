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
- Chưa làm: session theo kết nối, HASSH, route catch-all ghi mọi request HTTP, giới hạn tài nguyên (cap kết nối, timeout idle), shell giả sâu hơn, chuyển hướng traffic đáng ngờ sang honeypot.
