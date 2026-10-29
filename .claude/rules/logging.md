---
paths:
  - "nids/**/*.py"
  - "lab/**/*.py"
---

# Logging

- Cấu hình ở `nids/logger.py` (`setup_logging`, `ColorFormatter`), gọi một lần ở mỗi process: `nids/engine/main.py`, `nids/api/main.py`, `nids/honeypot/__main__.py`.
- Mức độ lấy từ `system.log_level` trong `settings.yaml` (mặc định `INFO`, `DEBUG` để xem chi tiết). Màu tự tắt khi đầu ra không phải terminal hoặc có biến môi trường `NO_COLOR`.
- Mỗi module dùng `logging.getLogger("nids.<khu vực>")`, không dùng `print`. Khu vực: `engine` (`engine/main.py`, `engine/detector.py`), `alert` (dòng cảnh báo trong `engine/main.py`), `rules` (`engine/rule_manager.py`), `db`, `capture`, `api`, `honeypot`, `attack` (`lab/attacker/attack_demo.py`).
- Cảnh báo mang `extra={"priority": n}` để formatter tô màu theo priority (P1 đỏ, P2 vàng, P3 xanh dương).
- Nội dung log viết tiếng Việt có dấu.
