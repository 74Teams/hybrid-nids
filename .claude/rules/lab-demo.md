---
paths:
  - "lab/**"
  - "tests/lab/**"
  - "docs/demo/**"
  - "rules/**/*.rules"
---

# Docker lab và kịch bản demo

- `lab/attacker/attack_demo.py` là kịch bản tấn công demo, chạy trong container attacker. Mỗi đòn khai báo SID kỳ vọng.
- `tests/lab/test_attack_demo.py` kiểm tra đòn nào cũng trúng đúng rule và rule nào cũng có đòn trình diễn: thêm rule mới thì phải thêm đòn.
- Nhóm `honeypot` dùng `CommandAttack` (hydra) và `HttpAttack` vào 2222/8080, không có SID kỳ vọng.
- `lab/victim/` là nginx victim; engine và honeypot dùng chung network namespace với nó.
- Kịch bản thuyết trình ở `docs/demo/kich-ban-demo.md`. Đổi đòn hoặc rule thì cập nhật kịch bản cho khớp.
