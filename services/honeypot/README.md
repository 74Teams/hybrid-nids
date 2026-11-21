# Honeypot

Honeypot SSH (shell giả, nhận mọi mật khẩu) và HTTP (trang đăng nhập WordPress giả). Chỉ ghi lại hành vi của attacker, không bao giờ thực thi input.

## Chạy

```bash
python -m nids.honeypot ssh      # cổng 2222
python -m nids.honeypot http     # cổng 8080
```

Đặt `PYTHONPATH` trước khi chạy trực tiếp: `source scripts/env.sh` hoặc `. .\scripts\env.ps1`.

## Đọc và ghi

- **Đọc:** kết nối của attacker
- **Ghi:** bảng `events` với `source_type=HONEYPOT`; khoá SSH host ở `data/work/server.key`

Chi tiết: [docs/honeypot-and-redirect.md](../../docs/honeypot-and-redirect.md).

## Thư mục

- `src/nids/...` mã nguồn
- `tests/` test của service (chạy cùng `pytest` ở gốc repo)
- `Dockerfile`, `requirements.txt` đóng gói riêng, build từ gốc repo

Quy tắc chi tiết cho khu vực này: `.claude/rules/`. Tài liệu: [docs/README.md](../../docs/README.md).
