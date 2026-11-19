# Redirector

Chọn IP có nhiều cảnh báo rule P1–P2 trong một cửa sổ thời gian rồi chuyển kết nối mới của IP đó (cổng 22 và 80) sang honeypot bằng iptables `REDIRECT`. Chỉ chạy trong Docker lab (cần `NET_ADMIN`).

## Chạy

```bash
python -m nids.redirector
```

Đặt `PYTHONPATH` trước khi chạy trực tiếp: `source scripts/env.sh` hoặc `. .\scripts\env.ps1`.

## Đọc và ghi

- **Đọc:** bảng `events`
- **Ghi:** bảng `redirects`; chain `NIDS_REDIRECT` trong iptables

Chi tiết: [docs/honeypot-and-redirect.md](../../docs/honeypot-and-redirect.md).

## Thư mục

- `src/nids/...` mã nguồn
- `tests/` test của service (chạy cùng `pytest` ở gốc repo)
- `Dockerfile`, `requirements.txt` đóng gói riêng, build từ gốc repo

Quy tắc chi tiết cho khu vực này: `.claude/rules/`. Tài liệu: [docs/README.md](../../docs/README.md).
