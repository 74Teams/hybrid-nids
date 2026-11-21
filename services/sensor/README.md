# Sensor

Bắt gói mạng (live hoặc đọc pcap), so khớp rule Snort 3, tái hợp luồng TCP, gom flow, phát hiện bất thường theo ngưỡng. Sinh cảnh báo `RULE_ENGINE` và `ANOMALY`. Mô hình AI theo flow (`nids.ai`) đã có đặc trưng và mô hình nhưng chưa được gắn vào pipeline.

## Chạy

```bash
python -m nids.engine                      # theo common/config/settings.yaml
docker compose up --build nids_sensor      # trong lab
```

Đặt `PYTHONPATH` trước khi chạy trực tiếp: `source scripts/env.sh` hoặc `. .\scripts\env.ps1`.

## Đọc và ghi

- **Đọc:** gói mạng, `data/rules/` (tự nạp lại khi file đổi), `data/models/`, bảng `events` (IP đã chạm honeypot)
- **Ghi:** bảng `events` (cảnh báo) và `flows`; id cảnh báo mới lên Redis

Chi tiết: [docs/detection-engine.md](../../docs/detection-engine.md), [docs/machine-learning-guide.md](../../docs/machine-learning-guide.md).

## Thư mục

- `src/nids/...` mã nguồn
- `tests/` test của service (chạy cùng `pytest` ở gốc repo)
- `Dockerfile`, `requirements.txt` đóng gói riêng, build từ gốc repo

Quy tắc chi tiết cho khu vực này: `.claude/rules/`. Tài liệu: [docs/README.md](../../docs/README.md).
