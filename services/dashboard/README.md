# Dashboard

REST API, WebSocket và web console (Dashboard, Logs, Traffic, Rules) bằng FastAPI và HTML/CSS/JavaScript thuần.

## Chạy

```bash
uvicorn nids.api.main:app --host 0.0.0.0 --port 8000      # Swagger tại /docs
```

Đặt `PYTHONPATH` trước khi chạy trực tiếp: `source scripts/env.sh` hoặc `. .\scripts\env.ps1`.

## Đọc và ghi

- **Đọc:** toàn bộ CSDL, Redis (WebSocket), `data/rules/`
- **Ghi:** xoá cảnh báo; `data/rules/state.yaml` và `data/rules/custom.rules` (cần header `X-API-Key` khớp `NIDS_API_KEY`)

Chi tiết: [docs/api-reference.md](../../docs/api-reference.md). Image dashboard chứa cả mã nguồn sensor, vì trang Rules kiểm tra `custom.rules` bằng bộ phân tích rule của sensor.

## Thư mục

- `src/nids/...` mã nguồn
- `tests/` test của service (chạy cùng `pytest` ở gốc repo)
- `Dockerfile`, `requirements.txt` đóng gói riêng, build từ gốc repo

Quy tắc chi tiết cho khu vực này: `.claude/rules/`. Tài liệu: [docs/README.md](../../docs/README.md).
