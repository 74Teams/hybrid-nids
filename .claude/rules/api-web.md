---
paths:
  - "nids/api/**"
  - "tests/api/**"
---

# API và web console (`nids/api/`)

## Process

`nids/api/main.py` là process FastAPI riêng. Khi khởi động, nó chỉ tạo bảng. DB chỉ lưu cảnh báo và flow log (bảng `events`, `event_payloads`, `flows`), không lưu rule; API chưa có endpoint đọc `flows` (issue #40); API chỉ ghi file trong `rules/` (`state.yaml`, `custom.rules`).

## Endpoint

- `GET /api/alerts` — danh sách; lọc theo `source_type/protocol/src_ip/dst_ip/sid/severity/since/until/q`, phân trang `limit/offset`, tổng ở header `X-Total-Count`. `source_type` là `HONEYPOT` hoặc `RULE_ENGINE`.
- `GET /api/alerts/{id}` (kèm payload), `/api/alerts/export.csv`, `/api/alerts/stats`, `/api/alerts/attackers`.
- `GET /api/alerts/timeline?minutes&buckets` — số cảnh báo NIDS/honeypot theo cột thời gian.
- `DELETE /api/alerts/` (cùng bộ lọc; không lọc = xoá hết), `DELETE /api/alerts/{id}`.
- `/api/rules/` — danh sách rule kèm category và trạng thái bật/tắt; `categories`, `sids`, `sids/reset`, `categories/{name}/all`, `custom` để bật/tắt category, override SID và sửa `custom.rules`.
- `/health`.

Thời gian: API trả ISO 8601 UTC kèm `Z` (`2026-10-31T14:00:00Z`, hàm `iso_utc`). `since`/`until` nhận giờ có múi (`+07:00`, `Z`) và được đổi về UTC; giờ không kèm múi coi là UTC. Trang web đổi sang giờ máy người xem bằng `new Date(iso)`; ô `datetime-local` ở bộ lọc phải đổi sang `toISOString()` trước khi gửi. Test múi giờ nằm ở `tests/api/test_timezone_utc.py`.

Thao tác ghi rule cần header `X-API-Key` khớp biến môi trường `NIDS_API_KEY`; chưa đặt biến thì thao tác ghi bị khoá. Không được nới điều kiện này.

## Web UI

- Giao diện kiểu pfSense trong `nids/api/static/`, CSS chung `style.css` mount tại `/static`.
- Dashboard tại `/`; Status › System Logs (`logs.html`) tại `/logs`; Services › Rules (`rules.html`) tại `/rules` kiểu Suricata trên pfSense: tab Categories, dropdown category, panel SID overrides (Apply / Reset All / Reset Current / Disable All / Enable All), ô sửa `custom.rules`.
- Chỉ có giao diện sáng, bám phong cách pfSense.
- Biểu đồ dashboard là SVG thuần trong `static/charts.js` (cột chồng theo thời gian, thanh chồng theo IP; xanh = NIDS, cam = honeypot). Không thêm thư viện frontend ngoài.
