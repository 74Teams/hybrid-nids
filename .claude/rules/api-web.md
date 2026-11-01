---
paths:
  - "nids/api/**"
  - "tests/api/**"
---

# API và web console (`nids/api/`)

## Process

`nids/api/main.py` là process FastAPI riêng. Khi khởi động, nó chỉ gọi `init_db()` để tạo bảng và thêm cột còn thiếu. DB chỉ lưu cảnh báo và flow log (bảng `events`, `event_payloads`, `flows`), không lưu rule; API chưa có endpoint đọc `flows` (issue #40); API chỉ ghi file trong `rules/` (`state.yaml`, `custom.rules`).

## Endpoint

- `GET /api/alerts` — danh sách; lọc theo `source_type/protocol/src_ip/dst_ip/sid/severity/since/until/q`, phân trang `limit/offset`, tổng ở header `X-Total-Count`. `source_type` là `HONEYPOT` hoặc `RULE_ENGINE`.
- `GET /api/alerts/{id}` (kèm payload), `/api/alerts/export.csv`, `/api/alerts/stats`, `/api/alerts/attackers`.
- `GET /api/alerts/sessions/{session_id}` — tối đa `SESSION_EVENT_LIMIT` (1000) sự kiện đầu tiên của một phiên honeypot, cũ đến mới, không kèm payload; không có phiên thì 404.
- `GET /api/alerts/timeline?minutes&buckets` — số cảnh báo NIDS/honeypot theo cột thời gian.
- `WS /api/alerts/ws` — gửi id mỗi cảnh báo mới (tin lấy từ Redis kênh `nids:alerts`); trình duyệt chỉ coi đó là tín hiệu rồi tải lại qua REST. Mỗi kết nối giữ một subscriber riêng, tối đa `MAX_WS_CLIENTS` (20). Redis tắt, lỗi hoặc hết chỗ thì đóng với code 1013 trước khi accept; subscribe phải xong trước `accept()` để không lỡ cảnh báo. Endpoint không xác thực, nhưng chỉ lộ id, không lộ thêm dữ liệu so với `GET /api/alerts`.
- `DELETE /api/alerts/` (cùng bộ lọc; không lọc = xoá hết), `DELETE /api/alerts/{id}`.
- `/api/rules/` — danh sách rule kèm category và trạng thái bật/tắt; `categories`, `sids`, `sids/reset`, `categories/{name}/all`, `custom` để bật/tắt category, override SID và sửa `custom.rules`.
- `/health`.

Thời gian: API trả ISO 8601 UTC kèm `Z` (`2026-10-31T14:00:00Z`, hàm `iso_utc`). `since`/`until` nhận giờ có múi (`+07:00`, `Z`) và được đổi về UTC; giờ không kèm múi coi là UTC. Trang web đổi sang giờ máy người xem bằng `new Date(iso)`; ô `datetime-local` ở bộ lọc phải đổi sang `toISOString()` trước khi gửi. Test múi giờ nằm ở `tests/api/test_timezone_utc.py`.

Thao tác ghi rule cần header `X-API-Key` khớp biến môi trường `NIDS_API_KEY`; chưa đặt biến thì thao tác ghi bị khoá. Không được nới điều kiện này.

## Web UI

- Giao diện kiểu shadcn/ui (token màu zinc, bo góc 0.5rem, card viền mảnh, tab dạng pill, button/input/badge/alert/dialog) viết bằng CSS thuần trong `nids/api/static/`, CSS chung `style.css` mount tại `/static`. Không dùng thư viện frontend hay font ngoài (lab chạy offline); đổi màu thì sửa biến ở `:root`, riêng biểu đồ SVG có hằng màu ở đầu `charts.js` cần đổi theo.
- Dashboard tại `/`; Status › System Logs (`logs.html`) tại `/logs`; Services › Rules (`rules.html`) tại `/rules` kiểu Suricata trên pfSense: tab Categories, dropdown category, panel SID overrides (Apply / Reset All / Reset Current / Disable All / Enable All), ô sửa `custom.rules`.
- Chỉ có giao diện sáng.
- `static/live.js` (`liveAlerts(load, pollMs, onMode)`) dùng chung cho dashboard và trang Logs (ô "Tự làm mới" mặc định bật, bỏ chọn thì ngắt WebSocket): nhận tín hiệu WebSocket rồi gọi `load` (gộp tối đa 2 lần/giây), vẫn tải lại mỗi 30 giây khi live (timeline trượt theo giờ, tab khác xoá cảnh báo không phát tín hiệu), mất WebSocket thì poll `pollMs` và nối lại với backoff 5–60 giây. Dashboard hiện "cập nhật tức thì" hay "tự làm mới mỗi 2 giây" theo chế độ.
- Biểu đồ dashboard là SVG thuần trong `static/charts.js` (cột chồng theo thời gian, thanh chồng theo IP; xanh = NIDS, cam = honeypot). Không thêm thư viện frontend ngoài.
