---
paths:
  - "nids/api/**"
  - "tests/api/**"
---

# API và web console (`nids/api/`)

## Process

`nids/api/main.py` là process FastAPI riêng. Khi khởi động, nó chỉ gọi `init_db()` để tạo bảng và thêm cột còn thiếu. DB chỉ lưu cảnh báo và flow log (bảng `events`, `event_payloads`, `flows`), không lưu rule; API chưa có endpoint đọc `flows` (issue #40); API chỉ ghi file trong `rules/` (`state.yaml`, `custom.rules`).

## Endpoint

- `GET /api/alerts` — danh sách; lọc theo `source_type/protocol/src_ip/dst_ip/sid/severity/since/until/q`, phân trang `limit/offset`, tổng ở header `X-Total-Count`. `source_type` là `HONEYPOT` hoặc `RULE_ENGINE`. `by_session=true` (trang Logs dùng) gom sự kiện cùng `session_id` thành một dòng kèm `event_count`, `last_timestamp`, `severity` nặng nhất, sắp theo hoạt động mới nhất; sự kiện không có phiên vẫn một dòng riêng, `X-Total-Count` là số dòng sau khi gom. Dashboard, CSV và `DELETE` không dùng tham số này.
- `GET /api/alerts/{id}` (kèm payload), `/api/alerts/export.csv`, `/api/alerts/stats`, `/api/alerts/attackers`.
- `GET /api/alerts/sessions/{session_id}` — tối đa `SESSION_EVENT_LIMIT` (1000) sự kiện đầu tiên của một phiên honeypot, cũ đến mới, không kèm payload; không có phiên thì 404.
- `GET /api/alerts/sessions/{session_id}/raw` — `text/plain`, mỗi sự kiện một dòng (giờ, loại, nguồn → đích, `matched_content` đầy đủ gồm HASSH và công cụ). `\`, xuống dòng trong nội dung được escape để attacker không giả được dòng log.
- `GET /api/alerts/timeline?minutes&buckets` — số cảnh báo NIDS/honeypot theo cột thời gian.
- `WS /api/alerts/ws` — gửi id mỗi cảnh báo mới (tin lấy từ Redis kênh `nids:alerts`); trình duyệt chỉ coi đó là tín hiệu rồi tải lại qua REST. Mỗi kết nối giữ một subscriber riêng, tối đa `MAX_WS_CLIENTS` (20). Redis tắt, lỗi hoặc hết chỗ thì đóng với code 1013 trước khi accept; subscribe phải xong trước `accept()` để không lỡ cảnh báo. Endpoint không xác thực, nhưng chỉ lộ id, không lộ thêm dữ liệu so với `GET /api/alerts`.
- `DELETE /api/alerts/` (cùng bộ lọc; không lọc = xoá hết), `DELETE /api/alerts/{id}`.
- `/api/rules/` — danh sách rule kèm category và trạng thái bật/tắt; `categories`, `sids`, `sids/reset`, `categories/{name}/all`, `custom` để bật/tắt category, override SID và sửa `custom.rules`.
- `/health`.

Thời gian: API trả ISO 8601 UTC kèm `Z` (`2026-10-31T14:00:00Z`, hàm `iso_utc`). `since`/`until` nhận giờ có múi (`+07:00`, `Z`) và được đổi về UTC; giờ không kèm múi coi là UTC. Trang web đổi sang giờ máy người xem bằng `new Date(iso)`; ô `datetime-local` ở bộ lọc phải đổi sang `toISOString()` trước khi gửi. Test múi giờ nằm ở `tests/api/test_timezone_utc.py`.

Thao tác ghi rule cần header `X-API-Key` khớp biến môi trường `NIDS_API_KEY`; chưa đặt biến thì thao tác ghi bị khoá. Không được nới điều kiện này.

## Web UI

- Giao diện kiểu shadcn/ui (token màu zinc, bo góc 0.5rem, card viền mảnh, tab dạng pill, button/input/badge/alert/dialog) viết bằng CSS thuần trong `nids/api/static/`, CSS chung `style.css` mount tại `/static`. Không dùng thư viện frontend hay font ngoài (lab chạy offline); quy tắc chi tiết (token, ánh xạ component, truy cập, cache) nằm ở `web-design.md`.
- Dashboard tại `/`; Status › System Logs (`logs.html`) tại `/logs`; Services › Rules (`rules.html`) tại `/rules` kiểu Suricata trên pfSense: tab Categories, dropdown category, panel SID overrides (Apply / Reset All / Reset Current / Disable All / Enable All), ô sửa `custom.rules`.
- Chỉ có giao diện sáng.
- Trang HTML và file tĩnh trả `Cache-Control: no-cache` (trình duyệt hỏi lại bằng ETag) nên sửa CSS/JS có hiệu lực ngay.
- Trang Logs: mỗi phiên honeypot là một dòng; bấm một dòng mở popup (`<dialog id="detail">`) có đủ các trường (IP, port, protocol, SID...). Dòng phiên có hai tab: Hoạt động (bảng giờ / hành động / nội dung, 20 dòng mỗi trang) và Raw log. `shortSummary` bỏ tiền tố `HONEYPOT <loại> [<công cụ>]` khi hiển thị, `KIND_LABELS` đổi loại kỹ thuật sang tiếng Việt. `openKey`/`openAlert` nằm ngoài `renderRows` để tự làm mới vẫn cập nhật popup đang mở.
- `static/live.js` (`liveAlerts(load, pollMs, onMode)`) dùng chung cho dashboard và trang Logs (ô "Tự làm mới" mặc định bật, bỏ chọn thì ngắt WebSocket): nhận tín hiệu WebSocket rồi gọi `load` (gộp tối đa 2 lần/giây), vẫn tải lại mỗi 30 giây khi live (timeline trượt theo giờ, tab khác xoá cảnh báo không phát tín hiệu), mất WebSocket thì poll `pollMs` và nối lại với backoff 5–60 giây. Dashboard hiện "cập nhật tức thì" hay "tự làm mới mỗi 2 giây" theo chế độ.
- Biểu đồ dashboard là SVG thuần trong `static/charts.js` (cột chồng theo thời gian, thanh chồng theo IP; xanh = NIDS, cam = honeypot). Không thêm thư viện frontend ngoài.
