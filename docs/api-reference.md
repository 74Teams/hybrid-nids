# API

API chạy bằng `uvicorn nids.api.main:app --host 0.0.0.0 --port 8000`. Tài liệu tương tác (OpenAPI) ở `/docs`.

## 1. Trang giao diện

| Trang | URL | Nội dung |
|---|---|---|
| Dashboard | `/` | Tổng cảnh báo theo priority, biểu đồ theo thời gian (15 phút đến 24 giờ), top loại tấn công, top IP, luồng cảnh báo mới |
| System Logs | `/logs` | Tab theo nguồn (NIDS, Anomaly, Honeypot SSH, Honeypot HTTP), bộ lọc nâng cao, popup chi tiết kèm payload, xoá, xuất CSV |
| Traffic | `/traffic` | Bảng flow, tab "Chưa khớp rule", top talker, top cổng, biểu đồ lưu lượng so với cảnh báo |
| Rules | `/rules` | Bật/tắt category và SID, sửa `custom.rules` (theo kiểu trang Suricata của pfSense) |

Dữ liệu tấn công luôn được hiển thị dạng văn bản thuần, nên payload không bao giờ chạy như HTML.

## 2. Quy ước chung

- **Phân trang:** `limit` và `offset`. Tổng số dòng nằm ở header `X-Total-Count`.
- **Thời gian:** trả về ISO 8601 UTC. Tham số `since` và `until` nhận ISO 8601.
- **Ghi rule:** mọi thao tác ghi rule cần header `X-API-Key` khớp biến môi trường `NIDS_API_KEY` của server. Chưa đặt biến này thì mọi thao tác ghi rule bị khoá. Trình duyệt hỏi key một lần.

## 3. Cảnh báo: `/api/alerts`

| Method | Endpoint | Mô tả |
|---|---|---|
| `GET` | `/api/alerts/` | Danh sách cảnh báo. Lọc: `source_type`, `protocol`, `src_ip`, `dst_ip`, `sid`, `severity`, `since`, `until`, `q` (từ khoá). `by_session=true` gộp mỗi phiên honeypot thành một dòng (kèm `event_count`, `last_timestamp`) |
| `GET` | `/api/alerts/{id}` | Chi tiết một cảnh báo, kèm `payload` (`matched_content`, `http_headers`, `http_body`) |
| `DELETE` | `/api/alerts/{id}` | Xoá một cảnh báo |
| `DELETE` | `/api/alerts/` | Xoá mọi cảnh báo khớp bộ lọc; không lọc là xoá hết. Trả `{"deleted": n}` |
| `GET` | `/api/alerts/export.csv` | Xuất các cảnh báo khớp bộ lọc ra CSV |
| `GET` | `/api/alerts/stats` | Tổng theo priority và top loại tấn công |
| `GET` | `/api/alerts/timeline` | Số cảnh báo theo khoảng thời gian, tách NIDS và honeypot |
| `GET` | `/api/alerts/attackers` | Theo từng IP: `honeypot_events`, `nids_alerts`, `first_seen`, `last_seen` |
| `GET` | `/api/alerts/sessions/{session_id}` | Các sự kiện của một phiên honeypot, cũ nhất trước |
| `GET` | `/api/alerts/sessions/{session_id}/raw` | Log thô của một phiên (text, mỗi sự kiện một dòng) |
| `WS` | `/api/alerts/ws` | Đẩy id của mỗi cảnh báo mới (qua Redis), tối đa 20 client |

**WebSocket:**

- Server gửi id dạng text; client tự gọi lại REST để lấy dữ liệu.
- Redis tắt hoặc lỗi thì server đóng socket với mã **1013**. Dashboard chuyển sang poll và kết nối lại có backoff.

Ví dụ:

```bash
curl "http://localhost:8000/api/alerts/?source_type=HONEYPOT&limit=5"
curl "http://localhost:8000/api/alerts/?severity=1&since=2026-11-19T00:00:00Z"
curl -X DELETE http://localhost:8000/api/alerts/          # xoá toàn bộ để demo lại
```

## 4. Flow: `/api/flows`

| Method | Endpoint | Mô tả |
|---|---|---|
| `GET` | `/api/flows/` | Flow mới nhất. Lọc: `src_ip`, `dst_ip`, `protocol`, `dst_port`, `since`, `until` (so với `first_seen`), `matched` (`false` là chỉ flow chưa khớp rule nào). `limit` tối đa 500 |
| `GET` | `/api/flows/stats` | Top talker, top cổng đích, phân bố protocol, byte/flow/cảnh báo theo thời gian. Tham số: `minutes` (1–1440), `buckets` (1–120), `top` (1–50) |

## 5. Chuyển hướng: `/api/redirects`

| Method | Endpoint | Mô tả |
|---|---|---|
| `GET` | `/api/redirects/` | IP đang bị chuyển hướng sang honeypot. `active=false` lấy cả lịch sử |

## 6. Rule: `/api/rules`

| Method | Endpoint | Cần key | Mô tả |
|---|---|---|---|
| `GET` | `/api/rules/` | | Danh sách rule kèm category và trạng thái bật. Lọc: `category`, `enabled`, `q` |
| `GET` | `/api/rules/categories` | | Các file rule và trạng thái nạp |
| `PUT` | `/api/rules/categories` | có | Lưu danh sách file được nạp |
| `POST` | `/api/rules/sids` | có | Bật/tắt SID: `{"enable": [...], "disable": [...]}` |
| `POST` | `/api/rules/sids/reset` | có | Bỏ override SID của một category hoặc tất cả |
| `POST` | `/api/rules/categories/{name}/all` | có | Bật hết hoặc tắt hết rule trong một file |
| `GET` | `/api/rules/custom` | | Đọc `custom.rules` (text) |
| `PUT` | `/api/rules/custom` | có | Thay `custom.rules`; nội dung sai cú pháp bị từ chối kèm số dòng lỗi |

Thay đổi được lưu vào `data/rules/state.yaml` hoặc `data/rules/custom.rules`. Engine đang chạy tự nạp lại trong vài giây.

## 7. Hệ thống

| Method | Endpoint | Mô tả |
|---|---|---|
| `GET` | `/health` | Kiểm tra API còn sống |
