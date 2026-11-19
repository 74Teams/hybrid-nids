# Tài liệu Hybrid NIDS

Hybrid NIDS là hệ thống phát hiện xâm nhập mạng (đồ án PBL4) kết hợp ba lớp phát hiện:

- **rule** cú pháp Snort 3;
- **ngưỡng bất thường** theo cửa sổ thời gian;
- **mô hình học máy** theo flow.

Hệ thống có thêm honeypot SSH/HTTP để xác nhận kẻ tấn công và một web console để theo dõi.

## Mục lục

| Tài liệu | Nội dung |
|---|---|
| [quick-start-guide.md](quick-start-guide.md) | Cài đặt và chạy: Docker lab, chạy trực tiếp trên Windows/Linux, cấu hình, lỗi thường gặp |
| [system-architecture.md](system-architecture.md) | Các process, luồng dữ liệu, cơ sở dữ liệu, Redis, mạng Docker |
| [technology-stack.md](technology-stack.md) | Công nghệ dùng ở từng tầng và lý do chọn |
| [detection-engine.md](detection-engine.md) | Engine phát hiện: pipeline, rule Snort 3, phễu so khớp, tái hợp TCP, flow, phát hiện bất thường, bộ rule |
| [honeypot-and-redirect.md](honeypot-and-redirect.md) | Honeypot SSH/HTTP, làm giàu cảnh báo, chuyển hướng IP đáng ngờ sang honeypot |
| [machine-learning-guide.md](machine-learning-guide.md) | Mô hình AI theo flow: lý thuyết, đặc trưng, dữ liệu, huấn luyện, kết quả, cách chạy |
| [performance-metrics.md](performance-metrics.md) | Bộ đo có nhãn CIC-IDS2017, cách đọc số liệu, kết quả của rule, engine và AI |
| [api-reference.md](api-reference.md) | REST API và WebSocket của dashboard |
| [demo-flow-explanation.md](demo-flow-explanation.md) | Kịch bản demo từng bước, bảng lệnh tấn công thủ công, câu hỏi thường gặp |
| [eval/](eval/) | Báo cáo đo do `tools.eval` sinh ra (không sửa tay) |

## Đọc theo mục đích

- **Chạy thử lần đầu:** quick-start-guide → demo-flow-explanation.
- **Hiểu hệ thống để thuyết trình:** system-architecture → detection-engine → honeypot-and-redirect → machine-learning-guide.
- **Đánh giá chất lượng:** performance-metrics.
- **Phát triển:** `CLAUDE.md` và `.claude/rules/` ở gốc repo có quy tắc chi tiết cho từng khu vực code.

## Trạng thái hiện tại

| Thành phần | Trạng thái |
|---|---|
| Rule engine Snort 3, tái hợp TCP, flow log | Hoàn chỉnh |
| Phát hiện bất thường theo ngưỡng (`ANOMALY`) | Hoàn chỉnh |
| Honeypot SSH/HTTP, làm giàu cảnh báo, chuyển hướng iptables | Hoàn chỉnh |
| Dashboard, cảnh báo realtime qua Redis + WebSocket | Hoàn chỉnh |
| Bộ đo có nhãn CIC-IDS2017 | Hoàn chỉnh |
| Mô hình AI theo flow (Random Forest) | Đã huấn luyện và đánh giá. **Chưa gắn vào engine** (`AITrafficWorker` vẫn là stub) |
