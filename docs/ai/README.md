# Phần AI của Hybrid NIDS

Bộ tài liệu này mô tả kế hoạch xây dựng tầng phát hiện bất thường bằng học máy (`AITrafficWorker`) cho Hybrid NIDS. Tài liệu đi lần lượt từ bối cảnh, lý thuyết, kiến trúc, dữ liệu cho tới lộ trình và tiêu chí nghiệm thu.

## Tóm tắt

- **Vấn đề:** rule engine kiểu Snort 3 đã chạy ổn nhưng chỉ bắt được những gì có chữ ký. Các dạng tấn công dựa trên hành vi (scan chậm, flood không có payload đặc trưng, brute force có payload hợp lệ) hoặc biến thể mới thì rule thường bỏ sót.
- **Hướng giải quyết:** gom gói tin thành **flow hai chiều**, tính **đặc trưng thống kê** cho từng flow rồi đưa qua hai mô hình:
  - **Random Forest** (có giám sát) để gán nhãn cho các loại tấn công đã biết: PortScan, DoS, BruteForce, WebAttack.
  - **IsolationForest** (không giám sát, chỉ học trên traffic bình thường) để báo những flow "lạ" mà RF vẫn xếp vào benign.
- **Tích hợp:** `AITrafficWorker.analyze_packet` vốn đã được gọi trong worker thread của engine. Cảnh báo AI đi qua đúng callback `handle_alert` → `EventRepository.save_alert` giống cảnh báo rule, với `source_type="AI_ENGINE"` và `sid=None`.
- **Kết quả cần đạt:** RF có macro F1 ≥ 0.95 và FPR ≤ 1% trên tập test; trong lab Docker bắt được mọi nhóm tấn công dạng flow, và ít nhất một trường hợp AI bắt được mà rule bỏ sót; bật AI không làm tăng số gói bị drop.

## Mục lục

| File | Nội dung |
|------|----------|
| [01-boi-canh.md](01-boi-canh.md) | Hiện trạng hệ thống, giới hạn của rule chữ ký, vai trò và ràng buộc của tầng AI |
| [02-ly-thuyet.md](02-ly-thuyet.md) | IDS chữ ký và IDS bất thường, flow, đặc trưng, Random Forest, IsolationForest, độ đo đánh giá |
| [03-kien-truc.md](03-kien-truc.md) | Luồng dữ liệu, các module dự kiến, logic quyết định, hợp đồng `alert_data`, cấu hình, hiệu năng |
| [04-du-lieu-va-huan-luyen.md](04-du-lieu-va-huan-luyen.md) | Dataset, gán nhãn, tập đặc trưng, quy trình huấn luyện và xuất mô hình |
| [05-lo-trinh-va-ket-qua.md](05-lo-trinh-va-ket-qua.md) | Các giai đoạn, tiêu chí nghiệm thu đo được, rủi ro và cách giảm |

## Issue liên quan

- [#22 Trích xuất đặc trưng theo flow cho AI worker](https://github.com/74Teams/intrusion-detection-system/issues/22): giai đoạn 1.
- [#23 Huấn luyện mô hình phát hiện bất thường và cài vào AITrafficWorker](https://github.com/74Teams/intrusion-detection-system/issues/23): giai đoạn 2 và 3.
