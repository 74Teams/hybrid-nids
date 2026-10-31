# 5. Lộ trình và kết quả cần đạt

## 5.1 Các giai đoạn

### Giai đoạn 1: Flow và đặc trưng ([#22](https://github.com/74Teams/intrusion-detection-system/issues/22))

- Tạo package `nids/ai/` gồm `features.py` (`FEATURE_NAMES`, `extract_features`). Phần gom flow đã có sẵn ở `nids/engine/flow.py` (`Flow`, `FlowTracker`, issue #39), dùng lại và bổ sung bộ đếm nếu cần.
- `AITrafficWorker` gom flow và log ở mức DEBUG khi một flow đóng; chưa có mô hình.
- Test trong `tests/ai/`, tự dựng `DecodedPacket` giống cách làm trong `tests/engine/`:
  - TCP handshake cộng FIN đóng đúng một flow, đếm đúng gói và byte theo cả hai chiều;
  - gói chiều ngược rơi vào cùng flow;
  - idle timeout và active timeout tính theo `packet.timestamp`;
  - một flow dựng sẵn có duration, rate và IAT biết trước cho ra đúng giá trị đặc trưng;
  - `max_flows` không bị vượt.

**Hoàn thành khi:** `pytest tests/ai` pass; replay pcap demo với AI bật không tăng số gói bị drop.

### Giai đoạn 2: Dữ liệu và huấn luyện

- `tools/ai/build_dataset.py` và `tools/ai/train.py` theo [04-du-lieu-va-huan-luyen.md](04-du-lieu-va-huan-luyen.md).
- Bắt pcap trong lab Docker, có ghi mốc thời gian của từng nhóm đòn.
- Viết báo cáo `docs/ai/ket-qua-danh-gia.md`.

**Hoàn thành khi:** có `models/flow_model.joblib` và báo cáo số liệu đạt tiêu chí ở mục 5.2.

### Giai đoạn 3: Tích hợp vào engine ([#23](https://github.com/74Teams/intrusion-detection-system/issues/23))

- `model.py` cộng logic quyết định và gộp cảnh báo trong `worker.py`.
- Thêm mục `ai` vào `settings.yaml`; gọi `ai_worker.flush()` khi đọc hết pcap offline.
- Cảnh báo có `source_type="AI_ENGINE"`. Kiểm tra API `?source_type=AI_ENGINE` và trang Logs hiển thị đúng.
- Thêm test cho worker: dùng một mô hình giả (stub có `predict`) để kiểm tra logic quyết định, nội dung `alert_data` và việc gộp cảnh báo, mà không cần file mô hình thật.

**Hoàn thành khi:** chạy `python -m nids.engine` ở chế độ offline với pcap lab sinh ra cảnh báo AI đúng nhãn và lưu được vào CSDL.

### Giai đoạn 4: Demo và báo cáo

- Bổ sung vào `docs/demo/kich-ban-demo.md` (thay đoạn "AI worker đâu?") một kịch bản mà **rule không bắt nhưng AI bắt**, ví dụ:
  - port scan chậm (`nmap -T2`) nằm dưới ngưỡng `detection_filter`;
  - SYN flood hoặc HTTP flood tới cổng không có rule;
  - brute force SSH vào victim (không qua honeypot).
- Cập nhật `CLAUDE.md`: mô tả `nids/ai/`, khu vực log `ai`, bỏ dòng ghi "AI worker là stub".
- Phần AI trong báo cáo đồ án: lấy nội dung từ thư mục `docs/ai/` này.

## 5.2 Kết quả phải đạt

| # | Tiêu chí | Ngưỡng | Cách đo |
|---|----------|--------|---------|
| 1 | Macro F1 của RF trên tập test CIC-IDS2017 | ≥ 0.95 | `train.py` |
| 2 | FPR (benign bị báo là tấn công) trên tập test | ≤ 1% | `train.py` |
| 3 | Recall từng lớp tấn công trên tập test lab | ≥ 0.90 với PortScan, DoS, BruteForce | `train.py`, tập test lab |
| 4 | Số trường hợp AI bắt được mà rule engine không bắt trong demo | ≥ 1 kịch bản | Chạy demo, so sánh `source_type` trên dashboard |
| 5 | Throughput | Bật AI không làm tăng số gói bị drop khi replay pcap demo; thời gian xử lý tăng ≤ 20% | Log tổng kết của engine (`format_summary`, `DropCounter`) |
| 6 | Độ bền | Thiếu file mô hình hoặc mô hình lỗi thì engine vẫn chạy, chỉ log lỗi | Test |
| 7 | Tái lập | Train lại từ cùng dữ liệu cho ra cùng mô hình (`random_state` cố định) | Chạy `train.py` hai lần |
| 8 | Giải thích được | Báo cáo có confusion matrix, feature importance và các ví dụ flow bị báo | `ket-qua-danh-gia.md` |

Nếu tiêu chí 3 không đạt vì domain shift thì vẫn chấp nhận được, với điều kiện báo cáo nêu rõ số liệu trước và sau khi bổ sung dữ liệu lab. Đây cũng là một kết quả có giá trị để trình bày.

## 5.3 Rủi ro và cách giảm

| Rủi ro | Mức | Cách giảm |
|--------|-----|-----------|
| Domain shift: mô hình học trên CIC-IDS2017 kém khi chạy trong lab | Cao | Dùng chung một extractor cho train và chạy; bổ sung dữ liệu lab; có tập test lab riêng |
| Báo nhầm nhiều, nhất là từ IsolationForest | Trung bình | Chọn ngưỡng theo FPR; cảnh báo IF chỉ ở P3; gộp cảnh báo theo `(src_ip, label)`; bỏ qua flow quá ngắn |
| Python chậm khi bị flood | Trung bình | Chỉ suy luận khi flow đóng; predict theo lô; giới hạn `max_flows`; số cây vừa phải |
| Nhãn CIC-IDS2017 có lỗi | Trung bình | Gán lại nhãn theo IP và khung giờ từ pcap gốc |
| Dataset lớn, xử lý tốn thời gian | Thấp | Chỉ lấy các ngày cần thiết; đọc pcap dạng stream; lưu bảng đặc trưng trung gian để không phải trích lại |
| Thiếu đặc trưng vì `DecodedPacket` không có TTL hay window size | Thấp | Chấp nhận tập con trước. Nếu cần thì thêm field vào `DecodedPacket` một cách có chủ đích (sửa decoder và test) |

## 5.4 Ngoài phạm vi

- Deep learning (LSTM, Autoencoder) và học trực tuyến (online learning).
- Phân tích nội dung traffic mã hoá.
- Tự động chặn IP (IPS): hệ thống chỉ phát hiện và cảnh báo.
- Huấn luyện lại tự động khi đang chạy.
