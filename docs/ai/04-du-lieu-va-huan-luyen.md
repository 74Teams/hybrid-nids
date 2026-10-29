# 4. Dữ liệu và huấn luyện

## 4.1 Nguồn dữ liệu

| Nguồn | Vai trò | Ghi chú |
|-------|---------|---------|
| **CIC-IDS2017** (Canadian Institute for Cybersecurity) | Nguồn chính để học các loại tấn công | Dùng **file pcap gốc** chứ không dùng CSV có sẵn, để trích đặc trưng bằng chính `extract_features` của dự án. Các ngày cần lấy: Tuesday (FTP/SSH brute force), Wednesday (DoS), Thursday (Web Attack), Friday (PortScan, DDoS). Monday chỉ có benign |
| **Lab Docker của dự án** | Giảm domain shift, kiểm thử demo | Chạy `lab/attacker/attack_demo.py` và bắt pcap trên `victim_app`; traffic bình thường lấy từ việc duyệt victim và gọi API |
| CSV CICFlowMeter của CIC-IDS2017 | Chỉ dùng để đối chiếu | Dùng để so sánh nhanh kết quả với các bài báo, **không** dùng để huấn luyện mô hình đưa vào chạy |

## 4.2 Gán nhãn

- **CIC-IDS2017:** gán nhãn theo IP attacker/victim và khung giờ tấn công mà dataset công bố cho từng ngày. Bảng khung giờ được viết vào `tools/ai/build_dataset.py` dưới dạng hằng số, có ghi nguồn. Theo Engelen và cộng sự (2021), nhãn gốc có lỗi, nên ưu tiên gán lại theo IP và thời gian thay vì dùng cột nhãn trong CSV.
- **Lab:** flow có IP nguồn là container attacker trong khoảng thời gian chạy một nhóm đòn thì nhận nhãn của nhóm đó; các flow còn lại là `BENIGN`. Script ghi lại thời điểm bắt đầu và kết thúc của từng nhóm đòn để gán nhãn tự động.
- **Gộp lớp** thành 5 lớp ổn định: `BENIGN`, `PortScan`, `DoS` (gồm DDoS, Hulk, GoldenEye, slowloris, SYN flood), `BruteForce` (SSH, FTP, HTTP login), `WebAttack` (SQLi, XSS, traversal; lớp này rule engine đã bắt tốt, đưa vào để so sánh).
- Bỏ các lớp quá hiếm như Heartbleed và Infiltration: quá ít mẫu để học.

## 4.3 Tập đặc trưng

Chỉ dùng các đặc trưng **tính được từ `DecodedPacket` hiện có** (`timestamp`, IP, port, protocol, `tcp_flags`, `raw_payload`, `raw_packet`). Tập dự kiến có khoảng 30 đặc trưng:

- `flow_duration`, `protocol`, `dst_port` (để dạng số; RF tự học các cổng đặc biệt)
- `fwd_packets`, `bwd_packets`, `fwd_bytes`, `bwd_bytes`
- `fwd_len_{min,max,mean,std}`, `bwd_len_{min,max,mean,std}` (độ dài `raw_packet`)
- `flow_iat_{mean,std,min,max}`, `fwd_iat_mean`, `bwd_iat_mean`
- `flow_packets_per_s`, `flow_bytes_per_s`, `down_up_ratio`
- `syn_count`, `ack_count`, `fin_count`, `rst_count`, `psh_count`, `urg_count`
- `fwd_payload_bytes`, `bwd_payload_bytes` (độ dài `raw_payload`)

Bỏ `src_ip`, `dst_ip` và timestamp tuyệt đối để mô hình không học thuộc địa chỉ của dataset. Danh sách cuối cùng được chốt khi làm giai đoạn 1 và chỉ được định nghĩa ở một chỗ duy nhất là `FEATURE_NAMES`.

## 4.4 Quy trình huấn luyện (`tools/ai/train.py`)

1. **Dựng dataset:** `build_dataset.py` đọc pcap bằng Scapy (`PcapReader`, đọc dạng stream để không tốn RAM), đưa từng gói qua `PacketDecoder.decode` → `FlowTable` → `extract_features`, rồi gắn nhãn và ghi ra parquet hoặc CSV.
2. **Làm sạch:** loại `inf`/`NaN` (chia cho 0 khi duration = 0), loại flow trùng lặp.
3. **Chia dữ liệu:**
   - Tập train/validation/test theo tỉ lệ 60/20/20, **phân tầng theo nhãn**.
   - Thêm một **tập test riêng** chỉ gồm dữ liệu lab. Mô hình không thấy tập này lúc train; dùng để đo domain shift.
4. **Random Forest:** `RandomForestClassifier(n_estimators=100, max_depth=20, class_weight="balanced", n_jobs=-1, random_state=42)`. Chỉ tinh chỉnh nhẹ `max_depth` và `min_samples_leaf` trên tập validation.
5. **IsolationForest:** `IsolationForest(n_estimators=100, random_state=42)` chỉ fit trên flow `BENIGN` của tập train. Chọn `if_threshold` trên tập validation sao cho FPR trên benign ≤ 1%.
6. **Chọn `rf_threshold`:** chọn trên tập validation theo mục tiêu FPR ≤ 1%, nhưng recall không được tụt quá 2% so với ngưỡng 0.5.
7. **Đánh giá trên tập test:** precision, recall và F1 theo từng lớp, macro F1, FPR, confusion matrix, top 15 feature importance. Lặp lại trên tập test lab.
8. **Xuất kết quả:**
   - `models/flow_model.joblib` theo đúng cấu trúc ở mục 3.2, có `version` (ngày cộng hash ngắn của dataset).
   - `docs/ai/ket-qua-danh-gia.md` chứa bảng số liệu và hình (confusion matrix, feature importance) để đưa vào báo cáo đồ án.

## 4.5 Thử nghiệm so sánh (tuỳ chọn)

Nếu còn thời gian thì chạy thêm các thử nghiệm sau, để trình bày phần lựa chọn mô hình trong báo cáo:

- XGBoost so với RF, trên cùng tập đặc trưng.
- RF chỉ train trên CIC-IDS2017 so với RF train trên CIC-IDS2017 cộng dữ liệu lab, cả hai đánh giá trên tập test lab. Thử nghiệm này đo trực tiếp tác động của domain shift.

## 4.6 Quản lý file

- File pcap và dataset trung gian rất lớn (hàng GB), nên không commit. Lưu ở ngoài repo hoặc trong `data/` (đã gitignore), và ghi rõ cách tải trong README của `tools/ai/`.
- File mô hình chỉ vài MB đến vài chục MB. Nếu dưới 50 MB thì có thể commit để demo chạy được ngay. Nếu lớn hơn thì đưa lên GitHub Release và ghi lệnh tải.
- `random_state` được cố định ở mọi bước để huấn luyện lại vẫn ra cùng kết quả.
