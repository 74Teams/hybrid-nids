# 2. Cơ sở lý thuyết

## 2.1 Phân loại IDS

| Tiêu chí | Loại | Mô tả |
|----------|------|-------|
| Vị trí | **NIDS** | Quan sát traffic mạng (dự án này) |
| | HIDS | Quan sát log và tiến trình trên một máy |
| Phương pháp | **Signature-based** (misuse) | So khớp mẫu đã biết. Chính xác, ít báo nhầm, nhưng mù với tấn công mới. Ví dụ: Snort, Suricata, rule engine của dự án |
| | **Anomaly-based** | Học "bình thường" rồi báo những gì lệch khỏi nó. Bắt được tấn công mới, nhưng dễ báo nhầm |
| | **Hybrid** | Kết hợp cả hai: hướng của dự án |

Phát hiện dựa trên học máy chia làm hai nhánh:

- **Có giám sát (supervised):** học từ dữ liệu đã gán nhãn (benign / loại tấn công). Đạt độ chính xác cao trên những loại đã thấy, nhưng không tổng quát hoá được sang loại chưa thấy.
- **Không giám sát / bán giám sát (unsupervised / one-class):** chỉ học trên traffic bình thường và coi mọi thứ lệch khỏi phân phối đó là bất thường.

Dự án dùng **cả hai** (mục 2.4 và 2.5) để bù cho nhau.

## 2.2 Flow

**Flow** (luồng) là tập các gói cùng thuộc một cuộc hội thoại, được xác định bằng **5-tuple**:

```
(src_ip, src_port, dst_ip, dst_port, protocol)
```

- **Flow hai chiều (bidirectional):** gói A→B và B→A thuộc cùng một flow. Chiều **forward** (fwd) là chiều của gói đầu tiên, tức là bên khởi tạo; chiều ngược lại là **backward** (bwd). Để tra cứu được cả hai chiều, khoá được chuẩn hoá bằng cách sắp xếp hai đầu mút.
- **Kết thúc flow** khi gặp một trong các điều kiện sau:
  - TCP gặp cờ `FIN` (ở cả hai chiều) hoặc `RST`;
  - **idle timeout:** quá lâu không có gói mới (ví dụ 15–60 giây);
  - **active timeout:** flow kéo dài quá lâu (ví dụ 120 giây) thì bị cắt thành nhiều đoạn, để kết nối dài vẫn được phân tích định kỳ.
- ICMP và UDP không có trạng thái kết nối nên chỉ kết thúc bằng timeout.

## 2.3 Đặc trưng flow

Hướng tiếp cận chuẩn trong nghiên cứu là **CICFlowMeter** (công cụ sinh dataset CIC-IDS2017), với khoảng 80 đặc trưng. Các nhóm chính:

| Nhóm | Ví dụ | Ý nghĩa với tấn công |
|------|-------|----------------------|
| Thời lượng | `flow_duration` | Scan: rất ngắn; slowloris: rất dài |
| Khối lượng | `fwd_packets`, `bwd_packets`, `fwd_bytes`, `bwd_bytes` | Flood: nhiều gói một chiều, gần như không có phản hồi |
| Tốc độ | `flow_packets_per_s`, `flow_bytes_per_s` | DoS: tốc độ rất cao |
| Kích thước gói | min / max / mean / std của độ dài payload theo từng chiều | Brute force: kích thước lặp lại rất đều |
| Khoảng cách giữa các gói (IAT) | mean / std / min / max của inter-arrival time | Công cụ tự động có nhịp đều, std nhỏ |
| Cờ TCP | số gói `SYN`, `ACK`, `FIN`, `RST`, `PSH`, `URG` | SYN scan: có SYN, không có ACK, đầu kia trả RST |
| Tỉ lệ | `down_up_ratio` = bwd/fwd | Scan và flood: tỉ lệ gần 0 |

Tất cả đặc trưng trên đều tính **tăng dần** được (giữ count, sum, sum of squares, min, max), nên không cần lưu lại các gói.

## 2.4 Random Forest

**Random Forest** (Breiman, 2001) là một tập hợp nhiều **cây quyết định**:

- **Bagging:** mỗi cây học trên một mẫu bootstrap (lấy mẫu có hoàn lại) của tập huấn luyện.
- **Random subspace:** tại mỗi nút, cây chỉ xét một tập con ngẫu nhiên của các đặc trưng (thường là √d đặc trưng) để tìm điểm tách.
- **Tiêu chí tách:** Gini impurity `G = 1 − Σ pₖ²`; chọn điểm tách làm giảm G nhiều nhất.
- **Dự đoán:** các cây bỏ phiếu; tỉ lệ phiếu cho mỗi lớp được dùng làm `predict_proba`.
- **Feature importance:** tổng mức giảm Gini mà mỗi đặc trưng đóng góp. Con số này dùng để giải thích mô hình trong báo cáo.

**Lý do chọn RF:**

- Không cần chuẩn hoá đặc trưng, chịu được đặc trưng có thang đo lệch nhau rất xa (byte và giây).
- Ít overfit nhờ lấy trung bình nhiều cây, gần như không phải tinh chỉnh tham số.
- Suy luận nhanh trên CPU, trong scikit-learn có sẵn `class_weight="balanced"`.
- Là baseline mạnh và phổ biến trong các bài báo về CIC-IDS2017, nên dễ so sánh kết quả.

**So với XGBoost:** gradient boosting thường nhỉnh hơn vài phần nghìn F1, đổi lại cần tinh chỉnh nhiều hơn và thêm một dependency. Kế hoạch dùng RF làm mô hình chính; XGBoost chỉ là thử nghiệm so sánh tuỳ chọn trong giai đoạn 2.

## 2.5 IsolationForest

**IsolationForest** (Liu và cộng sự, 2008) phát hiện điểm bất thường theo ý tưởng: *điểm bất thường thì ít và khác biệt, nên cô lập được nhanh hơn.*

- Dựng nhiều cây ngẫu nhiên: mỗi nút chọn ngẫu nhiên một đặc trưng và một ngưỡng nằm trong khoảng [min, max] của đặc trưng đó.
- **Path length** `h(x)` là số nút đi qua để cô lập được điểm `x`. Điểm bất thường có `h(x)` ngắn.
- **Anomaly score** `s(x) = 2^(−E[h(x)] / c(n))`, trong đó `c(n)` là độ dài đường đi trung bình dùng để chuẩn hoá. `s` gần 1 là bất thường; `s` nhỏ hơn 0.5 là bình thường.
- Tham số `contamination` quyết định ngưỡng (tỉ lệ điểm bất thường dự kiến). Dự án sẽ **chọn ngưỡng thủ công** trên tập validation thay vì dựa vào `contamination`.

**Vai trò trong hệ lai:** chỉ fit trên flow benign, rồi báo những flow mà RF xếp vào benign nhưng nằm ngoài phân phối bình thường. Đây là "lưới an toàn" cho các loại tấn công chưa có nhãn.

## 2.6 Độ đo đánh giá

Với dữ liệu IDS, số flow benign thường gấp hàng chục lần số flow tấn công. **Accuracy đánh lừa:** mô hình đoán mọi thứ là benign vẫn đạt accuracy 95%. Vì vậy dự án dùng các độ đo sau:

| Độ đo | Công thức | Ý nghĩa |
|-------|-----------|---------|
| Precision | TP / (TP + FP) | Trong số cảnh báo, bao nhiêu là thật |
| Recall (Detection Rate) | TP / (TP + FN) | Bắt được bao nhiêu phần trăm tấn công |
| F1 | 2·P·R / (P + R) | Cân bằng P và R |
| **Macro F1** | trung bình F1 các lớp | Không để lớp lớn lấn át lớp nhỏ |
| **FPR** | FP / (FP + TN) | Tỉ lệ traffic bình thường bị báo nhầm, là yếu tố quyết định việc vận hành |
| ROC-AUC / PR-AUC | Diện tích dưới đường cong | Dùng để so sánh mô hình độc lập với ngưỡng; PR-AUC hợp hơn khi dữ liệu lệch |
| Confusion matrix | | Nhìn ra lớp nào bị nhầm sang lớp nào |

Một FPR 1% nghe thì nhỏ, nhưng với 100.000 flow/giờ đó là 1.000 cảnh báo nhầm. Vì thế ngưỡng xác suất được chọn theo mục tiêu FPR, không lấy mặc định 0.5.

**Xử lý mất cân bằng dữ liệu:** dùng `class_weight="balanced"`, undersample bớt lớp benign, và chia train/test theo **phân tầng** (stratified).

## 2.7 Domain shift

Mô hình học trên dataset công khai (mạng, công cụ và thời điểm khác) rồi chạy trên mạng khác thường **giảm mạnh độ chính xác**. Các nghiên cứu về CIC-IDS2017 đã ghi nhận hiện tượng này. Có hai nguyên nhân chính:

1. **Lệch đặc trưng:** công cụ trích đặc trưng lúc train (CICFlowMeter, Java) khác với lúc chạy (code Python của dự án): cách cắt flow, cách tính IAT, đơn vị đo.
2. **Lệch phân phối:** traffic bình thường ở mỗi mạng mỗi khác.

Hướng xử lý được trình bày ở [04-du-lieu-va-huan-luyen.md](04-du-lieu-va-huan-luyen.md): **cùng một extractor** dùng cho cả train lẫn chạy thật, và bổ sung dữ liệu tự bắt từ chính lab.

## Tài liệu tham khảo

- L. Breiman, "Random Forests", *Machine Learning*, 2001.
- F. T. Liu, K. M. Ting, Z.-H. Zhou, "Isolation Forest", *ICDM*, 2008.
- I. Sharafaldin, A. H. Lashkari, A. A. Ghorbani, "Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization", *ICISSP*, 2018 (CIC-IDS2017).
- R. Sommer, V. Paxson, "Outside the Closed World: On Using Machine Learning for Network Intrusion Detection", *IEEE S&P*, 2010.
- G. Engelen, V. Rimmer, W. Joosen, "Troubleshooting an Intrusion Detection Dataset: the CICIDS2017 Case Study", *IEEE SPW*, 2021.
