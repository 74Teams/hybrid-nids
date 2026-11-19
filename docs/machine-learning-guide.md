# Mô hình AI theo flow

## 1. Mục đích

Rule Snort bắt tấn công có **nội dung đặc trưng** (chuỗi SQL injection, payload reverse shell). Nhiều loại tấn công không có nội dung nào để so khớp:

| Tấn công | Vì sao rule bỏ sót |
|---|---|
| Quét cổng | Mỗi lần gõ chỉ có hai gói (SYN đi, RST về), giống hệt một kết nối nhầm cổng |
| DoS, DDoS | Gói bình thường, chỉ khác ở số lượng và nhịp độ |
| Botnet | Máy nhiễm gọi về máy chủ điều khiển đều đặn; kết nối ngắn, không có payload |
| Brute force | Mỗi lần đăng nhập đều hợp lệ về cú pháp; bất thường nằm ở số lần thử |

Mô hình AI nhìn **hành vi của cả flow và của cả một IP theo thời gian**, không đọc payload. Hai lớp bổ sung cho nhau:

| Lớp | Lo phần | Cách nhận diện |
|---|---|---|
| Rule Snort | SQLi, XSS, exploit, webshell | Nội dung gói |
| Ngưỡng bất thường | Scan, flood vượt ngưỡng cố định | Đếm theo cửa sổ thời gian |
| AI | PortScan, DoS, DDoS, Bot, BruteForce | 40 đặc trưng flow, kể cả ngữ cảnh nhiều flow |

AI cố ý **không** lo tấn công web: lớp này khác ở nội dung chứ không ở hình dạng lưu lượng. Khi thử, precision chỉ khoảng 0,6.

## 2. Trạng thái

| Phần | Trạng thái |
|---|---|
| Trích đặc trưng (`services/sensor/src/nids/ai/features.py`, `services/sensor/src/nids/ai/context.py`) | Xong, có test |
| Dựng dataset từ pcap CIC-IDS2017 (`common/tools/ai/build_dataset.py`) | Xong |
| Huấn luyện và chấm (`common/tools/ai/train.py`) | Xong; mô hình `data/models/flow_model.joblib` (2,9 MB) |
| Demo ngoài engine (`common/tools/ai/demo_ai.py`) | Xong |
| Gắn vào engine (`AITrafficWorker` sinh cảnh báo `AI_ENGINE`) | **Chưa làm**. `services/sensor/src/nids/ai/worker.py` vẫn là stub |
| Chấm trên tập test (tập thi) | Chưa mở |

## 3. Cơ sở lý thuyết

### 3.1 Flow

Flow là tập gói của một cuộc hội thoại, xác định bằng 5-tuple `(src_ip, src_port, dst_ip, dst_port, protocol)` chuẩn hoá hai chiều.

- Chiều **forward** là chiều của bên khởi tạo, chiều **backward** là chiều ngược lại.
- Flow kết thúc khi TCP đóng (FIN hai chiều hoặc RST), hết idle timeout, hoặc vượt active timeout.
- Engine đã có sẵn `FlowTracker` (`services/sensor/src/nids/engine/flow.py`). AI dùng lại đúng module này, nên đặc trưng lúc học và lúc chạy được tính giống nhau.

### 3.2 Random Forest

Random Forest (Breiman, 2001) gồm nhiều cây quyết định:

- mỗi cây học trên một mẫu bootstrap;
- mỗi nút chỉ xét một tập con ngẫu nhiên các đặc trưng;
- dự đoán bằng cách các cây bỏ phiếu, tỉ lệ phiếu là `predict_proba`.

Lý do chọn:

- dữ liệu dạng bảng;
- không cần chuẩn hoá (byte và giây lệch thang đo rất xa);
- ít overfit;
- nhanh trên CPU;
- có `class_weight="balanced"` cho dữ liệu lệch;
- có feature importance để giải thích.

Học sâu cần nhiều dữ liệu và tài nguyên hơn mà chưa chắc tốt hơn với dữ liệu dạng bảng.

### 3.3 Độ đo

Dữ liệu IDS rất lệch: flow bình thường nhiều gấp hàng chục lần flow tấn công. Một mô hình đoán mọi thứ là bình thường vẫn đạt accuracy 95%, nên không dùng accuracy.

| Độ đo | Công thức | Ý nghĩa |
|---|---|---|
| Recall | TP / (TP + FN) | Bắt được bao nhiêu phần tấn công |
| Precision | TP / (TP + FP) | Trong số cảnh báo, bao nhiêu là thật |
| **FPR** | FP / (FP + TN) | Tỉ lệ traffic bình thường bị báo nhầm. Đây là yếu tố quyết định việc vận hành: FPR 1% trên 100.000 flow/giờ là 1.000 cảnh báo nhầm |
| Macro F1 | Trung bình F1 các lớp | Không để lớp lớn lấn át lớp nhỏ |

### 3.4 Domain shift

Mô hình học trên một mạng rồi chạy trên mạng khác thường kém đi. Hai nguyên nhân chính là công cụ trích đặc trưng khác nhau và phân phối traffic khác nhau. Dự án giảm nguyên nhân thứ nhất bằng cách **dùng chung một hàm `extract_features` cho cả lúc học lẫn lúc chạy**, và trích đặc trưng từ pcap gốc thay vì dùng CSV CICFlowMeter có sẵn.

## 4. Đặc trưng (40 cột)

`FEATURE_NAMES` trong `services/sensor/src/nids/ai/features.py` là nguồn duy nhất của danh sách cột. Mô hình lưu kèm danh sách này và bị từ chối nếu danh sách không khớp. Không dùng IP và giờ tuyệt đối, để mô hình không học thuộc "máy này là xấu".

| Nhóm | Cột |
|---|---|
| Cơ bản | `protocol`, `dst_port`, `flow_duration` |
| Khối lượng | `fwd_packets`, `bwd_packets`, `fwd_bytes`, `bwd_bytes`, `fwd_payload_bytes`, `bwd_payload_bytes` |
| Độ dài gói | `fwd_len_{min,max,mean,std}`, `bwd_len_{min,max,mean,std}` |
| Nhịp gói (IAT) | `flow_iat_{mean,std,min,max}`, `fwd_iat_mean`, `bwd_iat_mean` |
| Tốc độ, tỉ lệ | `flow_packets_per_s`, `flow_bytes_per_s`, `down_up_ratio` |
| Cờ TCP | `syn_count`, `ack_count`, `fin_count`, `rst_count`, `psh_count`, `urg_count` |
| Ngữ cảnh 60 giây | `src_dst_hosts_60s`, `src_short_ratio_60s`, `dst_flows_60s` |
| Ngữ cảnh 5 giây | `src_flows_5s`, `src_dst_ports_5s`, `src_dst_hosts_5s`, `src_port_diversity_5s`, `dst_flows_5s` |

Mọi đặc trưng tính được tăng dần từ bộ đếm của flow, không cần lưu gói. Flow chỉ có một gói (thời lượng 0) ghi tốc độ bằng 0 thay vì vô cực.

### 4.1 Đặc trưng ngữ cảnh

`FlowContext` (`services/sensor/src/nids/ai/context.py`) nhớ các flow vừa kết thúc theo IP nguồn và IP đích, trong hai cửa sổ:

- **60 giây:** IP này đã làm gì trong cả phút qua;
- **5 giây:** tốc độ hiện tại. `src_port_diversity_5s` là số cổng khác nhau chia số flow: gần 1 khi mỗi flow gõ một cổng khác (quét cổng), nhỏ khi nhiều flow cùng tới một cổng (duyệt web).

Hai cột đếm 60 giây theo IP nguồn (`src_flows_60s`, `src_dst_ports_60s`) vẫn được tính nhưng **không đưa vào mô hình**. Chúng chỉ đầy dần sau khoảng 20 giây, nên mô hình học được rằng "chưa đầy nghĩa là bình thường" và bỏ lọt 20 giây đầu của mỗi đợt quét.

**Hợp đồng lúc chạy** (phải giữ khi gắn vào engine):

- Gọi `FlowContext.update(flow)` cho **mọi** flow kết thúc, đúng theo thứ tự `FlowTracker` xuất flow, rồi truyền kết quả vào `extract_features(flow, context)`.
- Tham số `FlowContext` phải bằng `bundle["context"]`.

## 5. Dữ liệu

### 5.1 Nguồn

**CIC-IDS2017** (Canadian Institute for Cybersecurity): 5 ngày lưu lượng thật của một mạng thí nghiệm, có nhãn tấn công. Dự án dùng **pcap gốc** và tự trích đặc trưng; CSV nhãn `TrafficLabelling` chỉ dùng để gắn nhãn.

| Ngày | Tấn công |
|---|---|
| Thứ Hai | Chỉ có traffic bình thường |
| Thứ Ba | FTP-Patator, SSH-Patator |
| Thứ Tư | DoS Hulk, GoldenEye, slowloris, Slowhttptest, Heartbleed |
| Thứ Năm | Tấn công web (brute force, XSS, SQLi), Infiltration |
| Thứ Sáu | Botnet Ares, PortScan, DDoS LOIC |

### 5.2 Gán nhãn

- Mỗi flow được tra nhãn trong CSV theo IP, cổng, protocol và giờ, với dung sai 120 giây (`common/tools/cic/labels.py`).
- Nhãn gốc được gộp thành lớp: `DoS Hulk/GoldenEye/slowloris/Slowhttptest` → `DoS`; `FTP-Patator`, `SSH-Patator` → `BruteForce`; `Web Attack *` → `WebAttack`.
- **Sửa lỗi nhãn:** mọi flow có IP `205.174.165.73` (máy điều khiển botnet Ares) vào thứ Sáu là `Bot`, dù CSV ghi `BENIGN`. Bài báo của Engelen và cộng sự (2021) đã chỉ ra lỗi nhãn này.
- Lớp mà AI học: `BENIGN`, `PortScan`, `DoS`, `DDoS`, `Bot`, `BruteForce`. Bỏ `WebAttack` (để rule lo) và các lớp quá ít mẫu (`Heartbleed`, `Infiltration`).

### 5.3 Chia dữ liệu

- Pcap được cắt thành **chunk 10 phút**. Mỗi chunk thuộc tập **dev** (dùng để phát triển) hoặc **test** (tập thi, chỉ mở một lần khi chốt). Danh sách ở `docs/eval/manifest.md`.
- Hai máy bot `192.168.10.5` và `192.168.10.8` được **giữ riêng cho tập thi**: flow Bot của chúng không có trong dữ liệu học.
- Tổng cộng khoảng **1,3 triệu flow** dev dùng để học và chấm.

## 6. Huấn luyện và chấm (`common/tools/ai/train.py`)

| Bước | Cách làm |
|---|---|
| Lấy mẫu | Mỗi chunk lấy 5.000 flow BENIGN (cố định, `random_state=42`); flow tấn công lấy hết |
| Chia | Dữ liệu cắt thành **khối 5 phút**. 4 phần chia cố định bằng `StratifiedGroupKFold`, lưu ở `common/tools/ai/folds.csv` |
| Chấm out-of-fold | Mỗi phần được đoán bởi mô hình chưa học khối thời gian của nó; gộp 4 phần rồi tính chỉ số một lần |
| Mô hình | `RandomForestClassifier(n_estimators=100, max_depth=20, min_samples_leaf=2, class_weight="balanced", random_state=42)` |
| Ngưỡng | Mỗi lớp tấn công một ngưỡng, là ngưỡng nhỏ nhất (0,50–0,95) giữ FPR ≤ 1% chia đều cho các lớp |
| Lưu | `data/models/flow_model.joblib` gồm `rf`, `feature_names`, `thresholds.per_class`, `context`, `version`, `folds_version`, `sklearn_version` |

**Vì sao chia theo khối thời gian:** các flow sát nhau trong một đợt tấn công rất giống nhau. Chia ngẫu nhiên thì flow gần như trùng nằm ở cả hai phía, và điểm cao giả.

**Quyết định:** flow là tấn công nếu lớp có xác suất cao nhất là lớp tấn công **và** xác suất đó ≥ ngưỡng của lớp. Nếu không đạt thì coi là `BENIGN`.

Chạy:

```bash
python -m tools.ai.build_dataset --labels-dir <thư mục CSV TrafficLabelling> --jobs 8      # pcap → data/work/ai/features
python -m tools.ai.add_context --src data/work/ai/features-v2 --dst data/work/ai/features-v3        # tính lại cột ngữ cảnh, không đọc lại pcap
python -m tools.ai.train --make-folds                                                     # một lần duy nhất
python -m tools.ai.train --name thu-nghiem --no-save                                      # chỉ chấm
python -m tools.ai.train --features-dir data/work/ai/features-v3 --out data/models/flow_model.joblib  # học và lưu (khoảng 7 phút)
```

Huấn luyện lại từ cùng dữ liệu cho ra file mô hình giống từng byte.

## 7. Kết quả

Số đo trên phần validation của tập dev (out-of-fold), chưa phải tập thi.

| Chỉ số | Kết quả |
|---|---|
| FPR (flow bình thường bị báo nhầm) | **0,13%**, khoảng 1 trên 800 |
| Recall PortScan | 0,92 |
| Recall DDoS | 0,99 |
| Recall Bot | 0,999 |
| Recall BruteForce | 0,996 |
| Recall DoS | 0,97 (công cụ khác Hulk: 0,80) |
| Macro F1 | **0,986** |

**Tiến trình cải thiện PortScan:**

| Bước | Thay đổi | Recall PortScan |
|---|---|---|
| Ban đầu | Chỉ đặc trưng của từng flow | khoảng 0,59 (0,74 khi chấm theo khối thời gian) |
| 1 | Thêm "số cổng khác nhau trong 60 giây qua" | 0,87 |
| 2 | Xem các flow còn lọt: tất cả ở 20 giây đầu đợt quét. Thêm cửa sổ 5 giây, bỏ hai cột bị mù đầu đợt | **0,92** |

Theo nhóm (cặp IP trong khối 5 phút), cả 6 nhóm quét cổng đều bị phát hiện.

**Công cụ chưa từng thấy:** giấu hẳn một công cụ DoS khỏi dữ liệu học rồi đo.

| Công cụ bị giấu | Recall |
|---|---|
| GoldenEye, Slowhttptest (hình dạng gần với thứ đã học) | 0,67–0,71 |
| slowloris (khác hẳn) | 0,18 |

Kết luận: mô hình học **hình dạng flow**, không học tên công cụ.

## 8. Demo ngoài engine

`common/tools/ai/demo_ai.py` đưa lưu lượng qua đúng chuỗi của engine (`FlowTracker` → `FlowContext` → `extract_features`) rồi gọi mô hình.

```bash
python -m tools.ai.demo_ai --scenario scan                 # quét cổng giả lập, trộn người duyệt web và người gõ nhầm cổng
python -m tools.ai.demo_ai --scenario scan --slow 100      # kẻ quét chậm hơn 100 lần
python -m tools.ai.demo_ai --pcap <file.pcap> --limit 300000
```

Kết quả với lưu lượng giả lập, là chuỗi gói mô hình chưa từng thấy:

- kẻ quét: **15.980/16.001** flow bị báo;
- người duyệt web: 0 flow bị báo;
- người gõ nhầm cổng: 0/3 flow bị báo, dù flow của họ giống hệt flow quét ("SYN rồi RST, 60 byte").

| Tốc độ kẻ quét | Flow bị báo |
|---|---|
| 800 flow/giây | 99,9% |
| 80 flow/giây | 99,7% |
| 8 flow/giây | 97% |
| 1 flow/giây | 90% |
| 0,5 flow/giây | 29% |

Quét rất chậm là điểm yếu. Khi đó lớp ngưỡng bất thường và rule vẫn chạy song song.

**Lưu ý khi đọc kết quả demo trên pcap nhỏ:** đặc trưng ngữ cảnh cần vài chục flow mới có tín hiệu. Một pcap chỉ vài chục gói (ví dụ đợt quét 16 cổng) không phải bài thử phù hợp: kẻ quét dễ bị bỏ sót, và máy chỉ có 1–4 flow có thể bị gán nhãn sai.

## 9. Gắn vào engine (việc còn lại)

Phần capture, decoder, DB và API không phải sửa:

1. Nạp bundle. Kiểm tra `feature_names == FEATURE_NAMES` và tham số `context`; lệch thì tắt AI và log lỗi, engine vẫn chạy. Bản sklearn khác thì chỉ cảnh báo.
2. Nhận flow kết thúc từ `FlowLog`, đúng thứ tự `FlowTracker` xuất, rồi gọi `FlowContext.update` và `extract_features`.
3. Gọi `predict_proba` theo lô, áp ngưỡng `bundle["thresholds"]["per_class"]`.
4. Gộp cảnh báo theo `(src_ip, label)` trong một cửa sổ thời gian, để một đợt quét hàng nghìn flow chỉ ra một dòng.
5. Gửi qua `handle_alert` với `source_type="AI_ENGINE"`, `sid=None`, `classtype` là nhãn.

## 10. Giới hạn

| Giới hạn | Ghi chú |
|---|---|
| Mới học từ CIC-IDS2017 | Chưa đo trên traffic của lab Docker |
| Quét cực chậm | Dưới khoảng 1 flow/giây thì recall giảm mạnh |
| Công cụ DoS khác hẳn dữ liệu học | Ví dụ slowloris khi bị giấu: 0,18 |
| Chưa có số trên tập thi | Tập test mở một lần khi chốt mô hình |
| Phụ thuộc phiên bản sklearn | Mô hình học bằng sklearn 1.9.1 |

## Tài liệu tham khảo

- L. Breiman, "Random Forests", *Machine Learning*, 2001.
- I. Sharafaldin, A. H. Lashkari, A. A. Ghorbani, "Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization", *ICISSP*, 2018.
- G. Engelen, V. Rimmer, W. Joosen, "Troubleshooting an Intrusion Detection Dataset: the CICIDS2017 Case Study", *IEEE SPW*, 2021.
- R. Sommer, V. Paxson, "Outside the Closed World: On Using Machine Learning for Network Intrusion Detection", *IEEE S&P*, 2010.
