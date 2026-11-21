# Đánh giá hiệu quả

## 1. Bộ đo có nhãn

Một danh sách rule dài chưa nói lên điều gì; phải chạy trên traffic thật có nhãn mới biết hệ thống bắt đúng hay báo nhầm. Bộ đo (`common/tools/eval/`) chạy engine trên pcap CIC-IDS2017 rồi so với nhãn.

### 1.1 Cách hoạt động

1. Mỗi chunk pcap 10 phút chạy qua đúng pipeline của engine: decode → rule + tái hợp TCP → gom flow → ANOMALY. Bộ đo không ghi CSDL và không có queue, nên **không** đo việc rớt gói. Việc đó đo bằng `python -m nids.engine` ở chế độ offline.
2. Mỗi flow được tra nhãn trong CSV `TrafficLabelling` theo IP, cổng, protocol và giờ (dung sai 120 giây).
3. Mỗi cảnh báo rule được ghép với flow chứa nó và lấy nhãn của flow đó. Cảnh báo ANOMALY được ghép theo cặp IP với flow tấn công trong khoảng ±60 giây.

Kết quả không phụ thuộc máy chạy:

- biến header là biến mặc định cộng `--set-var`;
- tham số `stream`, `flow`, `anomaly` lấy từ `common/config/settings.example.yaml`;
- `data/rules/state.yaml` bị bỏ qua.

### 1.2 Chạy

```powershell
# 1. Cắt pcap thành chunk 10 phút (một lần)
editcap -i 600 Friday-WorkingHours.pcap split\fri.pcap
# 2. Lập manifest chia dev/test (một lần)
python -m tools.cic.manifest --split-dir <thư mục split> --labels-dir <thư mục TrafficLabelling>
# 3. Đo trên tập dev
python -m tools.eval.evaluate --labels-dir <thư mục TrafficLabelling> --set dev --set-var HOME_NET=192.168.10.0/24 --name <tên>
```

Báo cáo Markdown được ghi vào `docs/eval/<tên>.md`, số liệu JSON vào `data/work/eval/<tên>.json` (không commit). Tập test chỉ chạy khi thêm `--allow-test`.

### 1.3 Cách đọc

| Từ | Nghĩa |
|---|---|
| Bắt đúng (TP) | Cảnh báo rơi vào flow tấn công |
| Báo nhầm (FP) | Cảnh báo rơi vào flow `BENIGN` |
| Độ chính xác (precision) | TP / (TP + FP): trong số cảnh báo, bao nhiêu phần là thật |
| Độ phủ (recall) | Trong số flow tấn công, bao nhiêu phần bị báo |
| Tỉ lệ báo nhầm (FPR) | Trong số flow bình thường, bao nhiêu phần bị báo |
| Theo cặp IP | Mỗi cặp IP chỉ tính một lần, để một kẻ tấn công bị báo lặp không chi phối con số |
| Đợt | PortScan, DDoS: một khoảng giờ liên tục; Bot: một máy nhiễm |
| `UNLABELED` / `EXCLUDED` | Không có dòng CSV tương ứng / bị loại theo quy tắc giữ máy Bot cho tập thi. Không tính vào số liệu |

## 2. Hiệu năng engine

Đo trên một đoạn 10 phút traffic thật, trước và sau khi sửa engine:

| Vấn đề | Trước | Sau | Cách sửa |
|---|---:|---:|---|
| Gói bị bỏ khi đọc pcap | 86% | **0%** | Đọc file thì chờ queue có chỗ, không bỏ gói |
| Tốc độ | 1.680 gói/giây | **2.735–3.189 gói/giây** | Scapy chỉ bóc tới L4; ghi cảnh báo theo lô ở thread riêng |
| Chạy lại cùng file | 2.901 / 2.923 / 3.008 cảnh báo | **251 / 251** | Threshold tính theo giờ của gói, không theo giờ máy |
| Cảnh báo gửi người trực (8 triệu gói dev) | 140.601 | **5.103** (−96%) | Gộp cảnh báo trùng theo đúng kiểu đếm của rule |
| Số lần rule khớp | 659.984 | 659.984 | Không đổi: sửa engine không làm sai việc phát hiện |

Thời gian xử lý theo bước (5 ngày dev, 49,9 triệu gói):

| Bước | Tỉ lệ thời gian |
|---|---:|
| Scapy đọc và bóc gói | 52,9% |
| Decode | 22,1% |
| Rule + tái hợp TCP | 19,5% |
| Gom flow | 3,2% |
| ANOMALY | 2,4% |

Nút thắt nằm ở Scapy, không nằm ở phần so khớp rule.

## 3. Rule và ANOMALY trên 5 ngày CIC-IDS2017

Lượt đo `baseline-5-ngay`: tập dev gồm 221 chunk của cả 5 ngày, 68 rule tự viết, `HOME_NET=192.168.10.0/24`. Đây là **mốc gốc trước khi tinh chỉnh rule và ANOMALY**. Báo cáo đầy đủ: [eval/baseline-5-ngay.md](eval/baseline-5-ngay.md).

### 3.1 Theo lớp

| Lớp | Số flow | Bị rule báo |
|---|---:|---:|
| BENIGN | 1.515.436 | 51,3% (báo nhầm) |
| PortScan | 139.058 | 99,7% |
| DDoS | 62.420 | 98,8% |
| BruteForce | 5.129 | 98,5% |
| DoS | 100.898 | 94,4% |
| WebAttack | 1.411 | 7,0% |
| Bot | 2.547 | 1,6% |

### 3.2 Theo tầng

| Tầng | Cảnh báo | Bắt đúng | Báo nhầm | Độ chính xác |
|---|---:|---:|---:|---:|
| RULE_ENGINE | 26.937 | 1.514 | 24.339 | 5,9% |
| ANOMALY | 18.247 | 109 | 17.633 | 0,6% |

### 3.3 Nhận xét

- **Rule bao phủ tốt các tấn công có số lượng lớn** (PortScan, DDoS, BruteForce, DoS). Tuy vậy, một nửa flow bình thường cũng bị báo.
- **Báo nhầm tập trung ở vài rule có ngưỡng hoặc điều kiện quá rộng so với mạng thật.** Các rule này chạy đúng trong lab Docker, vì lab gần như không có traffic bình thường.

| SID | Rule | Báo nhầm | Nguyên nhân |
|---|---|---:|---|
| 1000038 | Remote File Inclusion | 8.879 | Bắt `=http` trong URL; link quảng cáo, theo dõi rất hay có dạng `?url=http...` |
| 1000205 | UDP flood | 7.083 | DNS server nội bộ nhận vượt 50 gói/giây là bình thường |
| 1000107 | SYN port scan | 3.580 | Đếm SYN mà không xét cổng đích; trình duyệt mở nhiều kết nối HTTPS cùng lúc |
| 1000301 | SSH probe banner | 2.268 | Kết nối SSH hợp lệ trong mạng nội bộ |
| 1000209 | HTTP GET flood | 671 | Một trang web tải hàng chục tài nguyên cùng lúc |

- **ANOMALY báo nhầm nhiều nhất ở loại "cổng hiếm"** (10.631), chủ yếu là DHCPv6 multicast (`ff02::1:2:547`).
- **Rule có độ chính xác cao:** brute force FTP và web login (100%), SSH brute force (95,1%), XSS `document.cookie` (100%), Slowloris (100%).
- **Botnet gần như không bị rule bắt** (1,6%). Mỗi kết nối về máy điều khiển chỉ có SYN rồi RST, không có nội dung để so khớp. Đây là phần giao cho AI, và AI đạt recall Bot 0,999.
- **Phát hiện theo đợt:** phần lớn đợt tấn công có ít nhất một cảnh báo. Các đợt ngắn (1–2 phút) và máy bot `192.168.10.14` bị bỏ sót.

## 4. Mô hình AI

Số đo out-of-fold trên phần validation của tập dev, 6 lớp:

| Chỉ số | Kết quả |
|---|---:|
| FPR | 0,13% |
| Macro F1 | 0,986 |
| Recall PortScan / DoS / DDoS / Bot / BruteForce | 0,92 / 0,97 / 0,99 / 0,999 / 0,996 |

So với rule trên cùng loại dữ liệu, AI có tỉ lệ báo nhầm thấp hơn nhiều (0,13% so với 51,3%) và bắt được botnet. Phương pháp chấm và các thí nghiệm: [machine-learning-guide.md](machine-learning-guide.md).

## 5. Báo cáo đo đã lưu

| File | Nội dung |
|---|---|
| [eval/README.md](eval/README.md) | Giới thiệu thư mục báo cáo |
| [eval/manifest.md](eval/manifest.md) | Danh sách chunk và cách chia dev/test |
| [eval/baseline-5-ngay.md](eval/baseline-5-ngay.md) | Lượt đo gốc trên 5 ngày: theo lớp, theo rule, theo ngày, theo đợt |

Các file trong `docs/eval/` do công cụ sinh ra, không sửa tay.
