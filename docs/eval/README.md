# Kết quả đo trên CIC-IDS2017

Thư mục này chứa kết quả các lượt đo của bộ đo có nhãn. Mọi file `.md` ở đây do công cụ sinh ra, đừng sửa tay. Tổng hợp và nhận xét: [../performance-metrics.md](../performance-metrics.md).

| File | Nội dung |
| :--- | :--- |
| `manifest.md` | Danh sách 49 chunk pcap 10 phút của thứ Sáu, chunk nào là dev (luyện), chunk nào là test (thi) |
| `baseline-5-ngay.md` | Lượt đo gốc trên tập dev của cả 5 ngày, trước khi tinh chỉnh rule và ANOMALY |
| `<tên>.md` | Các lượt đo sau, sinh bằng `python -m tools.eval.evaluate --name <tên>` |

Số liệu chi tiết dạng JSON nằm ở `data/work/eval/<tên>.json` (không commit, chạy lại lệnh là có).

## Cách chạy

```powershell
# 1. Cắt pcap thành đoạn 10 phút (một lần)
& "C:\Program Files\Wireshark\editcap.exe" -i 600 D:\Tools\PBL4\Friday-WorkingHours.pcap D:\Tools\PBL4\split\fri.pcap

# 2. Lập manifest (một lần, hoặc khi đổi cách chia)
python -m tools.cic.manifest --split-dir D:\Tools\PBL4\split --labels-dir D:\Temp\Temp\TrafficLabelling_

# 3. Đo trên tập dev
python -m tools.eval.evaluate --labels-dir D:\Temp\Temp\TrafficLabelling_ --set dev --set-var HOME_NET=192.168.10.0/24 --name <tên>

# Đo nhanh vài chunk
python -m tools.eval.evaluate --labels-dir D:\Temp\Temp\TrafficLabelling_ --chunks 14:09,15:59 --set-var HOME_NET=192.168.10.0/24 --name thu
```

Tập test là tập thi: chỉ chạy khi chốt kết quả, và phải thêm `--allow-test`.

## Bộ đo làm gì

1. Mỗi chunk pcap chạy qua đúng pipeline của engine: decode → rule + tái hợp TCP → gom flow → ANOMALY. Không ghi CSDL, không có queue, nên **không** đo được chuyện rớt gói; việc đó đo bằng `python -m nids.engine`.
2. Mỗi flow được tra nhãn trong CSV `TrafficLabelling_` theo IP, cổng, protocol và giờ (dung sai 120 giây).
3. Mỗi cảnh báo rule được ghép với flow chứa nó, và lấy nhãn của flow đó. Cảnh báo ANOMALY được ghép theo cặp IP (nguồn, đích) với flow tấn công trong ±60 giây.

Kết quả không phụ thuộc máy chạy:

- Biến header rule là biến mặc định cộng `--set-var`.
- Tham số `stream`, `flow`, `anomaly` lấy từ `common/config/settings.example.yaml`.
- `data/rules/state.yaml` bị bỏ qua (thêm `--use-state` nếu muốn dùng).

## Cách đọc số liệu

| Từ | Nghĩa |
| :--- | :--- |
| Bắt đúng (TP) | Cảnh báo rơi vào flow tấn công |
| Báo nhầm (FP) | Cảnh báo rơi vào flow BENIGN (bình thường) |
| Độ chính xác (precision) | Bắt đúng / (bắt đúng + báo nhầm): trong số cảnh báo, bao nhiêu phần là thật |
| Flow bị rule báo | Flow có ít nhất một rule khớp, tính cả lần bị threshold chặn |
| Tỉ lệ ở lớp tấn công | Độ phủ (recall): trong số flow tấn công, bao nhiêu phần bị rule báo |
| Tỉ lệ ở BENIGN | Tỉ lệ báo nhầm (FPR): trong số flow bình thường, bao nhiêu phần bị rule báo |
| Đợt | PortScan, DDoS: một khoảng giờ liên tục trong CSV. Bot: một máy nhiễm |
| UNLABELED | Flow không có dòng CSV tương ứng, không tính vào số liệu |
| EXCLUDED | Flow bị loại theo quy tắc giữ máy Bot cho tập thi, không tính vào số liệu |
| Khớp trước threshold | Số lần rule khớp, chưa qua bước chặn cảnh báo trùng; không phụ thuộc tốc độ chạy |

Nhãn được sửa ở một chỗ: mọi flow có IP `205.174.165.73` (máy điều khiển botnet Ares) là `Bot`, dù CSV ghi BENIGN. Nguồn và lý do nằm trong `common/tools/cic/labels.py`.
