# Lộ trình 3 tuần, bản dễ hiểu

Bản này tóm tắt plan chi tiết [PLAN-009](plans/2026-11-10-labeled-eval-optimization.md) bằng lời đơn giản. Muốn biết vì sao chọn cách làm nào thì đọc plan; muốn biết hôm nay làm gì thì đọc bản này.

## 1. Hiểu trong một phút

Hệ thống của mình giống một **camera an ninh cho mạng**: xem từng gói tin đi qua và kêu lên (cảnh báo) khi thấy dấu hiệu tấn công. Hiện tại camera có ba tật:

1. **Bỏ sót hình:** khi kêu nhiều, nó mải ghi biên bản (ghi CSDL) nên bỏ qua 86% số gói tin.
2. **Kêu bậy:** một nửa số kết nối bình thường bị coi là tấn công, trong khi tấn công thật thì gần như không thấy.
3. **Chưa có não:** phần AI mới là cái vỏ, chưa làm gì.

Ta lại **không có thước đo**: không biết sửa xong thì tốt lên hay tệ đi. Vì vậy việc đầu tiên là làm thước đo, sau đó mới sửa.

**Thước đo** dùng bộ dữ liệu CIC-IDS2017. Bộ này có sẵn pcap (gói tin thật) và file CSV ghi rõ kết nối nào là tấn công, loại gì. Cho hệ thống xem pcap rồi so với CSV là biết nó đúng bao nhiêu, sai bao nhiêu.

## 2. Dự án đang thiếu gì

| #   | Điểm thiếu                                                                                     | Hậu quả                                                                        | Đã đo được                                        |
| :-- | :--------------------------------------------------------------------------------------------- | :----------------------------------------------------------------------------- | :------------------------------------------------ |
| 1   | Không có cách đo đúng/sai trên traffic thật                                                    | Không biết rule tốt hay dở, không có số liệu cho báo cáo                       |                                                   |
| 2   | Mỗi cảnh báo ghi CSDL riêng một lần, ngay trong luồng phân tích                                | Hàng đợi tràn, engine vứt gói                                                  | 91.836/106.955 gói bị bỏ                          |
| 3   | Đọc file pcap mà hàng đợi đầy vẫn vứt gói                                                      | Đọc file thì không cần vội, nhưng vẫn mất dữ liệu                              |                                                   |
| 4   | Bộ chặn cảnh báo trùng gom theo cổng (cổng của gói trả lời là ngẫu nhiên) và theo giờ máy tính | Một rule bắn 2.145 lần trong 10 phút; chạy lại cùng file ra kết quả khác       |                                                   |
| 5   | 4 rule có ngưỡng quá thấp                                                                      | Báo nhầm khi DNS bận, khi trình duyệt mở nhiều kết nối, khi gặp link quảng cáo | 49% kết nối bình thường bị báo                    |
| 6   | Không có rule cho kiểu tấn công "không có nội dung" (botnet gọi về, scan)                      | Bỏ sót                                                                         | Chỉ bắt 13/118 kết nối PortScan, 0 kết nối botnet |
| 7   | AI chưa có (`nids/ai.py` rỗng)                                                                 | Không bắt được hành vi lạ                                                      |                                                   |
| 8   | Flow chỉ lưu số gói, số byte                                                                   | Chưa đủ thông tin cho AI học                                                   |                                                   |
| 9   | Đọc gói bằng Scapy chậm                                                                        | Giới hạn tốc độ khoảng 4.000 gói/giây                                          |                                                   |
| 10  | Rule chỉ thử trong lab Docker (gần như không có traffic bình thường)                           | Ra mạng thật thì báo nhầm hàng loạt                                            |                                                   |
| 11  | Dashboard chưa hiển thị cảnh báo AI                                                            | Khó demo phần AI                                                               |                                                   |

## 3. "Tối ưu" nghĩa là gì

Tối ưu theo ba hướng:

- **Nhanh:** không vứt gói, xử lý nhiều gói mỗi giây hơn.
- **Đúng:** ít báo nhầm, ít bỏ sót.
- **Thông minh:** AI bắt được thứ rule không thấy, ví dụ botnet.

Mỗi lần sửa đều theo cùng một vòng:

```
đo (ra con số) → sửa một chỗ → đo lại → so hai con số → giữ hoặc bỏ thay đổi
```

Không sửa theo cảm giác. Mỗi con số trước và sau đều được lưu trong `docs/eval/` để đưa vào báo cáo.

**Một quy tắc quan trọng:** dữ liệu chia làm hai phần.

- **Dev** (để luyện): dùng thoải mái khi sửa rule và dạy AI.
- **Test** (để thi): chỉ chạy 2 lần, cuối tuần 2 và cuối tuần 3. Không được nhìn kết quả test rồi sửa theo, nếu không con số sẽ đẹp giả.

## 4. Trình tự làm

```
Bước 1  Dọn dữ liệu, làm module đọc nhãn CIC          (tuần 1)
Bước 2  Sửa engine: không vứt gói, ghi CSDL theo lô   (tuần 1)
Bước 3  Làm bộ đo, chạy số liệu gốc (baseline)        (cuối tuần 1)
Bước 4  Sửa rule báo nhầm, thêm rule, chỉnh ngưỡng    (tuần 2)
Bước 5  Dạy AI từ pcap thứ Sáu                        (tuần 2)
Bước 6  Thi lần 1 trên tập test                        (cuối tuần 2)
Bước 7  Gắn AI vào engine, tăng tốc thêm              (tuần 3)
Bước 8  Thi lần cuối, viết kết quả, chạy thử demo     (cuối tuần 3)
```

Bước 1 và 2 làm song song (mỗi người một bước). Bước 4 và 5 cũng song song.

## 5. Chia vai

| Vai | Phụ trách | Ai (nhóm tự chốt) |
| :--- | :--- | :--- |
| **Người A**: engine và rule | Tốc độ, ghi CSDL, rule, ngưỡng ANOMALY | Đề xuất: bạn (nldd0507), vì bạn đã làm phần rule header |
| **Người B**: dữ liệu và AI | Đọc nhãn CIC, dataset, huấn luyện, gắn AI | Thành viên thứ hai |

Mỗi việc lớn làm trên một nhánh git riêng và mở một **PR** (pull request: gửi code lên GitHub để người kia xem trước khi gộp vào `main`).

## 6. Lịch từng ngày

### Tuần 1: có thước đo, hết vứt gói

| Ngày | Người A (engine, rule) | Người B (dữ liệu, AI) |
| :--- | :--- | :--- |
| **T3 10/11 (tối nay)** | Cả hai: đọc bản này; dọn thư mục `split` (mục 7); tạo issue GitHub cho plan; chốt vai A/B | |
| T4 11/11 | Tạo nhánh `feature/engine-alert-writer`. Sửa: đọc pcap mà hàng đợi đầy thì **chờ** chứ không vứt gói. Viết test | Tạo nhánh `feature/cic-label-tools`. Viết hàm đọc CSV CIC và đổi giờ: CSV ghi `2:09` (không có AM/PM) nghĩa là 14:09 giờ Canada, tức 17:09 UTC. Viết test |
| T5 12/11 | Viết **bộ ghi cảnh báo theo lô**: gom tối đa 200 cảnh báo rồi ghi một lần, ở một luồng riêng. Viết test | Viết hàm **gắn nhãn** cho flow (khớp IP, cổng, giờ với CSV). Thử trên đoạn 14:09: phải gắn được khoảng 99% |
| T6 13/11 | Sắp lại thứ tự tắt engine (ghi hết cảnh báo rồi mới in tổng kết); sửa 2 test cũ bị ảnh hưởng; bật chế độ WAL cho SQLite | Viết `manifest.py`: liệt kê 49 file 10 phút, kiểm tra tổng 9.997.874 gói, đánh dấu file nào là dev, file nào là test, chọn 2 máy botnet để thi |
| T7 14/11 | Sửa **bộ chặn cảnh báo trùng**: gom theo IP thay vì theo cổng, tính giờ theo gói thay vì giờ máy (cho cả rule lẫn ANOMALY). Viết test | Mở PR công cụ nhãn. Bắt đầu khung `evaluate.py`: chạy pipeline engine trên 1 file 10 phút |
| CN 15/11 | Bật lọc tầng Scapy (nhanh hơn khoảng 15%) + test. Đo engine thật trên `chienbuoito.pcap`, ghi số gói/giây | `evaluate.py`: ghép cảnh báo với flow, in bảng đúng/sai theo từng rule, từng loại tấn công |
| T2 16/11 | Cả hai: cho `evaluate.py` chạy nhiều file cùng lúc (máy có 16 nhân); viết test; chạy **baseline** trên code `main` hiện tại, **trước** khi gộp PR engine | |
| T3 17/11 | Mở PR engine, chờ CI xanh rồi gộp | Mở PR bộ đo. Cả hai đọc `docs/eval/baseline.md` và chọn việc cho tuần 2 |

### Tuần 2: rule đúng hơn, AI có dữ liệu

| Ngày | Người A | Người B |
| :--- | :--- | :--- |
| T4 18/11 | Nhánh `feature/rule-precision-cic`. Sửa rule UDP flood (1000205): không báo khi DNS server bận. Test, đo trên dev | Nhánh `feature/ai-flow-features`. Cho flow lưu thêm: độ dài gói nhỏ nhất, lớn nhất, trung bình; khoảng cách thời gian giữa các gói; số cờ TCP |
| T5 19/11 | Sửa rule SYN scan (1000107) và HTTP GET flood (1000209). Đo dev | Viết `features.py`: biến một flow thành khoảng 30 con số cho AI. Viết test |
| T6 20/11 | Sửa rule RFI (1000038): không báo với link quảng cáo. Cập nhật test demo. Đo dev | Mở PR đặc trưng. Nhánh `feature/ai-dataset-training`: chạy 49 file pcap → bảng đặc trưng có nhãn (`csv.gz`) |
| T7 21/11 | Mở pcap dev bằng Wireshark xem botnet, DDoS, PortScan; nếu có dấu hiệu nội dung thật thì viết rule mới, kèm đòn trong `attack_demo.py` | Viết `train.py`: dạy Random Forest (nhận loại tấn công) và IsolationForest (báo hành vi lạ) trên dev |
| CN 22/11 | Thử nhiều bộ ngưỡng ANOMALY trên dev, chọn bộ bắt đủ tấn công mà ít báo nhầm nhất | Mô hình so sánh trên `MachineLearningCVE` (để đối chiếu với bài báo) |
| T2 23/11 | Mở PR rule | Viết `docs/ai/ket-qua-danh-gia.md` (bảng nhầm lẫn, đặc trưng quan trọng); mở PR |
| T3 24/11 | Cả hai: **thi lần 1** trên tập test → `docs/eval/tuan-2.md`, so với baseline | |

### Tuần 3: AI chạy trong engine, tổng kết

| Ngày | Người A | Người B |
| :--- | :--- | :--- |
| T4 25/11 | Nhánh `refactor/flow-expire-sweep`: quét flow hết hạn nhanh hơn, kết quả phải giống hệt bản cũ | Nhánh `feature/ai-worker-integration`: đổi `nids/ai.py` thành thư mục `nids/ai/`, nạp mô hình |
| T5 26/11 | Thử nguyên mẫu đọc gói không dùng Scapy, chỉ đo tốc độ, chưa thay | Cho AI nhận flow vừa kết thúc và ra cảnh báo `AI_ENGINE`; lỗi AI chỉ ghi log, không làm sập engine. Test với mô hình giả |
| T6 27/11 | Mở PR; cập nhật kịch bản demo | Thêm cấu hình `ai` trong `settings.yaml`; dashboard hiện nhãn AI |
| T7 28/11 | Cập nhật tài liệu (`CLAUDE.md`, `.claude/rules/`) | Mở PR AI. Đo engine khi bật AI: chậm hơn không quá 20%, không vứt gói |
| CN 29/11 | Cả hai: **thi lần cuối** (bật AI) → `docs/eval/ket-qua-cuoi.md`, đối chiếu 9 tiêu chí của plan | |
| T2 30/11 | Cả hai: chạy thử demo đầy đủ bằng Docker, sửa lỗi | |
| T3 01/12 | Dự phòng cho việc trễ; đóng plan | |

Nếu bị trễ, cắt theo thứ tự: nguyên mẫu đọc gói không dùng Scapy, rồi mô hình so sánh `MachineLearningCVE`, rồi quét flow nhanh hơn.

## 7. Tối nay làm gì

**1. Dọn thư mục `split`.** Thư mục `D:\Tools\PBL4\split` đang chứa hai bộ cắt chồng nhau:

- 49 file cắt theo 10 phút (tổng 9.997.874 gói, đúng bằng file gốc). **Giữ bộ này.**
- 9 file cắt theo 1 triệu gói (`fri_00001_20170707191928.pcap` ... `fri_00009_20170708020806.pcap`). Bộ này trùng dữ liệu với bộ trên.

Chuyển 9 file kia sang thư mục khác (chuyển chứ không xoá). Lệnh PowerShell:

```powershell
New-Item -ItemType Directory -Force D:\Tools\PBL4\split-1M
Get-ChildItem D:\Tools\PBL4\split\*.pcap | Where-Object { $_.Name -notmatch '939\.pcap$' } | Move-Item -Destination D:\Tools\PBL4\split-1M
(Get-ChildItem D:\Tools\PBL4\split\*.pcap).Count   # phải ra 49
```

**2. Tạo issue GitHub** cho PLAN-009 và ghi số issue vào plan.

**3. Chốt vai A/B** với thành viên thứ hai.

**4. Duyệt plan:** đọc mục 2 (tiêu chí) và mục 6.8 (chia việc) của [PLAN-009](plans/2026-11-10-labeled-eval-optimization.md). Đồng ý thì báo để chuyển plan sang `APPROVED`. Chưa duyệt thì chưa sửa code.

## 8. Khi tải đủ CIC-IDS2017

Tối nay làm với thứ Sáu. Khi tải thêm thứ Hai đến thứ Năm:

1. Cắt mỗi file pcap thành đoạn 10 phút bằng `editcap` (có sẵn trong Wireshark).
2. Chạy `manifest.py` và `evaluate.py` cho ngày đó. Công cụ nhận ngày làm tham số, không phải sửa code.
3. Dạy lại AI với dữ liệu nhiều ngày.

Các ngày khác có thêm các kiểu tấn công thứ Sáu không có:

| Ngày | Tấn công | Ý nghĩa |
| :--- | :--- | :--- |
| Thứ Ba | Dò mật khẩu FTP, SSH | Thử rule `auth.rules` trên traffic thật |
| Thứ Tư | DoS (Hulk, GoldenEye, Slowloris, Slowhttptest), Heartbleed | Thử rule `dos.rules` |
| Thứ Năm | Tấn công web (dò mật khẩu, XSS, SQL injection), Infiltration | Lần đầu đo được 24 rule `web-attack.rules` trên traffic thật |
| Thứ Hai | Chỉ traffic bình thường | Dạy AI biết thế nào là "bình thường" |

## 9. Từ điển

| Từ | Nghĩa |
| :--- | :--- |
| pcap | File ghi lại các gói tin đã đi qua mạng, mở được bằng Wireshark |
| Flow | Một cuộc trò chuyện giữa hai máy (cùng IP, cổng, giao thức), gồm nhiều gói đi và về |
| Nhãn (label) | Ghi chú "flow này là tấn công loại X" hoặc "bình thường", có sẵn trong CSV của CIC |
| Báo nhầm (FP) | Kêu là tấn công nhưng thật ra bình thường |
| Bỏ sót (FN) | Có tấn công nhưng không kêu |
| Baseline | Con số đo trước khi sửa, để so sánh |
| Dev / Test | Dữ liệu để luyện / dữ liệu để thi |
| Đặc trưng (feature) | Các con số mô tả một flow (bao lâu, bao nhiêu gói, gói dài bao nhiêu...) để AI học |
| Random Forest | Mô hình học từ ví dụ có nhãn, đoán flow thuộc loại tấn công nào |
| IsolationForest | Mô hình chỉ học traffic bình thường, báo những flow trông "lạ" |
| PR (pull request) | Gửi code lên GitHub để người khác xem trước khi gộp vào `main` |
