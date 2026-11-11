# Lộ trình 3 tuần, bản dễ hiểu

Bản này tóm tắt plan chi tiết [PLAN-009](plans/2026-11-10-labeled-eval-optimization.md) bằng lời đơn giản. Muốn biết vì sao chọn cách làm nào thì đọc plan; muốn biết hôm nay làm gì thì đọc bản này.

**Cập nhật 11/11:** lộ trình được sắp lại theo yêu cầu của nhóm: **tối ưu so khớp và các điểm đang chưa tốt trước**, **phần AI dồn vào tuần cuối** (25/11–01/12), sau khi hệ thống đã được tối ưu.

## 1. Hiểu trong một phút

Hệ thống của mình giống một **camera an ninh cho mạng**: xem từng gói tin đi qua và kêu lên (cảnh báo) khi thấy dấu hiệu tấn công.

Tuần 1 (10–11/11) đã làm xong hai việc:

- **Làm cái thước đo:** cho engine xem pcap của CIC-IDS2017 rồi so với file nhãn CSV, ra bảng "đúng bao nhiêu, sai bao nhiêu" cho từng rule.
- **Sửa chỗ engine vứt gói:** trước bỏ 86% gói khi đọc pcap, giờ không bỏ gói nào, nhanh hơn 63–90%, và chạy lại lần nào cũng ra cùng kết quả.

Chi tiết ở [nhật ký ngày 1](nhat-ky-ngay-1.md) và [nhật ký ngày 2](nhat-ky-ngay-2.md).

Camera **vẫn còn kêu bậy nhiều**: một nửa số kết nối bình thường bị coi là tấn công. Vì vậy việc tiếp theo là **tối ưu phần so khớp** (rule và ANOMALY), trên cả 5 ngày dữ liệu. Sau đó tối ưu nốt các phần khác của hệ thống. Cuối cùng mới làm AI, khi hệ thống đã gọn và đo được chính xác AI giúp thêm được bao nhiêu.

## 2. Điểm chưa tốt hiện tại (xếp theo thứ tự sẽ sửa)

Số liệu đo ngày 10–11/11 trên 43 đoạn dev của thứ Sáu ([eval/sau-sua-engine.md](eval/sau-sua-engine.md)), trừ khi ghi khác.

### Nhóm 1: so khớp và phát hiện (sửa trước, 12–17/11)

| # | Điểm chưa tốt | Hậu quả | Số đo hiện tại |
| :-- | :--- | :--- | :--- |
| 1 | 4 rule có điều kiện quá rộng: 1000205 (UDP flood), 1000107 (SYN scan), 1000209 (HTTP GET flood), 1000038 (Remote File Inclusion) | Báo nhầm khi DNS server bận, khi trình duyệt mở nhiều kết nối, khi gặp link quảng cáo | **52,3%** flow bình thường bị rule báo; 1000205 có 1.339 cảnh báo, 0 đúng |
| 2 | ANOMALY "Rare port" coi traffic nội bộ bình thường là lạ | Báo nhầm hàng loạt với IPv6 multicast, LDAP (389), NetBIOS | Độ chính xác ANOMALY **2%** |
| 3 | Bỏ sót tấn công nhỏ và botnet | Đợt quét 13:05 lọt hoàn toàn; botnet gần như vô hình | PortScan **4/5** đợt; flow Bot bị báo **1,6%** |
| 4 | Mới đo trên 1 ngày (thứ Sáu) | 24 rule web, rule dò mật khẩu, rule DoS **chưa từng được đo** trên traffic thật | chưa đo |
| 5 | Phần so khớp chưa được đo kỹ xem tốn thời gian ở đâu | Không biết rule hay bước nào làm chậm | "Rule + tái hợp TCP" chiếm 17,5% thời gian |
| 6 | Bộ đo: nhãn Infiltration (thứ Năm) bị gắn nhầm thành Bot | Số liệu thứ Năm sẽ sai | 70 dòng "Bot", 0 dòng Infiltration |
| 7 | Bộ đo: độ chính xác tính theo số cảnh báo bị cảnh báo trùng chi phối; chưa lưu danh sách cảnh báo | Con số khó hiểu (tụt 30,3% → 6,6% dù báo nhầm giảm mạnh); không kiểm tra được vì sao máy Bot `.14` lọt | |

### Nhóm 2: phần còn lại của hệ thống (sửa sau, 18–24/11)

| # | Điểm chưa tốt | Hậu quả | Số đo hiện tại |
| :-- | :--- | :--- | :--- |
| 8 | Flow log vẫn ghi CSDL ngay trong luồng phân tích | CSDL bị khoá thì luồng phân tích đứng tới 30 giây; bắt gói trực tiếp sẽ rơi gói | lượt chạy 40 → 71 giây khi khoá CSDL 35 giây |
| 9 | Hai luồng (đọc gói và phân tích) tranh nhau CPU vì GIL của Python; Scapy chậm | Chưa đạt 3.000 gói/giây ở đoạn nhiều kết nối | 2.735 gói/giây (đoạn 14:09); 3.189 (đoạn 09:19) |
| 10 | Chưa đo chế độ bắt gói trực tiếp (live) | Không biết khi demo thật có rơi gói không | chưa đo |
| 11 | Bảng `events` thiếu index, không bao giờ được dọn; trang thống kê gom nhóm cả bảng mỗi lần tải | Dashboard chậm dần khi chạy lâu | chưa đo |
| 12 | Test CI `test_realtime_ws.py` chập chờn | CI đỏ ngẫu nhiên, PR phải chạy lại | PR #72 fail lần đầu vì nó |

### Nhóm 3: AI (làm cuối, 25/11–01/12)

| # | Điểm chưa tốt | Hậu quả |
| :-- | :--- | :--- |
| 13 | AI chưa có (`nids/ai.py` là cái vỏ rỗng) | Không bắt được hành vi lạ mà rule không có chữ ký, ví dụ botnet |
| 14 | Flow chỉ lưu số gói, số byte, cờ TCP | Chưa đủ thông tin cho AI học |
| 15 | Dashboard chưa hiển thị cảnh báo AI | Khó demo phần AI |

### Đã sửa ở tuần 1

| Điểm cũ | Trước | Sau |
| :--- | :--- | :--- |
| Không có cách đo đúng/sai | | Bộ đo có nhãn, baseline ở [eval/baseline.md](eval/baseline.md) |
| Đọc pcap mà hàng đợi đầy vẫn vứt gói | vứt 86% | vứt 0 |
| Mỗi cảnh báo ghi CSDL riêng một lần | 1 lần `commit` mỗi cảnh báo | 200 cảnh báo một lần, ở luồng riêng |
| Bộ chặn cảnh báo trùng gom theo cổng và theo giờ máy | cảnh báo trên dev: 140.601, mỗi lần chạy một khác | 5.103, lần nào chạy cũng vậy |
| Scapy bóc thừa các tầng ứng dụng | | đọc gói nhanh gấp đôi, đếm byte đúng ở mọi gói |

## 3. "Tối ưu" nghĩa là gì

Tối ưu theo ba hướng:

- **Đúng:** ít báo nhầm, ít bỏ sót. Đây là ưu tiên số một.
- **Nhanh:** không vứt gói, xử lý nhiều gói mỗi giây, dashboard trả lời nhanh.
- **Thông minh:** AI bắt được thứ rule không thấy, ví dụ botnet. Làm cuối.

Mỗi lần sửa đều theo cùng một vòng:

```
đo (ra con số) → sửa một chỗ → đo lại → so hai con số → giữ hoặc bỏ thay đổi
```

Không sửa theo cảm giác. Mỗi con số trước và sau đều được lưu trong `docs/eval/` để đưa vào báo cáo.

**Một quy tắc quan trọng:** dữ liệu chia làm hai phần.

- **Dev** (để luyện): dùng thoải mái khi sửa rule, chỉnh ngưỡng, dạy AI.
- **Test** (để thi): chỉ chạy 2 lần, **24/11** (sau khi tối ưu xong) và **30/11** (sau khi có AI). Không được nhìn kết quả test rồi sửa theo, nếu không con số sẽ đẹp giả.

## 4. Trình tự làm

```
Đã xong  Bộ đo có nhãn, baseline thứ Sáu, engine không vứt gói          (10–11/11)
Bước 1   Đo đủ 5 ngày, sửa lỗi bộ đo, đo kỹ phần so khớp                 (12–13/11)
Bước 2   Sửa 4 rule báo nhầm, sửa ANOMALY, thêm rule cho 4 ngày mới      (13–16/11)
Bước 3   Tăng tốc phần so khớp, đo lại cả 5 ngày                         (17/11)
Bước 4   Tối ưu engine, CSDL, API, CI; thử bắt gói trực tiếp             (18–23/11)
Bước 5   Thi lần 1 trên tập test 5 ngày                                  (24/11)
Bước 6   AI: đặc trưng flow, dataset, huấn luyện, gắn vào engine         (25–29/11)
Bước 7   Thi lần cuối có AI, chạy thử demo                               (30/11–01/12)
```

## 5. Chia vai

| Vai | Phụ trách đến 24/11 | Phụ trách từ 25/11 (AI) |
| :--- | :--- | :--- |
| **Người A**: so khớp và engine | Rule, tốc độ so khớp, tốc độ engine, flow log | Đặc trưng flow, dataset, gắn AI vào engine |
| **Người B**: bộ đo và hệ thống | Bộ đo 5 ngày, ANOMALY, CSDL, API, CI, thử live | Huấn luyện mô hình, báo cáo AI, đo engine khi bật AI |

Đề xuất bạn (nldd0507) làm người A. Thành viên thứ hai làm người B.

Mỗi việc lớn làm trên một nhánh git riêng và mở một **PR** (pull request: gửi code lên GitHub để người kia xem trước khi gộp vào `main`).

## 6. Lịch từng ngày

### Tuần 1 (đã xong 10–11/11): có thước đo, hết vứt gói

Xong T0–T8 trong 2 ngày, PR #72 và #73 đã merge. Xem [tuan-1-chi-tiet.md](tuan-1-chi-tiet.md).

### Phần còn lại tuần 1 (12–17/11): đo đủ 5 ngày, tối ưu so khớp

| Ngày | Người A (so khớp) | Người B (bộ đo) |
| :--- | :--- | :--- |
| T4 12/11 | Nhánh `feature/rule-precision-cic`. **Đo phần so khớp tốn thời gian ở đâu:** chạy `cProfile` trên đoạn 14:09, tách thời gian của từng tầng phễu (lọc theo protocol, Aho-Corasick, kiểm tra chi tiết, pcre, bộ chặn) và từng rule | Nhánh `feature/eval-five-days`. **Sửa lỗi nhãn Infiltration:** chỉ đổi dòng BENIGN có IP máy điều khiển thành Bot, không đè nhãn tấn công khác. Lập manifest cho thứ Hai–Năm (giờ chunk test của từng ngày, mục 8) |
| T5 13/11 | **Sửa rule 1000205 (UDP flood):** không báo khi đích là DNS/NTP/mDNS (cổng 53, 123, 5353) hoặc tăng ngưỡng. Test đúng (gói flood thật) và test sai (DNS server bận). Đo dev thứ Sáu | Bộ đo: thêm **độ chính xác theo cặp IP** và **lưu danh sách cảnh báo** ra file. Chạy baseline thứ Hai–Năm bằng code `main` hiện tại (chạy nền khoảng 1–2 giờ) |
| T6 14/11 | **Sửa 1000107 (SYN scan):** quét là nhiều *cổng khác nhau*, không chỉ nhiều SYN; đếm theo nguồn hoặc nhường cho ANOMALY. **Sửa 1000209 (GET flood):** đếm theo đích, tăng ngưỡng. Đo dev | Đọc baseline 4 ngày, lập bảng cho người A: rule web (thứ Năm), dò mật khẩu (thứ Ba), DoS (thứ Tư) bắt đúng bao nhiêu, nhầm bao nhiêu, sót đợt nào |
| T7 15/11 | **Sửa 1000038 (RFI):** chỉ bắt khi tham số có tên hay bị lợi dụng (`file=`, `page=`, `include=`, `path=`). Cập nhật test demo (`tests/lab/test_demo_rules.py`). Đo dev | **Sửa ANOMALY "Rare port":** bỏ qua IPv6 multicast và link-local, cổng dịch vụ nội bộ (LDAP 389/3268, NetBIOS 137–139). Đo dev |
| CN 16/11 | **Sửa và thêm rule** theo bảng của người B (ví dụ Slowloris và Slowhttptest thứ Tư, dò mật khẩu web thứ Năm), mỗi rule mới kèm đòn trong `lab/attacker/attack_demo.py` | **Chỉnh ngưỡng ANOMALY bằng dữ liệu:** thử nhiều bộ `scan`/`flood` trên dev 5 ngày, chọn bộ bắt được đợt PortScan 13:05 mà ít báo nhầm nhất; ghi vào `config/settings.example.yaml` |
| T2 17/11 | **Tăng tốc so khớp** theo kết quả đo ngày 12/11 (ví dụ rule không có fast pattern luôn bị kiểm tra, pcre nặng). Điều kiện: số lần rule khớp **không đổi**. Mở PR rule | Mở PR bộ đo. **Cả hai:** chạy bộ đo dev 5 ngày → `docs/eval/sau-sua-so-khop.md`, so với baseline |

### Tuần 2 (18–24/11): tối ưu phần còn lại của hệ thống, thi lần 1

| Ngày | Người A (engine) | Người B (hệ thống) |
| :--- | :--- | :--- |
| T3 18/11 | Nhánh `feature/flow-writer`. **Ghi flow log ở luồng riêng** (giống bộ ghi cảnh báo). Thử lại phép khoá CSDL 35 giây: luồng phân tích không được đứng | Nhánh `feature/api-db-perf`. **Công cụ đo API:** đổ 1 triệu cảnh báo vào CSDL thử, đo thời gian trả lời của trang thống kê, danh sách cảnh báo, biểu đồ |
| T4 19/11 | **Quét flow hết hạn nhanh hơn** (`FlowTracker.expire`), kết quả phải giống hệt bản cũ trên mọi chunk dev | **Thêm index** cho bảng `events` (cột lọc và gom nhóm), **cache 5 giây** cho thống kê và biểu đồ. Đo lại |
| T5 20/11 | **Nguyên mẫu 1:** tách đọc gói và phân tích thành hai process để tránh GIL. Đo tốc độ | **Dọn `events` theo hạn** (`database.events_retention_days`), lượt dọn không chặn engine. Viết test |
| T6 21/11 | **Nguyên mẫu 2:** đọc gói bằng byte thô, không qua Scapy. Đo tốc độ, so số lần rule khớp | **Sửa test CI chập chờn** cùng nmchien1106 (PLAN-001). Chạy `pytest` 10 lần liền đều phải xanh |
| T7 22/11 | Chọn nguyên mẫu lợi hơn và gọn hơn, đưa vào engine; không cái nào gọn thì giữ nguyên và ghi số đo | **Thử bắt gói trực tiếp:** phát lại đoạn 09:19 vào lab Docker bằng `tcpreplay`, đếm gói bị bỏ |
| CN 23/11 | **Cả hai:** mở PR, review chéo, cập nhật tài liệu (`CLAUDE.md`, `.claude/rules/`, kịch bản demo) | |
| T2 24/11 | **Cả hai: thi lần 1** trên tập test 5 ngày → `docs/eval/thi-lan-1.md`, đối chiếu tiêu chí của plan | |

### Tuần 3 (25/11–01/12): AI, sau khi hệ thống đã tối ưu

| Ngày | Người A | Người B |
| :--- | :--- | :--- |
| T3 25/11 | Nhánh `feature/ai-flow-features`. Cho flow lưu thêm: độ dài gói nhỏ nhất, lớn nhất, trung bình; khoảng cách thời gian giữa các gói; số cờ TCP; byte payload | Viết `nids/ai/features.py`: biến một flow thành khoảng 30 con số cho AI. Viết test |
| T4 26/11 | Viết `tools/ai/build_dataset.py`: chạy pcap 5 ngày song song → bảng đặc trưng có nhãn (`csv.gz`) | Viết `tools/ai/train.py`: dạy **Random Forest** trên dev 5 ngày, chia theo thời gian và theo máy Bot |
| T5 27/11 | Nhánh `feature/ai-worker-integration`: đổi `nids/ai.py` thành thư mục `nids/ai/`, nạp mô hình, nhận flow vừa kết thúc | Chọn ngưỡng sao cho báo nhầm ≤ 1%; thêm **IsolationForest** nếu kịp; viết `docs/ai/ket-qua-danh-gia.md` |
| T6 28/11 | Cảnh báo `AI_ENGINE`; lỗi AI chỉ ghi log, không làm sập engine; test với mô hình giả; dashboard hiện nhãn AI | **Đo engine khi bật AI:** chậm hơn không quá 20%, không vứt gói |
| T7 29/11 | **Cả hai:** mở PR AI, review chéo | |
| CN 30/11 | **Cả hai: thi lần cuối** (bật AI) → `docs/eval/ket-qua-cuoi.md`, đối chiếu tiêu chí | |
| T2 01/12 | **Cả hai:** chạy thử demo đầy đủ bằng Docker, sửa lỗi, dự phòng cho việc trễ, đóng plan | |

**Nếu bị trễ, cắt theo thứ tự:**

1. Tuần 3: IsolationForest, rồi mô hình so sánh trên `MachineLearningCVE`.
2. Tuần 2: nguyên mẫu đọc byte thô, rồi nguyên mẫu hai process, rồi phép thử live.

Không cắt việc sửa rule báo nhầm và hai lần thi.

### Issue trên GitHub

Mỗi việc trong lịch trên có một issue (tạo ngày 11/11, thuộc PLAN-009 #71). Đóng issue bằng PR có dòng `Closes #số`.

**Giai đoạn 1: so khớp và phát hiện (12–17/11)**

| Issue | Việc | Ngày | Ai |
| :--- | :--- | :--- | :--- |
| [#74](https://github.com/74Teams/hybrid-nids/issues/74) | Eval: sửa nhãn Infiltration bị gắn nhầm thành Bot | 12/11 | người B |
| [#75](https://github.com/74Teams/hybrid-nids/issues/75) | Eval: manifest và chia dev/test cho thứ Hai đến thứ Năm | 12/11 | người B |
| [#76](https://github.com/74Teams/hybrid-nids/issues/76) | Eval: độ chính xác theo cặp IP và lưu danh sách cảnh báo | 13/11 | người B |
| [#77](https://github.com/74Teams/hybrid-nids/issues/77) | Engine: đo thời gian từng tầng so khớp | 12/11 | người A |
| [#78](https://github.com/74Teams/hybrid-nids/issues/78) | Rules: sửa 4 rule báo nhầm 1000205, 1000107, 1000209, 1000038 | 13–15/11 | người A |
| [#79](https://github.com/74Teams/hybrid-nids/issues/79) | Engine: ANOMALY Rare port bỏ qua traffic nội bộ bình thường | 15/11 | người B |
| [#80](https://github.com/74Teams/hybrid-nids/issues/80) | Engine: chỉnh ngưỡng ANOMALY bằng dữ liệu 5 ngày | 16/11 | người B |
| [#81](https://github.com/74Teams/hybrid-nids/issues/81) | Rules: đo và bổ sung rule cho tấn công thứ Ba đến thứ Năm | 16/11 | người A |
| [#82](https://github.com/74Teams/hybrid-nids/issues/82) | Engine: tăng tốc so khớp theo kết quả đo | 17/11 | người A |

**Giai đoạn 2: phần còn lại của hệ thống (18–24/11)**

| Issue | Việc | Ngày | Ai |
| :--- | :--- | :--- | :--- |
| [#83](https://github.com/74Teams/hybrid-nids/issues/83) | Engine: ghi flow log ở luồng riêng | 18/11 | người A |
| [#84](https://github.com/74Teams/hybrid-nids/issues/84) | Engine: FlowTracker.expire không quét toàn bảng mỗi giây | 19/11 | người A |
| [#85](https://github.com/74Teams/hybrid-nids/issues/85) | Engine: thử vượt GIL bằng hai process hoặc decoder đọc byte thô | 20–22/11 | người A |
| [#86](https://github.com/74Teams/hybrid-nids/issues/86) | API: công cụ đo thời gian trả lời khi CSDL lớn | 18/11 | người B |
| [#87](https://github.com/74Teams/hybrid-nids/issues/87) | DB: index cho bảng events và cache thống kê dashboard | 19/11 | người B |
| [#88](https://github.com/74Teams/hybrid-nids/issues/88) | DB: dọn bảng events theo hạn | 20/11 | người B |
| [#89](https://github.com/74Teams/hybrid-nids/issues/89) | CI: sửa test realtime WebSocket chập chờn | 21/11 | người B cùng nmchien1106 (PLAN-001) |
| [#90](https://github.com/74Teams/hybrid-nids/issues/90) | Lab: thử bắt gói trực tiếp bằng tcpreplay | 22/11 | người B |
| [#91](https://github.com/74Teams/hybrid-nids/issues/91) | Eval: thi lần 1 trên tập test 5 ngày | 24/11 | cả hai |

**Giai đoạn 3: AI (25/11–01/12)**

| Issue | Việc | Ngày | Ai |
| :--- | :--- | :--- | :--- |
| [#92](https://github.com/74Teams/hybrid-nids/issues/92) | AI: bộ đếm đặc trưng cho flow và FEATURE_NAMES | 25/11 | người A và người B |
| [#93](https://github.com/74Teams/hybrid-nids/issues/93) | AI: dataset 5 ngày và huấn luyện Random Forest | 26–27/11 | người A (dataset) và người B (huấn luyện) |
| [#94](https://github.com/74Teams/hybrid-nids/issues/94) | AI: tích hợp AITrafficWorker vào engine và dashboard | 27–28/11 | người A, đo chi phí: người B |
| [#95](https://github.com/74Teams/hybrid-nids/issues/95) | Eval: thi lần cuối có AI và chạy thử demo | 30/11–01/12 | cả hai |

## 7. Ngày mai (12/11) làm gì

1. **Chốt vai A/B** với thành viên thứ hai.
2. **Người A:** tạo nhánh `feature/rule-precision-cic` từ `main` mới nhất, đo phần so khớp bằng `cProfile` trên `pcap/chienbuoito.pcap`.
3. **Người B:** tạo nhánh `feature/eval-five-days`, sửa lỗi nhãn Infiltration trong `tools/cic/labels.py`, rồi lập manifest cho thứ Hai–Năm:
   ```powershell
   python -m tools.cic.manifest --split-dir D:\Tools\PBL4\split\tuesday --labels-dir D:\Temp\Temp\TrafficLabelling_ --day tuesday --test-starts <giờ ở mục 8> --expect-packets 0 --summary docs\eval\manifest-tuesday.md --out data\cic\tuesday_manifest.json
   ```
   `--expect-packets 0` tạm bỏ kiểm tra tổng gói. Nên đếm tổng gói của file gốc bằng `capinfos` rồi điền số thật vào.

## 8. Dữ liệu 5 ngày (đã tải và cắt đủ)

Pcap ở `D:\Tools\PBL4\`, đã cắt 10 phút ở `D:\Tools\PBL4\split\` (thứ Sáu ở gốc thư mục, 4 ngày còn lại mỗi ngày một thư mục con). Các đợt tấn công đo từ file nhãn (giờ Canada):

| Ngày | Chunk bắt đầu lúc | Tấn công | Các đợt | Ý nghĩa |
| :--- | :--- | :--- | :--- | :--- |
| Thứ Hai | 08:55, 09:05, ... | Không có (chỉ traffic bình thường) | | Đo báo nhầm; dạy AI biết thế nào là "bình thường" |
| Thứ Ba | 08:53, 09:03, ... | Dò mật khẩu FTP, SSH | 09:17–10:21, 10:30–10:31, 14:09–15:12 | Đo rule `auth.rules` |
| Thứ Tư | 08:42, 08:52, ... | DoS (Hulk, GoldenEye, Slowloris, Slowhttptest), Heartbleed | 09:01–09:02, 09:48–10:38, 10:43–11:20, 14:24–14:26; Heartbleed 15:12–15:33 | Đo rule `dos.rules`. Heartbleed chỉ báo cáo vì engine chưa hiểu `byte_test` |
| Thứ Năm | 08:58, 09:08, ... | Tấn công web (dò mật khẩu, XSS, SQL injection), Infiltration | 09:15–10:01, 10:15–10:43; Infiltration buổi chiều | Lần đầu đo 24 rule `web-attack.rules` trên traffic thật |
| Thứ Sáu | 08:59, 09:09, ... | Botnet, PortScan, DDoS | xem [eval/manifest.md](eval/manifest.md) | Đã đo ở tuần 1 |

Mỗi ngày giữ phần sau của mỗi đợt tấn công làm tập test, cộng 1–2 chunk bình thường. Ví dụ thứ Ba: hai chunk cuối của đợt FTP và hai chunk cuối của đợt SSH. Giờ chính xác được chốt khi người B chạy manifest, ghi vào `docs/eval/manifest-<ngày>.md`.

## 9. Từ điển

| Từ | Nghĩa |
| :--- | :--- |
| pcap | File ghi lại các gói tin đã đi qua mạng, mở được bằng Wireshark |
| Flow | Một cuộc trò chuyện giữa hai máy (cùng IP, cổng, giao thức), gồm nhiều gói đi và về |
| So khớp | Bước engine kiểm tra gói tin có khớp rule nào không: lọc theo protocol và cổng, tìm chuỗi nhanh bằng Aho-Corasick, rồi kiểm tra chi tiết |
| Nhãn (label) | Ghi chú "flow này là tấn công loại X" hoặc "bình thường", có sẵn trong CSV của CIC |
| Báo nhầm (FP) | Kêu là tấn công nhưng thật ra bình thường |
| Bỏ sót (FN) | Có tấn công nhưng không kêu |
| Baseline | Con số đo trước khi sửa, để so sánh |
| Dev / Test | Dữ liệu để luyện / dữ liệu để thi |
| GIL | Khoá của Python: mỗi lúc chỉ một luồng được chạy code Python, nên hai luồng cùng tốn CPU phải thay phiên nhau |
| Index | "Mục lục" của bảng CSDL, giúp tìm và gom nhóm nhanh mà không phải đọc cả bảng |
| Đặc trưng (feature) | Các con số mô tả một flow (bao lâu, bao nhiêu gói, gói dài bao nhiêu...) để AI học |
| Random Forest | Mô hình học từ ví dụ có nhãn, đoán flow thuộc loại tấn công nào |
| IsolationForest | Mô hình chỉ học traffic bình thường, báo những flow trông "lạ" |
| PR (pull request) | Gửi code lên GitHub để người khác xem trước khi gộp vào `main` |
