# Lộ trình 3 tuần, bản dễ hiểu

Bản này tóm tắt plan chi tiết [PLAN-009](plans/2026-11-10-labeled-eval-optimization.md) bằng lời đơn giản. Muốn biết vì sao chọn cách làm nào thì đọc plan. Bản này là phần chung của cả nhóm: điểm chưa tốt, chia vai, điểm hẹn, dữ liệu. Việc từng ngày của mỗi người nằm ở [lo-trinh-A.md](lo-trinh-A.md) và [lo-trinh-B.md](lo-trinh-B.md).

**Cập nhật 11/11 (lần 2): đã chốt vai.**

- **A** là nldd0507. A làm rule, phần so khớp, engine, và **toàn bộ phần AI**.
- **B** là chiendev (nmchien1106). B làm bộ đo, ANOMALY, CSDL, API, CI và thử chạy live.
- Trong 2 tuần đầu (12–24/11), hai người chia nhau các việc tối ưu.
- Tuần cuối A làm AI. B làm tài liệu và lab demo, và chạy lại số liệu trên máy mình để kiểm tra kết quả lặp lại được.

Một người làm hết AI trong 7 ngày là quá sát, nên **phần AI không phụ thuộc kết quả tối ưu** (bộ đếm đặc trưng, khung worker chạy với mô hình giả) được A làm sớm ở cuối tuần 2. Dataset và huấn luyện vẫn để tuần cuối, sau khi engine đã ổn định.

## 1. Hiểu trong một phút

Hệ thống của mình giống một **camera an ninh cho mạng**: xem từng gói tin đi qua và kêu lên (cảnh báo) khi thấy dấu hiệu tấn công.

Tuần 1 (10–11/11) đã làm xong hai việc:

- **Làm cái thước đo:** cho engine xem pcap của CIC-IDS2017 rồi so với file nhãn CSV, ra bảng "đúng bao nhiêu, sai bao nhiêu" cho từng rule.
- **Sửa chỗ engine vứt gói:** trước bỏ 86% gói khi đọc pcap, giờ không bỏ gói nào, nhanh hơn 63–90%, và chạy lại lần nào cũng ra cùng kết quả.

Chi tiết ở [nhật ký ngày 1](nhat-ky-ngay-1.md) và [nhật ký ngày 2](nhat-ky-ngay-2.md).

Camera **vẫn còn kêu bậy nhiều**: một nửa số kết nối bình thường bị coi là tấn công. Vì vậy việc tiếp theo là **tối ưu phần so khớp** (rule và ANOMALY) trên cả 5 ngày dữ liệu, rồi tối ưu nốt các phần khác của hệ thống. AI làm sau cùng, khi hệ thống đã gọn và đo được chính xác AI giúp thêm được bao nhiêu.

## 2. Điểm chưa tốt hiện tại (xếp theo thứ tự sẽ sửa)

Số liệu đo ngày 10–11/11 trên 43 đoạn dev của thứ Sáu ([eval/sau-sua-engine.md](eval/sau-sua-engine.md)), trừ khi ghi khác. Cột "Ai" là người phụ trách theo lịch ở mục 6.

### Nhóm 1: so khớp và phát hiện (12–17/11)

| # | Điểm chưa tốt | Hậu quả | Số đo hiện tại | Ai |
| :-- | :--- | :--- | :--- | :-- |
| 1 | 4 rule có điều kiện quá rộng: 1000205 (UDP flood), 1000107 (SYN scan), 1000209 (HTTP GET flood), 1000038 (Remote File Inclusion) | Báo nhầm khi DNS server bận, khi trình duyệt mở nhiều kết nối, khi gặp link quảng cáo | **52,3%** flow bình thường bị rule báo; 1000205 có 1.339 cảnh báo, 0 đúng | A |
| 2 | ANOMALY "Rare port" coi traffic nội bộ bình thường là lạ | Báo nhầm hàng loạt với IPv6 multicast, LDAP (389), NetBIOS | Độ chính xác ANOMALY **2%** | B |
| 3 | Bỏ sót tấn công nhỏ và botnet | Đợt quét 13:05 lọt hoàn toàn; botnet gần như vô hình | PortScan **4/5** đợt; flow Bot bị báo **1,6%** | A (rule), B (ngưỡng ANOMALY) |
| 4 | Mới đo trên 1 ngày (thứ Sáu) | 24 rule web, rule dò mật khẩu, rule DoS **chưa từng được đo** trên traffic thật | chưa đo | A |
| 5 | Phần so khớp chưa được đo kỹ xem tốn thời gian ở đâu | Không biết rule hay bước nào làm chậm | "Rule + tái hợp TCP" chiếm 17,5% thời gian | A |
| 6 | Bộ đo: nhãn Infiltration (thứ Năm) bị gắn nhầm thành Bot | Số liệu thứ Năm sẽ sai | 70 dòng "Bot", 0 dòng Infiltration | A |
| 7 | Bộ đo: độ chính xác tính theo số cảnh báo bị cảnh báo trùng chi phối; chưa lưu danh sách cảnh báo | Con số khó hiểu (tụt 30,3% → 6,6% dù báo nhầm giảm mạnh); không kiểm tra được vì sao máy Bot `.14` lọt | | B |

### Nhóm 2: phần còn lại của hệ thống (18–24/11)

| # | Điểm chưa tốt | Hậu quả | Số đo hiện tại | Ai |
| :-- | :--- | :--- | :--- | :-- |
| 8 | Flow log vẫn ghi CSDL ngay trong luồng phân tích | CSDL bị khoá thì luồng phân tích đứng tới 30 giây; bắt gói trực tiếp sẽ rơi gói | lượt chạy 40 → 71 giây khi khoá CSDL 35 giây | A |
| 9 | Hai luồng (đọc gói và phân tích) tranh nhau CPU vì GIL của Python; Scapy chậm | Chưa đạt 3.000 gói/giây ở đoạn nhiều kết nối | 2.735 gói/giây (đoạn 14:09); 3.189 (đoạn 09:19) | A |
| 10 | `FlowTracker.expire` quét toàn bảng flow mỗi giây | Chậm khi bị flood (bảng tới 100.000 flow) | chưa đo | B |
| 11 | Chưa đo chế độ bắt gói trực tiếp (live) | Không biết khi demo thật có rơi gói không | chưa đo | B |
| 12 | Bảng `events` thiếu index, không bao giờ được dọn; trang thống kê gom nhóm cả bảng mỗi lần tải | Dashboard chậm dần khi chạy lâu | chưa đo | B |
| 13 | Test CI `test_realtime_ws.py` chập chờn | CI đỏ ngẫu nhiên, PR phải chạy lại | PR #72 fail lần đầu vì nó | B |

### Nhóm 3: AI (A làm toàn bộ; chuẩn bị 21–23/11, chính 25/11–01/12)

| # | Điểm chưa tốt | Hậu quả |
| :-- | :--- | :--- |
| 14 | AI chưa có (`nids/ai.py` là cái vỏ rỗng) | Không bắt được hành vi lạ mà rule không có chữ ký, ví dụ botnet |
| 15 | Flow chỉ lưu số gói, số byte, cờ TCP | Chưa đủ thông tin cho AI học |
| 16 | Dashboard chưa hiển thị cảnh báo AI | Khó demo phần AI |

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
Bước 1   Đo đủ 5 ngày, sửa lỗi bộ đo, đo kỹ phần so khớp                 (11–13/11)
Bước 2   Sửa 4 rule báo nhầm, sửa ANOMALY, thêm rule cho 4 ngày mới      (13–16/11)
Bước 3   Tăng tốc phần so khớp, đo lại cả 5 ngày                         (17/11)
Bước 4   Tối ưu engine, CSDL, API, CI; thử bắt gói trực tiếp             (18–20/11)
Bước 4b  A chuẩn bị AI: đặc trưng flow, khung worker với mô hình giả     (21–23/11)
Bước 5   Thi lần 1 trên tập test 5 ngày (chỉ rule và ANOMALY)            (24/11)
Bước 6   AI: dataset, huấn luyện, nạp mô hình thật vào engine            (25–29/11)
Bước 7   Thi lần cuối có AI, chạy thử demo                               (30/11–01/12)
```

**Vì sao bước 4b không làm hỏng quy tắc "AI làm cuối"?** Bước 4b chỉ thêm bộ đếm vào flow và dựng khung code. Công tắc `detection.enable_ai_worker` vẫn tắt, nên mọi số liệu rule và ANOMALY của lần thi 24/11 không đổi. Phần học từ dữ liệu (dataset, huấn luyện) vẫn chờ tới 25/11, khi engine đã ổn định.

## 5. Chia vai

| | **A: nldd0507** | **B: chiendev (nmchien1106)** |
| :--- | :--- | :--- |
| Tuần 1 (12–17/11) | Sửa nhãn và manifest 5 ngày, baseline 4 ngày, đo và sửa rule, tăng tốc so khớp | Dựng môi trường đo trên máy mình, bộ đo theo cặp IP, ANOMALY, sửa test CI |
| Tuần 2 (18–24/11) | Ghi flow ở luồng riêng, nguyên mẫu decoder đọc byte thô; từ 21/11 chuẩn bị AI | `FlowTracker.expire`, CSDL và API, thử live bằng `tcpreplay` |
| Tuần 3 (25/11–01/12) | **Toàn bộ AI**: dataset, huấn luyện, gắn vào engine, đo chi phí, báo cáo AI | Tài liệu, lab Docker và kịch bản demo, kiểm tra kết quả lặp lại được trên máy thứ hai, review PR AI |

Vì sao chia như vậy:

- **A có dữ liệu CIC trên máy** và đã viết bộ đo, nên các lượt đo dài trên 5 ngày (manifest, baseline, dataset) do A chạy.
- **B đã làm flow, Traffic và ANOMALY** (PLAN-004) và **realtime WebSocket** (PLAN-001), nên nhận ANOMALY, `FlowTracker.expire`, dashboard/API và test WebSocket chập chờn (test của chính PLAN-001).
- **Không đụng cùng file cùng lúc.** Hai việc cùng sửa `nids/engine/flow.py` là `FlowTracker.expire` (B) và bộ đếm đặc trưng (A): B mở PR ngày 19/11, A review và merge, A mới bắt đầu từ 21/11.

B vẫn còn PR #57 (PLAN-001) và #61 (PLAN-004) đang mở. Lịch dưới đây coi như B dành phần lớn thời gian cho PLAN-009. Nếu B phải ưu tiên hai PR kia thì cắt việc của B theo thứ tự ở cuối mục 6.

Mỗi việc lớn làm trên một nhánh git riêng và mở một **PR** (pull request: gửi code lên GitHub để người kia xem trước khi gộp vào `main`). Người này review PR của người kia.

## 6. Lịch

Lịch từng ngày tách thành hai file, mỗi người đọc file của mình:

- **[lo-trinh-A.md](lo-trinh-A.md)**: A (nldd0507), so khớp, engine, toàn bộ AI.
- **[lo-trinh-B.md](lo-trinh-B.md)**: B (chiendev), bộ đo, ANOMALY, CSDL, API, demo. Có phần chuẩn bị môi trường cho ngày đầu.

Tuần 1 (10–11/11) đã xong T0–T8, PR #72 và #73 đã merge. Xem [tuan-1-chi-tiet.md](tuan-1-chi-tiet.md).

### Lịch tóm tắt theo tuần

| Ngày | A (nldd0507) | B (chiendev) |
| :--- | :--- | :--- |
| 11–12/11 | Sửa nhãn (#74), manifest 5 ngày (#75), baseline 4 ngày, đo so khớp (#77) | Nhận dữ liệu, tái lập baseline thứ Sáu, sửa test CI (#89) |
| 13–15/11 | Sửa 4 rule báo nhầm (#78) | Bộ đo theo cặp IP (#76), bảng rule cho A, ANOMALY Rare port (#79) |
| 16–17/11 | Rule cho 4 ngày mới (#81), tăng tốc so khớp (#82) | Ngưỡng ANOMALY (#80) |
| 18–20/11 | Flow writer (#83), nguyên mẫu decoder byte thô (#85) | `FlowTracker.expire` (#84), đo API (#86), index và cache (#87) |
| 21–23/11 | Chuẩn bị AI: đặc trưng flow (#92), khung worker (#94) | Dọn `events` (#88), thử live (#90), tài liệu |
| 24/11 | **Thi lần 1** (#91) | **Thi lần 1** (#91) |
| 25–29/11 | AI: dataset, Random Forest, mô hình thật trong engine (#93, #94) | Lab Docker, kịch bản demo, báo cáo hệ thống, chạy lại dataset, review AI |
| 30/11–01/12 | **Thi lần cuối, demo** (#95) | **Thi lần cuối, demo** (#95) |

### Điểm hẹn giữa A và B

Các mốc mà một người phải chờ người kia. Trễ một mốc thì báo nhau ngay.

| Ngày | Ai giao | Giao gì | Để làm gì |
| :--- | :--- | :--- | :--- |
| 12/11 | A → B | Dữ liệu CIC (CSV nhãn, pcap thứ Sáu; cả 5 ngày trước 15/11), file manifest | B đo được trên máy mình |
| 12/11 | A → B | PR `feature/eval-five-days` (#74, #75, baseline 4 ngày) | B làm #76 trên đó |
| 14/11 | B → A | Bảng rule web, dò mật khẩu, DoS từ baseline 4 ngày | A thêm rule (#81) ngày 16/11 |
| 17/11 | cả hai | PR rule và PR ANOMALY | Đo dev 5 ngày → `docs/eval/sau-sua-so-khop.md` |
| 19/11 | B → A | PR #84 (`FlowTracker.expire`) đã merge | A sửa `flow.py` cho AI từ 21/11 |
| 20/11 | A | Chốt dùng hay bỏ decoder byte thô | Dataset AI ngày 25/11 dùng decoder cuối cùng |
| 28/11 | A → B | Lệnh chạy `build_dataset.py`, `train.py` | B kiểm tra số liệu AI lặp lại được trên máy thứ hai |

### Nếu bị trễ

Thứ tự cắt việc của từng người nằm cuối file của người đó. Không cắt: sửa 4 rule báo nhầm, ANOMALY, hai lần thi, Random Forest gắn vào engine.

### Issue trên GitHub

Mỗi việc có một issue (tạo ngày 11/11, thuộc PLAN-009 #71). Đóng issue bằng PR có dòng `Closes #số`.

| Giai đoạn | A (nldd0507) | B (nmchien1106) | Cả hai |
| :--- | :--- | :--- | :--- |
| So khớp và phát hiện (11–17/11) | [#74](https://github.com/74Teams/hybrid-nids/issues/74), [#75](https://github.com/74Teams/hybrid-nids/issues/75), [#77](https://github.com/74Teams/hybrid-nids/issues/77), [#78](https://github.com/74Teams/hybrid-nids/issues/78), [#81](https://github.com/74Teams/hybrid-nids/issues/81), [#82](https://github.com/74Teams/hybrid-nids/issues/82) | [#76](https://github.com/74Teams/hybrid-nids/issues/76), [#79](https://github.com/74Teams/hybrid-nids/issues/79), [#80](https://github.com/74Teams/hybrid-nids/issues/80), [#89](https://github.com/74Teams/hybrid-nids/issues/89) | |
| Phần còn lại của hệ thống (18–24/11) | [#83](https://github.com/74Teams/hybrid-nids/issues/83), [#85](https://github.com/74Teams/hybrid-nids/issues/85) | [#84](https://github.com/74Teams/hybrid-nids/issues/84), [#86](https://github.com/74Teams/hybrid-nids/issues/86), [#87](https://github.com/74Teams/hybrid-nids/issues/87), [#88](https://github.com/74Teams/hybrid-nids/issues/88), [#90](https://github.com/74Teams/hybrid-nids/issues/90) | [#91](https://github.com/74Teams/hybrid-nids/issues/91) |
| AI (21/11–01/12) | [#92](https://github.com/74Teams/hybrid-nids/issues/92), [#93](https://github.com/74Teams/hybrid-nids/issues/93), [#94](https://github.com/74Teams/hybrid-nids/issues/94) | | [#95](https://github.com/74Teams/hybrid-nids/issues/95) |

Gán người trên GitHub:

```powershell
gh issue edit 74 75 77 78 81 82 83 85 92 93 94 --repo 74Teams/hybrid-nids --add-assignee nldd0507
gh issue edit 76 79 80 84 86 87 88 89 90 --repo 74Teams/hybrid-nids --add-assignee nmchien1106
gh issue edit 91 95 --repo 74Teams/hybrid-nids --add-assignee nldd0507,nmchien1106
```

## 7. Ngày mai (12/11)

Xem mục "Ngày mai" cuối [lo-trinh-A.md](lo-trinh-A.md) và mục "Ngày đầu" cuối [lo-trinh-B.md](lo-trinh-B.md).

## 8. Dữ liệu 5 ngày và cách chia sẻ cho B

Pcap ở `D:\Tools\PBL4\` trên máy A, đã cắt 10 phút ở `D:\Tools\PBL4\split\` (thứ Sáu ở gốc thư mục, 4 ngày còn lại mỗi ngày một thư mục con). Các đợt tấn công đo từ file nhãn (giờ Canada):

| Ngày | Chunk bắt đầu lúc | Tấn công | Các đợt | Ý nghĩa |
| :--- | :--- | :--- | :--- | :--- |
| Thứ Hai | 08:55, 09:05, ... | Không có (chỉ traffic bình thường) | | Đo báo nhầm; dạy AI biết thế nào là "bình thường" |
| Thứ Ba | 08:53, 09:03, ... | Dò mật khẩu FTP, SSH | 09:17–10:21, 10:30–10:31, 14:09–15:12 | Đo rule `auth.rules` |
| Thứ Tư | 08:42, 08:52, ... | DoS (Hulk, GoldenEye, Slowloris, Slowhttptest), Heartbleed | 09:01–09:02, 09:48–10:38, 10:43–11:20, 14:24–14:26; Heartbleed 15:12–15:33 | Đo rule `dos.rules`. Heartbleed chỉ báo cáo vì engine chưa hiểu `byte_test` |
| Thứ Năm | 08:58, 09:08, ... | Tấn công web (dò mật khẩu, XSS, SQL injection), Infiltration | 09:15–10:01, 10:15–10:43; Infiltration buổi chiều | Lần đầu đo 24 rule `web-attack.rules` trên traffic thật |
| Thứ Sáu | 08:59, 09:09, ... | Botnet, PortScan, DDoS | xem [eval/manifest.md](eval/manifest.md) | Đã đo ở tuần 1 |

Mỗi ngày giữ phần sau của mỗi đợt tấn công làm tập test, cộng 1–2 chunk bình thường. Giờ chính xác được chốt khi A chạy manifest (#75), ghi vào `docs/eval/manifest-<ngày>.md`.

**B cần gì để chạy bộ đo:**

| Dữ liệu | Dung lượng | Cần cho việc |
| :--- | --: | :--- |
| `TrafficLabelling_` (8 file CSV nhãn) | 1,2 GB | mọi việc đo |
| `split\` thứ Sáu (49 file ở gốc thư mục) | khoảng 9 GB | 12–14/11: tái lập baseline, #76 |
| `split\` cả 5 ngày | 49 GB | 15–16/11: #79, #80 đo trên dev 5 ngày |
| `data\cic\*_manifest.json` | vài KB | mọi việc đo; chép kèm, hoặc B tự chạy `tools.cic.manifest` (kết quả tất định nên phải giống của A) |

Chép bằng ổ cứng ngoài hoặc chia sẻ qua mạng LAN. File manifest JSON ghi đường dẫn `split_dir` theo máy A, nên trên máy B luôn truyền `--split-dir` khi chạy `tools.eval.evaluate`. **Nếu không chép kịp 49 GB trước 15/11**, B chỉnh ANOMALY trên dev thứ Sáu, còn A chạy lượt đo 5 ngày giúp B và gửi file kết quả.

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
| Tái lập | Người khác, máy khác chạy lại cùng lệnh vẫn ra cùng con số |
| GIL | Khoá của Python: mỗi lúc chỉ một luồng được chạy code Python, nên hai luồng cùng tốn CPU phải thay phiên nhau |
| Index | "Mục lục" của bảng CSDL, giúp tìm và gom nhóm nhanh mà không phải đọc cả bảng |
| Đặc trưng (feature) | Các con số mô tả một flow (bao lâu, bao nhiêu gói, gói dài bao nhiêu...) để AI học |
| Mô hình giả | Một đối tượng nhỏ viết trong test, có hàm `predict` trả kết quả định sẵn, để thử worker AI khi chưa huấn luyện mô hình thật |
| Random Forest | Mô hình học từ ví dụ có nhãn, đoán flow thuộc loại tấn công nào |
| IsolationForest | Mô hình chỉ học traffic bình thường, báo những flow trông "lạ" |
| PR (pull request) | Gửi code lên GitHub để người khác xem trước khi gộp vào `main` |
