# Kịch bản thuyết trình: Hybrid NIDS và kết quả tuần 10–11/11

Kịch bản cho buổi báo cáo với giảng viên và nhóm. Gồm 3 phần:

1. Dự án là gì và chạy như thế nào (có demo lab Docker).
2. Những gì đã làm trong tuần này (PLAN-009, tuần 1).
3. Demo phần tuần này: đo engine trên traffic thật có nhãn.

Mỗi bước ghi **Nói** (ý chính, không cần đọc nguyên văn), **Làm** (lệnh hoặc thao tác) và **Thấy** (kết quả mong đợi). Kịch bản demo lab đầy đủ, kèm bảng lệnh tấn công thủ công, nằm ở [kich-ban-demo.md](kich-ban-demo.md).

| Phần | Nội dung | Thời gian |
| :--- | :--- | --: |
| 1 | Tổng quan dự án | 3 phút |
| 2 | Chạy dự án: demo lab Docker | 7 phút |
| 3 | Việc đã làm tuần này | 6 phút |
| 4 | Demo phần tuần này | 4 phút |
| 5 | Kết luận, việc tiếp theo, hỏi đáp | 5 phút |

---

## 0. Chuẩn bị (làm từ tối hôm trước)

**Lab Docker** (cho phần 2):

1. Mở Docker Desktop, chờ "Engine running".
2. Chạy `docker compose build`, rồi `docker compose up -d`. Đợi khoảng 30 giây cho MySQL sẵn sàng.
3. Kiểm tra: `docker logs nids_engine` có dòng `Đã nạp 68 rule` và `Lắng nghe trực tiếp`.
4. Mở [http://localhost:8000/](http://localhost:8000/), góc trên phải báo "Đã kết nối". Bấm **Xoá dữ liệu**.
5. Chạy thử nhanh: `docker exec -it nids_attacker python lab/attacker/attack_demo.py web --delay 0.2`, thấy cảnh báo hiện ra, rồi bấm **Xoá dữ liệu** lần nữa.

**Demo đo** (cho phần 4), trên máy có dữ liệu CIC-IDS2017:

1. Kiểm tra có đủ dữ liệu:
   - `D:\Tools\PBL4\split\fri_00031_20170708000939.pcap`: chunk 14:09 thứ Sáu, 107.996 gói.
   - `D:\Temp\Temp\TrafficLabelling_\` (8 file CSV nhãn).
   - `data\cic\friday_manifest.json`.
2. Sửa `config/settings.yaml` để engine đọc file pcap:
   ```yaml
   network:
     capture_mode: "offline"
     pcap_file: "D:/Tools/PBL4/split/fri_00031_20170708000939.pcap"
   detection:
     queue_max_size: 10000     # giá trị mặc định; trước khi sửa engine, giá trị này làm vứt 86% gói
   database:
     type: "sqlite"
     db_url: "sqlite:///./nids_events.db"
   ```
   **Chú ý:** `settings.yaml` local hiện đặt `queue_max_size: 10000000` và trỏ tới `pcap/chienbuoito.pcap`, mà file này không còn trong `pcap/`. Phải sửa cả hai dòng.
3. Chạy thử phần 4 một lần cho máy "nóng" (đọc đĩa lần đầu chậm hơn).
4. Mở sẵn trong VS Code hai báo cáo dự phòng: [eval/baseline.md](../eval/baseline.md) và [eval/sau-sua-engine.md](../eval/sau-sua-engine.md).

**Màn hình:** trình duyệt dashboard bên trái; bên phải là terminal `docker logs -f nids_engine` và một terminal PowerShell ở thư mục gốc repo.

---

## 1. Tổng quan dự án (3 phút)

**Nói:**

- **Bài toán.** Hệ thống phát hiện xâm nhập mạng (NIDS): xem từng gói tin đi qua và cảnh báo khi thấy dấu hiệu tấn công.
- **"Hybrid"** vì có ba nguồn phát hiện:
  1. **Rule chữ ký** theo cú pháp Snort 3. Có 68 rule, chia 6 nhóm: web, scan, DoS, brute force, mã độc/C2, recon.
  2. **Phát hiện bất thường theo ngưỡng** (ANOMALY), bắt thứ rule bỏ sót, ví dụ quét cổng chậm.
  3. **Honeypot SSH và HTTP**: không ai hợp lệ chạm vào honeypot, nên IP nào chạm vào là kẻ tấn công chắc chắn.
- **Phản ứng:** IP có nhiều cảnh báo P1/P2 bị **chuyển hướng sang honeypot** bằng iptables, trong một thời gian giới hạn.
- **Giao diện:** web console xem cảnh báo theo thời gian thực, tra log, xem traffic và quản lý rule kiểu pfSense.

**Làm:** mở sơ đồ trong `README.md` (mục "Project diagram").

**Nói (kiến trúc):**

- Mỗi thành phần là **một process riêng**: engine, API và dashboard, honeypot SSH, honeypot HTTP, redirector. Chúng chỉ nói chuyện qua CSDL chung. Khởi động lại dashboard không làm engine ngừng bắt gói.
- Đường đi của một gói trong engine:

  ```
  bắt gói (Scapy) → decode L2–L4 + HTTP → hàng đợi → phễu so khớp 4 tầng → chặn cảnh báo trùng → CSDL
  ```

  Phễu so khớp 4 tầng:
  1. Lọc theo protocol và cổng.
  2. **Aho-Corasick**: tìm mọi chuỗi mẫu trong một lần duyệt payload.
  3. Kiểm tra chi tiết (content, pcre, flags, `detection_filter`).
  4. Bộ chặn cảnh báo trùng.
- Cảnh báo mới được đẩy lên dashboard qua Redis pub/sub và WebSocket trong chưa tới một giây. Redis chết thì dashboard tự quay về poll 2 giây.

**Công nghệ** (nếu được hỏi): Python 3, Scapy, pyahocorasick, SQLAlchemy (MySQL trong Docker, SQLite khi chạy local), FastAPI, paramiko, Flask/waitress, Redis, Docker Compose, pytest; CI chạy pytest cho mọi PR.

---

## 2. Chạy dự án: demo lab Docker (7 phút)

Mạng Docker cô lập `172.28.0.0/16`: victim nginx `172.28.0.50`, attacker Kali `172.28.0.100`, dashboard [http://localhost:8000](http://localhost:8000).

| Bước | Nói | Làm | Thấy |
| :--- | :--- | :--- | :--- |
| 2.1 Bình thường | Truy cập web bình thường thì không có cảnh báo | `docker exec -it nids_attacker curl -s -o /dev/null -w "%{http_code}\n" http://172.28.0.50/` | In `200`, dashboard vẫn 0 cảnh báo |
| 2.2 Tấn công web | SQLi, XSS, path traversal, Log4Shell... gửi bằng HTTP thật | `docker exec -it nids_attacker python lab/attacker/attack_demo.py web` | Mỗi đòn một dòng log có màu; SID khớp "kỳ vọng SID" của attacker; dashboard tăng theo thời gian thực |
| 2.3 Quét mạng | Rule dựa trên cờ TCP: Xmas, Null, FIN, SYN scan | `docker exec -it nids_attacker nmap -sX -p 80 172.28.0.50` | SID 1000100 |
| 2.4 Bất thường | Quét chậm 8 cổng/giây lọt dưới ngưỡng rule, nhưng lớp ANOMALY bắt được | `docker exec -it nids_attacker nmap -sS -p 1000-1030 --max-rate 8 172.28.0.50` | Trang Logs, tab Anomaly: một dòng `ANOMALY Port scan` |
| 2.5 Chuyển hướng | Sau đợt tấn công web, IP attacker bị đẩy sang honeypot | `docker exec nids_attacker curl -s http://172.28.0.50/ \| head -5` | Trả về trang đăng nhập WordPress giả thay vì trang nginx; `curl http://localhost:8000/api/redirects/` có `172.28.0.100` |
| 2.6 Honeypot SSH | Kẻ tấn công tưởng vào được máy thật | `docker exec -it nids_attacker ssh -p 2222 -o StrictHostKeyChecking=no root@172.28.0.50`, mật khẩu bất kỳ, gõ `ls`, `whoami`, `exit` | Trang Logs, tab Honeypot SSH: một dòng "Phiên SSH"; bấm vào thấy từng lệnh. Lệnh **không hề được chạy** |
| 2.7 Tổng kết | Thống kê theo P1/P2/P3, top loại tấn công, top IP; API có tài liệu tự sinh | Mở dashboard, rồi [http://localhost:8000/docs](http://localhost:8000/docs) | |

**Hết giờ thì** chạy một lệnh: `docker exec -it nids_attacker python lab/attacker/attack_demo.py all --delay 0.5`.

**Chuyển ý sang phần 3 (nói):** "Lab chạy tốt. Nhưng lab gần như không có traffic bình thường, nên chưa biết hệ thống có dùng được trên mạng thật không. Tuần này em đem nó ra đo trên traffic thật."

---

## 3. Việc đã làm tuần này (6 phút)

### 3.1 Phát hiện vấn đề (10/11)

**Nói:** em cho engine đọc 10 phút traffic thật của bộ dữ liệu **CIC-IDS2017** (thứ Sáu, 14:09–14:19). Bộ này có sẵn file CSV ghi rõ kết nối nào là tấn công. Kết quả rất tệ:

| Vấn đề | Số đo |
| :--- | :--- |
| Engine **vứt gói** khi hàng đợi đầy, kể cả khi đọc file | 91.836 / 106.955 gói bị vứt (**86%**) |
| **Báo nhầm**: kết nối bình thường bị coi là tấn công | **49%** flow bình thường bị rule báo |
| **Bỏ sót** | Chỉ bắt 13 / 118 flow quét cổng; botnet: 0 cảnh báo |
| **Không lặp lại được** | Chạy cùng file 3 lần: 2.901, 2.923, 3.008 cảnh báo |

**Nói:** kết luận là chưa thể "sửa cho tốt hơn", vì chưa có cách đo tốt hay dở. Nên em làm theo thứ tự: **làm thước đo trước, rồi mới sửa**. Mọi thay đổi đều phải có con số trước và sau.

Kế hoạch 3 tuần là PLAN-009 (issue #71), qua phản biện 2 vòng trước khi duyệt.

### 3.2 Thước đo: bộ đo có nhãn (PR #72)

**Nói:**

- **Module đọc nhãn** (`tools/cic/labels.py`). CSV của CIC có hai bẫy:
  - giờ kiểu 12 tiếng **không có AM/PM** (`2:09` nghĩa là 14:09);
  - giờ Canada (UTC−3).

  Ghép flow của engine với CSV theo IP, cổng, giờ thì khớp **99,2%** số flow.
- **Sửa nhãn sai đã biết** của CIC: flow botnet gọi về máy điều khiển bị ghi là BENIGN (Engelen và cộng sự, 2021).
- **Chia dev/test** (`tools/cic/manifest.py`):
  - 49 đoạn pcap 10 phút;
  - dev để luyện; test để thi, chỉ chạy 2 lần trong cả 3 tuần, để con số không bị "đẹp giả";
  - máy nhiễm botnet chia theo máy, không theo giờ.
- **Bộ đo** (`tools/eval/evaluate.py`): một lệnh chạy đúng pipeline của engine trên nhiều đoạn song song (16 nhân), ra bảng đúng/sai theo lớp, theo rule và theo đợt tấn công.

### 3.3 Sửa engine (PR #73)

| Sửa gì | Vì sao | Kết quả |
| :--- | :--- | :--- |
| Đọc pcap mà hàng đợi đầy thì **chờ** chứ không vứt | Đọc file không cần vội | Vứt gói: 86% → **0** |
| **Ghi cảnh báo theo lô** (tối đa 200 cảnh báo hoặc 1 giây) ở luồng riêng | Trước đây mỗi cảnh báo một lần `commit`, ngay trong luồng phân tích | CSDL bị khoá 35 giây: engine vẫn chạy hết file, chỉ mất đúng lô bị lỗi |
| **Bộ chặn cảnh báo trùng** tính theo giờ của gói và theo kiểu đếm của rule | Gói DNS trả lời có cổng ngẫu nhiên nên không bao giờ bị gộp; tính theo giờ máy nên mỗi lần chạy một khác | Cùng file: **251 cảnh báo, lần nào cũng vậy**; rule UDP flood 2.192 → 34 |
| **Scapy chỉ bóc tới tầng 4** | Decoder không cần DNS, TLS... | Đọc gói nhanh gấp đôi (26,5 → 12,8 giây); sửa luôn lỗi đếm byte sai ở 117 gói |

**Nói (phát hiện bất ngờ):** em đoán CSDL làm chậm engine, nhưng đo lại thì tắt hẳn CSDL chỉ nhanh hơn 4 giây trên 51 giây. Nút thắt thật là **GIL của Python** (luồng đọc gói và luồng phân tích phải thay phiên nhau) và **Scapy**. Đo xong mới biết, đoán là sai.

### 3.4 Kết quả trên 43 đoạn dev (8 triệu gói)

| | Trước | Sau |
| :--- | --: | --: |
| Tốc độ engine thật | 1.680 gói/giây | 2.735 (đoạn 14:09), 3.189 (đoạn 09:19) |
| Thời gian chạy bộ đo | 1.470 giây | 922 giây (−37%) |
| Số lần rule khớp | 659.984 | **659.984** (giống hệt: sửa engine không làm đổi việc phát hiện) |
| Cảnh báo rule gửi người trực | 140.601 | **5.103** (−96%) |
| Flow bình thường bị báo | 52,3% | 52,3% (chưa đổi: phần này sửa ở tuần 2) |

**Nói (trung thực về chỗ chưa tốt):**

- Độ chính xác tính theo số cảnh báo tụt 30,3% → 6,6% dù báo nhầm giảm mạnh. Lý do: con số này bị cảnh báo trùng của **một** kẻ tấn công chi phối, nên em bổ sung cách đếm theo cặp IP (mục 3.6).
- Một máy botnet không còn bị phát hiện, vì cảnh báo về nó bị gộp chung với cảnh báo nhầm ngay trước đó.

Cả hai đều đã ghi vào plan để xử lý tiếp.

### 3.5 Lộ trình và chia việc (PR #96, #97)

**Nói:** lộ trình sắp lại theo hướng **tối ưu so khớp trước, AI làm cuối**, khi hệ thống đã ổn định:

- em (người A) làm rule, so khớp, engine và toàn bộ phần AI;
- chiendev (người B) làm bộ đo, ANOMALY, CSDL, API, CI;
- lịch từng ngày ở `docs/lo-trinh-A.md` và `docs/lo-trinh-B.md`; mỗi việc là một issue (#74–#95).

### 3.6 Đang làm (11/11, trên nhánh, chưa merge)

| Issue | Việc | Kết quả |
| :--- | :--- | :--- |
| #74 | Sửa nhãn Infiltration | Kiểm tra dữ liệu thấy IP `205.174.165.73` dùng cho cả botnet thứ Sáu lẫn Infiltration thứ Năm (36 dòng Infiltration, 34 dòng BENIGN). Quy tắc sửa nhãn giờ chỉ áp dụng cho dòng BENIGN của thứ Sáu |
| #75 | Manifest thứ Hai–Năm | Tổng gói khớp file gốc cả 4 ngày (11,7 / 11,6 / 13,8 / 9,3 triệu gói); chọn chunk test là phần sau của mỗi đợt tấn công |
| #76 | Bộ đo theo cặp IP, xuất danh sách cảnh báo, đo nhiều ngày một lượt | Đo được cả 5 ngày trong một lệnh mà không hết RAM (chỉ giữ flow có cảnh báo) |
| #77 | Đo phần so khớp tốn thời gian ở đâu | Đoạn 14:09: decode (Scapy) 34,4 giây, so khớp chỉ 5,8 giây; 46% thời gian so khớp là dựng lại danh sách rule ứng viên ở mỗi gói |
| #82 | Tăng tốc so khớp | Đoạn 14:09: so khớp 5,84 → **2,7 giây (−54%)**. Mã băm kết quả khớp giống hệt trước và sau trên 4 đoạn (thứ Ba FTP, thứ Tư DoS, thứ Năm web, thứ Sáu 14:09). Riêng đoạn FTP thứ Ba đo lúc máy đang bận chạy baseline, số giây chưa tin được, phải đo lại khi máy rảnh |

**Nói:** "Mã băm" là dấu vân tay của toàn bộ kết quả khớp, tức gói nào khớp rule nào. Hai bản code cho cùng mã băm nghĩa là tăng tốc **không làm đổi một kết quả nào**.

Nếu lượt baseline 5 ngày (`docs/eval/baseline-5-ngay.md`) đã xong trước buổi báo cáo, mở thêm bảng **Theo ngày** trong file đó: lần đầu tiên rule web, DoS và brute force được đo trên traffic thật.

---

## 4. Demo phần tuần này (4 phút)

### 4.1 Engine không còn vứt gói (khoảng 1 phút)

**Nói:** chạy engine thật trên đoạn 14:09, hàng đợi mặc định 10.000, ghi SQLite. Trước khi sửa, cấu hình này vứt 86% gói.

**Làm:**

```powershell
python -m nids.engine
```

**Thấy:** khoảng 40 giây sau có dòng tổng kết, và **không có** dòng `Queue đầy` nào:

```
Hoàn tất: 106955 gói, 251 cảnh báo (P1: 143, P2: 57, P3: 51) trong ~39 giây (~2735 gói/giây)
```

Chạy lại lần nữa (nếu còn thời gian) vẫn ra đúng **251** cảnh báo.

### 4.2 Bộ đo có nhãn (khoảng 2 phút)

**Nói:** cùng đoạn đó, nhưng giờ so với nhãn của CIC để biết đúng sai.

**Làm:**

```powershell
python -m tools.eval.evaluate --labels-dir D:\Temp\Temp\TrafficLabelling_ --chunks 14:09 --jobs 1 --set-var HOME_NET=192.168.10.0/24 --name demo-1409 --report-dir data\eval\demo --data-dir data\eval\demo
```

**Thấy:** dòng cuối in FPR flow BENIGN và độ chính xác cảnh báo rule. Mở `data\eval\demo\demo-1409.md`, chỉ vào 3 bảng:

1. **Theo lớp:** bao nhiêu flow PortScan bị bắt, bao nhiêu flow bình thường bị báo nhầm.
2. **Theo rule:** 4 rule 1000205, 1000107, 1000209, 1000038 gây gần hết báo nhầm. Đây là việc tuần sau.
3. **Theo đợt tấn công:** đợt PortScan 14:14 có được phát hiện không, sau bao nhiêu giây.

`--report-dir data\eval\demo` để báo cáo của buổi demo không lẫn vào `docs/eval/`.

### 4.3 (Tuỳ chọn) Tăng tốc mà không đổi kết quả

Chỉ chạy được trên nhánh `feature/rule-precision-cic` (worktree `..\hybrid-nids-rules`), vì phần này chưa merge.

```powershell
python -m tools.eval.profile_rules --pcap D:\Tools\PBL4\split\fri_00031_20170708000939.pcap --set-var HOME_NET=192.168.10.0/24
```

**Thấy:** `So khớp: 2.7 giây, 8976 lần khớp, mã băm dd7aa66a...`, cùng mã băm với bản trước khi tối ưu (5,8 giây).

### Nếu demo hỏng

Mở [eval/sau-sua-engine.md](../eval/sau-sua-engine.md) và [nhat-ky-ngay-2.md](../nhat-ky-ngay-2.md), trình bày bảng trước/sau thay cho chạy thật.

---

## 5. Kết luận và việc tiếp theo (2 phút)

**Nói:**

- **Đã có:**
  - hệ thống chạy đủ chuỗi trong lab: phát hiện, honeypot, chuyển hướng, dashboard thời gian thực;
  - một thước đo trên traffic thật có nhãn, chạy lại bằng một lệnh;
  - engine hết vứt gói và cho kết quả lặp lại được.
- **Chưa tốt:** báo nhầm vẫn cao (52% flow bình thường), ANOMALY chỉ đúng 2%, botnet gần như vô hình.
- **Tuần sau (12–17/11):**
  - sửa 4 rule báo nhầm, sửa ANOMALY;
  - thêm rule cho tấn công các ngày thứ Ba–Năm;
  - đo trên đủ 5 ngày.
- **Tuần 2 (18–24/11):** ghi flow ở luồng riêng, tăng tốc CSDL và API, thử bắt gói trực tiếp. **Thi lần 1** trên tập test ngày 24/11.
- **Tuần 3 (25/11–01/12):** AI (Random Forest trên đặc trưng flow) để bắt botnet mà rule không thấy. **Thi lần cuối** ngày 30/11.

---

## 6. Câu hỏi có thể gặp

**Vì sao chọn CIC-IDS2017?** Có cả pcap (gói thật) lẫn nhãn từng flow, nên đo được đúng/sai mà không phải tự gán nhãn. Bộ này phổ biến trong các bài báo, nên so sánh được.

**Nhãn của CIC có đúng không?** Không hoàn toàn: đã có bài báo chỉ ra nhãn sai (Engelen và cộng sự, 2021). Bộ đo sửa các lỗi đã biết, và báo cáo luôn in cả nhãn gốc lẫn nhãn đã sửa. Hôm nay còn tìm thêm một lỗi trong chính quy tắc sửa nhãn của nhóm (#74).

**Vì sao chia dev/test, mà test chỉ chạy 2 lần?** Nếu vừa nhìn kết quả test vừa chỉnh rule thì rule được chỉnh "theo đề", con số đẹp nhưng không phản ánh thực tế. Test giống đề thi: chỉ mở ở mốc đã định.

**Vì sao độ chính xác lại tụt sau khi sửa?** Vì nó đếm theo số cảnh báo. Trước khi sửa, một kẻ tấn công bị báo lặp lại hàng chục nghìn lần nên làm con số "đẹp". Bộ chặn mới gộp cảnh báo trùng nên con số phản ánh đúng hơn. Bộ đo giờ có thêm độ chính xác theo cặp IP và theo flow để đánh giá công bằng.

**Sao không làm AI ngay?** AI học từ đặc trưng flow do engine tính ra. Engine còn vứt gói hay tính sai byte thì AI học trên dữ liệu sai. Làm engine đúng trước, AI sau. Có số đo trước và sau thì cũng chứng minh được AI giúp thêm bao nhiêu.

**Engine nhanh cỡ nào, có đủ chạy thật không?** Khoảng 2.700–3.200 gói/giây trên một máy, đủ cho lab và mạng nhỏ. Nút thắt là Scapy và GIL của Python. Hướng tiếp theo đã có số đo: decoder đọc byte trực tiếp hoặc tách thành hai process (tuần 2).

**Đo có lặp lại được không?** Có. Bộ chặn cảnh báo giờ tính theo giờ của gói, nên chạy lại ra cùng con số. Manifest chia dev/test được sinh tất định từ code. Tuần cuối, thành viên thứ hai sẽ chạy lại trên máy khác để xác nhận.
