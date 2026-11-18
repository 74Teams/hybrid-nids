# Kịch bản báo cáo hàng tuần với giảng viên

Kịch bản cho buổi báo cáo tiến độ. Gồm ba phần:

1. **Cách chạy dự án**: trong lab Docker, và bằng file traffic thật (pcap của CIC-IDS2017).
2. **Những gì đã làm trong 3 tuần qua** (24/10–11/11): của nhóm và của riêng nldd0507, kèm cách demo, bảng so sánh và cách giải thích.
3. **Hướng phát triển 1 tháng cuối** (12/11–12/12).

Mỗi phần có **Nói** (ý chính), **Làm** (lệnh) và **Thấy** (kết quả mong đợi). Mục "Giải thích cho thầy" gợi ý cách nói những chỗ dễ hiểu nhầm. Bản chi tiết hơn của từng phần:

- [kich-ban-demo.md](kich-ban-demo.md): toàn bộ đòn tấn công trong lab;
- [thuyet-trinh-tuan-1.md](thuyet-trinh-tuan-1.md): chi tiết tuần 10–11/11.

| Phần | Thời gian |
| :--- | --: |
| 1. Chạy dự án: lab Docker | 6 phút |
| 1. Chạy dự án: file thật | 5 phút |
| 2. Đã làm được gì | 8 phút |
| 3. Kế hoạch 1 tháng cuối | 3 phút |
| Hỏi đáp | 5 phút |

---

## Phần 1. Cách chạy dự án

### 1.0 Hệ thống gồm những gì (nói trước khi chạy, 1 phút)

**Nói:** Hybrid NIDS là hệ thống phát hiện xâm nhập mạng. "Hybrid" vì kết hợp ba cách phát hiện:

| Cách | Bắt được gì | Ví dụ |
| :--- | :--- | :--- |
| **Rule chữ ký** (68 rule, cú pháp Snort 3) | Tấn công đã biết, có dấu hiệu rõ trong gói tin | `union select` trong URL, cờ TCP lạ của nmap |
| **Phát hiện bất thường theo ngưỡng** (ANOMALY) | Hành vi lạ không có chữ ký | Một máy chạm 15 cổng trong 5 giây |
| **Honeypot** SSH và HTTP | Kẻ tấn công chắc chắn, vì không ai hợp lệ dùng honeypot | Đăng nhập SSH vào cổng 2222 |

Thấy IP đáng ngờ thì hệ thống **chuyển hướng** IP đó sang honeypot. Mọi thứ hiện trên dashboard theo thời gian thực.

Mỗi thành phần là một process riêng, chỉ nói chuyện qua CSDL chung:

```
               ┌─────────────┐
 gói tin ────▶ │   engine    │──┐
               └─────────────┘  │
 honeypot SSH, HTTP ────────────┼──▶  CSDL  ──▶  API + dashboard
 redirector (iptables) ◀────────┘     (MySQL hoặc SQLite)
```

### 1.1 Chạy trong lab Docker (5 phút)

Lab là một mạng ảo cô lập, gồm máy tấn công Kali, máy nạn nhân nginx, engine, honeypot, MySQL, Redis và dashboard.

**Chuẩn bị (từ hôm trước):**

```powershell
copy .env.example .env               # điền 3 mật khẩu (MYSQL_ROOT_PASSWORD, NIDS_DB_PASSWORD, NIDS_REDIS_PASSWORD)
docker compose up --build -d
docker logs nids_engine              # phải có "Đã nạp 68 rule" và "Lắng nghe trực tiếp"
```

Mở [http://localhost:8000](http://localhost:8000), bấm **Xoá dữ liệu**.

**Trình diễn:**

| # | Nói | Làm | Thấy |
| :- | :--- | :--- | :--- |
| 1 | Traffic bình thường không bị báo | `docker exec -it nids_attacker curl -s -o /dev/null -w "%{http_code}\n" http://172.28.0.50/` | `200`, dashboard 0 cảnh báo |
| 2 | Tấn công web thật qua HTTP | `docker exec -it nids_attacker python lab/attacker/attack_demo.py web` | Cảnh báo SQLi, XSS, Log4Shell... hiện ngay trên dashboard (đẩy qua WebSocket) |
| 3 | Quét cổng bằng nmap | `docker exec -it nids_attacker nmap -sX -p 80 172.28.0.50` | SID 1000100 (Xmas scan) |
| 4 | Quét chậm lọt rule nhưng không lọt ANOMALY | `docker exec -it nids_attacker nmap -sS -p 1000-1030 --max-rate 8 172.28.0.50` | Trang Logs, tab Anomaly: `ANOMALY Port scan` |
| 5 | IP tấn công bị đẩy sang honeypot | `docker exec nids_attacker curl -s http://172.28.0.50/` | Trả về trang đăng nhập WordPress **giả**, thay cho nginx thật |
| 6 | Kẻ tấn công vào "máy" SSH giả | `docker exec -it nids_attacker ssh -p 2222 root@172.28.0.50`, mật khẩu bất kỳ, gõ `whoami`, `exit` | Tab Honeypot SSH: một dòng "Phiên SSH", bấm vào thấy từng lệnh. Lệnh **không được chạy thật** |
| 7 | Xem traffic theo flow | Trang Status › Traffic | Bảng flow (ai nói với ai, bao nhiêu gói), tab "Chưa khớp rule" |

Hết giờ thì chạy một lệnh: `docker exec -it nids_attacker python lab/attacker/attack_demo.py all --delay 0.5`.

**Giải thích cho thầy:** lab chứng minh **chuỗi xử lý chạy đủ**, từ bắt gói tới phát hiện, chuyển hướng và hiển thị. Nhưng lab gần như không có traffic bình thường, nên chưa chứng minh được hệ thống **báo đúng** trên mạng thật. Đó là lý do có cách chạy thứ hai.

**Tắt lab:** `docker compose down`.

### 1.2 Chạy bằng file traffic thật (5 phút)

Dữ liệu là **CIC-IDS2017** của Viện An ninh mạng Canada:

- 5 ngày traffic của một mạng công ty mô phỏng (thứ Hai đến thứ Sáu, khoảng 56 triệu gói);
- có tấn công thật xen giữa traffic bình thường;
- **file CSV ghi rõ từng kết nối là tấn công loại gì**. Nhờ file này mới biết hệ thống đúng hay sai.

Pcap của mỗi ngày đã cắt thành các đoạn 10 phút (`D:\Tools\PBL4\split\`).

**Cách A: engine thật đọc file, xem kết quả trên dashboard**

Chạy engine ở chế độ offline (đọc file thay vì bắt gói), ghi vào SQLite, rồi mở dashboard local đọc cùng CSDL đó.

1. Trong `config/settings.yaml`:
   ```yaml
   network:
     capture_mode: "offline"
     pcap_file: "D:/Tools/PBL4/split/fri_00031_20170708000939.pcap"   # thứ Sáu 14:09–14:19, có đợt quét cổng
   detection:
     queue_max_size: 10000
   database:
     type: "sqlite"
     db_url: "sqlite:///./nids_events.db"
   ```
2. Terminal 1, chạy dashboard local (tắt lab Docker trước vì trùng cổng 8000):
   ```powershell
   uvicorn nids.api.main:app --port 8000
   ```
3. Terminal 2, chạy engine:
   ```powershell
   python -m nids.engine
   ```

**Thấy:**

- Khoảng 40 giây sau, terminal 2 in:
  ```
  Hoàn tất: 106955 gói, 251 cảnh báo (P1: 143, P2: 57, P3: 51) trong ~39 giây (~2735 gói/giây)
  ```
- Không có dòng `Queue đầy` nào.
- Dashboard hiện cảnh báo trên traffic thật: quét cổng của `172.16.0.1`, nhưng cũng có rất nhiều cảnh báo nhầm, ví dụ DNS và link quảng cáo.

**Cách B: bộ đo có nhãn, so với đáp án**

```powershell
python -m tools.eval.evaluate --labels-dir D:\Temp\Temp\TrafficLabelling_ --chunks 14:09 --jobs 1 --set-var HOME_NET=192.168.10.0/24 --name demo-1409 --report-dir data\eval\demo --data-dir data\eval\demo
```

Chạy khoảng 30 giây, ra báo cáo `data\eval\demo\demo-1409.md`. Kết quả thật ngày 11/11:

| Câu hỏi | Kết quả |
| :--- | :--- |
| Đợt quét cổng 14:14 có bị phát hiện không? | **Có**, cảnh báo đầu tiên sau **3,8 giây** |
| Bao nhiêu flow quét cổng bị rule báo? | 13/118 (11%) |
| Bao nhiêu flow **bình thường** bị báo nhầm? | 2.652/5.594 (**47,4%**) |
| 3 máy nhiễm botnet có bị phát hiện không? | **Không** máy nào |
| Rule báo nhầm nhiều nhất | 1000038 (RFI): 40 lần nhầm, 0 lần đúng, toàn là link quảng cáo |

**Cách C: đo cả 5 ngày một lượt** (chạy nền 1–2 giờ, không demo trực tiếp)

```powershell
python -m tools.eval.evaluate --manifest data\cic\monday_manifest.json --manifest data\cic\tuesday_manifest.json --manifest data\cic\wednesday_manifest.json --manifest data\cic\thursday_manifest.json --manifest data\cic\friday_manifest.json --labels-dir D:\Temp\Temp\TrafficLabelling_ --set dev --set-var HOME_NET=192.168.10.0/24 --name baseline-5-ngay
```

Báo cáo `docs/eval/baseline-5-ngay.md` có bảng **Theo ngày**. Đây là lần đầu rule web, DoS và brute force được đo trên traffic thật. Lệnh này cần code của nhánh `feature/eval-five-days`.

**Giải thích cho thầy:** cách A là "hệ thống chạy thật trông như thế nào", cách B và C là "hệ thống đúng bao nhiêu phần trăm". Từ giờ, mọi thay đổi đều được chấm bằng cách B/C: đo trước, sửa, đo lại, so hai con số.

**Sau khi demo,** trả `settings.yaml` về như cũ nếu cần chạy lab.

---

## Phần 2. Những gì đã làm trong 3 tuần qua

### 2.1 Cả nhóm (24/10–11/11): 34 pull request đã merge

**Nói:** nhóm 3 người, mỗi việc đi qua một pull request có review và CI chạy test tự động. Hiện có hơn 600 test.

| Tuần | Đã làm được | Ai |
| :--- | :--- | :--- |
| **24–31/10**: dựng nền | Rule chỉ đọc từ file, chuẩn hoá cú pháp Snort 3, bộ 68 rule, lab Kali + victim nhiều dịch vụ | nmchien1106 |
| | Gộp honeypot vào NIDS, làm giàu cảnh báo từ IP đã chạm honeypot | nmchien1106 |
| | Giao diện kiểu pfSense: trang Logs, trang Rules (bật/tắt category và SID, sửa `custom.rules`), biểu đồ | nmchien1106 |
| | Gom code vào package `nids/`, CI chạy pytest cho mỗi PR, xoá mật khẩu khỏi repo | nmchien1106 |
| | Honeypot SSH có shell và hệ thống file giả, nhớ trạng thái giữa các lệnh | ngoccu2006 |
| | Lưu giờ theo UTC; gom gói thành **flow** và ghi flow log | nldd0507 |
| **01–07/11**: tính năng chính | Đẩy cảnh báo thời gian thực qua Redis + WebSocket; gom sự kiện honeypot theo phiên | nmchien1106 |
| | API flow, trang Traffic; **phát hiện bất thường theo ngưỡng** (ANOMALY); sửa decoder giữ payload DNS | nmchien1106 |
| | Nhận diện công cụ SSH của kẻ tấn công (HASSH); **chuyển hướng IP đáng ngờ sang honeypot** bằng iptables | ngoccu2006 |
| | **Tái hợp luồng TCP** (bắt chuỗi tấn công bị chia qua nhiều gói); **so khớp header rule** theo IP, cổng, biến (`$HOME_NET`...); sửa lấy payload từ tầng 4 | nldd0507 |
| **08–11/11**: ổn định và đo thật | Giới hạn tài nguyên honeypot (cap kết nối, timeout); honeypot HTTP ghi mọi request | ngoccu2006 |
| | SQLite chờ khoá và bật WAL; hướng dẫn cài trên Linux; plan lab 3 máy ảo VMware | nmchien1106 |
| | **Bộ đo có nhãn CIC-IDS2017**; **sửa engine** (hết vứt gói, ghi theo lô, chặn cảnh báo trùng theo giờ gói, Scapy chỉ bóc tới tầng 4); lộ trình 3 tuần | nldd0507 |

**Giải thích cho thầy:** hai tuần đầu là **xây đủ chức năng** (phát hiện, honeypot, phản ứng, giao diện). Tuần thứ ba chuyển sang **đo chất lượng**, vì đủ chức năng chưa có nghĩa là dùng được.

### 2.2 Phần của nldd0507

**Tuần 1–2: tính năng engine**

| Việc | Vấn đề trước đó | Cách demo |
| :--- | :--- | :--- |
| Flow log (#54) | Chỉ lưu gói có cảnh báo, không biết traffic tổng thể | Trang Traffic: mỗi kết nối là một dòng, có số gói, số byte, cờ TCP |
| So khớp header rule (#60) | Rule ghi `any any` cho mọi thứ, không dùng được `$HOME_NET`, dải cổng, danh sách IP | Mở `rules/dos.rules`, chỉ `$HTTP_PORTS`; trên trang Rules, lưu một rule sai cú pháp cổng thì bị báo lỗi theo dòng |
| Tái hợp luồng TCP (#58) | Chuỗi tấn công chia qua hai gói thì rule không thấy | Test `tests/engine/test_stream.py`: `union` ở gói 1, `select` ở gói 2 vẫn bị bắt |
| Giờ UTC (#53), payload tầng 4 (#64) | Lệch giờ giữa các process; payload lấy sai ở vài loại gói | (chỉ nói) |

**Tuần 3 (10–11/11): đo trên traffic thật và sửa engine**

**Nói:** đem engine ra đo trên 10 phút traffic thật thì thấy 4 vấn đề. Sửa xong, đo lại:

| Vấn đề | Trước | Sau | Sửa bằng cách nào |
| :--- | --: | --: | :--- |
| Vứt gói khi đọc file | 86% | **0%** | Đọc file thì chờ hàng đợi có chỗ, không vứt |
| Tốc độ | 1.680 gói/giây | **2.735–3.189** | Scapy chỉ bóc tới tầng 4; ghi cảnh báo theo lô ở luồng riêng |
| Chạy lại cùng file ra cùng kết quả | 2.901 / 2.923 / 3.008 cảnh báo | **251 / 251** | Bộ chặn cảnh báo trùng tính theo giờ của gói, không theo giờ máy |
| Cảnh báo gửi người trực (8 triệu gói dev) | 140.601 | **5.103** (−96%) | Gộp cảnh báo trùng theo đúng kiểu đếm của rule |
| Số lần rule khớp | 659.984 | **659.984** | Không đổi: chứng tỏ sửa engine không làm sai việc phát hiện |
| Flow bình thường bị báo nhầm | 52,3% | 52,3% | **Chưa sửa**, đây là việc tuần sau |

**Ngày 11/11 (trên nhánh, chưa merge):**

| Việc | Kết quả |
| :--- | :--- |
| Lập dev/test cho 4 ngày còn lại | Tổng gói khớp file gốc cả 4 ngày |
| Tìm ra lỗi nhãn | Cùng một IP dùng cho cả botnet (thứ Sáu) lẫn Infiltration (thứ Năm); đã sửa quy tắc |
| Bộ đo đo được 5 ngày một lượt | Không hết RAM, nhờ chỉ giữ flow có cảnh báo |
| Đo phần so khớp tốn thời gian ở đâu | Scapy tốn 34 giây, so khớp chỉ 5,8 giây trên 10 phút traffic |
| Tăng tốc so khớp | 5,8 → **2,7 giây**; kết quả khớp giống hệt từng gói (so bằng mã băm) |

### 2.3 Cách nói để thầy hiểu

**Ba con số phải phân biệt.** Nên viết lên bảng hoặc để trên slide:

| Tên | Câu hỏi nó trả lời | Ví dụ đoạn 14:09 |
| :--- | :--- | :--- |
| **Độ phủ** (recall) | Trong các kết nối tấn công, bắt được bao nhiêu? | 13/118 flow quét cổng = 11% |
| **Tỉ lệ báo nhầm** (FPR) | Trong các kết nối bình thường, báo nhầm bao nhiêu? | 2.652/5.594 = 47% |
| **Độ chính xác** (precision) | Trong các cảnh báo đưa ra, bao nhiêu là đúng? | 9/104 cảnh báo rule = 8,7% |

**Ví dụ đời thường:** hệ thống giống một **chuông báo trộm**.

- Độ phủ thấp: trộm vào mà chuông không kêu.
- Báo nhầm cao: mèo đi qua chuông cũng kêu.
- Độ chính xác thấp: 10 lần chuông kêu thì 9 lần là mèo, nên chủ nhà sẽ tắt chuông.

Chuông hiện tại kêu với cả mèo. Việc tuần sau là chỉnh cho bớt nhạy với mèo mà vẫn kêu khi có trộm.

**Vì sao làm thước đo trước khi sửa?** "Không sửa theo cảm giác". Ví dụ thật: em đoán CSDL làm engine chậm, đo lại thì tắt hẳn CSDL chỉ nhanh hơn 4 giây trên 51 giây. Nếu sửa theo đoán thì đã sửa sai chỗ.

**Vì sao chia dev/test?** Giống ôn thi: dev là đề luyện, dùng thoải mái. Test là đề thi, chỉ mở 2 lần (24/11 và 30/11). Nhìn đề thi rồi chỉnh rule thì điểm đẹp nhưng không thật.

**Vì sao có con số tệ đi?** Độ chính xác tính theo số cảnh báo tụt từ 30% xuống 6,6% sau khi sửa. Trước đó, **một** kẻ tấn công bị báo lặp lại hàng chục nghìn lần nên làm con số đẹp giả. Giờ cảnh báo trùng được gộp lại nên con số phản ánh đúng thực tế. Bộ đo đã có thêm cách đếm theo cặp IP để không bị đánh lừa.

**Chủ động nói chỗ yếu, đừng đợi thầy hỏi:** báo nhầm còn 47–52%, botnet chưa bắt được, ANOMALY mới đúng khoảng 2%. Nói ngay sau đó là đã có kế hoạch và con số mục tiêu (Phần 3).

---

## Phần 3. Hướng phát triển 1 tháng cuối (12/11–12/12)

Kế hoạch chi tiết là [PLAN-009](../plans/2026-11-10-labeled-eval-optimization.md), lịch theo ngày ở [lo-trinh-A.md](../lo-trinh-A.md) và [lo-trinh-B.md](../lo-trinh-B.md). Tuần 4 là đề xuất thêm; chưa có trong plan.

| Tuần | Trọng tâm | Việc chính | Ai |
| :--- | :--- | :--- | :--- |
| **1 (12–17/11)** | **Đúng hơn** | Sửa 4 rule báo nhầm nhiều nhất; sửa ANOMALY coi traffic nội bộ là lạ; thêm rule cho tấn công thứ Ba–Năm (brute force, Slowloris, web); đo trên đủ 5 ngày | nldd0507 (rule), nmchien1106 (ANOMALY, bộ đo) |
| **2 (18–24/11)** | **Nhanh và bền hơn** | Ghi flow ở luồng riêng; thử bắt gói trực tiếp; index và dọn bảng cảnh báo cho dashboard; sửa test CI chập chờn. **Thi lần 1** ngày 24/11 | cả hai |
| **3 (25/11–01/12)** | **Thông minh hơn: AI** | Trích ~30 đặc trưng mỗi flow; dataset 5 ngày; **Random Forest** bắt botnet mà rule không thấy; gắn vào engine. **Thi lần cuối** ngày 30/11 | nldd0507 (toàn bộ AI); nmchien1106 (lab, demo, kiểm tra lặp lại) |
| **4 (02–12/12)** | **Hoàn thiện để bảo vệ** | Lab 3 máy ảo VMware (PLAN-008); viết báo cáo cuối từ `docs/eval/`; slide; tập demo 2 lần | ngoccu2006 (lab VMware), cả nhóm |

**Mục tiêu bằng con số** (đo trên tập test, PLAN-009 mục 2):

| Chỉ số | Hiện tại | Mục tiêu |
| :--- | --: | --: |
| Gói bị vứt khi đọc file | 0% | 0% (đã đạt) |
| Tốc độ engine | 2.735–3.189 gói/giây | ≥ 3.000 |
| Flow bình thường bị rule báo nhầm | 52,3% | ≤ 2% |
| Độ chính xác cảnh báo rule | 6,6% | ≥ 80% |
| Đợt tấn công bị phát hiện | 4/5 đợt quét cổng | 100% đợt quét cổng, DDoS, máy botnet |
| AI: macro F1 (BENIGN, PortScan, DDoS, Bot) | chưa có | ≥ 0,90, báo nhầm ≤ 1% |

**Nói:** thứ tự là **đúng → nhanh → thông minh**. Làm AI trước khi rule và engine ổn thì AI học trên dữ liệu sai. Làm sau thì đo được chính xác AI giúp thêm bao nhiêu, ví dụ "rule bắt 0/3 máy botnet, AI bắt 3/3".

**Rủi ro và cách lo** (nếu thầy hỏi):

| Rủi ro | Cách lo |
| :--- | :--- |
| Không kịp | Đã xếp sẵn việc cắt được: nguyên mẫu decoder mới, IsolationForest, thử live. Không cắt: sửa rule, hai lần thi, AI Random Forest |
| Nhãn CIC có chỗ sai | Sửa theo bài báo đã công bố; báo cáo luôn in cả nhãn gốc lẫn nhãn đã sửa |
| AI chỉ học từ một bộ dữ liệu | Ghi rõ giới hạn; dữ liệu 5 ngày có 7 loại tấn công, nhiều hơn mức tối thiểu |
| Python chậm (GIL, Scapy) | Đã đo và biết chính xác chỗ chậm; tuần 2 thử hai cách, chỉ đưa vào cách nào đo thấy lợi |

---

## Hỏi đáp thường gặp

**Khác gì Snort thật?** Rule cùng cú pháp Snort 3, nhưng engine tự viết bằng Python và hiểu một tập con option. Điểm mạnh của dự án nằm ở phần kết hợp (honeypot, chuyển hướng, ANOMALY, AI) và ở việc đo được bằng số trên traffic thật.

**Vì sao không dùng thẳng bộ rule community của Snort?** Đã thử trên đoạn 14:09:

- 3.230/3.570 rule community dùng option engine chưa hỗ trợ (`byte_test`, `flowbits`...). Engine bỏ qua option đó, nên rule bị "nới lỏng".
- Kết quả: cảnh báo trên traffic bình thường tăng từ 2.927 lên **64.361**. Ví dụ rule tấn công IGMP bắn 9.018 lần, trong khi đoạn này không có tấn công IGMP nào.

Chi tiết ở `docs/danh-gia-bo-rule.md` mục 4.5. Muốn bật community thì phải cài thêm option cho engine trước.

**Bao lâu thì chạy được ngoài lab thật?** Tuần 2 sẽ thử bắt gói trực tiếp với traffic phát lại ở tốc độ thật. Tuần 4 dựng lab 3 máy ảo (Kali, IDS gateway, victim) giống mạng thật hơn Docker.

**Mỗi người làm gì?** Xem bảng 2.1. Từ 12/11: nldd0507 làm rule, so khớp, engine và AI; nmchien1106 làm bộ đo, ANOMALY, CSDL, API, CI; ngoccu2006 làm honeypot và lab VMware.
