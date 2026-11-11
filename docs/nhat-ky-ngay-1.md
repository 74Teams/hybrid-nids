# Nhật ký ngày 1 (10–11/11/2026): dữ liệu, bộ đo và baseline

Tài liệu này kể lại những gì đã làm trong ngày 1 của tuần 1 ([PLAN-009](plans/2026-11-10-labeled-eval-optimization.md), việc chi tiết ở [tuan-1-chi-tiet.md](tuan-1-chi-tiet.md)). Mỗi phần trả lời ba câu hỏi:

1. **Vấn đề là gì?**
2. **Đã thêm hoặc sửa gì, kèm ví dụ thật?**
3. **Việc đó giúp đạt mục tiêu nào của plan?**

## Tóm tắt trong một bảng

| Task | Kết quả | File chính | Test |
| :--- | :--- | :--- | --: |
| T0 | Dữ liệu sạch, nhánh sạch, plan được duyệt, issue #71 | `.gitignore`, `docs/plans/` | |
| T1 | Biết mỗi flow là tấn công gì | `tools/cic/labels.py` | 23 |
| T2 | Chia 49 đoạn pcap thành dev (luyện) và test (thi) | `tools/cic/manifest.py` | 15 |
| T3 | Một lệnh cho ra bảng đúng/sai; có số liệu baseline | `tools/eval/*.py`, `docs/eval/baseline.md` | 14 |

Tất cả nằm trên nhánh `feature/cic-eval-tools`, 4 commit, đã push lên GitHub:

```
702c976 docs(plans): add PLAN-009 labeled evaluation and system optimization plan (#71)
d156c9d chore: ignore large pcap files and SQLite WAL files (#71)
ac27b42 feat(eval): add CIC-IDS2017 label tools and labeled evaluation harness (#71)
fc230c6 docs(eval): add baseline measurement on Friday dev chunks (#71)
```

**Vì sao làm bộ đo trước khi sửa engine?** Mục tiêu của plan đều là con số, ví dụ "báo nhầm ≤ 2%" hay "độ chính xác ≥ 80%". Không có cách đo thì không biết đang ở đâu, cũng không biết sửa xong tốt lên hay tệ đi. Ngày 1 làm cái thước, ngày 2 mới dùng thước đó để sửa.

---

## T0. Dọn dữ liệu và nhánh git

### Vấn đề

Kiểm tra lúc đầu tìm ra ba chỗ sai:

| Chỗ sai | Hậu quả nếu để nguyên |
| :--- | :--- |
| Thư mục `split` chứa **hai bộ cắt chồng nhau**: 19 triệu gói, trong khi file gốc chỉ có 10 triệu | Mọi con số đếm gói, đếm flow bị nhân đôi một phần |
| Commit `tmp: create plan` chứa luôn `pcap/chienbuoito.pcap` (**54 MB**) | Đẩy file pcap lớn lên GitHub, repo nặng mãi mãi (git giữ cả lịch sử) |
| Nhánh tạo từ `main` cũ, chậm **11 commit** | PR sau này xung đột; bỏ lỡ bản sửa WAL của SQLite đã có trên `main` |

### Đã làm

**1. Cắt lại pcap** bằng `editcap -i 600` (mỗi file 10 phút), rồi kiểm tra tổng gói:

```
49 file, tổng gói: 9997874      ← đúng bằng Friday-WorkingHours.pcap gốc
```

**2. Gỡ commit `tmp` nhưng giữ file.** Lệnh `git reset --mixed HEAD~1` bỏ commit, còn mọi file vẫn nằm nguyên trên ổ đĩa. Commit cũ được giữ ở nhánh `backup/tmp-create-plan` phòng khi cần lấy lại.

**3. Dựng lại nhánh trên `main` mới nhất** bằng `git checkout -B feature/cic-eval-tools origin/main`.

**4. Chặn việc commit nhầm pcap về sau.** Thêm vào `.gitignore`:

```gitignore
*.db-wal
*.db-shm

# File pcap lớn (dữ liệu CIC, bản bắt tay); chỉ giữ pcap nhỏ dùng trong test
pcap/*.pcap
pcap/*.pcapng
!pcap/ipv4frags.pcap
```

Dòng `!pcap/ipv4frags.pcap` nghĩa là "trừ file này ra": pcap 3 KB dùng trong test vẫn được commit bình thường.

**5. Duyệt plan và tạo issue #71**, chuyển trạng thái plan sang `IN_PROGRESS`.

### Giúp đạt mục tiêu nào

Tiêu chí 9 (tái lập): người khác chạy lại phải ra cùng con số. Dữ liệu trùng hay nhánh lệch thì không ai chạy lại ra giống nhau được.

---

## T1. Module đọc nhãn: `tools/cic/labels.py`

### Vấn đề

Engine thấy flow: *"192.168.10.5 cổng 50000 nói chuyện với 205.174.165.73 cổng 8080 lúc 17:11 UTC"*. Nhưng engine **không biết** flow đó là tấn công hay bình thường. Câu trả lời nằm trong CSV của CIC, nên phải ghép flow của engine với dòng CSV tương ứng.

Khó ở chỗ hai bên ghi khác nhau:

| | Engine | CSV của CIC |
| :--- | :--- | :--- |
| Giờ | Epoch UTC, ví dụ `1499447460.0` | `7/7/2017 2:11`, kiểu 12 giờ, **không có AM/PM**, giờ Canada (UTC−3) |
| Chiều | Gói đi và gói về là cùng một flow | Ghi một chiều theo bên nào gửi trước |
| Nhãn | | Có ký tự lỗi mã hoá: `Web Attack \x96 Brute Force` |
| Độ đúng | | Có nhãn sai: flow của botnet bị ghi là BENIGN |

### Đã thêm

**1. Đổi giờ CSV sang UTC.** Giờ làm việc của dataset là 8h–17h, nên giờ 1..7 chắc chắn là buổi chiều:

```python
def parse_cic_timestamp(text: str) -> float:
    ...
    if not meridiem and hour < 8:     # "2:09" không có AM/PM → 14:09
        hour += 12
    return datetime(year, month, day, hour, minute, second, tzinfo=ADT).timestamp()   # ADT = UTC-3
```

Ví dụ chạy thật:

```
parse_cic_timestamp("7/7/2017 2:09")  →  2017-07-07 17:09:00 UTC
```

Phép tính: 2:09 → 14:09 giờ Canada → cộng 3 tiếng → 17:09 UTC.

**2. Dựng khoá flow giống hệt engine.** Engine sắp hai đầu `(IP, cổng)` theo thứ tự, nên gói đi và gói về có cùng khoá. Module làm y như vậy với dòng CSV:

```
cic_flow_key("205.174.165.73", 8080, "192.168.10.5", 50000, 6)
  → ('TCP', ('192.168.10.5', 50000), ('205.174.165.73', 8080))
```

Đảo chiều (`192.168.10.5` đứng trước) vẫn ra đúng khoá này.

**3. Gộp và sửa nhãn:**

```
group_label("Web Attack \x96 Brute Force")  →  "WebAttack"     (bỏ ký tự rác)
group_label("DoS Hulk")                     →  "DoS"
dòng có IP 205.174.165.73, CSV ghi BENIGN   →  "Bot"           (sửa nhãn sai, có ghi nguồn)
```

**4. Tra nhãn có dung sai.** CSV chỉ chính xác tới phút, nên một flow được nhận nhãn nếu có dòng CSV cùng khoá nằm trong khoảng *[đầu flow − 120 giây, cuối flow + 120 giây]*:

```
dòng CSV tấn công trong khoảng     → nhãn tấn công  (ví dụ "PortScan")
chỉ có dòng BENIGN                 → "BENIGN"
không có dòng nào                  → "UNLABELED"    (không tính vào số liệu)
```

### Kết quả trên dữ liệu thật (`chienbuoito.pcap`, đoạn 14:09–14:19)

| | Số flow |
| :--- | --: |
| Flow engine gom được | 7.697 |
| Có nhãn | 7.592 (**98,6%**) |
| PortScan | **118** (khớp phép đo ngày 10/11) |
| Bot, đã sửa từ BENIGN | 126 (đúng bằng số kết nối tới máy điều khiển) |

### Giúp đạt mục tiêu nào

Đây là nền cho mọi tiêu chí 3–7: không có nhãn thì không phân biệt được "báo đúng" và "báo nhầm".

---

## T2. Chia dev/test: `tools/cic/manifest.py`

### Vấn đề

Nếu dùng cùng một dữ liệu để vừa sửa rule vừa chấm điểm, ta sẽ vô tình chỉnh rule cho khớp đúng dữ liệu đó, và con số đẹp giả. Giống như học thuộc đề rồi đi thi chính đề đó. Vì vậy cần chia cố định:

- **dev** (để luyện): sửa rule, chỉnh ngưỡng, dạy AI thoải mái.
- **test** (để thi): chỉ chạy ở cuối tuần 2 và cuối tuần 3.

### Đã thêm

**1. Đọc nhanh 49 file pcap** (đọc byte thô, 8 tiến trình song song): 31 giây cho 10 triệu gói.

**2. Kiểm tra an toàn.** Nếu thư mục còn bộ cắt trùng như lần trước, công cụ dừng với thông báo:

```
fri_00001_..._190939.pcap và fri_00001_..._191928.pcap chồng thời gian: thư mục có hai bộ cắt khác nhau?
```

Tổng gói khác 9.997.874 cũng dừng. Không bao giờ chạy tiếp với dữ liệu sai.

**3. Gán dev/test theo giờ bắt đầu chunk** (giờ Canada):

```python
FRIDAY_TEST_STARTS = ("09:09", "14:59", "15:09", "15:19", "16:09", "16:29")
```

**4. Chọn máy botnet để thi.** Botnet chạy cả ngày trên 5 máy, nên không thể chia theo giờ. Công cụ chọn 2 máy có IP nhỏ nhất làm máy thi: `192.168.10.5` và `192.168.10.8`. Các máy này không được dùng khi luyện.

### Kết quả: `docs/eval/manifest.md`

Một đoạn của bảng:

```
| #  | Bắt đầu | Kết thúc | Tập      | Số gói    | BENIGN | PortScan | DDoS  | Bot |
| 35 | 14:49   | 14:59    | dev      | 417.945   | 10183  | 138493   | 0     | 42  |
| 36 | 14:59   | 15:09    | **test** | 115.613   | 8172   | 9029     | 0     | 42  |
| 43 | 16:09   | 16:19    | **test** | 529.191   | 20943  | 0        | 39567 | 37  |
```

Đọc bảng: đợt PortScan lớn nhất (14:49) nằm ở dev để luyện, còn các đợt sau (14:59, 15:09, 15:19) để thi.

Hai phát hiện từ bảng:

- Chunk test 09:09 không có Bot (botnet bắt đầu khoảng 10:04), nên chunk này chỉ dùng để đo báo nhầm.
- Chunk nhiều gói nhất là 09:19 (1,92 triệu gói), không phải 15:59 như plan dự đoán. Plan đã được sửa theo.

### Giúp đạt mục tiêu nào

Tiêu chí 5 và 6 đo trên tập test. Có cách chia cố định thì con số đó mới đáng tin, và giảng viên hỏi "có học tủ không" thì có câu trả lời.

---

## T3. Bộ đo và baseline: `tools/eval/`

### Vấn đề

Cần một lệnh cho mỗi rule biết: bắn bao nhiêu lần, bao nhiêu lần đúng, bao nhiêu lần nhầm.

### Đã thêm: 4 file, mỗi file một việc

```
runner.py    chạy engine trên một chunk:  gói → decode → rule → flow → ANOMALY
metrics.py   gắn nhãn flow, ghép cảnh báo với flow, đếm đúng/sai
report.py    in bảng Markdown
evaluate.py  dòng lệnh, chạy 12 chunk song song
```

**Ví dụ một cảnh báo đi qua bộ đo.** Ví dụ này là minh hoạ: cặp IP lấy từ cặp báo nhầm nhiều nhất của rule 1000205 trong baseline (`192.168.10.15 → 192.168.10.3:53`, 131 lần); cổng nguồn và giờ là giá trị ví dụ. Engine bắn rule 1000205 (UDP flood) cho gói `192.168.10.15:51234 → 192.168.10.3:53`:

```
1. Cảnh báo:  SID 1000205, 192.168.10.15:51234 → 192.168.10.3:53, lúc 10:15:02
2. Tìm flow:  cùng khoá (UDP, 192.168.10.15:51234, 192.168.10.3:53), đang sống lúc 10:15:02 → thấy
3. Nhãn flow: tra CSV → BENIGN (máy hỏi DNS bình thường)
4. Kết luận:  báo nhầm (FP)
```

Làm vậy với cả 140.601 cảnh báo rule thì ra cột "Bắt đúng" và "Báo nhầm" của từng rule.

### Ba lỗi bắt được khi làm, và cách sửa

**Lỗi 1, bộ biến (phản biện plan bắt được trước khi code).** Truyền `HOME_NET` thẳng vào `RuleManager` thì hàm này **thay hẳn** bộ biến, nên `$HTTP_PORTS` biến mất và 35 rule bị bỏ. Cách sửa là gộp với biến mặc định:

```python
variables = {**DEFAULT_RULE_VARIABLES, **overrides}   # mặc định + HOME_NET=192.168.10.0/24
decoder.HTTP_PORTS = http_ports(variables)            # decoder dùng cùng bộ biến
```

Kèm theo: bộ đo không đọc `settings.yaml` và `rules/state.yaml` của máy, nên hai người chạy trên hai máy ra cùng con số. Có một test riêng kiểm tra điều này (`test_result_does_not_depend_on_local_settings`).

**Lỗi 2, chấm ANOMALY quá dễ (phát hiện khi chạy thử).** Lúc đầu, cảnh báo ANOMALY được tính "bắt đúng Bot" chỉ cần dính **IP của máy nhiễm**. Nhưng máy nhiễm vẫn lướt web bình thường:

```
Trước:  cảnh báo ANOMALY từ máy nhiễm 192.168.10.14 tới một web server bình thường
        → chỉ cần dính IP 192.168.10.14 → tính là "bắt được Bot"            (sai)
Sau:    cặp IP (192.168.10.14, web server) không trùng flow tấn công nào
        → không có 205.174.165.73 trong cặp → tính là báo nhầm                 (đúng)
```

Chạy thử trên chunk 14:09, cách tính cũ ghi cả 3 máy nhiễm `.9`, `.14`, `.15` là "bị ANOMALY phát hiện". Với cách tính mới, baseline cho thấy ANOMALY chỉ bắt được Bot trên một máy (`.9`). Các phát hiện Bot còn lại đều do rule.

**Lỗi 3, giờ trong test quá ngắn.** Một chunk thử trong test chỉ dài 2 giây nên dòng CSV lúc 15:01 nằm ngoài. Đây là lỗi của test, không phải của code. Đã sửa test cho chunk dài như thật.

### Kết quả: baseline trên 43 chunk dev

Lệnh:

```powershell
python -m tools.eval.evaluate --labels-dir D:\Temp\Temp\TrafficLabelling_ --set dev --set-var HOME_NET=192.168.10.0/24 --name baseline --jobs 12
```

Chạy 1.470 giây (khoảng 24,5 phút) trên 8.078.211 gói. Kết quả đầy đủ ở [eval/baseline.md](eval/baseline.md).

| Đo gì | Kết quả | Ý nghĩa |
| :--- | --: | :--- |
| Flow bình thường bị rule báo | **52,3%** | Cứ 2 kết nối bình thường thì 1 bị nghi |
| Độ chính xác cảnh báo rule | **30,3%** | 10 cảnh báo thì 7 là giả |
| Độ chính xác cảnh báo ANOMALY | **4,0%** | Gần như toàn báo nhầm |
| Flow PortScan / DDoS bị báo | 99,7% / 98,8% | Đợt quét lớn thì rule bắt được |
| Flow Bot bị báo | 1,6% | Botnet gần như không bị phát hiện |
| Đợt PortScan 13:05 | không phát hiện | Đợt nhỏ lọt hoàn toàn |

Các rule gây báo nhầm nhiều nhất:

| SID | Rule | Cảnh báo | Báo nhầm | Bắt đúng | Nguyên nhân chính |
| :--- | :--- | --: | --: | --: | :--- |
| 1000205 | UDP flood | 80.546 | 69.426 | **0** | Máy hỏi DNS server `192.168.10.3` |
| 1000107 | SYN port scan | 55.562 | 14.183 | 37.615 | Trình duyệt mở nhiều kết nối |
| 1000209 | HTTP GET flood | 2.099 | 1.587 | 93 | Trang web tải nhiều file |
| 1000038 | Remote File Inclusion | 1.568 | 1.288 | 0 | Link quảng cáo dạng `?url=http...` |
| ANOMALY | Rare port | 1.163 | 1.016 | 5 | IPv6 multicast, LDAP nội bộ |

---

## Từ baseline tới mục tiêu: ngày 2 và tuần 2 sẽ sửa gì

| # | Tiêu chí | Hiện tại | Mục tiêu | Thay đổi sẽ làm | Ví dụ thay đổi |
| :- | :--- | :--- | :--- | :--- | :--- |
| 1 | Gói bị vứt khi đọc pcap | 86% (queue 10.000) | 0 | **T4**: đọc pcap mà hàng đợi đầy thì chờ, không vứt | `put_nowait(gói)` thành `put(gói, timeout=0.5)` trong vòng lặp |
| 2 | Tốc độ engine có ghi CSDL | 1.680 gói/giây | ≥ 3.000 | **T5**: ghi cảnh báo theo lô ở luồng riêng | 200 cảnh báo một lần `commit` thay vì 200 lần |
| 3 | Flow bình thường bị báo | 52,3% | ≤ 2% | **T6** (khoá chặn) và **tuần 2** (sửa 4 rule) | 1000205: không báo khi đích là DNS server cổng 53 |
| 4 | Độ chính xác rule | 30,3% | ≥ 80% | Tuần 2: sửa 1000205, 1000107, 1000209, 1000038 | 1000038: chỉ bắt khi tham số là `file=`, `page=`, `include=` |
| 5 | Phát hiện theo đợt | PortScan 4/5 | 100% | Tuần 2: chỉnh ngưỡng ANOMALY bằng dữ liệu | thử nhiều `scan.ports` trên dev, chọn bộ bắt đủ đợt 13:05 |
| 6–7 | AI | chưa có | F1 ≥ 0,90; bắt được Bot | Tuần 2–3: dạy AI trên flow có nhãn | Bot: 2 gói, cùng đích, lặp đều → AI nhận ra |
| 9 | Tái lập | chưa đạt | chạy lại ra cùng số | **T6**: threshold theo giờ của gói | xem ví dụ ngay dưới |

**Ví dụ vì sao cần T6.** Cùng một chunk 14:09, ba lần chạy cho ba kết quả khác nhau:

| Lần chạy | Số lần rule khớp | Số cảnh báo |
| :--- | --: | --: |
| Đo tay ngày 10/11 | 8.976 | 2.901 |
| Chạy thử bộ đo, 1 tiến trình | 8.976 | 2.923 |
| Baseline, 12 tiến trình | 8.976 | 3.008 |

Số lần rule khớp **luôn là 8.976**, nhưng số cảnh báo cứ thay đổi. Lý do là bộ chặn cảnh báo trùng tính theo **giờ máy tính**: máy chạy càng chậm thì "10 giây" trôi qua càng nhanh so với giờ trong pcap, nên càng nhiều cảnh báo lọt qua. T6 đổi sang **giờ của gói**, khi đó chạy bao nhiêu lần cũng ra cùng một số.

**Ví dụ vì sao cần đo tốc độ.** Chunk 09:19 có 1,92 triệu gói và chạy mất 1.461 trên tổng 1.470 giây. Các chunk khác xong từ lâu, chỉ còn chờ chunk này. Tốc độ đọc gói bằng Scapy (56% thời gian) đang là giới hạn lớn nhất. T7 thử bỏ bớt việc bóc giao thức thừa (đã đo trước: nhanh hơn khoảng 15%).

---

## Còn tồn tại

- Hai test WebSocket (`tests/api/test_realtime_ws.py`) fail chập chờn, kể cả trên `main` sạch. Đây là phần của nmchien1106 (PLAN-001), cần báo lại.
- Số cảnh báo trong baseline phụ thuộc tốc độ chạy (đã giải thích ở trên); các so sánh sau T6 nên dựa vào cột "Khớp trước threshold" và số liệu theo flow.
- `docs/huong-dan-chay.md` chưa commit, theo lựa chọn của bạn, sẽ đưa vào một nhánh docs riêng.
