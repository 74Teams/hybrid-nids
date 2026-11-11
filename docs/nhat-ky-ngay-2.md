# Nhật ký ngày 2 (11/11/2026): sửa engine

Tài liệu này kể lại ngày 2 của tuần 1 ([PLAN-009](plans/2026-11-10-labeled-eval-optimization.md), việc chi tiết ở [tuan-1-chi-tiet.md](tuan-1-chi-tiet.md)), viết giống [nhật ký ngày 1](nhat-ky-ngay-1.md). Mỗi phần trả lời ba câu hỏi:

1. **Vấn đề là gì?**
2. **Đã thêm hoặc sửa gì, kèm ví dụ thật?**
3. **Việc đó giúp đạt mục tiêu nào của plan?**

## Tóm tắt trong một bảng

| Task | Kết quả | File chính | Test mới |
| :--- | :--- | :--- | --: |
| T4 | Đọc pcap không vứt gói; worker chết hay gói lỗi đều không làm treo engine | `nids/engine/main.py`, `capture.py` | 7 |
| T5 | Cảnh báo ghi theo lô ở thread riêng; dòng tổng kết có tốc độ | `nids/engine/alert_writer.py`, `nids/db/repository.py` | 10 |
| T6 | Bộ chặn cảnh báo trùng tính theo giờ gói và theo kiểu đếm của rule | `nids/engine/threshold.py`, `detector.py`, `anomaly.py` | 9 |
| T7 | Scapy chỉ bóc tới L4: nhanh hơn, và đếm byte đúng | `nids/engine/capture.py` | 2 |
| T8 | Đo lại, so với baseline, mở 2 PR | `docs/eval/sau-sua-engine.md` | |

Kết quả chính, đo bằng engine thật trên `chienbuoito.pcap` (107.996 gói, hàng đợi 10.000, SQLite):

| | Trước (`main`) | Sau ngày 2 |
| :--- | --: | --: |
| Gói được phân tích | 15.119 (vứt 86%) | **106.955** (đủ) |
| Tốc độ | 1.680 gói/giây (khi đặt queue 10 triệu để khỏi vứt gói) | **2.735 gói/giây** |
| Số cảnh báo | 2.901, 2.923 hoặc 3.008 tuỳ lần chạy | **251, lần nào chạy cũng vậy** |
| Cảnh báo rule 1000205 (UDP flood) | khoảng 2.192 | **34** |

Hai nhánh, đã push và mở PR:

```
feature/cic-eval-tools (công cụ đo, ngày 1)
  702c976 docs(plans): add PLAN-009 labeled evaluation and system optimization plan (#71)
  d156c9d chore: ignore large pcap files and SQLite WAL files (#71)
  ac27b42 feat(eval): add CIC-IDS2017 label tools and labeled evaluation harness (#71)
  fc230c6 docs(eval): add baseline measurement on Friday dev chunks (#71)
  c7f18c0 feat(eval): decode like the engine when the Scapy layer filter exists (#71)
  f3c5ff0 docs: add day-1 work log for PLAN-009 week 1 (#71)

feature/engine-alert-writer (sửa engine, ngày 2)
  44b6c2b feat(engine): write alerts in batches and stop dropping packets offline (#71)
  7430eaf fix(engine): suppress alerts by packet time and detection_filter track (#71)
  b2cecba perf(engine): limit Scapy dissection to L2-L4 layers (#71)
  0a5ef3d chore: keep large pcap files out of the Docker build context (#71)
  203d826 docs(engine): document batched alert writes and packet-time suppression (#71)
```

---

## T4. Đọc pcap không vứt gói

### Vấn đề

Engine có hai luồng (thread): một luồng đọc gói rồi bỏ vào **hàng đợi**, một luồng (worker) lấy ra phân tích. Code cũ dùng `put_nowait`: hàng đợi đầy là vứt gói ngay. Khi bắt gói trực tiếp thì đúng là phải vậy, vì mạng không chờ ai. Nhưng khi **đọc file pcap** thì không có lý do gì phải vội: file vẫn nằm đó, chờ một chút cũng được.

Ngoài ra có hai chỗ có thể làm engine treo hoặc chết:

- Một gói lỗi (exception) làm chết luôn worker.
- Worker chết thì `packet_queue.join()` chờ mãi mãi, vì không còn ai đánh dấu "đã xử lý xong".

### Đã sửa

**1. Hàm `enqueue_packet`**: live và offline xử lý khác nhau.

```python
if live:
    try:
        packet_queue.put_nowait(packet)     # live: đầy thì bỏ và đếm, như cũ
        return True
    except queue.Full:
        ...
while not stop_event.is_set():              # offline: chờ chỗ trống
    try:
        packet_queue.put(packet, timeout=0.5)
        return True
    except queue.Full:
        if not worker_alive():              # worker chết thì thôi, không chờ mãi
            stop_event.set()
```

Vì sao chờ có `timeout=0.5` mà không chờ vô hạn? Trên Windows, một lệnh chờ không giới hạn sẽ không ngắt được bằng Ctrl+C. Chờ từng nửa giây thì cứ 0,5 giây chương trình lại "tỉnh dậy" một lần để kiểm tra Ctrl+C và kiểm tra worker còn sống không.

**2. Hàm `wait_until_processed`** thay cho `packet_queue.join()`: chờ worker xử lý hết, nhưng dừng nếu worker đã chết.

**3. Worker bắt lỗi từng gói**: một gói lỗi chỉ được ghi log (gộp đếm, không in cả trăm dòng), worker xử lý tiếp gói sau.

### Ví dụ

Test `test_offline_small_queue_processes_every_packet` cho engine đọc pcap 200 gói với hàng đợi **chỉ 2 chỗ**, và worker cố ý chạy chậm:

```
Trước: phần lớn gói bị vứt, log "Queue đầy, đã bỏ ... gói"
Sau:   "Hoàn tất: 200 gói ..." và không có dòng "Queue đầy" nào
```

Hai test còn lại: cho mọi gói đều lỗi (engine vẫn chạy hết và báo "200 gói bị bỏ qua vì lỗi khi phân tích"), và cho worker chết ngay từ đầu (engine dừng trong vài giây với log "Worker thread đã dừng, ngừng đọc pcap" thay vì treo mãi).

### Giúp đạt mục tiêu nào

Tiêu chí 1: gói bị vứt khi đọc pcap từ 86% xuống **0**.

---

## T5. Ghi cảnh báo theo lô ở luồng riêng

### Vấn đề

Mỗi cảnh báo được ghi vào CSDL ngay trong worker: mở session, `commit`, đóng session. Worker phải đứng chờ CSDL xong mới phân tích gói tiếp.

### Đã thêm

**`nids/engine/alert_writer.py`, lớp `AlertWriter`.** Worker chỉ việc bỏ cảnh báo vào một hàng đợi riêng. Thread `alert-writer` gom tối đa **200 cảnh báo, hoặc chờ tối đa 1 giây**, rồi ghi tất cả trong **một lần `commit`**:

```
Trước:  200 cảnh báo = 200 session + 200 commit, worker chờ cả 200 lần
Sau:    200 cảnh báo = 1 session + 1 commit, ở thread khác, worker không chờ
```

**`EventRepository.save_alerts(batch)`**: ghi một lô, trả về id, rồi mới gọi `publish_alert` cho từng id (giữ đúng luật "publish sau khi commit").

**Thứ tự tắt engine** khi đọc hết pcap: dừng worker (ghi nốt flow) → `AlertWriter.close()` (ghi nốt cảnh báo) → mới in dòng tổng kết. Nhờ vậy ai đọc CSDL ngay sau khi engine dừng cũng thấy đủ dữ liệu.

**Dòng tổng kết có tốc độ:**

```
Hoàn tất: 106955 gói, 251 cảnh báo (P1: 143, P2: 57, P3: 51) trong 39.1 giây (2735 gói/giây)
```

### Thử CSDL bị khoá giữa chừng

Cho engine chạy, sau 4 giây khoá CSDL 35 giây từ một chương trình khác. SQLite chờ khoá tối đa 30 giây rồi báo lỗi:

```
Không thể lưu 521 flow vào CSDL: (sqlite3.OperationalError) database is locked
Không thể lưu 6 cảnh báo vào CSDL: (sqlite3.OperationalError) database is locked
Hoàn tất: 106955 gói, 251 cảnh báo ... trong 71.2 giây
```

Trong CSDL còn 245 cảnh báo (= 251 − 6) và 7.176 flow (= 7.697 − 521): chỉ mất đúng hai lô bị lỗi, engine đọc hết pcap, không dừng, hết khoá thì ghi tiếp bình thường.

### Một điều bất ngờ: CSDL không phải nút thắt chính

Hôm qua mình đoán việc ghi CSDL làm engine chậm. Đo lại bằng cách tắt bớt từng phần:

| Thí nghiệm | Thời gian |
| :--- | --: |
| Đầy đủ | 51,5 giây |
| Không ghi CSDL | 47,8 giây |
| Không ghi CSDL, không in cảnh báo ra màn hình | 47,8 giây |
| Chạy tuần tự trong một luồng (đo ngày 10/11) | 30,5 giây |

Tắt hẳn CSDL chỉ nhanh hơn 4 giây. Phần chậm hơn chạy tuần tự đến từ **GIL** của Python: luồng đọc gói và worker đều cần CPU, nhưng Python chỉ cho một luồng chạy code Python tại một thời điểm, nên hai luồng phải thay phiên nhau. Vì vậy T5 vẫn cần (worker không còn phải chờ CSDL khi tấn công dồn dập, nhất là khi bắt gói trực tiếp), nhưng muốn nhanh hơn nữa thì phải giảm việc của Scapy. Đó là T7.

### Một lỗi trong test bắt được nhờ T5

Sau T5, một test cũ thỉnh thoảng mất vài flow. Nguyên nhân: test dùng SQLite trong bộ nhớ với `StaticPool`, tức **một kết nối dùng chung cho mọi thread**. Giờ flow (worker) và cảnh báo (`alert-writer`) được ghi từ hai thread; thread này đóng session thì rollback luôn phần đang ghi dở của thread kia. Khi chạy thật, mỗi session có kết nối riêng nên không bị. Đã đổi các test chạy `main.main()` sang **SQLite dạng file**; chạy 5 lần liền đều xanh.

### Giúp đạt mục tiêu nào

Tiêu chí 1 (không mất cảnh báo khi đọc pcap) và quy tắc của dự án "lỗi CSDL không được làm sập sensor".

---

## T6. Sửa bộ chặn cảnh báo trùng

### Vấn đề

Bộ chặn (`ThresholdManager`) có nhiệm vụ: cùng một cảnh báo lặp lại trong 10 giây thì chỉ báo một lần. Nó có hai lỗi:

**Lỗi 1, khoá chặn có cổng đích.** Rule 1000205 (UDP flood) đếm theo máy đích (`track by_dst`). Gói DNS trả lời đi tới **cổng ngẫu nhiên** của máy hỏi, nên mỗi gói là một khoá mới và không bao giờ bị chặn:

```
khoá cũ:  (1000205, 192.168.10.3, 192.168.10.1, 61777)   ← cổng đổi mỗi gói
          (1000205, 192.168.10.3, 192.168.10.1, 61778)   ← khoá mới, lại báo
          ...
khoá mới: (1000205, -, 192.168.10.1, -)                   ← theo máy đích, cổng không quan trọng
```

**Lỗi 2, tính theo giờ máy tính.** Cửa sổ "10 giây" là 10 giây của đồng hồ máy, không phải của gói tin. Đọc file pcap thì 10 phút traffic có thể trôi qua trong 40 giây, nên số cảnh báo phụ thuộc máy chạy nhanh hay chậm.

### Đã sửa

```python
def _key(sid, src_ip, dst_ip, dst_port, track):
    if track == "by_dst":
        return (sid, None, dst_ip, None)      # flood: theo đích
    if track == "by_src":
        return (sid, src_ip, None, None)      # scan, brute force: theo nguồn
    return (sid, src_ip, dst_ip, dst_port)    # rule thường: giữ như cũ
```

`DetectionEngine` và `AnomalyDetector` truyền thêm `now=packet.timestamp` (giờ của gói) và `track` của rule. Rule thường giữ nguyên khoá cũ, nên hành vi của chúng không đổi.

### Ví dụ

| `chienbuoito.pcap` | Trước | Sau |
| :--- | --: | --: |
| Cảnh báo, 3 lần chạy | 2.901 / 2.923 / 3.008 | 251 / 251 |
| Cảnh báo rule 1000205 | khoảng 2.192 | 34 |
| Cảnh báo P3 (chủ yếu ANOMALY) | 17 | 51 |

P3 tăng là **đúng**: trước đây ANOMALY tính "chặn 60 giây" theo giờ máy, cả 10 phút pcap đọc xong trong chưa tới 60 giây máy nên mỗi loại chỉ ra một cảnh báo. Giờ tính theo giờ gói, nên mỗi 60 giây của traffic có thể có cảnh báo riêng. Test `test_anomaly_suppression_follows_packet_time` kiểm tra đúng điều này: 3 đợt quét cách nhau 100 giây ra 3 cảnh báo (trước đây ra 1).

### Giúp đạt mục tiêu nào

Tiêu chí 9 (chạy lại ra cùng con số) và bước đầu cho tiêu chí 3, 4 (bớt báo nhầm). Việc sửa chính 4 rule báo nhầm là việc của tuần 2.

---

## T7. Scapy chỉ bóc tới L4

### Vấn đề

Scapy mặc định bóc mọi tầng của gói: Ethernet, IP, TCP, rồi tiếp tới DNS, TLS, NetBIOS... Decoder của dự án chỉ cần tới TCP/UDP/ICMP (phần sau đó lấy nguyên byte), nên phần bóc thêm là công cốc.

### Đã thêm

```python
KEEP_LAYER_MODULES = ("scapy.layers.l2", "scapy.layers.inet", "scapy.layers.inet6")

def apply_layer_filter():
    keep = [layer for layer in conf.layers if layer.__module__ in KEEP_LAYER_MODULES]
    conf.layers.filter(keep + [Raw, Padding])
```

Gọi trong `main()` trước khi bắt gói (không gọi lúc import, vì đây là cài đặt chung của cả Scapy). File `tests/engine/conftest.py` tự gỡ bộ lọc sau mỗi test.

**Vì sao giữ theo module mà không liệt kê vài lớp?** Lúc đầu thử danh sách ngắn (Ether, IP, TCP, UDP, ICMP...). Danh sách đó làm gói ICMPv6 bị coi là `Raw`, nên `raw_payload` của nó đổi. Giữ cả module `inet6` thì không còn khác biệt.

### Ví dụ: so trên toàn bộ 107.996 gói

| | Không lọc | Có lọc |
| :--- | --: | --: |
| Chỉ đọc file và bóc gói | 26,5 giây | **12,8 giây** |
| Đọc + decode | 36,5 giây | **28,2 giây** (−23%) |
| `raw_payload`, IP, cổng, cờ, HTTP khác nhau | | **0 gói** |
| `raw_packet` khớp byte gốc trên dây | thiếu 117 gói | **107.996/107.996** |

Dòng cuối là một lỗi được sửa "miễn phí": khi bóc hết các tầng, Scapy dựng lại byte của 117 gói (chủ yếu DNS, NetBIOS) khác với byte gốc. `flow.py` dùng `len(raw_packet)` để đếm byte của flow, nên số byte của những flow đó bị sai. Có lọc thì byte luôn là byte gốc.

### Giúp đạt mục tiêu nào

Tiêu chí 2 (tốc độ) và độ đúng của số byte trong flow log, thứ mà AI sẽ học ở tuần 2.

---

## T8. Đo lại và so với baseline

### Engine thật (tiêu chí 1, 2)

Plan đo trên hai file: `chienbuoito.pcap` (chunk 14:09) và chunk nhiều gói nhất theo manifest (09:19).

| File | Gói | Gói bị vứt | Cảnh báo | Thời gian | Tốc độ |
| :--- | --: | --: | --: | --: | --: |
| `chienbuoito.pcap` (14:09) | 106.955 | 0 | 251 | 39,1 giây | **2.735 gói/giây** |
| Chunk 09:19 | 1.919.255 | 0 | 170 | 601,8 giây | **3.189 gói/giây** |

**Tiêu chí 2 (≥ 3.000 gói/giây) đạt trên chunk 09:19, chưa đạt trên chunk 14:09.** Chunk 14:09 có nhiều kết nối ngắn và nhiều cảnh báo hơn trên mỗi gói, nên tốn công hơn. Giới hạn còn lại là GIL và Scapy (xem T5). Hướng tiếp theo đã ghi trong plan: thử bộ decode đọc byte trực tiếp không qua Scapy (tuần 3), và chuyển ghi flow sang thread riêng.

### Bộ đo trên 43 chunk dev (tiêu chí 3–5)

Chạy cùng lệnh với baseline trên 8.078.211 gói. Báo cáo đầy đủ: [eval/sau-sua-engine.md](eval/sau-sua-engine.md).

| | Baseline | Sau ngày 2 | Nhận xét |
| :--- | --: | --: | :--- |
| Thời gian chạy (12 tiến trình) | 1.470 giây | **922 giây** | −37% |
| Tốc độ một tiến trình | 983 gói/giây | **1.841 gói/giây** | +87%, chủ yếu nhờ T7 |
| Số lần rule khớp (trước bộ chặn) | 659.984 | **659.984** | Giống hệt: T4–T7 không làm đổi việc phát hiện |
| Số flow theo từng lớp, flow bị rule báo | | **giống hệt** | Cũng là bằng chứng không lệch |
| Flow BENIGN bị rule báo (FPR) | 52,3% | 52,3% | Chưa đổi: phần này sửa ở tuần 2 (sửa rule) |
| Cảnh báo rule gửi tới người trực | 140.601 | **5.103** | −96% nhờ bộ chặn mới (T6) |
| Cảnh báo rule 1000205 (UDP flood) | 80.546 | **1.339** | |
| Cảnh báo rule 1000107 (SYN scan) | 55.562 | **734** | |
| Độ chính xác cảnh báo rule | 30,3% | 6,6% | Xem giải thích dưới |
| Cảnh báo ANOMALY | 2.357 | 3.487 | Tăng vì giờ chặn giờ tính theo giờ gói (T6) |
| Đợt PortScan bị phát hiện (dev) | 4/5 | 4/5 | Đợt 13:05 vẫn lọt, việc tuần 2 |
| Máy Bot bị phát hiện (dev) | 3/3 | 2/3 | Máy `.14` lọt, xem dưới |

**Vì sao độ chính xác tụt từ 30,3% xuống 6,6% dù hệ thống tốt hơn?** Độ chính xác ở đây đếm theo *số cảnh báo*. Trong baseline, 37.615 cảnh báo "bắt đúng" của rule 1000107 phần lớn là cảnh báo lặp lại của **một** kẻ tấn công `172.16.0.1` trong đợt quét lớn 14:51. Bộ chặn mới gộp cảnh báo theo nguồn (10 giây một cảnh báo), nên chỉ còn 93. Báo nhầm cũng giảm (87.011 xuống 3.881), nhưng giảm ít hơn vì báo nhầm đến từ rất nhiều máy khác nhau. Kết luận: con số này đang bị **số cảnh báo trùng** chi phối, nên tuần 2 nên đo thêm độ chính xác theo *cặp IP* hoặc theo *flow* để đánh giá rule công bằng hơn (đã ghi vào plan).

**Vì sao máy Bot `.14` không còn bị phát hiện?** Trước đây có 2 cảnh báo rule rơi vào flow Bot của máy này, giờ không còn. Bộ đo chưa lưu từng cảnh báo nên chưa xác nhận được nguyên nhân; giả thuyết hợp lý nhất là máy `.14` vừa bị rule báo nhầm trên traffic web bình thường ngay trước đó, nên cảnh báo sau (rơi vào flow Bot) bị bộ chặn gộp mất (cùng SID, cùng nguồn, trong 10 giây). Tuần 2 nên cho bộ đo lưu danh sách cảnh báo để kiểm tra những trường hợp như thế này. Đây là cái giá của việc gộp cảnh báo. Cách giải quyết đúng không phải là bỏ bộ chặn, mà là bớt báo nhầm (tuần 2) và cho AI bắt Bot theo hành vi (tuần 2–3).

---

## Còn tồn tại

- **`FlowLog` vẫn ghi CSDL ngay trong worker.** Lúc thử khoá CSDL, worker phải chờ tới 30 giây cho lô flow, nên lượt chạy mất 71 giây thay vì 40. Khi bắt gói trực tiếp, khoảng chờ đó sẽ làm rơi gói. Nên chuyển flow sang thread ghi riêng giống `AlertWriter` (đã ghi vào plan, việc tuần sau).
- **Tốc độ trên chunk nhiều cảnh báo (14:09) vẫn dưới 3.000 gói/giây**, như trên.
- Hai test WebSocket (`tests/api/test_realtime_ws.py`) vẫn chập chờn trên `main`, của PLAN-001.
- `AlertWriter` gọi `publish_alert` từ thread `alert-writer`, trễ tối đa 1 giây so với trước. Đã báo nmchien1106 (PLAN-001) trong PR.
