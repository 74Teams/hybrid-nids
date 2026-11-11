# Tuần 1 làm trong 2 ngày: việc chi tiết từng bước

Tài liệu này tách tuần 1 của [PLAN-009](plans/2026-11-10-labeled-eval-optimization.md) thành 9 task cho **một người** làm trong 2 ngày (11/11 và 12/11/2026). Bản tóm tắt cả 3 tuần nằm ở [lo-trinh-3-tuan.md](lo-trinh-3-tuan.md).

## Tổng quan

| Ngày | Task | Việc | Thời gian ước tính | Nhánh git |
| :--- | :--- | :--- | :--- | :--- |
| 1 (11/11) | T0 | Chuẩn bị: duyệt plan, tạo issue, cắt lại pcap, tạo nhánh | 45 phút | |
| 1 | T1 | Module đọc nhãn CIC (`tools/cic/labels.py`) | 2,5 giờ | `feature/cic-eval-tools` |
| 1 | T2 | Danh sách chunk dev/test (`tools/cic/manifest.py`) | 1,5 giờ | `feature/cic-eval-tools` |
| 1 | T3 | Bộ đo (`tools/eval/evaluate.py`) và số liệu baseline | 3,5 giờ | `feature/cic-eval-tools` |
| 2 (12/11) | T4 | Đọc pcap không vứt gói | 1 giờ | `feature/engine-alert-writer` |
| 2 | T5 | Ghi cảnh báo theo lô ở luồng riêng | 3 giờ | `feature/engine-alert-writer` |
| 2 | T6 | Sửa bộ chặn cảnh báo trùng (threshold) | 1,5 giờ | `feature/engine-alert-writer` |
| 2 | T7 | Lọc tầng Scapy (tuỳ chọn, chỉ +15%) | 1 giờ | `feature/engine-alert-writer` |
| 2 | T8 | Đo lại, so với baseline, mở 2 PR | 1,5 giờ | |

**Thứ tự bắt buộc:** làm T1 → T2 → T3 trước, và **chạy baseline (T3) trước khi đụng vào engine (T4–T7)**. Baseline là con số "trước khi sửa"; sửa engine trước thì mất mốc so sánh.

**Nếu thiếu thời gian, cắt theo thứ tự:** T7, rồi phần ANOMALY trong T6, rồi bảng "theo đợt" trong T3.

**Khác với plan gốc** (sẽ ghi vào mục 12 của PLAN-009):

- Gộp PR2 (nhãn) và PR3 (bộ đo) của plan thành một nhánh `feature/cic-eval-tools`, vì một người làm liền mạch.
- T6 chỉ đổi khoá chặn cho rule có `detection_filter` (đúng chỗ gây lỗi), rule khác giữ nguyên khoá. Như vậy ít thay đổi hành vi hơn plan gốc.
- T5 giữ đường ghi đồng bộ khi chưa khởi tạo bộ ghi, nên test `test_alert_shown_even_if_db_fails` không phải sửa.

---

## Ngày 1: dữ liệu và bộ đo

### T0. Chuẩn bị (45 phút)

**Mục đích:** có đủ điều kiện để bắt đầu viết code đúng quy trình của repo.

1. **Duyệt plan.** Đọc mục 2 (tiêu chí) và 6.8 (chia việc) của PLAN-009. Đồng ý thì báo Claude: *"duyệt PLAN-009"*. Claude đổi trạng thái sang `APPROVED`, rồi `IN_PROGRESS`. Theo `.claude/rules/planning.md`, chưa `APPROVED` thì chưa được sửa code.
2. **Tạo issue** trên GitHub, lấy số issue (gọi là `#N`):
   ```powershell
   gh issue create --repo 74Teams/hybrid-nids --title "Bộ đo có nhãn CIC-IDS2017 và tối ưu hệ thống (PLAN-009)" --body "Plan: docs/plans/2026-11-10-labeled-eval-optimization.md" --assignee nldd0507
   ```
   Ghi `#N` vào trường `issue:` của plan và cột Issue trong `docs/plans/README.md`.
3. **Cắt lại pcap thứ Sáu.** Thư mục `split` cũ đã bị xoá. Cắt thành đoạn 10 phút:
   ```powershell
   New-Item -ItemType Directory -Force D:\Tools\PBL4\split
   & "C:\Program Files\Wireshark\editcap.exe" -i 600 D:\Tools\PBL4\Friday-WorkingHours.pcap D:\Tools\PBL4\split\fri.pcap
   (Get-ChildItem D:\Tools\PBL4\split\*.pcap).Count
   ```
   Phải ra **49** file (`fri_00000_...pcap` đến `fri_00048_...pcap`). Mất khoảng 2–5 phút.
4. **Tạo nhánh** từ `main` mới nhất:
   ```powershell
   git switch main
   git pull
   git switch -c feature/cic-eval-tools
   ```
5. **Tạo khung thư mục:**
   ```
   tools/__init__.py          (file rỗng)
   tools/cic/__init__.py      (file rỗng)
   tools/eval/__init__.py     (file rỗng)
   tests/tools/__init__.py    (file rỗng, nếu thư mục tests khác cũng có)
   ```
   `pytest.ini` đã đặt `pythonpath = .`, nên `import tools.cic.labels` chạy được từ thư mục gốc repo.

**Xong khi:** plan ở `APPROVED`, có số issue, có 49 file trong `split`, đang ở nhánh `feature/cic-eval-tools`.

### T1. Module đọc nhãn CIC: `tools/cic/labels.py` (2,5 giờ)

**Mục đích:** cho mỗi flow của engine biết nó là tấn công loại gì, dựa vào CSV của CIC.

**Kiến thức cần biết trước:**

- Mỗi dòng CSV là một flow do CICFlowMeter tính ra, có `Source IP`, `Source Port`, `Destination IP`, `Destination Port`, `Protocol` (6 = TCP, 17 = UDP, 1 = ICMP), `Timestamp`, `Label`.
- **Giờ trong CSV có hai bẫy:**
  - Kiểu 12 giờ **không có AM/PM**: `7/7/2017 2:09` là 14:09.
  - Là giờ Canada (ADT = UTC−3).

  Quy tắc: giờ từ 1 đến 7 là buổi chiều, cộng 12. File thứ Hai có cả giây: `03/07/2017 08:55:58`.
- Engine gom flow bằng `flow_key` (`nids/engine/flow.py`): `(protocol, (ip, port) nhỏ hơn, (ip, port) lớn hơn)`. Khoá chuẩn hoá hai chiều, nên gói đi và gói về ra cùng một khoá. Ta dựng khoá **giống hệt** từ CSV.

**Các bước:**

1. Viết hàm đổi giờ:
   ```python
   ADT = timezone(timedelta(hours=-3))

   def parse_cic_timestamp(text: str) -> float:
       """'7/7/2017 2:09' hoặc '03/07/2017 08:55:58' (ngày/tháng/năm, giờ ADT) -> epoch UTC."""
       date_part, time_part = text.strip().split(" ")
       day, month, year = (int(x) for x in date_part.split("/"))
       parts = [int(x) for x in time_part.split(":")]
       hour, minute = parts[0], parts[1]
       second = parts[2] if len(parts) > 2 else 0
       if hour < 8:          # giờ làm việc 8h-17h, nên 1..7 là buổi chiều
           hour += 12
       return datetime(year, month, day, hour, minute, second, tzinfo=ADT).timestamp()
   ```
2. Viết hàm dựng khoá giống `flow_key`:
   ```python
   PROTOCOLS = {6: "TCP", 17: "UDP", 1: "ICMP"}

   def cic_flow_key(src_ip, src_port, dst_ip, dst_port, protocol_number):
       a = (str(src_ip), int(src_port or 0))
       b = (str(dst_ip), int(dst_port or 0))
       return (PROTOCOLS.get(int(protocol_number), "UNKNOWN"), *sorted((a, b)))
   ```
3. Viết hàm gộp và sửa nhãn:
   - `GROUPS = {"BENIGN": "BENIGN", "PortScan": "PortScan", "DDoS": "DDoS", "Bot": "Bot"}`. Thêm sẵn các nhãn ngày khác: `"DoS Hulk": "DoS"`, `"FTP-Patator": "BruteForce"`... để sau này dùng.
   - `C2_IP = "205.174.165.73"`: dòng có IP này thì nhãn là `Bot`, dù CSV ghi gì. Comment ghi nguồn: Engelen và cộng sự 2021, cùng phép kiểm tra ngày 10/11 (42 flow tới IP này lúc 14:09–14:19 bị gắn BENIGN).
4. Viết `load_labels(csv_paths) -> LabelIndex`:
   - Đọc bằng `pandas.read_csv(path, encoding="latin-1", low_memory=False)`, chỉ lấy 7 cột cần.
   - Bỏ khoảng trắng đầu tên cột: `df.columns = [c.strip() for c in df.columns]`.
   - Bỏ dòng không có `Timestamp` (`dropna`).
   - Tính `ts`, `key`, `label_raw`, `label` (sau khi gộp và sửa).
5. Viết lớp `LabelIndex`:
   - Bên trong là `dict`: khoá → danh sách `(ts, label, label_raw)` đã sắp theo `ts`.
   - Hàm `lookup(key, first_seen, last_seen, tolerance=120) -> (label, label_raw)`: lấy các dòng cùng khoá có `ts` trong `[first_seen - 120, last_seen + 120]`. Có dòng tấn công thì trả nhãn tấn công; chỉ có BENIGN thì trả `BENIGN`; không có dòng nào thì trả `UNLABELED`. Dung sai 120 giây vì CSV chỉ chính xác tới phút.
   - Hàm `attack_windows(label)`: các khoảng phút liên tục của một nhãn (dùng cho "đợt" ở T3).
6. Log qua `logging.getLogger("nids.eval")`: số dòng đã đọc, số dòng bị sửa nhãn. Không dùng `print`.
7. **Viết test** `tests/tools/test_cic_labels.py`, tự tạo CSV nhỏ trong `tmp_path` (không đọc ổ D):
   - `parse_cic_timestamp("7/7/2017 2:09")` bằng epoch của 17:09 UTC ngày 7/7/2017.
   - `"7/7/2017 9:30"` vẫn là buổi sáng; `"03/07/2017 08:55:58"` có giây.
   - Khoá hai chiều: `cic_flow_key("1.1.1.1", 5, "2.2.2.2", 80, 6) == cic_flow_key("2.2.2.2", 80, "1.1.1.1", 5, 6)`, và bằng `flow_key` của một `DecodedPacket` cùng IP và cổng.
   - `lookup` trả `PortScan` khi có dòng tấn công, `BENIGN` khi chỉ có BENIGN, `UNLABELED` khi lệch giờ quá 120 giây.
   - Dòng có `205.174.165.73` ghi BENIGN thì `label == "Bot"`, `label_raw == "BENIGN"`.
   - Tên cột có khoảng trắng đầu vẫn đọc được.
8. Chạy `pytest tests/tools -q`.
9. **Kiểm tra trên dữ liệu thật** (chạy tay, không đưa vào test): dùng `pcap/chienbuoito.pcap` và CSV PortScan, ghép với flow. Phải ra khoảng 99% flow có nhãn và 118 flow PortScan, như phép đo ngày 10/11.

**Xong khi:** test xanh, và phép thử trên `chienbuoito.pcap` ra 118 flow PortScan.

### T2. Danh sách chunk: `tools/cic/manifest.py` (1,5 giờ)

**Mục đích:** một danh sách cố định cho biết file pcap 10 phút nào là **dev** (luyện), file nào là **test** (thi), để mọi lần đo đều dùng cùng một cách chia.

**Các bước:**

1. Tham số dòng lệnh (`argparse`): `--split-dir`, `--labels-dir`, `--day friday`, `--expect-packets 9997874`, `--out data/cic/friday_manifest.json`, `--summary docs/eval/manifest.md`.
2. Với mỗi file `*.pcap` (sắp theo tên), đếm gói và lấy giờ gói đầu, gói cuối bằng `scapy.utils.RawPcapReader`. Hàm này đọc byte thô, không bóc giao thức, nên nhanh: khoảng 1 phút cho 10 triệu gói. **Lấy giờ từ gói tin**, không lấy từ tên file (tên file theo giờ Việt Nam).
3. Tổng số gói khác `--expect-packets` thì log `ERROR` và thoát mã 1. Điều này chặn trường hợp thư mục có file trùng như lần trước.
4. Đổi giờ bắt đầu chunk sang ADT dạng `HH:MM`. Chunk thứ k bắt đầu lúc 08:59:39 + 10k phút, nên ra các giá trị `08:59`, `09:09`, ..., `16:59`.
5. Gán tập: `TEST_STARTS = {"09:09", "14:59", "15:09", "15:19", "16:09", "16:29"}` → `test`, còn lại → `dev`. Đây là danh sách trong mục 6.3 của plan.
6. Dùng `load_labels` (T1) đếm số dòng CSV theo nhãn đã sửa nằm trong mỗi chunk.
7. Tìm **máy nhiễm Bot**: IP `192.168.10.x` có dòng tới hoặc từ `205.174.165.73`. Sắp theo số (dùng `ipaddress.ip_address`) và lấy 2 IP nhỏ nhất làm **máy test** (`bot_test_hosts`). In số flow Bot theo chunk và theo máy.
8. Ghi JSON (`data/cic/`, đã gitignore) và bảng Markdown `docs/eval/manifest.md` (được commit, để người khác dùng cùng cách chia).
9. Thêm vào `tests/tools/test_cic_labels.py`: hàm gán tập với giờ cho trước ra đúng dev/test; chọn máy test tất định (thứ tự đầu vào khác nhau vẫn ra cùng 2 IP); sai tổng gói thì báo lỗi.
10. Chạy thật:
    ```powershell
    python -m tools.cic.manifest --split-dir D:\Tools\PBL4\split --labels-dir D:\Temp\Temp\TrafficLabelling_
    ```

**Xong khi:**

- Có 49 dòng, tổng 9.997.874 gói, 6 chunk test.
- `manifest.md` cho thấy chunk `16:29` có flow Bot của máy test. Nếu không có, chọn chunk BENIGN dự phòng trong bảng và ghi lại.

### T3. Bộ đo và baseline: `tools/eval/evaluate.py` (3,5 giờ)

**Mục đích:** một lệnh cho ra bảng "đúng bao nhiêu, sai bao nhiêu" cho từng rule và từng loại tấn công.

**Các bước:**

1. **Bộ biến không phụ thuộc máy.** Đây là lỗi BLOCKER mà `plan-critic` đã bắt:
   ```python
   from nids.engine.rule_header import DEFAULT_RULE_VARIABLES, http_ports
   import nids.engine.decoder as decoder

   variables = {**DEFAULT_RULE_VARIABLES, **overrides}   # overrides từ --set-var HOME_NET=192.168.10.0/24
   decoder.HTTP_PORTS = http_ports(variables)            # đặt lại trong MỖI tiến trình con
   rules = RuleManager("rules", variables=variables)
   ```
   Không truyền `overrides` trực tiếp vào `RuleManager`: hàm này **thay hẳn** bộ biến, nên 35 rule `$HTTP_PORTS` sẽ bị bỏ.
2. **Cấu hình engine** lấy từ file mẫu được commit, không lấy từ `settings.yaml` local:
   ```python
   from nids.config import load_settings, EXAMPLE_SETTINGS_PATH
   cfg = load_settings(EXAMPLE_SETTINGS_PATH)   # dùng cfg["stream"], cfg["flow"], cfg["anomaly"]
   ```
3. **Chặn rule lỗi:** gắn một `logging.Handler` vào `nids.rules` trong lúc `load_all_rules()`. Có bản ghi `WARNING` thì log lỗi và dừng.
4. **Hàm chạy một chunk** `run_chunk(path, variables) -> dict` (chạy trong tiến trình con):
   - Tạo `DetectionEngine(rules, alert_callback=alerts.append)` (threshold bật như engine thật), `StreamReassembler(...)`, `FlowTracker(...)`, `AnomalyDetector(cfg["anomaly"], alert_callback=alerts.append)`, tham số lấy từ `cfg`.
   - Đọc bằng `PcapReader`. Mỗi gói: `PacketDecoder.decode`, rồi `matched = evaluate_with_stream(engine, reasm, d)` (`nids/engine/main.py:175`), rồi `flows += tracker.update(d, len(matched))`, rồi `anomaly.observe(d)`. Cộng `raw_matches += len(matched)` (số lần khớp **trước** threshold, không phụ thuộc tốc độ chạy).
   - Hết file: `flows += tracker.flush()`.
   - Đo thời gian từng bước bằng `time.perf_counter()` và đếm phễu gói (tổng, không phải IP, vào phân tích).
   - Trả về dict gồm flow (đổi `Flow` sang dict bằng `dataclasses.asdict`, bỏ trường bắt đầu bằng `_`), cảnh báo, số đếm, thời gian.
5. **Chạy song song:** `multiprocessing.Pool(processes=N)` với `N = --jobs` (mặc định 12; máy có 16 nhân). Trên Windows, phần khởi chạy phải nằm trong `if __name__ == "__main__":`.
6. **Gắn nhãn flow:** `index.lookup(flow_key, first_seen, last_seen)`. Áp quy tắc `EXCLUDED` (mục 6.3 của plan):
   - Trong chunk test, flow Bot của máy không phải máy test bị loại.
   - Trong chunk dev, flow của máy test bị loại.
7. **Gắn cảnh báo vào flow:**
   - Cảnh báo rule: dựng khoá từ `protocol`, `src_ip`, `src_port`, `dst_ip`, `dst_port` của cảnh báo, tìm flow cùng khoá có `first_seen ≤ timestamp ≤ last_seen`.
   - Cảnh báo ANOMALY: đúng nếu trong vòng ±60 giây có flow tấn công chứa `src_ip` của cảnh báo (scan, rare) hoặc `dst_ip` (flood).
8. **Tính và ghi số liệu:**
   - Theo loại: số flow, số flow có cảnh báo rule (`alert_count > 0`), recall; FPR trên BENIGN.
   - Theo SID: số cảnh báo, tỉ lệ cảnh báo rơi vào flow tấn công, top 3 cặp IP báo nhầm.
   - Theo tầng: `RULE_ENGINE`, `ANOMALY`.
   - Đếm `UNLABELED` và `EXCLUDED`.
   - Phễu gói, thời gian từng bước.

   Ghi `docs/eval/<tên>.md` (bảng Markdown) và `data/eval/<tên>.json`.
9. **Test** `tests/tools/test_evaluate.py`:
   - Dựng pcap nhỏ bằng `wrpcap` (làm giống `tests/engine/test_stream.py:313`): một kết nối SQLi tới cổng 80 và một kết nối bình thường. Dựng CSV giả gắn nhãn cho hai kết nối đó. Chạy `run_chunk` cộng phần tính số liệu, kiểm tra đúng 1 TP và 0 FP.
   - Truyền `--set-var HOME_NET=10.0.0.0/8`: rule `$HTTP_PORTS` vẫn được nạp và vẫn bắn.
   - Kết quả không đổi khi `SETTINGS["detection"]["variables"]` bị monkeypatch thành giá trị khác.
10. Mở rộng `tests/test_code_language.py` (dòng 21) và `test_no_print_calls_left` (`tests/engine/test_main_output.py:86`) sang thư mục `tools`.
11. Chạy `pytest` (toàn bộ).
12. **Chạy baseline** (code engine chưa sửa):
    ```powershell
    python -m tools.eval.evaluate --manifest data\cic\friday_manifest.json --labels-dir D:\Temp\Temp\TrafficLabelling_ --set dev --set-var HOME_NET=192.168.10.0/24 --name baseline
    ```
    Chunk 14:09 phải khớp phép đo ngày 10/11: **7.697 flow, 118 flow PortScan**. Số cảnh báo sau threshold của code cũ phụ thuộc tốc độ chạy, nên chỉ ghi để tham khảo.
13. Commit nhánh này (xin Claude commit hoặc dùng `/ship`). Ví dụ message:
    ```
    feat(eval): add CIC-IDS2017 label tools and labeled evaluation harness (#N)
    ```
    Đừng gộp vào `main` trước khi xong T8, để PR engine so được với baseline.

**Xong khi:** có `docs/eval/manifest.md`, `docs/eval/baseline.md`, `pytest` xanh.

---

## Ngày 2: sửa engine

Tạo nhánh mới **từ `main`** (không từ nhánh tools, để hai PR độc lập):

```powershell
git switch main
git switch -c feature/engine-alert-writer
```

### T4. Đọc pcap không vứt gói (1 giờ)

**Vấn đề:** `on_raw_packet` (`nids/engine/main.py:284`) gọi `put_nowait`; hàng đợi đầy thì vứt gói, kể cả khi đọc file.

**Các bước:**

1. Trong `main()`, chuyển dòng `live = capture_mode != "offline"` (đang ở dòng 300) và `stop_event = threading.Event()` lên **trước** `def on_raw_packet`.
2. Sửa `on_raw_packet`:
   ```python
   if live:
       try:
           packet_queue.put_nowait(decoded)
           stats["packets"] += 1
       except queue.Full:
           ...  # giữ nguyên như cũ (DropCounter)
       return
   # offline: chờ chỗ trống, nhưng không chờ mãi nếu worker đã chết
   while not stop_event.is_set():
       try:
           packet_queue.put(decoded, timeout=0.5)
           stats["packets"] += 1
           return
       except queue.Full:
           if not worker_thread.is_alive():
               logger.error("Worker thread đã dừng, ngừng đọc pcap")
               stop_event.set()
   ```
   Có `timeout=0.5` thì Ctrl+C trên Windows vẫn ngắt được.
3. `nids/engine/capture.py`: `start_offline` nhận thêm `stop_filter=None` và truyền vào cả hai lời gọi `sniff(...)`. Trong `main()` gọi `capturer.start_offline(pcap_file, stop_filter=lambda _: stop_event.is_set())`, để đọc pcap dừng khi worker chết.
4. Trong `worker_loop`, bọc phần xử lý một gói (`evaluate_with_stream` đến `observe_anomaly`) bằng `try/except Exception as e: logger.error(...)`, để một gói lỗi không giết worker. Giữ `finally: packet_queue.task_done()`.
5. **Test** trong `tests/engine/test_main_output.py`, làm giống `test_stream.py:313`:
   - Dựng pcap 200 gói, `queue_max_size: 5`, chạy `main.main()`. Kiểm tra log tổng kết có `200 gói` và không có `Queue đầy`.
   - Monkeypatch `evaluate_with_stream` ném lỗi: `main.main()` vẫn kết thúc (không treo) và có log lỗi.

**Xong khi:** test mới xanh, `pytest tests/engine` xanh.

### T5. Ghi cảnh báo theo lô (3 giờ)

**Vấn đề:** mỗi cảnh báo mở một session CSDL, `commit` và `refresh` ngay trong worker (`nids/db/repository.py:19-48`), mất khoảng 11 ms một cảnh báo.

**Các bước:**

1. **`nids/db/repository.py`:**
   - Tách phần dựng `EventModel` trong `save_alert` ra hàm `_build_event(alert_data)`. `save_alert` gọi lại hàm này; hành vi không đổi, các test API vẫn chạy.
   - Thêm `save_alerts(alerts) -> List[int]`: một session, `add_all`, **một** `commit`, lấy danh sách id, rồi `publish_alert(id)` cho từng id (publish vẫn sau `commit`, đúng luật repo).
2. **File mới `nids/engine/alert_writer.py`:**
   ```python
   class AlertWriter:
       """Gom cảnh báo và ghi CSDL theo lô ở một thread riêng, để worker không phải chờ CSDL."""
       def __init__(self, save_batch, batch_size=200, flush_interval=1.0, max_queue=50000, block=False): ...
       def start(self): ...                  # tạo thread "alert-writer" (daemon)
       def submit(self, alert_data): ...     # live: put_nowait, đầy thì DropCounter + WARNING
                                             # offline (block=True): put(timeout=0.5), thread chết thì log ERROR và bỏ
       def close(self, timeout=10.0): ...    # báo dừng, ghi nốt, join thread; gọi nhiều lần vẫn an toàn
   ```
   Vòng lặp của thread: `get(timeout=flush_interval)`; đủ `batch_size` hoặc quá `flush_interval` thì gọi `save_batch(batch)` trong `try/except` (lỗi thì `logger.error`, bỏ lô, giống `FlowLog._write` ở `main.py:150`).
3. **`nids/engine/main.py`:**
   - Thêm biến module `alert_writer: Optional[AlertWriter] = None`.
   - `handle_alert`: nếu `alert_writer` khác `None` thì `alert_writer.submit(alert_data)`, không thì giữ nguyên lời gọi `EventRepository.save_alert` cũ. Nhờ vậy `test_alert_shown_even_if_db_fails` không phải sửa.
   - Trong `main()`, sau `init_db()`: tạo `AlertWriter(EventRepository.save_alerts, block=not live)`, `start()`, gán vào biến module (`global alert_writer`).
   - **Thứ tự kết thúc ở nhánh offline:** `packet_queue.join()`, rồi `stop_event.set()`, rồi `worker_thread.join(timeout=10)`, rồi `alert_writer.close()`, rồi mới log tổng kết. Bỏ `time.sleep(0.5)`.
   - Khối `finally`: gọi `alert_writer.close()` (an toàn khi gọi lần hai) và đặt `alert_writer = None`.
4. **Dòng tổng kết có tốc độ:** `format_summary(total, by_priority, elapsed=None)`. Có `elapsed` thì nối thêm `" trong 31.2 giây (3428 gói/giây)"`. Ba test cũ ở `test_main_output.py:47-50` vẫn đúng vì `elapsed` mặc định `None`. Trong `main()` đo `time.perf_counter()` từ lúc bắt đầu đọc pcap.
5. **`nids/db/__init__.py`:** `main` **đã có** WAL và thời gian chờ khoá 30 giây (commit `5aa3fec`, PR #69), nên không phải làm lại. Chỉ khi đo ở T8 thấy ghi CSDL vẫn chậm thì thêm `dbapi_conn.execute("PRAGMA synchronous=NORMAL")` vào hàm `_sqlite_wal` có sẵn.
6. `.gitignore` đã được thêm `*.db-wal`, `*.db-shm` và `pcap/*.pcap` ở T0. Còn `.dockerignore`: thêm `pcap/*.pcap` và `!pcap/ipv4frags.pcap` (kiểm tra `tests/test_dockerignore.py` vẫn xanh).
7. **Test** `tests/engine/test_alert_writer.py` (dùng hàm `save_batch` giả ghi vào list):
   - 450 cảnh báo, `batch_size=200`: ra các lô 200, 200, 50 sau `close()`.
   - 1 cảnh báo và `flush_interval=0.1`: được ghi trước khi `close()` (chờ 0,3 giây).
   - `save_batch` ném lỗi: có log `ERROR`, không ném ra ngoài, lô sau vẫn ghi.
   - `block=False`, `max_queue=1`, `save_batch` chậm: cảnh báo thừa bị bỏ và đếm.
   - `close()` gọi hai lần không lỗi.
   - Thêm vào `tests/api/test_db_init.py`: `save_alerts` ghi đủ và trả đúng số id.
8. Chạy `pytest`. `tests/engine/test_stream.py:313` và `tests/engine/test_flow_log.py:107` chạy `main.main()` rồi đọc CSDL ngay; chúng phải vẫn xanh nhờ thứ tự kết thúc ở bước 3.

**Xong khi:** `pytest` xanh; chạy engine trên `chienbuoito.pcap` thấy dòng tổng kết có gói/giây.

### T6. Sửa bộ chặn cảnh báo trùng (1,5 giờ)

**Vấn đề:**

- Rule 1000205 có `detection_filter: track by_dst`, nhưng khoá chặn lại gồm cả cổng đích (`threshold.py:34`). Gói DNS trả lời có cổng ngẫu nhiên, nên mỗi gói là một khoá mới, bắn 2.145 lần.
- Giờ lấy từ `time.time()` nên chạy lại cùng file ra kết quả khác.

**Các bước:**

1. `nids/engine/threshold.py`, `should_alert` thêm hai tham số tuỳ chọn `now: Optional[float] = None` và `track: Optional[str] = None`:
   ```python
   now = time.time() if now is None else now
   if track == "by_dst":
       key = (sid, None, dst_ip, None)
   elif track == "by_src":
       key = (sid, src_ip, None, None)
   else:
       key = (sid, src_ip, dst_ip, dst_port)   # rule thường: giữ như cũ
   ```
2. `__init__`: `self._last_cleanup = None`. `_periodic_cleanup`: nếu `self._last_cleanup is None` thì gán `now` rồi `return`. Nếu không làm, giờ gói năm 2017 nhỏ hơn giờ máy, và cache không bao giờ được dọn.
3. `nids/engine/detector.py:357`: truyền thêm `now=packet.timestamp` và `track=rule.detection_filter.track if rule.detection_filter else None`.
4. `nids/engine/anomaly.py:137`: truyền `now=packet.timestamp`. Xoá comment "shortcut" ở dòng 58.
5. **Sửa test cũ** `test_threshold_suppresses_alert_flood` (`tests/engine/test_diverse_rules_engine.py:305-332`):
   - Bỏ `time.sleep(2.1)`.
   - Gói thứ 11 dựng bằng `dataclasses.replace(pkt, timestamp=pkt.timestamp + 2.1)`.
6. **Test mới** `tests/engine/test_threshold.py`:
   - `track="by_dst"`: 100 lần gọi cùng `dst_ip`, mỗi lần một `dst_port` khác, trong 1 giây thì chỉ 1 lần được phép.
   - Rule không có `track`: hai cổng khác nhau vẫn là hai khoá (hành vi cũ).
   - Truyền `now` là giờ năm 2017: lần thứ hai sau 11 giây được phép; cache được dọn sau 60 giây giờ gói.
   - Chạy cùng chuỗi gói hai lần vào hai `AnomalyDetector` mới thì ra cùng danh sách cảnh báo (thêm vào `tests/engine/test_anomaly.py`).
7. Cập nhật `.claude/rules/engine.md`: câu "Cửa sổ chặn theo giờ hệ thống nên replay pcap chỉ ra một cảnh báo mỗi loại" đổi thành "cửa sổ chặn tính theo giờ của gói"; ghi khoá chặn theo `track`.

**Xong khi:** `pytest` xanh. Chạy lại bộ đo hai lần trên chunk 14:09 ra cùng số cảnh báo, và số cảnh báo 1000205 giảm mạnh.

### T7. Lọc tầng Scapy, tuỳ chọn (1 giờ)

**Mục đích:** Scapy không bóc DNS, TLS... vì decoder không dùng tới. Đã đo: nhanh hơn 15%, kết quả decode giống hệt.

**Các bước:**

1. `nids/engine/capture.py`:
   ```python
   from scapy.all import conf
   KEEP_LAYERS = [Ether, Dot1Q, ARP, IP, IPv6, IPv6ExtHdrHopByHop, IPv6ExtHdrRouting, IPv6ExtHdrFragment,
                  IPv6ExtHdrDestOpt, TCP, UDP, ICMP, IPerror, TCPerror, UDPerror, Raw, Padding]

   def apply_layer_filter():
       conf.layers.filter(KEEP_LAYERS)

   def reset_layer_filter():
       conf.layers.unfilter()
   ```
   **Không** gọi lúc import (sẽ ảnh hưởng mọi test). Gọi `apply_layer_filter()` trong `main()` trước khi bắt gói, và trong `run_chunk` của bộ đo.
2. **Test hồi quy** trong `tests/engine/test_decoder.py`:
   - Dựng các gói HTTP, DNS, Dot1Q, IPv6 có extension header, ICMP unreachable chứa TCP và UDP, cùng `pcap/ipv4frags.pcap`.
   - Decode khi chưa bật filter, rồi bật filter (từ byte thô: `Ether(bytes(p))`) decode lại, so từng trường của `DecodedPacket`.
   - Gọi `reset_layer_filter()` trong `finally`.
3. Nếu có trường khác nhau mà không sửa được trong 30 phút thì **bỏ T7**, ghi lý do vào PR.

**Xong khi:** test hồi quy xanh và `pytest` toàn bộ xanh.

### T8. Đo lại và mở PR (1,5 giờ)

1. **Đo engine thật.** `settings.yaml`: `capture_mode: "offline"`, `queue_max_size: 10000`, SQLite. Chạy:
   ```powershell
   python -m nids.engine
   ```
   Lần lượt với `pcap/chienbuoito.pcap` và chunk lớn nhất theo `manifest.md`. Mong đợi:
   - dòng tổng kết `Hoàn tất: 106955 gói ...` (với `chienbuoito.pcap`);
   - **không có** dòng `Queue đầy`;
   - ≥ 3.000 gói/giây (trước khi sửa là 1.680).
2. **Thử CSDL bị khoá giữa chừng:** khi engine vừa in `Đọc file PCAP`, mở terminal khác:
   ```powershell
   python -c "import sqlite3,time; c=sqlite3.connect('nids_events.db', isolation_level=None); c.execute('BEGIN EXCLUSIVE'); time.sleep(45)"
   ```
   SQLite chờ khoá tối đa 30 giây (đã có trên `main`), nên phải giữ khoá 45 giây mới thấy lỗi. Mong đợi:
   - Trong lúc bị khoá, worker **vẫn phân tích gói**, vì chỉ thread `alert-writer` phải chờ.
   - Sau khoảng 30 giây có log lỗi `database is locked` cho lô đang ghi.
   - Hết khoá thì các lô sau được ghi; engine đọc hết pcap, không dừng.
3. **Chạy bộ đo trên dev** với code đã sửa (bộ đo nằm ở nhánh tools, nên cần cả hai nhánh):
   ```powershell
   git switch feature/cic-eval-tools
   git merge --no-ff feature/engine-alert-writer   # chỉ gộp ở local để đo, không push nhánh gộp này
   python -m tools.eval.evaluate ... --set dev --name sau-sua-engine
   git reset --hard ORIG_HEAD                      # bỏ commit gộp tạm
   ```
   Hoặc nhờ Claude dựng worktree tạm để đo, không phải gộp. Ghi bảng so sánh baseline và sau sửa vào `docs/eval/sau-sua-engine.md` (đưa vào PR engine).
4. Chạy `pytest` trên từng nhánh.
5. **Mở 2 PR** (xin phép Claude rồi dùng `/ship`, hoặc làm tay theo `.claude/rules/git-workflow.md`):
   - PR 1, nhánh `feature/cic-eval-tools`: `feat(eval): add CIC-IDS2017 label tools and labeled evaluation harness (#N)`.
   - PR 2, nhánh `feature/engine-alert-writer`: `feat(engine): batch alert writes and stop dropping packets offline (#N)`.

   Mô tả PR viết tiếng Việt: tóm tắt, lý do, cách kiểm thử (lệnh đã chạy, số liệu trước và sau).
6. Báo **nmchien1106** (PLAN-001, Redis): `publish_alert` giờ gọi từ thread `alert-writer`, trễ tối đa 1 giây.
7. Cập nhật PLAN-009: tick các bước đã xong ở mục 11, ghi link PR vào bảng tổng hợp.

**Xong khi:**

- 2 PR đã mở, CI xanh.
- `docs/eval/baseline.md` và `docs/eval/sau-sua-engine.md` cho thấy: 0 gói bị vứt, ≥ 3.000 gói/giây, số cảnh báo 1000205 giảm mạnh.

---

## Checklist nhanh

**Ngày 1**

- [x] T0: plan `APPROVED`, issue `#N`, 49 file pcap, nhánh `feature/cic-eval-tools`
- [x] T1: `labels.py` + test; thử thật ra 118 flow PortScan
- [x] T2: `manifest.py`; `docs/eval/manifest.md` có 49 chunk, 6 chunk test
- [x] T3: `evaluate.py` + test; `docs/eval/baseline.md`; commit

**Ngày 2**

- [x] T4: offline không vứt gói, worker chết không treo
- [x] T5: `AlertWriter`, `save_alerts`, WAL, thứ tự kết thúc, tổng kết có gói/giây
- [x] T6: khoá chặn theo `track`, giờ theo gói (rule và ANOMALY)
- [x] T7 (tuỳ chọn): lọc tầng Scapy + test hồi quy
- [x] T8: đo lại, so baseline, 2 PR, báo nmchien1106

## Khi bị kẹt

| Triệu chứng | Nguyên nhân thường gặp | Cách xử lý |
| :--- | :--- | :--- |
| `ModuleNotFoundError: tools` | Chạy lệnh không ở thư mục gốc repo, hoặc thiếu `__init__.py` | `cd` về gốc repo, dùng `python -m tools.eval.evaluate` |
| `UnicodeEncodeError` khi in tiếng Việt | Terminal Windows dùng cp1252 | Đặt `$env:PYTHONIOENCODING="utf-8"` trước khi chạy |
| Bộ đo dừng vì `WARNING rules` | Bộ biến thiếu, ví dụ truyền `variables` không gộp mặc định | Xem T3 bước 1 |
| Rất ít flow có nhãn | Sai múi giờ hoặc quên cộng 12 cho giờ buổi chiều | Thử `parse_cic_timestamp("7/7/2017 2:09")` phải ra 17:09 UTC |
| `multiprocessing` treo hoặc chạy lại script | Thiếu `if __name__ == "__main__":` trên Windows | Đặt mọi lệnh khởi chạy trong khối này |
| Test engine treo | `put` không có timeout, hoặc chưa `close()` bộ ghi | Xem T4 bước 2, T5 bước 3 |
