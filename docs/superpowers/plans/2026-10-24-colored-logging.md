# Logging có màu và thống nhất ngôn ngữ: Kế hoạch triển khai

> **Dành cho agent thực thi:** BẮT BUỘC dùng superpowers:subagent-driven-development (khuyến nghị) hoặc superpowers:executing-plans để thực hiện từng task. Các bước dùng checkbox (`- [ ]`) để theo dõi.

**Mục tiêu:** Thay mọi `print` bằng module `logging` với đầu ra terminal có màu, cùng một khuôn cột dễ theo dõi; thống nhất comment, docstring và nội dung log sang tiếng Việt có dấu.

**Kiến trúc:** Một module mới `config/logger.py` cấu hình logger gốc `"nids"` (formatter màu tự viết, mức độ lấy từ `system.log_level`). Mỗi module dùng `logging.getLogger("nids.<khu vực>")`. `main.py` định dạng dòng cảnh báo theo priority và in dòng tổng kết cuối lượt replay pcap.

**Công nghệ:** Python 3.10 stdlib `logging`, pytest (`caplog`). Không thêm thư viện.

**Spec:** Không có file riêng; mô tả đã chốt trong chat nằm ở mục "Yêu cầu đã chốt".

## Yêu cầu đã chốt

- Người dùng xem log trực tiếp trên terminal; mục tiêu là đẹp, chuyên nghiệp, dễ theo dõi.
- Mỗi dòng có khuôn: `giờ  mức độ  khu vực  nội dung`, ví dụ `10:21:03 INFO     rules    Đã nạp 30 rule từ rules`.
- Có màu cho cột mức độ và cột khu vực; dòng cảnh báo tô màu theo priority: P1 đỏ, P2 vàng, P3 xanh dương.
- Chi tiết kỹ thuật ở mức DEBUG, ẩn mặc định; bật bằng `system.log_level: DEBUG` trong `config/settings.yaml`.
- Cuối lượt replay pcap có một dòng tổng kết số gói và số cảnh báo theo priority.
- Không in cảnh báo hai lần; cảnh báo "queue đầy" không được in liên tục.
- Comment, docstring và nội dung log viết tiếng Việt có dấu; tên trong code giữ tiếng Anh.
- Dùng `logging` có sẵn, không thêm thư viện; ép đầu ra UTF-8.
- *Quyết định của tôi:* option rule không hỗ trợ được báo bằng **một** dòng WARNING tổng hợp (kèm gợi ý bật DEBUG), chi tiết từng rule ở DEBUG, vì nó làm rule khớp sai nghĩa; nạp 0 rule là WARNING. Không còn dòng banner `=====` và các mốc `[1/4]`.

## Ràng buộc chung

- Tên logger cố định: `nids.engine` (`main.py`, `ids_realtime.py`), `nids.alert` (dòng cảnh báo trong `main.py`), `nids.rules` (`manager_rules.py`), `nids.db` (`services/database/__init__.py`), `nids.capture` (`packet_capture.py`), `nids.api` (`api/main.py`), `nids.pcap` (`create_demo_pcap.py`).
- Mã màu ANSI cố định: DEBUG `2`, INFO `32`, WARNING `33`, ERROR `31`, CRITICAL `1;31`, cột khu vực `36`; nội dung cảnh báo P1 `1;31`, P2 `33`, P3 `34`, priority khác không tô màu. Dạng `\033[<mã>m...\033[0m`.
- Không còn lời gọi `print(` trong `main.py`, `create_demo_pcap.py`, `api/`, `config/`, `services/`.
- Mọi nội dung log mới viết tiếng Việt có dấu.
- Làm trên nhánh mới `feature/colored-logging` tạo từ `main`. Chỉ `git commit` khi người dùng đồng ý rõ ràng; không push, không merge vào `main`.
- Không đổi hành vi phát hiện (`DetectionEngine.evaluate_packet`), cấu trúc DB hay API `/api/alerts`.

## Review Focus

- **Đầu ra bị chuyển hướng** (`python main.py > log.txt`, `docker logs`): không có mã màu ANSI trong văn bản. Test ở Task 1.
- **Terminal Windows dùng encoding cũ (cp1252)**: log tiếng Việt có dấu không gây `UnicodeEncodeError`. Test ở Task 1.
- **CSDL mất kết nối khi đang có tấn công**: cảnh báo vẫn hiện trên terminal, kèm một dòng ERROR. Test ở Task 3.
- **Cảnh báo ICMP (không có port) hoặc cảnh báo AI (`sid` là `None`)**: không in `:None`. Test ở Task 3.
- **Rule `priority:4` hoặc `log_level` sai trong settings**: không crash; P4 không tô màu và vẫn được đếm trong tổng kết; `log_level` sai thì về `INFO` kèm cảnh báo. Test ở Task 1 và Task 3.

---

### Task 1: Module cấu hình logging có màu

**Files:**
- Create: `config/logger.py`
- Test: `tests/test_logger.py`

**Interfaces:**
- Produces:
  - `class ColorFormatter(logging.Formatter)` với `__init__(self, use_color: bool)`. Định dạng `f"{giờ %H:%M:%S} {level:<8} {area:<8} {message}"`, trong đó `area` là tên logger bỏ tiền tố `"nids."`. Nếu record có thuộc tính `priority` (int) thì tô màu nội dung theo bảng màu ở Ràng buộc chung. Có `exc_info` thì nối traceback như `logging.Formatter`. Màu chỉ áp dụng khi `use_color` là True; khi tô màu, padding tính trên chữ chưa có mã màu.
  - `setup_logging(level: str = "INFO", stream: Optional[TextIO] = None) -> logging.Logger`, trả về logger `"nids"`:
    - không truyền `stream` thì dùng `sys.stdout` sau khi gọi `reconfigure(encoding="utf-8", errors="replace")` nếu có hàm đó;
    - `use_color = stream.isatty() and "NO_COLOR" not in os.environ`;
    - trên `win32`, khi có màu, bật chế độ ANSI bằng `os.system("")` và ghi comment `shortcut:` nêu giới hạn;
    - gọi lại nhiều lần không nhân đôi handler (luôn đúng một handler); `propagate = False`;
    - `level` không hợp lệ (không phải DEBUG/INFO/WARNING/ERROR/CRITICAL, không phân biệt hoa thường) thì dùng INFO và ghi WARNING có chứa chuỗi `log_level`.

- [ ] **Step 1: Viết test fail** trong `tests/test_logger.py`

  Có fixture `autouse` dọn sau mỗi test: xóa handler của logger `"nids"`, đặt `propagate = True`, `level = logging.NOTSET` (để `caplog` ở các test khác vẫn hoạt động).
  - `test_plain_format`: `ColorFormatter(use_color=False).format(record)` với record tên `"nids.rules"`, mức INFO, nội dung `"Đã nạp 30 rule"` khớp regex `^\d\d:\d\d:\d\d INFO     rules    Đã nạp 30 rule$`.
  - `test_colored_level_and_area`: `use_color=True`, kết quả chứa `"\033[32mINFO"` và `"\033[36mrules"`.
  - `test_alert_priority_colors`: record WARNING có `priority=1` chứa `"\033[1;31m"`; `priority=2` chứa `"\033[33m"` ở phần nội dung; `priority=3` chứa `"\033[34m"`; `priority=4` không chứa `"\033[1;31m"`, `"\033[34m"`, và nội dung không bị bọc mã màu.
  - `test_non_tty_stream_has_no_color`: `setup_logging("INFO", stream=io.StringIO())`, ghi một WARNING có `extra={"priority": 1}`; `"\033"` không có trong `stream.getvalue()`.
  - `test_level_and_idempotent_setup`: gọi `setup_logging("DEBUG", stream=s)` hai lần; `logging.getLogger("nids").level == logging.DEBUG`; `len(logging.getLogger("nids").handlers) == 1`; `propagate is False`; `logging.getLogger("nids.x").debug("chi tiết")` ghi đúng một dòng vào `s`.
  - `test_invalid_level_falls_back_to_info`: `setup_logging("VERBOSE", stream=s)`; level là INFO và `"log_level"` có trong `s.getvalue()`.
  - `test_utf8_on_legacy_encoding`: `monkeypatch.setattr(sys, "stdout", io.TextIOWrapper(io.BytesIO(), encoding="cp1252"))`; `setup_logging("INFO")`; `logging.getLogger("nids.rules").info("Đã nạp rule từ tệp")` không raise; `sys.stdout.encoding.lower().replace("-", "") == "utf8"`.

- [ ] **Step 2: Chạy để thấy fail**

Run: `python -m pytest tests/test_logger.py -v -p no:cacheprovider`
Expected: FAIL với `ModuleNotFoundError: No module named 'config.logger'`.

- [ ] **Step 3: Viết `ColorFormatter` và `setup_logging` trong `config/logger.py`** theo Interfaces.

- [ ] **Step 4: Chạy để thấy pass**

Run: `python -m pytest -q -p no:cacheprovider`
Expected: toàn bộ pass.

- [ ] **Step 5: Commit** (chỉ khi người dùng đồng ý)

```bash
git add config/logger.py tests/test_logger.py
git commit -m "feat(logging): them cau hinh logging co mau"
```

---

### Task 2: Chuyển print trong `services/` sang logging

**Files:**
- Modify: `services/detection/manager_rules.py`, `services/detection/ids_realtime.py`, `services/database/__init__.py`, `services/ingestion/packet_capture.py`
- Test: `tests/test_rule_loading.py` (thêm), `tests/test_db_init.py` (tạo)

**Interfaces:**
- Consumes: không cần `setup_logging`; module chỉ gọi `logging.getLogger("nids.<khu vực>")` ở đầu file.
- Produces: các thông điệp mà `main.py` (Task 3) không còn tự in:
  - `RuleManager.load_all_rules()` ghi INFO `"Đã nạp {n} rule từ {rules_dir}"` khi `n > 0`, và WARNING `"Không nạp được rule nào từ {rules_dir}, engine sẽ không phát hiện được tấn công nào"` khi `n == 0`.
  - Có rule mang option không hỗ trợ: một WARNING `"{k} rule có option không hỗ trợ, bật log_level: DEBUG để xem chi tiết"`, và mỗi rule một DEBUG `"SID {sid}: bỏ qua option không hỗ trợ {options} ({location})"`.
  - Lỗi parse: WARNING `"Lỗi dòng {line_no} trong {file}: {e}"`. SID trùng: WARNING `"Bỏ qua SID trùng {sid} ({location})"`.

Thông điệp còn lại (đổi sang tiếng Việt có dấu, giữ nguyên ý):
- `init_db`: mỗi lần thử lại là WARNING `"CSDL chưa sẵn sàng (lần {attempt}/{max_retries}), thử lại sau {delay}s"`; thành công là INFO `"Kết nối và khởi tạo CSDL thành công"`; hết lượt là ERROR rồi `raise`.
- BPF fallback trong `packet_capture.py`: WARNING.
- Nhánh không có callback trong `DetectionEngine._handle_alert_dispatch`: DEBUG (bỏ in trùng cảnh báo).

- [ ] **Step 1: Viết test fail**

Trong `tests/test_rule_loading.py` (dùng `caplog.set_level(logging.DEBUG, logger="nids")`):
  - `test_zero_rules_logs_warning`: thư mục không tồn tại, có record WARNING tên `"nids.rules"` chứa `"Không nạp được rule nào"`.
  - `test_loaded_rules_logs_info`: một rule hợp lệ, có record INFO chứa `"Đã nạp 1 rule"`.
  - `test_unsupported_option_summary`: rule `alert tcp any any -> any any (content:"x"; nocase; sid:1; rev:1;)`, đúng một WARNING chứa `"1 rule có option không hỗ trợ"`, và một DEBUG chứa `"SID 1"`.
  - `test_bad_line_and_duplicate_logged`: dòng thiếu `;` cuối và hai rule cùng `sid:2`, có WARNING chứa `"Lỗi dòng 1"` và WARNING chứa `"Bỏ qua SID trùng 2"`.

Trong `tests/test_db_init.py`:
  - `test_init_db_retries_then_succeeds`: monkeypatch `services.database.Base.metadata.create_all` để raise `OperationalError` giả (dùng `Exception("down")`) ở lần gọi đầu rồi thành công; `init_db(max_retries=3, delay=0)`; có WARNING `"nids.db"` chứa `"lần 1/3"` và INFO chứa `"thành công"`.

- [ ] **Step 2: Chạy để thấy fail**

Run: `python -m pytest tests/test_rule_loading.py tests/test_db_init.py -v -p no:cacheprovider`
Expected: các test mới FAIL vì chưa có record log.

- [ ] **Step 3: Thay `print` bằng logger** ở bốn file, đúng thông điệp và mức độ ở Interfaces. Việc tổng hợp WARNING option không hỗ trợ và INFO/WARNING số rule đặt ở cuối `load_all_rules`.

- [ ] **Step 4: Chạy toàn bộ test**

Run: `python -m pytest -q -p no:cacheprovider`
Expected: toàn bộ pass.

- [ ] **Step 5: Commit** (chỉ khi người dùng đồng ý)

```bash
git add services tests/test_rule_loading.py tests/test_db_init.py
git commit -m "refactor(logging): dung logging trong services"
```

---

### Task 3: Đầu ra của `main.py`, API và script tạo pcap

**Files:**
- Modify: `main.py`, `api/main.py`, `create_demo_pcap.py`
- Test: `tests/test_main_output.py` (tạo)

**Interfaces:**
- Consumes: `setup_logging(level: str, stream=None)` (Task 1); thông điệp nạp rule do `RuleManager` ghi (Task 2), nên `main.py` không tự in số rule nữa.
- Produces (cấp module trong `main.py`):
  - `format_alert(alert_data: dict) -> str`:
    - có đủ port: `"[P{severity}] SID {sid}  {msg}  {src_ip}:{src_port} → {dst_ip}:{dst_port}"`;
    - port là `None` thì bỏ phần `:port` của đầu đó;
    - `sid` là `None` thì thay `SID {sid}` bằng `AI-ANOMALY`.
  - `format_summary(total_packets: int, by_priority: Counter) -> str`: `"Hoàn tất: {total_packets} gói, {tổng} cảnh báo (P1: a, P2: b, P3: c)"`. Luôn có P1, P2, P3; priority khác có mặt thì nối thêm theo thứ tự tăng dần.
  - `class DropCounter` với `__init__(self, interval: float = 5.0)` và `record(self, now: float) -> Optional[int]`: lần drop đầu tiên trả về `1`; sau đó trả về số drop đã dồn (tính cả lần hiện tại) khi đã qua `interval` giây kể từ lần báo trước, ngược lại trả về `None`.
  - `handle_alert(alert_data: dict) -> None`:
    - ghi trước `logging.getLogger("nids.alert").warning(format_alert(alert_data), extra={"priority": severity})` và tăng bộ đếm priority cấp module `alert_counts: Counter`;
    - sau đó mới lưu DB; lỗi DB thì ghi ERROR `"Không thể lưu cảnh báo vào CSDL: {e}"`.

Hành vi `main()`:
- Gọi `setup_logging(SETTINGS.get("system", {}).get("log_level", "INFO"))` đầu tiên.
- INFO `"Khởi động Hybrid NIDS (chế độ: {capture_mode})"`, bỏ banner `=====` và các mốc `[1/4]`.
- Đếm số gói đã decode trong `on_raw_packet`. Queue đầy thì dùng `DropCounter` và ghi WARNING `"Queue đầy, đã bỏ {n} gói"` khi `record()` trả về số.
- Offline: sau `packet_queue.join()` ghi INFO `format_summary(...)` rồi INFO `"Xem cảnh báo tại http://localhost:8000/api/alerts/"`.
- Ctrl+C: INFO `"Dừng hệ thống NIDS"`. Lỗi capture: ERROR `"Lỗi khi bắt gói tin: {e}"`.

`api/main.py`: `lifespan` gọi `setup_logging(...)` như trên, ba `print` thành INFO trên `nids.api`. `create_demo_pcap.py`: gọi `setup_logging("INFO")`, các dòng tóm tắt thành INFO trên `nids.pcap`.

- [ ] **Step 1: Viết test fail** trong `tests/test_main_output.py`
  - `test_format_alert_with_ports`: `format_alert({"severity": 1, "sid": 1000001, "msg": "X", "src_ip": "1.1.1.1", "src_port": 5, "dst_ip": "2.2.2.2", "dst_port": 80}) == "[P1] SID 1000001  X  1.1.1.1:5 → 2.2.2.2:80"`.
  - `test_format_alert_icmp_and_ai`: cùng dữ liệu nhưng `src_port=None`, `dst_port=None`, `sid=None`, `severity=2` thì ra `"[P2] AI-ANOMALY  X  1.1.1.1 → 2.2.2.2"`.
  - `test_format_summary`: `format_summary(10, Counter({1: 2, 3: 1})) == "Hoàn tất: 10 gói, 3 cảnh báo (P1: 2, P2: 0, P3: 1)"`; `format_summary(5, Counter()) == "Hoàn tất: 5 gói, 0 cảnh báo (P1: 0, P2: 0, P3: 0)"`; `format_summary(1, Counter({4: 1})) == "Hoàn tất: 1 gói, 1 cảnh báo (P1: 0, P2: 0, P3: 0, P4: 1)"`.
  - `test_drop_counter`: `c = DropCounter(interval=5.0)`; `c.record(0.0) == 1`; `c.record(1.0) is None`; `c.record(2.0) is None`; `c.record(6.0) == 3`.
  - `test_alert_shown_even_if_db_fails`: monkeypatch `main.EventRepository.save_alert` để raise `Exception("db down")`; `caplog.set_level(logging.DEBUG, logger="nids")`; `handle_alert({...severity 1...})` không raise; có record WARNING tên `"nids.alert"` chứa `"SID 1000001"` với `record.priority == 1`, và record ERROR chứa `"db down"`.
  - `test_no_print_calls_left`: parse AST các file `main.py`, `create_demo_pcap.py`, `api/**/*.py`, `config/*.py`, `services/**/*.py`; không có `ast.Call` nào có `func` là `ast.Name(id="print")`.

- [ ] **Step 2: Chạy để thấy fail**

Run: `python -m pytest tests/test_main_output.py -v -p no:cacheprovider`
Expected: FAIL vì `format_alert`, `format_summary`, `DropCounter` chưa có, và `test_no_print_calls_left` báo các file còn `print`.

- [ ] **Step 3: Sửa `main.py`, `api/main.py`, `create_demo_pcap.py`** theo Interfaces và Hành vi ở trên.

- [ ] **Step 4: Kiểm tra**

Run: `python -m pytest -q -p no:cacheprovider`, rồi chạy thử replay pcap: tạm sửa `config/settings.yaml` thành `capture_mode: offline` và `database.type: sqlite`, chạy `python main.py`, sau đó hoàn tác bằng `git checkout config/settings.yaml` và xóa `nids_events.db` vừa sinh ra.
Expected: test pass; terminal hiện dòng khởi động, các dòng cảnh báo có màu, dòng `Hoàn tất: 39 gói, ...`, không có banner `=====`.

- [ ] **Step 5: Commit** (chỉ khi người dùng đồng ý)

```bash
git add main.py api/main.py create_demo_pcap.py tests/test_main_output.py
git commit -m "feat(logging): dong canh bao theo priority va tong ket replay"
```

---

### Task 4: Thống nhất ngôn ngữ comment và cập nhật tài liệu

**Files:**
- Modify (comment và docstring): `main.py`, `create_demo_pcap.py`, `api/main.py`, `services/ingestion/packet_capture.py`, `services/ingestion/packet_decoder.py`, `services/ingestion/__init__.py`, `services/detection/__init__.py`, `services/detection/manager_rules.py`, `services/detection/threshold_manager.py`, `services/database/repository.py`; các file `.py` khác trong `api/`, `config/`, `services/` nếu gặp comment không dấu hoặc câu tiếng Anh.
- Modify (tài liệu): `CLAUDE.md`, `README.md`
- Test: `tests/test_code_language.py` (tạo)

**Interfaces:**
- Consumes: không có. Chỉ đổi comment, docstring và chuỗi; không đổi logic.
- Produces: quy ước "comment, docstring, log viết tiếng Việt có dấu; thuật ngữ kỹ thuật và tên trong code giữ tiếng Anh".

- [ ] **Step 1: Viết test fail** `test_no_unaccented_vietnamese` trong `tests/test_code_language.py`

  - Dùng `tokenize` đọc mọi comment và mọi chuỗi (`STRING`) trong `main.py`, `create_demo_pcap.py`, `api/`, `config/`, `services/`, `tests/` (trừ chính `tests/test_code_language.py`).
  - Báo lỗi (liệt kê `file:dòng`) nếu khớp regex không phân biệt hoa thường `\b(khong|duoc|dang|chua|cua|nhung|voi|luat|nap|loi|trong|thanh cong|phat hien|goi tin|xu ly|ket noi|khoi dong|canh bao)\b`.

- [ ] **Step 2: Chạy để thấy fail**

Run: `python -m pytest tests/test_code_language.py -v -p no:cacheprovider`
Expected: FAIL, liệt kê các dòng không dấu (chủ yếu ở `main.py`, `packet_capture.py`, `packet_decoder.py`, `create_demo_pcap.py`).

- [ ] **Step 3: Viết lại comment và docstring** sang tiếng Việt có dấu, giữ nguyên ý. Câu tiếng Anh dạng văn xuôi cũng dịch; thuật ngữ (Aho-Corasick, payload, buffer, SID...) và tên trong code giữ nguyên. Không đổi payload hay dữ liệu trong `create_demo_pcap.py`.

- [ ] **Step 4: Cập nhật tài liệu**
  - `CLAUDE.md`: thay câu "comment trong code và log trộn tiếng Việt (thường không dấu) và tiếng Anh" bằng quy ước mới. Thêm một gạch đầu dòng ở mục Kiến trúc: logging cấu hình ở `config/logger.py`, kèm danh sách tên logger trong Ràng buộc chung, "dùng `logging.getLogger("nids.<khu vực>")`, không dùng `print`", mức độ lấy từ `system.log_level`.
  - `README.md`: ở phần cấu hình, ghi `system.log_level` (`INFO` mặc định, `DEBUG` để xem chi tiết) và biến môi trường `NO_COLOR` để tắt màu.

- [ ] **Step 5: Kiểm tra toàn bộ**

Run: `python -m pytest -q -p no:cacheprovider`
Expected: toàn bộ pass.

- [ ] **Step 6: Commit** (chỉ khi người dùng đồng ý)

```bash
git add main.py create_demo_pcap.py api config services CLAUDE.md README.md tests/test_code_language.py
git commit -m "docs: thong nhat comment tieng Viet co dau, ghi chu logging"
```
