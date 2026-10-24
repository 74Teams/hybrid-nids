# Rule chỉ đọc từ file: Kế hoạch triển khai

> **Dành cho agent thực thi:** BẮT BUỘC dùng superpowers:subagent-driven-development (khuyến nghị) hoặc superpowers:executing-plans để thực hiện từng task. Các bước dùng checkbox (`- [ ]`) để theo dõi.

**Mục tiêu:** Bỏ hoàn toàn việc lưu và quản lý rule trong database; `rules/local.rules` là nguồn rule duy nhất, engine chỉ đọc file lúc khởi động.

**Kiến trúc:** `main.py` đã nạp rule từ file nên không đổi. Việc cần làm là xóa phần DB và API của rule (bảng `rules`, `RuleRepository`, schema, nhóm `/api/rules`, hot-reload, singleton engine), rồi dọn parser khỏi cú pháp Snort 2 chỉ tồn tại để đọc rule cũ trong DB. DB chỉ còn lưu sự kiện cảnh báo (`events`).

**Công nghệ:** Python 3.10, SQLAlchemy 2.0, FastAPI, pytest.

**Spec:** Không có file spec riêng; các quyết định đã chốt trong cuộc trao đổi nằm ở mục "Quyết định đã chốt" bên dưới.

## Quyết định đã chốt

- Rule không còn CRUD qua API hay DB; muốn đổi rule thì sửa `rules/local.rules` rồi khởi động lại engine.
- **Bỏ hẳn** nhóm `/api/rules`, không giữ endpoint đọc.
- Giữ nguyên `/api/alerts` và `/health`.
- *Quyết định của tôi (chưa được xác nhận):* bỏ cột `events.rule_id` cùng quan hệ tới `RuleModel` (cột này chưa bao giờ được điền); bỏ phần đọc cú pháp Snort 2 trong parser; bỏ `SnortRule.is_enabled` (chỉ còn là `True`); bỏ field `detection_engine` khỏi `/health`.

## Ràng buộc chung

- Tài liệu viết bằng tiếng Việt có dấu (CLAUDE.md). Tên trong code, lệnh, đường dẫn giữ tiếng Anh.
- Chỉ `git commit` khi người dùng đồng ý rõ ràng; làm trên nhánh `feature/snort3-rules-cleanup`, không merge vào `main`.
- Không đổi hành vi `main.py`, `/api/alerts`, `EventRepository`, `DetectionEngine.evaluate_packet`.
- DB hiện có (MySQL/SQLite) không cần migration: cột `rule_id` còn lại cho phép NULL; bảng `rules` cũ để nguyên và không ai dùng.

## Review Focus

- **Rule file có CRLF** (soạn trên Windows): dòng vẫn được parse.
- **Rule bị tắt bằng cách comment** (`# alert ...`): không được nạp, không cảnh báo.
- **Thư mục rule trống hoặc không tồn tại**: nạp 0 rule, engine vẫn chạy và `evaluate_packet` trả về `[]`.
- **Rule dòng lỗi hoặc SID trùng**: bỏ qua dòng đó, các rule còn lại vẫn nạp.
- **Người dùng dán rule cú pháp Snort 2** (`http_method:"POST"`, `nocase;` đứng riêng): báo lỗi hoặc cảnh báo rõ ràng, không im lặng khớp sai.
- **Ghi sự kiện vào DB sau khi bỏ `rule_id`**: lưu được, không còn tham chiếu bảng `rules`.

---

### Task 1: Parser và engine chỉ đọc file

**Files:**
- Modify: `services/detection/manager_rules.py` (bỏ `load_from_db`, `reload_rules_from_db`, nhánh cú pháp Snort 2, docstring)
- Modify: `services/detection/ids_realtime.py` (bỏ `reload_rules_from_db`, bỏ kiểm tra `rule.is_enabled` trong `rebuild_index`)
- Modify: `services/detection/__init__.py` (bỏ field `SnortRule.is_enabled`)
- Modify: `tests/test_rule_parser.py` (thay `test_legacy_syntax_from_db_still_parses`)
- Create: `tests/test_rule_loading.py`

**Interfaces:**
- Consumes: `RuleManager.parse_rule_line(line: str) -> Optional[SnortRule]`, `RuleManager.load_all_rules() -> int`, `RuleManager.rules_by_sid`
- Produces: `RuleManager` chỉ có nguồn nạp là file. Parser nhận `http_method` chỉ ở dạng sticky buffer; `severity:` và `nocase;` đứng riêng được ghi vào `SnortRule.unsupported_options`.

- [ ] **Step 1: Viết test fail**

Trong `tests/test_rule_parser.py` thay test cũ bằng `test_snort2_syntax_is_not_silently_accepted`:
  - `parse('alert tcp any any -> any 80 (http_method:"POST"; content:"x"; sid:5; rev:1;)')` raise `ValueError`.
  - `parse('alert tcp any any -> any any (content:"x"; nocase; sid:6; rev:1;)').unsupported_options == ["nocase"]`.
  - `parse('alert tcp any any -> any any (content:"x"; severity:1; sid:7; rev:1;)').unsupported_options == ["severity"]`.

Trong `tests/test_rule_loading.py` (dùng `tmp_path`), mỗi test ghi `local.rules` rồi gọi `RuleManager(str(tmp_path)).load_all_rules()`:
  - `test_crlf_lines_are_parsed`: file dùng `\r\n`, hai rule hợp lệ, kết quả `== 2`.
  - `test_commented_rule_is_skipped`: một dòng `# alert ...` và một rule hợp lệ, kết quả `== 1`.
  - `test_missing_dir_loads_zero_and_engine_runs`: `RuleManager(str(tmp_path / "none")).load_all_rules() == 0`; `DetectionEngine(manager).evaluate_packet(<gói TCP tối thiểu>) == []`.
  - `test_bad_line_and_duplicate_sid_do_not_stop_loading`: một dòng thiếu `;` cuối, hai rule cùng `sid`, một rule hợp lệ khác; kết quả `== 2` (rule hợp lệ đầu tiên của SID trùng cộng rule còn lại).

- [ ] **Step 2: Chạy để thấy fail**

Run: `pytest tests/test_rule_parser.py tests/test_rule_loading.py -v`
Expected: `test_snort2_syntax_is_not_silently_accepted` FAIL (parser còn nhận cú pháp cũ); các test loading có thể pass vì hành vi đã có.

- [ ] **Step 3: Sửa `manager_rules.py`**

Xóa `load_from_db` và `reload_rules_from_db`; sửa docstring class còn một nguồn nạp; trong `parse_rule_line` xóa nhánh `name == "http_method" and value`, nhánh `elif name in CONTENT_MODIFIERS`, và `"severity"` khỏi `elif name in ("priority", "severity")`; `_register(self, rule, location)` giữ nguyên. Xóa hằng `CONTENT_MODIFIERS` nếu không còn ai dùng (`_apply_content_modifier` vẫn dùng chuỗi tên trực tiếp).

- [ ] **Step 4: Sửa `ids_realtime.py` và `__init__.py`**

Xóa `DetectionEngine.reload_rules_from_db`; xóa dòng `if not rule.is_enabled: continue` trong `rebuild_index`; xóa field `is_enabled` khỏi `SnortRule`.

- [ ] **Step 5: Chạy toàn bộ test**

Run: `pytest -q`
Expected: tất cả pass.

- [ ] **Step 6: Commit** (chỉ khi người dùng đồng ý)

```bash
git add services/detection tests/test_rule_parser.py tests/test_rule_loading.py
git commit -m "refactor(detection): chi doc rule tu file, bo cu phap Snort 2"
```

---

### Task 2: Gỡ rule khỏi DB và API

**Files:**
- Delete: `api/routes/rules.py`, `api/dependencies.py`, `services/database/schemas.py` (đã `git rm` trong working tree, cần commit)
- Modify: `services/database/models.py` (xóa `RuleModel`, `EventModel.rule_id`, quan hệ `rule`; dọn import `Boolean`, `ForeignKey`, `relationship` nếu thừa)
- Modify: `services/database/repository.py` (xóa `RuleRepository` và import liên quan; giữ `EventRepository`)
- Modify: `api/main.py` (xóa singleton, import rule trong `lifespan`, `rules_router`; sửa docstring và `description`; `/health` không còn `detection_engine`)
- Create: `tests/test_api_routes.py`

**Interfaces:**
- Consumes: `EventRepository.save_alert(alert_data: dict) -> EventModel` (không đổi)
- Produces: `api.main.app` chỉ có router `/api/alerts` và `/health`; `Base.metadata.tables` không chứa `rules`.

- [ ] **Step 1: Viết test fail** trong `tests/test_api_routes.py`

  - `test_no_rules_routes_remain`: `from api.main import app`; mọi `r.path` không bắt đầu bằng `/api/rules`; chứa `/api/alerts/` và `/health`.
  - `test_health_has_no_engine_field`: gọi hàm `health_check()` trực tiếp, kết quả `== {"status": "ok", "service": "NIDS_API"}`.
  - `test_rules_table_is_gone`: `"rules" not in Base.metadata.tables` và `not hasattr(EventModel, "rule_id")`.
  - `test_event_can_be_saved_without_rule_table`: tạo engine SQLite `:memory:`, `Base.metadata.create_all`, thêm một `EventModel` có đủ cột bắt buộc, `commit`, đọc lại được.

- [ ] **Step 2: Chạy để thấy fail**

Run: `pytest tests/test_api_routes.py -v`
Expected: FAIL (import `api.main` lỗi vì `api.routes.rules` không còn, và `RuleModel` còn tồn tại).

- [ ] **Step 3: Sửa `models.py`, `repository.py`, `api/main.py`** như danh sách Files ở trên. Trong `api/main.py`, `lifespan` chỉ còn `init_db()` rồi `yield`; docstring đầu file cập nhật thành "tạo bảng khi khởi động".

- [ ] **Step 4: Chạy để thấy pass**

Run: `pytest -q` rồi `python -c "import api.main; print('import OK')"`
Expected: tất cả pass và in `import OK`.

- [ ] **Step 5: Commit** (chỉ khi người dùng đồng ý)

```bash
git add -A api services tests/test_api_routes.py
git commit -m "refactor(api): bo CRUD rule, DB chi luu su kien canh bao"
```

---

### Task 3: Cập nhật tài liệu

**Files:**
- Modify: `README.md` (sơ đồ kiến trúc, bảng thành phần, cây thư mục, hướng dẫn chạy API, mục 7.1 và 8, bảng trạng thái tính năng, danh sách bảng DB)
- Modify: `CLAUDE.md` (mục kiến trúc, lưu ý hot-reload, `RuleManager`, parser, mục Rule)
- Modify: `.claude/rules/snort-rules.md` (quy trình, bảng SID, ghi chú `severity`)

**Interfaces:** không có; chỉ chứa thay đổi nội dung.

- [ ] **Step 1: README.md**
  - Bỏ mọi nhắc tới CRUD rule, hot-reload và bảng `rules`; mục 7.1 (Rules API) và mục 8 (Hot-Reload) xóa hẳn rồi đánh lại số mục.
  - Thay bằng một đoạn ngắn: rule nằm ở `rules/local.rules`, đổi rule thì sửa file và khởi động lại engine.
  - Bảng tính năng: bỏ hai dòng "Rule Management API" và "Hot-Reload"; cây thư mục bỏ `routes/rules.py`, `dependencies.py`, `schemas.py`.

- [ ] **Step 2: CLAUDE.md**
  - Bỏ đoạn "Lưu ý về hot-reload" và câu API import rule vào DB.
  - `RuleManager` chỉ parse từ file; bỏ câu "parser vẫn đọc được cú pháp cũ trong DB".
  - Mục Rule: nói rõ rule chỉ đọc từ file và áp dụng sau khi khởi động lại engine.

- [ ] **Step 3: `.claude/rules/snort-rules.md`**
  - Bước 3 "tăng `rev`": giữ làm quy ước ghi nhận thay đổi, bỏ lý do ghi đè DB.
  - Xóa dòng SID `2000001+` và phần nói `severity` chỉ còn để đọc rule cũ trong DB.
  - Mục "Option được hỗ trợ": ghi rõ cú pháp Snort 2 (`nocase;` đứng riêng, `http_method:"..."`, `severity:`) không được hỗ trợ.

- [ ] **Step 4: Kiểm tra tham chiếu còn sót**

Run: `grep -rnE "RuleRepository|RuleModel|load_from_db|reload_rules_from_db|hot-reload|Hot-Reload|/api/rules|_try_hot_reload|get_detection_engine" --include=*.md --include=*.py .`
Expected: không có kết quả nào (ngoại trừ chính file kế hoạch này).

- [ ] **Step 5: Kiểm tra toàn bộ**

Run: `pytest -q`
Expected: tất cả pass.

- [ ] **Step 6: Commit** (chỉ khi người dùng đồng ý)

```bash
git add README.md CLAUDE.md .claude/rules/snort-rules.md
git commit -m "docs: rule chi doc tu file, bo CRUD va hot-reload"
```
