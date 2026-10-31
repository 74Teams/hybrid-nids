# Project Instructions for Claude

File này hướng dẫn Claude Code (claude.ai/code) khi làm việc với code trong repository này. Quy tắc chi tiết theo từng khu vực nằm trong `.claude/rules/` và được nạp khi làm việc với file tương ứng.

## Project Overview

Hybrid NIDS + honeypot (đồ án PBL4): hệ thống phát hiện xâm nhập mạng kết hợp static rule tương thích Snort 3, một AI worker phát hiện bất thường theo flow và honeypot SSH/HTTP làm nguồn sự kiện thứ hai. Kèm theo là web console kiểu pfSense để xem cảnh báo và quản lý rule, cùng một môi trường Docker lab (attacker, victim) để trình diễn. Người dùng là nhóm sinh viên làm đồ án và giảng viên chấm, nên ưu tiên chạy được, demo được và dễ giải thích.

## Tech Stack

- Python 3.10+
- Scapy ≥ 2.5 (capture + decode), pyahocorasick ≥ 2.1 (prefilter)
- SQLAlchemy 2.0 + PyMySQL (MySQL trong Docker, SQLite khi chạy local)
- FastAPI + Uvicorn (API, dashboard); HTML/CSS/JS thuần, biểu đồ SVG tự vẽ, không dùng thư viện frontend
- paramiko ≥ 3.4 (honeypot SSH), Flask ≥ 3.0 (honeypot HTTP), pydantic-settings
- numpy, pandas, scikit-learn, joblib (dành cho AI worker, chưa dùng)
- pytest; Docker Compose; GitHub Actions chạy pytest cho mỗi PR vào `main`

## Project Structure

Lệnh luôn chạy từ thư mục gốc repo (`pytest.ini` đặt `pythonpath = .`).

- `nids/engine/` — process engine (`python -m nids.engine`): capture, decode, rule parser, Aho-Corasick, detection, threshold
- `nids/api/` — process FastAPI: `routes/` (alerts, rules), `static/` (dashboard, logs, rules page)
- `nids/honeypot/` — honeypot SSH và HTTP (`python -m nids.honeypot ssh|http`), `store.py` ghi sự kiện
- `nids/db/` — `models.py` (`events`, `event_payloads`), `repository.py` (`EventRepository`)
- `nids/ai.py` — `AITrafficWorker` (stub); `nids/config.py` — `SETTINGS`, `get_db_url()`; `nids/logger.py` — `setup_logging`
- `rules/` — file `.rules` theo category, `custom.rules`, `vendor/`, `state.yaml` (gitignore)
- `config/settings.example.yaml` — file mẫu được commit; `config/settings.yaml` — cấu hình local (bị git ignore, thiếu thì dùng file mẫu)
- `lab/` — Docker lab: `attacker/attack_demo.py`, `victim/`
- `tests/` — chia theo khu vực: `engine/`, `api/`, `honeypot/`, `lab/`
- `docs/` — `demo/kich-ban-demo.md` (kịch bản thuyết trình), `ai/` (thiết kế AI worker)
- `.claude/rules/` — quy tắc chi tiết theo khu vực; `.claude/commands/` — slash command (`them-rule`)

Các process (engine, API, mỗi honeypot một process) chạy riêng và chỉ giao tiếp qua database chung cùng các file trong `rules/`.

## Coding Conventions

- README, tài liệu, comment, docstring và nội dung log viết bằng tiếng Việt có dấu. Tên trong code, lệnh, đường dẫn, key cấu hình và thuật ngữ kỹ thuật chuẩn (Aho-Corasick, pub/sub, SID) giữ tiếng Anh.
- Commit message viết tiếng Anh, theo Conventional Commits, kèm tag issue `(#số)` nếu có. Branch đặt dạng `<loại>/<mô-tả-ngắn>`. Mô tả PR vẫn viết tiếng Việt. Chi tiết: `.claude/rules/git-workflow.md`; slash command `/ship` làm trọn quy trình.
- Không dùng `print`: mỗi module dùng `logging.getLogger("nids.<khu vực>")` (xem `.claude/rules/logging.md`).
- Dữ liệu truyền giữa các tầng dùng dataclass có sẵn (`DecodedPacket`, `ParsedHTTPRequest`, `SnortRule`), không dùng dict tự do.
- Test tự dựng `DecodedPacket` và khởi tạo `DetectionEngine` trực tiếp, thường với `enable_threshold=False`.

## Rules (Do Not Break)

- KHÔNG chạy `git commit`/`git push` khi chưa được người dùng cho phép rõ ràng. Không bao giờ commit, push hay merge thẳng vào `main`: tạo nhánh mới, push nhánh đó và mở pull request (xem `.claude/rules/git-workflow.md`).
- Honeypot không bao giờ thực thi input của attacker. Lỗi ghi CSDL không được làm sập sensor.
- DB chỉ lưu sự kiện cảnh báo. Rule chỉ nằm trong file `rules/`, không nạp rule từ DB.
- Thao tác ghi rule qua API phải kiểm tra header `X-API-Key` khớp `NIDS_API_KEY`. Chưa đặt biến môi trường thì thao tác ghi bị khoá.
- Thêm rule mới thì phải thêm đòn tương ứng trong `lab/attacker/attack_demo.py`, nếu không `tests/lab/test_attack_demo.py` sẽ fail. Trước khi thêm hoặc sửa rule, đọc `.claude/rules/snort-rules.md`.
- Không bỏ port 3306 khỏi `network.bpf_filter` (lý do ở mục Known Issues).

## Common Commands

- Cài đặt: `pip install -r requirements.txt`
- Engine: `python -m nids.engine` (live hoặc offline, theo `settings.yaml`)
- Honeypot: `python -m nids.honeypot ssh` (cổng 2222), `python -m nids.honeypot http` (cổng 8080)
- API + dashboard: `uvicorn nids.api.main:app --host 0.0.0.0 --port 8000 --reload` (Swagger tại `/docs`)
- Test: `pytest`; một test: `pytest tests/engine/test_diverse_rules_engine.py::test_name`
- Docker lab: `docker compose up --build` (MySQL, victim nginx, engine, honeypot, API, attacker trên mạng 172.28.0.0/16)
- Build: không có bước build riêng; chưa cấu hình linter.

## Current Focus

- Quản lý rule nhiều file (branch `feature/rule-management`): category, override theo SID, sửa `custom.rules` trên trang Rules kiểu pfSense.
- Thiết kế AI worker theo flow (`docs/ai/`) để thay stub trong `nids/ai.py` mà không phải sửa capture, decoder, DB hay API.
- Chưa triển khai: Redis pub/sub, WebSocket alert. Phía honeypot chưa có session theo kết nối, HASSH, route catch-all, giới hạn tài nguyên.

## Known Issues / Gotchas

- File mẫu `settings.example.yaml` được commit; `settings.yaml` là file local bị ignore, mật khẩu Docker nằm ở `.env`. Mặc định của file mẫu dùng `capture_mode: "live"`, interface `eth0` và MySQL của Docker. Khi chạy local thì chuyển sang `sqlite` (và `offline` kèm `pcap_file` nếu cần).
- Biến trong rule được hard-code: `$HTTP_PORTS` xử lý trong `_match_port`, còn `decoder.HTTP_PORTS` quyết định payload nào được parse thành HTTP. Thêm port hoặc biến mới thì phải sửa cả hai chỗ.
- Parser chỉ hiểu cú pháp Snort 3. Cú pháp Snort 2 (`nocase;` đứng riêng, `severity:`, `http_method:"POST"`) không được hỗ trợ.
- Engine sniff cả kết nối của chính nó tới MySQL. Nếu bỏ port 3306 khỏi BPF filter, câu INSERT chứa chuỗi tấn công sẽ sinh alert mới thành vòng lặp.
- `nids_api` cố ý chạy ở network riêng để request poll của dashboard không bị engine sniff nhầm.
- `init_db()` thử lại 15 lần × 2s vì MySQL khởi động chậm. Đừng coi lần kết nối thất bại đầu tiên là lỗi.
- Honeypot ghi từ process khác, nên cache IP honeypot trong engine có TTL 5 giây và cảnh báo có thể chưa được làm giàu ngay.
- `nids/ai.py` mới là stub: đừng viết test hay demo giả định AI worker đã sinh cảnh báo.

Quy tắc chi tiết: `.claude/rules/git-workflow.md`, `engine.md`, `api-web.md`, `honeypot.md`, `config-db-docker.md`, `logging.md`, `lab-demo.md`, `snort-rules.md`.
