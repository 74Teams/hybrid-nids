# Project Instructions for Claude

File này hướng dẫn Claude Code (claude.ai/code) khi làm việc với code trong repository này. Quy tắc chi tiết theo từng khu vực nằm trong `.claude/rules/` và được nạp khi làm việc với file tương ứng.

## Project Overview

Hybrid NIDS + honeypot (đồ án PBL4): hệ thống phát hiện xâm nhập mạng kết hợp static rule tương thích Snort 3, một AI worker phát hiện bất thường theo flow và honeypot SSH/HTTP làm nguồn sự kiện thứ hai. Kèm theo là web console kiểu shadcn/ui để xem cảnh báo và quản lý rule, cùng một môi trường Docker lab (attacker, victim) để trình diễn. Người dùng là nhóm sinh viên làm đồ án và giảng viên chấm, nên ưu tiên chạy được, demo được và dễ giải thích.

## Tech Stack

- Python 3.10+
- Scapy ≥ 2.5 (capture + decode), pyahocorasick ≥ 2.1 (prefilter)
- SQLAlchemy 2.0 + PyMySQL (MySQL trong Docker, SQLite khi chạy local)
- waitress ≥ 3.0 (server WSGI của honeypot HTTP)
- FastAPI + Uvicorn (API, dashboard); HTML/CSS/JS thuần, biểu đồ SVG tự vẽ, không dùng thư viện frontend
- Redis ≥ 7 (Docker) + redis-py ≥ 8.1: pub/sub đẩy tín hiệu cảnh báo mới tới WebSocket của dashboard (tuỳ chọn, tắt được)
- paramiko ≥ 3.4 (honeypot SSH), Flask ≥ 3.0 (honeypot HTTP), pydantic-settings
- numpy, pandas, scikit-learn, joblib (mô hình AI theo flow: đã huấn luyện bằng `common/tools/ai/`, `AITrafficWorker` chưa gắn vào engine)
- pytest; Docker Compose; GitHub Actions chạy pytest cho mỗi PR vào `main`

## Project Structure

Mã nguồn chia theo service. Mọi module vẫn nằm chung họ tên `nids.*` (namespace package, không có `nids/__init__.py`), mỗi thư mục `src/` đóng góp một phần. Chạy lệnh từ gốc repo sau khi đặt `PYTHONPATH` bằng `. .\scripts\env.ps1` (PowerShell) hoặc `source scripts/env.sh` (bash); `pytest` tự đặt qua `pytest.ini`.

```
services/                      mỗi service một thư mục: src/, tests/, Dockerfile, requirements.txt, README.md
├── sensor/        nids.engine (bắt gói, rule, tái hợp TCP, flow, ANOMALY), nids.ai (đặc trưng, mô hình; worker còn là stub)
├── honeypot/      nids.honeypot (SSH paramiko, HTTP Flask + waitress)
├── redirector/    nids.redirector (chuyển hướng IP đáng ngờ sang honeypot bằng iptables, chỉ chạy trong Docker lab)
└── dashboard/     nids.api (FastAPI: routes alerts/flows/rules/redirects; static: dashboard, logs, traffic, rules)
common/
├── core/          nids.config (SETTINGS), nids.logger, nids.realtime (publish_alert), nids.db (models, EventRepository)
├── config/        settings.example.yaml (commit); settings.yaml (local, gitignore)
└── tools/         ai/ (dựng dataset, huấn luyện, demo), eval/ (bộ đo CIC-IDS2017), cic/ (nhãn), rules/ (chuyển rule Snort 2 → 3)
data/
├── rules/         file .rules theo category, custom.rules, community-*.rules (sinh bằng tools.rules.snort2_convert), upstream/, vendor/; state.yaml (gitignore)
├── models/        flow_model.joblib (Random Forest)
├── pcap/          pcap nhỏ dùng cho test và demo (pcap lớn gitignore)
└── work/          dữ liệu sinh ra khi làm việc: manifest CIC, đặc trưng AI, kết quả đo, khoá SSH honeypot, DB SQLite local (gitignore)
lab/               attacker/ (attack_demo.py), victim/
tests/             test xuyên service: lab/ (kịch bản tấn công, compose, Dockerfile), kiểm tra ngôn ngữ, .dockerignore
docs/              tài liệu dự án, mục lục ở docs/README.md; docs/eval/ do tools.eval sinh ra
scripts/           env.ps1, env.sh (đặt PYTHONPATH)
.claude/           rules/ (quy tắc theo khu vực), commands/ (them-rule, ship, y-tuong), agents/ (git-workflow)
```

- Test của từng service nằm trong `services/<tên>/tests/` (và `common/*/tests/`); `pytest.ini` gom tất cả, một lệnh `pytest` chạy hết.
- `common/core` không được import từ service nào (chỉ chú thích kiểu qua `TYPE_CHECKING`). Dashboard cần bộ phân tích rule của sensor để kiểm tra `custom.rules`, nên image dashboard có cả mã nguồn sensor; `common/tools` cũng dùng lại mã sensor.
- Cấu hình, rule, mô hình đọc theo đường dẫn từ gốc repo (`data/rules`, `data/models`, `common/config`); trong Docker chúng được bind mount lúc chạy.

Các process (sensor, dashboard, redirector, mỗi honeypot một process) chạy riêng và chỉ giao tiếp qua database chung cùng các file trong `data/rules/`. Ngoại lệ duy nhất là tín hiệu "có cảnh báo mới" qua Redis (chỉ chứa id, dữ liệu vẫn lấy từ DB); Redis tắt hoặc chết thì mọi thứ vẫn chạy, dashboard quay về poll.

## Coding Conventions

- README, tài liệu, comment, docstring và nội dung log viết bằng tiếng Việt có dấu. Tên trong code, lệnh, đường dẫn, key cấu hình và thuật ngữ kỹ thuật chuẩn (Aho-Corasick, pub/sub, SID) giữ tiếng Anh.
- Commit message viết tiếng Anh, theo Conventional Commits, kèm tag issue `(#số)` nếu có. Branch đặt dạng `<loại>/<mô-tả-ngắn>`. Mô tả PR vẫn viết tiếng Việt. Chi tiết: `.claude/rules/git-workflow.md`; slash command `/ship` làm trọn quy trình.
- Không dùng `print`: mỗi module dùng `logging.getLogger("nids.<khu vực>")` (xem `.claude/rules/logging.md`).
- Dữ liệu truyền giữa các tầng dùng dataclass có sẵn (`DecodedPacket`, `ParsedHTTPRequest`, `SnortRule`), không dùng dict tự do.
- Test tự dựng `DecodedPacket` và khởi tạo `DetectionEngine` trực tiếp, thường với `enable_threshold=False`.

## Rules (Do Not Break)

- KHÔNG chạy `git commit`/`git push` khi chưa được người dùng cho phép rõ ràng. Không bao giờ commit, push hay merge thẳng vào `main`: tạo nhánh mới, push nhánh đó và mở pull request (xem `.claude/rules/git-workflow.md`).
- Honeypot không bao giờ thực thi input của attacker. Lỗi ghi CSDL không được làm sập sensor.
- DB chỉ lưu dữ liệu quan sát được và nhật ký hành động của hệ thống: sự kiện cảnh báo (`events`), flow log (`flows`, một dòng cho mỗi flow, không ghi từng gói) và lượt chuyển hướng IP sang honeypot (`redirects`). Rule chỉ nằm trong file `data/rules/`, không nạp rule từ DB.
- Thao tác ghi rule qua API phải kiểm tra header `X-API-Key` khớp `NIDS_API_KEY`. Chưa đặt biến môi trường thì thao tác ghi bị khoá.
- Thêm rule tự viết mới (không phải `community-*`) thì phải thêm đòn tương ứng trong `lab/attacker/attack_demo.py`, nếu không `tests/lab/test_attack_demo.py` sẽ fail. Trước khi thêm hoặc sửa rule, đọc `.claude/rules/snort-rules.md`.
- Không bỏ port 3306 và `172.28.0.30:6379` (Redis của lab) khỏi `network.bpf_filter` (lý do ở mục Known Issues).
- `publish_alert` và mọi đường Redis không được chặn hay làm lỗi sensor: publish chỉ ở thread nền, lỗi chỉ được log.

## Common Commands

- Cài đặt: `pip install -r requirements-dev.txt`; mỗi service có file riêng `services/<tên>/requirements.txt` (kèm `common/core/requirements.txt`)
- Đặt đường dẫn module (một lần mỗi terminal): `. .\scripts\env.ps1` hoặc `source scripts/env.sh`
- Sensor: `python -m nids.engine` (live hoặc offline, theo `settings.yaml`)
- Honeypot: `python -m nids.honeypot ssh` (cổng 2222), `python -m nids.honeypot http` (cổng 8080)
- Dashboard + API: `uvicorn nids.api.main:app --host 0.0.0.0 --port 8000 --reload` (Swagger tại `/docs`)
- Công cụ: `python -m tools.ai.train`, `python -m tools.eval.evaluate`, `python -m tools.rules.snort2_convert`
- Test: `pytest`; một test: `pytest services/sensor/tests/engine/test_diverse_rules_engine.py::test_name`
- Docker lab: `docker compose up --build` (MySQL, Redis, victim, sensor, honeypot, redirector, dashboard trên mạng 172.28.0.0/16); thêm máy tấn công: `docker compose --profile lab up --build`
- Build: mỗi service build từ Dockerfile riêng (`services/<tên>/Dockerfile`, context là gốc repo); chưa cấu hình linter.

## Current Focus

- Quản lý rule nhiều file (branch `feature/rule-management`): category, override theo SID, sửa `custom.rules` trên trang Rules kiểu pfSense.
- AI theo flow (issue #105): đã có mô hình và báo cáo (`docs/machine-learning-guide.md`); còn gắn `AITrafficWorker` vào engine (mục 9 của tài liệu đó) mà không phải sửa capture, decoder, DB hay API.
- Cảnh báo realtime qua Redis pub/sub + WebSocket (branch `feature/30-realtime-alert-push`, issue #30).
- Xem traffic và phát hiện bất thường theo ngưỡng: API flows + trang Traffic (#40, #41, đã merge), cảnh báo `ANOMALY` theo ngưỡng (#42, branch `feature/42-anomaly-detection`).
- Chuyển hướng IP đáng ngờ sang honeypot (branch `feature/29-redirect-to-honeypot`, issue #29).
- Giới hạn tài nguyên honeypot: cap kết nối, timeout idle, honeypot HTTP chạy bằng waitress (issue #27, branch `feature/27-honeypot-resource-limits`). Honeypot HTTP ghi mọi request (`http.request`, issue #26, branch `feature/26-http-catch-all`).

## Known Issues / Gotchas

- File mẫu `settings.example.yaml` được commit; `settings.yaml` là file local bị ignore, mật khẩu Docker nằm ở `.env`. Mặc định của file mẫu dùng `capture_mode: "live"`, interface `eth0` và MySQL của Docker. Khi chạy local thì chuyển sang `sqlite` (và `offline` kèm `pcap_file` nếu cần).
- Biến trong header rule (`$HTTP_PORTS`, `$HOME_NET`...) khai báo ở `detection.variables` trong `settings.yaml`, dùng chung cho parser và `decoder.HTTP_PORTS`. Đổi biến phải khởi động lại cả engine lẫn API (API dùng biến để kiểm tra `custom.rules`).
- Parser chỉ hiểu cú pháp Snort 3. Cú pháp Snort 2 (`nocase;` đứng riêng, `severity:`, `http_method:"POST"`) không được hỗ trợ.
- Engine sniff cả kết nối của chính nó tới MySQL. Nếu bỏ port 3306 khỏi BPF filter, câu INSERT chứa chuỗi tấn công sẽ sinh alert mới thành vòng lặp.
- Engine cũng sniff kết nối tới Redis (`172.28.0.30:6379`) nên BPF loại riêng địa chỉ này. Không loại cả cổng 6379 để vẫn thấy đòn nhắm vào cổng đó của victim. Tin Redis chỉ chứa id nên không thể sinh alert lặp, kể cả khi `settings.yaml` local còn BPF cũ.
- Cần `NIDS_REDIS_PASSWORD` trong `.env`, nếu không `docker compose` từ chối chạy. `redis.host` rỗng trong `settings.yaml` (mặc định khi chạy local) nghĩa là tắt Redis.
- `nids_api` cố ý chạy ở network riêng để request của dashboard (poll dự phòng, WebSocket) không bị engine sniff nhầm.
- `init_db()` thử lại 15 lần × 2s vì MySQL khởi động chậm. Đừng coi lần kết nối thất bại đầu tiên là lỗi.
- Honeypot ghi từ process khác, nên cache IP honeypot trong engine có TTL 5 giây và cảnh báo có thể chưa được làm giàu ngay.
- `data/rules/state.yaml` (do trang Rules ghi, gitignore) có thể tắt rule tự viết trên máy bạn và làm hỏng test rule/lab. Chạy `pytest` mà thấy lỗi SID không tồn tại thì đổi tên file đó tạm thời.
- Chạy lệnh Python từ gốc repo mà báo `No module named 'nids'` nghĩa là chưa đặt `PYTHONPATH`: chạy `scripts/env.ps1` hoặc `scripts/env.sh`.
- `services/sensor/src/nids/ai/worker.py` mới là stub (mô hình đã có nhưng chưa nạp vào engine): đừng viết test hay demo giả định AI worker đã sinh cảnh báo.

Quy tắc chi tiết: `.claude/rules/git-workflow.md`, `planning.md` (viết plan bằng tác nhân, không tự tạo file), `engine.md`, `api-web.md`, `web-design.md`, `honeypot.md`, `redirector.md`, `config-db-docker.md`, `logging.md`, `lab-demo.md`, `snort-rules.md`.
