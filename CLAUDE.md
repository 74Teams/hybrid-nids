# CLAUDE.md

File này hướng dẫn Claude Code (claude.ai/code) khi làm việc với code trong repository này.

## Dự án

Hybrid NIDS + honeypot (đồ án PBL4): hệ thống phát hiện xâm nhập mạng kết hợp static rule tương thích Snort, một AI worker phát hiện bất thường theo flow và honeypot SSH/HTTP làm nguồn sự kiện thứ hai. Python 3.10+, Scapy, pyahocorasick, SQLAlchemy 2.0, FastAPI, paramiko, Flask. README, tài liệu, comment, docstring và nội dung log đều viết bằng tiếng Việt có dấu; tên trong code và thuật ngữ kỹ thuật giữ tiếng Anh.

## Lệnh

```bash
pip install -r requirements.txt

python -m nids.engine            # chạy engine capture + detection (live hoặc offline, theo settings.yaml)
python -m nids.honeypot ssh       # honeypot SSH (cổng 2222); `python -m nids.honeypot http` cho honeypot HTTP (cổng 8080)
uvicorn nids.api.main:app --host 0.0.0.0 --port 8000 --reload   # API tra cứu alert (Swagger tại /docs)

pytest                                                      # chạy toàn bộ test
pytest tests/engine/test_diverse_rules_engine.py::test_name # chạy một test (test chia theo khu vực: engine, api, honeypot, lab)
```

Chưa cấu hình linter. Docker: `docker compose up --build` khởi động MySQL, một nginx "victim", NIDS engine và một container attacker trên mạng bridge cô lập (172.28.0.0/16).

## Kiến trúc

Toàn bộ code Python nằm trong package `nids/` (`engine/`, `api/`, `honeypot/`, `db/`, `ai.py`, `config.py`, `logger.py`); môi trường Docker demo (attacker, victim) nằm trong `lab/`; `config/` chỉ chứa `settings.yaml`. Lệnh luôn chạy từ thư mục gốc repo (`pytest.ini` đặt `pythonpath = .`).

Các **process riêng biệt** (engine, API, mỗi honeypot một process) dùng chung một database:

- `nids/engine/main.py` (chạy bằng `python -m nids.engine`) — process engine: `PacketCapture` (Scapy, live hoặc pcap offline) → `PacketDecoder.decode` (L2–L4 + HTTP L7 qua `http_parser`) → `queue.Queue` có giới hạn → một worker thread duy nhất gọi `DetectionEngine.evaluate_packet` và `AITrafficWorker.analyze_packet`. Alert đi qua callback `handle_alert` → `EventRepository.save_alert`.
- `nids/api/main.py` — process FastAPI. Khi khởi động, nó chỉ tạo bảng. API gồm `/api/alerts` (danh sách, lọc theo `source_type/protocol/src_ip/dst_ip/sid/severity/since/until/q`, phân trang `limit/offset`, tổng ở header `X-Total-Count`), `/api/alerts/{id}` (kèm payload), `/api/alerts/export.csv`, `/api/alerts/stats`, `/api/alerts/timeline?minutes&buckets` (số cảnh báo NIDS/honeypot theo cột thời gian), `DELETE /api/alerts/` (cùng bộ lọc; không lọc = xoá hết), `DELETE /api/alerts/{id}`, `/api/rules/` (danh sách rule kèm category và trạng thái bật/tắt; `categories`, `sids`, `sids/reset`, `categories/{name}/all`, `custom` để bật/tắt category, override SID và sửa `custom.rules` — thao tác ghi cần header `X-API-Key` khớp biến môi trường `NIDS_API_KEY`, chưa đặt thì bị khoá), `/health`. Web UI kiểu pfSense trong `nids/api/static/` (CSS chung `style.css` mount tại `/static`): dashboard tại `/`, trang Status › System Logs (`logs.html`) tại `/logs`, trang Services › Rules (`rules.html`) tại `/rules` kiểu Suricata trên pfSense: tab Categories, dropdown category, panel SID overrides (Apply / Reset All / Reset Current / Disable All / Enable All), ô sửa `custom.rules`. Chỉ giao diện sáng, bám phong cách pfSense. Biểu đồ dashboard là SVG thuần trong `nids/api/static/charts.js` (cột chồng theo thời gian, thanh chồng theo IP; xanh = NIDS, cam = honeypot; không dùng thư viện ngoài). DB chỉ lưu sự kiện cảnh báo (bảng `events`, `event_payloads`), không lưu rule; API chỉ ghi file trong `rules/` (`state.yaml`, `custom.rules`).
- `nids/honeypot/` — honeypot SSH (`ssh_honeypot.py`, paramiko, nhận mọi mật khẩu, shell giả) và HTTP (`web_honeypot.py`, Flask, trang login WordPress giả), chạy bằng `python -m nids.honeypot`. Cấu hình qua biến môi trường `HONEYPY_*` (`nids/honeypot/settings.py`); host key SSH tự sinh vào `data/` ở gốc repo (gitignore). Sensor chỉ thu thập: `nids/honeypot/store.py::log_event` ghi vào bảng `events` chung với `source_type="HONEYPOT"` (`attack_type` = event type như `ssh.auth.attempt`, dữ liệu thô vào `event_payloads`); lỗi ghi CSDL không được làm sập sensor. Không bao giờ thực thi input của attacker.
- `lab/attacker/attack_demo.py` — kịch bản tấn công demo, chạy trong container attacker. Mỗi đòn khai báo SID kỳ vọng; `tests/lab/test_attack_demo.py` kiểm tra đòn nào cũng trúng đúng rule và rule nào cũng có đòn trình diễn (thêm rule mới thì phải thêm đòn). Nhóm `honeypot` dùng `CommandAttack` (hydra) và `HttpAttack` vào 2222/8080, không có SID kỳ vọng. Kịch bản thuyết trình ở `docs/demo/kich-ban-demo.md`.

### Logging

- Cấu hình ở `nids/logger.py` (`setup_logging`, `ColorFormatter`), gọi một lần ở mỗi process: `nids/engine/main.py`, `nids/api/main.py`, `nids/honeypot/__main__.py`. Mức độ lấy từ `system.log_level` trong `settings.yaml` (mặc định `INFO`, `DEBUG` để xem chi tiết). Màu tự tắt khi đầu ra không phải terminal hoặc có biến môi trường `NO_COLOR`.
- Mỗi module dùng `logging.getLogger("nids.<khu vực>")`, không dùng `print`. Khu vực: `engine` (`engine/main.py`, `engine/detector.py`), `alert` (dòng cảnh báo trong `engine/main.py`), `rules` (`engine/rule_manager.py`), `db`, `capture`, `api`, `honeypot`, `attack` (`lab/attacker/attack_demo.py`).
- Cảnh báo mang `extra={"priority": n}` để formatter tô màu theo priority (P1 đỏ, P2 vàng, P3 xanh dương).

### Detection engine (`nids/engine/`)

- `RuleManager` chỉ parse rule cú pháp Snort từ file (`load_all_rules`); không có đường nạp rule từ DB.
- Parser hiểu cú pháp Snort 3: sticky buffer (`http_uri; content:...`), modifier sau dấu phẩy (`content:"x",nocase,depth 4`), tách option theo `;` nằm ngoài dấu ngoặc kép. Mỗi `ContentMatch`/`PcreMatch` mang buffer riêng của nó. Cú pháp Snort 2 (`nocase;` đứng riêng, `severity:`, `http_method:"POST"`) không được hỗ trợ.
- `DetectionEngine.rebuild_index` dựng danh sách rule theo protocol, cùng các matcher Aho-Corasick riêng (`MultiPatternMatcher`) cho URI, header, body và raw payload. Mỗi rule được index bằng fast pattern của nó (content có `fast_pattern`, nếu không thì content dài nhất). Rule không có fast pattern vào `no_content_rules` và luôn được đánh giá. `evaluate_packet` là phễu 4 tầng: demux theo protocol/port → prefilter Aho-Corasick → kiểm tra chi tiết (flags, flow, dsize, itype/icode, content theo buffer, pcre, `detection_filter`) → `ThresholdManager` chặn bớt để tránh bão alert.
- Biến trong rule được hard-code, không phải biến Snort tổng quát: `$HTTP_PORTS` được xử lý riêng trong `_match_port`, còn `decoder.HTTP_PORTS` (80, 8080, 8000, 3000, 5000, 443) quyết định payload nào được parse thành HTTP. Thêm biến mới hoặc HTTP port mới thì phải sửa cả hai chỗ.
- `DecodedPacket` / `ParsedHTTPRequest` (`nids/engine/packet.py`) và `SnortRule` (`nids/engine/rule.py`) là các dataclass truyền giữa các tầng. Các module còn lại: `capture.py`, `decoder.py` + `http_parser.py`, `rule_manager.py`, `matcher.py` (Aho-Corasick), `threshold.py`, `detector.py` (`DetectionEngine`).

### Làm giàu cảnh báo bằng honeypot

IP đã chạm honeypot (trong 1 giờ gần nhất) chắc chắn là attacker. `nids/engine/main.py::handle_alert` gọi `enrich_alert`: cảnh báo rule engine từ IP đó được nâng một bậc priority (tối đa P1) và gắn `[honeypot-confirmed]`. Danh sách IP đọc từ CSDL qua `HoneypotIPCache` (TTL 5 giây vì honeypot ghi từ process khác). API: `GET /api/alerts/?source_type=HONEYPOT|RULE_ENGINE` và `GET /api/alerts/attackers`.

### Cấu hình và database

- `config/settings.yaml` được load một lần lúc import vào `nids.config.SETTINGS`. `get_db_url()` dựng URL từ mục `database`, và các biến môi trường `NIDS_DB_HOST/PORT/NAME/USER/PASSWORD` sẽ ghi đè (docker-compose dựa vào điều này). `type: sqlite` dùng `db_url`.
- `init_db()` thử lại tối đa 15 lần, mỗi lần cách 2s, vì MySQL khởi động chậm trong Docker.
- `settings.yaml` đã commit mặc định dùng `capture_mode: "live"`, interface `eth0` và IP MySQL của Docker; khi chạy local thì chuyển sang `sqlite` (và `offline` kèm `pcap_file` nếu có file pcap riêng).
- Trong Docker, `honeypot_ssh` và `honeypot_http` cũng dùng `network_mode: service:victim_app` (cổng 2222 và 8080; 8080 nằm trong `HTTP_PORTS` nên rule web áp dụng luôn), nên cùng một đòn vừa sinh cảnh báo rule vừa sinh sự kiện honeypot. `nids_engine` dùng `network_mode: service:victim_app` để sniff traffic của victim, và mount repo vào `/app`. `nids_api` (API + dashboard) cố ý chạy ở network riêng để request poll của dashboard không bị engine sniff nhầm. `network.bpf_filter` loại port 3306: engine thấy cả kết nối ghi alert vào MySQL, nếu không loại thì câu INSERT chứa chuỗi tấn công sẽ sinh alert mới (vòng lặp).

### Test

Test khởi tạo `DetectionEngine` trực tiếp (thường với `enable_threshold=False`) và tự dựng các `DecodedPacket`. `tests/engine/test_rule_parser.py` kiểm tra parser và ngữ nghĩa từng option.

## Rule

- Mỗi file `.rules` là một category, cú pháp Snort 3. Rule built-in chia theo nhóm SID: `rules/web-attack.rules`, `scan.rules`, `dos.rules`, `auth.rules`, `malware-c2.rules`, `recon.rules`; `rules/custom.rules` dành cho rule tự viết trên web (SID ≥ 2000000). Trước khi thêm hoặc sửa rule, đọc `.claude/rules/snort-rules.md`: tài liệu này có quy trình, các option được hỗ trợ, dải SID và giới hạn của engine.
- `rules/vendor/*.rules` (bộ community của Snort) là category `vendor/<tên>`, mặc định tắt.
- Bật/tắt category và override theo SID lưu ở `rules/state.yaml` (gitignore; thiếu file = mặc định: bật mọi file ở gốc `rules/`, tắt vendor). Dòng `# alert ...` là rule mặc định tắt. `RuleManager` parse mọi file vào `catalog` nhưng chỉ đưa rule đang bật vào `rules`/`rules_by_sid`.
- Engine tự nạp lại rule khi file `.rules` hoặc `state.yaml` đổi (`RuleReloader` trong `nids/engine/main.py`, kiểm tra mỗi 2 giây trong worker thread), không cần khởi động lại.

## Quy ước repo

- KHÔNG chạy `git commit`/`git push` khi chưa được người dùng cho phép rõ ràng; không bao giờ merge thẳng vào `main`. Làm việc trên feature branch và merge qua PR.
- Mọi tài liệu phải viết bằng tiếng Việt có dấu: README, tài liệu thiết kế, spec, plan, mô tả PR và chính file `CLAUDE.md` này. Giữ nguyên dạng tiếng Anh cho tên trong code, lệnh, đường dẫn file, key cấu hình và các thuật ngữ kỹ thuật chuẩn (ví dụ Aho-Corasick, pub/sub, SID).
- Thông điệp commit (dòng tiêu đề và nội dung) viết bằng tiếng Anh ngắn gọn, theo kiểu Conventional Commits (`feat:`, `fix:`, `docs:`, `refactor:`, `chore:`...). Quy ước này chỉ áp dụng cho commit message, không áp dụng cho mô tả PR (vẫn viết tiếng Việt có dấu theo dòng trên).
- Honeypot được gộp từ dự án HONEYPY cũ (repo `74Teams/my_honeypot` trên GitHub, còn giữ lịch sử). Chưa làm: session theo kết nối, HASSH, route catch-all ghi mọi request HTTP, giới hạn tài nguyên (cap kết nối, timeout idle), shell giả sâu hơn, chuyển hướng traffic đáng ngờ sang honeypot.
- Một số tính năng đã lên kế hoạch (Redis pub/sub, WebSocket alert, AI engine theo flow) chưa được triển khai, và `nids/ai.py` (`AITrafficWorker`) mới chỉ là stub.
