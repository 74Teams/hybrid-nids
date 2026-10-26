# CLAUDE.md

File này hướng dẫn Claude Code (claude.ai/code) khi làm việc với code trong repository này.

## Dự án

Hybrid NIDS + honeypot (đồ án PBL4): hệ thống phát hiện xâm nhập mạng kết hợp static rule tương thích Snort, một AI worker phát hiện bất thường theo flow và honeypot SSH/HTTP làm nguồn sự kiện thứ hai. Python 3.10+, Scapy, pyahocorasick, SQLAlchemy 2.0, FastAPI, paramiko, Flask. README, tài liệu, comment, docstring và nội dung log đều viết bằng tiếng Việt có dấu; tên trong code và thuật ngữ kỹ thuật giữ tiếng Anh.

## Lệnh

```bash
pip install -r requirements.txt

python create_demo_pcap.py        # tạo lại pcap_samples/demo_attacks.pcap
python main.py                    # chạy engine capture + detection (offline hoặc live, theo settings.yaml)
python -m honeypot ssh            # honeypot SSH (cổng 2222); `python -m honeypot http` cho honeypot HTTP (cổng 8080)
uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload   # API tra cứu alert (Swagger tại /docs)

pytest                                                      # chạy toàn bộ test
pytest tests/test_diverse_rules_engine.py::test_name        # chạy một test
```

Chưa cấu hình linter. Docker: `docker compose up --build` khởi động MySQL, một nginx "victim", NIDS engine và một container attacker trên mạng bridge cô lập (172.28.0.0/16).

## Kiến trúc

Các **process riêng biệt** (engine, API, mỗi honeypot một process) dùng chung một database:

- `main.py` — process engine: `PacketCapture` (Scapy, live hoặc pcap offline) → `PacketDecoder.decode` (L2–L4 + HTTP L7 qua `http_parser`) → `queue.Queue` có giới hạn → một worker thread duy nhất gọi `DetectionEngine.evaluate_packet` và `AITrafficWorker.analyze_packet`. Alert đi qua callback `handle_alert` → `EventRepository.save_alert`.
- `api/main.py` — process FastAPI. Khi khởi động, nó chỉ tạo bảng. API gồm `/api/alerts` (danh sách), `/api/alerts/stats`, `DELETE /api/alerts/`, `/health`, và dashboard `api/static/dashboard.html` phục vụ tại `/`. DB chỉ lưu sự kiện cảnh báo (bảng `events`, `event_payloads`), không lưu rule.
- `honeypot/` — honeypot SSH (`ssh_honeypot.py`, paramiko, nhận mọi mật khẩu, shell giả) và HTTP (`web_honeypot.py`, Flask, trang login WordPress giả), chạy bằng `python -m honeypot`. Cấu hình qua biến môi trường `HONEYPY_*` (`honeypot/settings.py`); host key SSH tự sinh vào `data/` (gitignore). Sensor chỉ thu thập: `honeypot/store.py::log_event` ghi vào bảng `events` chung với `source_type="HONEYPOT"` (`attack_type` = event type như `ssh.auth.attempt`, dữ liệu thô vào `event_payloads`); lỗi ghi CSDL không được làm sập sensor. Không bao giờ thực thi input của attacker.
- `attacker/attack_demo.py` — kịch bản tấn công demo, chạy trong container attacker. Mỗi đòn khai báo SID kỳ vọng; `tests/test_attack_demo.py` kiểm tra đòn nào cũng trúng đúng rule và rule nào cũng có đòn trình diễn (thêm rule mới thì phải thêm đòn). Nhóm `honeypot` dùng `CommandAttack` (hydra) và `HttpAttack` vào 2222/8080, không có SID kỳ vọng. Kịch bản thuyết trình ở `docs/demo/kich-ban-demo.md`.

### Logging

- Cấu hình ở `config/logger.py` (`setup_logging`, `ColorFormatter`), gọi một lần ở `main.py`, `api/main.py` và `create_demo_pcap.py`. Mức độ lấy từ `system.log_level` trong `settings.yaml` (mặc định `INFO`, `DEBUG` để xem chi tiết). Màu tự tắt khi đầu ra không phải terminal hoặc có biến môi trường `NO_COLOR`.
- Mỗi module dùng `logging.getLogger("nids.<khu vực>")`, không dùng `print`. Khu vực: `engine` (`main.py`, `ids_realtime.py`), `alert` (dòng cảnh báo trong `main.py`), `rules` (`manager_rules.py`), `db`, `capture`, `api`, `pcap`, `attack` (`attacker/attack_demo.py`).
- Cảnh báo mang `extra={"priority": n}` để formatter tô màu theo priority (P1 đỏ, P2 vàng, P3 xanh dương).

### Detection engine (`services/detection/`)

- `RuleManager` chỉ parse rule cú pháp Snort từ file (`load_all_rules`); không có đường nạp rule từ DB.
- Parser hiểu cú pháp Snort 3: sticky buffer (`http_uri; content:...`), modifier sau dấu phẩy (`content:"x",nocase,depth 4`), tách option theo `;` nằm ngoài dấu ngoặc kép. Mỗi `ContentMatch`/`PcreMatch` mang buffer riêng của nó. Cú pháp Snort 2 (`nocase;` đứng riêng, `severity:`, `http_method:"POST"`) không được hỗ trợ.
- `DetectionEngine.rebuild_index` dựng danh sách rule theo protocol, cùng các matcher Aho-Corasick riêng (`MultiPatternMatcher`) cho URI, header, body và raw payload. Mỗi rule được index bằng fast pattern của nó (content có `fast_pattern`, nếu không thì content dài nhất). Rule không có fast pattern vào `no_content_rules` và luôn được đánh giá. `evaluate_packet` là phễu 4 tầng: demux theo protocol/port → prefilter Aho-Corasick → kiểm tra chi tiết (flags, flow, dsize, itype/icode, content theo buffer, pcre, `detection_filter`) → `ThresholdManager` chặn bớt để tránh bão alert.
- Biến trong rule được hard-code, không phải biến Snort tổng quát: `$HTTP_PORTS` được xử lý riêng trong `_match_port`, còn `packet_decoder.HTTP_PORTS` (80, 8080, 8000, 3000, 5000, 443) quyết định payload nào được parse thành HTTP. Thêm biến mới hoặc HTTP port mới thì phải sửa cả hai chỗ.
- `DecodedPacket` / `ParsedHTTPRequest` (`services/ingestion/__init__.py`) và `SnortRule` (`services/detection/__init__.py`) là các dataclass truyền giữa các tầng.

### Làm giàu cảnh báo bằng honeypot

IP đã chạm honeypot (trong 1 giờ gần nhất) chắc chắn là attacker. `main.py::handle_alert` gọi `enrich_alert`: cảnh báo rule engine từ IP đó được nâng một bậc priority (tối đa P1) và gắn `[honeypot-confirmed]`. Danh sách IP đọc từ CSDL qua `HoneypotIPCache` (TTL 5 giây vì honeypot ghi từ process khác). API: `GET /api/alerts/?source_type=HONEYPOT|RULE_ENGINE` và `GET /api/alerts/attackers`.

### Cấu hình và database

- `config/settings.yaml` được load một lần lúc import vào `config.config.SETTINGS`. `get_db_url()` dựng URL từ mục `database`, và các biến môi trường `NIDS_DB_HOST/PORT/NAME/USER/PASSWORD` sẽ ghi đè (docker-compose dựa vào điều này). `type: sqlite` dùng `db_url`.
- `init_db()` thử lại tối đa 15 lần, mỗi lần cách 2s, vì MySQL khởi động chậm trong Docker.
- `settings.yaml` đã commit mặc định dùng `capture_mode: "live"`, interface `eth0` và IP MySQL của Docker; khi chạy local thì chuyển sang `offline` và/hoặc `sqlite`.
- Trong Docker, `honeypot_ssh` và `honeypot_http` cũng dùng `network_mode: service:victim_app` (cổng 2222 và 8080; 8080 nằm trong `HTTP_PORTS` nên rule web áp dụng luôn), nên cùng một đòn vừa sinh cảnh báo rule vừa sinh sự kiện honeypot. `nids_engine` dùng `network_mode: service:victim_app` để sniff traffic của victim, và mount repo vào `/app`. `nids_api` (API + dashboard) cố ý chạy ở network riêng để request poll của dashboard không bị engine sniff nhầm. `network.bpf_filter` loại port 3306: engine thấy cả kết nối ghi alert vào MySQL, nếu không loại thì câu INSERT chứa chuỗi tấn công sẽ sinh alert mới (vòng lặp).

### Test

Test khởi tạo `DetectionEngine` trực tiếp (thường với `enable_threshold=False`) và hoặc replay `pcap_samples/demo_attacks.pcap`, hoặc tự dựng các `DecodedPacket`. Test pcap kiểm tra các SID cụ thể và số packet (39), nên tạo lại pcap hoặc sửa rule có thể làm test fail. `tests/test_rule_parser.py` kiểm tra parser và ngữ nghĩa từng option.

## Rule

- Toàn bộ rule nằm trong một file duy nhất `rules/local.rules`, cú pháp Snort 3. Rule chỉ được đọc từ file này và chỉ có hiệu lực sau khi khởi động lại engine. Trước khi thêm hoặc sửa rule, đọc `.claude/rules/snort-rules.md`: tài liệu này có quy trình, các option được hỗ trợ, dải SID và giới hạn của engine.
- `vendor/community.rules` là bộ rule community của Snort, mặc định không được load.

## Quy ước repo

- KHÔNG chạy `git commit`/`git push` khi chưa được người dùng cho phép rõ ràng; không bao giờ merge thẳng vào `main`. Làm việc trên feature branch và merge qua PR.
- Mọi tài liệu phải viết bằng tiếng Việt có dấu: README, tài liệu thiết kế, spec, plan, mô tả PR và chính file `CLAUDE.md` này. Giữ nguyên dạng tiếng Anh cho tên trong code, lệnh, đường dẫn file, key cấu hình và các thuật ngữ kỹ thuật chuẩn (ví dụ Aho-Corasick, pub/sub, SID).
- Thông điệp commit (dòng tiêu đề và nội dung) viết bằng tiếng Anh ngắn gọn, theo kiểu Conventional Commits (`feat:`, `fix:`, `docs:`, `refactor:`, `chore:`...). Quy ước này chỉ áp dụng cho commit message, không áp dụng cho mô tả PR (vẫn viết tiếng Việt có dấu theo dòng trên).
- Honeypot được gộp từ dự án HONEYPY cũ (repo `74Teams/my_honeypot` trên GitHub, còn giữ lịch sử). Chưa làm: session theo kết nối, HASSH, route catch-all ghi mọi request HTTP, giới hạn tài nguyên (cap kết nối, timeout idle), shell giả sâu hơn, chuyển hướng traffic đáng ngờ sang honeypot.
- Một số tính năng đã lên kế hoạch (Redis pub/sub, WebSocket alert, AI engine theo flow) chưa được triển khai, và `ai_worker.py` mới chỉ là stub.
