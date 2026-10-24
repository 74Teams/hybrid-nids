# CLAUDE.md

File này hướng dẫn Claude Code (claude.ai/code) khi làm việc với code trong repository này.

## Dự án

Hybrid NIDS (đồ án PBL4): hệ thống phát hiện xâm nhập mạng kết hợp static rule tương thích Snort với một AI worker phát hiện bất thường theo flow. Python 3.10+, Scapy, pyahocorasick, SQLAlchemy 2.0, FastAPI. README và tài liệu phần lớn viết bằng tiếng Việt; comment trong code và log trộn tiếng Việt (thường không dấu) và tiếng Anh.

## Lệnh

```bash
pip install -r requirements.txt

python create_demo_pcap.py        # tạo lại pcap_samples/demo_attacks.pcap
python main.py                    # chạy engine capture + detection (offline hoặc live, theo settings.yaml)
uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload   # API quản lý (Swagger tại /docs)

pytest                                                      # chạy toàn bộ test
pytest tests/test_diverse_rules_engine.py::test_name        # chạy một test
```

Chưa cấu hình linter. Docker: `docker compose up --build` khởi động MySQL, một nginx "victim", NIDS engine và một container attacker trên mạng bridge cô lập (172.28.0.0/16).

## Kiến trúc

Hai **process riêng biệt** dùng chung một database:

- `main.py` — process engine: `PacketCapture` (Scapy, live hoặc pcap offline) → `PacketDecoder.decode` (L2–L4 + HTTP L7 qua `http_parser`) → `queue.Queue` có giới hạn → một worker thread duy nhất gọi `DetectionEngine.evaluate_packet` và `AITrafficWorker.analyze_packet`. Alert đi qua callback `handle_alert` → `EventRepository.save_alert`.
- `api/main.py` — process FastAPI. Khi khởi động, nó tạo bảng và import `rules/*.rules` vào DB (rule đã có chỉ bị ghi đè khi `rev` trong file lớn hơn).

**Lưu ý về hot-reload:** các route CRUD rule gọi `_try_hot_reload`, hàm này dùng `api.main.get_detection_engine()`. Singleton đó chỉ được gán qua `set_detection_engine()`, mà hiện tại `main.py` không gọi, nên khi hai process chạy riêng thì API báo engine là `not_attached` và thay đổi rule chỉ vào DB chứ không vào RAM của engine đang chạy. Cần nhớ điều này khi sửa phần hot-reload.

### Detection engine (`services/detection/`)

- `RuleManager` parse rule cú pháp Snort từ file (`load_all_rules`) hoặc từ DB (`load_from_db` / `reload_rules_from_db`). Sau lần import đầu, DB là nguồn dữ liệu chính; `RuleModel.raw_rule` lưu chuỗi rule Snort.
- Parser hiểu cú pháp Snort 3: sticky buffer (`http_uri; content:...`), modifier sau dấu phẩy (`content:"x",nocase,depth 4`), tách option theo `;` nằm ngoài dấu ngoặc kép. Mỗi `ContentMatch`/`PcreMatch` mang buffer riêng của nó. Parser vẫn đọc được cú pháp cũ trong DB (`nocase;` đứng riêng, `severity:`, `http_method:"POST"`).
- `DetectionEngine.rebuild_index` dựng danh sách rule theo protocol, cùng các matcher Aho-Corasick riêng (`MultiPatternMatcher`) cho URI, header, body và raw payload. Mỗi rule được index bằng fast pattern của nó (content có `fast_pattern`, nếu không thì content dài nhất). Rule không có fast pattern vào `no_content_rules` và luôn được đánh giá. `evaluate_packet` là phễu 4 tầng: demux theo protocol/port → prefilter Aho-Corasick → kiểm tra chi tiết (flags, flow, dsize, itype/icode, content theo buffer, pcre, `detection_filter`) → `ThresholdManager` chặn bớt để tránh bão alert.
- Biến trong rule được hard-code, không phải biến Snort tổng quát: `$HTTP_PORTS` được xử lý riêng trong `_match_port`, còn `packet_decoder.HTTP_PORTS` (80, 8080, 8000, 3000, 5000, 443) quyết định payload nào được parse thành HTTP. Thêm biến mới hoặc HTTP port mới thì phải sửa cả hai chỗ.
- `DecodedPacket` / `ParsedHTTPRequest` (`services/ingestion/__init__.py`) và `SnortRule` (`services/detection/__init__.py`) là các dataclass truyền giữa các tầng.

### Cấu hình và database

- `config/settings.yaml` được load một lần lúc import vào `config.config.SETTINGS`. `get_db_url()` dựng URL từ mục `database`, và các biến môi trường `NIDS_DB_HOST/PORT/NAME/USER/PASSWORD` sẽ ghi đè (docker-compose dựa vào điều này). `type: sqlite` dùng `db_url`.
- `init_db()` thử lại tối đa 15 lần, mỗi lần cách 2s, vì MySQL khởi động chậm trong Docker.
- `settings.yaml` đã commit mặc định dùng `capture_mode: "live"`, interface `eth0` và IP MySQL của Docker; khi chạy local thì chuyển sang `offline` và/hoặc `sqlite`.
- Trong Docker, `nids_engine` dùng `network_mode: service:victim_app` để sniff traffic của victim, và mount repo vào `/app`.

### Test

Test khởi tạo `DetectionEngine` trực tiếp (thường với `enable_threshold=False`) và hoặc replay `pcap_samples/demo_attacks.pcap`, hoặc tự dựng các `DecodedPacket`. Test pcap kiểm tra các SID cụ thể và số packet (39), nên tạo lại pcap hoặc sửa rule có thể làm test fail. `tests/test_rule_parser.py` kiểm tra parser và ngữ nghĩa từng option.

## Rule

- Toàn bộ rule nằm trong một file duy nhất `rules/local.rules`, cú pháp Snort 3. Trước khi thêm hoặc sửa rule, đọc `.claude/rules/snort-rules.md`: tài liệu này có quy trình, các option được hỗ trợ, dải SID và giới hạn của engine.
- `vendor/community.rules` là bộ rule community của Snort, mặc định không được load.

## Quy ước repo

- KHÔNG chạy `git commit`/`git push` khi chưa được người dùng cho phép rõ ràng; không bao giờ merge thẳng vào `main`. Làm việc trên feature branch và merge qua PR.
- Mọi tài liệu phải viết bằng tiếng Việt có dấu: README, tài liệu thiết kế, spec, plan, mô tả PR và chính file `CLAUDE.md` này. Giữ nguyên dạng tiếng Anh cho tên trong code, lệnh, đường dẫn file, key cấu hình và các thuật ngữ kỹ thuật chuẩn (ví dụ Aho-Corasick, pub/sub, SID).
- Một số tính năng đã lên kế hoạch (Redis pub/sub, WebSocket alert, AI engine theo flow) chưa được triển khai, và `ai_worker.py` mới chỉ là stub.
