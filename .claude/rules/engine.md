---
paths:
  - "nids/engine/**"
  - "nids/ai.py"
  - "tests/engine/**"
---

# Detection engine (`nids/engine/`)

## Pipeline

`nids/engine/main.py` (chạy bằng `python -m nids.engine`): `PacketCapture` (Scapy, live hoặc pcap offline) → `PacketDecoder.decode` (L2–L4 + HTTP L7 qua `http_parser`) → `queue.Queue` có giới hạn → một worker thread duy nhất gọi `DetectionEngine.evaluate_packet` rồi `AITrafficWorker.analyze_packet`. Alert đi qua callback `handle_alert` → `EventRepository.save_alert`.

## Rule

- `RuleManager` chỉ parse rule cú pháp Snort từ file (`load_all_rules`); không có đường nạp rule từ DB.
- `RuleManager` parse mọi file vào `catalog` nhưng chỉ đưa rule đang bật vào `rules`/`rules_by_sid`.
- Engine tự nạp lại rule khi file `.rules` hoặc `state.yaml` đổi (`RuleReloader` trong `main.py`, kiểm tra mỗi 2 giây trong worker thread), không cần khởi động lại.
- Parser hiểu cú pháp Snort 3: sticky buffer (`http_uri; content:...`), modifier sau dấu phẩy (`content:"x",nocase,depth 4`), tách option theo `;` nằm ngoài dấu ngoặc kép. Mỗi `ContentMatch`/`PcreMatch` mang buffer riêng của nó.
- Cú pháp Snort 2 (`nocase;` đứng riêng, `severity:`, `http_method:"POST"`) không được hỗ trợ.
- Viết rule: xem `snort-rules.md`.

## Phễu phát hiện

- `DetectionEngine.rebuild_index` dựng danh sách rule theo protocol, cùng các matcher Aho-Corasick riêng (`MultiPatternMatcher`) cho URI, header, body và raw payload.
- Mỗi rule được index bằng fast pattern của nó (content có `fast_pattern`, nếu không thì content dài nhất). Rule không có fast pattern vào `no_content_rules` và luôn được đánh giá.
- `evaluate_packet` là phễu 4 tầng: demux theo protocol/port → prefilter Aho-Corasick → kiểm tra chi tiết (flags, flow, dsize, itype/icode, content theo buffer, pcre, `detection_filter`) → `ThresholdManager` chặn bớt để tránh bão alert.

## Biến hard-code

`$HTTP_PORTS` được xử lý riêng trong `_match_port`, còn `decoder.HTTP_PORTS` (80, 8080, 8000, 3000, 5000, 443) quyết định payload nào được parse thành HTTP. Thêm biến mới hoặc HTTP port mới thì phải sửa cả hai chỗ.

## Kiểu dữ liệu

`DecodedPacket` / `ParsedHTTPRequest` (`packet.py`) và `SnortRule` (`rule.py`) là các dataclass truyền giữa các tầng. Các module còn lại: `capture.py`, `decoder.py` + `http_parser.py`, `rule_manager.py`, `matcher.py` (Aho-Corasick), `threshold.py`, `detector.py` (`DetectionEngine`).

## Làm giàu cảnh báo bằng honeypot

IP đã chạm honeypot trong 1 giờ gần nhất chắc chắn là attacker. `main.py::handle_alert` gọi `enrich_alert`: cảnh báo rule engine từ IP đó được nâng một bậc priority (tối đa P1) và gắn `[honeypot-confirmed]`. Danh sách IP đọc từ CSDL qua `HoneypotIPCache` (TTL 5 giây vì honeypot ghi từ process khác).

## Tái hợp luồng TCP

- `nids/engine/stream.py` (`StreamReassembler`, `StreamView`) ghép payload chiều client → server theo `tcp_seq`, dùng lại `flow_key`. Module thuần, không biết CSDL hay `SETTINGS`; gói không có `tcp_seq` (gói tự dựng trong test) được bỏ qua.
- So khớp từng gói giữ nguyên. `main.py::evaluate_with_stream` gọi `evaluate_packet`, rồi `reassembler.feed(packet, matched)`; nếu buffer có từ hai đoạn thì nhận gói ảo (`reassembled=True`) và gọi `DetectionEngine.evaluate_stream`.
- Client là bên gửi SYN. Không thấy SYN thì bên có cổng đích nhỏ hơn được coi là client; khi đó không xử lý được đảo thứ tự ở đoạn đầu.
- Đến sai thứ tự thì giữ ở `pending`; quá `max_pending_segments` thì coi như mất gói và ghép lại từ đoạn mới nhất. Chồng lấn: dữ liệu đến trước được giữ.
- Không quét lại buffer ở mọi segment vì chi phí tăng theo bậc hai. Buffer tới `SCAN_EVERY_SEGMENT_BYTES` (4 KB) thì quét mỗi segment; lớn hơn thì chỉ quét khi gấp đôi lần trước, khi đủ một HTTP request, khi client gửi FIN/RST, hoặc ngay trước khi vượt `depth`. Dữ liệu chưa quét sẽ không được quét nếu stream hết idle timeout, bị đẩy khỏi bảng, hoặc do server đóng trước.
- Bộ nhớ: mỗi stream tối đa `depth` byte (vượt thì dừng ghép stream đó), toàn bảng tối đa `max_total_bytes` và `max_streams` (vượt thì bỏ stream lâu nhất không có gói).
- Chống báo trùng: mỗi stream nhớ tập SID đã bắn, tập được làm mới khi cắt xong một HTTP request (đủ header và `Content-Length`), nên request tấn công sau trên cùng kết nối vẫn được báo. `chunked` và pipelining chưa được tách ranh giới.
- Cấu hình ở mục `stream` trong `settings.yaml`; `enabled: false` tắt hẳn bước ghép.

## Flow log

- `nids/engine/flow.py` (`Flow`, `FlowTracker`, `flow_key`) gom gói theo 5-tuple chuẩn hoá hai chiều; module thuần, không biết CSDL, để AI worker (#22) dùng lại. Bên gửi gói đầu là nguồn (SYN-ACK đầu tiên thì đảo chiều). Mốc thời gian lấy từ `packet.timestamp`, nên replay pcap cho kết quả lặp lại được.
- Flow TCP đóng bằng FIN hai chiều hoặc RST thì chờ `closing_timeout` rồi mới xuất (để ACK cuối không thành flow riêng). Ngoài ra xuất khi idle, active timeout, bảng đầy (`max_flows`, đẩy flow lâu không có gói nhất) hoặc khi engine dừng.
- `main.py::FlowLog` bọc `FlowTracker`: gom flow đã kết thúc rồi ghi theo lô qua `EventRepository.save_flows`. Worker thread gọi `flow_log.on_packet(packet, len(matched))` **sau** `evaluate_packet`; `len(matched)` là số rule khớp (kể cả cảnh báo bị `ThresholdManager` chặn), nên `alert_count` có thể lớn hơn số dòng trong `events`.
- Chế độ live: khi queue trống worker gọi `flow_log.tick(time.time())` để flow hết hạn. Khi dừng (hết pcap hoặc Ctrl+C), `main()` đặt `stop_event` và worker tự gọi `flow_log.close()` để ghi nốt flow còn mở; chỉ worker thread được đụng vào bảng flow.
- Lỗi CSDL khi ghi flow chỉ được log, batch đó bị bỏ, engine vẫn chạy. Traffic cổng 3306 không có trong flow vì BPF filter loại nó.

## AI worker

`nids/ai.py` (`AITrafficWorker`) mới là stub. Nó được khởi tạo với cùng callback `handle_alert` như rule engine, nên khi làm phần AI chỉ sửa bên trong `nids/ai.py`. Thiết kế nằm ở `docs/ai/`.

## Test

Test khởi tạo `DetectionEngine` trực tiếp (thường với `enable_threshold=False`) và tự dựng các `DecodedPacket`. `tests/engine/test_rule_parser.py` kiểm tra parser và ngữ nghĩa từng option.
