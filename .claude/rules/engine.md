---
paths:
  - "nids/engine/**"
  - "nids/ai.py"
  - "tests/engine/**"
---

# Detection engine (`nids/engine/`)

## Pipeline

`nids/engine/main.py` (chạy bằng `python -m nids.engine`): `PacketCapture` (Scapy, live hoặc pcap offline) → `PacketDecoder.decode` (L2–L4 + HTTP L7 qua `http_parser`) → `queue.Queue` có giới hạn → một worker thread duy nhất gọi `DetectionEngine.evaluate_packet` rồi `AITrafficWorker.analyze_packet`. Alert đi qua callback `handle_alert` → `AlertWriter` (`nids/engine/alert_writer.py`): thread `alert-writer` gom tối đa 200 cảnh báo hoặc 1 giây rồi gọi `EventRepository.save_alerts` (một `commit` mỗi lô, `publish_alert` sau `commit`). Lỗi CSDL chỉ log và bỏ lô. Khi `main()` chưa chạy (test gọi `handle_alert` trực tiếp) thì vẫn ghi đồng bộ bằng `save_alert`.

Hàng đợi gói (`enqueue_packet`): live thì đầy là bỏ gói và đếm (`DropCounter`); offline thì chờ chỗ trống (`put` có timeout 0,5 giây để Ctrl+C trên Windows vẫn ngắt được), không bỏ gói. Worker chết thì việc đọc pcap dừng (`stop_filter`), `wait_until_processed` thay cho `packet_queue.join()` để không treo. Một gói lỗi trong worker chỉ được log (gộp đếm), worker chạy tiếp. Thứ tự kết thúc offline: worker join (ghi nốt flow) → `AlertWriter.close()` (ghi nốt cảnh báo) → in `format_summary` (có thời gian và gói/giây). Test chạy `main.main()` phải dùng SQLite dạng file, không dùng in-memory + `StaticPool`: flow và cảnh báo được ghi từ hai thread, một kết nối chung sẽ làm mất dữ liệu.

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
- `evaluate_packet` là phễu 4 tầng: demux theo protocol/port → prefilter Aho-Corasick → kiểm tra chi tiết (flags, flow, dsize, itype/icode, content theo buffer, pcre, `detection_filter`) → `ThresholdManager` chặn bớt để tránh bão alert. Cửa sổ chặn tính theo `packet.timestamp` (replay pcap lặp lại được). Khoá chặn: rule có `detection_filter` theo `track` (`by_dst` → `(sid, dst_ip)`, `by_src` → `(sid, src_ip)`), rule khác `(sid, src_ip, dst_ip, dst_port)`.

## Header rule và biến

- `nids/engine/rule_header.py` biên dịch IP và cổng của header lúc nạp rule thành `AddrSpec`/`PortSpec` (gắn vào `SnortRule.src_addrs/src_ports/dst_addrs/dst_ports`). Hiểu `any`, giá trị đơn, dải cổng `1:1024`, CIDR, danh sách lồng nhau `[a,b]`, phủ định `!x`, biến `$X`. Dạng không hiểu được ném `ValueError` nên rule bị bỏ kèm `WARNING rules` (không khớp tất cả); `!any` cũng là lỗi, kể cả khi sinh ra từ biến.
- `DetectionEngine._match_header` so khớp cổng trước IP; hướng `<>` khớp cả chiều ngược. Cổng `None` (ICMP) chỉ khớp `any`. IP của gói rỗng hoặc sai định dạng chỉ khớp `any`: `matches()` chạy trên worker thread duy nhất nên không bao giờ được ném lỗi.
- Đường nóng: `PortSpec` là bảng bit 65536 cổng tính sẵn (dùng chung giữa rule có cùng biểu thức), tra O(1); rule có cả bốn thành phần là `any` có `header_any = True` và bỏ qua bước này; IP của gói qua `lru_cache(4096)`.
- Biến lấy từ `get_rule_variables()` (`nids/config.py`): `DEFAULT_RULE_VARIABLES` chồng bởi `detection.variables`. `decoder.HTTP_PORTS` và rule `$HTTP_PORTS` dùng chung một nguồn, nên thêm cổng HTTP chỉ cần sửa cấu hình. `HTTP_PORTS` cấu hình sai thì `http_ports()` ghi `logger.error` và dùng mặc định, engine không dừng. Mặc định không có 443 (HTTP trên 443 là TLS nên không parse được).
- `RuleManager(rules_dir, variables=None)`: test truyền `variables` riêng để không phụ thuộc `settings.yaml`.

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

## Phát hiện bất thường theo ngưỡng

- `nids/engine/anomaly.py` (`AnomalyDetector`) bắt tấn công chưa có rule bằng thống kê theo cửa sổ thời gian của gói (`packet.timestamp`, replay pcap lặp lại được); module thuần, không biết CSDL hay `SETTINGS`. Worker gọi `main.py::observe_anomaly(anomaly, packet)` sau `flow_log.on_packet`; lỗi chỉ được log.
- Gói "mở kết nối" là TCP SYN không ACK, ICMP echo, và UDP không xuất phát từ cổng trong `common_ports` (để trả lời của DNS server không bị coi là quét).
- Port scan / host sweep: một nguồn mở kết nối tới `scan.ports` cặp (IP, cổng) hoặc `scan.hosts` máy trong `scan.window` giây (P2). SYN flood / packet flood: một đích nhận `flood.syn` SYN hoặc `flood.packets` gói trong `flood.window` giây (P1). Rare: TCP SYN tới cổng ngoài `common_ports`, UDP tới cổng < 1024 ngoài danh sách, ICMP type ngoài {0, 3, 8, 11} (P3); bỏ qua khi nguồn đang bị đánh dấu scan.
- Cảnh báo đi qua `handle_alert` với `source_type="ANOMALY"`, `sid=None`, bằng chứng ở `matched_content`; `format_alert` in nhãn `ANOMALY`. Chặn bớt bằng `ThresholdManager` riêng (`suppress_seconds`): scan và rare khoá theo nguồn, flood theo đích. Cửa sổ chặn tính theo giờ của gói, nên replay pcap ra cùng số cảnh báo như chạy thật.
- Bộ nhớ: tối đa `max_tracked` IP mỗi bảng (đầy thì bỏ IP lâu nhất không có gói), mỗi nguồn nhớ tối đa 10000 gói trong cửa sổ scan, mục hết cửa sổ được dọn mỗi giây theo giờ gói.
- Báo cả khi rule cũng bắt cùng traffic (ví dụ 1000107 và ANOMALY Port scan). `alert_count` của flow chỉ đếm rule.

## AI worker

`nids/ai.py` (`AITrafficWorker`) mới là stub. Nó được khởi tạo với cùng callback `handle_alert` như rule engine, nên khi làm phần AI chỉ sửa bên trong `nids/ai.py`. Thiết kế nằm ở `docs/ai/`.

## Test

Test khởi tạo `DetectionEngine` trực tiếp (thường với `enable_threshold=False`) và tự dựng các `DecodedPacket`. `tests/engine/test_rule_parser.py` kiểm tra parser và ngữ nghĩa từng option.
