# Đánh giá Detection Engine

## 1. Phạm vi tài liệu

Tài liệu này đánh giá riêng pipeline phát hiện của Hybrid NIDS hiện tại, tập trung vào:

- Giải mã packet và nhận diện HTTP.
- So khớp rule trong `DetectionEngine`.
- Quản lý TCP flow và payload.
- Độ chính xác, hiệu năng và khả năng chống quá tải.
- Cơ chế sinh và lưu cảnh báo.
- Hot-reload rule ảnh hưởng đến engine.

Phạm vi được đối chiếu với mã nguồn hiện tại:

- `services/ingestion/packet_capture.py`
- `services/ingestion/packet_decoder.py`
- `services/ingestion/http_parser.py`
- `services/detection/ids_realtime.py`
- `services/detection/manager_rules.py`
- `services/detection/pattern_matcher.py`
- `main.py`

## 2. Tóm tắt điều hành

Detection Engine hiện phù hợp cho demo offline trên PCAP nhỏ và các rule đơn giản. Pipeline hiện tại có cấu trúc dễ hiểu, nhưng chưa đủ tin cậy cho traffic thực tế vì xử lý từng packet độc lập, chưa có TCP stream reassembly, chưa kiểm tra đầy đủ IP/direction, và việc ghi alert đồng bộ có thể làm nghẽn worker.

Các rủi ro ưu tiên cao:

| ID | Vấn đề | Tác động chính | Ưu tiên |
|---|---|---|---|
| DE-01 | Không reassemble TCP stream | Bỏ sót payload bị chia qua nhiều packet | P0 |
| DE-02 | HTTP parser chỉ xử lý từng packet | False negative/false positive ở HTTP thực tế | P0 |
| DE-03 | Không match `src_ip`, `dst_ip`, `direction` | Rule có thể áp dụng sai packet | P0 |
| DE-04 | TCP flags match quá lỏng | Phân loại scan không chính xác | P1 |
| DE-05 | Aho-Corasick chưa nằm trong đường quyết định | Hiệu năng thực tế không như tài liệu | P1 |
| DE-06 | Alert persistence đồng bộ | Queue tăng, packet bị drop khi DB chậm | P0 |
| DE-07 | Không có deduplication/suppression | Alert storm và database phình nhanh | P1 |
| DE-08 | Regex không có giới hạn tài nguyên | Có thể làm treo analysis worker | P1 |
| DE-09 | Rule parser chỉ tương thích một phần Snort | Rule hợp lệ có thể bị parse sai/bỏ qua | P1 |
| DE-10 | Không có flow memory/shutdown/metrics đầy đủ | Khó vận hành và khó chứng minh độ tin cậy | P1 |

## 3. Luồng xử lý hiện tại

```text
Scapy sniff()
    |
    v
PacketCapture.raw_callback
    |
    v
PacketDecoder.decode()
    |-- L3/L4 fields
    |-- raw payload
    |-- HTTPParser.parse_payload() nếu port thuộc HTTP_PORTS
    v
queue.Queue(maxsize=10000)
    |
    v
worker_loop()
    |-- DetectionEngine.evaluate_packet()
    |      |-- duyệt toàn bộ rule
    |      |-- match protocol/port/flags/content/PCRE
    |      |-- gọi alert_callback ngay khi match
    |
    |-- AITrafficWorker.analyze_packet() hiện chưa xử lý
    v
EventRepository.save_alert()
```

### 3.1. Điểm đúng trong thiết kế hiện tại

- Capture được tách khỏi decode và detection.
- Queue có giới hạn để tránh tăng RAM vô hạn.
- `DecodedPacket` là contract trung gian rõ ràng giữa ingestion và detection.
- Rule được biểu diễn bằng `SnortRule`, thuận tiện cho việc mở rộng.
- Có hỗ trợ protocol, port, TCP flags, HTTP modifier và PCRE.
- Có sẵn `MultiPatternMatcher` để tối ưu tìm nhiều content pattern.

### 3.2. Khoảng cách giữa thiết kế và runtime

- Queue đầy sẽ drop packet, nên chưa thể gọi là “zero packet loss”.
- `MultiPatternMatcher` được build nhưng `evaluate_packet()` vẫn kiểm tra content theo từng rule.
- HTTP được parse theo từng packet, không theo TCP stream.
- `EventRepository.save_alert()` commit đồng bộ ngay trong analysis worker.
- Rule có `src_ip`, `dst_ip`, `direction`, nhưng engine hiện chưa dùng đầy đủ các trường này.

## 4. Đánh giá chi tiết các điểm yếu

## DE-01 — Không có TCP stream reassembly

### Hiện trạng

`PacketDecoder.decode()` lấy `Raw.load` của một packet rồi chuyển trực tiếp cho `HTTPParser`. `DetectionEngine` cũng chỉ nhận một `DecodedPacket` tại một thời điểm.

Một HTTP request có thể được chia như sau:

```text
TCP segment 1: GET /search?q=UN
TCP segment 2: ION+SELECT HTTP/1.1\r\n...
```

Rule `content:"union"; content:"select";` sẽ không match nếu chuỗi bị cắt giữa hai segment.

### Tác động

- False negative đối với payload bị phân mảnh.
- Không xử lý đúng packet out-of-order hoặc retransmission.
- Không xác định được boundary của request/response.
- Không thể áp dụng chính xác các rule phụ thuộc flow.

### Giải pháp đề xuất

Thêm một `FlowTracker` trước HTTP parser và detection:

```text
DecodedPacket
    |
    v
FlowTracker
    |-- xác định flow key
    |-- sắp xếp theo TCP sequence
    |-- loại retransmission
    |-- ghép payload
    |-- timeout/FIN/RST cleanup
    v
ReassembledStream
    |
    v
HTTP parser + rule engine
```

Flow key nên giữ hướng:

```python
FlowKey = (
    src_ip,
    src_port,
    dst_ip,
    dst_port,
    protocol,
)
```

Mỗi flow cần lưu tối thiểu:

```python
class FlowState:
    key: FlowKey
    next_sequence: int | None
    pending_segments: dict[int, bytes]
    client_buffer: bytearray
    server_buffer: bytearray
    last_seen: float
    bytes_from_client: int
    bytes_from_server: int
```

Quy tắc an toàn bắt buộc:

1. Giới hạn số flow đồng thời.
2. Giới hạn buffer mỗi flow, ví dụ 1 MiB.
3. Expire flow sau timeout idle, ví dụ 60 giây.
4. Xóa flow khi nhận FIN/RST hoặc khi vượt giới hạn.
5. Xử lý segment đến trễ trong một cửa sổ sequence giới hạn.
6. Không giữ payload vô hạn chỉ vì HTTP header chưa hoàn chỉnh.

### Tiêu chí nghiệm thu

- Payload bị chia tại mọi vị trí trong chuỗi tấn công vẫn được phát hiện.
- Packet out-of-order hợp lệ cho cùng flow cho kết quả giống packet đúng thứ tự.
- Retransmission không tạo duplicate alert.
- Flow timeout giải phóng bộ nhớ.
- Test được packet drop/segment quá lớn mà không làm process crash.

## DE-02 — HTTP parser chỉ xử lý từng packet

### Hiện trạng

`HTTPParser.parse_payload()` giả định payload đã là một HTTP request hoàn chỉnh. Parser chỉ được gọi khi source hoặc destination port nằm trong:

```python
{80, 8080, 8000, 3000, 5000, 443}
```

Việc dùng port 443 để parse plaintext cũng có thể tạo kết quả sai vì HTTPS thường chứa TLS ciphertext.

### Tác động

- Request nhiều segment không được parse.
- Dữ liệu không phải HTTP trên port quen thuộc có thể bị hiểu nhầm.
- Không xử lý chunked body.
- Không canonicalize URL trước khi match.
- Payload URL-encoded có thể bypass rule.
- Không có giới hạn rõ ràng cho URI, header và body.

### Giải pháp đề xuất

Tách parser thành hai tầng:

```text
Reassembled TCP bytes
    |
    v
HTTP framing parser
    |-- request line
    |-- headers
    |-- Content-Length
    |-- chunked encoding
    |-- request boundary
    v
CanonicalizedHTTPRequest
```

Canonicalization nên có thứ tự ổn định:

1. Decode bytes theo charset an toàn.
2. Tách request line và header.
3. Decode percent encoding ở URI/query.
4. Chuẩn hóa các dạng encoding hợp lệ theo chính sách.
5. Giới hạn số lần decode để tránh double-encoding abuse.
6. Giữ cả giá trị raw và normalized để điều tra.

Không nên coi mọi payload trên port 443 là HTTP. Cần:

- Chỉ parse plaintext HTTP khi request line hợp lệ.
- Gắn trạng thái `protocol_detected = HTTP` sau khi nhận diện thành công.
- Bỏ qua hoặc chuyển TLS traffic cho module TLS metadata riêng.

### Tiêu chí nghiệm thu

- Parse được GET/POST nhiều segment.
- Parse đúng `Content-Length` và chunked body.
- Rule match được `%55%4e%49%4f%4e` theo chính sách canonicalization.
- Không tạo HTTP alert cho TLS ciphertext hoặc dữ liệu TCP tùy ý.
- URI/body/header vượt giới hạn bị từ chối an toàn và có metric.

## DE-03 — Chưa match source IP, destination IP và direction

### Hiện trạng

`SnortRule` có các trường `src_ip`, `dst_ip`, `direction`, nhưng `DetectionEngine.evaluate_packet()` hiện chủ yếu kiểm tra protocol, port và flags. Điều kiện IP/direction chưa được áp dụng đầy đủ.

Một rule giới hạn cho:

```text
alert tcp 192.168.1.10 any -> 10.0.0.5 80 (...)
```

có thể match packet từ source khác nếu payload và port phù hợp.

### Tác động

- False positive.
- Vi phạm ý nghĩa rule.
- Không thể triển khai rule theo subnet hoặc vùng mạng.
- Rule hai chiều `<>` không hoạt động đúng.

### Giải pháp đề xuất

Tạo helper riêng, không nối logic vào `evaluate_packet()`:

```python
def match_address(rule_value: str, packet_ip: str) -> bool:
    # any, single IP, CIDR, list/range theo grammar được hỗ trợ
    ...

def match_direction(rule: SnortRule, packet: DecodedPacket) -> bool:
    forward = (
        match_address(rule.src_ip, packet.src_ip)
        and match_address(rule.dst_ip, packet.dst_ip)
        and match_port(packet.src_port, rule.src_port)
        and match_port(packet.dst_port, rule.dst_port)
    )
    if rule.direction == "->":
        return forward
    if rule.direction == "<>":
        return forward or reverse_match(...)
    return False
```

Nên dùng `ipaddress.ip_address()` và `ipaddress.ip_network()` thay vì tự parse chuỗi IP.

Grammar ban đầu nên hỗ trợ rõ ràng:

- `any`
- Một IPv4/IPv6
- CIDR
- Danh sách địa chỉ
- Port đơn
- Port list
- Port range
- `$HTTP_PORTS`

Các dạng chưa hỗ trợ phải bị reject khi import/create rule, không âm thầm match.

### Tiêu chí nghiệm thu

- Rule IP đơn chỉ match đúng IP.
- Rule CIDR match đúng subnet và không match subnet khác.
- Rule `->` không match chiều ngược.
- Rule `<>` match cả hai chiều.
- Rule grammar không hợp lệ trả lỗi rõ ràng khi tạo/import.

## DE-04 — TCP flags match quá lỏng

### Hiện trạng

`_match_flags()` dùng logic tương tự:

```python
return all(flag in raw_flags for flag in rule_flags)
```

Vì vậy `flags:F` có thể match `F`, `FA`, `FUP` hoặc `SF`. Logic này chỉ biểu diễn “có chứa flag”, không biểu diễn “chính xác tập flag”.

### Tác động

- Phân loại Xmas/FIN/SYN-FIN không chính xác.
- Tăng false positive trong network scan detection.
- Không tương thích rõ ràng với semantics flags của Snort.

### Giải pháp đề xuất

Trước hết cần định nghĩa semantics trong parser và tài liệu. Có thể hỗ trợ hai chế độ:

```text
flags:F       # required: phải có FIN
flags:=F      # exact: chỉ có FIN
flags:!A      # absent: không có ACK
```

Nếu chưa muốn mở rộng grammar, phải chọn một semantics duy nhất và viết test rõ ràng. Với rule scan hiện tại, nên dùng exact matching cho các rule:

- Null: `raw_flags == ""`
- FIN: `raw_flags == "F"`
- Xmas: tập flag chính xác là `{F, U, P}` nếu đó là mục tiêu rule
- SYN-FIN: có `{S, F}`, đồng thời quy định có cho phép flag khác hay không

Không nên so sánh chuỗi chưa chuẩn hóa. Hãy chuyển flags về bitset hoặc `frozenset[str]`.

### Tiêu chí nghiệm thu

- `F` không tự động match `FA` nếu rule exact.
- Null scan không match packet có ACK.
- Xmas và SYN-FIN có test riêng cho các tổ hợp flag gần giống.
- Kết quả được document trong rule contract.

## DE-05 — Aho-Corasick chưa được dùng trong đường quyết định

### Hiện trạng

`MultiPatternMatcher` có thể build automaton, nhưng `DetectionEngine` vẫn duyệt từng rule và gọi `_match_contents()` trên từng rule. Do đó hiệu năng thực tế chưa tương ứng với mô tả “multi-pattern O(N)”.

### Tác động

- Mỗi packet phải kiểm tra nhiều content lặp lại.
- CPU tăng theo số rule.
- Regex và các bước hậu kiểm chạy trên tập candidate lớn hơn cần thiết.
- Benchmark dễ bị trình bày sai nếu chỉ đo matcher độc lập.

### Giải pháp đề xuất

Dùng hai pha:

```text
Phase 1: Candidate extraction
    raw/http text -> Aho-Corasick -> candidate rule IDs

Phase 2: Rule validation
    candidate rules -> address/port/flags/http modifier/PCRE
```

Nên lưu metadata khi build:

```python
PatternEntry(
    pattern=normalized_pattern,
    rule_sid=rule.sid,
    target="http_uri" | "http_body" | "http_header" | "raw",
    nocase=rule.nocase,
)
```

Lưu ý:

- Content không có pattern vẫn cần được xử lý theo điều kiện khác.
- Rule có nhiều content phải kiểm tra đủ tất cả content.
- `nocase` cần được normalize nhất quán trước khi build.
- Candidate index phải được rebuild atomically khi hot-reload.
- PCRE chỉ chạy sau khi content candidate đã match, nếu rule có content.

### Tiêu chí nghiệm thu

- Kết quả trước/sau tối ưu giống nhau trên toàn bộ regression corpus.
- Benchmark có số rule tăng dần.
- Đo CPU/packet và latency p50/p95/p99.
- Không dùng matcher cũ cho quyết định chính sau khi hoàn tất migration.

## DE-06 — Ghi alert đồng bộ trong analysis worker

### Hiện trạng

Khi match rule, `_trigger_alert()` gọi callback; callback gọi `EventRepository.save_alert()`. Repository tạo session, insert và commit ngay lập tức.

Như vậy worker detection bị phụ thuộc trực tiếp vào latency của database.

### Tác động

- Database chậm làm packet analysis chậm.
- Queue đầy và drop packet.
- Database tạm thời unavailable có thể làm mất alert hoặc dừng pipeline.
- Mỗi alert một transaction gây overhead lớn.

### Giải pháp đề xuất

Tách thành pipeline:

```text
Detection worker
    |
    v
Bounded alert queue
    |
    v
Alert persistence worker
    |-- batch insert
    |-- retry có backoff
    |-- dead-letter/error metric
    v
Database
```

Alert object nên là immutable DTO, không truyền SQLAlchemy session vào detection engine.

Chính sách khi alert queue đầy phải được định nghĩa rõ:

- Ưu tiên giữ alert severity 1.
- Gộp alert trùng.
- Ghi buffer tạm thời.
- Hoặc drop có metric và thông báo rõ ràng.

Không nên gọi là “zero loss” nếu hệ thống chưa có durable queue.

### Tiêu chí nghiệm thu

- Database delay không block packet analysis trong thời gian ngắn.
- Alert được retry khi database tạm thời lỗi.
- Batch insert giảm số transaction.
- Có metric `alerts_queued`, `alerts_persisted`, `alerts_failed`, `alerts_dropped`.

## DE-07 — Không có deduplication, threshold và suppression

### Hiện trạng

Mỗi packet match rule đều tạo một event. Không có fingerprint, cooldown hoặc grouping theo flow.

### Tác động

- Một scan có thể tạo hàng nghìn bản ghi.
- Database phình nhanh.
- Dashboard bị alert storm.
- Khó xác định incident thực tế.
- Chính NIDS có thể bị làm nghẽn bằng traffic lặp.

### Giải pháp đề xuất

Tạo fingerprint ổn định, không hash toàn bộ payload vô hạn:

```text
fingerprint =
hash(sid, normalized_src, normalized_dst,
     dst_port, protocol, flow_id, normalized_evidence)
```

Thiết kế suppression:

```text
same fingerprint trong 30 giây -> gộp vào một incident
incident -> count, first_seen, last_seen, sample evidence
```

Tách khái niệm:

- `packet_match`: một packet match rule.
- `alert`: cảnh báo đã qua threshold/suppression.
- `incident`: nhóm alert cùng nguyên nhân.

### Tiêu chí nghiệm thu

- Packet lặp không tạo vô hạn event độc lập.
- Event vẫn giữ được count và first/last seen.
- Hai attack khác nhau không bị gộp nhầm.
- Suppression có thể cấu hình theo SID/severity.

## DE-08 — PCRE chưa có giới hạn tài nguyên

### Hiện trạng

`_match_pcre()` gọi `re.search()` trực tiếp trên input. Python `re` có thể bị backtracking lớn với regex không an toàn.

Ngoài ra, regex có thể đến từ rule được tạo qua API.

### Tác động

- Analysis worker bị chiếm CPU.
- Queue tăng và packet bị drop.
- Một rule xấu có thể ảnh hưởng toàn bộ sensor.

### Giải pháp đề xuất

1. Giới hạn độ dài PCRE và payload đưa vào regex.
2. Compile regex khi rule được load, không compile mỗi packet.
3. Validate regex lúc import/create/update.
4. Dùng thư viện có timeout hoặc regex engine an toàn khi phù hợp.
5. Cô lập rule untrusted trong process/worker có giới hạn CPU.
6. Ghi rõ rule SID và lỗi compile vào log/metric.
7. Reject regex lỗi thay vì giữ rule “enabled” nhưng match im lặng.

Không nên dùng `except Exception: return False` cho mọi lỗi regex mà không lưu lý do. Một regex invalid phải làm rule ở trạng thái lỗi hoặc bị từ chối.

### Tiêu chí nghiệm thu

- Regex invalid bị từ chối khi lưu rule.
- Regex vượt giới hạn bị từ chối.
- Một regex tốn CPU không làm treo toàn bộ capture.
- Có test latency timeout và trạng thái rule lỗi.

## DE-09 — Rule parser chỉ tương thích một phần Snort

### Hiện trạng

`RuleManager.parse_rule_line()` tách option bằng `split(";")` và chỉ hỗ trợ một số option. Cách này dễ hỏng khi option chứa ký tự đặc biệt hoặc PCRE phức tạp.

Các option nâng cao như `offset`, `depth`, `distance`, `within`, `flow`, `urilen`, `byte_test` chưa được hỗ trợ.

### Tác động

- Rule hợp lệ có thể parse sai.
- Rule bị bỏ qua nhưng hệ thống chỉ in warning.
- Kết quả detection khác với kỳ vọng của người viết rule.
- Tài liệu “Snort-compatible” gây kỳ vọng vượt quá implementation.

### Giải pháp đề xuất

Thiết kế parser theo grammar có state:

1. Parse header bằng tokenizer.
2. Parse option block có hỗ trợ quote/escape.
3. Tách option theo dấu `;` chỉ khi đang ở ngoài quote/regex delimiter.
4. Validate option theo schema.
5. Chuẩn hóa thành AST/domain model.
6. Compile matcher từ domain model.

Nên chia compatibility thành các mức:

```text
Supported:
  content, nocase, pcre, flags,
  http_uri, http_header, http_client_body, http_method

Rejected explicitly:
  option chưa hỗ trợ

Future:
  offset, depth, flow, byte_test, ...
```

Không nên âm thầm bỏ qua option mà người dùng tưởng là đang có hiệu lực.

### Tiêu chí nghiệm thu

- Parser có test cho quote, escape và PCRE.
- Option chưa hỗ trợ tạo lỗi rõ ràng.
- Rule import báo file, dòng, SID và lý do lỗi.
- Tất cả rule hợp lệ trong corpus hiện tại parse ổn định.

## DE-10 — Thiếu flow state, shutdown và metrics

### Hiện trạng

Worker hiện chạy vòng lặp vô hạn và là daemon thread. Chưa có stop event, flow memory hoặc metrics vận hành đầy đủ.

### Tác động

- Có thể mất alert cuối khi process dừng.
- Khó biết queue có đang quá tải không.
- Không biết bao nhiêu packet bị drop.
- Không biết latency detection và persistence.
- Không có cơ sở để đặt capacity hoặc chứng minh SLA.

### Giải pháp đề xuất

### Shutdown

- Dùng `threading.Event()` làm stop signal.
- Dừng capture trước.
- Ngừng nhận packet mới.
- Drain analysis queue trong thời gian giới hạn.
- Drain alert queue.
- Flush database writer.
- Join worker và ghi trạng thái shutdown.

### Metrics tối thiểu

```text
packets_captured_total
packets_decoded_total
packets_ignored_total
packets_dropped_total
queue_depth
flow_count
flow_evictions_total
rules_loaded
rule_reload_failures_total
detection_duration_seconds
alerts_matched_total
alerts_persisted_total
alerts_dropped_total
regex_failures_total
```

Nên phân biệt:

- `capture health`: còn nhận packet không.
- `detection health`: worker còn xử lý không.
- `storage health`: database có ghi được không.
- `rule health`: số rule active và lần reload cuối.

### Tiêu chí nghiệm thu

- Shutdown bình thường không mất alert đã nhận trước deadline.
- Có thể quan sát queue depth và packet drop.
- Có p50/p95/p99 detection latency.
- Health endpoint phân biệt liveness và readiness.

## 5. Kiến trúc Detection Engine đề xuất

```text
PacketCapture
    |
    v
DecodeWorker
    |
    v
FlowTracker / TCP Reassembler
    |
    +--> Flow metadata/features
    |
    v
Protocol Parser
    |-- HTTP plaintext
    |-- raw TCP/UDP/ICMP
    v
Candidate Matcher
    |-- address/port index
    |-- Aho-Corasick content index
    v
Rule Evaluator
    |-- flags
    |-- HTTP modifiers
    |-- PCRE with limits
    |-- threshold/stateful conditions
    v
Alert Aggregator
    |-- dedupe
    |-- suppression
    |-- incident grouping
    v
Bounded Alert Queue
    |
    v
Persistence Worker / Event Bus
    |
    +--> Database
    +--> WebSocket/dashboard
    +--> Metrics/logging
```

### Nguyên tắc thiết kế

1. Capture không được làm detection hoặc database I/O.
2. Detection không được phụ thuộc vào transaction database đồng bộ.
3. Mọi buffer phải có giới hạn và eviction policy.
4. Rule compile/reload phải atomic: phiên bản mới hoàn chỉnh rồi mới swap.
5. Mỗi packet/flow có correlation ID để trace.
6. Lỗi rule phải hiển thị rõ, không fallback thành “không match” im lặng.
7. Raw evidence phải có retention và privacy policy.

## 6. Lộ trình triển khai

### Phase 1 — Sửa lỗi ảnh hưởng độ chính xác và an toàn

1. Implement address/direction matching.
2. Làm rõ và sửa TCP flags semantics.
3. Thêm giới hạn HTTP/PCRE/content.
4. Bỏ silent exception ở reload và regex.
5. Viết unit test cho parser và matcher.

### Phase 2 — TCP flow và HTTP correctness

1. Thêm `FlowTracker`.
2. Implement TCP sequence reassembly có bounded memory.
3. Parse request boundary sau reassembly.
4. Canonicalize URI/body theo chính sách.
5. Thêm flow timeout và cleanup metrics.

### Phase 3 — Hiệu năng và độ bền

1. Tích hợp Aho-Corasick vào candidate extraction.
2. Tách detection worker và persistence worker.
3. Batch insert/retry/backoff.
4. Alert deduplication và suppression.
5. Thêm graceful shutdown.

### Phase 4 — Production hardening

1. Structured logging.
2. Metrics và health/readiness.
3. Benchmark theo packet rate và số lượng rule.
4. PCAP regression corpus.
5. Fault injection cho database chậm/mất kết nối.
6. Tài liệu compatibility của rule engine.

## 7. Chiến lược kiểm thử

### Unit test

- Decode IPv4/IPv6/TCP/UDP/ICMP.
- HTTP request line/header/body.
- URL encoding/canonicalization.
- Address, CIDR, port và direction matching.
- Exact/required TCP flags.
- Parser option có quote/escape.
- PCRE compile/validation.

### Integration test

- PCAP packet -> decode -> flow -> detection -> alert DTO.
- Alert queue -> database persistence.
- Rule reload trong lúc traffic đang chạy.
- Database unavailable rồi hoạt động lại.
- Flow timeout và packet out-of-order.

### Regression test

Mỗi fixture cần có:

```json
{
  "pcap": "fixture.pcap",
  "expected_alerts": [
    {"sid": 1000001, "count": 1}
  ],
  "expected_drops": 0
}
```

Không nên chỉ kiểm tra “có alert hay không”. Cần kiểm tra:

- SID.
- Severity.
- Source/destination.
- Protocol.
- Số lượng alert.
- Latency.
- Packet drop.

### Performance test

Đo tối thiểu:

- Packet per second.
- Payload bytes per second.
- Số rule.
- Tỷ lệ rule có PCRE.
- Queue depth.
- CPU/RAM.
- Detection p50/p95/p99.
- Alert persistence throughput.

## 8. Tiêu chí sẵn sàng production

Detection Engine chỉ nên được xem là sẵn sàng cho traffic thật khi đáp ứng:

- Có TCP reassembly hoặc giới hạn rõ ràng về loại traffic được hỗ trợ.
- Match đúng IP, CIDR, port và direction.
- Có test coverage cho toàn bộ rule đang enabled.
- Có bounded memory cho flow/payload/regex.
- Database chậm không block capture.
- Có alert deduplication hoặc rate control.
- Có metrics packet drop và detection latency.
- Có graceful shutdown.
- Có benchmark ở tải mục tiêu.
- Tài liệu phản ánh đúng hành vi thực tế.

## 9. Kết luận

Detection Engine hiện là một prototype rule engine tốt cho mục tiêu minh họa và demo PCAP. Điểm yếu cốt lõi nằm ở việc engine đang coi mỗi packet là một message hoàn chỉnh, trong khi TCP/HTTP thực tế là stream; đồng thời các điều kiện rule chưa được áp dụng đầy đủ và persistence đang nằm trên đường nóng.

Thứ tự nên làm là:

1. Sửa correctness: IP/direction, flags, parser validation.
2. Thêm bounded TCP reassembly và HTTP framing.
3. Tách persistence khỏi detection.
4. Tích hợp Aho-Corasick và alert aggregation.
5. Bổ sung metrics, shutdown, benchmark và regression suite.

Sau các bước này, engine mới có cơ sở để mở rộng sang flow anomaly detection và dashboard realtime mà không xây thêm tính năng trên một pipeline chưa ổn định.
