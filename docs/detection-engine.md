# Engine phát hiện

Engine (`services/sensor/src/nids/engine/`, chạy bằng `python -m nids.engine`) có hai lớp phát hiện:

- **rule** cú pháp Snort 3, bắt tấn công có nội dung đặc trưng;
- **phát hiện bất thường theo ngưỡng** (`ANOMALY`), bắt hành vi mà rule bỏ sót.

Engine cũng gom mọi gói thành **flow** để ghi log traffic và làm đầu vào cho mô hình AI.

## 1. Pipeline

| Bước | Module | Việc làm |
|---|---|---|
| 1. Capture | `capture.py` | Scapy sniff live (promiscuous) hoặc đọc pcap offline; áp `bpf_filter` |
| 2. Decode | `decoder.py`, `http_parser.py` | IP/TCP/UDP/ICMP, cờ TCP, payload L4; tách HTTP request (method, URI, header, body) thành `ParsedHTTPRequest` |
| 3. Queue | `main.py` | `queue.Queue` có giới hạn (`queue_max_size`, mặc định 10.000) |
| 4. Rule | `detector.py` | Phễu 4 tầng (mục 3) trên từng gói |
| 5. Tái hợp TCP | `stream.py` | Ghép payload client → server, chạy lại rule trên luồng đã ghép |
| 6. Flow | `flow.py` | Gom gói thành flow hai chiều, ghi bảng `flows` |
| 7. Bất thường | `anomaly.py` | Đếm theo cửa sổ thời gian: scan, flood, cổng hiếm |
| 8. Cảnh báo | `main.py`, `alert_writer.py` | `handle_alert` làm giàu bằng honeypot, rồi `AlertWriter` ghi theo lô |

Dữ liệu giữa các tầng dùng dataclass: `DecodedPacket`, `ParsedHTTPRequest` (`packet.py`) và `SnortRule` (`rule.py`).

Mọi mốc thời gian (threshold, flow, anomaly) lấy theo `packet.timestamp`, không theo đồng hồ máy. Nhờ vậy replay cùng một file pcap luôn ra đúng cùng số cảnh báo.

## 2. Rule cú pháp Snort 3

### 2.1 Ví dụ

```text
alert tcp any any -> any $HTTP_PORTS (msg:"WEB-ATTACK SQL Injection - UNION SELECT detected";
  flow:to_server,established; http_uri; content:"union",nocase; content:"select",nocase,distance 0;
  service:http; classtype:web-application-attack; priority:1; sid:1000001; rev:2;)
```

### 2.2 Phần được hỗ trợ

| Thành phần | Hỗ trợ |
|---|---|
| Header | `any`, IP đơn, CIDR, dải cổng `1:1024`, danh sách lồng `[a,b]`, phủ định `!x`, biến `$X`, hướng `->` và `<>` |
| Sticky buffer | `http_uri`, `http_header`, `http_client_body`, `http_method`, raw payload |
| `content` | modifier sau dấu phẩy: `nocase`, `depth`, `offset`, `distance`, `within`, `fast_pattern` |
| Option khác | `pcre`, `flags`, `flow`, `dsize`, `itype`/`icode`, `detection_filter`, `classtype`, `priority` |

- Chỉ hiểu **cú pháp Snort 3**. Cú pháp Snort 2 (`nocase;` đứng riêng, `http_method:"POST"`) không được hỗ trợ. Rule community đã được chuyển sang Snort 3 bằng `python -m tools.rules.snort2_convert`.
- Header không hiểu được thì rule bị bỏ kèm log `WARNING`. Rule đó không bao giờ bị hiểu thành "khớp tất cả".
- `flow:established` được xấp xỉ bằng cờ ACK.

### 2.3 Biến

Biến khai báo ở `detection.variables` trong `settings.yaml`, chồng lên giá trị mặc định trong code. `$HTTP_PORTS` dùng chung cho rule và cho decoder: thêm một cổng HTTP chỉ cần sửa cấu hình. Mặc định không có 443, vì HTTP trên 443 là TLS nên không parse được.

### 2.4 Quản lý rule

- Rule chỉ đọc từ file trong `data/rules/`, mỗi file là một category.
- `data/rules/state.yaml` (gitignore) lưu các category và SID được bật hoặc tắt trên trang Rules. File này **được dashboard ghi tự động**.
- Engine kiểm tra mỗi 2 giây. File `.rules` hoặc `state.yaml` đổi thì engine nạp lại và dựng lại index, không cần khởi động lại.
- `custom.rules` là rule viết trên web (SID ≥ 2000000). API kiểm tra cú pháp từng dòng trước khi lưu.

## 3. Phễu so khớp

```
gói ──► (1) demux theo protocol/cổng ──► (2) prefilter Aho-Corasick ──► (3) kiểm tra chi tiết ──► (4) threshold ──► cảnh báo
```

| Tầng | Cách làm | Mục đích |
|---|---|---|
| 1. Demux | Chỉ xét rule cùng protocol; cổng so bằng bảng bit 65.536 cổng tính sẵn (O(1)); rule `any any -> any any` bỏ qua bước này | Loại phần lớn rule ngay từ đầu |
| 2. Prefilter | Mỗi rule được index bằng *fast pattern* (content có `fast_pattern`, nếu không có thì content dài nhất). Mỗi buffer (URI, header, body, raw) có một matcher Aho-Corasick riêng | Một lần duyệt payload tìm mọi mẫu; chỉ rule có mẫu xuất hiện mới đi tiếp |
| 3. Chi tiết | flags, flow, dsize, itype/icode, từng `content` theo buffer và vị trí, `pcre`, `detection_filter` | Xác nhận đúng ngữ nghĩa rule |
| 4. Threshold | `ThresholdManager` chặn cảnh báo trùng theo khoá `(sid, src, dst, dst_port)`, hoặc theo `track` của `detection_filter` | Tránh bão cảnh báo |

Rule không có `content` nằm trong `no_content_rules` và luôn được đánh giá ở tầng 3.

## 4. Tái hợp luồng TCP

Kẻ tấn công có thể chia chuỗi `union select` qua hai gói để né so khớp từng gói. `StreamReassembler` (`stream.py`) xử lý trường hợp này:

- Ghép payload **chiều client → server** theo `tcp_seq`. Client là bên gửi SYN.
- Gói đến sai thứ tự được giữ ở `pending`. Dữ liệu chồng lấn thì giữ phần đến trước.
- Buffer có từ hai đoạn trở lên thì chạy lại rule trên một gói ảo (`reassembled=True`).
- Không quét lại toàn bộ buffer ở mọi segment, để tránh chi phí tăng theo bậc hai. Dưới 4 KB thì quét mỗi segment. Lớn hơn thì chỉ quét khi buffer gấp đôi, khi đủ một HTTP request, hoặc khi client gửi FIN/RST.
- Mỗi stream nhớ các SID đã bắn để không báo lặp. Tập SID được làm mới sau mỗi HTTP request, nên đòn thứ hai trên cùng kết nối keep-alive vẫn bị báo.
- Giới hạn bộ nhớ: `depth` byte cho mỗi stream (mặc định 64 KB), cộng giới hạn tổng byte và tổng số stream.

## 5. Flow log

`FlowTracker` (`flow.py`) gom gói theo 5-tuple chuẩn hoá hai chiều. Bên gửi gói đầu tiên là nguồn; nếu gói đầu là SYN-ACK thì đảo chiều.

| Điều kiện kết thúc flow | Mặc định |
|---|---|
| TCP đóng bằng FIN hai chiều hoặc RST, chờ thêm `closing_timeout` để ACK cuối không thành flow riêng | 2 giây |
| Không có gói (`idle_timeout`) | 30 giây |
| Flow sống quá lâu (`active_timeout`), bị cắt thành nhiều dòng | 120 giây |
| Bảng đầy (`max_flows`), đẩy flow lâu nhất không có gói ra | 100.000 flow |

- Flow kết thúc được ghi theo lô (500 flow hoặc 5 giây) vào bảng `flows`. Flow cũ hơn `retention_hours` (mặc định 24 giờ) bị xoá.
- `alert_count` là số rule khớp, tính cả lần bị threshold chặn. `alert_count = 0` nghĩa là traffic **chưa có rule nào bắt**; tab "Chưa khớp rule" trên trang Traffic lọc theo cột này.
- Thứ tự `FlowTracker` xuất flow là một phần hợp đồng với mô hình AI ([machine-learning-guide.md](machine-learning-guide.md)). Có test khoá thứ tự này.

## 6. Phát hiện bất thường theo ngưỡng

`AnomalyDetector` (`anomaly.py`) bắt tấn công chưa có rule bằng cách đếm gói "mở kết nối" theo cửa sổ thời gian. Gói mở kết nối gồm: TCP SYN không có ACK, ICMP echo, và UDP không xuất phát từ cổng trong `common_ports`.

| Loại | Điều kiện mặc định | Priority | Khoá chặn |
|---|---|---|---|
| Port scan | Một nguồn chạm ≥ 15 cặp (IP, cổng) trong 5 giây | P2 | theo nguồn |
| Host sweep | Một nguồn chạm ≥ 10 máy trong 5 giây | P2 | theo nguồn |
| SYN flood | Một đích nhận ≥ 100 SYN trong 1 giây | P1 | theo đích |
| Packet flood | Một đích nhận ≥ 500 gói trong 1 giây | P1 | theo đích |
| Cổng / ICMP hiếm | TCP SYN tới cổng ngoài `common_ports`; UDP tới cổng < 1024 ngoài danh sách; ICMP type ngoài {0, 3, 8, 11} | P3 | theo nguồn |

- Mỗi loại chỉ báo một lần trong `suppress_seconds` (mặc định 60 giây).
- Cảnh báo có `source_type="ANOMALY"`, `sid` rỗng, và bằng chứng (danh sách cổng, số gói) ở `matched_content`.
- Lớp này vẫn báo kể cả khi rule cũng bắt cùng traffic. Ví dụ SID 1000107 và `ANOMALY Port scan` cùng bắn khi quét cổng nhanh. Khi quét chậm dưới ngưỡng rule, chỉ ANOMALY bắn.

## 7. Bộ rule

### 7.1 Rule tự viết (68 rule)

| Dải SID | File | Số rule | Bao phủ |
|---|---|---|---|
| `10000xx` | `web-attack.rules` | 24 | SQLi, XSS, path traversal, LFI/RFI, command injection, Log4Shell, Shellshock, XXE, SSRF, file nhạy cảm |
| `10001xx` | `scan.rules` | 8 | Nmap Xmas/Null/FIN, SYN-FIN, SYN-RST, SYN scan, User-Agent công cụ quét |
| `10002xx` | `dos.rules` | 9 | SYN/UDP/ICMP/HTTP flood, Slowloris, ICMP lớn, khuếch đại NTP/DNS/Memcached |
| `10003xx` | `auth.rules` | 7 | Brute force SSH/FTP/web, FTP anonymous, HTTP Basic, đăng nhập admin |
| `10004xx` | `malware-c2.rules` | 11 | Webshell, reverse shell, PowerShell, Mimikatz, EICAR, cryptominer, sqlmap, Nikto |
| `10005xx` | `recon.rules` | 9 | SNMP `public`, DNS tunneling/AXFR/`version.bind`, ICMP timestamp/mask, NetBIOS, SSDP |
| `≥ 2000000` | `custom.rules` | | Rule viết trên trang Rules |

Mỗi rule tự viết có test gói tấn công, test gói lành tính gần giống, và một đòn tương ứng trong `lab/attacker/attack_demo.py`. Test `tests/lab/test_attack_demo.py` kiểm tra mọi rule đều có đòn trình diễn.

### 7.2 Rule community (2.792 rule)

Bộ Snort Community được chuyển sang Snort 3 bằng `python -m tools.rules.snort2_convert` từ `data/rules/upstream/community.rules`, rồi chia thành 4 file:

| File | Số rule |
|---|---|
| `community-web.rules` | 1.070 |
| `community-malware.rules` | 843 |
| `community-server.rules` | 595 |
| `community-protocol.rules` | 284 |

Không sửa tay các file này: sinh lại bằng công cụ chuyển đổi.

### 7.3 Viết rule mới

1. Chọn SID còn trống trong dải của nhóm, thêm rule vào file của nhóm.
2. Viết test positive và negative, thêm đòn vào `lab/attacker/attack_demo.py`.
3. Engine đang chạy tự nạp lại sau vài giây.

Hướng dẫn đầy đủ: `.claude/rules/snort-rules.md`. Lệnh `/them-rule` trong Claude Code làm trọn các bước này.

## 8. Giới hạn đã biết

| Giới hạn | Ảnh hưởng |
|---|---|
| Chỉ một tập con option Snort | Một số option (`byte_test`, `byte_jump`, `flowbits`...) không được hỗ trợ |
| Python + Scapy | Khoảng 2.300–3.200 gói/giây; Scapy chiếm hơn 50% thời gian |
| Tái hợp TCP một chiều | Không ghép chiều server → client; chưa tách ranh giới HTTP `chunked` và pipelining |
| Không thấy SYN | Bên có cổng nhỏ hơn được coi là server; không xử lý được đảo thứ tự ở đoạn đầu |
| Ngưỡng cố định | Một số rule tần suất (1000205, 1000107, 1000209) và ANOMALY báo nhầm nhiều trên mạng thật ([performance-metrics.md](performance-metrics.md)) |
