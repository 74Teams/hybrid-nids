---
paths:
  - "rules/**/*.rules"
  - "nids/engine/**"
  - "nids/db/repository.py"
---

# Quy tắc viết rule (Snort 3)

Rule built-in chia theo nhóm, mỗi nhóm một file: `rules/web-attack.rules`, `scan.rules`, `dos.rules`, `auth.rules`, `malware-c2.rules`, `recon.rules` (xem bảng SID). Rule tự viết qua web nằm trong `rules/custom.rules`. Cú pháp là **Snort 3**, nhưng engine chỉ hiểu một tập con: chỉ dùng các option liệt kê ở mục "Option được hỗ trợ". Rule viết đúng theo tài liệu này cũng chạy được trên Snort 3 thật.

## Quy trình thêm hoặc sửa rule

1. Chọn SID còn trống trong dải của nhóm (bảng SID bên dưới). Đặt rule vào đúng file của nhóm đó, giữ thứ tự SID tăng dần.
2. Viết rule theo **thứ tự option chuẩn**.
3. Rule mới: `rev:1`. Sửa rule đã có: **tăng `rev` thêm 1**. Việc tăng `rev` chỉ để ghi nhận rule đã đổi. Engine đang chạy tự nạp lại trong vài giây sau khi file đổi.
4. Thêm test trong `tests/engine/test_diverse_rules_engine.py`: một gói tấn công làm rule bắn, và một gói hợp lệ gần giống mà rule **không** bắn.
5. Xong khi: `pytest` xanh, và khi nạp file không có dòng `WARNING rules` nào (dòng này nghĩa là lỗi cú pháp, SID trùng hoặc có option bị bỏ qua; đặt `system.log_level: DEBUG` để xem chi tiết từng rule).

## Header

```
alert <proto> <src_ip> <src_port> -> <dst_ip> <dst_port> (<options>)
```

| Thành phần | Giá trị dùng được |
|---|---|
| action | `alert` |
| proto | `tcp`, `udp`, `icmp`, `ip` |
| IP | `any` (engine chưa so khớp IP, mọi giá trị đều coi như `any`) |
| port | `any`, một số cổng (`22`), hoặc `$HTTP_PORTS` |
| hướng | `->` |

Engine chưa hỗ trợ danh sách cổng (`[80,443]`), dải cổng (`1:1024`) hay phủ định cổng (`!80`): chúng khớp mọi cổng mà không báo lỗi. Khi cần nhiều cổng, viết mỗi cổng một rule.

`$HTTP_PORTS` được định nghĩa cứng ở hai nơi: `DetectionEngine._match_port` (80, 8080, 8000, 3000, 5000) và `nids/engine/decoder.py::HTTP_PORTS` (danh sách cổng sẽ được parse HTTP). Thêm cổng HTTP thì sửa cả hai.

## Thứ tự option chuẩn

```
msg; flow; [flags | itype/icode | dsize]; [buffer; content...; pcre...]...; [detection_filter]; [service]; classtype; priority; sid; rev;
```

Ví dụ:

```
alert tcp any any -> any $HTTP_PORTS (msg:"WEB-ATTACK SQL Injection - UNION SELECT detected"; flow:to_server,established; http_uri; content:"union",nocase; content:"select",nocase,distance 0; service:http; classtype:web-application-attack; priority:1; sid:1000001; rev:2;)
```

Mọi option kết thúc bằng `;`, kể cả option cuối cùng trước `)`. Mỗi rule nằm trên một dòng.

## Sticky buffer

Buffer là **sticky**: viết tên buffer **trước** các content/pcre, và mọi content/pcre phía sau thuộc buffer đó cho đến khi gặp buffer khác.

| Buffer | Nội dung |
|---|---|
| `pkt_data` | payload thô (mặc định khi chưa khai báo buffer nào) |
| `http_uri` | URI của request, chưa URL-decode (`%3D` vẫn là `%3D`, `+` vẫn là `+`) |
| `http_header` | toàn bộ header dạng `name: value`, nối bằng `\r\n`, tên header viết thường |
| `http_header:field <name>` | chỉ giá trị của một header, `<name>` viết thường |
| `http_client_body` | body của request |
| `http_method` | method (`GET`, `POST`...) |

Rule có buffer `http_*` thêm `service:http;`. Buffer `http_*` chỉ có khi gói tin tới cổng trong `nids/engine/decoder.py::HTTP_PORTS`. Vì `http_uri` chưa được URL-decode, pcre trên URI phải tự bao cả dạng encode, ví dụ `[\s+]` cho khoảng trắng và `(=|%3d)` cho dấu bằng.

## Option được hỗ trợ

| Option | Cú pháp | Ghi chú |
|---|---|---|
| `msg` | `msg:"..."` | Bắt đầu bằng tiền tố nhóm: `WEB-ATTACK`, `SCAN`, `DOS`, `AUTH`, `MALWARE`, `C2`, `RECON` |
| `content` | `content:[!]"chuỗi"[,nocase][,offset N][,depth N][,distance N][,within N][,fast_pattern]` | Modifier viết sau dấu phẩy, cùng option |
| `pcre` | `pcre:"/regex/flags"` | Chỉ hỗ trợ flag `i s m x`; regex theo cú pháp Python `re` |
| `flow` | `flow:to_server,established` hoặc `flow:stateless` | Xem giới hạn engine |
| `flags` | `flags:S`, `S+`, `SF*`, `!F`, `0`, `S,CE` | Không có `+`/`*`/`!` nghĩa là khớp **chính xác** (cờ thừa thì không khớp) |
| `dsize` | `dsize:>800`, `<10`, `100<>200` | Độ dài payload |
| `itype`, `icode` | `itype:8`, `icode:0` | Chỉ dùng cho `icmp` |
| `detection_filter` | `detection_filter:track by_src\|by_dst, count N, seconds S` | Chỉ bắn khi có hơn N lần khớp trong S giây |
| `classtype` | `classtype:web-application-attack` | Dùng tên có trong `classification.config` của Snort |
| `priority` | `priority:1` | 1 = cao, 2 = trung bình, 3 = thấp  |
| `sid`, `rev` | `sid:1000001; rev:1;` | Bắt buộc |
| `service`, `reference`, `metadata`, `gid` | | Được chấp nhận nhưng engine không dùng |

Option ngoài bảng (`byte_test`, `isdataat`, `threshold`, `pcre` có flag `R`...) sẽ bị bỏ qua kèm cảnh báo, hoặc làm rule lỗi. Khi cần một option mới, cài nó trong `RuleManager.parse_rule_line` và `DetectionEngine`, viết test, rồi bổ sung vào bảng này.

Dùng `priority` để đặt mức độ. Cú pháp Snort 2 không được hỗ trợ: `nocase;` đứng riêng (viết `content:"x",nocase`), `http_method:"..."` (dùng sticky buffer `http_method; content:...`) và `severity:` (dùng `priority`).

## Chuỗi trong content và pcre

- Ký tự `"`, `;`, `\` trong chuỗi phải escape: `\"`, `\;`, `\\`.
- Byte nhị phân trong content viết dạng hex giữa hai dấu `|`: `content:"|04 06|public"`. Ký tự `|` thật thì viết `|7C|`.
- Trong pcre, nên viết `;` là `\x3b` và nháy kép là `\x22` để chuỗi không phụ thuộc cách escape.

## Chất lượng phát hiện

- **Rule TCP có content** thêm `flow:to_server,established` (hoặc `flow:established` khi không biết hướng). **Rule chỉ xét cờ TCP** dùng `flow:stateless`.
- **Fast pattern** là content dài nhất của rule (hoặc content có `fast_pattern`), dùng để lọc nhanh bằng Aho-Corasick. Hãy chọn content dài và đặc trưng nhất. Rule chỉ có pcre hoặc chỉ có content ngắn sẽ bị đánh giá trên mọi gói, nên ghép thêm một content.
- **Neo vị trí** khi biết chỗ chuỗi xuất hiện: `depth` cho banner hoặc lệnh ở đầu payload (`content:"SSH-2.0",depth 7`), và `distance`/`within` cho content thứ hai đứng sau content thứ nhất.
- **Phát hiện dựa trên tần suất** (flood, brute force) dùng `detection_filter`, để một gói hợp lệ đơn lẻ không gây cảnh báo.
- **Đặc trưng phải là của giao thức hoặc tấn công thật** (opcode, cấu trúc gói, `itype`, `dsize`), không phải chuỗi tự đặt chỉ có trong gói demo.

## SID

| Dải | Nhóm | File |
|---|---|---|
| `10000xx` | WEB-ATTACK | `rules/web-attack.rules` |
| `10001xx` | SCAN | `rules/scan.rules` |
| `10002xx` | DOS | `rules/dos.rules` |
| `10003xx` | AUTH | `rules/auth.rules` |
| `10004xx` | MALWARE, C2 | `rules/malware-c2.rules` |
| `10005xx` | RECON (UDP / ICMP) | `rules/recon.rules` |
| `≥ 2000000` | Rule tự viết trên web | `rules/custom.rules` |

Mỗi SID chỉ xuất hiện một lần trong mọi file. Nếu trùng, parser giữ rule nạp trước (file xếp theo tên) và bỏ rule sau.

## Giới hạn của engine

Đây là những chỗ engine khác Snort 3 thật. Cần nhớ khi viết rule hoặc test:

- `flow:established` được xấp xỉ: gói TCP có ACK và không có SYN. `to_server`/`from_server` chưa được kiểm tra.
- Các content trong một buffer được khớp tham lam theo thứ tự, không quay lui. Hãy viết content theo đúng thứ tự xuất hiện trong dữ liệu.
- Tái hợp luồng TCP chỉ làm cho chiều client → server và `stream.depth` byte đầu mỗi stream (mặc định 64 KB). Chiều server → client vẫn so khớp từng gói, nên rule `to_client`/`from_server` không bắt được chuỗi bị chia gói.
- Lượt so khớp trên dữ liệu đã ghép chỉ xét rule có `content`/`pcre` và không có `dsize`, `flags`, `detection_filter`. Rule có các option này chỉ khớp trên từng gói.
- Rule đã bắn trên một gói hoặc trên dữ liệu đã ghép thì không báo lại cho cùng HTTP request (với traffic không phải HTTP là cả stream).
- `detection_filter` đếm theo `packet.timestamp`, nên trong test các gói dựng sẵn phải có timestamp nằm trong cửa sổ `seconds`.
