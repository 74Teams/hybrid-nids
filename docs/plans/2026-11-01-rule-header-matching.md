---
type: PLAN
plan_id: PLAN-003
title: So khớp header rule theo biến, cổng và IP
status: IN_PROGRESS
issue: 17, 18, 20, 21
owner: nldd0507
created: 2026-11-01
updated: 2026-11-01
---

# PLAN-003: So khớp header rule theo biến, cổng và IP


## 1. Bối cảnh

Header của rule Snort (`alert tcp <IP nguồn> <cổng nguồn> -> <IP đích> <cổng đích>`) hiện chỉ được hiểu một phần:

- `$HTTP_PORTS` được viết cứng ở hai nơi và **đang lệch nhau**: `nids/engine/detector.py:189` có 5 cổng, `nids/engine/decoder.py:10` có thêm 443.
- `[80,443]`, `1:1024`, `!80` khớp mọi cổng mà không báo lỗi: `_match_port` (`detector.py:186`) bắt `ValueError` rồi trả về `True`. Rule viết đúng cú pháp vẫn âm thầm sai.
- IP trong header bị bỏ qua hoàn toàn, nên `$HOME_NET` hay `10.0.0.0/8` không có tác dụng.

Bốn issue cùng chạm một chỗ nên gộp một PR theo quyết định của người dùng: #20 (biến), #17 (cổng), #18 (IP), #21 (nạp lại rule). #21 đã có code (`RuleReloader`, `nids/engine/main.py`) và test (`tests/engine/test_main_output.py:83`), PR này chỉ bổ sung test theo đúng điều kiện "Xong khi" rồi đóng issue.

## 2. Mục tiêu và tiêu chí thành công

- **Mục tiêu**: mọi dạng header hợp lệ được so khớp đúng; dạng không hiểu được thì báo lỗi lúc nạp thay vì khớp tất cả; biến khai báo một chỗ trong `settings.yaml`.
- **Xong khi**:
  - Thêm một cổng HTTP chỉ cần sửa `detection.variables.HTTP_PORTS`, cả rule `$HTTP_PORTS` lẫn việc parse HTTP đều nhận (#20).
  - `[80,443]`, `1:1024`, `!80`, `![80,443]` có test đúng và sai; dạng sai sinh `WARNING rules` và rule bị bỏ qua (#17).
  - Rule giới hạn theo IP, CIDR, danh sách, phủ định chỉ bắn với đúng IP (#18).
  - Sửa file `.rules` khi engine đang chạy thì rule mới có hiệu lực; gói đã nằm trong queue vẫn được xử lý vì `RuleReloader` chạy ngay trên worker thread, giữa hai gói (#21). Gói **mới** vẫn có thể bị drop nếu queue đầy trong lúc nạp lại; mục 9 đo điều này trên traffic thật.
  - 67 rule đang bật cho kết quả y như cũ: `tests/lab/` xanh.

## 3. Phạm vi

- **Trong phạm vi**: parser header, biến, so khớp cổng và IP trong `detector`, hướng `<>`, nguồn `HTTP_PORTS` cho `decoder` và `stream`, test #21, tài liệu.
- **Ngoài phạm vi**:
  - `flow:established` theo bắt tay thật (#19) và kiểm tra `to_server`/`from_server`.
  - Bật `vendor/community.rules` hay sửa nội dung rule.
  - Nạp lại `settings.yaml` khi đang chạy: đổi biến cần khởi động lại cả engine lẫn API, vì API dùng biến để kiểm tra `custom.rules`.
  - Sửa cơ chế của `RuleReloader`: khi một dòng rule sai, rule đó bị bỏ và các rule khác vẫn chạy, giữ nguyên hành vi hiện tại.
  - Giao diện sửa biến trên web.

## 4. Hiện trạng

- `RuleManager.parse_rule_line` (`nids/engine/rule_manager.py:287`) tách header thành 7 token và giữ nguyên chuỗi (`rule_manager.py:302`). Lỗi `ValueError` được `_parse_file` (`rule_manager.py:120-126`) log `WARNING` và bỏ rule, `validate_custom` (`rule_manager.py:250`) trả về theo dòng cho trang Rules. Dùng lại đường báo lỗi này.
- `SnortRule` (`nids/engine/rule.py:45`) có `src_ip`, `src_port`, `direction`, `dst_ip`, `dst_port` dạng chuỗi.
- `DetectionEngine.evaluate_packet` kiểm tra cổng ở `detector.py:168-171`; `direction` chưa từng được đọc.
- `decoder.HTTP_PORTS` được dùng ở `decoder.py:113-114`, `nids/engine/stream.py:16,247,267`, `tests/engine/test_stream.py:13,33` đều qua toán tử `in`.
- `RuleManager(...)` được tạo ở `nids/engine/main.py:240`, `nids/api/routes/rules.py:43` và nhiều test, phần lớn không truyền thêm tham số.
- `nids/config.py` đã có mẫu `get_redis_settings()` để đọc mục cấu hình.
- Số liệu thực tế:
  - 67 rule đang bật: IP đều `any any`; cổng đều là `any`, số, hoặc `$HTTP_PORTS`.
  - `vendor/community.rules` (đang tắt, mọi dòng kể cả bị comment là 4.013 rule): 13 biến khác nhau, 107 cổng dạng danh sách, 62 dải, 2 phủ định, 11 rule hướng `<>`, 5 IP cố định.

## 5. Các phương án đã cân nhắc

| Phương án | Ưu điểm | Nhược điểm | Kết luận |
| :-------- | :------ | :--------- | :------- |
| Biên dịch header thành đối tượng matcher lúc parse | Lỗi lộ ngay lúc nạp; so khớp nhanh; `any` đi đường tắt | Thêm một module và field trong `SnortRule` | Chọn: đúng yêu cầu "cảnh báo lúc nạp" của #17 |
| Giữ chuỗi, parse lại trong `_match_port` mỗi gói | Sửa ít code | Chậm trên đường nóng, lỗi vẫn chỉ lộ lúc chạy | Loại, không đạt #17 |
| Chỉ hỗ trợ biến cho `HTTP_PORTS`, `HOME_NET`, `EXTERNAL_NET` | Gọn hơn | 318+954+... rule vendor dùng biến khác sẽ bị bỏ khi bật category | Loại: khai báo đủ 13 biến với giá trị mặc định chuẩn của Snort |

## 6. Thiết kế đã chọn

```
settings.yaml (detection.variables) + DEFAULT_RULE_VARIABLES
        -> get_rule_variables()
        -> parse_ports() / parse_addrs()   lúc nạp rule, lỗi => ValueError => WARNING
        -> SnortRule.src_ports / dst_ports / src_addrs / dst_addrs
        -> DetectionEngine._match_header() mỗi gói
```

Module mới `nids/engine/rule_header.py`, thuần, không biết `SETTINGS`:

- `PortSpec`, `AddrSpec`: có `matches(value)` và `__contains__`, nên `dst_port in HTTP_PORTS` ở `decoder` và `stream` chạy nguyên trạng.
- `parse_ports(text, variables)`, `parse_addrs(text, variables)` dùng chung một bộ tách danh sách.

| Dạng | Cổng | IP |
| :--- | :--- | :- |
| Tất cả | `any` | `any` |
| Đơn | `80` | `10.0.0.1` |
| Dải / mạng | `1:1024`, `:1024`, `1024:` | `10.0.0.0/8` |
| Danh sách, lồng nhau | `[80,443,8000:8080]`, `[$HTTP_PORTS,8443]` | `[10.0.0.0/8,192.168.1.1]` |
| Phủ định | `!80`, `![80,443]` | `!10.0.0.1`, `![10.0.0.0/8,1.1.1.1]` |
| Biến | `$HTTP_PORTS` | `$HOME_NET`, `!$HOME_NET` (khi `HOME_NET` khác `any`) |

Ngữ nghĩa danh sách theo Snort: khớp khi nằm trong phần dương (không có phần dương thì coi như tất cả) và không nằm trong phần âm. Phủ định cả danh sách đảo từng phần tử; hai lần phủ định triệt tiêu. IP có host bit như `192.168.1.1/24` được chấp nhận (`ip_network(strict=False)`).

Báo lỗi (`ValueError`, rule bị bỏ kèm `WARNING rules`):

- Biến chưa khai báo, biến tham chiếu vòng.
- Thiếu `]`, danh sách rỗng, cổng ngoài 0–65535, dải ngược (`5:1`), IP sai.
- `!any`: khớp không gì cả, chắc chắn là viết nhầm. Áp dụng cả khi `!any` sinh ra từ biến: với `HOME_NET` mặc định `any`, rule `!$HOME_NET` bị bỏ và thông báo lỗi nêu tên biến. Vì vậy `EXTERNAL_NET` mặc định là `any`, không phải `!$HOME_NET`; comment file mẫu dặn đặt `HOME_NET` cụ thể trước.
- Hướng khác `->` và `<>`.

Quyết định chính:

- **`matches()` không bao giờ ném lỗi:** nó chạy trong worker thread duy nhất, và `evaluate_packet` nằm ngoài `try` của worker. IP của gói rỗng hoặc không hợp lệ thì chỉ spec `any` khớp, kể cả với spec phủ định.

- **Cổng `None` (ICMP):** chỉ `any` khớp, kể cả với `!80`. Giữ đúng hành vi hiện tại của `_match_port`.
- **Hướng `<>`:** khớp theo chiều xuôi hoặc chiều ngược. Trước đây bị bỏ qua, phải làm vì IP nay có tác dụng.
- **Đường nóng:** kiểm tra cổng trước IP; spec `any` trả `True` ngay, không parse IP. IP của gói qua `ipaddress` có `lru_cache(maxsize=4096)`; giới hạn hữu hạn vì IP nguồn do attacker kiểm soát.
- **Cổng 443:** bỏ khỏi danh sách chung. `HTTP_PORTS` mặc định là `[80,8080,8000,3000,5000]`, khớp tài liệu và rule hiện có. HTTP chạy trên 443 là TLS nên `HTTPParser` vốn không parse được.
- **Bảng biến mặc định** trong `nids/config.py`, để `settings.yaml` local cũ vẫn chạy: `HOME_NET`, `EXTERNAL_NET` = `any`; `HTTP_SERVERS`, `SQL_SERVERS`, `SMTP_SERVERS`, `TELNET_SERVERS`, `SIP_SERVERS` = `$HOME_NET`; `HTTP_PORTS`; `ORACLE_PORTS` = `1521`; `SIP_PORTS` = `[5060,5061]`; `SSH_PORTS` = `22`; `FTP_PORTS` = `21`; `FILE_DATA_PORTS` = `[$HTTP_PORTS,110,143]`.
- **`settings.yaml` viết list YAML** (`HTTP_PORTS: [80, 8080]`) cũng được nhận: `get_rule_variables()` nối các phần tử bằng dấu phẩy, không dùng `str(list)` để tránh dấu nháy. File mẫu quote mọi giá trị, vì `!$HOME_NET` không quote là YAML tag và `22:25` không quote có thể thành số.
- **Cấu hình sai không được làm sập engine:** làm fail-fast lúc import sẽ ra traceback trước `setup_logging`, và `restart: unless-stopped` của Docker biến nó thành vòng khởi động lại. Thay vào đó, hàm `http_ports(variables)` trong `rule_header.py` bắt lỗi, ghi `logger.error` và dùng giá trị mặc định cho `decoder`; rule dùng biến sai bị bỏ kèm `WARNING rules`.

Field mới của `SnortRule` dùng `default_factory` trả về spec `any`, để `SnortRule` dựng tay vẫn hoạt động. `PortSpec` và `AddrSpec` là dataclass `frozen=True`.

## 7. Thay đổi cần làm

| File | Thay đổi | Dùng lại |
| :--- | :------- | :------- |
| `nids/engine/rule_header.py` (mới) | `PortSpec`, `AddrSpec`, `parse_ports`, `parse_addrs`, tách danh sách và mở rộng biến | `ipaddress` chuẩn |
| `nids/config.py` | `DEFAULT_RULE_VARIABLES`, `get_rule_variables()` | Mẫu của `get_redis_settings` |
| `nids/engine/rule.py` | Thêm `src_ports`, `dst_ports`, `src_addrs`, `dst_addrs`; giữ chuỗi gốc | |
| `nids/engine/rule_manager.py` | `RuleManager(rules_dir, variables=None)`; `parse_rule_line` biên dịch header, kiểm tra hướng | Đường lỗi của `_parse_file`, `validate_custom` |
| `nids/engine/detector.py` | Thay `_match_port` bằng `_match_header`, xử lý `<>` | |
| `nids/engine/decoder.py` | `HTTP_PORTS = http_ports(get_rule_variables())` | |
| `config/settings.example.yaml` | Thêm `detection.variables`, quote mọi giá trị, comment về khởi động lại và `!$HOME_NET` | |
| `nids/engine/stream.py`, `nids/api/routes/rules.py`, `nids/engine/main.py` | Không cần sửa, kiểm chứng bằng test | |

Tài liệu cần cập nhật:

- `CLAUDE.md`: bỏ gotcha "Biến trong rule được hard-code".
- `.claude/rules/engine.md`: thay mục "Biến hard-code".
- `.claude/rules/snort-rules.md`: bảng header, mục `$HTTP_PORTS`, bỏ đoạn "Engine chưa hỗ trợ danh sách cổng".
- `.claude/rules/config-db-docker.md`: thêm `detection.variables` vào mục Cấu hình.
- `.claude/commands/them-rule.md`: dòng 26 (đang dặn dừng lại khi cần danh sách, dải, phủ định cổng) và dòng 59–60 (IP, `HTTP_PORTS`).
- `docs/demo/kich-ban-demo.md`: dòng 119 đang nói chưa so khớp IP và dải cổng.

Ba file `docs/` chưa track (`kien-truc-va-lo-trinh.md`, `doc-hieu-code-python.md`, `nen-tang-mang-va-nids.md`) không thuộc PR này, nhưng sẽ có đoạn lỗi thời.

## 8. Kiểm thử

| Test | Kiểm tra điều gì |
| :--- | :--------------- |
| `tests/engine/test_rule_header.py` | Đúng và sai cho từng dạng cổng và IP; dải hở; danh sách lồng; phần âm trong danh sách; hai lần phủ định; IPv6; host bit `192.168.1.1/24`; cổng `None` |
| `tests/engine/test_rule_header.py` (đường lỗi) | `[80`, `[]`, `99999`, `5:1`, `10.0.0.300`, `!any`, `$NOPE`, biến vòng: `ValueError`. `!$HOME_NET` với mặc định: lỗi nêu tên biến; với `HOME_NET` cụ thể: hợp lệ |
| `tests/engine/test_rule_header.py` (IP lỗi của gói) | `matches("")` và `matches("abc")` không ném lỗi: `any` trả `True`, spec dương và spec phủ định đều trả `False` |
| `tests/engine/test_rule_header.py` (cấu hình sai) | `http_ports` với giá trị sai ghi `logger.error`, trả mặc định, không ném lỗi |
| `tests/engine/test_rule_parser.py` | Hướng sai như `<-` là lỗi |
| `tests/engine/test_rule_loading.py` | Rule sai sinh `WARNING rules`, bị bỏ, rule khác vẫn nạp; rule sai **không** khớp mọi gói |
| `tests/engine/test_rule_categories.py` | `validate_custom` trả lỗi theo dòng cho header sai |
| `tests/engine/test_diverse_rules_engine.py` | Rule thật qua `DetectionEngine`: cổng, IP, `$HOME_NET`, `<>` hai chiều; `ip` protocol; ICMP không cổng |
| `tests/engine/test_rule_header.py` (vendor) | Mọi header trong `rules/vendor/community.rules` parse được, kể cả dòng bị comment |
| `tests/test_config.py` | `get_rule_variables()` gộp mặc định, ghi đè, list YAML không dính dấu nháy, thiếu mục `detection` |
| `tests/engine/test_rule_header.py` (#20) | Đổi `HTTP_PORTS` thành có `9090`: rule `$HTTP_PORTS` bắn và decoder parse HTTP trên 9090; `decoder.HTTP_PORTS` lấy từ cấu hình; 443 không còn parse |
| `tests/engine/test_main_output.py` (#21) | Thêm file `.rules`: rule mới có hiệu lực qua `RuleReloader`, gói trong `queue.Queue` còn nguyên sau `check()`. Sửa một dòng thành sai: rule đó bị bỏ, rule khác còn. File không đọc được (không phải UTF-8): `engine.rules_by_proto` giữ nguyên, `check()` trả `False` |

Lệnh: `pytest`

`tests/lab/` chứng minh 67 rule và đòn demo không đổi kết quả.

## 9. Xác minh end-to-end

1. `pytest` toàn bộ. Nếu `tests/api/test_realtime_ws.py` fail, chạy lại file đó trên `main` sạch để đối chiếu và ghi kết quả vào PR, không tự loại test. Khi kiểm thử #16, file này đã fail 3/3 lần trên `origin/main` sạch với Python 3.14 local, CI vẫn xanh.
2. Docker lab, mật khẩu ngẫu nhiên trong scratchpad qua `--env-file`, không tạo `.env` trong repo. Điều kiện: `rules/state.yaml` chưa có `enabled_categories`, nếu không category mới sẽ không được bật. Container attacker chỉ có `python3`.
   - `attack_demo.py web` cho cùng tập SID như trước.
   - Khi engine đang chạy và attacker gửi traffic liên tục, tạo `rules/lab-check.rules` (xoá sau khi thử) với rule SID `≥ 2000000` dùng `172.28.0.100`, `!172.28.0.100`, `[8080,9000:9100]`: rule có hiệu lực không cần khởi động lại, đúng IP thì bắn, sai IP thì không, log không có `Queue đầy`.
   - Thêm rule sai header vào file đó: log engine có `WARNING rules`, engine không dừng, không rule nào khớp bừa.
3. Đổi cấu hình thật (#20): tạo `config/settings.yaml` tạm từ file mẫu, thêm `9090` vào `HTTP_PORTS`, khởi động lại `nids_engine` và `nids_api`. Từ attacker gửi gói PSH+ACK chứa `GET /?q=union+select+1` tới `172.28.0.50:9090` bằng Scapy (không cần service nghe cổng này): sinh SID 1000001. Xoá file tạm sau khi thử.
4. Cấu hình sai: đặt `HTTP_PORTS: "[80"`, khởi động lại engine: log có lỗi rõ ràng, engine vẫn chạy, không rơi vào vòng khởi động lại.
5. Hiệu năng: một script tạm (không commit) chạy `PacketDecoder.decode` + `evaluate_with_stream` với 3.000 request một gói và 50 upload 45 đoạn 1.400 byte, trên 67 rule đang bật. Chạy 5 lần trên `main` và 5 lần trên nhánh, so trung vị gói/giây. Chênh lệch không quá 5%.

## 10. Rủi ro và ảnh hưởng tới nhóm

| Rủi ro | Mức độ | Cách xử lý |
| :----- | :----- | :--------- |
| Rule cũ trong `custom.rules` có header lạ trước đây khớp tất cả, nay bị bỏ | Vừa | Có `WARNING rules` và lỗi theo dòng trên trang Rules; đây chính là mục tiêu của #17 |
| Bỏ 443 làm mất so khớp `http_*` trên HTTP thuần ở cổng 443 | Thấp | Khai báo lại trong `detection.variables.HTTP_PORTS`; ghi trong tài liệu |
| Parser chặt hơn làm rớt rule vendor khi bật category | Vừa | Khai báo đủ 13 biến, có test parse toàn bộ header vendor |
| Sửa `detection.variables` nhưng quên khởi động lại, hoặc chỉ khởi động lại engine nên web vẫn từ chối rule dùng biến mới | Thấp | Ghi rõ "khởi động lại engine và API" trong comment file mẫu và `engine.md` |
| `$HOME_NET` đổi khỏi `any` làm các rule dùng biến này đổi hành vi | Thấp | 67 rule đang bật đều dùng `any`, chỉ ảnh hưởng vendor |
| `HTTP_PORTS` cấu hình sai: 35 rule `$HTTP_PORTS` bị bỏ | Vừa | Có `logger.error` và `WARNING rules`, engine vẫn chạy với các rule còn lại |
| Reload chạy trên worker thread nên gói mới có thể bị drop khi queue đầy | Thấp | Hành vi có sẵn; bộ rule nhỏ nên nạp nhanh; quan sát ở mục 9 |
| Thêm chi phí trên đường nóng | Thấp | `any` đi đường tắt, có `lru_cache`, đo ở mục 9 |

**Thành viên khác cần làm gì**: Không bắt buộc. `settings.yaml` cũ vẫn chạy nhờ giá trị mặc định. Không đổi CSDL, không cần build lại image vì không thêm dependency.

## 11. Các bước thực hiện

Nhánh: `feature/20-rule-header-matching`, tách từ `main` mới nhất. #16 đã merge (PR #58); phải `git switch main` và `git pull` trước, vì local đang ở nhánh `feature/16-tcp-reassembly`.

- [x] Chép plan sang `docs/plans/`, thêm vào bảng tổng hợp, chuyển `IN_PROGRESS`
- [x] #17, #18: `rule_header.py` kèm test đơn vị, gồm đường lỗi
- [x] #20: `get_rule_variables`, mục `detection.variables`, nối vào `RuleManager` và `decoder`
- [x] Nối `SnortRule` và `detector`, xử lý `<>`, xoá `_match_port`
- [x] Test parse toàn bộ header vendor, test tích hợp với `DetectionEngine`
- [x] #21: bổ sung test nạp lại rule
- [x] Cập nhật tài liệu ở mục 7
- [x] Chạy `pytest`, xác minh theo mục 9
- [ ] Tạo PR với `Closes #17`, `Closes #18`, `Closes #20`, `Closes #21`, cập nhật bảng tổng hợp

**Kết quả xác minh (2026-11-01)**: `pytest` 415 passed, 1 failed (`test_realtime_ws.py`, chập chờn có sẵn trên main). Docker lab: `attack_demo.py web` cho 24 SID khác nhau, không lỗi engine; rule IP/CIDR/phủ định/danh sách cổng nạp khi engine đang chạy và bắn đúng; header sai bị bỏ kèm `WARNING rules`; thêm `9090` vào `detection.variables` thì SID 1000001 bắn ở cổng 9090; `HTTP_PORTS` sai thì engine và API vẫn chạy với 32 rule. Hiệu năng (xen kẽ 5 vòng): −1,1% và +12,9% so với `main`, nằm trong nhiễu.

## 12. Quyết định và nhật ký

**Quyết định**

| Ngày | Quyết định | Người chốt | Lý do |
| :--- | :--------- | :--------- | :---- |
| 2026-11-01 | Chia 10 issue thành 3 PR: Rule, Web, Anomaly + lab; #19 làm sau | Người dùng | Giảm số PR mà mỗi PR vẫn một chủ đề |
| 2026-11-01 | Làm nhóm Rule trước | Người dùng | Độc lập, ít rủi ro |
| 2026-11-01 | Bỏ 443 khỏi `HTTP_PORTS` chung | Claude | Khớp tài liệu và rule; TLS vốn không parse được |
| 2026-11-01 | Header sai làm rule bị bỏ, không khớp tất cả | Claude | Yêu cầu của #17 |
| 2026-11-01 | `!any` là lỗi | Claude | Rule không bao giờ khớp, gần như chắc chắn viết nhầm |
| 2026-11-01 | Hỗ trợ `<>` | Claude | IP có tác dụng thì 11 rule vendor dùng `<>` sẽ sai nếu bỏ qua |
| 2026-11-01 | `ORACLE_PORTS` mặc định `1521` thay vì `1024:` của Snort | Claude | Ít báo nhầm hơn; rule vendor đang tắt |
| 2026-11-01 | Đổi biến cần khởi động lại engine và API | Claude | `SETTINGS` chỉ nạp một lần lúc import ở cả hai process |
| 2026-11-01 | `!any` sinh ra từ biến cũng là lỗi, thông báo nêu tên biến | Claude | Rule không bao giờ khớp thì nên báo, không im lặng |
| 2026-11-01 | `HTTP_PORTS` sai: log lỗi, dùng mặc định cho decoder, không dừng engine | Claude | Tránh traceback trước `setup_logging` và vòng restart của Docker |
| 2026-11-01 | IP gói không hợp lệ chỉ khớp `any` | Claude | `matches()` chạy trên worker thread duy nhất, không được ném lỗi |
| 2026-11-01 | Tối ưu đường nóng bằng bảng bit cổng và cờ `header_any` | Claude | Lần đo đầu chậm 24% so với `main`, vượt ngân sách 5% |
| 2026-11-01 | Commit viết tiếng Việt, giữ tiền tố Conventional Commits | Người dùng | Yêu cầu của người dùng trong phiên này, khác với `git-workflow.md` |

**Câu hỏi còn mở**: Không

**Kết quả phản biện**: `plan-critic` kết luận `PASS_WITH_WARNINGS`, không có `BLOCKER`. Đã sửa 8/9 `WARNING` trong plan. `WARNING` còn lại là "#16 chưa có trên main": không phải lỗi, vì critic đọc ref local cũ; `gh pr view 58` cho thấy đã `MERGED` và `main` chỉ hơn nhánh local đúng merge commit, không khác file nào. `NOTE` về `state.yaml`, `strict=False`, YAML, `frozen`, hướng sai đã đưa vào plan. `NOTE` về test chập chờn: mục 9 đổi sang đối chiếu trên `main` thay vì tự loại.
