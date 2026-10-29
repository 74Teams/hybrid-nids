---
description: Thêm một rule phát hiện kiểu Snort vào file rule của nhóm (rules/<nhóm>.rules) kèm test positive/negative. Dùng khi cần phát hiện một dấu hiệu tấn công mới.
argument-hint: <mô tả tấn công cần phát hiện>
---

Yêu cầu: $ARGUMENTS

Ngữ cảnh đã nhúng sẵn (đọc kỹ trước khi làm):
- Tài liệu cú pháp, option được hỗ trợ, dải SID và giới hạn engine: @.claude/rules/snort-rules.md
- Rule hiện có theo nhóm (để chọn nhóm và SID kế tiếp): @rules/web-attack.rules @rules/scan.rules @rules/dos.rules @rules/auth.rules @rules/malware-c2.rules @rules/recon.rules

Bạn đang thêm một rule phát hiện cho dự án NIDS này. Tuân thủ đúng `.claude/rules/snort-rules.md` ở trên — nó là nguồn chân lý về cú pháp. Làm tuần tự các bước sau, không bỏ bước.

## Quy trình

1. **Đọc tài liệu.** Nắm mục "Option được hỗ trợ", "Thứ tự option chuẩn", "Sticky buffer", bảng "SID" và "Giới hạn của engine" trong `.claude/rules/snort-rules.md`.

2. **Phân loại và chọn SID.** Xếp tấn công vào đúng nhóm rồi lấy dải SID tương ứng:
   - `10000xx` WEB-ATTACK · `10001xx` SCAN · `10002xx` DOS · `10003xx` AUTH · `10004xx` MALWARE/C2 · `10005xx` RECON (UDP/ICMP).
   - **SID mới = SID lớn nhất đang dùng _trong chính nhóm đó_ + 1** (không phải max toàn cục + 1). Ví dụ nhóm WEB cao nhất là `1000030` thì SID mới là `1000031`.
   - Nếu nhóm đã hết chỗ trong dải `xx` → **DỪNG và báo**, không lấn sang dải nhóm khác.

3. **Viết rule** vào **đúng file của nhóm** (`rules/web-attack.rules`, `scan.rules`, `dos.rules`, `auth.rules`, `malware-c2.rules`, `recon.rules`), giữ SID tăng dần. Yêu cầu:
   - `rev:1`; `msg` bắt đầu bằng tiền tố nhóm (`WEB-ATTACK`/`SCAN`/`DOS`/`AUTH`/`MALWARE`/`C2`/`RECON`).
   - Theo đúng thứ tự option chuẩn: `msg; flow; [flags|itype/icode|dsize]; [buffer; content...; pcre...]; [detection_filter]; [service]; classtype; priority; sid; rev;`.
   - **Chỉ dùng option có trong bảng "Option được hỗ trợ".** Nếu dấu hiệu bắt buộc cần một option chưa hỗ trợ (`byte_test`, `isdataat`, `threshold`, `http_method:"..."`, `severity:`, `nocase;` đứng riêng, pcre flag `R`, danh sách/dải/phủ định cổng...) → **DỪNG và báo rõ option còn thiếu**, không tự chế hay xấp xỉ bằng cách sai.
   - Chọn fast pattern tốt: một `content` dài, đặc trưng. Rule TCP có content thêm `flow:to_server,established`; rule chỉ xét cờ TCP dùng `flow:stateless`. Rule `http_*` thêm `service:http;`.

4. **Thêm test** vào `tests/engine/test_diverse_rules_engine.py`, đặt trong section nhóm tương ứng, dùng helper sẵn có (`make_http_packet`, `make_tcp_packet`, `make_udp_packet`, `make_icmp_packet`) và fixture `real_engine`. Thêm **hai** hàm test:
   - Positive — gói KHỚP:
     ```python
     def test_<ten_ngan>(real_engine):
         pkt = make_http_packet(uri="/...payload khop...")
         matched = real_engine.evaluate_packet(pkt)
         assert any(r.sid == <SID_MOI> for r in matched)
     ```
   - Negative — gói GẦN GIỐNG nhưng benign (chống dương tính giả):
     ```python
     def test_<ten_ngan>_benign(real_engine):
         pkt = make_http_packet(uri="/...gan giong, hop le...")
         assert not any(r.sid == <SID_MOI> for r in real_engine.evaluate_packet(pkt))
     ```
   - Đọc **giá trị trả về** của `evaluate_packet` (list `SnortRule`, dùng `r.sid`) — không dùng alert callback.

5. **Chạy test** (có thể giao cho subagent `general-purpose`; repo **không** có subagent `test-runner`):
   ```
   pytest tests/engine/test_diverse_rules_engine.py tests/engine/test_rule_loading.py
   ```
   Và xác nhận khi nạp ruleset **không** có dòng `WARNING rules` (đặt `system.log_level: DEBUG` trong `config/settings.yaml` để xem chi tiết nếu nghi ngờ). `WARNING rules` nghĩa là lỗi cú pháp, SID trùng, hoặc có option bị bỏ qua.

6. **Báo lại** ngắn gọn: rule đã thêm (dán nguyên dòng rule), lý do chọn từng option chính (buffer, content/pcre, flow, detection_filter...), SID và nhóm, các file đã sửa, và kết quả `pytest`.

## Giới hạn engine phải nhớ khi sinh rule/test

Viết sai những điểm này thì rule/test sẽ không khớp dù cú pháp đúng:
- **Không tái hợp luồng TCP** — toàn bộ content của một rule phải nằm trong **một** gói. Dựng payload test đầy đủ trong một packet.
- `flow:established` được xấp xỉ là "gói TCP có ACK và không có SYN"; `to_server`/`from_server` **không** được kiểm tra.
- `detection_filter` đếm theo `packet.timestamp` → trong test các gói dựng sẵn phải có timestamp nằm trong cửa sổ `seconds`.
- **IP không được so khớp** (mọi IP coi như `any`); **không** hỗ trợ danh sách cổng `[80,443]`, dải `1:1024`, hay phủ định `!80` (chúng khớp mọi cổng mà không báo lỗi).
- Buffer `http_*` chỉ tồn tại khi gói tới cổng thuộc `HTTP_PORTS` (`{80,8080,8000,3000,5000,443}`); `http_uri` **chưa** URL-decode (`%3D` vẫn là `%3D`, `+` vẫn là `+`) — pcre trên URI phải tự bao cả dạng encode.
- Content trong **một** buffer khớp tham lam theo thứ tự, không quay lui — viết content theo đúng thứ tự xuất hiện trong dữ liệu; dùng `distance`/`within` cho content đứng sau.
- `flags` không có `+`/`*`/`!` nghĩa là khớp **chính xác** (cờ thừa thì không khớp).
