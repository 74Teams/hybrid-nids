---
type: PLAN
plan_id: PLAN-007
title: Honeypot HTTP ghi mọi request (catch-all)
status: IN_PROGRESS
issue: 26
owner: Vo Ngoc Cu (ngoccu2006)
created: 2026-11-09
updated: 2026-11-10
---

# PLAN-007: Honeypot HTTP ghi mọi request (catch-all)

## 1. Bối cảnh

Honeypot HTTP chỉ ghi sự kiện cho `POST /wp-admin-login`. Mọi request dò quét khác (`GET /.env`, `/phpmyadmin/`, `/wp-login.php`, `HEAD`, `PUT`...) nhận 404 hoặc 405 của Flask và không để lại dấu vết nào, nên mất đúng loại dữ liệu mà honeypot sinh ra để thu thập. Yêu cầu đến từ issue #26 (người mở: `nmchien1106`; **chưa biết ai được assign vì máy không có `gh`**, cần xác nhận trước khi duyệt).

## 2. Mục tiêu và tiêu chí thành công

- **Mục tiêu**: Mọi request vào cổng 8080, bất kể method hay đường dẫn, đều sinh một sự kiện có method, URI, header và body, hiện ở tab Honeypot HTTP của trang Logs.
- **Xong khi**:
  - `curl http://172.28.0.50:8080/bat-ky-duong-dan` (và `-X PUT`, `-X DELETE`, `-X OPTIONS`...) sinh sự kiện `http.request` với đúng `http_method`, `http_uri`.
  - Mở sự kiện trên `/logs` thấy HTTP headers và HTTP body ở phần payload.
  - `POST /wp-admin-login` vẫn sinh đúng một sự kiện `http.login` (không bị ghi đôi), nay kèm header và body.
  - Phản hồi cho client không đổi so với hiện tại (trang login ở `/`, 404 ở đường dẫn lạ).
  - Header, body, method hoặc URI rất dài không làm lỗi ghi DB (kể cả MySQL strict); lỗi DB vẫn không làm sập sensor.
  - Body không bao giờ bị nạp vào RAM quá `MAX_CONTENT_LENGTH`, kể cả khi request dùng chunked.
  - `GET /` (trang login giả) cũng được ghi là `http.request`: honeypot HTTP không có người dùng hợp lệ nên mọi request đều đáng ghi.
  - `pytest` xanh.

## 3. Phạm vi

- **Trong phạm vi**: ghi mọi request (kể cả 404/405) với method, URI, header, body; truyền header/body xuống `event_payloads`; loại sự kiện `http.request`; nhãn tiếng Việt trên trang Logs; test; cập nhật tài liệu.
- **Ngoài phạm vi**:
  - Phản hồi giả giàu hơn (trả `/.env`, `phpinfo`, trang quản trị khác): vẫn chỉ trang login và 404.
  - Gắn `attack_tag` (SQLi/LFI/scanner...) cho request catch-all.
  - Che (redact) giá trị header hoặc body: honeypot chỉ ghi dữ liệu attacker tự gửi.
  - Dọn sự kiện cũ, giới hạn tốc độ ghi DB (xem rủi ro mục 10).
  - Giới hạn tài nguyên/waitress (PLAN-006, #27).

## 4. Hiện trạng

- [nids/honeypot/web_honeypot.py](../../nids/honeypot/web_honeypot.py): chỉ có route `/` (GET) và `/wp-admin-login` (POST); `before_request` cấp `g.session_id`, `after_request` đặt cookie. Request tới route/method không có thì Flask trả 404/405 mà không gọi `log_event`.
- [nids/honeypot/store.py](../../nids/honeypot/store.py): `log_event` đã nhận `http_method`, `http_uri`, `user_agent`, `session_id` nhưng **chưa có tham số header và body**; `SEVERITY` chỉ có `http.login` và `http.login.sqli`.
- [nids/db/repository.py](../../nids/db/repository.py): `save_alert` chỉ tạo `EventPayloadModel(matched_content=...)`, bỏ qua `http_headers`, `http_body`.
- [nids/db/models.py](../../nids/db/models.py): bảng `event_payloads` **đã có** cột `http_headers`, `http_body` (kiểu `Text`) nên không cần đổi schema hay migration.
- API: `EventRepository.get_payload` và `GET /api/alerts/{id}` đã trả `http_headers`, `http_body`; trang Logs (`logs.html`, hàm hiển thị payload) đã vẽ hai mục này. Tab "Honeypot HTTP" đã lọc `source_type=HONEYPOT&protocol=http`, nên sự kiện mới tự hiện, chỉ thiếu nhãn tiếng Việt cho `http.request` trong bảng nhãn (dòng ~98).
- Nhánh `feature/27-honeypot-resource-limits` (PR chưa merge) cũng sửa `web_honeypot.py` (waitress, `MAX_CONTENT_LENGTH`, 413) và `store.py` (cắt độ dài trường). Plan này xuất phát từ `main`, sẽ phải rebase sau khi #27 merge.

## 5. Các phương án đã cân nhắc

| Phương án | Ưu điểm | Nhược điểm | Kết luận |
| :-------- | :------ | :--------- | :------- |
| Hook `after_request` ghi mọi request chưa được route ghi (cờ `g.logged`) | Bắt cả 404/405/lỗi do Flask sinh; không đổi route hiện có; một chỗ duy nhất | Không phải "route" theo đúng chữ của issue | Chọn (Claude đề xuất) |
| Route catch-all `/<path:path>` với mọi method | Đúng chữ issue, dễ hiểu | `/wp-admin-login` bị `GET` vẫn ra 405 mà không vào catch-all; `/` chỉ GET; thiếu sót phải vá thêm | Loại |
| Cả hai (catch-all route + hook) | Phủ kín | Hai cơ chế cho một việc, dễ ghi đôi | Loại |
| Ghi header/body vào cột mới của `events` | Truy vấn nhanh | Đổi schema, cần migration; cột `event_payloads` đã sẵn | Loại |
| Gộp header/body vào `matched_content` | Không sửa repository | Trộn lẫn dữ liệu, trang Logs đã có mục riêng cho header/body | Loại |

## 6. Thiết kế đã chọn

```
request → before_request (session) → route/404/405 → after_request
              route login: log_event(http.login, headers, body); g.logged = True
              after_request: nếu chưa g.logged → log_event(http.request, headers, body)
```

- **Loại sự kiện** `http.request`, protocol `http`, severity P3 (cùng mức `ssh.auth.attempt`: dò quét thông thường), thêm vào `SEVERITY`. `msg` dạng `HONEYPOT http.request GET /.env` để trang Logs hiển thị gọn như các sự kiện khác.
- **Header**: chuỗi `Tên: giá trị` mỗi dòng, theo thứ tự attacker gửi, cắt ở `MAX_HEADERS_LEN` (8192 ký tự).
- **Body (đọc một lần, đúng thứ tự)**: `before_request` đặt `app.config["MAX_CONTENT_LENGTH"] = 65536` rồi gọi `request.get_data(cache=True)` ngay đầu request (trước mọi route). Werkzeug áp trần này cả với chunked; vượt trần thì `RequestEntityTooLarge`, hook bắt lỗi, ghi sự kiện không có body (kèm ghi chú trong `msg`) và request trả 413 như bình thường. Vì body đã được cache nên `request.form` trong `login()` vẫn parse được từ bản cache (Werkzeug dùng `_cached_data` khi parse form); **không** đọc `request.stream` trực tiếp. Sau khi giải mã `utf-8` với `errors="replace"`, body cắt ở `MAX_BODY_LEN` (8192 ký tự); body rỗng thì lưu `None`. Sau khi rebase lên #27, giá trị trần lấy từ `settings.http_max_body_bytes` thay cho hằng số này.
- **Cắt trường khác trước khi lưu** (MySQL strict báo `Data too long` và `log_event` nuốt lỗi, nên sẽ mất đúng request lạ): `http_method[:10]` (cột `String(10)`), `http_uri` tối đa 2048 ký tự, `msg` đã cắt 500.
- **`msg`**: `log_event` hiện dựng `detail = command` hoặc `username:password`; với `http.request` không có hai trường đó sẽ ra `None:None`. Sửa: khi `username`, `password`, `command` đều None và có `http_method` thì `detail = "<method> <uri>"`.
- **Dữ liệu tới DB**: `log_event` nhận thêm `http_headers`, `http_body`; `save_alert` tạo `EventPayloadModel` khi có bất kỳ trường payload nào (không chỉ `matched_content`). Với `http.request`, `matched_content` chứa `user_agent=...` như `http.login`.
- **Luồng `http.login`**: giữ nguyên route, bổ sung truyền header/body và đặt `g.logged = True`, nên không ghi đôi.
- **Không đổi phản hồi**: hook chỉ đọc request, không sửa response. Honeypot vẫn không thực thi hay phản hồi nội dung attacker.
- **Hook ghi sự kiện**: đăng ký riêng, bọc `try/except` và luôn trả `response`; dùng `g.get("logged")` (không giả định `before_request` đã chạy). Flask chạy `after_request` theo thứ tự ngược đăng ký; hai hook không phụ thuộc nhau. Cờ `g.logged = True` đặt ngay sau lời gọi `log_event` của `login()` (`log_event` nuốt lỗi nên không raise). Nếu `login()` thoát sớm trước `log_event` (multipart hỏng, 413) thì hook ghi một `http.request`: là hành vi mong muốn, request lỗi vẫn được ghi đúng một lần.
- **Tác động tới phần khác**: engine và API dùng tập IP có sự kiện `HONEYPOT` để gắn `[honeypot-confirmed]` và đếm `honeypot_events`. Ghi mọi request mở rộng tập này; chấp nhận vì honeypot HTTP không có người dùng hợp lệ (xem mục 10).
- **An toàn**: honeypot không thực thi hay phản hồi nội dung attacker; lỗi DB không làm sập sensor.
- **Giao diện**: chỉ thêm nhãn `"http.request": "Request web"` vào bảng nhãn của `logs.html`. Không đổi API.
- `network.bpf_filter` và Docker không đổi.

## 7. Thay đổi cần làm

| File | Thay đổi | Dùng lại |
| :--- | :------- | :------- |
| `nids/honeypot/web_honeypot.py` | Hook `after_request` ghi `http.request`; cờ `g.logged`; helper dựng header/body; `login()` truyền header/body | `log_event`, `g.session_id` |
| `nids/honeypot/store.py` | Tham số `http_headers`, `http_body`; `SEVERITY["http.request"] = 3`; `detail` cho `msg` khi không có username/password/command; cắt `http_method`/`http_uri` | `log_event` hiện có |
| `nids/db/repository.py` | `save_alert` tạo payload khi có ít nhất một trong `matched_content`, `http_headers`, `http_body` khác rỗng | `EventPayloadModel` |
| `nids/api/static/logs.html` | Thêm nhãn `http.request` | Bảng nhãn có sẵn |
| `tests/honeypot/test_honeypot.py` | Test catch-all (xem mục 8); sửa `web_login` và các test cookie (~dòng 296-317) vì `GET /` nay cũng sinh sự kiện: lọc theo `attack_type == "http.login"` thay vì lấy sự kiện mới nhất | Test client Flask, fixture DB bộ nhớ |
| `.claude/rules/honeypot.md` (dòng "Chưa làm"), `CLAUDE.md` (Current Focus), `README.md`, `docs/demo/kich-ban-demo.md` | Bỏ "route catch-all" khỏi "Chưa làm"; ghi loại sự kiện `http.request` (grep trước, chỉ sửa nơi có nhắc) | |

Không thêm dependency, bảng hay cột CSDL.

## 8. Kiểm thử

| Test | Kiểm tra điều gì |
| :--- | :--------------- |
| GET đường dẫn lạ | 404 không đổi, có đúng 1 sự kiện `http.request`, đúng method/URI/session |
| Nhiều method (PUT, DELETE, OPTIONS, PATCH) | Mỗi method sinh 1 sự kiện; `HEAD` cũng ghi |
| `GET /wp-admin-login` | 405 vẫn được ghi (route chỉ cho POST) |
| `POST /wp-admin-login` | Đúng 1 sự kiện `http.login`, không có `http.request` kèm theo; payload có header/body |
| Payload | `http_headers` chứa header attacker gửi; `http_body` đúng nội dung; body rỗng thì không có `http_body` |
| Cắt độ dài | Header/body lớn hơn trần bị cắt đúng; method > 10 ký tự bị cắt về 10; URI > 2048 bị cắt; không raise |
| Body vượt `MAX_CONTENT_LENGTH` (kể cả chunked) | Trả 413, vẫn có 1 sự kiện không body, RAM không nạp quá trần |
| `POST /wp-admin-login` đọc form sau khi cache body | `username`/`password` trong DB đúng, `http_body` có nội dung, tag `sqli` vẫn đúng |
| `POST /wp-admin-login` multipart hỏng | Đúng 1 sự kiện (`http.request`), không ghi đôi |
| `HEAD /`, `OPTIONS /`, `GET /` | Mỗi request 1 sự kiện; `summary` dạng `HONEYPOT http.request GET /` (không có `None:None`) |
| Test hiện có | `web_login` và các test cookie vẫn pass sau khi lọc theo `http.login` |
| Body không phải UTF-8 | Ghi được (thay ký tự lỗi), không raise |
| Lỗi DB | `save_alert` raise thì phản hồi cho client vẫn bình thường (mở rộng test `log_event` không raise) |
| `save_alert` | Tạo payload khi chỉ có header/body; vẫn tạo khi chỉ có `matched_content`; không tạo khi không có gì hoặc chỉ có chuỗi rỗng |

Lệnh: `pytest tests/honeypot tests/api`, sau đó `pytest` toàn bộ.

## 9. Xác minh end-to-end

Chạy từ gốc repo, trong Docker lab (`docker compose up --build -d`, không dùng `down`).

1. `docker compose restart honeypot_http` (code mount `.:/app`), kiểm tra `docker logs nids_honeypot_http --tail 5`.
2. Từ attacker, gửi nhiều kiểu request:
   `docker exec nids_attacker sh -c "curl -s -o /dev/null -w '%{http_code}\n' http://172.28.0.50:8080/.env; curl -s -o /dev/null -w '%{http_code}\n' -X PUT -d 'a=1' -H 'X-Test: abc' http://172.28.0.50:8080/admin/upload; curl -s -o /dev/null -w '%{http_code}\n' http://172.28.0.50:8080/wp-admin-login"`
   Kỳ vọng mã trả về `404`, `404`, `405` (không đổi so với trước khi sửa).
3. Gửi một đăng nhập: `docker exec nids_attacker curl -s -d "username=a&password=b" http://172.28.0.50:8080/wp-admin-login`.
4. Mở `http://localhost:8000/logs#http`: có 3 sự kiện `http.request` (PUT có `X-Test: abc` và body `a=1` ở phần payload) và 1 `http.login`; đăng nhập không bị ghi đôi.
5. `docker exec nids_attacker python3 lab/attacker/attack_demo.py` hoặc kịch bản demo hiện có: các sự kiện cũ vẫn ra đủ.

## 10. Rủi ro và ảnh hưởng tới nhóm

| Rủi ro | Mức độ | Cách xử lý |
| :----- | :----- | :--------- |
| Quét hàng loạt sinh rất nhiều dòng `events` (mỗi request một dòng), phình DB | Vừa | Cắt header/body; ghi rõ ngoài phạm vi; để giới hạn tốc độ/dọn dữ liệu cho issue riêng |
| Body lớn nạp hết vào RAM | Vừa | Đọc tối đa `MAX_BODY_LEN` từ stream; PLAN-006 bổ sung trần ở tầng server |
| Xung đột với PR #27 ở `web_honeypot.py` và `store.py` | Vừa | Nhánh xuất phát từ `main`; rebase sau khi #27 merge, hợp nhất phần cắt độ dài trường |
| Trang Logs ồn vì quét dò chiếm hết tab | Thấp | Severity P3; tab đã lọc theo protocol |
| Cookie/header nhạy cảm của attacker được lưu | Thấp | Chấp nhận: đó là dữ liệu của kẻ tấn công trên hệ thống mồi |
| Mọi request thành sự kiện `HONEYPOT` nên mở rộng tập IP "đã chạm honeypot" (engine gắn `[honeypot-confirmed]`, API đếm `honeypot_events`); một scanner quét rộng cũng bị gắn nhãn | Thấp | Chấp nhận: honeypot HTTP không có người dùng hợp lệ, kẻ chạm vào đều đáng ngờ |
| Method dài hoặc URI khổng lồ làm MySQL strict từ chối ghi, mất sự kiện | Vừa | Cắt method và URI trước khi lưu; có test |
| Chính engine cũng sniff cổng 8080 và có thể báo cảnh báo cho cùng request | Thấp | Là hai nguồn khác nhau (`RULE_ENGINE` và `HONEYPOT`), đúng thiết kế |

**Thành viên khác cần làm gì**: Không cần sửa `.env`, không cần build lại. Sau khi pull, `docker compose restart honeypot_http` (không `down` vì MySQL dùng volume ẩn danh).

## 11. Các bước thực hiện

Nhánh: `feature/26-http-catch-all`

- [ ] Xác nhận issue #26 được assign cho ai (chưa xác nhận được, máy không có `gh`)
- [x] `store.py` + `repository.py`: header/body xuống payload, test `save_alert`
- [x] `web_honeypot.py`: hook ghi `http.request`, cờ `g.logged`, `login()` truyền header/body, test
- [x] Nhãn `http.request` trong `logs.html`
- [x] Cập nhật tài liệu ở mục 7
- [ ] Chạy `pytest`, xác minh theo mục 9
- [x] Rebase lên `main` sau khi #27 merge, chạy lại test
- [ ] Tạo PR (tiêu đề tiếng Anh, mô tả tiếng Việt, `Closes #26`), cập nhật bảng tổng hợp

## 12. Quyết định và nhật ký

**Quyết định**

| Ngày | Quyết định | Người chốt | Lý do |
| :--- | :--------- | :--------- | :---- |
| 2026-11-09 | Nhánh xuất phát từ `main`, chờ #27 merge rồi rebase | Người dùng | Giữ hai nhánh độc lập |
| 2026-11-09 | Dùng hook `after_request` thay route catch-all | Claude (chờ duyệt) | Bắt được cả 404/405 sinh bởi Flask |
| 2026-11-09 | Loại sự kiện mới `http.request`, severity P3 | Claude (chờ duyệt) | Tách khỏi `http.login` (P2) |
| 2026-11-09 | Lưu header/body vào `event_payloads`, không đổi schema | Claude (chờ duyệt) | Cột đã có sẵn, UI đã hiển thị |
| 2026-11-09 | Cắt header và body ở 8192 ký tự; trần đọc body 64 KiB bằng `MAX_CONTENT_LENGTH` | Claude (chờ duyệt) | Bảo vệ RAM và DB; trần Werkzeug áp cả chunked |
| 2026-11-09 | Ghi cả `GET /` | Claude (chờ duyệt) | Honeypot không có người dùng hợp lệ |

**Nhật ký thực hiện**

- 2026-11-09: Tạo nhánh `feature/26-http-catch-all` từ `main`, soạn plan.
- 2026-11-10: Người dùng yêu cầu code trên nhánh (coi là duyệt plan). #27 đã merge nên dùng `MAX_CONTENT_LENGTH`/`settings.http_max_body_bytes` có sẵn thay vì hằng 64 KiB, và `clip()`/`MAX_FIELD_LEN` (256) cho `http_uri` thay vì 2048. Đã code và test: 54 test honeypot pass; toàn bộ `pytest` còn 3 lỗi sẵn có trên Windows (2 test engine, `test_realtime_ws` thất thường), không liên quan. Chưa chạy bước E2E mục 9 trong Docker.

**Câu hỏi còn mở**

- Issue #26 đang assign cho ai? (planning.md bước 2 yêu cầu báo trước nếu là người khác.)
- Có cần gắn `attack_tag` (ví dụ SQLi trong URI) cho `http.request` không, hay để issue sau? Plan này chọn để issue sau.
- Trần cắt 8192 ký tự có phù hợp không?

**Kết quả phản biện**: `plan-critic` vòng 1: 2 BLOCKER (cách đọc body mâu thuẫn và làm hỏng `request.form`; `msg` ra `None:None`), 5 WARNING (test hiện có bị ảnh hưởng, tập IP honeypot mở rộng, method/URI vượt cột, thứ tự hook và `g.get`, chunked/trần RAM, `g.logged`). Đã sửa ở mục 2, 6, 7, 8, 10, 12. Cần xác nhận bằng test khi cài: Werkzeug parse form từ body đã cache; OPTIONS/HEAD tự động qua hook.
