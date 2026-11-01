---
type: PLAN
plan_id: PLAN-002
title: Gom sự kiện honeypot theo session kết nối
status: IN_PROGRESS
issue: 24
owner: Vo Ngoc Cu (ngoccu2006)
created: 2026-11-01
updated: 2026-11-01
---

# PLAN-002: Gom sự kiện honeypot theo session kết nối

## 1. Bối cảnh

Mỗi sự kiện honeypot đang được ghi rời rạc vào bảng `events`. Không có gì cho biết một sự kiện thuộc phiên kết nối nào, nên hai phiên SSH từ cùng một IP bị trộn lẫn và người phân tích không dựng lại được chuỗi hành động của attacker. Yêu cầu đến từ issue #24. Chuỗi lệnh theo phiên cũng là phần dễ trình diễn khi demo với giảng viên.

## 2. Mục tiêu và tiêu chí thành công

- **Mục tiêu**: Mỗi kết nối SSH và mỗi phiên HTTP có session id riêng, lưu cùng sự kiện, và xem lại được cả phiên theo thứ tự thời gian.
- **Xong khi**:
  - Sau một phiên SSH có đăng nhập và nhiều lệnh, `GET /api/alerts/sessions/{session_id}` trả đủ các sự kiện đó, cũ đến mới.
  - Trên `/logs`, mở chi tiết một sự kiện SSH và bấm "Xem cả phiên" thì thấy toàn bộ chuỗi lệnh của phiên.
  - Hai phiên SSH song song từ cùng một IP có hai session id khác nhau và không trộn sự kiện.
  - Hai request HTTP gửi cùng cookie được cấp có cùng session id.
  - Lab đang chạy với CSDL cũ, sau khi restart vẫn hoạt động, dữ liệu cũ còn nguyên và sự kiện mới vẫn được ghi.

## 3. Phạm vi

- **Trong phạm vi**: cột `events.session_id` có index, tự thêm cột vào CSDL cũ trong `init_db`, session id cho SSH và HTTP, endpoint đọc sự kiện của một phiên, nút xem phiên trên trang Logs, cập nhật tài liệu.
- **Ngoài phạm vi**:
  - Bộ lọc `session_id` trên `GET/DELETE /api/alerts/`, và danh sách các phiên.
  - Bảng `sessions` riêng; thời điểm mở, đóng và thời lượng phiên.
  - Sự kiện kết nối không đăng nhập: client ngắt trước khi đăng nhập vẫn không sinh sự kiện.
  - Gom đợt brute force qua nhiều phiên: `ssh.bruteforce` chỉ gắn với phiên chạm ngưỡng, muốn xem cả đợt thì lọc theo IP.
  - Hệ thống migration tổng quát như Alembic.
  - Route catch-all cho HTTP; hiện chỉ `POST /wp-admin-login` sinh sự kiện.

## 4. Hiện trạng

- `client_handle` tạo dict `conn` cho mỗi kết nối SSH ([nids/honeypot/ssh_honeypot.py:218](../../nids/honeypot/ssh_honeypot.py#L218)). Mọi lệnh gọi `log_event` phía SSH đã truyền `**conn` (dòng 151, 186, 190, 208, 240), nên chỉ cần thêm một key.
- `log_event` ([nids/honeypot/store.py:27](../../nids/honeypot/store.py#L27)) dựng dict rồi gọi `EventRepository.save_alert`, ánh xạ thủ công từng cột tại [nids/db/repository.py:17](../../nids/db/repository.py#L17).
- `EventModel` ở [nids/db/models.py:24](../../nids/db/models.py#L24).
- `init_db` chỉ gọi `create_all` ([nids/db/__init__.py:43](../../nids/db/__init__.py#L43)), không thêm cột vào bảng đã có. Engine, API và honeypot đều gọi `init_db` khi khởi động ([nids/engine/main.py:220](../../nids/engine/main.py#L220), [nids/api/main.py:34](../../nids/api/main.py#L34), [nids/honeypot/__main__.py:33](../../nids/honeypot/__main__.py#L33)).
- Vòng retry của `init_db` bắt mọi exception rồi thử lại sau 2 giây, nên dùng được để xử lý nhiều process cùng thêm cột.
- `tests/api/test_db_init.py` stub `create_all` và không có CSDL thật, nên lời gọi mới trong `init_db` phải được stub ở hai test này.
- `FIELDS` và `_to_dict` ([nids/api/routes/alerts.py:23](../../nids/api/routes/alerts.py#L23)) quyết định trường trả về của API và cột CSV. Danh sách sắp xếp mới đến cũ ([nids/db/repository.py:81](../../nids/db/repository.py#L81)), nên không dùng trực tiếp cho chuỗi phiên được.
- `web_honeypot` là Flask, ghi sự kiện ở [nids/honeypot/web_honeypot.py:29](../../nids/honeypot/web_honeypot.py#L29), chưa dùng cookie.
- Hộp chi tiết trang Logs nằm ở `showDetail` ([nids/api/static/logs.html:228](../../nids/api/static/logs.html#L228)). Helper `el()` (dòng 96) dùng `textContent`, nên nội dung tấn công không bị render thành HTML.
- Các endpoint đọc cảnh báo không có xác thực; `GET /api/alerts/{id}` đã trả các dữ liệu này.
- Rule duy nhất nhắc tới cookie là `rules/web-attack.rules:26` (chuỗi `document.cookie` trong request), không khớp cookie toàn hex.

## 5. Các phương án đã cân nhắc

| Phương án | Ưu điểm | Nhược điểm | Kết luận |
| :-------- | :------ | :--------- | :------- |
| Cột `session_id` + `init_db` tự thêm vào CSDL cũ | Truy vấn có index, không mất dữ liệu, nhóm không phải reset | Thêm khoảng 10 dòng vào `init_db` | Chọn, người dùng chốt |
| Cột `session_id` + bắt buộc reset CSDL | Code ít nhất | Ai quên reset thì sự kiện mất âm thầm vì `log_event` nuốt lỗi | Loại |
| Lưu `session=<id>` trong `matched_content` | Không đổi schema | Phải `LIKE` qua `event_payloads`, không có index | Loại |
| HTTP: cookie do honeypot cấp | Ít code, không giữ state | Client không giữ cookie thì mỗi request là một phiên | Chọn, người dùng chốt |
| HTTP: gom theo IP + User-Agent | Gom được công cụ không dùng cookie | Thêm state, có thể gộp nhầm sau NAT | Loại |
| Chỉ làm SSH | PR nhỏ hơn | Issue yêu cầu cả SSH/HTTP | Loại |
| Xem phiên qua API + trang Logs | Dễ demo, không phải tự chép id | Sửa thêm `logs.html` | Chọn, người dùng chốt |
| Chỉ API | Ít việc | Khó demo | Loại |

## 6. Thiết kế đã chọn

```
SSH:  client_handle → conn["session_id"] = uuid4().hex → **conn → log_event
HTTP: before_request → cookie hợp lệ hoặc uuid4().hex → g.session_id → log_event
                                                  → after_request đặt cookie nếu là id mới
log_event → save_alert → events.session_id
GET /api/alerts/sessions/{id} → get_session_events (cũ đến mới) → nút "Xem cả phiên"
```

- **Session id**: `uuid4().hex`, 32 ký tự hex, cột `String(32)`, nullable, có index. Sự kiện rule engine và sự kiện cũ có giá trị `NULL`.
- **SSH**: mỗi kết nối TCP là một phiên. Id được tạo cùng `conn`, trước khi bắt tay, nên mọi sự kiện của kết nối đều có. Hydra mở kết nối mới cho mỗi mật khẩu nên mỗi lần thử là một phiên riêng.
- **HTTP**: cookie tên `wordpress_sess`, cho hợp với trang login WordPress giả, có `HttpOnly` và `SameSite=Lax`. Giá trị do client gửi chỉ được chấp nhận nếu `re.fullmatch(r"[0-9a-f]{32}", value)` khớp, nếu không thì cấp id mới. Dùng `fullmatch` để giá trị có ký tự xuống dòng ở cuối không lọt qua và vượt `String(32)`. Cookie được đặt ở mọi response, kể cả `GET /`, khi request chưa có id hợp lệ.
- **Nâng cấp CSDL**: hàm `_add_missing_columns()` trong `nids/db/__init__.py` chạy ngay sau `create_all`, dùng `inspect(engine)` kiểm tra cột `session_id`, rồi duyệt `EventModel.__table__.indexes` để tạo mọi index còn thiếu của bảng `events`. Kiểm tra cột và index riêng vì DDL của MySQL không nằm trong transaction, nên có thể dừng giữa hai lệnh. Duyệt mọi index vì trên CSDL trắng, nhiều process chạy `create_all` cùng lúc có thể làm một index khác bị bỏ sót sau lần retry. Nhiều process cùng thêm thì process thua nhận lỗi trùng, rơi vào vòng retry sẵn có, và lượt sau thấy đã có nên bỏ qua.
- **Lỗi nâng cấp CSDL**: lỗi vĩnh viễn như thiếu quyền `ALTER` sẽ qua hết 15 lần retry, ghi log `ERROR` rồi `raise`, giống hành vi hiện tại khi không kết nối được CSDL. Đây là chủ ý: thiếu cột thì mọi lần ghi `events` đều hỏng và bị `log_event` nuốt lỗi, nên dừng sớm với log rõ ràng tốt hơn sensor chạy mà mất sự kiện âm thầm. Quy tắc "lỗi ghi CSDL không được làm sập sensor" áp dụng lúc đang chạy và vẫn giữ nguyên.
- **API**: `GET /api/alerts/sessions/{session_id}` trả tối đa `SESSION_EVENT_LIMIT` (1000) sự kiện đầu tiên, theo `timestamp` rồi `id` tăng dần, không kèm payload. Phiên không tồn tại trả 404. Route này có hai đoạn path nên không đụng `/{event_id}`.
- **Bảo mật**: endpoint mới chỉ đọc, trả cùng loại dữ liệu mà `GET /api/alerts/{id}` đã trả, nên không mở thêm dữ liệu. Trang Logs dựng bảng bằng `el()`, không dùng `innerHTML`.
- **Sensor**: tạo session id không chạm mạng hay CSDL. Lỗi ghi vẫn do `try/except` trong `log_event` xử lý. Không có traffic mới, nên `network.bpf_filter` giữ nguyên.

## 7. Thay đổi cần làm

| File | Thay đổi | Dùng lại |
| :--- | :------- | :------- |
| `nids/db/models.py` | Thêm `EventModel.session_id` có index | |
| `nids/db/__init__.py` | Thêm `_add_missing_columns()`, gọi trong `init_db` sau `create_all`; cập nhật docstring `init_db` | Vòng retry của `init_db` |
| `nids/db/repository.py` | `save_alert` lưu `session_id`; thêm `get_session_events(session_id, limit)` | Mẫu của `get_recent_events` |
| `nids/honeypot/store.py` | `log_event` nhận `session_id` và đưa vào dict gửi `save_alert` | |
| `nids/honeypot/ssh_honeypot.py` | Thêm `session_id` vào `conn` trong `client_handle` | `**conn` sẵn có |
| `nids/honeypot/web_honeypot.py` | Thêm `before_request`, `after_request` xử lý cookie; truyền `session_id` vào `log_event` | |
| `nids/api/routes/alerts.py` | Thêm `session_id` vào cuối `FIELDS` (CSV có thêm cột cuối); thêm endpoint và `SESSION_EVENT_LIMIT` | `_to_dict` |
| `nids/api/main.py` | Cập nhật docstring khởi động (dòng 4): `init_db` tạo bảng và thêm cột còn thiếu | |
| `nids/api/static/logs.html` | Thêm `session_id` vào danh sách trường; nút "Xem cả phiên" chỉ hiện khi `session_id` khác `null`; hàm `showSession` | `el()`, dialog `detail` |
| `tests/api/test_db_init.py` | Stub `_add_missing_columns` trong `test_init_db_retries_then_succeeds`; thêm test nâng cấp schema | |
| `tests/honeypot/test_honeypot.py` | Thêm helper mới dùng `invoke_shell()`, gửi nhiều lệnh rồi `exit`; thêm test session SSH và HTTP | Fixture `memory_db` |
| `tests/api/test_api_dashboard.py` | Thêm test endpoint phiên | Fixture `client` |

Tài liệu cần cập nhật: `CLAUDE.md` (dòng 71), `.claude/rules/honeypot.md` (mô tả session, bỏ khỏi "Chưa làm"), `.claude/rules/api-web.md` (endpoint mới, và câu "chỉ tạo bảng" ở dòng 11), `.claude/rules/config-db-docker.md` (`init_db` tự thêm cột), `README.md` (bảng endpoint), `docs/demo/kich-ban-demo.md` (bước xem phiên SSH), `docs/demo/bao-cao-demo-honeypot.md` (dòng 165).

## 8. Kiểm thử

| Test | Kiểm tra điều gì |
| :--- | :--------------- |
| `tests/api/test_db_init.py` | CSDL SQLite có bảng `events` kiểu cũ: cột và index được thêm, dòng cũ còn nguyên với `session_id` là `NULL`; gọi lần hai không lỗi; có cột nhưng thiếu index thì chỉ thêm index; thiếu index khác của `events` thì cũng được tạo; lỗi tạm thời ở lần đầu thì `init_db` retry rồi thành công; lỗi vĩnh viễn thì `raise` sau hết lượt |
| `tests/honeypot/test_honeypot.py` | Một phiên SSH thật có đăng nhập và nhiều lệnh qua `invoke_shell()`: mọi sự kiện cùng một id. Hai phiên song song cùng IP: giữ hai kết nối cùng mở, gửi lệnh luân phiên và chờ từng sự kiện được ghi (fixture `memory_db` dùng `StaticPool`, ghi đồng thời từ hai thread có thể mất sự kiện); hai id khác nhau, không trộn. HTTP: request đầu nhận cookie, gửi lại thì cùng id; cookie sai định dạng, quá dài hoặc có ký tự xuống dòng ở cuối bị thay bằng id mới |
| `tests/api/test_api_dashboard.py` | Endpoint trả đúng thứ tự cũ đến mới, kể cả khi cùng `timestamp`; không lẫn phiên khác; phiên không tồn tại trả 404 (dùng id `"0" * 32`); dừng ở giới hạn; `GET /api/alerts/{id}` và CSV có `session_id` |

Lệnh: `pytest tests/api tests/honeypot`, sau đó chạy toàn bộ `pytest`.

## 9. Xác minh end-to-end

1. Lab đang chạy code cũ và có sẵn sự kiện. Chuyển sang code mới rồi chạy `docker compose restart nids_engine honeypot_ssh honeypot_http nids_api`, không dùng `docker compose down`. Log có "Kết nối và khởi tạo CSDL thành công" và sự kiện cũ vẫn còn trên `/logs`.
2. Từ attacker, mở hai phiên song song: `docker exec -it nids_attacker ssh -p 2222 -o StrictHostKeyChecking=no root@172.28.0.50`, gõ các lệnh khác nhau rồi `exit`.
3. Trên `http://localhost:8000/logs`, tab Honeypot SSH, mở một sự kiện `ssh.command`, bấm "Xem cả phiên": thấy đúng chuỗi đăng nhập và lệnh của phiên đó, không có lệnh của phiên kia.
4. Gõ một lệnh chứa `<script>alert(1)</script>` trong phiên SSH: bảng phiên hiện nguyên văn, không chạy script.
5. HTTP: chạy hai lần `docker exec nids_attacker curl -s -c /tmp/c -b /tmp/c -d username=a -d password=b http://172.28.0.50:8080/wp-admin-login`. Hai sự kiện `http.login` có cùng `session_id`. Chạy từ PowerShell; trong Git Bash phải thêm `MSYS_NO_PATHCONV=1` trước lệnh, nếu không `/tmp/c` bị đổi thành đường dẫn Windows và curl không lưu được cookie.
6. Trường hợp lỗi: `docker exec nids_attacker curl -s -b wordpress_sess=abc -d username=a -d password=b http://172.28.0.50:8080/wp-admin-login`. Sự kiện được ghi với id 32 ký tự hex, không phải `abc`.
7. Trường hợp lỗi: gọi `GET /api/alerts/sessions/00000000000000000000000000000000` trả 404.

## 10. Rủi ro và ảnh hưởng tới nhóm

| Rủi ro | Mức độ | Cách xử lý |
| :----- | :----- | :--------- |
| Tài khoản CSDL không có quyền `ALTER` | Thấp | `nids_app` có toàn quyền trên `nids_db` do entrypoint MySQL cấp qua `MYSQL_DATABASE`, xác minh ở mục 9 bước 1. Nếu vẫn lỗi thì engine và honeypot dừng sau khoảng 30 giây với log `ERROR` và Docker khởi động lại, theo thiết kế ở mục 6 |
| Nhiều process cùng thêm cột | Thấp | Vòng retry của `init_db` xử lý; process thua có thể ghi vài dòng cảnh báo "CSDL chưa sẵn sàng" |
| Nhóm chạy `docker compose down` rồi `up` để nâng cấp | Vừa | `mysql_db` không có named volume nên cách này mất dữ liệu. Tài liệu và mục "Thành viên khác cần làm gì" ghi rõ dùng `docker compose restart` |
| `summary` bị cắt ở 500 ký tự nên lệnh rất dài không hiện đủ trong bảng phiên | Thấp | Chấp nhận; lệnh dài hiếm gặp. Nội dung đầy đủ xem qua `GET /api/alerts/{id}` |
| Thêm cột trên bảng `events` lớn làm khởi động chậm | Thấp | Dữ liệu lab nhỏ, chỉ chạy một lần |
| Process cũ còn chạy khi cột đã được thêm | Thấp | Cột nullable nên process cũ vẫn ghi được |
| CSV có thêm cột `session_id` | Thấp | Không có chỗ nào trong repo phụ thuộc thứ tự cột CSV |
| Phiên quá 1000 sự kiện bị cắt khi xem | Thấp | Hiếm với honeypot; dữ liệu vẫn còn trong CSDL |
| Client không giữ cookie nên HTTP không gom được | Vừa | Đã chấp nhận khi chọn phương án; sự kiện vẫn có id riêng |
| Attacker tự chọn cookie đúng định dạng | Thấp | Chỉ ảnh hưởng cách gom sự kiện của chính attacker, không có quyền hay dữ liệu nào gắn với id |

**Thành viên khác cần làm gì**: Thay đổi này không cần sửa `.env` hay build lại image. Riêng lab cũ hơn PR #57 vẫn phải thêm `NIDS_REDIS_PASSWORD` vào `.env` và chạy `docker compose up --build -d` (không `down`) vì `redis-py` là dependency mới. Sau khi pull, nếu lab đang chạy thì dùng `docker compose restart` để cột được thêm và code mới có hiệu lực. Muốn giữ dữ liệu thì không chạy `docker compose down`, vì `mysql_db` dùng volume ẩn danh.

## 11. Các bước thực hiện

Nhánh: `feature/24-honeypot-session`

- [x] Thêm cột vào `EventModel`, `_add_missing_columns`, và test trong `tests/api/test_db_init.py`
- [x] `save_alert`, `log_event` lưu `session_id`
- [x] SSH: thêm `session_id` vào `conn`, test phiên thật và phiên song song
- [x] HTTP: cookie `wordpress_sess`, test cấp mới, dùng lại và từ chối cookie sai
- [x] `get_session_events`, endpoint, `FIELDS`, test API
- [x] `logs.html`: nút "Xem cả phiên" và `showSession`
- [x] Cập nhật tài liệu ở mục 7
- [ ] Chạy `pytest`, xác minh theo mục 9
- [ ] Tạo PR, cập nhật bảng tổng hợp

## 12. Quyết định và nhật ký

**Quyết định**

| Ngày | Quyết định | Người chốt | Lý do |
| :--- | :--------- | :--------- | :---- |
| 2026-11-01 | Lưu ở cột `events.session_id`, `init_db` tự thêm vào CSDL cũ | Người dùng | Không mất dữ liệu, nhóm không phải reset |
| 2026-11-01 | Session HTTP dùng cookie do honeypot cấp | Người dùng | Ít code, không giữ state |
| 2026-11-01 | Xem phiên qua API và trang Logs | Người dùng | Dễ trình diễn |
| 2026-11-01 | Dùng endpoint riêng, không thêm bộ lọc `session_id` | Claude | Danh sách sắp mới đến cũ; thêm bộ lọc còn mở cả `DELETE` theo phiên, ngoài phạm vi |
| 2026-11-01 | Mỗi kết nối TCP là một phiên SSH | Claude | Khớp yêu cầu issue, không cần gom theo thời gian |
| 2026-11-01 | `uuid4().hex`, không dùng số tăng dần | Claude | Nhiều process không cần phối hợp, không đoán được |
| 2026-11-01 | Giới hạn 1000 sự kiện mỗi phiên | Claude | Tránh tải vô hạn, đủ cho honeypot |
| 2026-11-01 | Endpoint không kèm payload | Claude | `summary` đã có lệnh; xem chi tiết từng sự kiện qua API sẵn có |
| 2026-11-01 | Lỗi vĩnh viễn khi nâng cấp CSDL thì fail-fast | Claude | Giống hành vi khi không kết nối được CSDL; tốt hơn sensor chạy mà mất sự kiện âm thầm |
| 2026-11-01 | `_add_missing_columns` tạo mọi index còn thiếu của `events` | Claude | Tránh bỏ sót index do race trên CSDL trắng |

**Nhật ký thực hiện**

- 2026-11-01: Xác minh trên lab thật, MySQL 8.0, CSDL cũ có 45 sự kiện. `init_db` thêm cột và index, dữ liệu cũ còn nguyên với `session_id` là `NULL`. `nids_honeypot_ssh` gặp đúng race dự kiến: một lần cảnh báo "CSDL chưa sẵn sàng", thử lại rồi thành công.
- 2026-11-01: Bước 2 của mục 9 dùng client paramiko chạy trong container `nids_api` để điều khiển hai phiên song song, thay cho hai terminal OpenSSH. Kết quả đạt: hai phiên không trộn, chuỗi `<script>alert(1)</script>` trả về nguyên văn qua API.
- 2026-11-01: Helper test `ssh_shell` đóng kết nối thay vì gửi `exit`, vì `exit` làm phiên kết thúc trước prompt. Test chờ prompt nên không cần polling, và lệnh gửi lần lượt nên không ghi đồng thời lên `StaticPool`.
- 2026-11-01: Chưa bấm thử nút "Xem cả phiên" trên trình duyệt thật. Đã kiểm tra cú pháp JS bằng `node --check`, trang phục vụ đúng nút mới, và dựng bảng chỉ bằng `el()` (`logs.html` không có `innerHTML`).
- 2026-11-01: `tests/test_realtime.py` và `tests/api/test_realtime_ws.py` fail thất thường trên Windows, kể cả trên `origin/main` sạch, không liên quan tới plan này.

**Câu hỏi còn mở**: Không

**Kết quả phản biện**: `plan-critic` kết luận `PASS_WITH_WARNINGS` (0 `BLOCKER`, 3 `WARNING`, 7 `NOTE`). Cả 3 `WARNING` đã xử lý trong plan: fail-fast khi nâng cấp CSDL lỗi được ghi ở mục 6 và 10, thêm helper `invoke_shell()` cho test nhiều lệnh và phiên song song, sửa lệnh curl ở mục 9 để chạy từ container attacker. Các `NOTE` đã được đưa vào plan. Không còn `WARNING` nào bị giữ lại. `plan-critic` chỉ đọc code, chưa chạy thử; các nhận định về race của `create_all` và volume ẩn danh sẽ được kiểm chứng khi thực hiện. Sau khi sửa, plan không được phản biện lại vì lần đầu không có `BLOCKER`.
