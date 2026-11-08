---
type: PLAN
plan_id: PLAN-006
title: Giới hạn tài nguyên cho honeypot SSH và HTTP
status: IN_PROGRESS
issue: 27
owner: Vo Ngoc Cu (ngoccu2006)
created: 2026-11-08
updated: 2026-11-08
---

# PLAN-006: Giới hạn tài nguyên cho honeypot SSH và HTTP

## 1. Bối cảnh

Honeypot là dịch vụ mở cho attacker nên phải tự chịu được tải xấu. Hiện cả hai honeypot không có giới hạn nào: mỗi kết nối SSH sinh một thread không trần, phiên shell không có timeout idle, buffer lệnh tăng vô hạn, và HTTP nhận body không giới hạn. Một lần quét hoặc brute force quá đà (hydra, SYN flood) có thể làm cạn thread và RAM của sensor, làm mất luôn nguồn sự kiện thứ hai của hệ thống. Yêu cầu đến từ issue #27. Nội dung issue (người dùng dán ngày 2026-11-08): "Thêm giới hạn số kết nối và timeout idle, cấu hình qua `HONEYPY_*`. Xong khi: flood kết nối không làm sập sensor; kết nối idle tự đóng." Issue hẹp hơn plan: phần trần dữ liệu (body HTTP, độ dài lệnh SSH) và cắt trường ghi DB là mở rộng do Claude đề xuất, xem mục 12.

## 2. Mục tiêu và tiêu chí thành công

- **Mục tiêu**: Mỗi honeypot có trần số kết nối đồng thời, timeout cho kết nối im lặng, và trần kích thước dữ liệu nhận từ attacker; vượt giới hạn thì từ chối hoặc đóng kết nối, ghi log, sensor vẫn chạy.
- **Xong khi**:
  - Mở quá `ssh_max_connections` kết nối SSH thì kết nối thừa bị đóng ngay và log WARNING; kết nối cũ không ảnh hưởng.
  - Một kết nối SSH im lặng quá `ssh_idle_timeout` (trong shell) hoặc quá `ssh_handshake_timeout` (trước khi mở channel) bị đóng và giải phóng chỗ.
  - Gõ ký tự không có Enter quá `ssh_max_command_bytes` thì buffer bị cắt/phiên bị đóng, RAM không tăng tiếp.
  - HTTP: POST body quá `http_max_body_bytes` nhận 413; client chậm quá `http_request_timeout` bị ngắt.
  - Lệnh tấn công trong `attack_demo.py` (hydra `-t 4`) và kịch bản demo vẫn ra đủ sự kiện, không bị giới hạn mặc định chặn.
  - `pytest` xanh.

## 3. Phạm vi

- **Trong phạm vi**: trần kết nối đồng thời SSH (toàn cục và theo IP), timeout handshake/idle/tổng thời gian phiên SSH, trần độ dài lệnh SSH và số lần auth mỗi kết nối, giới hạn body và timeout HTTP, cắt độ dài trường ghi DB trong `log_event`, biến cấu hình `HONEYPY_*`, test, cập nhật tài liệu.
- **Ngoài phạm vi**:
  - Rate limit theo thời gian (kết nối/giây) và chặn IP tạm thời.
  - Giới hạn CPU/RAM ở tầng container (`mem_limit`, `pids_limit` trong `docker-compose.yml`) — có thể làm riêng sau.
  - Đổi sang server WSGI khác ngoài waitress (gunicorn...).
  - Route catch-all HTTP và shell giả sâu hơn (vẫn ở mục "Chưa làm").
  - Giới hạn kết nối ở tầng `redirector`/iptables.

## 4. Hiện trạng

- SSH: `honeypot()` chạy vòng `accept` rồi `threading.Thread(...).start()` cho mọi kết nối, không đếm, không trần ([nids/honeypot/ssh_honeypot.py:288](../../nids/honeypot/ssh_honeypot.py#L288)). `socks.listen(100)` chỉ là backlog.
- `client_handle` ([ssh_honeypot.py:217](../../nids/honeypot/ssh_honeypot.py#L217)): `transport.accept(100)` chờ channel tới 100 giây (dòng 232); `server.event.wait(10)` đã có giới hạn 10 giây (dòng 238); `transport.join(5)` cho nhánh exec. Phần `finally` đã đóng transport và socket.
- `emulated_shell` ([ssh_honeypot.py:102](../../nids/honeypot/ssh_honeypot.py#L102)): `channel.recv(1)` chặn vô hạn (dòng 107); `command += char` không trần (dòng 145); vòng đọc chuỗi escape `ESC [` cũng chặn vô hạn (dòng 133-137).
- `Server.check_auth_password` ([ssh_honeypot.py:185](../../nids/honeypot/ssh_honeypot.py#L185)) không giới hạn số lần thử trong một kết nối; paramiko cũng không tự giới hạn.
- `BruteForceTracker` ([ssh_honeypot.py:58](../../nids/honeypot/ssh_honeypot.py#L58)) đã dọn đợt hết hạn mỗi lần `hit`, nên không phình vô hạn — không cần sửa.
- HTTP: `app.run(debug=False, port, host)` ([web_honeypot.py:62](../../nids/honeypot/web_honeypot.py#L62)) dùng Werkzeug dev server, mặc định `threaded=True`, không `MAX_CONTENT_LENGTH`, không timeout.
- `log_event` ([store.py:27](../../nids/honeypot/store.py#L27)) cắt `msg` ở 500 ký tự nhưng `matched_content` (`evidence`) và các trường username/password/command/user_agent đi vào DB nguyên độ dài. Cần kiểm tra độ dài cột trong `nids/db/models.py` khi thực hiện.
- Cấu hình honeypot ở [settings.py](../../nids/honeypot/settings.py) (`HONEYPY_*`, pydantic-settings), test ở [tests/honeypot/test_honeypot.py](../../tests/honeypot/test_honeypot.py) (đã có test `emulated_shell` với channel giả ở dòng ~112 và test `Settings` đọc env).
- Lab: `attack_demo.py` chạy hydra với `-t 4` vào cổng 2222 ([lab/attacker/attack_demo.py:225](../../lab/attacker/attack_demo.py#L225)); redirector chuyển traffic của IP đáng ngờ vào cùng honeypot, nên nhiều kết nối từ một IP là chuyện bình thường.

## 5. Các phương án đã cân nhắc

| Phương án | Ưu điểm | Nhược điểm | Kết luận |
| :-------- | :------ | :--------- | :------- |
| SSH: `BoundedSemaphore` toàn cục + đếm theo IP, thread-per-connection giữ nguyên | Ít code, không đổi kiến trúc, dễ test | Vẫn là thread, trần phải đủ nhỏ | Chọn |
| SSH: `ThreadPoolExecutor` | Trần thread sẵn có | Kết nối thừa xếp hàng chứ không bị từ chối, giữ socket lâu | Loại |
| SSH: chuyển sang asyncio (asyncssh) | Chịu nhiều kết nối nhất | Viết lại toàn bộ, đổi dependency, ngoài sức đồ án | Loại |
| HTTP: giữ Werkzeug, semaphore và handler con tự viết | Không thêm dependency | Nhiều code dễ sót (cờ `g`, teardown, handler con), slowloris vẫn chiếm thread, route catch-all sau này phải tự bảo đảm không đi vòng | Loại, người dùng chốt waitress |
| HTTP: chạy bằng `waitress` | Giới hạn là tham số server (`threads`, `connection_limit`, `channel_timeout`, `max_request_body_size`), dọn kết nối im (không chặn được client nhỏ giọt từng byte), route mới tự được bảo vệ, thuần Python chạy được trên Windows và Docker | Thêm dependency `waitress` vào `requirements.txt`, nhóm phải build lại image | Chọn, người dùng chốt |
| Giới hạn chỉ ở Docker (`mem_limit`, `pids_limit`) | Không đụng code | Container chết/restart thay vì từ chối mềm, mất sự kiện đang giữ | Bổ sung sau, ngoài phạm vi |
| Trần theo IP mặc định thấp (3-5) | Chặn một nguồn chiếm hết chỗ | hydra `-t 4` + redirector dễ chạm, làm hỏng demo | Chọn trần theo IP đủ rộng (20), mặc định có thể tắt bằng 0 |

## 6. Thiết kế đã chọn

```
accept → ConnectionLimiter.acquire(ip)
           ├─ hết chỗ (toàn cục hoặc theo IP) → close + log WARNING, không tạo thread
           └─ được → Thread(client_handle) ... finally: release(ip)
client_handle: socket timeout handshake → accept(channel, ssh_auth_timeout)
               → emulated_shell: channel.settimeout(ssh_idle_timeout), deadline = ssh_session_max_seconds
HTTP: waitress.serve(threads, connection_limit, channel_timeout, max_request_body_size) → 413 khi body quá lớn
```

- **`ConnectionLimiter`** (lớp nhỏ trong `ssh_honeypot.py`, dạng `BruteForceTracker`): `threading.Lock` + `dict ip → số kết nối` + tổng. `acquire(ip)` trả `False` khi tổng ≥ `ssh_max_connections` hoặc số của IP ≥ `ssh_max_connections_per_ip` (0 = không giới hạn theo IP). `release(ip)` luôn gọi trong `finally` của thread. Xoá khoá IP khi về 0 để dict không phình. Log từ chối ở mức WARNING nhưng giới hạn tần suất (mỗi IP tối đa 1 dòng/10 giây) để chính log không bị flood.
- **Cấu trúc để test được**: logic nhận kết nối tách khỏi vòng `while True` của `honeypot()` thành hàm `accept_connection(client, addr, limiter, ...)` (acquire, tạo thread, rollback khi lỗi). `ConnectionLimiter`, các timeout và trần truyền qua tham số có mặc định lấy từ `settings` (settings đọc ở module level nên test không thể đổi bằng env). Cách này khớp các test hiện có, vốn gọi thẳng `client_handle` qua socketpair.
- **Đường lỗi của limiter**: `acquire` và `Thread.start()` nằm trong `try/except`; nếu `start()` ném lỗi (cạn thread, đúng tình huống đang phòng) thì `release(ip)`, `client.close()`, log, vòng `accept` vẫn chạy. Kết nối bị từ chối cũng `client.close()` ngay.
- **Ngữ nghĩa 0**: mọi giới hạn bằng 0 nghĩa là tắt giới hạn đó (cả `ssh_max_connections` lẫn `ssh_max_connections_per_ip`). Backlog `listen(100)` không liên quan tới trần này.
- **Timeout SSH**:
  - Trước `start_server`: `client.settimeout(ssh_handshake_timeout)` để bắt tay SSH (kex) mà client im lặng không chặn vô hạn, sau đó trả socket về chế độ blocking cho paramiko.
  - `ssh_auth_timeout` (mặc định 90 giây) thay cho `accept(100)`: bao cả bước xác thực để người gõ mật khẩu bằng tay (giảng viên khi demo) không bị ngắt. `ssh_handshake_timeout` mặc định 30 giây.
  - `ssh_idle_timeout` (mặc định 120 giây): `channel.settimeout(...)`; `emulated_shell` bắt `socket.timeout` rồi đóng phiên, cả ở vòng đọc escape.
  - `ssh_session_max_seconds` (mặc định 600): kiểm tra deadline mỗi vòng, tránh phiên gõ chậm giữ mãi.
- **Trần dữ liệu SSH**: `ssh_max_command_bytes` (mặc định 4096): vượt thì đóng phiên (không cắt âm thầm, để không ghi lệnh sai). **Không** thêm trần số lần auth mỗi kết nối: ở chế độ mặc định lần đăng nhập đầu luôn thành công và hydra mở kết nối mới cho mỗi mật khẩu, nên trần này gần như vô nghĩa, còn việc chặn sau lượt N sẽ làm mất bằng chứng. Số kết nối đã được `ConnectionLimiter` kiềm chế.
- **HTTP**: chạy bằng `waitress.serve(app, host=..., port=..., threads=http_threads, connection_limit=http_max_connections, channel_timeout=http_request_timeout, max_request_body_size=http_max_body_bytes, ident=...)`. Mặc định: `http_threads` 8, `http_max_connections` 100, `http_request_timeout` 30 giây, `http_max_body_bytes` 16 KB (đủ cho form login). Lưu ý: `connection_limit` làm waitress ngừng accept chứ không đóng kết nối thừa nên không có log WARNING như SSH; `channel_timeout` là timeout không hoạt động, dọn theo chu kỳ `cleanup_interval` thay cho `app.run`. Waitress là server async I/O: kết nối chưa gửi đủ request không chiếm worker thread và bị `channel_timeout` dọn (kiềm chế slowloris), `connection_limit` là trần kết nối, `threads` là trần worker, body quá `max_request_body_size` bị từ chối 413. Thêm `app.config["MAX_CONTENT_LENGTH"] = http_max_body_bytes` làm lớp thứ hai, handler 413 trả chuỗi dựng sẵn và không ghi sự kiện chứa body. Mọi giới hạn nằm ở tầng server nên route mới (catch-all ở issue tiếp theo) tự được bảo vệ. `ident` đặt header `Server:` cho khỏi lộ honeypot (tên cụ thể chốt ở issue catch-all). Không dùng semaphore hay handler con. Khi thực hiện phải kiểm chứng trên waitress đã cài: tham số và hành vi `channel_timeout`/`max_request_body_size`, và `REMOTE_PORT` có trong `environ` không (`web_honeypot.py:47` đọc nó; thiếu thì `src_port` là `None`, cột nullable nên không lỗi).
- **Cắt trường ghi DB**: trong `log_event`, cắt username/password/command/user_agent/http_uri về `MAX_FIELD_LEN` (256) và `evidence` (`matched_content`, cột `Text` nên không có trần sẵn) về `MAX_EVIDENCE_LEN` (1024), nhằm bảo vệ cả CSDL lẫn bộ nhớ. Không đổi schema.
- **Bảo mật**: giới hạn chỉ đóng/từ chối, không bao giờ thực thi hay phản hồi nội dung attacker; lỗi trong limiter hay timeout được bắt và log, không làm sập vòng `accept` ("lỗi ghi CSDL không sập sensor" vẫn giữ). Không có traffic mới nên `network.bpf_filter` giữ nguyên.
- **Giá trị mặc định** chọn để demo không bị chạm: hydra `-t 4` = 4 kết nối song song/IP, nhỏ hơn 20 nhiều.

## 7. Thay đổi cần làm

| File | Thay đổi | Dùng lại |
| :--- | :------- | :------- |
| `nids/honeypot/settings.py` | Thêm `ssh_max_connections`, `ssh_max_connections_per_ip`, `ssh_handshake_timeout`, `ssh_auth_timeout`, `ssh_idle_timeout`, `ssh_session_max_seconds`, `ssh_max_command_bytes`, `http_threads`, `http_max_connections`, `http_max_body_bytes`, `http_request_timeout` | pydantic `Settings` hiện có |
| `nids/honeypot/ssh_honeypot.py` | `ConnectionLimiter`; tách `accept_connection` khỏi `honeypot()` (acquire/rollback, release trong `finally` của thread); timeout và deadline trong `client_handle`/`emulated_shell` nhận qua tham số; trần `command` | Mẫu `BruteForceTracker` |
| `nids/honeypot/web_honeypot.py` | `run_web_honeypot` gọi `waitress.serve(...)` thay `app.run`; `MAX_CONTENT_LENGTH` và handler 413 | Flask `errorhandler` |
| `requirements.txt` | Thêm `waitress` (ghim phiên bản tối thiểu, ví dụ `waitress>=3.0`, kiểm tra phiên bản khi cài) cạnh `flask` | |
| `nids/honeypot/store.py` | Cắt độ dài trường trước khi lưu | `log_event` hiện có |
| `tests/honeypot/test_honeypot.py` | Test limiter, timeout, trần lệnh, 413, cắt trường | Channel giả ở test `emulated_shell`, fixture `memory_db` |
| `.claude/rules/honeypot.md`, `CLAUDE.md` (dòng 74), `README.md` (mục `HONEYPY_*`) | Bỏ "giới hạn tài nguyên" khỏi "Chưa làm", ghi các biến mới | |

`docker-compose.yml` và `attack_demo.py` không đổi (mặc định đủ rộng). Thêm dependency `waitress`; không thêm bảng hay cột CSDL. Image Docker dùng chung được build từ `requirements.txt` nên phải build lại.

## 8. Kiểm thử

| Test | Kiểm tra điều gì |
| :--- | :--------------- |
| `ConnectionLimiter` | Chạm trần toàn cục thì `acquire` False; chạm trần theo IP thì False, IP khác vẫn được; `release` trả lại chỗ; 0 = tắt trần theo IP; dict rỗng sau khi hết kết nối; `release` luôn được gọi kể cả khi `client_handle` ném lỗi |
| `emulated_shell` | Channel giả ném `socket.timeout` ở `recv` thì vòng thoát sạch; buffer vượt `ssh_max_command_bytes` thì đóng; vượt deadline thì đóng |
| `accept_connection` | Giả lập `Thread.start` ném `RuntimeError`: chỗ được trả lại, socket đóng, hàm không ném ra ngoài; kết nối thừa bị đóng và không tạo thread |
| SSH qua socketpair + `client_handle` (như test phiên hiện có) | Client im sau khi nối thì bị đóng sau `ssh_handshake_timeout` nhỏ truyền qua tham số; phiên shell im quá `ssh_idle_timeout` thì đóng; `ssh.bruteforce` vẫn ra ở lần thứ 5 |
| HTTP | Body vượt giới hạn → 413 và không ghi sự kiện chứa body; `run_web_honeypot` truyền đúng tham số vào `waitress.serve` (giả `serve`); chạy server waitress thật trên cổng tạm: body quá lớn → 413, kết nối im bị đóng sau `channel_timeout` và `cleanup_interval` nhỏ truyền vào `serve`; `src_port` và `dst_ip` của sự kiện `http.login` đúng và không rỗng; request bình thường vẫn ghi `http.login` |
| `log_event` | Chuỗi dài bị cắt đúng giới hạn, không raise; `test_log_event_never_raises` vẫn pass |
| `Settings` | Đọc được các biến `HONEYPY_*` mới, giá trị mặc định như mục 6 |

Lệnh: `pytest tests/honeypot`, sau đó `pytest` toàn bộ (lưu ý `tests/test_realtime.py` và `tests/api/test_realtime_ws.py` từng fail thất thường trên Windows, không liên quan).

## 9. Xác minh end-to-end

Chạy từ gốc repo. Lệnh `docker exec ... sh -c` trong **cmd** phải bọc bằng dấu nháy kép (cmd không coi nháy đơn là dấu bọc chuỗi, nên hiểu `>/dev/null` là chuyển hướng ra file và báo "The system cannot find the path specified"). PowerShell dùng được cả hai.

**Bước 0: chuẩn bị lab**
1. `docker compose up --build -d` (build lại vì có dependency `waitress`; không dùng `down` vì MySQL dùng volume ẩn danh).
2. `docker logs nids_honeypot_http --tail 20`: waitress lắng nghe, không có `ModuleNotFoundError`.
3. `docker logs nids_honeypot_ssh --tail 5`: honeypot SSH đang lắng nghe.

**Bước 1: hạ trần để dễ thử.** Tạo `docker-compose.override.yml` ở gốc repo (chỉ dùng tạm, KHÔNG commit):

```yaml
services:
  honeypot_ssh:
    environment:
      HONEYPY_SSH_MAX_CONNECTIONS: "5"
      HONEYPY_SSH_MAX_CONNECTIONS_PER_IP: "0"
      HONEYPY_SSH_HANDSHAKE_TIMEOUT: "10"
      HONEYPY_SSH_IDLE_TIMEOUT: "20"
      HONEYPY_SSH_MAX_COMMAND_BYTES: "200"
  honeypot_http:
    environment:
      HONEYPY_HTTP_REQUEST_TIMEOUT: "10"
      HONEYPY_HTTP_MAX_BODY_BYTES: "1024"
```

Áp dụng bằng `docker compose up -d honeypot_ssh honeypot_http`. Kiểm tra:
- `docker exec nids_honeypot_ssh env | Select-String HONEYPY` phải liệt kê các biến trên.
- `docker exec nids_honeypot_ssh grep -c quiet_close /app/nids/honeypot/ssh_honeypot.py` phải lớn hơn 0. Container thấy code mới nhờ mount `.:/app`; sửa code thì chỉ cần `docker compose restart honeypot_ssh`.

**Bước 2: flood kết nối SSH (trần kết nối).**
1. PowerShell: `docker compose restart honeypot_ssh; Start-Sleep 5; $t = Get-Date`. `docker logs` giữ lịch sử cũ qua restart, nên dùng mốc `$t` để chỉ đọc log mới.
2. Cmd khác: `docker exec nids_attacker sh -c "for i in 1 2 3 4 5 6 7 8; do (sleep 60 | nc 172.28.0.50 2222 >/dev/null &) ; done"`. Nếu không có `nc` (kiểm tra bằng `docker exec nids_attacker sh -c "command -v nc python3"`) thì dùng `docker exec nids_attacker python3 -c "import socket,time; s=[socket.create_connection(('172.28.0.50',2222)) for _ in range(8)]; time.sleep(60)"`.
3. Đợi khoảng 15 giây rồi đọc log: `docker logs nids_honeypot_ssh --since $t.ToUniversalTime().ToString("o") 2>&1 | Select-String "Từ chối|Đóng kết nối|Traceback|Bad file"`.
4. Kỳ vọng: có "Từ chối kết nối SSH từ ... vượt giới hạn kết nối đồng thời" (tối đa 1 dòng/10 giây/IP) và "Đóng kết nối SSH ... không hoàn tất bắt tay"; **không** có `Traceback` hay `Bad file descriptor`; `docker ps` vẫn thấy `nids_honeypot_ssh` Up.

**Bước 3: timeout (kết nối idle tự đóng).** Chờ các kết nối ở bước 2 được dọn (~15 giây), kẻo hết slot.
1. Kết nối im lặng bị đóng sau `HONEYPY_SSH_HANDSHAKE_TIMEOUT` (đã thấy ở bước 2).
2. Shell idle: `docker exec -it nids_attacker ssh -p 2222 -o StrictHostKeyChecking=no root@172.28.0.50`, nhập mật khẩu bất kỳ, để yên 20 giây: phiên hiện "Connection timed out" rồi đóng; log có "Đóng phiên SSH ... im lặng quá thời gian cho phép".
3. Lệnh quá dài: vào shell, dán chuỗi dài hơn 200 ký tự mà không nhấn Enter: phiên bị đóng, log có "dòng lệnh dài quá 200 byte".
4. Người gõ mật khẩu chậm (~40 giây) vẫn vào được, vì nhỏ hơn `HONEYPY_SSH_AUTH_TIMEOUT` (90 giây).

**Bước 4: HTTP.**
1. Body quá lớn, kỳ vọng `413`: `docker exec nids_attacker sh -c "head -c 5000 /dev/zero | tr '\0' a > /tmp/big; curl -s -o /dev/null -w '%{http_code}' --data-binary @/tmp/big http://172.28.0.50:8080/wp-admin-login"` (dùng được trong cả cmd và PowerShell vì cả lệnh nằm trong cặp nháy kép ngoài).
2. Request bình thường, kỳ vọng `200`: `docker exec nids_attacker curl -s -o /dev/null -w "%{http_code}" -d "username=a&password=b" http://172.28.0.50:8080/wp-admin-login`.
3. Trang `http://localhost:8000/logs`: có sự kiện `http.login` với `dst_ip` không rỗng và `src_port` có giá trị; request 413 không sinh sự kiện.
4. Kết nối mở rồi im lặng tới cổng 8080 bị waitress dọn sau `HONEYPY_HTTP_REQUEST_TIMEOUT` (có thể trễ thêm một chu kỳ `cleanup_interval`).

**Bước 5: kịch bản demo không bị chặn (giá trị mặc định).**
1. Xoá `docker-compose.override.yml`, rồi `docker compose up -d honeypot_ssh honeypot_http`.
2. `docker exec nids_attacker hydra -l root -p 123456 -t 4 -s 2222 ssh://172.28.0.50`.
3. Trang Logs hiện đủ `ssh.auth.attempt` và một `ssh.bruteforce`. Thiếu sự kiện nghĩa là mặc định đang chặn nhầm.

**Bước 6: dọn dẹp.** `Remove-Item docker-compose.override.yml`, `docker compose up -d honeypot_ssh honeypot_http`, rồi `git status --short` không còn thấy file override.

## 10. Rủi ro và ảnh hưởng tới nhóm

| Rủi ro | Mức độ | Cách xử lý |
| :----- | :----- | :--------- |
| Mặc định chặn nhầm kịch bản demo/hydra | Vừa | Mặc định rộng (toàn cục 100, theo IP 20); bước 7 mục 9 kiểm tra lại; biến `HONEYPY_*` chỉnh được không cần sửa code |
| Timeout làm cắt phiên giảng viên đang thao tác chậm | Thấp | `ssh_idle_timeout` 120 giây, `ssh_session_max_seconds` 600; đổi qua env |
| Timeout handshake/xác thực ngắt người gõ mật khẩu chậm giữa demo | Vừa | Tách `ssh_handshake_timeout` 30 giây (kex) và `ssh_auth_timeout` 90 giây (gồm đăng nhập); bước 3 mục 9 kiểm tra |
| Waitress khác Werkzeug về `environ`/header (`REMOTE_PORT`, `SERVER_NAME` theo cấu hình chứ không theo `Host`, header `Server:`) | Vừa | `dst_ip` là cột `nullable=False`, nên khi thực hiện phải kiểm chứng `SERVER_NAME`/`SERVER_PORT` dưới waitress và chốt cách tính `dst_ip` (từ `request.host` hoặc socket); thiếu `REMOTE_PORT` thì `src_port` là `None`; `ident` đặt `Server:`; test dùng server waitress thật |
| Log của waitress đi qua logger `waitress`, không theo định dạng `nids.honeypot` | Thấp | Kiểm tra hiển thị khi thực hiện, gắn vào `setup_logging` nếu cần |
| Thêm dependency, nhóm quên build lại image nên honeypot HTTP không khởi động | Vừa | Ghi rõ ở "Thành viên khác cần làm gì"; lỗi `ModuleNotFoundError` hiện ngay trong log container |
| `release` bị bỏ sót → rò chỗ, honeypot dần từ chối hết | Vừa | `release` trong `finally` của thread; có test ném lỗi giữa chừng |
| Log từ chối bị flood | Thấp | Giới hạn 1 dòng/10 giây/IP |
| Cắt trường làm mất bằng chứng dài | Thấp | 256 ký tự đủ cho mật khẩu/lệnh; chấp nhận |
| Test timeout chậm, flaky | Thấp | Truyền timeout nhỏ qua tham số, không `sleep` thật dài |

**Thành viên khác cần làm gì**: Không cần sửa `.env`. Có dependency mới nên sau khi pull chạy `pip install -r requirements.txt` (chạy local) và `docker compose up --build -d` (lab; không `down` vì MySQL dùng volume ẩn danh), `restart` đơn thuần là không đủ. Muốn đổi giới hạn thì đặt biến `HONEYPY_*` trong môi trường của service honeypot.

## 11. Các bước thực hiện

Nhánh: `feature/27-honeypot-resource-limits`

- [x] Đối chiếu nội dung issue #27 (người dùng đã dán): tiêu chí "flood không sập sensor, idle tự đóng" đã nằm trong mục 2
- [x] `settings.py`: thêm các biến giới hạn và test `Settings`
- [x] `ConnectionLimiter` và test; nối vào `honeypot()`
- [x] Timeout, deadline, trần lệnh trong SSH, kèm test
- [x] HTTP: thêm `waitress` vào `requirements.txt`, đổi `run_web_honeypot` sang `waitress.serve`, 413, test
- [x] `log_event` cắt trường, test
- [x] Cập nhật tài liệu ở mục 7
- [x] Chạy `pytest`, xác minh theo mục 9 (bước 0-4, 6 đạt; bước 5 xem nhật ký)
- [ ] Tạo PR (tiêu đề tiếng Anh, mô tả tiếng Việt, `Closes #27`), cập nhật bảng tổng hợp

## 12. Quyết định và nhật ký

**Quyết định**

| Ngày | Quyết định | Người chốt | Lý do |
| :--- | :--------- | :--------- | :---- |
| 2026-11-08 | Giữ thread-per-connection, thêm limiter thay vì đổi sang asyncio | Claude (chờ duyệt) | Đổi kiến trúc quá lớn cho đồ án |
| 2026-11-08 | HTTP chuyển sang `waitress`, bỏ semaphore và handler con tự viết | Người dùng | Giới hạn thành tham số server, chặn slowloris đúng nghĩa, route catch-all ở issue tiếp theo tự được bảo vệ; đổi lại thêm một dependency |
| 2026-11-08 | Trần theo IP mặc định 20, toàn cục 100 | Claude (chờ duyệt) | hydra `-t 4` và redirector không được chạm trần |
| 2026-11-08 | Vượt trần lệnh thì đóng phiên, không cắt âm thầm | Claude (chờ duyệt) | Không ghi lệnh sai vào bằng chứng |
| 2026-11-08 | Giữ nguyên phạm vi đầy đủ của plan, dù rộng hơn issue #27 (thêm trần body HTTP, trần độ dài lệnh SSH, cắt trường DB, trần theo IP, deadline phiên) | Người dùng | Người dùng chốt sau khi Claude đề xuất cắt về đúng issue |
| 2026-11-08 | Bỏ `ssh_max_auth_attempts` | Claude (theo plan-critic) | Gần như vô nghĩa với cấu hình mặc định, và chặn sẽ làm mất bằng chứng |
| 2026-11-08 | Tách `ssh_handshake_timeout` (30s) và `ssh_auth_timeout` (90s) | Claude (theo plan-critic) | Tránh ngắt người gõ mật khẩu chậm khi demo |
| 2026-11-08 | Giới hạn tầng container (`mem_limit`, `pids_limit`) ngoài phạm vi | Claude (chờ duyệt) | Làm riêng nếu cần |

**Nhật ký thực hiện**

- 2026-11-08: Soạn plan trong plan mode. Chưa đọc được issue #27 vì máy không có `gh`; người dùng dán nội dung issue.
- 2026-11-08: Code xong và `pytest tests/honeypot` xanh (40 test). Đã cài waitress 3.0.2: có `REMOTE_PORT`, `SERVER_NAME` theo cấu hình server nên `dst_ip` lấy từ header `Host` (cắt 45 ký tự theo cột). `start_server(event=...)` thay cho gọi chặn để có timeout bắt tay. `pytest` toàn bộ: 2 test engine fail (`test_rule_header`, `test_stream::test_decoder_fills_tcp_seq`) vì scapy trên máy Windows không thấy interface loopback; `test_rule_header` fail cả trên `main`. Chạy xác minh Docker (mục 9) đang tiến hành: bước 2 lộ traceback paramiko `Bad file descriptor` khi đóng kết nối đang bắt tay, đã sửa bằng cờ `quiet_close` trong `HasshTransport` và thêm test hồi quy; chờ chạy lại.
- 2026-11-09: Xác minh trên lab Docker thật (override hạ trần). Bước 0: `honeypot_http` trả 200 qua waitress; thêm log "HTTP honeypot đang lắng nghe" vì waitress không in gì ra log của repo. Bước 2: 8 kết nối giữ im, trần 5: có 1 dòng "Từ chối" cho cả đợt (giới hạn tần suất log) và 5 dòng "Đóng kết nối ... bắt tay trong 10.0s", 0 traceback, sensor vẫn Up. Bước 3 (client paramiko chạy trong `nids_honeypot_http` vì container attacker không có paramiko): shell idle đóng sau 19 giây, dòng lệnh 300 byte đóng sau 0,1 giây, phiên bình thường vẫn chạy. Bước 4: body 5000 byte trả 413, request thường 200, sự kiện `http.login` có `src_port` và `dst_ip` đúng. Bước 5/6: đã gỡ override, hydra `-t 4` với giá trị mặc định vẫn ra `ssh.auth.attempt`, không có dòng "Từ chối"; một lần hydra với một mật khẩu chỉ tạo 1 lần đăng nhập nên chưa chạm ngưỡng `ssh.bruteforce` (5 lần), việc này không liên quan tới giới hạn mới. Chưa kiểm: kết nối im tới cổng 8080 bị waitress dọn (đã có test với waitress thật).
- 2026-11-09: Thông báo "Connection timed out" cũng hiện khi dòng lệnh quá dài; chấp nhận vì không lộ lý do cho attacker.

**Câu hỏi còn mở**

- Issue #27 đang assign cho ai? (planning.md bước 2 yêu cầu báo trước nếu là người khác; owner trong plan tạm đặt theo git user.)

**Kết quả phản biện**: `plan-critic` kết luận `PASS_WITH_WARNINGS` (0 `BLOCKER`, 6 `WARNING`, 5 `NOTE`). Cả 6 `WARNING` đã xử lý ở mục 6, 7, 8, 9, 10: ngữ nghĩa semaphore HTTP và cờ `g.slot_acquired`; tách timeout handshake/xác thực; bỏ `ssh_max_auth_attempts`; tách `accept_connection` để test được; rollback khi `Thread.start()` lỗi; chốt `MAX_EVIDENCE_LEN` vì cột là `Text`. `NOTE` về ngữ nghĩa 0, cách đặt env khi thử, và backlog đã đưa vào plan. `plan-critic` chưa kiểm chứng hành vi thật của paramiko/werkzeug; việc này làm khi thực hiện. Vòng 2 (sau khi đổi HTTP sang waitress): `PASS_WITH_WARNINGS` (0 `BLOCKER`, 5 `WARNING`, 5 `NOTE`). Các `WARNING` về semaphore ở vòng 1 nay không còn áp dụng. Đã xử lý 5 `WARNING` mới: dọn nội dung còn sót (503, trần auth, sơ đồ `accept`), chốt giá trị mặc định HTTP, hạ khẳng định về slowloris và ghi ngữ nghĩa `connection_limit`/`cleanup_interval`, thêm rủi ro `SERVER_NAME`/`dst_ip` với bước kiểm chứng. CI và `docker-compose.yml` không cần đổi (Dockerfile cài từ `requirements.txt`). Hành vi thật của waitress chưa được kiểm chứng, làm khi thực hiện.
