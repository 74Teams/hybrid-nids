---
type: PLAN
plan_id: PLAN-001
title: Đẩy cảnh báo thời gian thực qua Redis pub/sub và WebSocket
status: IN_PROGRESS
issue: 30
owner: Nguyễn Minh Chiến (nmchien1106)
created: 2026-11-01
updated: 2026-11-01
---

# PLAN-001: Đẩy cảnh báo thời gian thực qua Redis pub/sub và WebSocket

## 1. Bối cảnh

Dashboard poll 4 endpoint mỗi 2 giây, trang Logs poll mỗi 5 giây khi bật "Tự làm mới". Cảnh báo vì vậy trễ tới 2–5 giây, và mỗi tab tạo tải đều đặn lên API và CSDL kể cả khi không có gì mới. Issue #30 yêu cầu đẩy cảnh báo qua WebSocket, gợi ý Redis pub/sub vì engine, honeypot và API là các process riêng. Người dùng đã chọn Redis pub/sub.

## 2. Mục tiêu và tiêu chí thành công

- **Mục tiêu**: Cảnh báo mới từ engine và honeypot hiện trên dashboard và trang Logs gần như tức thì, trình duyệt không cần poll để biết có cảnh báo mới.
- **Xong khi**:
  - Trong Docker lab, từ lúc gửi đòn tới lúc API đẩy tín hiệu qua WebSocket không quá 1 giây (đo theo mục 9), và dòng cảnh báo hiện trên dashboard ngay sau đó.
  - Khi không có cảnh báo mới, tab Network của dashboard chỉ còn một lượt tải mỗi 30 giây thay vì mỗi 2 giây.
  - Dừng container Redis: engine và honeypot vẫn chạy, cảnh báo vẫn vào CSDL, dashboard tự quay về poll 2 giây. Bật Redis lại: dashboard tự về chế độ đẩy trong tối đa 60 giây.
  - Chạy local không có Redis: mọi thứ hoạt động như hiện tại.

## 3. Phạm vi

- **Trong phạm vi**: service Redis trong Docker lab, publish id cảnh báo từ `EventRepository.save_alert`, endpoint WebSocket `/api/alerts/ws`, client WebSocket dùng chung cho dashboard và trang Logs, poll dự phòng khi mất WebSocket, cập nhật BPF, cấu hình, test và tài liệu.
- **Ngoài phạm vi**:
  - Đẩy nguyên nội dung cảnh báo qua Redis hoặc WebSocket. Dữ liệu vẫn lấy qua REST.
  - Báo thao tác xoá cảnh báo sang tab khác. Các tab còn lại cập nhật ở lượt tải 30 giây.
  - Thông báo trình duyệt, âm thanh, toast.
  - Lưu bền Redis, Redis cluster, Redis Stream, replay tin đã lỡ.
  - Xác thực cho `/api/alerts/ws` và các endpoint đọc cảnh báo (hiện chưa có auth, xem mục 6).

## 4. Hiện trạng

- Mọi cảnh báo đều đi qua một chỗ: `EventRepository.save_alert` ([nids/db/repository.py:17](../../nids/db/repository.py#L17)), commit ở dòng 40.
  - Engine gọi từ `handle_alert` ([nids/engine/main.py:210](../../nids/engine/main.py#L210)) trong worker thread duy nhất xử lý gói. AI worker dùng cùng callback này.
  - Honeypot gọi từ `log_event` ([nids/honeypot/store.py:38](../../nids/honeypot/store.py#L38)).
  - Cả hai đã bọc `try/except`, nhưng chỉ bảo vệ khỏi exception, không bảo vệ khỏi việc bị chặn.
- Dashboard: `refresh()` ([dashboard.html:170](../../nids/api/static/dashboard.html#L170)) gọi 4 endpoint, `setInterval(refresh, 2000)` ở dòng 195, nhãn trạng thái ở dòng 167.
- Trang Logs: `load()` ([logs.html:200](../../nids/api/static/logs.html#L200)), checkbox `auto` ở dòng 58 và `setInterval(load, 5000)` ở dòng 262. Bộ lọc và phân trang nằm trong `load()`.
- `/api/alerts/timeline` tính cửa sổ theo `utc_now()` ([repository.py:158](../../nids/db/repository.py#L158)), nên biểu đồ cần được tải lại theo thời gian dù không có cảnh báo mới.
- `router` của cảnh báo ở [nids/api/routes/alerts.py:9](../../nids/api/routes/alerts.py#L9). Các endpoint đọc cảnh báo không có xác thực; CORS đang là `*` ([nids/api/main.py:55](../../nids/api/main.py#L55)).
- `get_db_url()` ([nids/config.py:26](../../nids/config.py#L26)) là mẫu cho việc đọc settings và cho biến môi trường ghi đè.
- `network.bpf_filter` ở [config/settings.example.yaml:11](../../config/settings.example.yaml#L11) chỉ loại 3306. Engine và honeypot dùng `network_mode: service:victim_app` nên engine thấy cả traffic Redis của chính nó và của honeypot.
- `tests/lab/test_compose_secrets.py:13` buộc mọi dòng `*PASSWORD:` trong compose dùng dạng `"${VAR:?...}"`.
- `websockets` và `uvicorn[standard]` đã có trong `requirements.txt`. Chưa có `redis`. Các IP đang dùng trong lab: `.10`, `.20`, `.50`, `.100`.
- Thư mục `rules/` không có rule nào nhắc tới Redis hay cổng 6379.

## 5. Các phương án đã cân nhắc

| Phương án | Ưu điểm | Nhược điểm | Kết luận |
| :-------- | :------ | :--------- | :------- |
| Redis pub/sub + WebSocket | Đúng gợi ý của issue, đẩy thật từ nguồn tới trình duyệt, đo được khoảng 20–40 ms từ publish tới WebSocket | Thêm service, dependency, mật khẩu, cổng trong BPF và đường lỗi mới | **Chọn**, người dùng chốt |
| API theo dõi `MAX(id)` của `events` mỗi 0,5 giây rồi báo qua WebSocket | Không thêm service, không sửa engine và honeypot | Server vẫn poll CSDL, trễ tới 0,5 giây | Loại, người dùng chọn Redis |
| Engine và honeypot gọi HTTP nội bộ vào API | Không thêm service | Cổng 8000 nằm trong `HTTP_PORTS`, engine sniff được nên nội dung cảnh báo có thể sinh alert lặp; phải có thêm auth | Loại, vì nguy cơ vòng lặp alert |
| Server-Sent Events thay WebSocket | `EventSource` tự nối lại | Issue yêu cầu WebSocket; luồng vô hạn khó test bằng `TestClient` | Loại |

## 6. Thiết kế đã chọn

```
engine / honeypot / AI
  └─ save_alert: commit CSDL ──► publish_alert(id): put_nowait, không chặn
                                   └─ daemon thread ──► Redis PUBLISH nids:alerts <id>
                                                          │
                     API: mỗi WebSocket một subscriber ◄──┘
                       └─ /api/alerts/ws gửi id ──► trình duyệt ──► load() qua REST như cũ
```

**Tin nhắn chỉ chứa `event.id`.** Redis chỉ là tín hiệu, CSDL vẫn là nguồn dữ liệu duy nhất:

- Giao diện dùng lại nguyên `refresh()` và `load()`, nên thống kê, biểu đồ, bộ lọc và phân trang của trang Logs vẫn đúng mà không viết lại logic ở phía trình duyệt.
- Traffic Redis không chứa chuỗi tấn công, nên kể cả `settings.yaml` local còn BPF cũ thì cũng không thể sinh vòng lặp alert.
- Endpoint WebSocket không xác thực nhưng chỉ lộ id, không mở thêm dữ liệu so với `GET /api/alerts`. Lý do này cũng là vì sao không cần kiểm tra `Origin`.
- Mất tin không làm mất dữ liệu: lượt tải 30 giây sẽ bù lại.

**Phía publish, `nids/realtime.py` (module mới):**

- `publish_alert(event_id)` chỉ `put_nowait` vào `queue.Queue(maxsize=QUEUE_SIZE)` rồi trả về; đầy thì bỏ. Một daemon thread khởi tạo lười (có lock vì honeypot SSH đa luồng) mới gọi `PUBLISH`.
- `publish_alert` không bao giờ ném lỗi, kể cả lỗi cấu hình hay không tạo được thread, vì nó chạy sau khi đã commit: lỗi lọt ra sẽ làm `handle_alert` ghi log "không thể lưu" trong khi cảnh báo đã vào CSDL.
- Không gọi Redis trực tiếp từ luồng xử lý gói. Spike đo được: Redis chết thì một lần `publish` chờ 13,9 giây với retry mặc định của redis-py 8, và vẫn 1 giây khi đã tắt retry. Gọi đồng bộ sẽ làm ngừng worker thread của engine.
- Client tạo với `socket_connect_timeout=1`, `socket_timeout=1`, `retry=Retry(NoBackoff(), 0)`. Lỗi publish thì log `WARNING`, bỏ tin, ngủ `RETRY_SECONDS = 5` để không tràn log.
- `import redis` đặt bên trong thread và bên trong route, không ở đầu module. Thành viên chạy `docker compose up` quên `--build` thì sensor vẫn chạy, chỉ mất tín hiệu.
- `get_redis_settings()` trả `None` khi `host` rỗng: `publish_alert` thành no-op và không tạo thread. Đây là mặc định khi chạy local và trong CI.

**Phía API, `@router.websocket("/ws")` trong `alerts.py`:**

- Mỗi WebSocket có một subscriber Redis riêng, giới hạn `MAX_WS_CLIENTS = 20`. Không cần hub, không đổi lifespan, client chậm chỉ ảnh hưởng chính nó.
- Client async đặt `socket_connect_timeout=1` và retry bằng 0, nhưng **không** đặt `socket_timeout`: `listen()` phải chờ được vô hạn khi không có cảnh báo.
- Thứ tự bắt buộc: `subscribe` → chờ xác nhận bằng `get_message(timeout=1)` (trả `None` coi như lỗi) → `ws.accept()`. Trình duyệt tải REST ở `onopen`, nên đăng ký trước khi accept mới không lỡ cảnh báo trong khoảng giữa. Spike đã tái hiện đúng lỗi này khi đặt lấy mốc sau `accept()`.
- Chạy song song hai task bằng `asyncio.wait(..., FIRST_COMPLETED)`: `relay` đọc `pubsub.listen()` rồi gửi id, `until_closed` lặp `ws.receive_text()` để phát hiện client ngắt. Hết thì huỷ task còn lại, đợi nó dừng, rồi `aclose()` pubsub và client.
- Redis tắt, Redis lỗi lúc subscribe, hoặc vượt giới hạn: `ws.close(code=1013)` trước `accept` (trình duyệt thấy handshake thất bại, HTTP 403). Redis chết giữa chừng: đóng WebSocket với 1013.
- Spike trên uvicorn thật với `redis:7-alpine` và redis-py 8.1.0: tín hiệu tới sau 20–40 ms, burst 5 tin đúng thứ tự, client đóng hoặc mất mạng đột ngột đều dọn subscriber về 0, Redis bị dừng thì WS đóng ngay với 1013, handshake khi Redis chết thất bại sau 1 giây.

**Phía trình duyệt, `static/live.js` (mới):** `liveAlerts(load, pollMs, onMode)` trả về hàm dừng.

- Bắt đầu ở chế độ poll `pollMs` và chỉ đổi khi `onopen`, nên kết nối đang treo vẫn có dữ liệu.
- `onopen`: gọi `load()`, giãn poll còn 30 giây, reset backoff.
- `onmessage`: gọi `load()`, gộp tối đa 2 lần mỗi giây. Tin đầu chạy ngay, các tin trong lúc đang tải gộp thành một lần chạy sau đó.
- `onclose`: quay về poll `pollMs`, nối lại với backoff 5 giây tăng dần tới 60 giây (local không có Redis không sinh log mỗi 5 giây mãi mãi). Hàm dừng phải chặn được việc nối lại.
- Lượt 30 giây vẫn cần giữ: cửa sổ timeline trượt theo giờ, tab khác xoá cảnh báo không phát tín hiệu, và bù tin bị mất. Cảnh báo mới không phụ thuộc vào lượt này.

**Redis trong compose:** không `ports:`, chỉ trong mạng lab tại `172.28.0.30`, bắt buộc mật khẩu từ `.env`, không lưu bền. Không đặt `depends_on: redis` ở engine, honeypot, API, vì Redis không được là điều kiện để sensor khởi động; publisher và client tự thử lại. Đã thử `docker compose config`: lệnh tách đúng `--save ""`, và compose từ chối chạy khi thiếu mật khẩu.

**BPF:** dùng `ip and not port 3306 and not (host 172.28.0.30 and port 6379)`, đã biên dịch được bằng `tcpdump -d` trong image `hybrid-nids-app`. Chỉ loại traffic tới đúng máy Redis, không loại cả cổng 6379, để đòn quét hoặc tấn công vào cổng 6379 của victim vẫn được engine nhìn thấy.

## 7. Thay đổi cần làm

| File | Thay đổi | Dùng lại |
| :--- | :------- | :------- |
| `requirements.txt` | Thêm `redis>=8.1.0` (bản đã spike) | |
| `config/settings.example.yaml` | Thêm mục `redis` (`host: ""`, `port`, `password: ""`); đổi `bpf_filter` theo mục 6, sửa comment | |
| `nids/config.py` | Thêm `get_redis_settings()`, đọc `NIDS_REDIS_HOST/PORT/PASSWORD` ghi đè settings | Mẫu `get_db_url()` |
| `nids/realtime.py` (mới) | `CHANNEL`, `publish_alert`, daemon thread publish, hàm tạo client async cho API | `get_redis_settings()` |
| `nids/db/repository.py` | `save_alert` gọi `publish_alert(event.id)` sau `session.refresh(event)` | `save_alert` là điểm chung, không cần sửa engine và honeypot |
| `nids/api/routes/alerts.py` | Thêm `@router.websocket("/ws")`, `MAX_WS_CLIENTS`, logger `nids.api` | `router` có sẵn |
| `nids/api/static/live.js` (mới) | `liveAlerts(load, pollMs, onMode)` | Mẫu nạp `charts.js` |
| `nids/api/static/dashboard.html` | Nạp `live.js`, thay `setInterval` dòng 195 bằng `liveAlerts(refresh, 2000, ...)`, nhãn trạng thái theo chế độ: "Đã kết nối – cập nhật tức thì", "Đã kết nối – tự làm mới mỗi 2 giây", "Mất kết nối tới API" | `refresh()` |
| `nids/api/static/logs.html` | Nạp `live.js`; checkbox `auto` bật thì `liveAlerts(load, 5000, ...)`, tắt thì gọi hàm dừng; đổi nhãn thành "Tự làm mới" | `load()` |
| `docker-compose.yml` | Thêm service `redis` (`redis:7-alpine`, `container_name: nids_redis`, `172.28.0.30`, `--requirepass "${NIDS_REDIS_PASSWORD:?đặt trong .env}"`, `--save ""`, `--appendonly no`); thêm `NIDS_REDIS_HOST` và `NIDS_REDIS_PASSWORD` cho `nids_engine`, `nids_api` và anchor `&nids_db_env`; sửa comment dòng 101–102 | Mẫu `mysql_db` |
| `.env.example` | Thêm `NIDS_REDIS_PASSWORD=` kèm comment | |

Tài liệu cần cập nhật:

- `CLAUDE.md`: Tech Stack, Project Structure (`nids/realtime.py`), Rules và Known Issues (thêm 6379 vào BPF), Common Commands, bỏ dòng "Chưa triển khai: Redis pub/sub, WebSocket alert", sửa dòng 76.
- `.claude/rules/api-web.md`: endpoint `/api/alerts/ws`, `live.js`.
- `.claude/rules/config-db-docker.md`: mục `redis`, service Redis, BPF, sửa dòng 30.
- `.claude/rules/logging.md`: thêm khu vực `realtime`.
- `README.md`: dòng 162 (BPF), 180 (biến môi trường), bảng service quanh dòng 260, dòng 267–270 (`.env`), 286–287.
- `docs/demo/kich-ban-demo.md:3` và `docs/demo/bao-cao-demo-honeypot.md:22`: thêm Redis `172.28.0.30`.

## 8. Kiểm thử

Test dùng client giả, không cần Redis thật và không thêm `fakeredis`, vì CI không có service Redis. `TestClient.receive_text()` không có timeout và CI không có `pytest-timeout`, nên viết helper nhận tin có timeout bằng daemon thread để test lỗi thì fail thay vì treo CI.

| Test | Kiểm tra điều gì |
| :--- | :--------------- |
| `tests/test_realtime.py` | Redis tắt: `publish_alert` là no-op, không tạo thread. Client giả có `publish` chặn lâu: `publish_alert` vẫn trả về ngay. Queue đầy: không ném lỗi. `publish` ném lỗi: thread sống tiếp và gửi được tin sau (`RETRY_SECONDS` patch về 0). |
| `tests/api/test_realtime_ws.py` | Tin từ pubsub giả tới được WebSocket, bỏ qua tin không phải `message`. Redis tắt, subscribe lỗi, không nhận được xác nhận subscribe, thiếu thư viện `redis`: đóng 1013 trước accept. `listen()` ném lỗi giữa chừng: đóng 1013. Client thứ 21 bị từ chối, nối lại được sau khi client khác đóng. Client ngắt: `aclose()` được gọi, bộ đếm về 0. Thứ tự `subscribe` trước `accept`. `save_alert` publish đúng id đã commit; `log_event` của honeypot cũng publish; `publish_alert` lỗi không làm `save_alert` lỗi. |
| `tests/api/test_api_dashboard.py` | `/static/live.js` phục vụ được; `dashboard.html` và `logs.html` nạp `live.js`. |
| `tests/test_config.py` | `get_redis_settings()` trả `None` khi host rỗng, biến môi trường ghi đè; file mẫu không có mật khẩu Redis, BPF loại 3306 và `172.28.0.30:6379`. |
| `tests/lab/test_compose_secrets.py` | Có `${NIDS_REDIS_PASSWORD:?`; service `redis` không có `ports:`. |

Lệnh: `pytest tests/test_realtime.py tests/api tests/test_config.py tests/lab/test_compose_secrets.py`, sau đó chạy toàn bộ `pytest`.

## 9. Xác minh end-to-end

Điều kiện: đã thêm `NIDS_REDIS_PASSWORD` vào `.env`.

1. `docker compose config -q` không lỗi, rồi `docker compose up --build -d`. `docker compose ps` thấy `nids_redis` chạy.
2. Không có mật khẩu thì không dùng được Redis từ máy tấn công: `docker exec nids_attacker python -c "import socket; s=socket.create_connection(('172.28.0.30',6379)); s.sendall(b'PING\r\n'); print(s.recv(64))"` phải in `-NOAUTH`.
3. Mở http://localhost:8000/, nhãn hiện "Đã kết nối – cập nhật tức thì". Tab Network: khi không có cảnh báo, một lượt tải mỗi 30 giây.
4. Đo độ trễ từ máy host, kết quả không quá 1000 ms (gồm cả thời gian khởi động `docker exec`). Nếu không nhận được tin, đợi hết cửa sổ của `ThresholdManager` rồi chạy lại.

   ```python
   import asyncio, subprocess, time, websockets

   async def main():
       async with websockets.connect("ws://localhost:8000/api/alerts/ws") as ws:
           t0 = time.perf_counter()
           subprocess.run(["docker", "exec", "nids_attacker", "curl", "-s", "-o", "/dev/null",
                           "http://172.28.0.50/?id=1+union+select+1"])
           await asyncio.wait_for(ws.recv(), 3)
           print(f"{(time.perf_counter() - t0) * 1000:.0f} ms")

   asyncio.run(main())
   ```

5. `docker exec nids_attacker python lab/attacker/attack_demo.py web` và nhóm `honeypot`: cả hai nguồn đều hiện gần như tức thì trên dashboard, và trên trang Logs khi bật "Tự làm mới", bộ lọc đang đặt vẫn được giữ.
6. Lỗi Redis: `docker stop nids_redis`. Nhãn đổi thành "tự làm mới mỗi 2 giây", chạy lại `web` thì cảnh báo vẫn hiện trong khoảng 2 giây, `docker logs nids_engine` chỉ có `WARNING` thưa, không traceback, engine và honeypot vẫn `Up`. `docker start nids_redis`: nhãn về "cập nhật tức thì" trong tối đa 60 giây.
7. Không có vòng lặp và không lẫn traffic Redis: sau bước 5, trong `flows` không có dòng `dst_port = 6379`, và số dòng `events` đứng yên khi ngừng tấn công.
8. Chạy local không Redis: `sqlite`, `redis.host` rỗng, `uvicorn nids.api.main:app`. Dashboard ở chế độ poll 2 giây, log API không bị spam.

## 10. Rủi ro và ảnh hưởng tới nhóm

| Rủi ro | Mức độ | Cách xử lý |
| :----- | :----- | :--------- |
| Redis chậm hoặc chết làm chậm sensor | Cao | Publish ở daemon thread, queue có giới hạn, `put_nowait`, retry bằng 0; có test client chặn và bước 6 mục 9 |
| `settings.yaml` local còn BPF cũ, engine sniff traffic Redis | Vừa | Tin chỉ chứa id nên không thể sinh alert lặp, chỉ sinh thêm dòng `flows`; báo nhóm sửa, kiểm tra ở bước 7 mục 9 |
| Container `attacker` cùng mạng với Redis | Vừa | Bắt buộc mật khẩu, không publish cổng ra host, tin không chứa dữ liệu. Giữ nguyên hiện trạng lab: `attacker` mount repo vào `/app` nên đọc được `.env`, giống mật khẩu MySQL hiện tại |
| Mở nhiều WebSocket chiếm tài nguyên API | Thấp | Giới hạn 20 kết nối; không xác thực, giống các endpoint đọc hiện có |
| Bão cảnh báo làm trình duyệt tải liên tục, nặng nhất ở `get_timeline` | Vừa | Gộp tối đa 2 lần/giây, khoảng 4 lần tải mỗi tab so với hiện tại nhưng chỉ khi đang có cảnh báo, và `ThresholdManager` đã giảm bão; nếu nặng thì tăng khoảng gộp lên 1 giây trong `live.js` |
| Mất tin khi Redis restart hoặc khi queue đầy | Thấp | Pub/sub không lưu tin; CSDL không mất gì, lượt 30 giây bù lại |

**Thành viên khác cần làm gì**:

- Thêm `NIDS_REDIS_PASSWORD` (chuỗi hex) vào `.env`, nếu không compose từ chối khởi động.
- Chạy `docker compose up --build` để image có `redis`; chạy `pip install -r requirements.txt` nếu chạy ngoài Docker.
- Ai có `config/settings.yaml` thì sửa `bpf_filter` thành `ip and not port 3306 and not (host 172.28.0.30 and port 6379)`.

## 11. Các bước thực hiện

Nhánh: `feature/30-realtime-alert-push`, tạo từ `main` sau khi nhánh `chore/claude-planning-workflow` (chứa `docs/plans/`) đã merge.

- [x] Thêm `redis` vào `requirements.txt`, `get_redis_settings()`, mục `redis` và BPF trong file mẫu, kèm test cấu hình
- [x] Viết `nids/realtime.py` kèm `tests/test_realtime.py`
- [x] Gọi `publish_alert` trong `save_alert`, kèm test engine và honeypot cùng đi qua đường này
- [x] Thêm route `/api/alerts/ws` kèm `tests/api/test_realtime_ws.py`
- [x] Viết `static/live.js`, sửa `dashboard.html` và `logs.html`, kèm test phục vụ file
- [x] Thêm service Redis và biến môi trường vào `docker-compose.yml`, `.env.example`, kèm test compose
- [x] Cập nhật tài liệu ở mục 7
- [x] Chạy `pytest` (285 passed, 34 skipped), xác minh theo mục 9 trong lab thật bằng WebSocket client và container tạm thay `attacker` (image Kali không build được: BuildKit sập vì thiếu RAM). Chưa xem bằng trình duyệt thật
- [x] Tạo PR ([#57](https://github.com/74Teams/hybrid-nids/pull/57)), cập nhật bảng tổng hợp

## 12. Quyết định và nhật ký

**Quyết định**

| Ngày | Quyết định | Người chốt | Lý do |
| :--- | :--------- | :--------- | :---- |
| 2026-11-01 | Dùng Redis pub/sub, không dùng cách API theo dõi `MAX(id)` | Người dùng | Đúng định hướng của issue #30 |
| 2026-11-01 | Tin chỉ chứa id, dữ liệu vẫn lấy qua REST | Claude | Dùng lại `refresh()`/`load()`, không lộ thêm dữ liệu, không thể sinh alert lặp |
| 2026-11-01 | Publish trong `save_alert`, không sửa `handle_alert` và `log_event` | Claude | Một điểm chung cho engine, honeypot và AI |
| 2026-11-01 | Publish qua daemon thread, queue giới hạn, retry bằng 0 | Claude | Spike đo được publish chờ tới 13,9 giây khi Redis chết |
| 2026-11-01 | Mỗi WebSocket một subscriber, giới hạn 20, không làm hub | Claude | Ít code nhất; đủ cho demo và không đổi lifespan |
| 2026-11-01 | Subscribe và chờ xác nhận trước `accept` | Claude | Spike tái hiện được lỗi lỡ cảnh báo nếu làm ngược lại |
| 2026-11-01 | Giữ poll dự phòng và lượt tải 30 giây | Claude | Redis là phụ trợ, không được làm mất cảnh báo trên giao diện; timeline trượt theo giờ |
| 2026-11-01 | `redis.host` rỗng là tắt; không `depends_on: redis`; import `redis` lười | Claude | Local, CI và sensor không phụ thuộc Redis |
| 2026-11-01 | Không thêm `fakeredis`, test bằng client giả | Claude | Không thêm dependency cho vài lớp giả nhỏ |
| 2026-11-01 | BPF chỉ loại `172.28.0.30:6379`, không loại cả cổng 6379 | Claude | IDS không bị mù với đòn nhắm vào cổng 6379 của victim |
| 2026-11-01 | Ô "Tự làm mới" của trang Logs mặc định bật (bổ sung sau khi người dùng thử trên Chrome) | Claude | Để tắt thì trang không mở WebSocket, cảnh báo mới chỉ hiện khi tải lại |
| 2026-11-01 | Bỏ bước phản biện bằng `plan-critic` cho plan này | Người dùng | Subagent quá tốn thời gian và token |
| 2026-11-01 | Khi publish lỗi, bỏ cả backlog trong hàng đợi thay vì thử lại từng tin (bổ sung lúc làm) | Claude | Smoke test thật cho thấy tin cũ từ lúc Redis chết bị xả ra sau khi phục hồi, mỗi tin lỗi tốn thêm 5 giây ngủ; tin chỉ là gợi ý "có thay đổi" |

**Câu hỏi còn mở**: Không

**Kết quả phản biện**: Không có phản biện độc lập. `plan-critic` bị dừng giữa chừng, không trả kết quả, và người dùng đã bỏ bước này. Claude tự rà lại plan và kiểm chứng bằng spike thật: relay Redis sang WebSocket, lệnh compose, biên dịch BPF.
