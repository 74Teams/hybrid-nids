---
type: PLAN
plan_id: PLAN-004
title: Chuyển hướng traffic của IP đáng ngờ sang honeypot
status: IN_PROGRESS
issue: 29
owner: Vo Ngoc Cu (ngoccu2006)
created: 2026-11-01
updated: 2026-11-01
---

# PLAN-004: Chuyển hướng traffic của IP đáng ngờ sang honeypot

## 1. Bối cảnh

Honeypot hiện chỉ nhận kết nối gửi thẳng tới cổng 2222 và 8080, nên attacker nhắm vào dịch vụ thật của victim (SSH cổng 22, HTTP cổng 80) không bao giờ chạm honeypot. NIDS đã biết IP nào đang tấn công (cảnh báo rule engine) nhưng chưa dùng thông tin đó để phản ứng. Yêu cầu đến từ issue #29 (nmchien1106 tạo, ngoccu2006 nhận, priority thấp): thiết kế cách chuyển hướng IP bị đánh dấu sang honeypot và demo trong Docker. Đây cũng là điểm nhấn "hybrid" khi trình diễn: cùng một attacker, sau vài cảnh báo, bị dẫn sang honeypot ngay giữa buổi demo. `docs/demo/bao-cao-demo-honeypot.md:166` và `.claude/rules/honeypot.md` đều ghi mục này là "chưa làm".

## 2. Mục tiêu và tiêu chí thành công

- **Mục tiêu**: IP gây đủ số cảnh báo mức cao trong một cửa sổ thời gian bị tự động chuyển hướng các kết nối **mới** tới SSH (22) và HTTP (80) của victim sang honeypot (2222, 8080) trong một khoảng TTL, rồi tự được gỡ.
- **Xong khi**:
  - Từ attacker, trước khi bị đánh dấu: `nc 172.28.0.50 22` trả banner OpenSSH của victim (Debian); sau khi chạy `attack_demo.py web`: cùng lệnh trả banner của honeypot (`SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13`), `curl http://172.28.0.50/` trả trang login WordPress giả thay vì trang nginx.
  - Sự kiện honeypot của IP đó xuất hiện trên `/logs` với đúng IP attacker (IP nguồn không bị đổi).
  - Hết TTL, kết nối mới tới cổng 22 và 80 lại tới dịch vụ thật; chain iptables không còn rule của IP đó.
  - IP trong allowlist (MySQL, API, Redis, victim) không bao giờ bị chuyển hướng dù đủ ngưỡng.
  - `GET /api/redirects` liệt kê các IP đang bị chuyển hướng và thời điểm hết hạn.
  - Lỗi iptables, lỗi CSDL hay chạy ngoài Docker không làm engine hay honeypot dừng; redirector chỉ log.

## 3. Phạm vi

- **Trong phạm vi**: process mới `nids/redirector` (chính sách chọn IP, bọc iptables, vòng lặp, dọn khi dừng), bảng `redirects`, cấu hình mục `redirect`, service `nids_redirector` trong compose, thêm gói `iptables` vào image, endpoint chỉ đọc `GET /api/redirects`, test, cập nhật tài liệu và kịch bản demo.
- **Ngoài phạm vi**:
  - Chặn (DROP/REJECT) thay vì dẫn dụ.
  - Chuyển hướng FTP (21) và các cổng khác; ánh xạ cổng cấu hình được nhưng mặc định chỉ 22 và 80.
  - Tiêu chí đánh dấu dựa trên sự kiện honeypot (`ssh.bruteforce`) hay AI worker.
  - Giao diện dashboard hiển thị danh sách chuyển hướng (chỉ làm API).
  - Gỡ hay thêm IP thủ công qua API, vì cần xác thực ghi và thiết kế thêm.
  - Chuyển hướng kết nối đang mở: iptables chỉ áp cho kết nối mới.
  - IPv6.
  - Chạy ngoài Docker (iptables chỉ có trong lab Linux).

## 4. Hiện trạng

- Engine, `victim_app` (nginx:80, sshd:22, vsftpd), `honeypot_ssh` và `honeypot_http` dùng chung một network namespace qua `network_mode: service:victim_app` ([docker-compose.yml:55](../../docker-compose.yml#L55), [docker-compose.yml:82](../../docker-compose.yml#L82), [docker-compose.yml:105](../../docker-compose.yml#L105)). Honeypot nghe `0.0.0.0` cổng 2222 và 8080 ([nids/honeypot/settings.py:21](../../nids/honeypot/settings.py#L21)), nên một rule `REDIRECT` trong namespace này đưa được kết nối tới honeypot.
- `nids_engine` có `cap_add: NET_ADMIN` ([docker-compose.yml:56](../../docker-compose.yml#L56)); repo chưa có đoạn code hay package nào gọi iptables, và `Dockerfile` chưa cài `iptables`.
- Cảnh báo rule engine được lưu vào `events` với `source_type="RULE_ENGINE"` và `severity` 1–3 qua `handle_alert` ([nids/engine/main.py:218](../../nids/engine/main.py#L218)) và `EventRepository.save_alert` ([nids/db/repository.py:19](../../nids/db/repository.py#L19)). Mọi thứ cần để chọn "IP đáng ngờ" đã nằm trong bảng `events`, nên không cần sửa engine.
- Mẫu cần dùng lại: `EventRepository.honeypot_attacker_ips` truy vấn IP theo cửa sổ thời gian ([nids/db/repository.py:167](../../nids/db/repository.py#L167)); `HoneypotIPCache` cache có TTL ([nids/engine/main.py:185](../../nids/engine/main.py#L185)); `utc_now()` ([nids/db/models.py:9](../../nids/db/models.py#L9)).
- Bảng mới được `create_all` tự tạo trong `init_db`, không cần `_add_missing_columns` ([nids/db/__init__.py:35](../../nids/db/__init__.py#L35)). Cả ba process cùng gọi `init_db` khi khởi động; process mới cũng phải gọi.
- Engine sniff `eth0` bằng AF_PACKET, thấy gói **trước** khi NAT PREROUTING đổi cổng, nên vẫn thấy kết nối tới cổng 22/80 gốc và vẫn sinh cảnh báo rule như thường. Sự kiện honeypot cũng được ghi song song.
- `network.bpf_filter` đã loại 3306 và Redis; redirector chỉ kết nối MySQL (cổng 3306), nên không cần đổi filter.
- `honeypot_attacker_ips` và `enrich_alert` đã dùng IP chạm honeypot để nâng priority; hai cơ chế này độc lập với chuyển hướng.
- `.claude/rules/lab-demo.md`: `tests/lab/test_attack_demo.py` duyệt `GROUPS`; plan này không thêm rule hay nhóm đòn mới nên không đụng test đó.
- Quy tắc dự án liên quan: "DB chỉ lưu dữ liệu quan sát được" (CLAUDE.md), "lỗi ghi CSDL không được làm sập sensor", và Redis/đường phụ trợ không được chặn hay làm lỗi sensor. Xem quyết định ở mục 12.

## 5. Các phương án đã cân nhắc

**Tiêu chí "đáng ngờ"**

| Phương án | Ưu điểm | Nhược điểm | Kết luận |
| :-------- | :------ | :--------- | :------- |
| A. Một cảnh báo P1/P2 là đủ | Đơn giản, phản ứng tức thì | Một false positive chuyển hướng nhầm người dùng hợp lệ | Loại |
| B. Đủ N cảnh báo P1/P2 trong T giây | Giảm nhầm, đếm thẳng từ `events`, không sửa engine | Thêm một truy vấn `GROUP BY` mỗi chu kỳ | Chọn |
| C. Thêm sự kiện honeypot vào điều kiện | Phản ánh hành vi thật hơn | Honeypot chỉ thấy IP đã tới nó, không giúp dẫn IP chưa tới | Loại, để lần sau |

**Cơ chế chuyển hướng**

| Phương án | Ưu điểm | Nhược điểm | Kết luận |
| :-------- | :------ | :--------- | :------- |
| 1. iptables `REDIRECT` trong namespace victim | Đúng cấu trúc lab, phủ cả SSH và HTTP, giữ IP nguồn, không đổi mạng | Cần `NET_ADMIN`, image thêm `iptables`, chỉ Linux | Chọn |
| 2. Reverse proxy theo IP | Không cần quyền kernel | Chỉ HTTP, phải thay nginx của victim | Loại |
| 3. ARP/route/SDN | Gần mạng thật | Quá nặng cho đồ án | Loại |

**Ai áp iptables**

| Phương án | Ưu điểm | Nhược điểm | Kết luận |
| :-------- | :------ | :--------- | :------- |
| Engine tự áp | Không thêm service | Gắn thao tác firewall vào worker thread phát hiện; lỗi dễ ảnh hưởng sensor; vi phạm "mỗi process một việc" | Loại |
| Process `nids_redirector` riêng | Cô lập quyền và lỗi, engine không đổi, khởi động lại độc lập | Thêm một service và một lần build image | Chọn |

**Nơi lưu danh sách**

| Phương án | Ưu điểm | Nhược điểm | Kết luận |
| :-------- | :------ | :--------- | :------- |
| Bảng `redirects` trong CSDL | Truy vấn được từ API, sống qua restart redirector, có lịch sử | Thêm bảng (không phải "dữ liệu quan sát") | Chọn, người dùng chốt |
| Redis | Nhanh | Mất khi restart, Redis là phụ trợ tuỳ chọn | Loại |
| File trong `rules/` | Không động tới DB | Trái quy tắc "rule chỉ ở `rules/`", trộn state với rule | Loại |

## 6. Thiết kế đã chọn

```
events (RULE_ENGINE, P1/P2) ──┐
                              ▼
        nids_redirector  (network_mode: service:victim_app, NET_ADMIN)
          mỗi poll_interval giây:
            1. suspicious_ips(window, min_alerts, max_priority)      ← bảng events
            2. bỏ IP trong allowlist / IP đang bị chuyển hướng
            3. add_redirect(ip, expires_at)  → bảng redirects
               firewall.add(ip)              → iptables -t nat chain NIDS_REDIRECT
            4. expire: redirects.expires_at <= now → firewall.remove(ip), removed_at = now
          khi khởi động: flush chain, nạp lại các dòng chưa hết hạn từ redirects
          khi nhận SIGTERM/SIGINT: flush chain

iptables -t nat:
  PREROUTING  → -j NIDS_REDIRECT
  NIDS_REDIRECT: -s <ip> -p tcp --dport 22 -j REDIRECT --to-ports 2222
                 -s <ip> -p tcp --dport 80 -j REDIRECT --to-ports 8080

GET /api/redirects → các dòng redirects còn hiệu lực
```

- **Chọn IP (tiêu chí B)**: `EventRepository.suspicious_ips(window_seconds, min_alerts, max_priority)` đếm `events` có `source_type="RULE_ENGINE"`, `severity <= max_priority`, `timestamp >= now - window`, `GROUP BY src_ip HAVING count >= min_alerts`. Mặc định `window_seconds=60`, `min_alerts=5`, `max_priority=2`. Sự kiện HONEYPOT không được đếm.
- **Không đổi engine**: redirector chỉ đọc `events`, nên độ trễ phản ứng là `poll_interval` (mặc định 5 giây) cộng thời gian ghi alert. Đủ cho demo, chấp nhận.
- **TTL**: mặc định 600 giây. IP đang bị chuyển hướng không được gia hạn trong khi còn hiệu lực. Hết hạn mà vẫn đủ ngưỡng trong cửa sổ mới thì bị thêm lại ở chu kỳ sau, nên attacker vẫn hoạt động liên tục sẽ liên tục bị dẫn; các cảnh báo cũ phát sinh trước khi bị chuyển hướng (nằm ngoài cửa sổ mới) không làm bị thêm lại.
- **Allowlist**: `redirect.allowlist` gồm IP/CIDR, mặc định `127.0.0.0/8`, `172.28.0.1` (gateway), `172.28.0.10` (MySQL), `172.28.0.20` (API), `172.28.0.30` (Redis), `172.28.0.50` (victim). Kiểm tra bằng `ipaddress`, IP sai định dạng hoặc ngoài allowlist-check đều bị bỏ kèm log, không bao giờ ném lỗi ra vòng lặp.
- **iptables an toàn**: `IptablesFirewall` gọi `subprocess.run([...], shell=False, timeout=5)` với argv dựng sẵn; chỉ nhận chuỗi đã qua `ipaddress.ip_address()` (kể cả IPv4 từ DB, vì `src_ip` đến từ gói tin); dùng `-w` để chờ khoá xtables. Chain riêng `NIDS_REDIRECT` nên flush không động tới rule khác. Lệnh nhận `runner` tiêm vào để test không cần iptables thật. Không có đường nào chạy input của attacker.
- **Tự sửa khi bị xoá ngoài ý muốn**: đầu mỗi `run_once`, `firewall.ensure_setup()` kiểm tra chain và jump `PREROUTING → NIDS_REDIRECT` bằng `-C`, thiếu thì tạo lại, rồi đối chiếu rule của các IP đang hiệu lực và thêm lại rule bị mất. Nhờ vậy `iptables -t nat -F` từ bên ngoài chỉ làm gián đoạn tối đa một `poll_interval`.
- **Idempotent và dọn**: thêm rule dùng `-C` kiểm tra trước khi `-A`; khởi động luôn flush rồi nạp lại từ bảng `redirects` (dòng có `removed_at IS NULL` và chưa hết hạn), nên crash hay `docker compose restart` không để lại rule mồ côi. SIGTERM flush chain và đánh dấu `removed_at` các dòng đang hiệu lực.
- **Lỗi**: lỗi iptables hoặc CSDL trong một chu kỳ chỉ `logger.error`, vòng lặp chạy tiếp ở chu kỳ sau. Nếu không gọi được `iptables` lúc khởi động (không có binary, thiếu quyền), process ghi `ERROR` rồi thoát với **mã 1** vì nó không còn tác dụng; `restart: unless-stopped` không được đặt cho service này để không lặp vô hạn.
- **Bật/tắt**: `redirect.enabled` mặc định `false` trong code, `true` trong `settings.example.yaml`. Khi `enabled=false` (ví dụ `settings.yaml` cũ không có mục `redirect`) process ghi `WARNING` hướng dẫn rồi thoát với **mã 0**; đây là trạng thái bình thường, không phải lỗi. Vì repo được mount vào `/app`, thành viên có `settings.yaml` cũ sẽ thấy container `nids_redirector` thoát ngay sau `docker compose up`.
- **Cấu hình `ports`**: ánh xạ `cổng gốc: cổng honeypot`, ví dụ `22: 2222`; `get_redirect_settings()` kiểm tra mọi cổng nằm trong 1–65535 và các tham số số là số dương, sai thì ghi `ERROR` và dùng mặc định (giống `http_ports()`).
- **Bảng `redirects`**: `id`, `ip` (String(45), index), `created_at`, `expires_at` (index), `removed_at` (nullable), `alert_count`, `reason` (Text). Toàn bộ thời gian là UTC naive, dùng `utc_now()`. Là nhật ký hành động của hệ thống, không phải rule; xem mục 12 về việc sửa CLAUDE.md.
- **API**: `GET /api/redirects?active=true` (mặc định) trả các dòng đang hiệu lực, `active=false` trả cả lịch sử gần nhất (giới hạn 200). Chỉ đọc, không xác thực, cùng mức dữ liệu với `GET /api/alerts`. Dùng `iso_utc` cho thời gian.
- **Hiệu ứng lên NIDS**: engine vẫn thấy gói tới cổng 22/80 gốc nên vẫn sinh cảnh báo rule; honeypot ghi thêm sự kiện HONEYPOT, `enrich_alert` nâng priority các cảnh báo sau đó như hiện nay. Đây là hành vi mong muốn (bằng chứng đầy đủ), không phải vòng lặp: redirector đọc `events`, không ghi `events`.
- **Kết nối đang mở**: không đổi (conntrack giữ NAT cũ); chỉ kết nối mới bị chuyển hướng. Ghi rõ trong tài liệu.

## 7. Thay đổi cần làm

| File | Thay đổi | Dùng lại |
| :--- | :------- | :------- |
| `nids/redirector/__init__.py` | Package mới | |
| `nids/redirector/firewall.py` | `IptablesFirewall` (`setup`, `add`, `remove`, `flush`) với `runner` tiêm vào, kiểm tra IP | |
| `nids/redirector/service.py` | `RedirectPolicy` (allowlist, chọn IP) và `Redirector.run_once()` / `run()`, xử lý tín hiệu dừng | `EventRepository`, `utc_now` |
| `nids/redirector/__main__.py` | Điểm vào `python -m nids.redirector`: `setup_logging`, `init_db`, đọc cấu hình, chạy vòng lặp | `setup_logging`, `init_db` |
| `nids/db/models.py` | Thêm `RedirectModel` (bảng `redirects`) | `Base`, `utc_now` |
| `nids/db/repository.py` | `suspicious_ips`, `add_redirect`, `active_redirects`, `expire_redirects`, `list_redirects` | Mẫu `honeypot_attacker_ips` |
| `nids/config.py` | `get_redirect_settings()` trả dataclass có mặc định, kiểm tra kiểu | Mẫu `get_redis_settings()` |
| `nids/api/routes/redirects.py`, `nids/api/main.py` | Router `GET /api/redirects` | Mẫu `routes/alerts.py` |
| `config/settings.example.yaml` | Mục `redirect` (`enabled`, `window_seconds`, `min_alerts`, `max_priority`, `ttl_seconds`, `poll_interval`, `ports`, `allowlist`) kèm comment tiếng Việt | |
| `Dockerfile` | Thêm gói `iptables` vào `apt-get install` | |
| `docker-compose.yml` | Service `nids_redirector`: image dùng chung, `network_mode: service:victim_app`, `cap_add: NET_ADMIN`, `depends_on` MySQL healthy và victim, `environment: *nids_db_env`, `stop_grace_period: 10s`, không `restart` | Anchor `*nids_db_env` |
| `tests/redirector/conftest.py` | Fixture CSDL SQLite trong bộ nhớ (`memory_db`) riêng cho khu vực này, vì fixture cùng tên chỉ nằm trong `tests/honeypot/test_honeypot.py:22`, không dùng chung được | Cách dựng của `memory_db` ở `tests/honeypot/test_honeypot.py:21` |
| `tests/redirector/test_firewall.py`, `test_service.py`, `test_repository.py`, `test_config.py`, `test_main.py` | Test mới (mục 8) | |
| `tests/api/test_api_dashboard.py` | Test endpoint `redirects` | Fixture `client` |
| `tests/api/test_db_init.py` | Kiểm tra bảng `redirects` được tạo; stub nếu cần | |

Tài liệu cần cập nhật: `CLAUDE.md` (cấu trúc thư mục, danh sách process, câu "DB chỉ lưu dữ liệu quan sát được", "Current Focus"), `.claude/rules/honeypot.md` (bỏ "chuyển hướng traffic đáng ngờ" khỏi "Chưa làm"), `.claude/rules/config-db-docker.md` (bảng `redirects`, mục `redirect`, service mới), `.claude/rules/logging.md` (khu vực `redirector`), `.claude/rules/api-web.md` (endpoint mới), tạo `.claude/rules/redirector.md` (có `paths:` cho `nids/redirector/**` và `tests/redirector/**`), `README.md`, `docs/demo/kich-ban-demo.md` (bước chuyển hướng), `docs/demo/bao-cao-demo-honeypot.md` (dòng 166).

## 8. Kiểm thử

| Test | Kiểm tra điều gì |
| :--- | :--------------- |
| `tests/redirector/test_firewall.py` | Với `runner` giả: `setup` tạo chain và jump, không tạo lặp khi gọi lại; `add` sinh đúng argv cho từng cặp cổng, dùng `-C` trước `-A`; `remove` gỡ đúng IP; `flush` gọi `-F`; từ chối IP sai định dạng, chuỗi có dấu cách/`;`/xuống dòng, IPv6, không bao giờ chạy lệnh; `runner` ném lỗi hoặc trả mã khác 0 thì ném `FirewallError`, không phải lỗi khác |
| `tests/redirector/test_service.py` | CSDL SQLite trong bộ nhớ: đủ `min_alerts` trong cửa sổ thì IP bị thêm đúng một lần; thiếu một cảnh báo, ngoài cửa sổ, `severity` 3, hoặc `source_type="HONEYPOT"` thì không; IP trong allowlist (đơn và CIDR) không bao giờ bị thêm; hết TTL thì bị gỡ và `removed_at` được đặt; khởi động lại nạp lại dòng chưa hết hạn và bỏ dòng đã hết hạn; lỗi firewall hoặc CSDL ở một chu kỳ không làm `run_once` ném lỗi và chu kỳ sau vẫn chạy; tín hiệu dừng flush chain |
| `tests/redirector/test_service.py` (bổ sung) | Chain hoặc jump bị xoá giữa hai chu kỳ thì `run_once` tạo lại và thêm lại rule của IP đang hiệu lực |
| `tests/redirector/test_repository.py` | `suspicious_ips` đúng ngưỡng, cửa sổ, mức priority, nguồn sự kiện; vòng đời `add_redirect` → `active_redirects` → `expire_redirects`; `list_redirects` giới hạn 200 |
| `tests/redirector/test_config.py` | `get_redirect_settings()` trả mặc định khi thiếu mục; cổng ngoài 1–65535, tham số âm hoặc sai kiểu thì dùng mặc định kèm `ERROR`; allowlist sai định dạng bị bỏ kèm log |
| `tests/redirector/test_main.py` | `enabled=false` thoát mã 0 kèm `WARNING`; `iptables` không dùng được (runner giả ném lỗi) thoát mã 1 kèm `ERROR`, không traceback; không gọi `init_db` thật |
| `tests/api/test_api_dashboard.py` | `GET /api/redirects` chỉ trả dòng đang hiệu lực, `active=false` trả cả đã gỡ, thứ tự mới đến cũ, thời gian có `Z`, danh sách rỗng khi chưa có |
| `tests/api/test_db_init.py` | `init_db` tạo bảng `redirects` trên CSDL trống và không lỗi khi chạy lần hai |

Lệnh: `pytest tests/redirector tests/api`, sau đó chạy toàn bộ `pytest`. Test không gọi iptables thật nên chạy được trên Windows. Test dừng bằng tín hiệu dùng phương thức `stop()` thay vì `signal` thật.

## 9. Xác minh end-to-end

1. Build lại image vì thêm `iptables`: `docker compose up --build -d` (không `down`, để giữ dữ liệu `mysql_db`). `docker logs nids_redirector` có dòng "Redirector sẵn sàng" và `docker exec nids_redirector iptables -t nat -S` có chain `NIDS_REDIRECT`. Nếu iptables báo lỗi nft/legacy trên Docker Desktop, chuyển bằng `update-alternatives --set iptables /usr/sbin/iptables-legacy` trong image và ghi vào mục 12.
2. Trước khi tấn công, từ attacker: `docker exec nids_attacker nc -w 3 172.28.0.50 22` in banner OpenSSH Debian của victim; `docker exec nids_attacker curl -s http://172.28.0.50/` trả trang nginx.
3. Chạy `docker exec -it nids_attacker python lab/attacker/attack_demo.py web`. Trước đó đếm số cảnh báo P1/P2 thật mà nhóm `web` sinh ra trong 60 giây; nếu dưới `min_alerts` thì chỉnh ngưỡng mặc định và ghi vào mục 12. Trong vòng khoảng `poll_interval` giây, `GET http://localhost:8000/api/redirects` có IP `172.28.0.100`, và `iptables -t nat -S NIDS_REDIRECT` có hai rule cho IP đó.
4. Lặp lại hai lệnh ở bước 2: `nc` trả `SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13`, `curl` trả trang login WordPress giả. Trên `/logs`, tab Honeypot có sự kiện mới với IP nguồn `172.28.0.100` (không phải IP khác).
5. Hết TTL (đặt `ttl_seconds: 60` để thử nhanh): rule biến mất khỏi `iptables`, `nc` lại trả banner Debian, `redirects` có `removed_at`.
6. Trường hợp lỗi, allowlist: chèn thủ công 5 cảnh báo giả P1 cho `172.28.0.20` vào `events`; IP đó không xuất hiện trong `redirects`. Trong log có dòng bỏ qua.
7. Trường hợp lỗi, khôi phục: `docker restart nids_redirector` khi đang có IP bị chuyển hướng; sau restart rule vẫn tồn tại một lần (không nhân đôi) và chain không có rule của IP đã hết hạn. `docker stop nids_redirector` làm chain rỗng.
8. Trường hợp lỗi, sensor an toàn: `docker stop nids_redirector`, engine và honeypot vẫn chạy, cảnh báo vẫn vào `events`. Chạy `docker exec nids_redirector iptables -t nat -F` khi đang có IP bị chuyển hướng: trong vòng một `poll_interval`, chain, jump và rule của IP đó được tạo lại (xem `iptables -t nat -S`), redirector không crash.
9. Chạy `python -m nids.redirector` ở máy local Windows (không có iptables): in log hướng dẫn và thoát, không traceback.

## 10. Rủi ro và ảnh hưởng tới nhóm

| Rủi ro | Mức độ | Cách xử lý |
| :----- | :----- | :--------- |
| Chuyển hướng nhầm IP hạ tầng làm hỏng lab (ví dụ API, MySQL) | Cao | Allowlist mặc định gồm toàn bộ IP lab, kiểm tra bằng test và bước 6 mục 9; redirector chỉ áp cho cổng 22 và 80 của victim, không phải cổng MySQL/Redis |
| Chuyển hướng nhầm người dùng hợp lệ do false positive | Vừa | Tiêu chí B cần nhiều cảnh báo P1/P2, TTL ngắn, tự gỡ; lab không có người dùng hợp lệ nên chấp nhận |
| Kernel của Docker Desktop không hỗ trợ backend nft của iptables | Vừa | Kiểm tra ở bước 1 mục 9, có phương án chuyển sang `iptables-legacy` trong image |
| `REDIRECT` không chạm kết nối đang mở | Thấp | Ghi trong tài liệu; demo dùng kết nối mới |
| Rule mồ côi sau crash hoặc restart | Vừa | Flush khi khởi động và khi dừng, nạp lại từ `redirects`, chain riêng `NIDS_REDIRECT` |
| Thêm bảng làm trái dòng "DB chỉ lưu dữ liệu quan sát được" | Thấp | Bảng là nhật ký hành động; sửa câu trong CLAUDE.md và `config-db-docker.md` để nói rõ (quyết định ở mục 12) |
| Thêm service cần quyền `NET_ADMIN` | Thấp | Cùng mức quyền `nids_engine` đã có; không publish cổng; không nhận input từ mạng |
| Phản ứng chậm tối đa `poll_interval` + độ trễ ghi alert | Thấp | 5 giây, đủ cho demo; cấu hình được |
| Cảnh báo vẫn sinh với cổng gốc nên số cảnh báo của IP bị chuyển hướng vẫn tăng | Thấp | Chủ ý: engine sniff trước NAT; ghi trong tài liệu để khỏi tưởng nhầm là lỗi |
| Lỗi hoặc treo `iptables` chặn vòng lặp | Thấp | `subprocess.run(timeout=5)`; lỗi chỉ log |
| `src_ip` lấy từ gói tin nên có thể bị giả (`attack_demo.py` hỗ trợ tham số `src`), khiến IP bên thứ ba bị chuyển hướng | Thấp | Allowlist chặn IP hạ tầng; trong lab cô lập chỉ ảnh hưởng chính attacker. Ghi nhận, không xử lý thêm |
| `GET /api/redirects` không xác thực, attacker cùng mạng `nids_isolated_net` đọc được danh sách | Thấp | Cùng mức với `GET /api/alerts` hiện có; không mở thêm loại dữ liệu mới |
| Container `nids_redirector` thoát ngay ở máy có `settings.yaml` cũ | Thấp | Thoát mã 0 kèm `WARNING` hướng dẫn; ghi ở "Thành viên khác cần làm gì" |

**Thành viên khác cần làm gì**: Build lại image một lần (`docker compose up --build -d`, không `down` để giữ dữ liệu) vì `Dockerfile` thêm `iptables`; bảng `redirects` tự được tạo. Ai có `config/settings.yaml` riêng thì thêm mục `redirect` (copy từ `settings.example.yaml`); nếu không, container `nids_redirector` thoát ngay với `WARNING` hướng dẫn, đó là bình thường. Không cần sửa `.env`. Máy chạy local (không Docker) không bị ảnh hưởng.

## 11. Các bước thực hiện

Nhánh: `feature/29-redirect-to-honeypot`

- [x] Người dùng xác nhận đổi câu "DB chỉ lưu dữ liệu quan sát được" (câu hỏi mở đầu tiên ở mục 12), trước khi thêm bảng
- [x] Thêm `tests/redirector/conftest.py`, `RedirectModel`, các hàm trong `EventRepository`, `test_repository.py`
- [x] Thêm `get_redirect_settings()`, mục `redirect` trong `settings.example.yaml`, `test_config.py`
- [x] `nids/redirector/firewall.py` với `runner` tiêm vào, kèm `tests/redirector/test_firewall.py`
- [x] `nids/redirector/service.py` (chính sách, allowlist, `run_once`, dọn khi dừng), kèm `tests/redirector/test_service.py`
- [x] `nids/redirector/__main__.py` (+ `test_main.py`), `Dockerfile`, service `nids_redirector` trong `docker-compose.yml` (đặt sau `honeypot_http`, dùng lại `*nids_db_env`; chấp nhận thừa biến `NIDS_REDIS_*`)
- [x] Endpoint `GET /api/redirects` và test
- [x] Cập nhật tài liệu ở mục 7 và kịch bản demo
- [ ] Chạy `pytest`, xác minh theo mục 9 trên lab thật
- [ ] Tạo PR, cập nhật bảng tổng hợp

## 12. Quyết định và nhật ký

**Quyết định**

| Ngày | Quyết định | Người chốt | Lý do |
| :--- | :--------- | :--------- | :---- |
| 2026-11-01 | Tiêu chí đánh dấu: đủ N cảnh báo P1/P2 trong T giây (phương án B) | Người dùng | Giảm chuyển hướng nhầm so với một cảnh báo |
| 2026-11-01 | Cơ chế: iptables `REDIRECT` trong namespace victim | Người dùng | Đúng cấu trúc lab, phủ SSH và HTTP |
| 2026-11-01 | Process `nids_redirector` riêng, không đặt trong engine | Người dùng | Tách quyền firewall khỏi luồng phát hiện |
| 2026-11-01 | Danh sách IP lưu trong bảng `redirects` ở CSDL | Người dùng | Truy vấn qua API, sống qua restart |
| 2026-11-01 | Có allowlist, mặc định gồm toàn bộ IP hạ tầng lab | Người dùng | Không tự chặn hệ thống của mình |
| 2026-11-01 | Redirector chỉ đọc `events`, không sửa engine | Claude | Giữ engine không đổi, cô lập lỗi, đủ cho tiêu chí B |
| 2026-11-01 | Bảng `redirects` được coi là nhật ký hành động, sửa câu "DB chỉ lưu dữ liệu quan sát được" trong CLAUDE.md cho khớp | Claude, người dùng duyệt | Trạng thái chuyển hướng không thể suy ra từ `events`; người dùng duyệt plan ngày 2026-11-01 |
| 2026-11-01 | `redirect.enabled` mặc định `false` trong code, `true` trong file mẫu | Claude | Máy local và `settings.yaml` cũ không bị ảnh hưởng, lab Docker bật sẵn |
| 2026-11-01 | Không thêm UI dashboard, không thêm API ghi | Claude | Giữ PR nhỏ; API ghi cần thiết kế xác thực riêng |
| 2026-11-01 | Mặc định chỉ chuyển hướng cổng 22→2222 và 80→8080, TTL 600 giây, poll 5 giây, ngưỡng 5 cảnh báo / 60 giây, `max_priority` 2 | Claude | Khớp hai honeypot hiện có, đủ nhanh cho demo; đều cấu hình được |
| 2026-11-01 | Không gia hạn TTL khi IP còn đang bị chuyển hướng | Claude | Đơn giản, hết hạn mà vẫn tấn công thì tự được thêm lại |
| 2026-11-01 | Redirector thoát với mã lỗi khi không dùng được iptables, không đặt `restart` | Claude | Process vô dụng thì dừng rõ ràng thay vì lặp vô hạn |

**Câu hỏi còn mở**: Không. Người dùng duyệt plan ngày 2026-11-01, gồm việc đổi câu "DB chỉ lưu dữ liệu quan sát được" thành "DB chỉ lưu dữ liệu quan sát được và nhật ký hành động của hệ thống", và `owner` là ngoccu2006.

**Lịch sử trạng thái**: DRAFT → REVIEW (sau `plan-critic`) → APPROVED (2026-11-01).
- Issue #29 đang assign cho ngoccu2006 (`priority: low`); nmchien1106 là người mở issue và cũng phụ trách PLAN-001. Cần xác nhận người thực hiện là Vo Ngoc Cu (ngoccu2006) như trong phần `owner`.

**Kết quả phản biện**: `plan-critic` kết luận `PASS_WITH_WARNINGS` (0 `BLOCKER`, 5 `WARNING`, 5 `NOTE`). Đã xử lý trong plan:

- Quyết định đổi quy tắc DB nay là điều kiện tiên quyết trước `APPROVED` và là bước đầu ở mục 11.
- Redirector tự tạo lại chain, jump và rule bị xoá ngoài ý muốn (`ensure_setup` ở mục 6); bước 8 mục 9 sửa cho khớp, thêm test.
- `memory_db` không dùng chung được, nên thêm `tests/redirector/conftest.py`.
- Thêm test cho repository, cấu hình và `__main__`.
- Tách rõ mã thoát: `enabled=false` là 0, lỗi iptables là 1.
- Các `NOTE` đã vào mục 6, 9 và 10: định dạng `ports`, giả mạo `src_ip`, API không xác thực, hiệu chỉnh `min_alerts` bằng số liệu thật, tham số `*nids_db_env`.

Không còn `WARNING` nào bị giữ lại. `plan-critic` chưa chạy thử iptables, nft/legacy trên Docker Desktop và conntrack; các điểm này được kiểm chứng ở mục 9. Plan không được phản biện lại vì lần đầu không có `BLOCKER`.

**Nhật ký thực hiện**

- 2026-11-01: Code, test và tài liệu xong. `pytest` toàn bộ: 498 passed, 3 failed không liên quan. `tests/engine/test_stream.py::test_decoder_fills_tcp_seq` và `tests/engine/test_rule_header.py::test_decoder_parses_http_on_a_port_added_by_configuration` fail cả trên `main` sạch (Scapy không thấy interface mạng của máy dev Windows); `tests/api/test_realtime_ws.py` fail thất thường trên Windows như đã ghi ở PLAN-002.
- 2026-11-01: Chưa xác minh end-to-end theo mục 9 vì Docker Desktop chưa chạy trên máy dev. Chưa kiểm chứng: iptables nft/legacy, `REDIRECT` với conntrack, số cảnh báo P1/P2 thật của nhóm `web` trong 60 giây.
- 2026-11-01: Thêm thư viện còn thiếu vào Python của máy dev để chạy test (`pyyaml`, `pymysql`, `scapy`, `pyahocorasick`, ...), không đổi `requirements.txt`.
