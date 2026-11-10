---
type: PLAN
plan_id: PLAN-008
title: Lab ba máy ảo trên VMware (Kali, IDS gateway, Victim + Honeypot)
status: REVIEW
issue: "#68"
owner: ngoccu2006
created: 2026-11-10
updated: 2026-11-10
---

# PLAN-008: Lab ba máy ảo trên VMware (Kali, IDS gateway, Victim + Honeypot)

## 1. Bối cảnh

Hiện tại toàn bộ lab chạy trên một máy, gồm các container trong `docker-compose.yml`, mạng `172.28.0.0/16`. Engine, honeypot và redirector dùng chung network namespace với victim (`network_mode: service:victim_app`). Nhóm cần trình diễn thêm một mô hình giống mạng thật: attacker, IDS và victim là các máy riêng chạy trên VMware Workstation. Docker lab vẫn phải chạy như cũ để làm phương án dự phòng.

Có hai ràng buộc ngăn việc chỉ đơn giản tách container ra nhiều máy:

- Ở mạng switch, một máy IDS riêng không thấy traffic của victim. Muốn engine thấy thì traffic phải đi qua máy IDS.
- Redirector dùng `REDIRECT` ([firewall.py:55-56](../../nids/redirector/firewall.py#L55-L56)). Rule này chỉ chuyển kết nối sang cổng trên chính máy chạy iptables, nên không dùng được khi iptables nằm ở gateway còn honeypot nằm ở victim.

Người dùng đã chốt: 3 máy, VMware Workstation, phương án B (Docker trên từng VM, `network_mode: host`), gộp vào một issue, người phụ trách là vongoccu (`ngoccu2006`).

## 2. Mục tiêu và tiêu chí thành công

- **Mục tiêu**: một người trong nhóm làm theo tài liệu là dựng được lab 3 VM. Kali tấn công victim thì dashboard trên IDS hiện cảnh báo và sự kiện honeypot, IP vượt ngưỡng bị chuyển sang honeypot giống Docker lab.
- **Xong khi**:
  - Trên Kali, `sudo python3 lab/attacker/attack_demo.py all --target 10.10.2.50` sinh cảnh báo với SID khớp "kỳ vọng SID" trên dashboard `http://<IP mgmt của IDS>:8000/`.
  - Sau khoảng 5 cảnh báo P1/P2, `ssh root@10.10.2.50` từ Kali rơi vào honeypot (`/api/redirects` có dòng mới). Trên IDS, `iptables -t nat -S NIDS_REDIRECT` hiện rule `DNAT --to-destination 10.10.2.50:2222`.
  - Trên máy dev, `docker compose up --build` vẫn chạy như trước và `pytest` xanh.

## 3. Phạm vi

- **Trong phạm vi**:
  - Khoá cấu hình `redirect.target_host` cho redirector (để trống thì dùng `REDIRECT` như cũ, đặt IP thì dùng `DNAT`).
  - Thư mục `lab/vmware/`: compose cho IDS và cho Victim, file settings cho IDS, netplan mẫu cho 3 VM, `.env.example`.
  - Tài liệu dựng lab trên VMware (bổ sung vào `docs/setup-linux.md`).
- **Ngoài phạm vi**:
  - Script cài tự động, unit systemd (phương án A, C bị loại).
  - VM honeypot riêng (4 máy).
  - Proxmox, VirtualBox (chỉ ghi chú tương đương).
  - Hardening chặn Kali truy cập cổng 8000 của IDS bằng iptables `INPUT` (chỉ ghi là bước tuỳ chọn trong tài liệu).
  - IPv6.
  - Đổi kịch bản demo trong `docs/demo/kich-ban-demo.md`.

## 4. Hiện trạng

- `IptablesFirewall._rule` ([firewall.py:55-56](../../nids/redirector/firewall.py#L55-L56)) dựng `-s ip -p tcp --dport N -j REDIRECT --to-ports M`. `add`, `remove` và `flush` dùng chung `_rule`, nên chỉ cần sửa một chỗ.
- `IptablesFirewall(settings.ports)` được tạo ở [__main__.py:34](../../nids/redirector/__main__.py#L34).
- `RedirectSettings` và `get_redirect_settings` ([config.py:84-143](../../nids/config.py#L84-L143)) kiểm tra từng trường, giá trị sai thì ghi ERROR và dùng mặc định. Trường mới làm theo đúng mẫu này. `normalize_ip` ([firewall.py:27](../../nids/redirector/firewall.py#L27)) dùng lại để kiểm tra `target_host`.
- Test của firewall dùng `tests/redirector/fake_iptables.py` nên không cần iptables thật. `tests/redirector/test_redirect_config.py` có sẵn mẫu test cấu hình.
- `Dockerfile` (python:3.10-slim, đã có `iptables`, `libpcap-dev`) và `lab/victim/` (nginx, vsftpd, sshd, ncat 3333/4444) dùng lại nguyên vẹn.
- `get_db_url()` và `get_redis_settings()` đọc `NIDS_DB_*` và `NIDS_REDIS_*` từ môi trường, nên honeypot ở VM victim trỏ được về MySQL/Redis của IDS mà không phải sửa code.
- `load_settings()` ([config.py:17](../../nids/config.py#L17)) chỉ đọc `config/settings.yaml`, thiếu file thì dùng file mẫu. Compose VMware sẽ mount file settings riêng vào đường dẫn này, không cần sửa code.
- `attack_demo.py` đã có `--target`. Nó chỉ cần scapy và `hydra`, Kali có sẵn cả hai.

## 5. Các phương án đã cân nhắc

| Phương án | Ưu điểm | Nhược điểm | Kết luận |
| :-------- | :------ | :--------- | :------- |
| A. Native + systemd trên từng VM | Dễ giải thích, không có Docker trong VM | Phải cài tay MySQL/Redis/nginx/vsftpd, dễ lệch phiên bản, cần viết khoảng 5 unit systemd | Loại: người dùng chọn B |
| B. Docker trên từng VM, `network_mode: host` | Dùng lại `Dockerfile` và `lab/victim`, ít file mới, Docker lab không đổi | Cần xử lý chain FORWARD mà Docker đặt mặc định DROP, và kiểm tra iptables nft trong container | **Chọn** |
| C. Script bash cài tự động | Dựng lại lab nhanh | Script dài, khó debug | Loại: khối lượng lớn |
| Redirector: thêm chế độ DNAT bằng `target_host` | Một đoạn code cho cả hai môi trường, mặc định giữ nguyên hành vi cũ | Thêm một nhánh trong `_rule` | **Chọn** |
| Redirector: viết riêng `DnatFirewall` | Tách bạch | Lặp lại `add`/`remove`/`flush` | Loại: trùng code |

## 6. Thiết kế đã chọn

```
                    VMnet8 (NAT, mgmt): mở dashboard từ Windows, cài gói
                              │ ens33 (DHCP)
[Kali]  ──VMnet2──  ens34 [IDS / gateway] ens35  ──VMnet3──  [Victim + Honeypot]
10.10.1.100        10.10.1.1          10.10.2.1             10.10.2.50
gw 10.10.1.1       engine (sniff ens34), API :8000,          nginx :80, vsftpd :21, sshd :22,
                   MySQL + Redis (bind 10.10.2.1),           honeypot ssh :2222, http :8080
                   redirector (iptables nat PREROUTING)      gw 10.10.2.1
```

**Mạng.** VMnet2 và VMnet3 là mạng host-only không có DHCP (hoặc LAN Segment). IDS bật `net.ipv4.ip_forward=1`. Victim có default gateway là `10.10.2.1`, Kali có route `10.10.2.0/24 via 10.10.1.1`. Không dùng SNAT, nên victim và honeypot thấy đúng IP của Kali. Chỉ IDS có card NAT. VM Victim cần một card NAT tạm để `docker build`, xây xong thì ngắt.

**Engine.** `interface: ens34`. libpcap bắt gói trước netfilter nên engine thấy cổng gốc 22/80 trước khi DNAT, giống Docker lab. Traffic honeypot → MySQL/Redis (`10.10.2.50` → `10.10.2.1`) và dashboard (ens33) không đi qua ens34, nên engine không sniff được. Giữ `not port 3306` trong `bpf_filter`, đổi vế Redis thành `host 10.10.2.1 and port 6379`.

**Redirector (thay đổi code duy nhất).** Thêm `RedirectSettings.target_host: str = ""`. `get_redirect_settings` kiểm tra bằng `ipaddress`: không phải IPv4 thì ghi ERROR rồi để rỗng. Rỗng nghĩa là redirector vẫn chạy ở chế độ REDIRECT, nên lỗi cấu hình không bao giờ tạo ra rule trỏ sai chỗ. Truyền vào `IptablesFirewall(ports, target_host=...)`; trong `__init__` gọi `normalize_ip` nếu có giá trị. `_rule` khi có `target_host` sinh `-s <ip> -d <host> -p tcp --dport N -j DNAT --to-destination <host>:<M>`, ngược lại giữ `REDIRECT`. Có `-d` thì chỉ kết nối tới victim bị chuyển hướng; kết nối từ Kali tới chính IDS (vd. SSH vào gateway) không bị chuyển. Chain, jump PREROUTING và luồng `service.py` không đổi.

**Allowlist trên IDS.** `127.0.0.0/8`, `10.10.1.1`, `10.10.2.1`, `10.10.2.50`.

**Docker trên IDS** (`lab/vmware/compose.ids.yml`). Tất cả service dùng `network_mode: host` và image `hybrid-nids-app` build từ `Dockerfile` ở gốc repo:
- `mysql` (`--bind-address=10.10.2.1`) và `redis` (`--bind 10.10.2.1 127.0.0.1 --requirepass`), cùng mật khẩu lấy từ `.env`.
- `engine` (`NET_RAW`, `NET_ADMIN`), `api` (cổng 8000), `redirector` (`NET_ADMIN`).
- Các service mount repo vào `/app`, mount `lab/vmware/settings.ids.yaml` vào `/app/config/settings.yaml`, đặt `NIDS_DB_HOST=10.10.2.1`.

Docker đặt policy FORWARD là DROP khi khởi động, nên tài liệu thêm bước `iptables -I DOCKER-USER -i ens34 -o ens35 -j ACCEPT` và chiều ngược lại. Hai rule này được lưu bằng `iptables-persistent` hoặc một unit `oneshot` tối thiểu ghi sẵn trong tài liệu.

**Docker trên Victim** (`lab/vmware/compose.victim.yml`):
- `victim`: `build: ../victim`, `network_mode: host`.
- `honeypot_ssh` và `honeypot_http`: image `hybrid-nids-app` (build từ `../..` ngay trên VM Victim), mount repo và `settings.ids.yaml` như IDS, `network_mode: host`, môi trường `NIDS_DB_HOST=10.10.2.1`, `NIDS_REDIS_HOST=10.10.2.1`.

sshd của container chiếm cổng 22, nên tài liệu yêu cầu tắt `ssh.service` và `ssh.socket` của Ubuntu trên VM Victim, hoặc cài Ubuntu không có OpenSSH.

**Kali.** Clone repo, `sudo python3 lab/attacker/attack_demo.py <nhóm> --target 10.10.2.50`. Không cần Docker.

## 7. Thay đổi cần làm

| File | Thay đổi | Dùng lại |
| :--- | :------- | :------- |
| `nids/config.py` | Thêm `target_host` vào `RedirectSettings`; `get_redirect_settings` đọc và kiểm tra trường này | Mẫu kiểm tra từng trường hiện có, `ipaddress` |
| `nids/redirector/firewall.py` | `IptablesFirewall.__init__(..., target_host="")` gọi `normalize_ip`; `_rule` sinh DNAT khi có `target_host`; sửa docstring đầu file | `normalize_ip` |
| `nids/redirector/__main__.py` | Truyền `settings.target_host`; log một dòng chế độ (REDIRECT hoặc DNAT tới host) | |
| `config/settings.example.yaml` | Thêm `target_host: ""` kèm comment trong mục `redirect` | |
| `lab/vmware/compose.ids.yml` | Mới: mysql, redis, engine, api, redirector, host network | `Dockerfile` |
| `lab/vmware/compose.victim.yml` | Mới: victim, honeypot_ssh, honeypot_http, host network | `lab/victim/`, `Dockerfile` |
| `lab/vmware/settings.ids.yaml` | Mới: interface `ens34`, BPF, MySQL `10.10.2.1`, `redis.host` `10.10.2.1`, `redirect.target_host: "10.10.2.50"`, allowlist 10.10.x | `settings.example.yaml` |
| `lab/vmware/netplan/{ids,victim,kali}.yaml` | Mới: IP tĩnh, gateway, route (Kali dùng `nmcli`, ghi lệnh trong tài liệu nếu không dùng netplan) | |
| `lab/vmware/.env.example` | Mới: `MYSQL_ROOT_PASSWORD`, `NIDS_DB_PASSWORD`, `NIDS_REDIS_PASSWORD`, `NIDS_API_KEY` | `.env.example` |
| `docs/setup-linux.md` | Thêm mục "Cách C: lab 3 máy ảo trên VMware": tạo VMnet, cấu hình VM, IP forward, DOCKER-USER, tắt sshd của victim, chạy, kiểm tra, lỗi thường gặp | |
| `tests/redirector/test_firewall.py` | Test chế độ DNAT | `fake_iptables.py` |
| `tests/redirector/test_redirect_config.py` | Test `target_host` hợp lệ, sai, không có | |

Tài liệu cần cập nhật: `.claude/rules/redirector.md` (cơ chế DNAT, `target_host`), `.claude/rules/config-db-docker.md` (khoá `redirect.target_host`, thư mục `lab/vmware/`), `CLAUDE.md` (Project Structure: `lab/vmware/`; Current Focus), `README.md` (một dòng trỏ tới tài liệu VMware).

## 8. Kiểm thử

| Test | Kiểm tra điều gì |
| :--- | :--------------- |
| `tests/redirector/test_firewall.py::test_add_builds_dnat_rule_when_target_host_set` | Có `target_host` thì `add` sinh `-d 10.10.2.50 ... -j DNAT --to-destination 10.10.2.50:2222` cho từng cổng, không còn `REDIRECT` |
| `tests/redirector/test_firewall.py::test_remove_and_flush_work_in_dnat_mode` | `remove` gỡ đúng rule DNAT đã thêm |
| `tests/redirector/test_firewall.py::test_invalid_target_host_raises` | `target_host="1.2.3.4;rm"` hoặc IPv6 thì ném `FirewallError` khi khởi tạo, không chạy lệnh nào |
| `tests/redirector/test_firewall.py` (test cũ) | Không đặt `target_host` thì rule vẫn là `REDIRECT` (hành vi Docker lab giữ nguyên) |
| `tests/redirector/test_redirect_config.py::test_target_host_*` | Thiếu khoá thì `""`; IPv4 hợp lệ thì được giữ; chuỗi sai hoặc IPv6 thì `""` kèm 1 ERROR |

Lệnh: `pytest tests/redirector` rồi `pytest`

## 9. Xác minh end-to-end

1. **Docker lab không hồi quy.** Trên máy dev chạy `docker compose up --build -d`, rồi `docker exec -it nids_attacker python lab/attacker/attack_demo.py all`. Dashboard có cảnh báo. `docker logs nids_redirector` ghi chế độ REDIRECT, và sau ngưỡng thì có rule `REDIRECT` trong `iptables -t nat -S NIDS_REDIRECT` (chạy trong `nids_redirector`).
2. **Mạng VMware.** Ping `10.10.2.50` từ Kali thành công. `curl http://10.10.2.50/` trả trang nginx. Trên IDS, `tcpdump -ni ens34 host 10.10.1.100` thấy gói.
3. **Phát hiện.** Trên Kali chạy `sudo python3 lab/attacker/attack_demo.py web --target 10.10.2.50`. Dashboard trên IDS hiện cảnh báo với SID khớp log của attacker.
4. **Honeypot.** Chạy `attack_demo.py honeypot --target 10.10.2.50`. Trang Logs có sự kiện `HONEYPOT` với `src_ip` `10.10.1.100` (không bị SNAT).
5. **Chuyển hướng.** Sau bước 3 (≥ 5 cảnh báo P1/P2), `ssh root@10.10.2.50` từ Kali hiện banner của honeypot. `/api/redirects` có dòng `10.10.1.100`. `iptables -t nat -S NIDS_REDIRECT` trên IDS hiện rule DNAT. Dashboard vẫn thấy cảnh báo cổng 22 (engine bắt gói trước NAT).
6. **Lỗi cấu hình.** Đặt `target_host: "abc"` rồi khởi động lại redirector. Log có ERROR và redirector chạy ở chế độ REDIRECT, không sập.
7. **Redis tắt.** Chạy `docker compose -f lab/vmware/compose.ids.yml stop redis`. Engine và honeypot vẫn ghi DB, dashboard quay về poll.

## 10. Rủi ro và ảnh hưởng tới nhóm

| Rủi ro | Mức độ | Cách xử lý |
| :----- | :----- | :--------- |
| Docker đặt FORWARD DROP nên Kali không tới được victim | Cao | Tài liệu bắt buộc thêm rule `DOCKER-USER` cho ens34↔ens35 và lưu lại qua reboot; bước 2 của mục 9 phát hiện ngay |
| iptables trong container (Debian, backend nft) và host Ubuntu dùng backend khác nhau, nên rule không có hiệu lực | Vừa | Bước 5 của mục 9 kiểm tra rule bằng `iptables` của host. Lệch backend thì ghi hướng dẫn chọn `iptables-legacy` đồng bộ trong tài liệu |
| Tên card không phải `ens33/34/35` | Vừa | Tài liệu bảo kiểm tra bằng `ip -br link` rồi sửa `interface` và netplan; ghi rõ card nào gắn VMnet nào |
| sshd của Ubuntu chiếm cổng 22 trên VM Victim | Vừa | Tắt `ssh.service` và `ssh.socket` (ghi trong tài liệu) |
| MySQL/Redis lộ ra phía Kali | Vừa | Bind `10.10.2.1`, Redis có mật khẩu; nhắc ở rủi ro rằng API :8000 vẫn nghe mọi card (sửa rule cần API key) |
| VM Victim không có Internet để build image | Thấp | Thêm card NAT tạm khi build, hoặc `docker save`/`docker load` từ IDS |
| Máy host thiếu RAM (Kali 2–4 GB, IDS 2 GB, Victim 1 GB) | Thấp | Ghi cấu hình tối thiểu; Kali có thể dùng bản không GUI |

**Thành viên khác cần làm gì**: Docker lab không cần làm gì (`target_host` mặc định rỗng). Ai có `config/settings.yaml` local thì không bắt buộc sửa. Chỉ người dựng lab VMware làm theo tài liệu mới.

## 11. Các bước thực hiện

Nhánh: `feature/68-vmware-lab`

- [ ] Thêm `target_host` vào `RedirectSettings` và `get_redirect_settings`, kèm test cấu hình
- [ ] Thêm chế độ DNAT vào `IptablesFirewall`, truyền từ `__main__.py`, kèm test firewall
- [ ] Thêm `target_host: ""` vào `config/settings.example.yaml`
- [ ] Tạo `lab/vmware/` (2 file compose, `settings.ids.yaml`, netplan, `.env.example`)
- [ ] Viết mục VMware trong `docs/setup-linux.md`
- [ ] Cập nhật `.claude/rules/redirector.md`, `.claude/rules/config-db-docker.md`, `CLAUDE.md`, `README.md`
- [ ] Chạy `pytest`, xác minh theo mục 9 (Docker lab và 3 VM)
- [ ] Tạo PR, cập nhật bảng tổng hợp

## 12. Quyết định và nhật ký

**Quyết định**

| Ngày | Quyết định | Người chốt | Lý do |
| :--- | :--------- | :--------- | :---- |
| 2026-11-10 | 3 máy: Kali, IDS gateway, Victim + Honeypot | Người dùng | Ít VM, giữ honeypot chung máy với victim như Docker lab |
| 2026-11-10 | Hypervisor VMware Workstation | Người dùng | Nhóm đang dùng |
| 2026-11-10 | Phương án B: Docker trên từng VM, `network_mode: host` | Người dùng | Dùng lại image, ít việc cài tay |
| 2026-11-10 | Một issue, phụ trách `ngoccu2006` (vongoccu) | Người dùng | Theo yêu cầu |
| 2026-11-10 | IDS làm gateway thay vì dùng promiscuous hay port mirroring | Claude | Engine chắc chắn thấy mọi gói, và redirector cần nằm trên đường đi của traffic |
| 2026-11-10 | Thêm `redirect.target_host` (DNAT) thay vì viết lớp firewall riêng | Claude | Sửa một hàm, mặc định giữ hành vi Docker lab |
| 2026-11-10 | `target_host` sai thì để rỗng (REDIRECT), không dừng process | Claude | Cùng cách xử lý với các trường khác của `get_redirect_settings` |
| 2026-11-10 | Engine chỉ sniff ens34 (phía Kali) | Claude | Thấy cổng gốc trước NAT; không sniff traffic DB/Redis/dashboard nên không sinh cảnh báo lặp |
| 2026-11-10 | MySQL/Redis bind `10.10.2.1`, không dùng mạng bridge | Claude | Không phát sinh NAT của Docker trong FORWARD; Kali không tới được |
| 2026-11-10 | Mount `settings.ids.yaml` vào `/app/config/settings.yaml` thay vì thêm biến chọn file settings | Claude | Không phải sửa `load_settings` |

**Câu hỏi còn mở**: Không

**Kết quả phản biện**: Tự rà theo `.claude/agents/plan-critic.md` (người dùng yêu cầu không dùng subagent `plan-critic`), nên phản biện không độc lập. Không có BLOCKER. Các WARNING giữ lại:
- Chưa kiểm tra thực tế độ tương thích iptables nft/legacy; để mục 9 bước 5 kiểm tra.
- API :8000 vẫn nghe ở ens34; chấp nhận được trong lab vì thao tác ghi cần `NIDS_API_KEY`.
