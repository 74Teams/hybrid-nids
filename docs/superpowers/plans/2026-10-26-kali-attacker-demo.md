# Attacker Kali, victim nhiều dịch vụ: Kế hoạch triển khai

> **Dành cho agent thực thi:** BẮT BUỘC dùng superpowers:subagent-driven-development (khuyến nghị) hoặc superpowers:executing-plans để thực hiện từng task. Các bước dùng checkbox (`- [ ]`) để theo dõi.

**Mục tiêu:** Cho phép gõ lệnh dòng lệnh trực tiếp (`nmap`, `ping`, `ftp`, `hping3`, `hydra`, `curl`, `dig`, `snmpwalk`, `nc`...) trong container `attacker` khi demo, và để các lệnh đó thực sự chạm tới dịch vụ trên victim (FTP, SSH, các cổng TCP lắng nghe) để rule tương ứng trong `rules/local.rules` bắn đúng.

**Kiến trúc:** `attacker/attack_demo.py` (script Python, đã có) giữ làm phương án dự phòng. Thêm hai image Docker mới: `attacker/Dockerfile` build từ `kalilinux/kali-rolling` với các gói dòng lệnh cần cho bảng lệnh demo; `victim/Dockerfile` + `victim/start.sh` build từ `debian:bookworm-slim` chạy nhiều dịch vụ (nginx, vsftpd, sshd, dnsmasq, hai listener `ncat`) thay cho `nginx:alpine` hiện tại. `docker-compose.yml` đổi hai service này sang `build:`. Không đổi engine, rule hay API.

**Công nghệ:** Docker, Debian/Kali base image, Bash, Python/pytest cho test kiểm tra tài liệu khớp rule.

**Spec:** Không có file spec riêng; quyết định đã chốt nằm ở mục dưới, lấy từ buổi brainstorm trong chat (người dùng chọn "gõ lệnh trong container", xem toàn bộ bảng lệnh → SID).

## Quyết định đã chốt

- Attacker dùng Kali thật (`kalilinux/kali-rolling`), không dùng script giả lập làm phương án chính; vào bằng `docker exec -it nids_attacker bash`.
- Victim thay nginx đơn thuần bằng image chạy thêm FTP anonymous, SSH, và các cổng TCP nhận payload thô, để các rule `flow:established` và AUTH bắn được với lệnh thật.
- Giữ nguyên IP tĩnh hiện có: victim `172.28.0.50`, attacker `172.28.0.100`; engine vẫn `network_mode: service:victim_app`.
- `attacker/attack_demo.py` không bị xóa, vẫn dùng khi lệnh thật không tiện (ví dụ không có Internet để build Kali).
- *Quyết định của tôi (chưa được xác nhận):* không cài DNS server riêng cho victim trừ khi một rule RECON cần cổng 53 TCP/UDP mở thật; cổng 53 hiện chỉ cần nhận packet (không cần phản hồi đúng) nên dùng listener `ncat -u -lk 53` là đủ cho rule bắn, không cần `dnsmasq` đầy đủ.

## Ràng buộc chung

- Tài liệu viết bằng tiếng Việt có dấu (CLAUDE.md). Tên trong code, lệnh, đường dẫn, tên gói phần mềm giữ tiếng Anh.
- Chỉ `git commit` khi người dùng đồng ý rõ ràng; làm trên nhánh `feature/demo-dashboard` (nhánh đang có các thay đổi dashboard/rule/attack_demo.py chưa commit), không merge vào `main`.
- Không đổi hành vi `DetectionEngine.evaluate_packet`, `rules/local.rules`, API `/api/alerts`, hay `attacker/attack_demo.py`.
- Không có Docker daemon chạy trong môi trường thực thi plan này: mọi bước "Run" liên quan `docker build`/`docker compose up` chỉ là **Verification thủ công** người dùng tự làm sau, không phải bước agent tự chạy. Agent xác minh bằng cách đọc lại Dockerfile, chạy `docker compose config -q` (không cần daemon) và chạy `pytest`.
- IP tĩnh, tên container, tên network trong `docker-compose.yml` giữ nguyên như hiện tại (`172.28.0.0/16`, `nids_mysql`, `nids_victim`, `nids_engine`, `nids_attacker`, `nids_api`).

## Review Focus

- **`docker compose config -q` phải chạy sạch** sau mỗi thay đổi compose (không cần daemon, chỉ cần binary `docker`). Nếu máy review không có `docker` binary, ghi rõ trong report và coi bước đó là bỏ qua, không phải lỗi.
- **Victim phải giữ đúng IP `172.28.0.50`** và cổng 80 vẫn phục vụ HTTP (không đổi hành vi các rule WEB-ATTACK hiện có dựa trên `curl`/HTTP qua port 80).
- **Script `start.sh` phải chạy tiến trình nền ở foreground** (container không tự thoát ngay sau khi start) — kiểm tra bằng đọc script, không chạy thật.
- **Bảng lệnh trong tài liệu demo không được liệt kê SID không tồn tại trong `rules/local.rules`** — bắt buộc có test tự động, không chỉ đọc bằng mắt.

---

### Task 1: Image attacker kiểu Kali

**Files:**
- Create: `attacker/Dockerfile`
- Modify: `docker-compose.yml`

**Interfaces:**
- Produces: image build từ `kalilinux/kali-rolling`, cài gói: `nmap hping3 hydra curl ftp netcat-openbsd iputils-ping dnsutils snmp sqlmap nikto masscan python3-scapy openssh-client`. `WORKDIR /app`. Không có `CMD`/`ENTRYPOINT` chạy tiến trình nền — container compose sẽ dùng `command: sleep infinity` (giữ nguyên cách attacker hiện tại được giữ sống).
- Consumes: không có (độc lập Task 2).

- [ ] **Step 1: Viết test fail** trong `tests/test_attacker_dockerfile.py`:
  - `test_dockerfile_exists_and_uses_kali`: file `attacker/Dockerfile` tồn tại, dòng `FROM` đầu tiên chứa `kalilinux/kali-rolling`.
  - `test_dockerfile_installs_required_tools`: đọc nội dung file, assert mỗi tên gói trong danh sách `["nmap", "hping3", "hydra", "ftp", "netcat-openbsd", "iputils-ping", "dnsutils", "snmp", "sqlmap", "nikto", "masscan", "python3-scapy", "openssh-client"]` xuất hiện dạng từ nguyên vẹn (dùng `re.search(rf"\b{pkg}\b", text)`) trong file.
  - `test_compose_attacker_builds_from_local_dockerfile`: đọc `docker-compose.yml` bằng `yaml.safe_load`, service `attacker` có `build` trỏ tới thư mục `attacker` (chấp nhận dạng chuỗi `"./attacker"` hoặc mapping `{"context": "./attacker"}`), không còn `image: python:3.10-slim`.

- [ ] **Step 2: Chạy để thấy fail**

Run: `python -m pytest tests/test_attacker_dockerfile.py -v -p no:cacheprovider`
Expected: FAIL vì `attacker/Dockerfile` chưa tồn tại và `docker-compose.yml` còn `build: .` (image chung với engine, không phải Kali).

- [ ] **Step 3: Viết `attacker/Dockerfile`** theo Interfaces. Thêm một dòng `RUN echo 'echo "Target: 172.28.0.50"' >> /root/.bashrc` (gợi ý khi mở shell), không bắt buộc cho test.

- [ ] **Step 4: Sửa `docker-compose.yml`**: service `attacker` đổi `build: .` thành `build: ./attacker`, giữ `volumes: - .:/app`, `cap_add: [NET_RAW, NET_ADMIN]` (thêm `NET_ADMIN`, cần cho `ping -f`/`hping3 --flood`/`nmap -sS`), `command: sleep infinity`, giữ IP `172.28.0.100`.

- [ ] **Step 5: Chạy để thấy pass**

Run: `python -m pytest tests/test_attacker_dockerfile.py -v -p no:cacheprovider`
Expected: toàn bộ pass.

- [ ] **Step 6: Xác minh compose hợp lệ (không cần daemon)**

Run: `docker compose config -q`
Expected: không in lỗi, exit code 0. Nếu máy không có binary `docker`, ghi "bỏ qua: không có docker binary" trong báo cáo task, không coi là fail.

- [ ] **Step 7: Commit** (chỉ khi người dùng đồng ý)

```bash
git add attacker/Dockerfile docker-compose.yml tests/test_attacker_dockerfile.py
git commit -m "feat(docker): attacker dung Kali de go lenh nmap/hping3/hydra truc tiep khi demo"
```

---

### Task 2: Image victim nhiều dịch vụ

**Files:**
- Create: `victim/Dockerfile`, `victim/start.sh`
- Modify: `docker-compose.yml`

**Interfaces:**
- Produces: image build từ `debian:bookworm-slim`, cài `nginx vsftpd openssh-server ncat`. `victim/start.sh` (copy vào image, `chmod +x`, là `CMD`) khởi động theo thứ tự: `vsftpd` (nền, `anonymous_enable=YES` trong `/etc/vsftpd.conf`, cổng 21), `/usr/sbin/sshd` (nền, cổng 22), `ncat -lk -p 4444 >/dev/null &` và `ncat -lk -p 3333 >/dev/null &` (nhận payload thô, không cần phản hồi), rồi `exec nginx -g "daemon off;"` làm tiến trình chính (PID 1, chạy foreground, cổng 80).
- Consumes: không (độc lập Task 1).

- [ ] **Step 1: Viết test fail** trong `tests/test_victim_dockerfile.py`:
  - `test_dockerfile_exists_and_installs_services`: `victim/Dockerfile` tồn tại; nội dung chứa cả bốn tên gói `nginx`, `vsftpd`, `openssh-server`, `ncat` (dùng `\b` như Task 1).
  - `test_start_script_runs_nginx_in_foreground`: `victim/start.sh` tồn tại; nội dung chứa `nginx` và cờ `daemon off`; dòng chạy nginx là dòng cuối cùng không rỗng của file (đảm bảo nginx là tiến trình giữ container sống, chạy sau khi các dịch vụ khác đã lên).
  - `test_start_script_enables_ftp_anonymous`: nội dung `start.sh` hoặc một file cấu hình được copy vào image chứa `anonymous_enable=YES`.
  - `test_compose_victim_builds_from_local_dockerfile`: `docker-compose.yml` qua `yaml.safe_load`, service `victim_app` có `build` trỏ `./victim`, không còn `image: nginx:alpine`; IP vẫn `172.28.0.50` (đọc từ `networks.nids_isolated_net.ipv4_address`).

- [ ] **Step 2: Chạy để thấy fail**

Run: `python -m pytest tests/test_victim_dockerfile.py -v -p no:cacheprovider`
Expected: FAIL vì chưa có `victim/Dockerfile`, `victim/start.sh`, và compose còn `image: nginx:alpine`.

- [ ] **Step 3: Viết `victim/Dockerfile` và `victim/start.sh`** theo Interfaces. `start.sh` dùng `#!/bin/sh` hoặc `#!/bin/bash` (có sẵn trong `debian:bookworm-slim` qua gói `bash` nếu cần, hoặc viết bằng `sh` thuần). Tạo thư mục `/var/run/sshd` trước khi chạy `sshd` (bắt buộc với OpenSSH trên Debian) trong `Dockerfile` (`RUN mkdir -p /var/run/sshd`), không phải trong `start.sh`.

- [ ] **Step 4: Sửa `docker-compose.yml`**: service `victim_app` đổi `image: nginx:alpine` thành `build: ./victim`, giữ IP `172.28.0.50`, không thêm port map mới (port 80 đã lộ ra qua `nids_api`/`nids_engine` theo cấu hình hiện tại, không đổi).

- [ ] **Step 5: Chạy để thấy pass**

Run: `python -m pytest tests/test_victim_dockerfile.py -v -p no:cacheprovider`
Expected: toàn bộ pass.

- [ ] **Step 6: Xác minh compose hợp lệ**

Run: `docker compose config -q` (bỏ qua nếu không có `docker` binary, như Task 1).

- [ ] **Step 7: Commit** (chỉ khi người dùng đồng ý)

```bash
git add victim/Dockerfile victim/start.sh docker-compose.yml tests/test_victim_dockerfile.py
git commit -m "feat(docker): victim chay them FTP anonymous, SSH va listener TCP de rule AUTH ban duoc voi lenh thuc"
```

---

### Task 3: Bảng lệnh demo → SID, kèm test khớp với bộ rule

**Files:**
- Modify: `docs/demo/kich-ban-demo.md`
- Create: `tests/test_demo_commands.py`

**Interfaces:**
- Produces: mục mới "Demo gõ lệnh thủ công" trong `docs/demo/kich-ban-demo.md`, dạng bảng Markdown `| Nhóm | Lệnh | SID kỳ vọng |`, mỗi dòng SID kỳ vọng là một hoặc nhiều số nguyên cách nhau bởi `,` hoặc `·` (ví dụ `1000001, 1000003`).
- Consumes: `rules/local.rules` (qua `RuleManager.rules_by_sid`, không phải việc tự ý thêm rule mới).

- [ ] **Step 1: Viết test fail** trong `tests/test_demo_commands.py`:
  - Đọc `docs/demo/kich-ban-demo.md`, dùng regex tìm mọi số 7 chữ số bắt đầu bằng `1000` trong các dòng bảng của mục "Demo gõ lệnh thủ công" (ví dụ `r"\b(1000\d{3})\b"`, chỉ trong đoạn văn bản từ heading đó tới heading tiếp theo hoặc hết file).
  - `test_manual_command_sids_exist_in_ruleset`: nạp `RuleManager("rules")`, assert mọi SID tìm được nằm trong `rules_by_sid`.
  - `test_manual_command_section_is_non_empty`: assert tìm được ít nhất 20 SID khác nhau (bảng phải thực sự có nội dung, không phải heading rỗng).

- [ ] **Step 2: Chạy để thấy fail**

Run: `python -m pytest tests/test_demo_commands.py -v -p no:cacheprovider`
Expected: FAIL (`test_manual_command_section_is_non_empty`) vì mục "Demo gõ lệnh thủ công" chưa tồn tại trong tài liệu.

- [ ] **Step 3: Thêm mục "Demo gõ lệnh thủ công"** vào `docs/demo/kich-ban-demo.md`, ngay sau mục "2. Trình tự trình diễn" hiện có. Mỗi dòng gồm lệnh thật chạy trong attacker (target `172.28.0.50`) và SID kỳ vọng, lấy đúng SID đã có trong `rules/local.rules` (không tự đặt SID mới). Phân theo nhóm: bình thường (không alert), ping/ICMP, Nmap quét cờ, Nmap quét cổng, UDP/recon, flood (hping3), FTP/SSH, web (curl/sqlmap/nikto), payload qua `nc` tới các cổng listener của victim (4444, 3333). Ghi chú ngắn cho các lệnh flood: chạy vài giây rồi Ctrl+C để không làm đầy hàng đợi engine.

- [ ] **Step 4: Chạy để thấy pass**

Run: `python -m pytest tests/test_demo_commands.py -v -p no:cacheprovider`
Expected: toàn bộ pass. Nếu một SID trong bảng không tồn tại, sửa lại SID (tra `rules/local.rules`) cho tới khi pass — không thêm rule mới trong task này.

- [ ] **Step 5: Chạy toàn bộ test**

Run: `python -m pytest -q -p no:cacheprovider`
Expected: toàn bộ pass (không đổi hành vi engine/rule/API).

- [ ] **Step 6: Commit** (chỉ khi người dùng đồng ý)

```bash
git add docs/demo/kich-ban-demo.md tests/test_demo_commands.py
git commit -m "docs(demo): bang lenh go tay (nmap, ping, ftp...) voi SID ky vong, co test khop rule"
```

---

### Task 4: Cập nhật CLAUDE.md và README.md

**Files:**
- Modify: `CLAUDE.md`, `README.md`

**Interfaces:**
- Consumes: không có logic, chỉ mô tả lại Task 1–3 cho người đọc sau.
- Produces: không có interface mới.

- [ ] **Step 1**: Trong `CLAUDE.md`, mục Docker (phần "Trong Docker, `nids_engine` dùng..."), thêm một câu: attacker build từ Kali (`attacker/Dockerfile`) để gõ lệnh dòng lệnh trực tiếp; victim build từ `victim/Dockerfile`, chạy thêm FTP anonymous, SSH và hai listener TCP (4444, 3333) để các lệnh đó chạm được dịch vụ thật. Nhắc `attacker/attack_demo.py` vẫn là phương án dự phòng.

- [ ] **Step 2**: Trong `README.md`, mục "Cách 2: Demo trực tiếp bằng Docker" (đã có từ trước, nói về `attack_demo.py`), thêm đoạn ngắn: có thể vào `docker exec -it nids_attacker bash` và gõ lệnh trực tiếp theo bảng trong `docs/demo/kich-ban-demo.md`.

- [ ] **Step 3: Chạy toàn bộ test**

Run: `python -m pytest -q -p no:cacheprovider`
Expected: toàn bộ pass (bao gồm `tests/test_code_language.py` nếu đoạn thêm vào dùng tiếng Việt có dấu đúng quy ước).

- [ ] **Step 4: Commit** (chỉ khi người dùng đồng ý)

```bash
git add CLAUDE.md README.md
git commit -m "docs: ghi chu attacker Kali va victim nhieu dich vu trong CLAUDE.md, README"
```

## Verification thủ công (người dùng tự làm, cần Docker daemon chạy)

1. `docker compose build` (lần đầu cần Internet để kéo `kalilinux/kali-rolling` và các gói apt).
2. `docker compose up -d`; `docker compose ps` cả 5 container `running`.
3. `docker exec -it nids_attacker bash`; trong đó `nmap -p 21,22,53,80,3333,4444 172.28.0.50` phải thấy 21, 22, 80, 3333, 4444 ở trạng thái `open` (53 có thể `closed`/`filtered` nếu không cài DNS server, không ảnh hưởng các rule đã liệt kê trong bảng lệnh).
4. Chạy lần lượt các lệnh trong mục "Demo gõ lệnh thủ công" của `docs/demo/kich-ban-demo.md`; `docker logs -f nids_engine` và dashboard `http://localhost:8000/` phải hiện đúng SID kỳ vọng.
5. `ping -c 3 172.28.0.50` và `curl http://172.28.0.50/` không sinh alert nào.
