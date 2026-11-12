# Hướng dẫn cài đặt trên Linux

Tài liệu này hướng dẫn chạy Hybrid NIDS trên Linux (Ubuntu/Debian; distro khác chỉ khác lệnh cài gói). Có ba cách:

- **Cách A: Docker lab.** Chạy đủ MySQL, Redis, victim, engine, honeypot, redirector, API và máy attacker. Nên dùng cách này để demo.
- **Cách B: chạy trực tiếp trên máy.** Dùng SQLite, sniff card mạng thật hoặc đọc file pcap. Hợp khi cần sửa code và chạy test.
- **Cách C: lab 3 máy ảo trên VMware.** Kali (attacker), IDS làm gateway và Victim kèm honeypot là các máy riêng, gần với mạng thật hơn Docker lab (mục 4).

Mọi lệnh đều chạy từ thư mục gốc repo.

---

## 1. Lấy mã nguồn

```bash
sudo apt update
sudo apt install -y git
git clone https://github.com/74Teams/intrusion-detection-system.git
cd intrusion-detection-system
```

---

## 2. Cách A: Docker lab

### 2.1. Cài Docker Engine và Compose v2

```bash
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker $USER     # để chạy docker không cần sudo
newgrp docker                     # hoặc đăng xuất rồi đăng nhập lại
docker compose version            # phải là v2.x
```

### 2.2. Tạo file `.env`

Compose sẽ từ chối chạy nếu thiếu mật khẩu. Hãy dùng chuỗi hex, không chứa `$`, dấu nháy hay backtick.

```bash
cp .env.example .env
sed -i "s/^MYSQL_ROOT_PASSWORD=.*/MYSQL_ROOT_PASSWORD=$(openssl rand -hex 24)/" .env
sed -i "s/^NIDS_DB_PASSWORD=.*/NIDS_DB_PASSWORD=$(openssl rand -hex 24)/" .env
sed -i "s/^NIDS_REDIS_PASSWORD=.*/NIDS_REDIS_PASSWORD=$(openssl rand -hex 24)/" .env
sed -i "s/^NIDS_API_KEY=.*/NIDS_API_KEY=$(openssl rand -hex 32)/" .env   # tuỳ chọn: cho phép sửa rule trên web
```

Không cần tạo `config/settings.yaml`. Khi file này không tồn tại, chương trình dùng `config/settings.example.yaml`, vốn đã cấu hình sẵn cho lab (live trên `eth0`, MySQL `172.28.0.10`).

### 2.3. Khởi động

```bash
docker compose up --build -d
docker compose ps
docker logs -f nids_engine        # chờ dòng "Đã nạp ... rule"
```

Mở dashboard tại http://localhost:8000/ (Swagger ở http://localhost:8000/docs).

### 2.4. Chạy đòn tấn công demo

```bash
docker exec -it nids_attacker python lab/attacker/attack_demo.py all     # mọi rule
docker exec -it nids_attacker python lab/attacker/attack_demo.py web     # hoặc: scan | dos | auth | malware | recon | honeypot
docker exec -it nids_attacker bash                                      # tự gõ lệnh, vd: nmap -sX -p 80 172.28.0.50
```

Kịch bản thuyết trình đầy đủ nằm ở [demo/kich-ban-demo.md](demo/kich-ban-demo.md).

### 2.5. Dừng và chạy lại

```bash
docker compose stop               # dừng, giữ dữ liệu
docker compose restart            # khởi động lại, giữ dữ liệu
docker compose down               # xoá container, MẤT dữ liệu MySQL (volume ẩn danh)
```

Muốn xoá cảnh báo để chạy lại từ đầu thì bấm **Xoá dữ liệu** trên dashboard, hoặc chạy `curl -X DELETE http://localhost:8000/api/alerts/`.

---

## 3. Cách B: chạy trực tiếp trên máy

### 3.1. Cài gói hệ thống

```bash
sudo apt install -y python3 python3-venv python3-pip python3-dev build-essential libpcap-dev
python3 --version                 # cần 3.10 trở lên
```

### 3.2. Tạo virtualenv và cài thư viện

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

### 3.3. Tạo cấu hình local

```bash
cp config/settings.example.yaml config/settings.yaml
ip -br link                       # xem tên card mạng, vd: enp3s0, wlp2s0
```

Sửa `config/settings.yaml` (file này bị git ignore):

```yaml
network:
  interface: "enp3s0"             # tên card lấy từ lệnh ip -br link; để "" thì dùng card mặc định
  capture_mode: "live"            # hoặc "offline" để đọc pcap
  # pcap_file: "pcap/demo_traffic.pcap"   # dùng khi capture_mode: "offline"

database:
  type: "sqlite"
  db_url: "sqlite:///nids_events.db"

redis:
  host: ""                        # rỗng = tắt Redis, dashboard tự poll

redirect:
  enabled: false                  # redirector chỉ chạy trong Docker lab
```

Giữ nguyên `bpf_filter`. Lý do nằm ở mục Known Issues trong `CLAUDE.md`.

### 3.4. Chạy các process

Mỗi process chạy trong một terminal riêng. Terminal nào cũng phải `source .venv/bin/activate` trước.

**Engine.** Sniff live cần quyền root. Lệnh `sudo python` sẽ không thấy venv, nên gọi thẳng python của venv:

```bash
sudo .venv/bin/python -m nids.engine
```

Muốn chạy không cần sudo thì cấp quyền bắt gói cho python của venv (chỉ nên làm trên máy lab):

```bash
sudo setcap cap_net_raw,cap_net_admin=eip "$(readlink -f .venv/bin/python)"
python -m nids.engine
```

Ở chế độ `offline` (đọc pcap), engine không cần root.

**API và dashboard:**

```bash
uvicorn nids.api.main:app --host 0.0.0.0 --port 8000 --reload
```

Muốn sửa rule trên web thì chạy `export NIDS_API_KEY=$(openssl rand -hex 32)` trước lệnh trên. Không đặt biến này thì trang Rules chỉ xem được, không sửa được.

**Honeypot (tuỳ chọn):**

```bash
python -m nids.honeypot ssh       # cổng 2222
python -m nids.honeypot http      # cổng 8080
```

Mở http://localhost:8000/.

### 3.5. Chạy test

```bash
pytest
pytest tests/engine/test_diverse_rules_engine.py::test_name   # chạy một test
```

---

## 4. Cách C: lab 3 máy ảo trên VMware

Mô hình: Kali tấn công Victim, nhưng mọi gói phải đi qua máy IDS (gateway) nên engine thấy hết. Redirector trên IDS dùng `DNAT` để chuyển IP đáng ngờ sang honeypot nằm ở Victim. Docker lab ở Cách A không bị ảnh hưởng.

```
                    VMnet8 (NAT): mở dashboard từ Windows, cài gói
                              │ ens33 (DHCP)
[Kali]  ──VMnet2──  ens34 [IDS / gateway] ens35  ──VMnet3──  [Victim + Honeypot]
10.10.1.100        10.10.1.1          10.10.2.1             10.10.2.50
gw 10.10.1.1       engine, API :8000, MySQL, Redis,         nginx :80, vsftpd :21, sshd :22,
                   redirector (iptables nat)                honeypot ssh :2222, http :8080
```

Cấu hình tối thiểu: Kali 2–4 GB RAM (có thể dùng bản không GUI), IDS 2 GB, Victim 1 GB. IDS và Victim là Ubuntu Server. Các file mẫu nằm trong [lab/vmware/](../lab/vmware/).

### 4.1. Tạo mạng ảo trong VMware (trên Windows, làm một lần)

**Edit → Virtual Network Editor → Change Settings** (cần quyền admin), rồi **Add Network**:

| Mạng | Kiểu | Subnet | DHCP | Host virtual adapter |
|------|------|--------|------|----------------------|
| VMnet2 | Host-only | 10.10.1.0 / 255.255.255.0 | **tắt** | **tắt** |
| VMnet3 | Host-only | 10.10.2.0 / 255.255.255.0 | **tắt** | **tắt** |
| VMnet8 | NAT | giữ mặc định | giữ mặc định | giữ mặc định |

Phải tắt "Connect a host virtual adapter": nếu để bật, Windows chiếm `10.10.1.1` hoặc `10.10.2.1`, trùng IP của IDS. LAN Segment cũng dùng được thay cho host-only.

Tắt VM rồi gắn card (**Settings → Add → Network Adapter → Custom: Specific virtual network**):

| VM | Card | Mạng |
|----|------|------|
| Kali | 1 | VMnet2 |
| IDS | 1 | VMnet8 (NAT) |
| IDS | 2 | VMnet2 |
| IDS | 3 | VMnet3 |
| Victim | 1 | VMnet3 |
| Victim | 2 (tạm) | VMnet8 (NAT), ngắt sau khi build xong |
| Kali | 2 (tạm) | VMnet8 (NAT), chỉ để `git clone` |

### 4.2. Đặt IP tĩnh

Trong mỗi VM, chạy `ip -br link` để biết tên card rồi đối chiếu MAC với **Settings → Network Adapter → Advanced** của VMware. Tên card có thể khác `ens33/34/35`; nếu khác thì sửa file mẫu và `network.interface` trong `lab/vmware/settings.ids.yaml`.

```bash
# IDS và Victim (Ubuntu): chép netplan mẫu, sửa tên card nếu cần
sudo cp lab/vmware/netplan/ids.yaml    /etc/netplan/50-lab.yaml     # trên VM IDS
sudo cp lab/vmware/netplan/victim.yaml /etc/netplan/50-lab.yaml     # trên VM Victim
sudo chmod 600 /etc/netplan/50-lab.yaml && sudo netplan apply

# Kali (NetworkManager); đổi eth0 nếu tên card khác
sudo nmcli con add type ethernet ifname eth0 con-name lab ipv4.method manual \
  ipv4.addresses 10.10.1.100/24 ipv4.routes "10.10.2.0/24 10.10.1.1"
sudo nmcli con up lab
```

Kali chỉ thêm route tới `10.10.2.0/24` qua IDS, không đặt default gateway, để card NAT tạm vẫn cho Kali ra Internet khi `git clone`.

Trên Victim, route mặc định qua IDS có metric 200 nên card NAT tạm (DHCP) thắng khi còn cắm. Nhờ vậy Victim có Internet để clone và build; rút card NAT ra thì mọi traffic đi qua IDS. Cái giá là khi card NAT còn cắm, gói trả lời Kali cũng đi ra NAT và Kali không ping được Victim: **trước khi kiểm tra hoặc demo từ Kali, hãy ngắt card NAT của Victim** (VMware: Settings → Network Adapter 2 → bỏ Connected).

Chưa có repo trên VM thì clone trước (mục 1; đang thử nhánh chưa merge thì `git clone -b feature/68-vmware-lab <url>`). Victim và Kali cần card NAT tạm mới clone được; Victim không có Internet thì clone ở IDS rồi `scp -r` sang (làm trước khi tắt sshd ở mục 4.4).

Sau khi đặt IP xong, chạy bước kiểm tra mạng của mục 4.6 (bước 1–3) khi chưa cài Docker, rồi chụp snapshot cả 3 VM (VM → Snapshot → Take Snapshot) để hỏng thì quay lại được.

### 4.3. VM IDS

```bash
# 1. Chuyển tiếp gói giữa hai card
echo 'net.ipv4.ip_forward=1' | sudo tee /etc/sysctl.d/99-nids.conf && sudo sysctl --system
sysctl net.ipv4.ip_forward                  # phải ra = 1

# 2. Cài Docker (mục 2.1), rồi mở FORWARD cho hai chiều ens34 <-> ens35.
#    Docker đặt policy FORWARD là DROP nên thiếu bước này Kali không tới được Victim.
sudo iptables -I DOCKER-USER -i ens34 -o ens35 -j ACCEPT
sudo iptables -I DOCKER-USER -i ens35 -o ens34 -j ACCEPT
sudo apt install -y iptables-persistent && sudo netfilter-persistent save   # giữ rule sau khi reboot

# 3. Mật khẩu: .env của lab nằm cạnh file compose
cp lab/vmware/.env.example lab/vmware/.env
for k in MYSQL_ROOT_PASSWORD NIDS_DB_PASSWORD NIDS_REDIS_PASSWORD; do
  sed -i "s/^$k=.*/$k=$(openssl rand -hex 24)/" lab/vmware/.env
done
sed -i "s/^NIDS_API_KEY=.*/NIDS_API_KEY=$(openssl rand -hex 32)/" lab/vmware/.env   # tuỳ chọn

# 4. Chạy
docker compose -f lab/vmware/compose.ids.yml up --build -d
docker compose -f lab/vmware/compose.ids.yml ps
docker logs -f nids_engine                  # chờ dòng "Đã nạp ... rule"
docker logs nids_redirector                 # phải ghi "Chế độ DNAT: ... 10.10.2.50"
```

Rule `DOCKER-USER` chỉ thêm được khi Docker đã chạy (chain này do Docker tạo). Nếu `netfilter-persistent` khôi phục rule trước Docker thì chép lệnh `iptables -I DOCKER-USER ...` vào một unit `oneshot` chạy sau `docker.service`.

Mở dashboard từ Windows: `http://<IP của ens33 trên IDS>:8000/` (xem bằng `ip -4 addr show ens33`).

### 4.4. VM Victim

```bash
# 1. Nhường cổng 22 cho sshd trong container (sau bước này mất SSH vào VM, hãy dùng console VMware)
sudo systemctl disable --now ssh.service ssh.socket

# 2. Cài Docker (mục 2.1), dùng CÙNG ba mật khẩu với VM IDS
cp lab/vmware/.env.example lab/vmware/.env      # rồi điền đúng giá trị đã tạo trên IDS

# 3. Build và chạy (cần card NAT tạm); build xong thì ngắt card NAT trong VMware
docker compose -f lab/vmware/compose.victim.yml up --build -d
docker compose -f lab/vmware/compose.victim.yml ps
```

Victim không ra Internet được thì build image ở IDS rồi chuyển sang: `docker save hybrid-nids-app | ssh user@10.10.2.50 docker load` (tương tự cho image `victim`).

### 4.5. VM Kali

Không cần Docker. Chỉ cần repo, Scapy và `hydra` (Kali có sẵn):

```bash
git clone https://github.com/74Teams/intrusion-detection-system.git && cd intrusion-detection-system
sudo python3 lab/attacker/attack_demo.py all --target 10.10.2.50     # hoặc: web | scan | dos | auth | malware | recon | honeypot
```

### 4.6. Kiểm tra từng tầng

Tầng nào hỏng thì dừng ở đó, đừng đi tiếp. Các bước có Kali ↔ Victim chỉ đúng khi card NAT tạm của Victim đã ngắt (mục 4.2).

| # | Chạy ở | Lệnh | Kết quả đúng |
|---|--------|------|--------------|
| 1 | Kali | `ping -c2 10.10.1.1` | thông (Kali ↔ IDS) |
| 2 | Victim | `ping -c2 10.10.2.1` | thông (Victim ↔ IDS) |
| 3 | Kali | `ping -c2 10.10.2.50` và `curl http://10.10.2.50/` | thông, trả trang nginx (qua IDS) |
| 4 | IDS | `sudo tcpdump -ni ens34 host 10.10.1.100` rồi ping từ Kali | thấy gói |
| 5 | Kali | `attack_demo.py web --target 10.10.2.50` | dashboard có cảnh báo, SID khớp log của attacker |
| 6 | Kali | `attack_demo.py honeypot --target 10.10.2.50` | trang Logs có sự kiện `HONEYPOT`, `src_ip` là `10.10.1.100` (không bị SNAT) |
| 7 | Kali | sau ≥ 5 cảnh báo P1/P2: `ssh root@10.10.2.50` | hiện banner honeypot |
| 8 | IDS | `sudo iptables -t nat -S NIDS_REDIRECT` và `curl http://localhost:8000/api/redirects` | có rule `DNAT --to-destination 10.10.2.50:2222`, có dòng `10.10.1.100` |

Kiểm tra bước 8 bằng `iptables` của host, không phải trong container: nếu rule trong container không thấy ở host thì hai bên dùng khác backend (nft/legacy), xem bảng lỗi bên dưới.

Muốn thử Redis tắt: `docker compose -f lab/vmware/compose.ids.yml stop redis`. Engine và honeypot vẫn ghi DB, dashboard quay về poll.

### 4.7. Lỗi thường gặp (Cách C)

| Triệu chứng | Nguyên nhân thường gặp |
|-------------|------------------------|
| Kali ping được IDS nhưng không ping được Victim | Chưa bật `ip_forward` hoặc chưa thêm rule `DOCKER-USER` (mục 4.3). |
| Ping tới nhưng không có đường về | Victim thiếu default gateway `10.10.2.1`, hoặc card NAT tạm của Victim còn cắm (gói trả lời ra NAT thay vì qua IDS): ngắt card NAT trong VMware. |
| Không ping được cả IDS | Gắn nhầm card vào VMnet, hoặc sai tên card trong netplan. |
| IP `10.10.x.1` báo trùng hoặc chập chờn | Windows đang giữ host virtual adapter (chưa tắt ở mục 4.1). |
| `docker build` trên Victim lỗi mạng | Card NAT tạm chưa bật (VMware: Network Adapter 2 phải ở trạng thái Connected), hoặc `ens34` chưa nhận DHCP: kiểm tra `ip -br addr`. |
| Engine báo `No such device` | `network.interface` trong `lab/vmware/settings.ids.yaml` không trùng tên card phía Kali. |
| Redirector có rule trong container nhưng `iptables -t nat -S` trên host không thấy | Container (Debian) dùng backend nft còn host dùng legacy hoặc ngược lại. Trên host: `sudo update-alternatives --set iptables /usr/sbin/iptables-nft` (hoặc `-legacy`) cho trùng với image rồi chạy lại redirector. |
| Container victim không khởi động, cổng 22 bị chiếm | `ssh.service` hoặc `ssh.socket` của Ubuntu còn chạy: làm lại mục 4.4 bước 1. |
| Honeypot ở Victim không ghi được DB | Mật khẩu `.env` hai VM khác nhau, hoặc Victim không ping được `10.10.2.1`. |
| Có file `config/settings.yaml` rỗng trong repo trên VM | Do Docker tạo điểm gắn cho `settings.ids.yaml`. File bị git ignore nên bỏ qua được; xoá đi nếu muốn chạy Cách B trên máy đó. |

Dashboard (cổng 8000) nghe ở mọi card nên Kali cũng mở được; thao tác ghi rule vẫn cần `NIDS_API_KEY`. Muốn chặn hẳn thì thêm rule `INPUT` trên IDS, ví dụ `sudo iptables -I INPUT -i ens34 -p tcp --dport 8000 -j DROP`. Đây là bước tuỳ chọn, mặc định lab không làm.

Các hạn chế: Victim và honeypot dùng chung một máy, chưa có VM honeypot riêng; chỉ hỗ trợ IPv4.

---

## 5. Lỗi thường gặp

| Lỗi | Cách xử lý |
|-----|------------|
| `PermissionError: [Errno 1] Operation not permitted` khi chạy engine | Engine thiếu quyền bắt gói. Chạy bằng `sudo .venv/bin/python -m nids.engine` hoặc dùng `setcap` như mục 3.4. |
| `ModuleNotFoundError` khi chạy với `sudo` | `sudo python` gọi python hệ thống, không phải python của venv. Dùng `sudo .venv/bin/python`. |
| `OSError: ... No such device` | Sai tên interface. Kiểm tra lại bằng `ip -br link`. |
| `sqlite3.OperationalError: database is locked` | Có nhiều process cùng ghi một file SQLite. Code đã đặt timeout 30s và bật WAL. Nếu vẫn lỗi, hãy dừng các process thừa hoặc chuyển sang MySQL. |
| `docker compose` báo `đặt trong .env` | `.env` thiếu mật khẩu. Làm lại mục 2.2. |
| `permission denied ... docker.sock` | User chưa nằm trong nhóm `docker`. Chạy `sudo usermod -aG docker $USER` rồi đăng nhập lại. |
| Engine báo không kết nối được MySQL trong vài giây đầu | Đây là hiện tượng bình thường vì MySQL khởi động chậm. `init_db()` sẽ thử lại tối đa 15 lần. |
| Đổi mật khẩu trong `.env` nhưng MySQL vẫn từ chối | Mật khẩu chỉ được áp dụng khi MySQL tạo dữ liệu lần đầu. Dùng `ALTER USER` trong container `nids_mysql` hoặc `docker compose down` rồi chạy lại (mất dữ liệu). |
| Cổng 8000, 2222 hoặc 8080 đã bị chiếm | Tìm process đang chiếm bằng `sudo ss -ltnp \| grep 8000`, rồi dừng nó hoặc đổi cổng. |
