# Hướng dẫn cài đặt trên Linux

Tài liệu này hướng dẫn chạy Hybrid NIDS trên Linux (Ubuntu/Debian; distro khác chỉ khác lệnh cài gói). Có hai cách:

- **Cách A: Docker lab.** Chạy đủ MySQL, Redis, victim, engine, honeypot, redirector, API và máy attacker. Nên dùng cách này để demo.
- **Cách B: chạy trực tiếp trên máy.** Dùng SQLite, sniff card mạng thật hoặc đọc file pcap. Hợp khi cần sửa code và chạy test.

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

## 4. Lỗi thường gặp

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
