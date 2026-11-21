# Hướng dẫn cài đặt và chạy

Có hai cách chạy:

| Cách | Gồm | Dùng khi |
|---|---|---|
| **A. Docker lab** | MySQL, Redis, victim, engine, honeypot, redirector, API, máy attacker Kali | Demo, thử tấn công thật |
| **B. Chạy trực tiếp** | Engine, API, honeypot trên máy, dùng SQLite | Sửa code, chạy test, đọc pcap |

Mọi lệnh chạy từ **thư mục gốc repo**.

## 1. Yêu cầu

| Thành phần | Cách A | Cách B |
|---|---|---|
| Docker Engine / Docker Desktop với Compose v2 | Bắt buộc | |
| Python 3.10+ và `pip` | | Bắt buộc |
| Driver bắt gói | | Windows: [Npcap](https://npcap.com/#download), chọn *WinPcap API-compatible Mode*. Linux: `libpcap-dev` |
| Quyền admin/root | | Khi sniff live |

```bash
git clone https://github.com/74Teams/intrusion-detection-system.git
cd intrusion-detection-system
```

## 2. Cách A: Docker lab

### 2.1 Tạo `.env`

Compose từ chối chạy nếu thiếu mật khẩu. Dùng chuỗi hex, không chứa `$`, dấu nháy hay backtick.

```bash
cp .env.example .env
sed -i "s/^MYSQL_ROOT_PASSWORD=.*/MYSQL_ROOT_PASSWORD=$(openssl rand -hex 24)/" .env
sed -i "s/^NIDS_DB_PASSWORD=.*/NIDS_DB_PASSWORD=$(openssl rand -hex 24)/" .env
sed -i "s/^NIDS_REDIS_PASSWORD=.*/NIDS_REDIS_PASSWORD=$(openssl rand -hex 24)/" .env
sed -i "s/^NIDS_API_KEY=.*/NIDS_API_KEY=$(openssl rand -hex 32)/" .env      # tuỳ chọn: cho phép sửa rule trên web
```

Trên Windows thì mở `.env` và điền tay. Không cần tạo `common/config/settings.yaml`: thiếu file này thì chương trình dùng `common/config/settings.example.yaml`, vốn cấu hình sẵn cho lab.

### 2.2 Khởi động

```bash
docker compose up --build -d                       # thêm --profile lab nếu cần máy attacker (mục 2.3)
docker compose ps
docker logs -f nids_engine            # chờ dòng "Đã nạp ... rule" và "Lắng nghe trực tiếp"
```

| Trang | URL |
|---|---|
| Dashboard | http://localhost:8000/ |
| System Logs | http://localhost:8000/logs |
| Traffic | http://localhost:8000/traffic |
| Rules | http://localhost:8000/rules |
| Swagger | http://localhost:8000/docs |

### 2.3 Tấn công thử

Máy attacker nằm trong profile `lab` nên chỉ chạy khi bạn bật nó:

```bash
docker compose --profile lab up -d
docker exec -it nids_attacker python lab/attacker/attack_demo.py all       # mọi rule
docker exec -it nids_attacker python lab/attacker/attack_demo.py web       # hoặc: scan | dos | auth | malware | recon | honeypot
docker exec -it nids_attacker bash                                         # tự gõ lệnh, ví dụ: nmap -sX -p 80 172.28.0.50
```

Kịch bản trình diễn đầy đủ: [demo-flow-explanation.md](demo-flow-explanation.md).

### 2.4 Dừng và chạy lại

| Lệnh | Dữ liệu MySQL |
|---|---|
| `docker compose stop` / `docker compose restart` | Giữ |
| `docker compose down` | **Mất** (volume ẩn danh) |

Muốn xoá cảnh báo để chạy lại từ đầu thì bấm **Xoá dữ liệu** trên dashboard, hoặc chạy `curl -X DELETE http://localhost:8000/api/alerts/`.

## 3. Cách B: chạy trực tiếp

### 3.1 Cài đặt

```bash
# Linux: cài gói hệ thống
sudo apt install -y python3 python3-venv python3-pip python3-dev build-essential libpcap-dev

python3 -m venv .venv
source .venv/bin/activate              # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt
cp common/config/settings.example.yaml common/config/settings.yaml     # Windows: copy

# Đặt PYTHONPATH (mã nguồn nằm ở nhiều thư mục src/), mỗi terminal một lần:
source scripts/env.sh                  # PowerShell: . .\scripts\env.ps1
```

Không đặt `PYTHONPATH` thì lệnh `python -m nids...` báo `No module named 'nids'`. `pytest` tự đặt qua `pytest.ini` nên không cần bước này.

### 3.2 Cấu hình local

Sửa `common/config/settings.yaml` (file bị gitignore):

```yaml
network:
  interface: ""                   # rỗng = card mặc định; Linux xem tên bằng: ip -br link
  capture_mode: "live"            # hoặc "offline" để đọc pcap
  # pcap_file: "data/pcap/demo_traffic.pcap"
  bpf_filter: "ip and not port 3306 and not (host 172.28.0.30 and port 6379)"   # giữ nguyên

database:
  type: "sqlite"
  db_url: "sqlite:///nids_events.db"

redis:
  host: ""                        # rỗng = tắt Redis, dashboard tự poll

redirect:
  enabled: false                  # redirector chỉ chạy trong Docker lab
```

Biến môi trường ghi đè cấu hình:

- `NIDS_DB_HOST`, `NIDS_DB_PORT`, `NIDS_DB_NAME`, `NIDS_DB_USER`, `NIDS_DB_PASSWORD`;
- `NIDS_REDIS_HOST`, `NIDS_REDIS_PORT`, `NIDS_REDIS_PASSWORD`;
- `HONEYPY_*` cho honeypot.

### 3.3 Chạy các process

Mỗi process chạy trong một terminal riêng.

```bash
# Engine: sniff live cần quyền admin/root; chế độ offline thì không cần
sudo .venv/bin/python -m nids.engine          # Linux (sudo python sẽ không thấy venv)
python -m nids.engine                          # Windows: chạy terminal bằng quyền Administrator

# API và dashboard
uvicorn nids.api.main:app --host 0.0.0.0 --port 8000 --reload

# Honeypot (tuỳ chọn)
python -m nids.honeypot ssh                    # cổng 2222
python -m nids.honeypot http                   # cổng 8080
```

- Trên Linux có thể chạy engine không cần `sudo` bằng cách cấp quyền bắt gói cho python của venv (chỉ nên làm trên máy lab): `sudo setcap cap_net_raw,cap_net_admin=eip "$(readlink -f .venv/bin/python)"`.
- Muốn sửa rule trên web thì đặt `NIDS_API_KEY` trước khi chạy API. Không đặt thì trang Rules chỉ xem được.

### 3.4 Chạy test

```bash
pytest
pytest services/sensor/tests/engine/test_diverse_rules_engine.py::test_name     # một test
```

Test đọc rule thật trong `data/rules/`. Nếu `data/rules/state.yaml` local (do trang Rules ghi) đang tắt rule tự viết, các test rule sẽ fail. Đổi tên file đó tạm thời khi chạy test.

## 4. Lỗi thường gặp

| Lỗi | Cách xử lý |
|---|---|
| `PermissionError: Operation not permitted` khi chạy engine | Thiếu quyền bắt gói: chạy bằng `sudo .venv/bin/python` (Linux) hoặc terminal Administrator (Windows) |
| `ModuleNotFoundError` khi chạy với `sudo` | `sudo python` gọi python hệ thống. Dùng `sudo .venv/bin/python` |
| `OSError: No such device` | Sai tên interface; kiểm tra bằng `ip -br link` |
| `database is locked` (SQLite) | Nhiều process cùng ghi một file SQLite. Đã có WAL và timeout 30 giây; vẫn lỗi thì dừng process thừa hoặc dùng MySQL |
| `docker compose` báo `đặt trong .env` | `.env` thiếu mật khẩu; làm lại mục 2.1 |
| `permission denied ... docker.sock` | User chưa thuộc nhóm `docker`: `sudo usermod -aG docker $USER` rồi đăng nhập lại |
| Engine không kết nối được MySQL vài giây đầu | Bình thường, MySQL khởi động chậm; `init_db()` thử lại 15 lần |
| Đổi mật khẩu trong `.env` nhưng MySQL vẫn từ chối | Mật khẩu chỉ áp dụng khi MySQL tạo dữ liệu lần đầu. Dùng `ALTER USER` trong container `nids_mysql`, hoặc `docker compose down` rồi chạy lại (mất dữ liệu) |
| Dashboard trống dù đã tấn công | Kiểm tra lần lượt: `docker logs nids_engine` có cảnh báo không; `docker compose ps` mọi container `running`; `curl http://localhost:8000/health` |
| Cổng 8000, 2222 hoặc 8080 bị chiếm | `sudo ss -ltnp \| grep 8000`, dừng process đó hoặc đổi cổng |
| `InconsistentVersionWarning` khi nạp mô hình AI | Bản scikit-learn khác bản đã huấn luyện (1.9.1) |
