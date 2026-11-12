# Dựng lab 3 máy ảo trên VMware (Kali, IDS, Victim)

Hướng dẫn từng bước, viết theo đúng quá trình đã dựng thật (PLAN-008, issue #68). Mục "Cách C" của [setup-linux.md](setup-linux.md) là bản tóm tắt; tài liệu này chi tiết hơn và ghi cả các lỗi đã gặp.

Ba máy ảo, mọi traffic từ Kali tới Victim buộc phải đi qua IDS (IDS làm gateway) nên engine thấy hết:

```
                    VMnet8 (NAT): mở dashboard từ Windows, cài gói
                              │ ens33 (DHCP)
[Kali]  ──VMnet2──  ens34 [IDS / gateway] ens35  ──VMnet3──  [Victim + Honeypot]
10.10.1.100        10.10.1.1          10.10.2.1             10.10.2.50
```

| Máy | Hệ điều hành | RAM / CPU | Vai trò |
|-----|--------------|-----------|---------|
| IDS | Ubuntu Server 22.04/24.04 | 2 GB / 2 | engine, API + dashboard :8000, MySQL, Redis, redirector (đặt rule DNAT) |
| Victim | Ubuntu Server 22.04/24.04 | 1–2 GB / 1 | nginx :80, vsftpd :21, sshd :22, honeypot SSH :2222 và HTTP :8080 |
| Kali | Kali bản dựng sẵn cho VMware | 2–4 GB / 2 | chạy `attack_demo.py` |

Tên card (`ens33`, `ens34`...) **khác nhau giữa các máy**, nên mọi lệnh dưới đây phải đối chiếu với `ip -br link` của máy bạn (xem mục 3).

---

## 1. Tạo mạng ảo VMnet2 và VMnet3 (làm một lần, trên Windows)

**Edit → Virtual Network Editor → Change Settings** (cần quyền admin), rồi **Add Network**:

| Mạng | Kiểu | Subnet | DHCP | Host virtual adapter |
|------|------|--------|------|----------------------|
| VMnet2 | Host-only | 10.10.1.0 / 255.255.255.0 | **tắt** | **tắt** |
| VMnet3 | Host-only | 10.10.2.0 / 255.255.255.0 | **tắt** | **tắt** |
| VMnet8 | NAT | giữ mặc định | giữ mặc định | giữ mặc định |

Bỏ tick "Use local DHCP service" và "Connect a host virtual adapter to this network". Nếu để tick, Windows chiếm `10.10.x.1`, trùng IP của IDS.

## 2. Gắn card mạng cho từng VM

Tắt VM, rồi **Settings → Add → Network Adapter → Custom: Specific virtual network**:

| VM | Card | Mạng | Ghi chú |
|----|------|------|---------|
| Kali | 1 | VMnet2 | |
| Kali | 2 | VMnet8 (NAT) | tạm, chỉ để `git clone` |
| IDS | 1 | VMnet8 (NAT) | giữ lâu dài: mở dashboard, cài gói |
| IDS | 2 | VMnet2 | phía Kali |
| IDS | 3 | VMnet3 | phía Victim |
| Victim | VMnet3 | VMnet3 | nối tới IDS |
| Victim | NAT | VMnet8 (NAT) | tạm: clone, cài Docker, build |

Mỗi VM đều tick **Connected** và **Connect at power on** cho card cần dùng.

## 3. Biết card nào là card nào

Trong mỗi VM Ubuntu chạy `ip -br link`, rồi đối chiếu địa chỉ MAC với **Settings → Network Adapter → Advanced → MAC Address** trong VMware. Cách nhanh hơn: card nào nhận được IP DHCP dạng `192.168.x.x` (ví dụ `ip -br addr`) là card nối NAT.

Trường hợp đã gặp: Victim cài khi chỉ có một card NAT nên card đó là `ens33` (nhận DHCP), còn card VMnet3 thêm sau là `ens34`. Netplan phải đặt IP lab lên `ens34`, không phải `ens33`. Đặt nhầm thì IDS ping Victim không thông, và `ens33` có cả IP tĩnh lẫn IP DHCP.

## 4. Đặt IP tĩnh

Các file mẫu nằm trong [lab/vmware/netplan/](../lab/vmware/netplan/). Chép vào `/etc/netplan/50-lab.yaml`, **sửa tên card cho đúng máy bạn**, rồi:

```bash
sudo chmod 600 /etc/netplan/50-lab.yaml
sudo netplan apply
ip -br addr
```

**IDS** (`/etc/netplan/50-lab.yaml`):

```yaml
network:
  version: 2
  ethernets:
    ens33: { dhcp4: true }                # NAT
    ens34: { addresses: [10.10.1.1/24] }  # VMnet2, phía Kali
    ens35: { addresses: [10.10.2.1/24] }  # VMnet3, phía Victim
```

**Victim** (giữ nguyên file cài đặt cũ cho card NAT; `50-lab.yaml` chỉ cấu hình card VMnet3). Ví dụ card VMnet3 là `ens34`:

```yaml
network:
  version: 2
  ethernets:
    ens34:
      dhcp4: false
      addresses: [10.10.2.50/24]
      routes:
        - to: default
          via: 10.10.2.1
          metric: 200      # card NAT (DHCP, metric 100) thắng khi còn cắm; ngắt NAT thì đi qua IDS
```

Chạy `ls /etc/netplan/` để chắc không có file khác cũng cấu hình cùng card theo kiểu mâu thuẫn.

**Kali** (NetworkManager, card thường là `eth0`). Chỉ thêm route tới mạng Victim, **không đặt default gateway** để card NAT tạm vẫn cho Kali ra Internet:

```bash
sudo nmcli con add type ethernet ifname eth0 con-name lab \
  ipv4.method manual ipv4.addresses 10.10.1.100/24 \
  ipv4.routes "10.10.2.0/24 10.10.1.1"
sudo nmcli con up lab
```

## 5. Biến IDS thành gateway

Trên IDS:

```bash
echo 'net.ipv4.ip_forward=1' | sudo tee /etc/sysctl.d/99-nids.conf
sudo sysctl --system
sysctl net.ipv4.ip_forward        # phải ra = 1
```

Kiểm tra mạng (chưa cần Docker):

| Chạy ở | Lệnh | Kết quả |
|--------|------|---------|
| IDS | `ping -c2 10.10.2.50` | thông |
| Victim | `ping -c2 10.10.2.1` | thông |
| Kali | `ping -c2 10.10.1.1` | thông |

Kali ping `10.10.2.50` chỉ thông khi **card NAT của Victim đã ngắt** (mục 9). Chụp snapshot cả 3 VM ở bước này (VM → Snapshot → Take Snapshot).

## 6. Lấy code và cài Docker (IDS và Victim)

Cần card NAT đang bật. Nhánh `feature/68-vmware-lab` chưa merge nên phải chỉ rõ nhánh:

```bash
sudo apt update && sudo apt install -y git
git clone -b feature/68-vmware-lab https://github.com/74Teams/hybrid-nids.git
cd hybrid-nids
git branch --show-current          # feature/68-vmware-lab
```

Cài Docker (nếu chưa có):

```bash
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker $USER && newgrp docker
docker compose version             # phải là v2.x
```

Về sau lấy bản mới bằng `git pull` trong thư mục `hybrid-nids`.

## 7. IDS: mở FORWARD, tạo `.env`, chạy

Mọi lệnh `docker compose` chạy từ **thư mục gốc repo** (`~/hybrid-nids`).

**7.1. Mở FORWARD giữa hai card** (Docker phải đã chạy để có chain `DOCKER-USER`):

```bash
sudo iptables -I DOCKER-USER -i ens34 -o ens35 -j ACCEPT
sudo iptables -I DOCKER-USER -i ens35 -o ens34 -j ACCEPT
sudo apt install -y iptables-persistent && sudo netfilter-persistent save   # chọn Yes khi hỏi
sudo iptables -S DOCKER-USER       # phải thấy hai rule ACCEPT
```

Policy FORWARD trên máy thử là `ACCEPT` nên Kali tới được Victim cả khi thiếu hai rule này, nhưng vẫn nên thêm để không phụ thuộc cấu hình Docker từng máy.

**7.2. Tạo `lab/vmware/.env`** (hai máy phải dùng cùng mật khẩu):

```bash
cp lab/vmware/.env.example lab/vmware/.env
for k in MYSQL_ROOT_PASSWORD NIDS_DB_PASSWORD NIDS_REDIS_PASSWORD; do sed -i "s/^$k=.*/$k=$(openssl rand -hex 24)/" lab/vmware/.env; done
sed -i "s/^NIDS_API_KEY=.*/NIDS_API_KEY=$(openssl rand -hex 32)/" lab/vmware/.env
cat lab/vmware/.env                # đủ 4 giá trị, không dòng nào trống
```

**7.3. Chép `.env` sang Victim** (làm trước khi tắt sshd của Victim ở mục 8; thay `ubuntu` bằng tên người dùng trên Victim):

```bash
scp lab/vmware/.env ubuntu@10.10.2.50:~/hybrid-nids/lab/vmware/
```

**7.4. Chạy IDS** (lần đầu build khoảng 5 phút):

```bash
docker compose -f lab/vmware/compose.ids.yml up --build -d
docker compose -f lab/vmware/compose.ids.yml ps        # 5 container Up, nids_mysql healthy
docker logs nids_redirector --tail 5                   # "Chế độ DNAT: ... 10.10.2.50"
docker logs nids_engine --tail 10                      # "Đã nạp 68 rule" và đang lắng nghe
```

Các dòng `CSDL chưa sẵn sàng (lần n/15)` ở đầu log là bình thường (MySQL khởi động chậm).

## 8. Victim: tắt sshd của Ubuntu, chạy container

Dùng **cửa sổ console VMware** cho bước này, vì tắt sshd xong có thể mất SSH. Card NAT phải còn cắm (cần Internet để build).

```bash
cd ~/hybrid-nids
cat lab/vmware/.env                                        # phải giống IDS
sudo systemctl disable --now ssh.service ssh.socket        # nhường cổng 22 cho container victim
systemctl is-active ssh.service ssh.socket                 # cả hai phải ra inactive
sudo ss -ltnp | grep ':22 ' || echo "cổng 22 đã rảnh"
docker compose -f lab/vmware/compose.victim.yml up --build -d
docker compose -f lab/vmware/compose.victim.yml ps         # 3 container Up
```

Cảnh báo `Disabling 'ssh.service', but its triggering units are still active: ssh.socket` có thể xuất hiện; chỉ cần `is-active` ra `inactive` là được. Nếu `ssh.socket` còn `active` thì `sudo systemctl stop ssh.socket`.

Cổng 2222 và 8080 (honeypot) **chưa lên ngay**: honeypot gọi `init_db()` (thử MySQL của IDS tối đa 15 lần × 2 giây) trước khi mở cổng. Khi IDS đã chạy, vài chục giây sau kiểm tra lại:

```bash
sudo ss -ltn | grep -E ':(21|22|80|2222|8080) '            # phải thấy đủ 5 cổng LISTEN
```

Vẫn thiếu 2222/8080 thì xem `docker logs nids_honeypot_ssh --tail 10` và thử `nc -zv 10.10.2.1 3306` từ Victim.

## 9. Ngắt card NAT của Victim

Trong VMware: **Settings → Network Adapter** (card đang dùng NAT) → bỏ tick **Connected** và **Connect at power on**, rồi OK. Không bấm Remove, và không ngắt nhầm card VMnet3. Làm được cả khi VM đang chạy.

Kiểm tra trong Victim:

```bash
ip route          # phải còn: default via 10.10.2.1 ... metric 200
```

Lý do: khi card NAT còn cắm, gói trả lời Kali bị đẩy ra NAT thay vì qua IDS, nên Kali không ping được Victim. Cần build hoặc `git pull` lại trên Victim thì tick Connected lại, xong thì ngắt.

## 10. Kali: lấy code và kiểm tra

Bật card NAT tạm của Kali, clone, kiểm tra công cụ:

```bash
git clone -b feature/68-vmware-lab https://github.com/74Teams/hybrid-nids.git
cd hybrid-nids
python3 -c "import scapy; print(scapy.__version__)"        # cần >= 2.5
which hydra
python3 lab/attacker/attack_demo.py --list                 # xem các đòn
```

Kali không cần Docker, cũng không cần SSH vào Kali. Thiếu Scapy hoặc hydra thì `sudo apt install -y python3-scapy hydra`. Chạy `--list | head` sẽ in lỗi `BrokenPipeError`, chỉ là do `head` đóng ống, không phải lỗi thật.

Kiểm tra đường đi (card NAT Victim đã ngắt):

```bash
ping -c2 10.10.2.50
curl -sI http://10.10.2.50/ | head -1                      # HTTP/1.1 200 OK
```

## 11. Dashboard

Trên IDS: `ip -4 addr show ens33` để lấy IP card NAT, rồi mở `http://<IP đó>:8000/` trên Windows. Dashboard cập nhật theo thời gian thực nhờ Redis.

## 12. Kịch bản tấn công

Chạy từ `~/hybrid-nids` trên Kali, luôn dùng `sudo`:

| # | Lệnh | Kỳ vọng |
|---|------|----------|
| 1 | `sudo python3 lab/attacker/attack_demo.py scan --target 10.10.2.50` | 8 đòn, cảnh báo SID 1000100–1000107 |
| 2 | `sudo python3 lab/attacker/attack_demo.py web --target 10.10.2.50` | 22 đòn, SID 1000001–1000044, vượt ngưỡng 5 cảnh báo P1/P2 trong 60 giây |
| 3 | `ssh root@10.10.2.50` | sau bước 2: hiện banner của honeypot, không phải sshd thật |
| 4 | `sudo python3 lab/attacker/attack_demo.py honeypot --target 10.10.2.50` | hydra brute force SSH, web login sai: sự kiện `HONEYPOT` ở trang Logs, `src_ip` = `10.10.1.100` |
| 5 | các nhóm `auth`, `malware`, `recon`, `dos` | tuỳ thời gian; `dos` để cuối vì sinh rất nhiều cảnh báo |

Chạy tất cả một lần: `sudo python3 lab/attacker/attack_demo.py all --target 10.10.2.50`.

Sau bước 2, kiểm tra chuyển hướng trên **IDS**:

```bash
sudo iptables -t nat -S NIDS_REDIRECT          # rule DNAT ... --to-destination 10.10.2.50:2222 và :8080
curl -s http://localhost:8000/api/redirects     # có dòng 10.10.1.100
```

Dashboard vẫn thấy cảnh báo cổng 22/80 khi đã bị chuyển hướng, vì engine bắt gói trước khi DNAT đổi cổng. Chuyển hướng chỉ áp cho kết nối mới và tự gỡ sau 600 giây; muốn gỡ ngay thì `docker compose -f lab/vmware/compose.ids.yml restart redirector`. Muốn xoá dữ liệu để chạy lại thì bấm **Xoá dữ liệu** trên dashboard.

## 13. Lỗi thường gặp

| Triệu chứng | Nguyên nhân và cách xử lý |
|-------------|---------------------------|
| IDS ping Victim không thông | Card VMnet3 của Victim chưa Connected, hoặc IP lab đặt nhầm lên card NAT (mục 3, 4). Chạy `ip -br addr` trên cả hai máy. |
| `ens33` của Victim có hai IP (một tĩnh, một `192.168.x.x`) | Hai file netplan cùng cấu hình một card. IP lab phải ở card VMnet3, `ens33` (NAT) giữ DHCP. |
| Kali ping IDS thông, ping Victim không | Chưa bật `ip_forward` (mục 5), hoặc card NAT của Victim còn cắm (mục 9). |
| Mất `ssh` vào Victim | Đúng thiết kế sau khi tắt sshd. Dùng console VMware. Muốn SSH lại: `docker compose -f lab/vmware/compose.victim.yml stop` rồi `sudo systemctl enable --now ssh.service ssh.socket`. |
| Victim thiếu cổng 2222/8080 | Honeypot đang chờ MySQL của IDS. Chạy IDS trước hoặc đợi, xem mục 8. |
| Engine báo `No such device` | `network.interface` trong `lab/vmware/settings.ids.yaml` (mặc định `ens34`) không phải card phía Kali. Sửa rồi `docker compose -f lab/vmware/compose.ids.yml restart engine`. |
| Dashboard không có cảnh báo | Trên IDS chạy `sudo tcpdump -ni ens34 host 10.10.1.100`; không thấy gói thì sai card hoặc forward. |
| Có rule DNAT trong container nhưng `iptables -t nat -S` trên host không thấy | Container (Debian) và host dùng khác backend nft/legacy. Trên host: `sudo update-alternatives --set iptables /usr/sbin/iptables-nft` (hoặc `-legacy`) cho trùng rồi restart redirector. |
| `docker build` trên Victim lỗi mạng | Card NAT chưa Connected, hoặc chưa nhận DHCP (`ip -br addr`). |
| Có file `config/settings.yaml` rỗng trong repo trên VM | Do Docker tạo điểm gắn cho `settings.ids.yaml`. File bị git ignore nên bỏ qua; xoá đi nếu muốn chạy Cách B trên máy đó. |
| Đổi mật khẩu `.env` nhưng MySQL vẫn từ chối | Mật khẩu chỉ áp dụng khi MySQL tạo dữ liệu lần đầu. Xoá volume MySQL rồi chạy lại (mất dữ liệu). |

Dashboard (cổng 8000) nghe trên mọi card nên Kali cũng mở được; thao tác ghi rule vẫn cần `NIDS_API_KEY`. Chặn hẳn là bước tuỳ chọn: `sudo iptables -I INPUT -i ens34 -p tcp --dport 8000 -j DROP` trên IDS.

## 14. Dừng và dọn

```bash
docker compose -f lab/vmware/compose.victim.yml down     # trên Victim
docker compose -f lab/vmware/compose.ids.yml down        # trên IDS (mất dữ liệu MySQL; dùng stop để giữ)
```

Phạm vi hiện tại: Victim và honeypot dùng chung một máy, chưa có VM honeypot riêng; chỉ hỗ trợ IPv4.
