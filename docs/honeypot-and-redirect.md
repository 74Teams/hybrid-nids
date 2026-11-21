# Honeypot và chuyển hướng

Honeypot là **nguồn sự kiện thứ hai**, độc lập với engine. Không người dùng hợp lệ nào kết nối tới honeypot, nên IP nào chạm vào honeypot thì chắc chắn là kẻ tấn công. Hệ thống dùng thông tin đó theo hai cách:

- **làm giàu cảnh báo:** nâng priority cảnh báo rule từ IP đó;
- **chuyển hướng:** đẩy kết nối mới của IP đáng ngờ sang honeypot thay vì dịch vụ thật.

## 1. Honeypot SSH

`services/honeypot/src/nids/honeypot/ssh_honeypot.py` (paramiko), chạy bằng `python -m nids.honeypot ssh`, cổng 2222.

- **Nhận mọi mật khẩu** rồi mở một shell giả có hệ thống file giả, nhớ trạng thái giữa các lệnh (ví dụ `cd` rồi `pwd`).
- **Không bao giờ thực thi** lệnh của attacker. Shell chỉ trả các chuỗi dựng sẵn.
- **Nhận diện công cụ** bằng HASSH, là fingerprint tính từ gói KEXINIT của client. Tên công cụ (hydra, OpenSSH, paramiko...) lấy từ bảng `KNOWN_HASSH`, không có thì lấy banner client.
- **Phiên:** mỗi kết nối là một phiên (`session_id`). Dashboard gộp mọi sự kiện của một phiên thành một dòng, kèm popup liệt kê từng lệnh theo thứ tự và log thô.

| Sự kiện (`attack_type`) | Khi nào | Priority |
|---|---|---|
| `ssh.auth.attempt` | Mỗi lần thử đăng nhập | P3 |
| `ssh.bruteforce` | Cùng IP và cùng HASSH thử ≥ 5 lần, mỗi lần cách nhau ≤ 60 giây | P2 |
| `ssh.command` | Mỗi lệnh gõ trong shell giả | P2 |
| `ssh.exec` | Lệnh chạy một lần (`ssh host 'cmd'`) | P2 |

## 2. Honeypot HTTP

`services/honeypot/src/nids/honeypot/web_honeypot.py` (Flask, chạy trên waitress), chạy bằng `python -m nids.honeypot http`, cổng 8080.

| Sự kiện | Khi nào | Priority |
|---|---|---|
| `http.login` | Gửi form đăng nhập WordPress giả | P2; **P1** nếu có dấu hiệu SQL injection |
| `http.request` | Mọi request khác (404, 405, `HEAD`, `OPTIONS`, `GET /`...), kèm header và body | P3 |

Phiên HTTP theo cookie `wordpress_sess`. Client không giữ cookie thì mỗi request là một phiên.

## 3. Bảo vệ honeypot

Honeypot phải chịu được chính kẻ tấn công. Mọi giới hạn cấu hình qua biến `HONEYPY_*`; giá trị 0 là tắt giới hạn.

| Giới hạn | Mặc định |
|---|---|
| Kết nối SSH tổng / mỗi IP | 100 / 20; kết nối thừa bị đóng ngay |
| Timeout SSH: handshake / xác thực / idle / tối đa một phiên | 30 / 90 / 120 / 600 giây |
| Độ dài một lệnh SSH | 4.096 byte, vượt thì đóng phiên |
| HTTP: thread / kết nối / timeout request / body | 8 / 100 / 30 giây / 16 KB (quá thì trả 413) |
| Trường do attacker chọn khi ghi DB | Bị cắt theo `MAX_FIELD_LEN`, `MAX_EVIDENCE_LEN`; header và body tối đa 8.192 ký tự |

Lỗi ghi CSDL chỉ được log, không làm sập honeypot.

## 4. Làm giàu cảnh báo

```
Honeypot ghi event HONEYPOT ──► DB ──► HoneypotIPCache (engine, TTL 5 giây)
                                              │
Cảnh báo rule từ IP đó ──► enrich_alert ──► priority − 1 (tối đa P1) + "[honeypot-confirmed]"
```

- Chỉ áp dụng cho cảnh báo `RULE_ENGINE` từ IP đã chạm honeypot trong **1 giờ** gần nhất.
- Honeypot ghi từ process khác và cache trong engine có TTL 5 giây, nên cảnh báo ngay sau lần chạm honeypot đầu tiên có thể chưa được nâng.
- Cảnh báo trước khi IP chạm honeypot giữ nguyên priority. Nhờ vậy dashboard cho thấy rõ trước và sau.

## 5. Chuyển hướng IP đáng ngờ

Process riêng `python -m nids.redirector` (service `nids_redirector`, chỉ chạy trong Docker lab). Nó không sửa engine hay honeypot.

**Tiêu chí:** một IP có ≥ `min_alerts` cảnh báo `RULE_ENGINE` mức P1–P2 trong `window_seconds`. Sự kiện honeypot không được đếm.

| Tham số `redirect` | Mặc định |
|---|---|
| `window_seconds` | 60 |
| `min_alerts` | 5 |
| `max_priority` | 2 |
| `ttl_seconds` | 600 (tự gỡ sau 10 phút) |
| `poll_interval` | 5 giây |
| `ports` | 22 → 2222, 80 → 8080 |
| `allowlist` | IP hạ tầng lab: gateway, MySQL, API, Redis, victim, `127.0.0.0/8` |

**Cơ chế:**

- Chain NAT riêng `NIDS_REDIRECT` (nhảy từ `PREROUTING`). Mỗi IP có hai rule `REDIRECT` sang cổng honeypot.
- Redirector chạy chung namespace mạng với victim, nên IP nguồn không đổi. Engine sniff trước NAT nên vẫn thấy cổng gốc và vẫn sinh cảnh báo.
- Chỉ **kết nối mới** bị chuyển hướng; conntrack giữ nguyên kết nối đang mở.
- Mỗi lượt được ghi vào bảng `redirects` trước rồi mới thêm rule iptables, để lỗi iptables được thử lại ở chu kỳ sau. `GET /api/redirects/` xem danh sách.
- An toàn đầu vào: `src_ip` đến từ gói của attacker, nên chỉ IPv4 hợp lệ (kiểm bằng `ipaddress`) mới được đưa vào lệnh. Lệnh gọi bằng argv dựng sẵn, không qua shell.
- Khi dừng (SIGTERM), redirector xoá toàn bộ rule và đánh dấu `removed_at`.

**Chưa làm:** chặn hẳn (DROP), cổng khác ngoài 22/80, IPv6.
