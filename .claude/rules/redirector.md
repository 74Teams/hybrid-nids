---
paths:
  - "nids/redirector/**"
  - "tests/redirector/**"
---

# Redirector (`nids/redirector/`)

- Process riêng `python -m nids.redirector` (service `nids_redirector`): chọn IP đáng ngờ từ bảng `events` rồi chuyển hướng kết nối mới của IP đó tới SSH/HTTP của victim sang honeypot. Không sửa engine hay honeypot, không ghi `events`.
- Tiêu chí: IP có ít nhất `redirect.min_alerts` cảnh báo `RULE_ENGINE` mức `max_priority` trở lên trong `window_seconds` (`EventRepository.suspicious_ips`). Sự kiện HONEYPOT không được đếm.
- Cơ chế: chain NAT riêng `NIDS_REDIRECT` (jump từ `PREROUTING`), mỗi IP hai rule `-s <ip> -p tcp --dport 22|80 -j REDIRECT --to-ports 2222|8080`. Chạy chung network namespace với victim nên không đổi IP nguồn; engine sniff trước NAT nên vẫn thấy cổng gốc và vẫn sinh cảnh báo.
- `firewall.py` (`IptablesFirewall`) chỉ nhận IPv4 hợp lệ, gọi `subprocess.run` với argv dựng sẵn (không shell, `timeout=5`, cờ `-w`), runner tiêm được để test không cần iptables thật (`tests/redirector/fake_iptables.py`). Không bao giờ truyền chuỗi chưa qua `ipaddress` vào lệnh: `src_ip` đến từ gói tin của attacker.
- `service.py` (`Redirector.run_once`): gỡ lượt hết hạn (thất bại thì nhớ trong `_pending_removal` để thử lại), tạo lại chain/jump/rule của lượt còn hiệu lực (phòng bị xoá từ ngoài), rồi thêm IP mới. Ghi `redirects` trước, thêm rule sau, để lỗi iptables được thử lại ở chu kỳ kế. Lỗi iptables hoặc CSDL chỉ `logger.error`, vòng lặp không bao giờ ném lỗi.
- Allowlist (`redirect.allowlist`) mặc định gồm toàn bộ IP hạ tầng lab: không bao giờ chuyển hướng. Đổi IP trong `docker-compose.yml` thì sửa theo.
- Khởi động: kiểm tra iptables, dựng chain, flush rồi nạp lại từ `redirects`; dừng (SIGTERM/SIGINT): flush và đánh dấu `removed_at`. Mã thoát: `enabled=false` là 0, iptables không dùng được là 1; service không đặt `restart`.
- iptables chỉ có trong lab Linux. REDIRECT chỉ áp cho kết nối mới (conntrack giữ NAT của kết nối đang mở). Chưa làm: chặn (DROP), FTP và cổng khác, UI dashboard, API ghi, IPv6.
