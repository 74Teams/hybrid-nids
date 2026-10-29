# 1. Bối cảnh

## 1.1 Hiện trạng hệ thống

Hybrid NIDS hiện gồm ba nguồn phát hiện:

| Thành phần | Trạng thái | Ghi chú |
|------------|------------|---------|
| Rule engine (`nids/engine/detector.py`) | Hoàn chỉnh | Rule cú pháp Snort 3 trong `rules/local.rules`, phễu 4 tầng: demux theo protocol/port → prefilter Aho-Corasick → kiểm tra chi tiết → `ThresholdManager` |
| Honeypot SSH/HTTP (`nids/honeypot/`) | Hoàn chỉnh | Ghi sự kiện vào bảng `events` với `source_type="HONEYPOT"`, dùng để làm giàu cảnh báo rule (`enrich_alert`) |
| AI worker (`nids/ai.py`) | **Stub** | `AITrafficWorker.analyze_packet` chỉ có `pass` |

Phần AI đã có chỗ trong pipeline. Trong `nids/engine/main.py`, worker thread lấy từng `DecodedPacket` ra khỏi queue, rồi lần lượt gọi:

```python
detection_engine.evaluate_packet(packet)
ai_worker.analyze_packet(packet)
```

`AITrafficWorker` cũng được khởi tạo với cùng callback `handle_alert` mà rule engine dùng. Nhờ vậy, khi phần AI có code thật thì chỉ cần thay bên trong `nids/ai.py`: không phải sửa capture, decoder, database hay API.

## 1.2 Giới hạn của phát hiện theo chữ ký

Rule engine so khớp **nội dung từng gói**: content, pcre, cờ TCP, dsize. Cách làm này rất chính xác với các tấn công đã biết, nhưng có những điểm mù:

1. **Tấn công không có payload đặc trưng.** SYN flood, UDP flood hay port scan chỉ là rất nhiều gói "bình thường". Rule chỉ bắt được khi đếm ngưỡng bằng `detection_filter`, và ngưỡng thì cố định, dễ né bằng cách đi chậm lại.
2. **Scan chậm và phân tán.** Ví dụ một gói mỗi vài giây, hoặc nhiều nguồn chia nhau quét: ngưỡng theo cửa sổ thời gian ngắn sẽ không vượt.
3. **Brute force có payload hợp lệ.** Mỗi lần đăng nhập SSH/HTTP đều hợp lệ về cú pháp; điểm bất thường chỉ nằm ở số lần thử và nhịp độ.
4. **Biến thể mới và zero-day.** Chưa có chữ ký thì không có rule.
5. **Traffic mã hoá.** Với TLS/SSH, content không đọc được, nhưng metadata của flow (kích thước, nhịp gói, thời lượng) thì vẫn quan sát được.

## 1.3 Vai trò của tầng AI

Tầng AI là **tầng phát hiện thứ hai, bổ sung chứ không thay thế** rule engine:

- Rule engine trả lời câu hỏi *"gói này có chứa chữ ký tấn công không?"*: chính xác, giải thích được bằng SID.
- AI trả lời câu hỏi *"hành vi của cả kết nối này có giống tấn công, hoặc có khác thường không?"*: nhìn ở mức flow, không đọc payload.

Hai tầng chạy song song trên cùng một luồng gói và ghi vào cùng một bảng `events`. Dashboard phân biệt nguồn qua `source_type` (`RULE_ENGINE`, `HONEYPOT`, `AI_ENGINE`).

## 1.4 Ràng buộc kỹ thuật

| Ràng buộc | Hệ quả cho thiết kế |
|-----------|---------------------|
| Một worker thread duy nhất chạy cả rule engine lẫn AI | Mỗi lần gọi `analyze_packet` phải rất rẻ (O(1)); chỉ chạy suy luận khi flow kết thúc |
| Queue giới hạn `detection.queue_max_size` (mặc định 10000); đầy thì drop gói | AI không được làm tăng tỉ lệ drop; cần đo khi replay pcap |
| Engine chạy cả live lẫn offline pcap | Mọi tính toán thời gian dùng `packet.timestamp`, không dùng đồng hồ hệ thống, để kết quả offline lặp lại được |
| Python thuần, không GPU | Chọn mô hình dạng cây (scikit-learn), suy luận nhanh trên CPU |
| Lab Docker cô lập 172.28.0.0/16 (attacker, victim, honeypot) | Tự sinh và tự gán nhãn được dữ liệu tấn công thật trên chính hạ tầng demo |
| `DecodedPacket` chỉ có L2–L4 + HTTP (không có TTL, window size, header length) | Tập đặc trưng phải giới hạn trong những gì decoder cung cấp, hoặc bổ sung decoder một cách có chủ đích |
| Tài liệu và log viết tiếng Việt, tên trong code giữ tiếng Anh | Áp dụng cho cả module AI, script huấn luyện và báo cáo |
