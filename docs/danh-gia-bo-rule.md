# Đánh giá bộ rule và hướng cải thiện

Tài liệu này trả lời ba câu hỏi: bộ rule hiện tại đã đủ chưa, nếu chưa thì sửa theo hướng nào, và AI giúp được gì. Mọi con số dưới đây đo thật trên file `pcap/chienbuoito.pcap` ngày 10/11/2026, với 68 rule built-in đang bật.

## 1. Trả lời ngắn

- **Chưa đủ, và vấn đề lớn nhất không phải thiếu rule mà là báo nhầm.** Trên đoạn traffic thật, gần như toàn bộ 2.901 cảnh báo rơi vào traffic bình thường, còn tấn công thật thì gần như bị bỏ sót.
- **Bật thêm bộ community (hơn 3.500 rule) làm tệ hơn**, vì engine chưa hiểu phần lớn option của các rule đó.
- **AI áp dụng được theo hai cách:** mô hình học máy phát hiện tấn công theo hành vi (đúng phần `docs/ai/` đã thiết kế), và AI dạng chatbot hỗ trợ viết, sửa, kiểm rule. Cả hai đều cần một bộ đo có nhãn để biết kết quả tốt hay xấu.

## 2. "Đầy đủ" nghĩa là gì

Một bộ rule tốt phải đạt cùng lúc hai điều:

| Thuật ngữ | Nghĩa | Ví dụ |
|---|---|---|
| **TP** (true positive, bắt đúng) | Có tấn công và có cảnh báo | Kẻ tấn công thử mật khẩu SSH, rule brute force bắn |
| **FP** (false positive, báo nhầm) | Không có tấn công nhưng có cảnh báo | Trình duyệt mở 20 tab, rule "port scan" bắn |
| **FN** (false negative, bỏ sót) | Có tấn công nhưng không có cảnh báo | Máy nhiễm botnet gọi về máy chủ điều khiển mà không ai biết |

- **Độ phủ (recall)** = TP / (TP + FN): trong số tấn công thật, bắt được bao nhiêu phần.
- **Độ chính xác (precision)** = TP / (TP + FP): trong số cảnh báo, bao nhiêu phần là thật.

Thêm nhiều rule chỉ làm tăng độ phủ khi rule viết đúng. Rule quá rộng làm độ chính xác giảm mạnh: người trực nhận hàng nghìn cảnh báo giả và bỏ qua luôn cảnh báo thật.

## 3. Bộ rule hiện có

| Nhóm         | File                     | Số rule | Bao phủ                                                                             |
| ------------ | ------------------------ | ------- | ----------------------------------------------------------------------------------- |
| WEB-ATTACK   | `web-attack.rules`       | 24      | SQLi, XSS, path traversal, LFI/RFI, Log4Shell, Shellshock, XXE, SSRF, file nhạy cảm |
| MALWARE / C2 | `malware-c2.rules`       | 11      | Webshell, reverse shell, PowerShell, sqlmap/nikto, Mimikatz, EICAR, cryptominer     |
| DOS          | `dos.rules`              | 9       | SYN/UDP/ICMP/HTTP flood, Slowloris, khuếch đại NTP/DNS/Memcached                    |
| RECON        | `recon.rules`            | 9       | SNMP, DNS (tunneling, AXFR, version.bind), ICMP timestamp/mask, NetBIOS, SSDP       |
| SCAN         | `scan.rules`             | 8       | Nmap Xmas/Null/FIN, cờ TCP lạ, User-Agent của công cụ quét, SYN scan                |
| AUTH         | `auth.rules`             | 7       | Brute force SSH/FTP/web login, FTP anonymous, HTTP Basic                            |
| (tắt)        | `vendor/community.rules` | 4.013   | Bộ rule cộng đồng của Snort                                                         |

Nhìn theo danh mục thì bộ rule khá rộng cho một đồ án. Nhưng một danh sách dài chưa nói lên điều gì; phải chạy trên traffic thật mới biết.

## 4. Kết quả đo trên traffic thật

### 4.1 File pcap là gì

`chienbuoito.pcap` là một đoạn 10 phút của bộ dữ liệu **CIC-IDS2017** (Đại học New Brunswick, Canada), ngày thứ Sáu 07/07/2017, từ 14:09 đến 14:19 giờ địa phương. Dấu hiệu nhận ra: dải IP `192.168.10.x`, DNS server `192.168.10.3`, máy chủ web nạn nhân `192.168.10.50`. Theo tài liệu của bộ dữ liệu, trong khung giờ này có:

- Đợt **PortScan** từ `172.16.0.1` (kẻ tấn công) vào `192.168.10.50`.
- Botnet **Ares**: các máy nhiễm định kỳ gọi về máy chủ điều khiển `205.174.165.73:8080`.

Mình tạm coi mọi traffic dính hai IP này là tấn công và phần còn lại là bình thường. Cách gán nhãn theo IP này chỉ gần đúng; muốn chính xác phải dùng file nhãn CSV đi kèm CIC-IDS2017 (mục 5.1).

### 4.2 Con số

| | Tổng | Có cảnh báo |
|---|---|---|
| Cảnh báo | 2.901 | **chỉ 2** dính IP tấn công (1 SSH brute force SID 1000305, 1 ANOMALY) |
| Flow tấn công | 284 | 13 (4,6%) |
| Flow bình thường | 7.413 | **3.699 (50%)** |

Nói cách khác: một nửa số kết nối bình thường bị coi là đáng ngờ, trong khi 95% kết nối tấn công lọt qua.

### 4.3 Bốn rule gây gần hết báo nhầm

| SID     | Rule                             | Số lần bắn | Vì sao bắn nhầm                                                                                                                  |
| ------- | -------------------------------- | ---------- | -------------------------------------------------------------------------------------------------------------------------------- |
| 1000205 | DOS UDP flood                    | 2.145      | Ngưỡng 50 gói/giây vào một đích. DNS server `192.168.10.3` phục vụ cả mạng LAN nên nhận vượt ngưỡng này là bình thường           |
| 1000107 | SCAN TCP SYN port scan           | 516        | Đếm 20 SYN trong 2 giây từ một nguồn, không quan tâm cổng đích. Trình duyệt mở một trang web có thể mở 20 kết nối HTTPS cùng lúc |
| 1000209 | DOS HTTP GET flood               | 130        | 30 request GET/giây từ một nguồn. Một trang web thường tải hàng chục ảnh, script cùng lúc                                        |
| 1000038 | WEB-ATTACK Remote File Inclusion | 52         | Bắt `=http` trong URL. Link quảng cáo, theo dõi rất hay có dạng `?url=http%3A%2F%2F...`                                          |

Bốn rule này đều đúng về ý tưởng nhưng **ngưỡng hoặc điều kiện quá rộng** so với mạng thật. Chúng chạy tốt trong lab Docker vì lab gần như không có traffic bình thường.

### 4.4 Tấn công bị bỏ sót

- **Botnet Ares:** 5 máy (`192.168.10.5`, `.8`, `.9`, `.14`, `.15`) gọi tới `205.174.165.73:8080` tổng cộng 126 lần, không có cảnh báo nào. Mỗi kết nối chỉ có 2 gói (SYN rồi RST, vì máy chủ điều khiển không trả lời), nên **không có nội dung nào để rule so khớp**. Dấu hiệu duy nhất là hành vi: nhiều máy cùng gọi một IP bên ngoài đều đặn theo chu kỳ (gọi là *beaconing*). Rule kiểu Snort gần như không diễn tả được kiểu dấu hiệu này.
- **Traffic từ `172.16.0.1`:** 158 flow vào `192.168.10.50`, chỉ 13 flow có cảnh báo.

### 4.5 Bật `community.rules` có giúp không

| | Built-in | Built-in + community |
|---|---|---|
| Số rule nạp được | 68 | 68 + 3.570 (443 rule lỗi, bị bỏ) |
| Rule bị bỏ bớt option engine không hiểu | 0 | **3.230 / 3.570** |
| Cảnh báo trên traffic bình thường | 2.927 | **64.361** |

Khi engine gặp option chưa hỗ trợ (`byte_test`, `byte_jump`, `flowbits`, `isdataat`, `file_data`, `urilen`...), nó bỏ qua option đó. Rule bị "nới lỏng" và bắn trên cả traffic vô hại. Ví dụ rule SID 272 "Microsoft Windows IGMP dos attack" bắn 9.018 lần, trong khi đoạn pcap này không hề có tấn công IGMP. Vì vậy **chưa nên bật community** khi engine chưa hỗ trợ đủ option.

## 5. Hướng giải quyết, theo thứ tự nên làm

### 5.1 Dựng bộ đo có nhãn (làm trước tiên)

Không đo thì không biết sửa rule xong tốt lên hay tệ đi. Cần một script:

1. Chạy engine trên pcap của CIC-IDS2017.
2. Ghép mỗi cảnh báo, mỗi flow với nhãn trong file CSV của bộ dữ liệu (theo IP, cổng, giao thức và thời gian). Ví dụ đoạn pcap này dùng file `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv`.
3. In bảng TP/FP/FN, độ phủ và độ chính xác **theo từng rule** và **theo từng loại tấn công**.

Sau đó mỗi lần sửa rule chỉ cần chạy lại và so con số với lần trước.

### 5.2 Giảm báo nhầm cho 4 rule ở mục 4.3

Gợi ý sửa (phải đo lại bằng bộ đo trước khi chốt):

- **Khai báo mạng nội bộ:** đặt `HOME_NET` trong `detection.variables` (ví dụ `"192.168.10.0/24"` cho CIC-IDS2017, `"172.28.0.0/16"` cho lab). Khi đó rule viết được theo hướng `$EXTERNAL_NET -> $HOME_NET`, không báo traffic nội bộ với nhau.
- **1000205 UDP flood:** loại các cổng dịch vụ nhận nhiều truy vấn hợp lệ (53, 5353, 123), hoặc tăng ngưỡng.
- **1000107 SYN scan:** quét cổng nghĩa là nhiều *cổng khác nhau*, không chỉ nhiều SYN. Lớp ANOMALY (`nids/engine/anomaly.py`) đã đếm số cổng đích khác nhau, nên có thể tắt rule này và để ANOMALY lo, hoặc tăng ngưỡng.
- **1000209 HTTP GET flood:** đếm theo đích (`track by_dst`) và tăng ngưỡng, vì flood là nhiều request dồn vào một máy chủ.
- **1000038 RFI:** chỉ bắt khi tham số có tên hay bị lợi dụng (`file=`, `page=`, `include=`, `path=`), hoặc URL ngoài kết thúc bằng `.txt`, `.php`, hoặc `?`.

### 5.3 Lấp chỗ trống theo các loại tấn công của CIC-IDS2017

CIC-IDS2017 có: FTP/SSH brute force (Patator), DoS Hulk/GoldenEye/Slowloris/Slowhttptest, Heartbleed, tấn công web (brute force, XSS, SQLi), Infiltration, Botnet Ares, PortScan, DDoS LOIC. Đối chiếu với bảng ở mục 3:

- Đã có rule tương ứng: brute force, Slowloris, XSS/SQLi, PortScan, flood. Cần đo xem có bắt được thật không.
- Chưa có: Heartbleed (engine chưa hiểu `byte_test`), Slowhttptest, botnet beaconing.
- Dấu hiệu theo hành vi (beaconing, scan chậm, DDoS không có payload đặc trưng) thì giao cho AI (mục 6.1), không cố nhét vào rule.

### 5.4 Nâng engine để dùng được community

Nếu muốn tận dụng 4.000 rule có sẵn, cần cài thêm option theo thứ tự hay gặp nhất trong `community.rules`: `flowbits` (439 rule), `byte_jump` (335), `byte_test` (320), `file_data` (264), `isdataat` (257), `urilen` (190). Đây là việc lớn, chạm vào parser và `DetectionEngine`. Trong lúc chưa làm, chỉ nên bật lẻ từng rule community nào không bị bỏ option (còn khoảng 340 rule như vậy) và đo trước khi bật.

## 6. AI có áp dụng được không

Có, theo hai cách khác nhau.

### 6.1 AI phát hiện tấn công (học máy trên flow)

Đây là phần `AITrafficWorker` mà `docs/ai/` đã thiết kế: tính đặc trưng thống kê cho mỗi flow (số gói, số byte, thời lượng, khoảng cách giữa các gói...), rồi dùng **Random Forest** để nhận diện loại tấn công đã biết và **IsolationForest** để báo flow lạ.

- **Bù đúng chỗ rule yếu:** botnet Ares ở mục 4.4 không có nội dung, nhưng flow của nó rất khác thường: 2 gói, cùng một đích bên ngoài, lặp đều đặn. Mô hình học trên flow nhìn thấy được điều này.
- **Dữ liệu huấn luyện có sẵn:** CIC-IDS2017 có nhãn cho từng flow, và engine đã ghi flow vào bảng `flows`.
- **Hạn chế:** AI cũng báo nhầm, khó giải thích "vì sao" hơn rule, và không cho biết tên lỗ hổng cụ thể. Mô hình học trên CIC-IDS2017 thường kém đi khi chạy trên mạng khác (`docs/ai/02-ly-thuyet.md`, mục về tổng quát hoá). Vì vậy hệ thống mới là *hybrid*: rule cho tấn công đã biết rõ, AI cho hành vi bất thường.

`nids/ai.py` hiện vẫn là stub, nên chưa thể tính AI vào kết quả demo.

### 6.2 AI hỗ trợ viết và kiểm rule (chatbot như Claude)

AI dạng chatbot có thể:

- Viết rule từ mô tả tấn công, mã CVE hoặc một mẫu payload, theo đúng cú pháp trong `.claude/rules/snort-rules.md`. Repo đã có lệnh `/them-rule` làm việc này kèm test.
- Đọc bảng FP ở mục 4.3 và đề xuất cách thu hẹp rule.
- Chuyển rule cú pháp Snort 2 sang Snort 3.

Điều kiện bắt buộc: **mọi rule do AI viết phải qua test và qua bộ đo có nhãn ở mục 5.1.** AI có thể viết rule đúng cú pháp nhưng quá rộng, hoặc dùng option engine chưa hỗ trợ, đúng như chuyện đã xảy ra với `community.rules`.

### 6.3 Dùng dữ liệu để chọn ngưỡng

Đây là cách đơn giản nhất để "dùng dữ liệu thay vì đoán". Các rule `detection_filter` (flood, brute force, scan) có tham số `count` và `seconds`. Với bộ đo có nhãn, thử nhiều cặp giá trị và chọn cặp có cả độ phủ lẫn độ chính xác cao nhất. Không cần mô hình phức tạp mà vẫn có kết quả có số liệu để trình bày.

## 7. Thứ tự đề xuất

1. Bộ đo có nhãn (mục 5.1). Mọi bước sau đều dựa vào nó.
2. Sửa 4 rule báo nhầm và đặt `HOME_NET` (mục 5.2), đo lại.
3. Làm AI worker theo `docs/ai/` (issue #22, #23), dùng bộ đo để so rule, AI và rule kết hợp AI.
4. Nếu còn thời gian: cài thêm option để dùng `community.rules` (mục 5.4).
