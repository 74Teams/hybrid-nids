# Kết quả đo: baseline-5-ngay

File này do `python -m tools.eval.evaluate` sinh ra. Cách đọc số liệu: `docs/eval/README.md`.

- Ngày: monday, tuesday, wednesday, thursday, friday
- Tập: **dev**, 221 chunk (monday 08:55, monday 09:05, monday 09:15, monday 09:25, monday 09:35, monday 09:45, monday 09:55, monday 10:05, monday 10:15, monday 10:35, monday 10:45, monday 10:55, monday 11:05, monday 11:15, monday 11:25, monday 11:35, monday 11:45, monday 11:55, monday 12:05, monday 12:15, monday 12:25, monday 12:35, monday 12:45, monday 12:55, monday 13:15, monday 13:25, monday 13:35, monday 13:45, monday 13:55, monday 14:05, monday 14:15, monday 14:25, monday 14:35, monday 14:45, monday 14:55, monday 15:05, monday 15:15, monday 15:25, monday 15:35, monday 15:45, monday 15:55, monday 16:05, monday 16:25, monday 16:35, monday 16:45, monday 16:55, tuesday 08:53, tuesday 09:03, tuesday 09:13, tuesday 09:23, tuesday 09:33, tuesday 09:43, tuesday 09:53, tuesday 10:23, tuesday 10:33, tuesday 10:43, tuesday 10:53, tuesday 11:03, tuesday 11:13, tuesday 11:23, tuesday 11:33, tuesday 11:43, tuesday 11:53, tuesday 12:03, tuesday 12:13, tuesday 12:23, tuesday 12:33, tuesday 12:43, tuesday 12:53, tuesday 13:03, tuesday 13:13, tuesday 13:23, tuesday 13:33, tuesday 13:43, tuesday 13:53, tuesday 14:03, tuesday 14:13, tuesday 14:23, tuesday 14:33, tuesday 14:43, tuesday 15:13, tuesday 15:23, tuesday 15:33, tuesday 15:43, tuesday 15:53, tuesday 16:03, tuesday 16:13, tuesday 16:33, tuesday 16:43, tuesday 16:53, wednesday 08:42, wednesday 08:52, wednesday 09:02, wednesday 09:12, wednesday 09:22, wednesday 09:32, wednesday 09:42, wednesday 09:52, wednesday 10:12, wednesday 10:22, wednesday 10:42, wednesday 11:02, wednesday 11:22, wednesday 11:32, wednesday 11:42, wednesday 11:52, wednesday 12:02, wednesday 12:12, wednesday 12:22, wednesday 12:32, wednesday 12:42, wednesday 12:52, wednesday 13:02, wednesday 13:12, wednesday 13:22, wednesday 13:32, wednesday 13:42, wednesday 13:52, wednesday 14:02, wednesday 14:12, wednesday 14:22, wednesday 14:32, wednesday 14:42, wednesday 14:52, wednesday 15:02, wednesday 15:12, wednesday 15:32, wednesday 15:42, wednesday 15:52, wednesday 16:02, wednesday 16:22, wednesday 16:32, wednesday 16:42, wednesday 16:52, wednesday 17:02, thursday 08:58, thursday 09:08, thursday 09:18, thursday 09:28, thursday 09:38, thursday 10:08, thursday 10:18, thursday 10:38, thursday 10:48, thursday 10:58, thursday 11:08, thursday 11:18, thursday 11:28, thursday 11:38, thursday 11:48, thursday 11:58, thursday 12:08, thursday 12:18, thursday 12:28, thursday 12:38, thursday 12:48, thursday 12:58, thursday 13:08, thursday 13:18, thursday 13:28, thursday 13:38, thursday 13:48, thursday 13:58, thursday 14:08, thursday 14:18, thursday 14:28, thursday 14:38, thursday 14:48, thursday 14:58, thursday 15:08, thursday 15:18, thursday 15:48, thursday 15:58, thursday 16:08, thursday 16:18, thursday 16:38, thursday 16:48, thursday 16:58, friday 08:59, friday 09:19, friday 09:29, friday 09:39, friday 09:49, friday 09:59, friday 10:09, friday 10:19, friday 10:29, friday 10:39, friday 10:49, friday 10:59, friday 11:09, friday 11:19, friday 11:29, friday 11:39, friday 11:49, friday 11:59, friday 12:09, friday 12:19, friday 12:29, friday 12:39, friday 12:49, friday 12:59, friday 13:09, friday 13:19, friday 13:29, friday 13:39, friday 13:49, friday 13:59, friday 14:09, friday 14:19, friday 14:29, friday 14:39, friday 14:49, friday 15:29, friday 15:39, friday 15:49, friday 15:59, friday 16:19, friday 16:39, friday 16:49, friday 16:59)
- Code: `debba86 (có thay đổi chưa commit)`; rule nạp: 68; biến ghi đè: `HOME_NET=192.168.10.0/24`
- Máy Bot dùng để thi: `192.168.10.5`, `192.168.10.8`
- Thời gian chạy: 4.456,0 giây với 11 tiến trình
- Danh sách từng cảnh báo: `data/eval/baseline-5-ngay-alerts.csv.gz`

## Phễu gói

| Bước | Số gói |
| :-- | --: |
| Có trong pcap | 50.152.105 |
| Bị bỏ vì không phải IP | 240.707 |
| Vào phân tích | 49.911.398 |
| Lỗi khi so khớp | 0 |
| Số lần rule khớp trước threshold | 2.568.477 |

## Thời gian từng bước (cộng mọi chunk, một tiến trình)

| Bước | Giây | Tỉ lệ |
| :-- | --: | --: |
| Scapy đọc và bóc gói | 11.515,8 | 52,9% |
| Decode | 4.800,6 | 22,1% |
| Rule + tái hợp TCP | 4.249,6 | 19,5% |
| Gom flow | 690,3 | 3,2% |
| ANOMALY | 514,0 | 2,4% |
| **Tốc độ** | 2.303,7 gói/giây | |

## Theo lớp (flow)

Flow bị rule báo: có ít nhất một rule khớp. Với lớp tấn công tỉ lệ này là độ phủ (recall), với BENIGN là tỉ lệ báo nhầm (FPR).

| Lớp | Số flow | Bị rule báo | Tỉ lệ |
| :-- | --: | --: | --: |
| BENIGN | 1.515.436 | 777.411 | 51,3% |
| Bot | 2.547 | 41 | 1,6% |
| BruteForce | 5.129 | 5.054 | 98,5% |
| DDoS | 62.420 | 61.655 | 98,8% |
| DoS | 100.898 | 95.252 | 94,4% |
| Heartbleed | 7 | 0 | 0,0% |
| Infiltration | 53 | 0 | 0,0% |
| PortScan | 139.058 | 138.688 | 99,7% |
| WebAttack | 1.411 | 99 | 7,0% |
| EXCLUDED | 48.489 | 22.965 | 47,4% |
| UNLABELED | 13.199 | 3.537 | 26,8% |

## Theo tầng phát hiện (cảnh báo)

Độ chính xác = cảnh báo rơi vào flow tấn công / (cảnh báo rơi vào flow tấn công + cảnh báo rơi vào BENIGN).
Theo cặp IP và theo flow: mỗi cặp IP (không phân biệt chiều), mỗi flow chỉ tính một lần, nên cảnh báo lặp lại của cùng một kẻ tấn công không chi phối con số. Cặp hoặc flow là đúng nếu có ít nhất một cảnh báo rơi vào tấn công. ANOMALY không gắn với flow nên không có cột theo flow.

| Tầng | Cảnh báo | Bắt đúng | Báo nhầm | Bỏ qua | Độ chính xác | Cặp IP đúng / nhầm | Theo cặp IP | Flow đúng / nhầm | Theo flow |
| :-- | --: | --: | --: | --: | --: | --: | --: | --: | --: |
| ANOMALY | 18.247 | 109 | 17.633 | 505 | 0,6% | 5 / 4.837 | 0,1% | – | – |
| RULE_ENGINE | 26.937 | 1.514 | 24.339 | 1.084 | 5,9% | 2 / 7.192 | 0,0% | 1.105 / 21.825 | 4,8% |

## Theo rule

| SID | Tên | Khớp trước threshold | Cảnh báo | Bắt đúng | Báo nhầm | Độ chính xác | Theo cặp IP | Báo nhầm nhiều nhất |
| :-- | :-- | --: | --: | --: | --: | --: | --: | :-- |
| ANOMALY | ANOMALY Rare port/ICMP type | – | 10.891 | 12 | 10.631 | 0,1% | 0,8% | fe80::6d07:ea13:6f73:ed41 → ff02::1:2:547 (616); fe80::3c60:fc97:3f94:ac8f → ff02::1:2:547 (615); fe80::f470:cd16:3cf6:bd7b → ff02::1:2:547 (607) |
| 1000038 | WEB-ATTACK Remote File Inclusion - external URL in parameter | 24.207 | 9.211 | 0 | 8.879 | 0,0% | 0,0% | 192.168.10.9 → 173.241.242.220:80 (189); 192.168.10.5 → 162.252.74.5:80 (154); 192.168.10.8 → 173.241.242.220:80 (138) |
| 1000205 | DOS UDP flood (high packet rate to one target) | 1.488.246 | 7.480 | 0 | 7.083 | 0,0% | 0,0% | 192.168.10.3 → 192.168.10.1:53 (438); 192.168.10.5 → 192.168.10.3:53 (293); 192.168.10.15 → 192.168.10.3:53 (282) |
| ANOMALY | ANOMALY Packet flood (high packet rate to one target) | – | 4.042 | 57 | 3.844 | 1,5% | 0,0% | 192.168.10.15 → 13.107.4.50:80 (59); 192.168.10.14 → 13.107.4.50:80 (27); 192.168.10.5 → 192.33.31.192:443 (16) |
| 1000107 | SCAN TCP SYN port scan (many SYN from one source) | 631.595 | 3.913 | 185 | 3.580 | 4,9% | 0,1% | 192.168.10.5 → 162.208.20.178:443 (37); 192.168.10.5 → 162.208.22.34:443 (23); 192.168.10.17 → 199.167.65.25:443 (16) |
| ANOMALY | ANOMALY Host sweep (one source probing many hosts) | – | 3.220 | 2 | 3.102 | 0,1% | 0,1% | 192.168.10.19 → 72.21.91.29:80 (14); 192.168.10.9 → 72.21.91.29:80 (11); 192.168.10.16 → 72.21.91.29:80 (9) |
| 1000301 | AUTH SSH probe banner attempt | 11.494 | 2.577 | 224 | 2.268 | 9,0% | 9,1% | 192.168.10.9 → 192.168.10.50:22 (259); 192.168.10.15 → 192.168.10.50:22 (253); 192.168.10.12 → 192.168.10.50:22 (239) |
| 1000505 | RECON NetBIOS name query (nbtstat) | 2.951 | 879 | 0 | 825 | 0,0% | 0,0% | 192.168.10.3 → 192.168.10.51:137 (9); 192.168.10.3 → 192.168.10.1:137 (9); 192.168.10.3 → 192.168.10.12:137 (9) |
| 1000209 | DOS HTTP GET flood (many requests from one source) | 205.604 | 825 | 125 | 671 | 15,7% | 0,2% | 192.168.10.17 → 192.229.211.82:80 (8); 192.168.10.12 → 119.205.194.11:80 (7); 192.168.10.9 → 69.4.95.11:80 (5) |
| 1000201 | DOS SYN Flood attempt to HTTP port | 181.890 | 643 | 182 | 452 | 28,7% | 0,3% | 192.168.10.8 → 23.50.75.27:80 (12); 192.168.10.12 → 119.205.194.11:80 (10); 192.168.10.12 → 61.251.165.12:80 (10) |
| 1000003 | WEB-ATTACK SQL Injection - SQL comment execution (--) | 832 | 349 | 0 | 331 | 0,0% | 0,0% | 192.168.10.51 → 172.217.12.162:80 (7); 192.168.10.16 → 172.217.11.2:80 (5); 192.168.10.15 → 172.217.12.130:80 (5) |
| 1000305 | AUTH SSH brute force (repeated connection attempts) | 2.426 | 265 | 252 | 13 | 95,1% | 14,3% | 192.168.10.8 → 192.168.10.50:22 (4); 192.168.10.8 → 192.168.10.5:22 (3); 192.168.10.8 → 192.168.10.15:22 (2) |
| 1000307 | AUTH FTP brute force (repeated PASS) | 8.602 | 242 | 242 | 0 | 100,0% | 100,0% |  |
| 1000306 | AUTH Web login brute force (repeated POST /login) | 1.269 | 161 | 161 | 0 | 100,0% | 100,0% |  |
| 1000507 | RECON SSDP M-SEARCH discovery | 7.134 | 127 | 0 | 124 | 0,0% | 0,0% | 192.168.10.5 → 239.255.255.250:1900 (106); 192.168.10.15 → 239.255.255.250:1900 (9); 192.168.10.14 → 239.255.255.250:1900 (7) |
| 1000034 | WEB-ATTACK Cross-Site Scripting - document.cookie theft | 594 | 75 | 75 | 0 | 100,0% | 100,0% |  |
| 1000202 | DOS Slowloris HTTP header probe detected | 906 | 67 | 59 | 0 | 100,0% | 100,0% |  |
| ANOMALY | ANOMALY SYN flood (high SYN rate to one target) | – | 63 | 34 | 29 | 54,0% | 7,1% | 192.168.10.25 → 173.223.152.83:443 (1); 192.168.10.8 → 192.168.10.14:4129 (1); 192.168.10.8 → 192.168.10.15:256 (1) |
| 1000100 | SCAN Nmap Xmas Scan detected (FUP flags) | 166 | 32 | 0 | 32 | 0,0% | 0,0% | 192.168.10.8 → 192.168.10.12:1 (3); 192.168.10.8 → 192.168.10.9:1 (3); 192.168.10.8 → 192.168.10.16:1 (2) |
| ANOMALY | ANOMALY Port scan (one source probing many ports) | – | 31 | 4 | 27 | 12,9% | 6,7% | 192.168.10.3 → 192.168.10.25:49171 (3); 192.168.10.12 → 178.255.83.1:80 (1); 192.168.10.3 → 192.168.10.50:60181 (1) |
| 1000207 | DOS DNS ANY query (amplification) | 43 | 27 | 0 | 26 | 0,0% | 0,0% | 192.168.10.8 → 192.168.10.3:53 (15); 192.168.10.3 → 192.168.10.1:53 (11) |
| 1000101 | SCAN Nmap Null Scan detected (No flags) | 206 | 23 | 0 | 23 | 0,0% | 0,0% | 192.168.10.8 → 192.168.10.5:135 (4); 192.168.10.8 → 192.168.10.12:139 (3); 192.168.10.8 → 192.168.10.14:135 (3) |
| 1000103 | SCAN Suspicious SYN-FIN packet detected | 206 | 23 | 0 | 23 | 0,0% | 0,0% | 192.168.10.8 → 192.168.10.5:135 (4); 192.168.10.8 → 192.168.10.12:139 (3); 192.168.10.8 → 192.168.10.14:135 (3) |
| 1000001 | WEB-ATTACK SQL Injection - UNION SELECT detected | 8 | 6 | 6 | 0 | 100,0% | 100,0% |  |
| 1000302 | AUTH FTP anonymous login attempt | 11 | 5 | 0 | 5 | 0,0% | 0,0% | 192.168.10.51 → 185.170.48.239:21 (3); 192.168.10.8 → 192.168.10.50:21 (2) |
| 1000032 | WEB-ATTACK SQL Injection - information_schema enumeration | 3 | 3 | 3 | 0 | 100,0% | 100,0% |  |
| 1000105 | SCAN Nmap Scripting Engine User-Agent | 80 | 2 | 0 | 2 | 0,0% | 0,0% | 192.168.10.8 → 192.168.10.50:80 (2) |
| 1000043 | WEB-ATTACK Sensitive File Access - exposed .git directory | 4 | 2 | 0 | 2 | 0,0% | 0,0% | 192.168.10.8 → 192.168.10.50:80 (2) |

## Theo ngày

| Ngày | Chunk | Flow BENIGN | Bị rule báo (FPR) | Cảnh báo rule | Độ chính xác rule | Theo cặp IP | Cảnh báo ANOMALY | Độ chính xác ANOMALY | Đợt phát hiện |
| :-- | --: | --: | --: | --: | --: | --: | --: | --: | --: |
| monday | 46 | 385.343 | 46,7% | 6.178 | 0,0% | 0,0% | 3.842 | 0,0% | 0/0 |
| tuesday | 44 | 296.427 | 48,6% | 5.885 | 11,8% | 0,0% | 3.582 | 0,0% | 2/3 |
| wednesday | 45 | 299.837 | 51,3% | 5.181 | 5,9% | 0,1% | 3.711 | 1,2% | 5/8 |
| thursday | 43 | 307.679 | 59,0% | 4.590 | 5,4% | 0,1% | 3.625 | 0,1% | 6/6 |
| friday | 43 | 226.150 | 52,3% | 5.103 | 6,6% | 0,2% | 3.487 | 2,0% | 6/8 |

## Theo đợt tấn công

| Ngày | Lớp | Đợt | Bắt đầu (ADT) | Kết thúc (ADT) | Phát hiện | Cảnh báo | Theo tầng | Thời gian tới cảnh báo đầu |
| :-- | :-- | :-- | :-- | :-- | :-- | --: | :-- | --: |
| tuesday | BruteForce | đợt 1 | 09:17:00 | 10:03:32 | có | 242 | RULE_ENGINE 242 | 140,2 giây |
| tuesday | BruteForce | đợt 2 | 10:30:00 | 10:31:00 | **không** | 0 |  | – |
| tuesday | BruteForce | đợt 3 | 14:09:00 | 14:53:32 | có | 446 | RULE_ENGINE 446 | 1,1 giây |
| wednesday | DoS | đợt 1 | 09:01:00 | 09:02:00 | **không** | 0 |  | – |
| wednesday | DoS | đợt 2 | 09:48:00 | 10:02:42 | có | 134 | ANOMALY 3, RULE_ENGINE 131 | 46,2 giây |
| wednesday | DoS | đợt 3 | 10:12:42 | 10:32:42 | có | 42 | ANOMALY 12, RULE_ENGINE 30 | 175,9 giây |
| wednesday | DoS | đợt 4 | 10:43:00 | 10:52:42 | có | 129 | ANOMALY 27, RULE_ENGINE 102 | 23,2 giây |
| wednesday | DoS | đợt 5 | 11:02:42 | 11:12:42 | có | 44 | ANOMALY 2, RULE_ENGINE 42 | 441,2 giây |
| wednesday | DoS | đợt 6 | 14:24:00 | 14:26:00 | **không** | 0 |  | – |
| wednesday | Heartbleed | đợt 1 | 15:12:00 | 15:22:42 | có | 1 | ANOMALY 1 | 15,7 giây |
| wednesday | Heartbleed | đợt 2 | 15:32:42 | 15:33:00 | **không** | 0 |  | – |
| thursday | Infiltration | đợt 1 | 14:19:00 | 14:20:00 | có | 1 | ANOMALY 1 | 2,5 giây |
| thursday | Infiltration | đợt 2 | 14:28:00 | 14:43:00 | có | 1 | ANOMALY 1 | 33,1 giây |
| thursday | Infiltration | đợt 3 | 15:04:00 | 15:28:58 | có | 1 | ANOMALY 1 | 25,5 giây |
| thursday | WebAttack | đợt 1 | 09:15:00 | 09:48:58 | có | 161 | RULE_ENGINE 161 | 393,5 giây |
| thursday | WebAttack | đợt 2 | 10:15:00 | 10:28:58 | có | 75 | RULE_ENGINE 75 | 78,1 giây |
| thursday | WebAttack | đợt 3 | 10:38:58 | 10:43:00 | có | 9 | RULE_ENGINE 9 | 83,5 giây |
| friday | DDoS | đợt 1 | 15:56:00 | 16:09:39 | có | 265 | ANOMALY 39, RULE_ENGINE 226 | 34,5 giây |
| friday | PortScan | đợt 1 | 13:05:00 | 13:07:00 | **không** | 0 |  | – |
| friday | PortScan | đợt 2 | 13:52:00 | 14:01:00 | có | 8 | ANOMALY 4, RULE_ENGINE 4 | 216,3 giây |
| friday | PortScan | đợt 3 | 14:14:00 | 14:17:00 | có | 11 | ANOMALY 2, RULE_ENGINE 9 | 3,8 giây |
| friday | PortScan | đợt 4 | 14:51:00 | 14:57:00 | có | 50 | ANOMALY 14, RULE_ENGINE 36 | 45,5 giây |
| friday | Bot | 192.168.10.9 | 10:04:13 | 17:01:06 | có | 1 | ANOMALY 1 | 1.979,3 giây |
| friday | Bot | 192.168.10.14 | 10:24:28 | 17:00:52 | **không** | 0 |  | – |
| friday | Bot | 192.168.10.15 | 10:06:54 | 17:01:21 | có | 2 | ANOMALY 1, RULE_ENGINE 1 | 10,1 giây |

## Flow không tính vào số liệu

- UNLABELED (không có dòng CSV tương ứng): 13.199
- EXCLUDED (quy tắc chia máy Bot): 48.489
- Cảnh báo rule không tìm được flow: 0

## Ghi chú

Baseline 5 ngày (#76): engine và rule giống main sau PR #73, trước khi sửa rule (#78, #81) và ANOMALY (#79, #80).
