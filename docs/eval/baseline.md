# Kết quả đo: baseline

File này do `python -m tools.eval.evaluate` sinh ra. Cách đọc số liệu: `docs/eval/README.md`.

- Tập: **dev**, 43 chunk (08:59, 09:19, 09:29, 09:39, 09:49, 09:59, 10:09, 10:19, 10:29, 10:39, 10:49, 10:59, 11:09, 11:19, 11:29, 11:39, 11:49, 11:59, 12:09, 12:19, 12:29, 12:39, 12:49, 12:59, 13:09, 13:19, 13:29, 13:39, 13:49, 13:59, 14:09, 14:19, 14:29, 14:39, 14:49, 15:29, 15:39, 15:49, 15:59, 16:19, 16:39, 16:49, 16:59)
- Code: `7c7d552 (có thay đổi chưa commit)`; rule nạp: 68; biến ghi đè: `HOME_NET=192.168.10.0/24`
- Máy Bot dùng để thi: `192.168.10.5`, `192.168.10.8`
- Thời gian chạy: 1.469,9 giây với 12 tiến trình

## Phễu gói

| Bước | Số gói |
| :-- | --: |
| Có trong pcap | 8.078.211 |
| Bị bỏ vì không phải IP | 47.014 |
| Vào phân tích | 8.031.197 |
| Lỗi khi so khớp | 0 |
| Số lần rule khớp trước threshold | 659.984 |

## Thời gian từng bước (cộng mọi chunk, một tiến trình)

| Bước | Giây | Tỉ lệ |
| :-- | --: | --: |
| Scapy đọc và bóc gói | 4.625,0 | 56,3% |
| Decode | 1.583,4 | 19,3% |
| Rule + tái hợp TCP | 1.436,1 | 17,5% |
| Gom flow | 275,9 | 3,4% |
| ANOMALY | 293,6 | 3,6% |
| **Tốc độ** | 983,5 gói/giây | |

## Theo lớp (flow)

Flow bị rule báo: có ít nhất một rule khớp. Với lớp tấn công tỉ lệ này là độ phủ (recall), với BENIGN là tỉ lệ báo nhầm (FPR).

| Lớp | Số flow | Bị rule báo | Tỉ lệ |
| :-- | --: | --: | --: |
| BENIGN | 226.150 | 118.362 | 52,3% |
| Bot | 2.547 | 41 | 1,6% |
| DDoS | 62.420 | 61.655 | 98,8% |
| PortScan | 139.058 | 138.688 | 99,7% |
| EXCLUDED | 48.489 | 22.965 | 47,4% |
| UNLABELED | 2.666 | 940 | 35,3% |

## Theo tầng phát hiện (cảnh báo)

Độ chính xác = cảnh báo rơi vào flow tấn công / (cảnh báo rơi vào flow tấn công + cảnh báo rơi vào BENIGN).

| Tầng | Cảnh báo | Bắt đúng | Báo nhầm | Bỏ qua | Độ chính xác |
| :-- | --: | --: | --: | --: | --: |
| ANOMALY | 2.357 | 81 | 1.933 | 343 | 4,0% |
| RULE_ENGINE | 140.601 | 37.840 | 87.011 | 15.750 | 30,3% |

## Theo rule

| SID | Tên | Khớp trước threshold | Cảnh báo | Bắt đúng | Báo nhầm | Độ chính xác | Báo nhầm nhiều nhất |
| :-- | :-- | --: | --: | --: | --: | --: | :-- |
| 1000205 | DOS UDP flood (high packet rate to one target) | 279.049 | 80.546 | 0 | 69.426 | 0,0% | 192.168.10.15 → 192.168.10.3:53 (131); 192.168.10.14 → 192.168.10.3:53 (130); 192.168.10.9 → 192.168.10.3:53 (116) |
| 1000107 | SCAN TCP SYN port scan (many SYN from one source) | 244.174 | 55.562 | 37.615 | 14.183 | 72,6% | 192.168.10.15 → 178.255.83.1:80 (39); 192.168.10.12 → 178.255.83.1:80 (35); 192.168.10.9 → 72.21.91.29:80 (34) |
| 1000209 | DOS HTTP GET flood (many requests from one source) | 66.070 | 2.099 | 93 | 1.587 | 5,5% | 192.168.10.12 → 119.205.194.14:80 (10); 192.168.10.12 → 61.251.165.12:80 (10); 192.168.10.12 → 125.209.226.232:80 (10) |
| 1000038 | WEB-ATTACK Remote File Inclusion - external URL in parameter | 5.374 | 1.568 | 0 | 1.288 | 0,0% | 192.168.10.9 → 198.54.12.97:80 (31); 192.168.10.9 → 173.241.242.220:80 (31); 192.168.10.16 → 173.241.242.220:80 (24) |
| ANOMALY | ANOMALY Rare port/ICMP type | – | 1.163 | 5 | 1.016 | 0,5% | fe80::3c60:fc97:3f94:ac8f → ff02::1:2:547 (66); fe80::f470:cd16:3cf6:bd7b → ff02::1:2:547 (64); 192.168.10.51 → 192.168.10.3:389 (63) |
| ANOMALY | ANOMALY Packet flood (high packet rate to one target) | – | 723 | 42 | 562 | 7,0% | 192.168.10.15 → 13.107.4.50:80 (25); 13.107.4.50 → 192.168.10.15:49808 (24); 192.168.10.15 → 8.253.104.126:80 (9) |
| ANOMALY | ANOMALY Host sweep (one source probing many hosts) | – | 437 | 1 | 354 | 0,3% | 192.168.10.12 → 125.209.226.232:80 (5); 192.168.10.19 → 192.168.10.3:53 (4); 192.168.10.12 → 172.217.6.232:443 (2) |
| 1000301 | AUTH SSH probe banner attempt | 1.712 | 421 | 0 | 337 | 0,0% | 192.168.10.16 → 192.168.10.50:22 (54); 192.168.10.15 → 192.168.10.50:22 (53); 192.168.10.9 → 192.168.10.50:22 (49) |
| 1000201 | DOS SYN Flood attempt to HTTP port | 62.659 | 191 | 92 | 90 | 50,5% | 192.168.10.12 → 119.205.194.11:80 (10); 192.168.10.12 → 61.251.165.12:80 (10); 192.168.10.25 → 61.251.165.12:80 (6) |
| 1000505 | RECON NetBIOS name query (nbtstat) | 318 | 89 | 0 | 34 | 0,0% | 192.168.10.3 → 192.168.10.1:137 (2); 192.168.10.3 → 192.168.10.50:137 (2); 192.168.10.50 → 192.168.10.3:137 (2) |
| 1000003 | WEB-ATTACK SQL Injection - SQL comment execution (--) | 176 | 80 | 0 | 63 | 0,0% | 192.168.10.19 → 172.217.6.194:80 (5); 192.168.10.19 → 23.21.110.210:80 (4); 192.168.10.15 → 69.4.95.11:80 (4) |
| 1000305 | AUTH SSH brute force (repeated connection attempts) | 153 | 40 | 40 | 0 | 100,0% |  |
| ANOMALY | ANOMALY SYN flood (high SYN rate to one target) | – | 25 | 25 | 0 | 100,0% |  |
| ANOMALY | ANOMALY Port scan (one source probing many ports) | – | 9 | 8 | 1 | 88,9% | 192.168.10.3 → 192.168.10.25:49169 (1) |
| 1000507 | RECON SSDP M-SEARCH discovery | 296 | 3 | 0 | 2 | 0,0% | 192.168.10.14 → 239.255.255.250:1900 (1); 192.168.10.15 → 239.255.255.250:1900 (1) |
| 1000207 | DOS DNS ANY query (amplification) | 3 | 2 | 0 | 1 | 0,0% | 192.168.10.3 → 192.168.10.1:53 (1) |

## Theo đợt tấn công

| Lớp | Đợt | Bắt đầu (ADT) | Kết thúc (ADT) | Phát hiện | Cảnh báo | Theo tầng | Thời gian tới cảnh báo đầu |
| :-- | :-- | :-- | :-- | :-- | --: | :-- | --: |
| PortScan | đợt 1 | 13:05:00 | 13:07:00 | **không** | 0 |  | – |
| PortScan | đợt 2 | 13:52:00 | 14:01:00 | có | 4 | ANOMALY 2, RULE_ENGINE 2 | 216,3 giây |
| PortScan | đợt 3 | 14:14:00 | 14:17:00 | có | 4 | ANOMALY 1, RULE_ENGINE 3 | 3,8 giây |
| PortScan | đợt 4 | 14:51:00 | 14:57:00 | có | 37.559 | ANOMALY 26, RULE_ENGINE 37533 | 45,5 giây |
| DDoS | đợt 1 | 15:56:00 | 16:09:39 | có | 327 | ANOMALY 51, RULE_ENGINE 276 | 34,5 giây |
| Bot | 192.168.10.9 | 10:04:13 | 17:01:06 | có | 7 | ANOMALY 1, RULE_ENGINE 6 | 1.042,7 giây |
| Bot | 192.168.10.14 | 10:24:28 | 17:00:52 | có | 2 | RULE_ENGINE 2 | 11.426,1 giây |
| Bot | 192.168.10.15 | 10:06:54 | 17:01:21 | có | 14 | RULE_ENGINE 14 | 10,1 giây |

## Flow không tính vào số liệu

- UNLABELED (không có dòng CSV tương ứng): 2.666
- EXCLUDED (quy tắc chia máy Bot): 48.489
- Cảnh báo rule không tìm được flow: 0

## Ghi chú

Số cảnh báo (sau threshold) của engine trước PR1 phụ thuộc tốc độ chạy, vì `ThresholdManager` chặn theo giờ máy (`time.time()`); chạy lại có thể ra số hơi khác. Cột "Khớp trước threshold", số flow và nhãn flow thì không phụ thuộc tốc độ.
