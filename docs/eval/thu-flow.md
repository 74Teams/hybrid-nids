# Kết quả đo: thu-flow

File này do `python -m tools.eval.evaluate` sinh ra. Cách đọc số liệu: `docs/eval/README.md`.

- Tập: **chọn tay**, 1 chunk (14:09)
- Code: `2ffcb54 (có thay đổi chưa commit)`; rule nạp: 68; biến ghi đè: `HOME_NET=192.168.10.0/24`
- Máy Bot dùng để thi: `192.168.10.5`, `192.168.10.8`
- Thời gian chạy: 26,3 giây với 12 tiến trình

## Phễu gói

| Bước | Số gói |
| :-- | --: |
| Có trong pcap | 107.996 |
| Bị bỏ vì không phải IP | 1.041 |
| Vào phân tích | 106.955 |
| Lỗi khi so khớp | 0 |
| Số lần rule khớp trước threshold | 8.976 |

## Thời gian từng bước (cộng mọi chunk, một tiến trình)

| Bước | Giây | Tỉ lệ |
| :-- | --: | --: |
| Scapy đọc và bóc gói | 13,2 | 55,9% |
| Decode | 4,8 | 20,5% |
| Rule + tái hợp TCP | 3,9 | 16,7% |
| Gom flow | 1,2 | 5,0% |
| ANOMALY | 0,5 | 1,9% |
| **Tốc độ** | 4.580,1 gói/giây | |

## Theo lớp (flow)

Flow bị rule báo: có ít nhất một rule khớp. Với lớp tấn công tỉ lệ này là độ phủ (recall), với BENIGN là tỉ lệ báo nhầm (FPR).

| Lớp | Số flow | Bị rule báo | Tỉ lệ |
| :-- | --: | --: | --: |
| BENIGN | 5.594 | 2.652 | 47,4% |
| Bot | 72 | 0 | 0,0% |
| PortScan | 118 | 13 | 11,0% |
| EXCLUDED | 1.813 | 1.025 | 56,5% |
| UNLABELED | 100 | 22 | 22,0% |

## Theo tầng phát hiện (cảnh báo)

Độ chính xác = cảnh báo rơi vào flow tấn công / (cảnh báo rơi vào flow tấn công + cảnh báo rơi vào BENIGN).

| Tầng | Cảnh báo | Bắt đúng | Báo nhầm | Bỏ qua | Độ chính xác |
| :-- | --: | --: | --: | --: | --: |
| ANOMALY | 87 | 2 | 69 | 16 | 2,8% |
| RULE_ENGINE | 164 | 9 | 95 | 60 | 8,7% |

## Theo rule

| SID | Tên | Khớp trước threshold | Cảnh báo | Bắt đúng | Báo nhầm | Độ chính xác | Báo nhầm nhiều nhất |
| :-- | :-- | --: | --: | --: | --: | --: | :-- |
| 1000038 | WEB-ATTACK Remote File Inclusion - external URL in parameter | 233 | 80 | 0 | 40 | 0,0% | 192.168.10.19 → 38.69.238.19:80 (6); 192.168.10.19 → 52.54.195.143:80 (6); 192.168.10.19 → 165.254.34.231:80 (6) |
| ANOMALY | ANOMALY Rare port/ICMP type | – | 51 | 2 | 41 | 4,7% | 192.168.10.25 → 192.168.10.255:137 (3); 192.168.10.50 → 192.168.10.12:137 (2); 192.168.10.51 → 192.168.10.3:389 (2) |
| 1000205 | DOS UDP flood (high packet rate to one target) | 7.207 | 34 | 0 | 25 | 0,0% | 192.168.10.3 → 192.168.10.1:53 (4); 192.168.10.19 → 192.168.10.3:53 (3); 192.168.10.3 → 192.168.10.14:63037 (1) |
| ANOMALY | ANOMALY Host sweep (one source probing many hosts) | – | 20 | 0 | 14 | 0,0% | 192.168.10.19 → 192.168.10.3:53 (2); 192.168.10.14 → 207.244.77.134:443 (1); 192.168.10.19 → 195.248.251.144:80 (1) |
| ANOMALY | ANOMALY Packet flood (high packet rate to one target) | – | 16 | 0 | 14 | 0,0% | 23.205.22.154 → 192.168.10.14:56259 (1); 63.144.176.8 → 192.168.10.19:50715 (1); 193.240.182.34 → 192.168.10.17:51510 (1) |
| 1000107 | SCAN TCP SYN port scan (many SYN from one source) | 1.099 | 15 | 0 | 12 | 0,0% | 192.168.10.14 → 31.13.69.203:443 (1); 192.168.10.19 → 172.217.10.35:80 (1); 192.168.10.19 → 69.172.216.111:80 (1) |
| 1000301 | AUTH SSH probe banner attempt | 56 | 14 | 0 | 11 | 0,0% | 192.168.10.19 → 192.168.10.50:22 (2); 192.168.10.12 → 192.168.10.50:22 (2); 192.168.10.9 → 192.168.10.50:22 (2) |
| 1000305 | AUTH SSH brute force (repeated connection attempts) | 13 | 9 | 9 | 0 | 100,0% |  |
| 1000003 | WEB-ATTACK SQL Injection - SQL comment execution (--) | 11 | 8 | 0 | 4 | 0,0% | 192.168.10.19 → 172.217.6.194:80 (3); 192.168.10.19 → 69.172.216.111:80 (1) |
| 1000209 | DOS HTTP GET flood (many requests from one source) | 354 | 2 | 0 | 1 | 0,0% | 192.168.10.19 → 63.144.176.8:80 (1) |
| 1000201 | DOS SYN Flood attempt to HTTP port | 3 | 2 | 0 | 2 | 0,0% | 192.168.10.19 → 69.172.216.111:80 (1); 192.168.10.12 → 104.25.17.36:80 (1) |

## Theo đợt tấn công

| Lớp | Đợt | Bắt đầu (ADT) | Kết thúc (ADT) | Phát hiện | Cảnh báo | Theo tầng | Thời gian tới cảnh báo đầu |
| :-- | :-- | :-- | :-- | :-- | --: | :-- | --: |
| PortScan | đợt 1 | 14:14:00 | 14:17:00 | có | 11 | ANOMALY 2, RULE_ENGINE 9 | 3,8 giây |
| Bot | 192.168.10.9 | 14:10:17 | 14:18:43 | **không** | 0 |  | – |
| Bot | 192.168.10.14 | 14:10:16 | 14:18:42 | **không** | 0 |  | – |
| Bot | 192.168.10.15 | 14:10:08 | 14:18:59 | **không** | 0 |  | – |

## Flow không tính vào số liệu

- UNLABELED (không có dòng CSV tương ứng): 100
- EXCLUDED (quy tắc chia máy Bot): 1.813
- Cảnh báo rule không tìm được flow: 0
