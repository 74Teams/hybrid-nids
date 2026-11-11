# Lộ trình của B (chiendev): bộ đo, ANOMALY, CSDL, API và demo

Đây là lịch riêng của **B** (nmchien1106), tách từ [lộ trình chung](lo-trinh-3-tuan.md). Muốn biết vì sao làm việc này thì đọc lộ trình chung và [PLAN-009](plans/2026-11-10-labeled-eval-optimization.md). Lịch của A ở [lo-trinh-A.md](lo-trinh-A.md).

## Tóm tắt

| Giai đoạn | Việc chính | Issue |
| :--- | :--- | :--- |
| 12–17/11 | Dựng môi trường đo, sửa test CI chập chờn, bộ đo theo cặp IP, sửa và chỉnh ngưỡng ANOMALY | #89, #76, #79, #80 |
| 18–23/11 | `FlowTracker.expire`, đo API, index và cache, dọn bảng `events`, thử live bằng `tcpreplay` | #84, #86, #87, #88, #90 |
| 24/11 | Thi lần 1 cùng A, chạy lại trên máy mình để kiểm tra | #91 |
| 25/11–01/12 | Lab Docker, kịch bản demo, phần báo cáo về hệ thống, chạy lại dataset trên máy mình, review PR AI, thi lần cuối, demo | #95 |

**A làm toàn bộ AI.** B không phải viết code AI, chỉ review và chạy lại để kiểm tra số liệu.

B vẫn còn PR #57 (PLAN-001) và #61 (PLAN-004) đang mở. Lịch dưới đây coi như B dành phần lớn thời gian cho PLAN-009. Nếu phải ưu tiên hai PR kia thì cắt việc theo thứ tự ở cuối file.

## Trước khi bắt đầu (12/11)

**1. Dữ liệu.** Dữ liệu CIC-IDS2017 nằm trên máy A; nhận từ A bằng ổ ngoài hoặc qua mạng LAN:

| Dữ liệu | Dung lượng | Cần cho |
| :--- | --: | :--- |
| `TrafficLabelling_` (8 file CSV nhãn) | 1,2 GB | mọi việc đo |
| `split\` thứ Sáu (49 file pcap 10 phút) | khoảng 9 GB | 12–14/11 |
| `split\` cả 5 ngày | 49 GB | 15–16/11 (#79, #80) |
| `data\cic\*_manifest.json` | vài KB | mọi việc đo; đặt vào `data\cic\` của repo |

File manifest ghi đường dẫn pcap theo máy A, nên trên máy B **luôn truyền `--split-dir`** khi chạy bộ đo.

**2. Đọc trước** (khoảng 1 giờ):

- [eval/README.md](eval/README.md): cách đọc bảng số liệu của bộ đo.
- [nhat-ky-ngay-1.md](nhat-ky-ngay-1.md): bộ đo làm gì, nhãn CIC có những bẫy gì (giờ không có AM/PM, giờ Canada).
- [eval/sau-sua-engine.md](eval/sau-sua-engine.md): số liệu mới nhất, dùng để so khi tái lập.
- PLAN-009 mục 6.3: dev/test, chia Bot theo máy nhiễm. **Không được chạy tập test** (`--set test`, `--allow-test`) ngoài hai lần thi 24/11 và 30/11.

**3. Quy ước của repo** (chi tiết trong `CLAUDE.md`, `.claude/rules/`):

- Code mới trong `tools/` và `nids/` dùng `logging.getLogger("nids.<khu vực>")`, không dùng `print`. Log và comment viết tiếng Việt có dấu.
- Nhánh đặt dạng `<loại>/<mô-tả>`, commit tiếng Anh theo Conventional Commits, mô tả PR tiếng Việt.
- Test trong `tests/tools/` không đọc dữ liệu trên ổ D, chỉ dùng file nhỏ dựng trong test.

## Phối hợp với A

| Ngày | B nhận từ A | B giao cho A |
| :--- | :--- | :--- |
| 12/11 | Dữ liệu CIC, file manifest | Kết quả tái lập baseline thứ Sáu: giống hay khác |
| 12/11 | PR `feature/eval-five-days` (#74, #75, baseline 4 ngày), làm nền cho #76 | |
| 14/11 | | **Bảng rule web, dò mật khẩu, DoS** từ baseline 4 ngày: bắt đúng, nhầm, sót đợt nào. A cần bảng này cho #81 ngày 16/11 |
| 17/11 | PR rule | PR ANOMALY; cùng đo dev 5 ngày |
| 19/11 | A review PR #84 | **PR #84 phải sẵn sàng merge trong ngày 19/11**: A sửa `flow.py` từ 21/11 và cần #84 vào trước |
| 23/11 | PR #92 và PR khung AI | Review |
| 28/11 | Lệnh chạy `build_dataset.py`, `train.py` | Số liệu chạy lại trên máy B |
| 29/11 | PR AI | Review, thử demo có bật AI |

## Lịch từng ngày

### 12–17/11: bộ đo và ANOMALY

| Ngày | Việc | Issue | Nhánh | Xong khi |
| :--- | :--- | :--- | :--- | :--- |
| T5 12/11 | **Dựng môi trường đo:** nhận dữ liệu, chạy lại baseline thứ Sáu (lệnh ở dưới). **Sửa test CI chập chờn** `tests/api/test_realtime_ws.py`; việc này không cần dữ liệu, làm trong lúc chờ chép file | #89 | `bugfix/89-realtime-ws-flaky` | Số flow, số lần rule khớp, số cảnh báo giống hệt `sau-sua-engine.md`; `pytest` chạy 10 lần liền đều xanh |
| T6 13/11 | Bộ đo: thêm **độ chính xác theo cặp IP** và **lưu danh sách cảnh báo** ra file. Dùng nó tìm lý do máy Bot `192.168.10.14` không còn bị phát hiện (`nhat-ky-ngay-2.md`, mục T8) | #76 | `feature/eval-pair-precision`, tách từ `feature/eval-five-days` | Báo cáo có thêm cột theo cặp IP; có file danh sách cảnh báo trong `data/eval/` |
| T7 14/11 | Đọc baseline 4 ngày của A, **lập bảng cho A** (rule web thứ Năm, dò mật khẩu thứ Ba, DoS thứ Tư). Mở PR #76 | #76 | như trên | A nhận bảng trước tối 14/11 |
| CN 15/11 | **Sửa ANOMALY "Rare port":** bỏ qua IPv6 multicast và link-local, cổng dịch vụ nội bộ (LDAP 389/3268, NetBIOS 137–139). Đo dev | #79 | `feature/anomaly-tuning` | Độ chính xác ANOMALY tăng rõ so với 2%, không mất đợt nào |
| T2 16/11 | **Chỉnh ngưỡng ANOMALY bằng dữ liệu:** thử nhiều bộ `scan`/`flood` trên dev 5 ngày, chọn bộ bắt được đợt PortScan 13:05 mà ít báo nhầm nhất; ghi vào `config/settings.example.yaml` kèm lý do | #80 | như trên | FPR flow BENIGN của ANOMALY ≤ 1%, phát hiện mọi đợt dev |
| T3 17/11 | Mở PR ANOMALY. Cùng A đo dev 5 ngày → `docs/eval/sau-sua-so-khop.md` | #79, #80 | | Có bảng so với baseline |

**Lệnh tái lập baseline thứ Sáu (12/11):**

```powershell
pip install -r requirements.txt
python -m tools.eval.evaluate --labels-dir <thư mục TrafficLabelling_> --split-dir <thư mục split thứ Sáu> --set dev --set-var HOME_NET=192.168.10.0/24 --name tai-lap-may-b --report-dir data\eval\tai-lap
```

Lệnh chạy khoảng 15–25 phút tuỳ số nhân CPU (`--jobs` mặc định là số nhân trừ 2, tối đa 12). Kết quả khác `sau-sua-engine.md` nghĩa là bộ đo phụ thuộc máy (tiêu chí 9 của plan), báo A ngay.

**Ghi chú về ANOMALY:** bộ đo lấy ngưỡng từ `config/settings.example.yaml`, không đọc `settings.yaml` local. Đây là nguồn ngưỡng duy nhất cho cả bộ đo lẫn engine thật, nên chỉnh ngưỡng nghĩa là sửa file mẫu này.

### 18–24/11: engine, CSDL, API, thử live

| Ngày | Việc | Issue | Nhánh | Xong khi |
| :--- | :--- | :--- | :--- | :--- |
| T4 18/11 | **Quét flow hết hạn nhanh hơn:** idle timeout duyệt từ đầu `OrderedDict` và dừng ở flow đầu tiên chưa hết hạn (PLAN-009 mục 6.5 điểm 5) | #84 | `refactor/flow-expire-sweep` | Số flow và tổng gói **giống hệt** bản cũ trên mọi chunk dev; `tests/engine/test_flow.py` xanh |
| T5 19/11 | **Mở PR #84** (A cần merge trong ngày). **Công cụ đo API:** đổ 1 triệu cảnh báo vào CSDL thử, đo trang thống kê, danh sách cảnh báo, biểu đồ | #84, #86 | `feature/api-db-perf` | Có bảng thời gian trả lời trước khi tối ưu |
| T6 20/11 | **Thêm index** cho bảng `events` (cột lọc và gom nhóm), **cache 5 giây** cho thống kê và biểu đồ. Đo lại | #87 | như trên | Bảng trước/sau |
| T7 21/11 | **Dọn `events` theo hạn** (`database.events_retention_days`), lượt dọn không chặn engine. Viết test | #88 | như trên | Test xanh; engine không chờ lượt dọn |
| CN 22/11 | **Thử bắt gói trực tiếp:** phát lại đoạn 09:19 vào lab Docker bằng `tcpreplay`, đếm gói bị bỏ. Mở PR CSDL/API | #90 | | Có số gói bị bỏ ở chế độ live |
| T2 23/11 | Review PR của A (#92, khung AI). Cập nhật tài liệu cho thay đổi tuần 1–2: `CLAUDE.md`, `.claude/rules/engine.md`, `config-db-docker.md` | | | |
| T3 24/11 | **Thi lần 1** cùng A, tập test 5 ngày, chỉ rule và ANOMALY → `docs/eval/thi-lan-1.md`. Chạy cùng lệnh trên máy mình để kiểm tra số liệu lặp lại được | #91 | | Số trên hai máy giống nhau |

**Trước khi code #86–#88:** ba việc này chạm nhiều khu vực cùng lúc (db, api, config), nên theo `.claude/rules/planning.md` cần một plan nhỏ, hoặc bổ sung vào phạm vi PLAN-009 (mục 3 hiện chưa có). Nên viết bằng `/idea-to-plan` trong tuần 1, để 18/11 vào việc được ngay.

### 25/11–01/12: demo, báo cáo, kiểm tra AI

| Ngày | Việc | Xong khi |
| :--- | :--- | :--- |
| T4 25/11 | **Lab Docker từ đầu tới cuối** (PLAN-009 mục 9 bước 8): `docker compose up --build`, `attack_demo.py` sinh cảnh báo cho rule cũ và rule mới; sửa lỗi nếu có | Mọi rule có đòn đều ra cảnh báo |
| T5 26/11 | Cập nhật **kịch bản demo** (`docs/demo/kich-ban-demo.md`) theo rule và ngưỡng mới; chừa chỗ cho đoạn "AI bắt Bot" | Kịch bản chạy đúng thứ tự trong lab |
| T6 27/11 | Viết **phần báo cáo về hệ thống**: tốc độ engine, thời gian trả lời API, kết quả thử live, số liệu trước và sau (lấy từ `docs/eval/`) | |
| T7 28/11 | Chạy `build_dataset.py` và `train.py` của A trên máy mình, so với số của A (tiêu chí 9) | Số liệu khớp, hoặc đã báo A chỗ lệch |
| CN 29/11 | **Review PR AI**, chạy thử demo có bật AI trong lab | |
| T2 30/11 | **Thi lần cuối** cùng A (#95): B chạy phần rule, ANOMALY và so với thi lần 1 | |
| T3 01/12 | Chạy thử demo đầy đủ bằng Docker cùng A, sửa lỗi, dự phòng | |

## Nếu bị trễ, cắt theo thứ tự

1. Thử live bằng `tcpreplay` (#90).
2. Dọn `events` theo hạn (#88).
3. Chạy lại dataset trên máy thứ hai (28/11).

Không cắt: ANOMALY (#79, #80), #84 (A cần trước 21/11), hai lần thi.

**Phần thêm nếu xong sớm ở tuần 2:** nguyên mẫu tách đọc gói và phân tích thành hai process để tránh GIL (#85, phần A không làm).

## Ngày đầu (12/11)

1. Nhận dữ liệu từ A, đặt `*_manifest.json` vào `data\cic\`.
2. Trong lúc chờ chép: sửa test chập chờn #89.
3. Chạy lệnh tái lập baseline thứ Sáu ở trên, so với `docs/eval/sau-sua-engine.md`, báo A kết quả.
