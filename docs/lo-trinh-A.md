# Lộ trình của A (nldd0507): so khớp, engine và toàn bộ AI

Đây là lịch riêng của **A**, tách từ [lộ trình chung](lo-trinh-3-tuan.md). Muốn biết vì sao làm việc này thì đọc lộ trình chung và [PLAN-009](plans/2026-11-10-labeled-eval-optimization.md). Lịch của B ở [lo-trinh-B.md](lo-trinh-B.md).

## Tóm tắt

| Giai đoạn | Việc chính | Issue |
| :--- | :--- | :--- |
| 11–17/11 | Sửa nhãn và lập manifest 5 ngày, baseline 4 ngày, đo phần so khớp, sửa 4 rule báo nhầm, thêm rule cho 4 ngày mới, tăng tốc so khớp | #74, #75, #77, #78, #81, #82 |
| 18–20/11 | Ghi flow ở luồng riêng, nguyên mẫu decoder đọc byte thô | #83, #85 |
| 21–23/11 | Chuẩn bị AI: bộ đếm đặc trưng, `features.py`, khung worker với mô hình giả | #92, #94 (phần khung) |
| 24/11 | Thi lần 1 cùng B | #91 |
| 25/11–01/12 | **Toàn bộ AI**: dataset, Random Forest, gắn mô hình thật vào engine, đo chi phí, báo cáo; thi lần cuối, demo | #93, #94, #95 |

Dữ liệu CIC nằm trên máy A, nên **mọi lượt đo dài trên 5 ngày do A chạy** (manifest, baseline, dataset).

## Phối hợp với B

| Ngày | A giao cho B | A nhận từ B |
| :--- | :--- | :--- |
| 12/11 | Dữ liệu CIC (CSV nhãn, pcap thứ Sáu, sau đó cả 5 ngày) và file `data/cic/*_manifest.json` | |
| 12/11 | PR `feature/eval-five-days` (#74, #75, baseline 4 ngày), để B làm #76 trên đó | |
| 14/11 | | Bảng rule web, dò mật khẩu, DoS: bắt đúng, nhầm, sót đợt nào (đầu vào cho #81 ngày 16/11) |
| 17/11 | PR rule | PR ANOMALY; cả hai đo dev 5 ngày |
| 19/11 | Review PR #84 của B | PR #84 (`FlowTracker.expire`): **phải merge trước khi A sửa `flow.py` ngày 21/11** |
| 23/11 | PR #92 và PR khung AI | B review |
| 28/11 | Lệnh chạy `build_dataset.py` và `train.py` | B chạy lại trên máy mình, so số với A |
| 29/11 | PR AI | B review, thử demo có bật AI |

## Lịch từng ngày

### 11–17/11: đo đủ 5 ngày, tối ưu so khớp

| Ngày | Việc | Issue | Nhánh | Xong khi |
| :--- | :--- | :--- | :--- | :--- |
| T4 11/11 (tối nay) | Theo [viec-hom-nay-11-11.md](viec-hom-nay-11-11.md): **sửa nhãn Infiltration**, **manifest thứ Hai–Năm**, `cProfile` bước 1–2, bật **baseline 4 ngày** chạy qua đêm | #74, #75, #77 | `feature/eval-five-days`, `feature/rule-precision-cic` | Manifest thứ Sáu không đổi; có 4 file `docs/eval/manifest-<ngày>.md`; baseline đang chạy |
| T5 12/11 | Kiểm tra 4 file `docs/eval/baseline-<ngày>.md`. Xong #77: đếm theo từng rule (số lần kiểm tra chi tiết, số lần khớp), ghi bảng vào `docs/eval/`. **Mở PR `feature/eval-five-days`**. Đưa dữ liệu cho B | #77 | | Có bảng top rule và top bước tốn thời gian, kèm đề xuất tăng tốc |
| T6 13/11 | **Sửa rule 1000205 (UDP flood):** không báo khi đích là DNS/NTP/mDNS (cổng 53, 123, 5353) hoặc tăng ngưỡng. Test đúng (gói flood thật) và test sai (DNS server bận). Đo dev thứ Sáu | #78 | `feature/rule-precision-cic` | FPR flow BENIGN giảm, không mất đợt nào |
| T7 14/11 | **Sửa 1000107 (SYN scan):** quét là nhiều *cổng khác nhau*, không chỉ nhiều SYN. **Sửa 1000209 (GET flood):** đếm theo đích, tăng ngưỡng. Đo dev | #78 | như trên | như trên |
| CN 15/11 | **Sửa 1000038 (RFI):** chỉ bắt khi tham số có tên hay bị lợi dụng (`file=`, `page=`, `include=`, `path=`). Cập nhật `tests/lab/test_demo_rules.py`. Đo dev | #78 | như trên | Đòn demo vẫn kích hoạt rule |
| T2 16/11 | **Sửa và thêm rule** theo bảng của B, ví dụ Slowloris, Slowhttptest (thứ Tư), dò mật khẩu web (thứ Năm). Mỗi rule mới kèm đòn trong `lab/attacker/attack_demo.py` | #81 | như trên | `tests/lab/test_attack_demo.py` xanh |
| T3 17/11 | **Tăng tốc so khớp** theo kết quả #77 (rule không có fast pattern, pcre nặng). Số lần rule khớp phải **không đổi**. Mở PR rule. Cùng B đo dev 5 ngày → `docs/eval/sau-sua-so-khop.md` | #82 | như trên | Có bảng so với baseline |

**Luật khi sửa rule** (đọc `.claude/rules/snort-rules.md` trước):

- Tăng `rev` của rule.
- Có test positive và test negative. Test negative dùng mẫu báo nhầm thật, ví dụ URL quảng cáo, DNS server bận.
- Rule phải nạp sạch với cả ba giá trị `HOME_NET`: `any`, `172.28.0.0/16` và `192.168.10.0/24`. Vì vậy không dùng `!$HOME_NET`.
- Rule mới phải có đòn tương ứng trong `attack_demo.py`.

### 18–24/11: tối ưu engine, chuẩn bị AI, thi lần 1

| Ngày | Việc | Issue | Nhánh | Xong khi |
| :--- | :--- | :--- | :--- | :--- |
| T4 18/11 | **Ghi flow log ở luồng riêng**, giống `AlertWriter`. Thử lại phép khoá CSDL 35 giây | #83 | `feature/flow-writer` | Luồng phân tích không đứng khi CSDL bị khoá |
| T5 19/11 | Mở PR flow writer. **Nguyên mẫu đọc gói bằng byte thô**, không qua Scapy. Review PR #84 của B | #85 | `feature/raw-decoder-prototype` | Nguyên mẫu chạy được trên `chienbuoito.pcap` |
| T6 20/11 | Đo nguyên mẫu: tốc độ, và số lần rule khớp phải giống hệt Scapy. **Chốt ngay hôm nay:** đưa vào engine hay chỉ ghi số đo | #85 | như trên | Có quyết định ghi vào mục 12 của plan. Decoder ảnh hưởng đặc trưng AI, nên không được chốt muộn hơn |
| T7 21/11 | **Bộ đếm đặc trưng cho `Flow`**: độ dài gói nhỏ nhất, lớn nhất, trung bình theo chiều; khoảng cách thời gian giữa các gói (IAT); số lần mỗi cờ TCP; byte payload. Bắt đầu **sau khi #84 đã merge** | #92 | `feature/ai-flow-features` | Mỗi gói chỉ tốn O(1); test flow dựng sẵn ra đúng số |
| CN 22/11 | `nids/ai/features.py`: `FEATURE_NAMES` (khoảng 30 đặc trưng) và `extract_features(flow)`. Mở PR | #92 | như trên | Test không chia cho 0; số đếm flow và số cảnh báo trên dev không đổi |
| T2 23/11 | **Phần khung AI:** đổi `nids/ai.py` thành thư mục `nids/ai/` (vẫn `from nids.ai import AITrafficWorker`), `FlowLog` gọi callback `on_flow_finished`, cảnh báo `AI_ENGINE`, nhãn AI trên dashboard và trang Logs. Test bằng **mô hình giả**. Công tắc `detection.enable_ai_worker` vẫn tắt | #94 | `feature/ai-worker-integration` | Lỗi `predict` chỉ được log, engine chạy tiếp |
| T3 24/11 | **Thi lần 1** cùng B: tập test 5 ngày, chỉ rule và ANOMALY → `docs/eval/thi-lan-1.md` | #91 | | Đối chiếu tiêu chí 1–5 của plan |

### 25/11–01/12: AI

| Ngày | Việc | Issue | Xong khi |
| :--- | :--- | :--- | :--- |
| T4 25/11 | `tools/ai/build_dataset.py`: chạy pcap 5 ngày song song → `data/ai/features.csv.gz` có cột `chunk`, `split`, `label`, `label_raw`. Bật chạy qua đêm | #93 | Có file dataset, số flow theo nhãn khớp manifest |
| T5 26/11 | `tools/ai/train.py`: **Random Forest** (`class_weight="balanced"`) trên dev 5 ngày, chia theo thời gian và theo máy Bot; chia ngẫu nhiên để tham khảo | #93 | Có `models/flow_model.joblib` kèm `feature_names` và `version` |
| T6 27/11 | Chọn ngưỡng trên dev sao cho báo nhầm ≤ 1%. IsolationForest nếu kịp. Viết `docs/ai/ket-qua-danh-gia.md`: bảng nhầm lẫn, đặc trưng quan trọng, ví dụ flow | #93 | Có báo cáo; chưa nhìn tập test |
| T7 28/11 | **Nạp mô hình thật vào worker.** Thiếu mô hình hoặc `feature_names` lệch thì log lỗi và tắt AI, engine chạy tiếp. **Đo engine khi bật AI** (tiêu chí 8). Gửi B lệnh chạy lại dataset và train | #94 | Chậm hơn ≤ 20%, không vứt gói |
| CN 29/11 | Mở PR AI. Cập nhật `docs/ai/03`, `04`, `05` và mục `ai` trong `config/settings.example.yaml` | #94 | B đã review |
| T2 30/11 | **Thi lần cuối** cùng B, bật AI → `docs/eval/ket-qua-cuoi.md`. A chạy và giải thích phần AI | #95 | Đối chiếu đủ 9 tiêu chí |
| T3 01/12 | Chạy thử demo đầy đủ bằng Docker cùng B, kịch bản "AI bắt Bot"; dự phòng; đóng plan | #95 | |

## Nếu bị trễ, cắt theo thứ tự

1. IsolationForest, rồi mô hình so sánh trên `MachineLearningCVE`.
2. Nguyên mẫu đọc byte thô (#85): bỏ hẳn, giữ Scapy. Có thêm 2 ngày cho AI.
3. Phần khung AI (23/11) dời sang 25/11, dataset dời sang 26/11.

Không cắt: sửa 4 rule báo nhầm, hai lần thi, Random Forest gắn vào engine.

## Ngày mai (12/11)

1. Kiểm tra baseline 4 ngày chạy qua đêm đã ra đủ `docs/eval/baseline-<ngày>.md`.
2. Đếm theo từng rule cho #77, viết bảng kết quả.
3. Mở PR `feature/eval-five-days` (#74, #75 và 4 file baseline) để B làm #76 trên đó.
4. Chép dữ liệu cho B: CSV nhãn và pcap thứ Sáu trước, cả 5 ngày (49 GB) trước 15/11. Chi tiết ở [lộ trình chung](lo-trinh-3-tuan.md) mục 8.
