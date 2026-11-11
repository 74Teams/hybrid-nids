# Việc làm được hôm nay (11/11/2026)

Tài liệu này dựa trên [lộ trình 3 tuần](lo-trinh-3-tuan.md) bản cập nhật 11/11 (PR #96), [PLAN-009](plans/2026-11-10-labeled-eval-optimization.md) và [nhật ký ngày 2](nhat-ky-ngay-2.md). Nó trả lời một câu hỏi: **phần còn lại của hôm nay nên làm gì, theo thứ tự nào.**

## 1. Đang ở đâu

Tuần 1 của PLAN-009 dự kiến làm trong 2 ngày (10–11/11) và **đã xong**: PR #72 (bộ đo) và PR #73 (sửa engine) đã merge, PR #96 (sắp lại lộ trình) cũng đã merge. Lịch mới bắt đầu từ 12/11, nên mọi việc dưới đây là **làm trước lịch** việc của ngày 12/11.

| Đã có | Con số |
| :--- | :--- |
| Bộ đo có nhãn chạy trên thứ Sáu | baseline ở [eval/baseline.md](eval/baseline.md), sau khi sửa ở [eval/sau-sua-engine.md](eval/sau-sua-engine.md) |
| Engine không vứt gói khi đọc pcap | 86% → 0% |
| Tốc độ engine thật | 2.735 gói/giây (chunk 14:09), 3.189 (chunk 09:19) |
| Cảnh báo lặp lại được giữa các lần chạy | 251 / 251 trên `chienbuoito.pcap` |
| Pcap 5 ngày đã cắt 10 phút | `D:\Tools\PBL4\split\` (thứ Sáu ở gốc) và `split\{monday,tuesday,wednesday,thursday}` (49, 49, 51, 49 file) |
| Manifest | **mới có thứ Sáu** (`data/cic/friday_manifest.json`) |

Điểm chưa tốt lớn nhất vẫn là **báo nhầm**: 52,3% flow bình thường bị rule báo. Lộ trình mới vì vậy làm phần so khớp trước, AI để tuần cuối.

## 2. Tóm tắt việc hôm nay

Làm theo đúng thứ tự trong bảng. Thứ tự này không tuỳ ý: việc sau dùng kết quả của việc trước, và việc chạy lâu nhất được để chạy nền qua đêm.

| # | Việc | Issue | Thời gian | Nhánh |
| :- | :--- | :--- | :--- | :--- |
| 0 | Dọn dẹp git, chốt vai A/B | | 15 phút | `main` |
| 1 | Sửa lỗi nhãn Infiltration | [#74](https://github.com/74Teams/hybrid-nids/issues/74) | 45 phút | `feature/eval-five-days` |
| 2 | Lập manifest thứ Hai đến thứ Năm | [#75](https://github.com/74Teams/hybrid-nids/issues/75) | 1–1,5 giờ | `feature/eval-five-days` |
| 3 | Đo phần so khớp tốn thời gian ở đâu | [#77](https://github.com/74Teams/hybrid-nids/issues/77) | 1,5–2 giờ | `feature/rule-precision-cic` |
| 4 | Chạy baseline 4 ngày (chạy nền qua đêm) | một phần của [#76](https://github.com/74Teams/hybrid-nids/issues/76) | bấm chạy 10 phút, máy tự chạy 1–2 giờ | `feature/eval-five-days` |
| 5 | (nếu còn sức) Đọc trước rule 1000205 cho ngày mai | [#78](https://github.com/74Teams/hybrid-nids/issues/78) | 30 phút | chỉ đọc |

Theo [lộ trình](lo-trinh-3-tuan.md) bản đã chốt vai, cả 5 việc này là của bạn (người A). Lý do: dữ liệu CIC đang nằm trên máy bạn. chiendev (người B) bắt đầu từ 12/11 bằng việc chép dữ liệu và chạy lại baseline thứ Sáu trên máy mình.

**Vì sao việc 3 đứng trước việc 4?** Việc 4 dùng 12 tiến trình, gần như chiếm hết CPU. Đo thời gian (việc 3) trong lúc máy đang bận sẽ ra số sai. Vậy nên đo trước, rồi mới bật baseline và để máy chạy.

---

## 3. Việc 0: dọn dẹp (15 phút)

**1. Kéo `main` mới nhất.** `main` trên máy đang chậm hơn GitHub một PR (#96, lộ trình mới):

```powershell
git switch main
git pull
```

**2. Hai file `M` trong `git status`.** `README.md` và `docs/setup-linux.md` đang hiện là đã sửa, nhưng `git diff -w` không có dòng nào khác: chỉ khác kiểu xuống dòng (LF và CRLF của Windows). Kiểm tra lại cho chắc rồi bỏ:

```powershell
git diff README.md docs/setup-linux.md     # không in nội dung nào thì đúng là chỉ khác xuống dòng
git restore README.md docs/setup-linux.md
```

Nếu `git diff` có in nội dung thật thì **đừng** chạy `git restore`, vì lệnh đó xoá thay đổi.

**3. Worktree thừa.** Có một worktree `..\hybrid-nids-alldays` ở nhánh `feature/71-cic-all-days`, không có commit nào mới và không có file sửa. Lộ trình mới dùng tên nhánh `feature/eval-five-days` thay cho nhánh này. Nếu không dùng nữa:

```powershell
git worktree remove ..\hybrid-nids-alldays
git branch -d feature/71-cic-all-days
```

Ba nhánh local đã merge cũng xoá được: `git branch -d feature/cic-eval-tools feature/engine-alert-writer docs/71-roadmap-optimize-first`.

**4. Chốt vai A/B** với thành viên thứ hai (mục 5 của lộ trình). Đây vẫn là câu hỏi còn mở ở mục 12 của PLAN-009.

---

## 4. Việc 1: sửa lỗi nhãn Infiltration (#74, 45 phút)

### Vấn đề

`tools/cic/labels.py` (dòng 231) có quy tắc: dòng CSV nào có IP `205.174.165.73` thì đổi nhãn thành `Bot`, **dù CSV ghi nhãn gì**:

```python
if C2_IP in (str(src_ip).strip(), str(dst_ip).strip()) and label != "Bot":
    label = "Bot"
```

Quy tắc này viết cho thứ Sáu: máy nhiễm botnet gọi về IP này cả ngoài khung giờ Bot nhưng CSV lại ghi BENIGN. Nhưng thứ Năm, đợt Infiltration cũng dùng IP này, nên 70 dòng `Infiltration` bị đè thành `Bot`, còn lớp Infiltration thì biến mất.

### Cách sửa

Tạo nhánh từ `main` vừa kéo về:

```powershell
git switch -c feature/eval-five-days
```

Chỉ đổi dòng **BENIGN**, không đè nhãn tấn công khác:

```python
if C2_IP in (str(src_ip).strip(), str(dst_ip).strip()) and label == BENIGN:
    label = "Bot"
```

### Hai chỗ cần kiểm tra thêm

Issue #74 chưa nhắc tới hai điểm sau, nhưng chúng làm sai số liệu của các ngày khác:

1. **IP này không chỉ là máy điều khiển botnet.** Theo mô tả của CIC-IDS2017, `205.174.165.73` là máy Kali của phía tấn công, dùng cho nhiều đợt khác nhau. Vì vậy nếu thứ Hai đến thứ Năm có dòng BENIGN với IP này, sau khi sửa ở trên chúng vẫn bị đổi thành `Bot`, mà ngày đó không hề có botnet. Cách kiểm tra: đọc nhãn từng ngày và xem dòng log `... dòng được sửa thành Bot`:
   ```powershell
   python -c "from tools.cic.labels import load_labels, find_label_files; from nids.logger import setup_logging; setup_logging('INFO'); load_labels(find_label_files(r'D:\Temp\Temp\TrafficLabelling_', 'thursday'))"
   ```
   Ngày nào ngoài thứ Sáu mà số này lớn hơn 0 thì nên chỉ áp dụng quy tắc sửa nhãn cho thứ Sáu (cho `load_labels` nhận thêm tham số `day`).
2. **`bot_hosts` trong `tools/cic/manifest.py`** (dòng 125) coi mọi IP nội bộ có flow với `205.174.165.73` là máy nhiễm Bot, không xét nhãn. Thứ Năm, máy bị Infiltration sẽ bị tính nhầm là máy Bot. Nên chỉ tính khoá flow có ít nhất một dòng nhãn `Bot`.

### Test

Thêm vào `tests/tools/test_cic_labels.py` (dùng CSV nhỏ tự tạo trong `tmp_path`, không đọc ổ D):

- dòng `Infiltration` có IP `205.174.165.73` giữ nguyên `Infiltration`;
- dòng `BENIGN` có IP đó vẫn thành `Bot` (thứ Sáu);
- nếu sửa `bot_hosts`: máy chỉ có flow Infiltration không nằm trong danh sách máy Bot.

### Xong khi

```powershell
pytest tests/tools -q
python -m tools.cic.manifest --split-dir D:\Tools\PBL4\split --labels-dir D:\Temp\Temp\TrafficLabelling_
git diff docs/eval/manifest.md        # phải không đổi gì
```

Manifest thứ Sáu không đổi chứng tỏ bản sửa không làm hỏng số liệu đã có.

---

## 5. Việc 2: manifest thứ Hai đến thứ Năm (#75, 1–1,5 giờ)

**Manifest** là danh sách cố định cho biết file pcap 10 phút nào để luyện (**dev**), file nào để thi (**test**). Thứ Sáu đã có; giờ làm cho 4 ngày còn lại.

### Bước 1: đếm tổng gói của file gốc

Manifest kiểm tra tổng gói của các chunk bằng file gốc, để chặn trường hợp thư mục có file trùng như lần trước. Đếm bằng `capinfos` (có sẵn trong Wireshark):

```powershell
foreach ($f in "Monday-WorkingHours","Tuesday-WorkingHours","Wednesday-workingHours","Thursday-WorkingHours") {
    & "C:\Program Files\Wireshark\capinfos.exe" -c -M "D:\Tools\PBL4\$f.pcap"
}
```

Ghi lại 4 số "Number of packets". Lệnh mất vài phút vì phải đọc hết từng file.

### Bước 2: chạy thử để xem nhãn rơi vào chunk nào

Chưa biết giờ test thì chạy một lần với giờ test giả `00:00`. Công cụ chỉ in cảnh báo "Giờ test không khớp chunk nào" và coi mọi chunk là dev. Ví dụ thứ Ba:

```powershell
python -m tools.cic.manifest --split-dir D:\Tools\PBL4\split\tuesday --labels-dir D:\Temp\Temp\TrafficLabelling_ --day tuesday --test-starts 00:00 --expect-packets <số của bước 1> --summary docs\eval\manifest-tuesday.md
```

**Chú ý `--summary`:** không truyền thì công cụ ghi đè `docs/eval/manifest.md` của thứ Sáu. File JSON tự ghi vào `data/cic/tuesday_manifest.json`.

Mở `docs/eval/manifest-tuesday.md`: mỗi dòng là một chunk, kèm số dòng nhãn của từng lớp tấn công trong chunk đó.

### Bước 3: chọn giờ test

Quy tắc (mục 8 của lộ trình): **phần sau của mỗi đợt tấn công + 1–2 chunk bình thường**. Lấy phần sau chứ không lấy ngẫu nhiên, để khi thi mô hình và rule gặp một đoạn tấn công chưa từng thấy lúc luyện.

| Ngày | Chunk bắt đầu lúc | Các đợt (giờ Canada) | Gợi ý chunk test |
| :--- | :--- | :--- | :--- |
| Thứ Hai | 08:55, 09:05, ... | không có tấn công | 2–3 chunk bình thường rải trong ngày (sáng, trưa, chiều) |
| Thứ Ba | 08:53, 09:03, ... | FTP 09:17–10:21; 10:30–10:31; SSH 14:09–15:12 | 2 chunk cuối đợt FTP, 2 chunk cuối đợt SSH, 1 chunk bình thường |
| Thứ Tư | 08:42, 08:52, ... | 09:01–09:02; DoS 09:48–10:38 và 10:43–11:20; 14:24–14:26; Heartbleed 15:12–15:33 | chunk cuối của mỗi đợt DoS chính, 1 chunk Heartbleed, 1 chunk bình thường |
| Thứ Năm | 08:58, 09:08, ... | Web 09:15–10:01 và 10:15–10:43; Infiltration buổi chiều | chunk cuối của mỗi đợt web, 1 chunk Infiltration, 1 chunk bình thường |

Chunk được chọn phải **thực sự chứa** lớp tấn công đó theo bảng ở bước 2. Đợt rất ngắn (vài phút) mà chỉ nằm trong 1 chunk thì để nó ở dev, vì không có "phần sau" để thi.

### Bước 4: chạy thật và ghi giờ test vào code

Chạy lại bước 2 với `--test-starts` là giờ đã chọn. Theo #75, sau đó đưa giờ test và tổng gói của 4 ngày vào `tools/cic/manifest.py` làm mặc định (giống `FRIDAY_TEST_STARTS`, `FRIDAY_PACKETS`), để người khác chạy không phải nhớ tham số. Thêm test: mỗi ngày có bộ mặc định, `--day tuesday` không cần `--test-starts` vẫn chạy được.

### Xong khi

Có 4 file `docs/eval/manifest-<ngày>.md`, tổng gói khớp file gốc, mỗi ngày có chunk test chứa mọi lớp tấn công của ngày đó, `pytest tests/tools -q` xanh.

---

## 6. Việc 3: đo phần so khớp tốn thời gian ở đâu (#77, 1,5–2 giờ)

### Vấn đề

Bảng thời gian của bộ đo chỉ có một dòng gộp "Rule + tái hợp TCP" (17,5% thời gian). Chưa biết trong đó rule nào, bước nào tốn nhất, nên chưa biết tăng tốc chỗ nào (#82, ngày 17/11).

**`cProfile`** là công cụ có sẵn của Python: chạy chương trình và ghi lại mỗi hàm được gọi bao nhiêu lần, tốn bao nhiêu giây.

### Bước 1: chạy bộ đo trên một chunk, trong một tiến trình

Chú ý hai điều: `cProfile` chỉ đo được tiến trình chính và thread chính. Vì vậy:

- **không** đo bằng `python -m nids.engine`, vì phần so khớp chạy trong worker thread;
- dùng bộ đo với `--jobs 1`: khi đó bộ đo chạy chunk ngay trong tiến trình chính, không tạo tiến trình con.

Trước khi đổi nhánh, phần sửa của việc 1–2 trên `feature/eval-five-days` phải được commit (hoặc `git stash`). Nếu không, các file đang sửa dở sẽ đi theo sang nhánh mới và hai việc bị trộn vào nhau.

```powershell
git switch main
git switch -c feature/rule-precision-cic
python -m cProfile -o data\eval\profile-1409.prof -m tools.eval.evaluate --labels-dir D:\Temp\Temp\TrafficLabelling_ --chunks 14:09 --jobs 1 --set-var HOME_NET=192.168.10.0/24 --name profile-1409 --report-dir data\eval\profile
```

`--report-dir data\eval\profile` để báo cáo của lượt đo thử này không lẫn vào `docs/eval/`. Chunk 14:09 chính là `chienbuoito.pcap`.

### Bước 2: đọc kết quả

```powershell
python -c "import pstats; s = pstats.Stats(r'data\eval\profile-1409.prof'); s.sort_stats('cumulative').print_stats('nids', 40)"
python -c "import pstats; s = pstats.Stats(r'data\eval\profile-1409.prof'); s.sort_stats('tottime').print_stats('nids', 30)"
```

- `cumulative`: thời gian của hàm **kể cả** các hàm nó gọi. Dùng để thấy tầng nào tốn (ví dụ toàn bộ `DetectionEngine.evaluate`).
- `tottime`: thời gian **chỉ riêng** thân hàm. Dùng để thấy chỗ thật sự làm chậm (ví dụ hàm so `content`, `pcre`).

Cần tách được các tầng của phễu: lọc theo protocol và cổng, Aho-Corasick, kiểm tra chi tiết (`content`, `pcre`, `flags`, `detection_filter`), bộ chặn (`ThresholdManager`), tái hợp TCP (`StreamReassembler`).

### Bước 3: đếm theo từng rule

`cProfile` chỉ cho biết theo hàm, không cho biết theo rule. Phần thứ hai của #77 là đếm cho **mỗi SID**: bao nhiêu lần được kiểm tra chi tiết (đã qua Aho-Corasick) và bao nhiêu lần khớp. Rule được kiểm tra rất nhiều mà gần như không khớp là ứng viên tăng tốc số một (thường là rule không có fast pattern, nên gói nào cũng phải kiểm tra). Phần này cần thêm bộ đếm vào code; hôm nay làm được bước 1–2 là đủ, bước 3 để sáng 12/11.

### Xong khi (cho hôm nay)

Có file `.prof` và một bảng nháp top 10 hàm tốn thời gian nhất, đủ để ngày mai viết `docs/eval/` cho #77.

---

## 7. Việc 4: baseline 4 ngày, chạy nền qua đêm

### Vì sao chạy hôm nay

Từ 13/11 bạn sẽ sửa rule. **Baseline** là con số *trước khi sửa*; sửa rule rồi mới đo thì mất mốc so sánh, giống lý do ở tuần 1. Chạy 4 ngày mất khoảng 1–2 giờ với 12 tiến trình, nên bật trước khi nghỉ là vừa.

### Lệnh

Ở nhánh `feature/eval-five-days` (đã có bản sửa nhãn của việc 1; phần engine và rule giống hệt `main`):

```powershell
git switch feature/eval-five-days
foreach ($d in "monday","tuesday","wednesday","thursday") {
    python -m tools.eval.evaluate --manifest data\cic\${d}_manifest.json --labels-dir D:\Temp\Temp\TrafficLabelling_ --set dev --set-var HOME_NET=192.168.10.0/24 --name baseline-$d
}
```

Kết quả: `docs/eval/baseline-<ngày>.md` và `data/eval/baseline-<ngày>.json`. Chỉ chạy `--set dev`: tập test để dành cho lần thi 24/11.

### Không được làm trong lúc nó chạy

Bộ đo **nạp lại rule ở mỗi chunk** (`tools/eval/runner.py`, hàm `run_chunk`). Nếu trong lúc chạy bạn sửa file trong `rules/` hay `nids/`, hoặc `git switch` sang nhánh khác, các chunk sau sẽ chạy bằng code khác và baseline bị trộn. Muốn làm tiếp việc khác thì dùng một worktree riêng:

```powershell
git worktree add ..\hybrid-nids-work feature/rule-precision-cic
```

rồi mở thư mục `..\hybrid-nids-work` mà làm.

### Xong khi

Sáng mai có 4 file `docs/eval/baseline-<ngày>.md`. Đây là đầu vào cho việc ngày 14/11 của người B: lập bảng rule web (thứ Năm), dò mật khẩu (thứ Ba), DoS (thứ Tư) bắt đúng bao nhiêu, nhầm bao nhiêu, sót đợt nào.

---

## 8. Việc 5: đọc trước cho ngày mai (30 phút, chỉ đọc)

Ngày 13/11 sửa rule 1000205 (UDP flood, `rules/dos.rules` dòng 10). Đọc trước để mai vào việc ngay:

- [danh-gia-bo-rule.md](danh-gia-bo-rule.md) mục 5.2: hướng sửa 4 rule báo nhầm.
- [eval/sau-sua-engine.md](eval/sau-sua-engine.md): 1000205 có 1.339 cảnh báo trên dev, 0 cảnh báo đúng.
- `.claude/rules/snort-rules.md`: luật viết rule của repo (bắt buộc đọc trước khi sửa rule). Nhớ luật: rule phải nạp sạch với cả ba giá trị `HOME_NET` (`any`, `172.28.0.0/16`, `192.168.10.0/24`), nên không dùng `!$HOME_NET`.

---

## 9. Hôm nay không làm

- **Không chạy tập test** (`--set test`, `--allow-test`). Chỉ thi 2 lần: 24/11 và 30/11.
- **Không sửa rule** khi baseline 4 ngày chưa chạy xong.
- **Không đụng AI**: đã dời sang 25/11.
- **Không commit hay push** khi chưa quyết định rõ; khi muốn đẩy code thì dùng `/ship` hoặc nhờ Claude, theo `.claude/rules/git-workflow.md`.

## 10. Kiểm tra cuối ngày

- [ ] `main` local đã kéo PR #96; `git status` sạch
- [ ] Đã chốt vai A/B (hoặc ghi rõ vẫn làm một mình)
- [ ] #74: `pytest tests/tools -q` xanh, `docs/eval/manifest.md` của thứ Sáu không đổi
- [ ] #75: có 4 file `docs/eval/manifest-<ngày>.md`, tổng gói khớp `capinfos`
- [ ] #77: có `data/eval/profile-1409.prof` và bảng nháp top hàm tốn thời gian
- [ ] Baseline 4 ngày đang chạy nền, không ai sửa code trong worktree đó
- [ ] Ghi kết quả vào nhật ký (ví dụ `docs/nhat-ky-ngay-3.md`) để làm số liệu báo cáo
