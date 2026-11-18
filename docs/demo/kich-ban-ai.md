# Kịch bản trình bày phần AI của Hybrid NIDS

Thời lượng gợi ý: **8–10 phút** (3 phút nói, 3 phút demo, còn lại hỏi đáp). Kịch bản dành cho người trình bày; người nghe là giảng viên, chưa cần biết học máy. Nối tiếp [kich-ban-demo.md](kich-ban-demo.md), chèn sau bước 7b ("tấn công chưa có rule").

## 0. Ba ý phải nhớ

Nếu thầy chỉ nhớ ba câu, hãy là ba câu này:

1. **Rule (Snort) bắt thứ đã biết mặt, AI bắt thứ có dáng điệu lạ.** Hai thứ bổ sung nhau, nên hệ thống gọi là *hybrid*.
2. **AI nhìn hành vi của cả một chuỗi kết nối, không nhìn từng gói.** Ví dụ quét cổng: từng kết nối một đều vô hại, chỉ khi thấy một máy gõ hàng trăm cổng trong vài giây mới biết là quét.
3. **Con số trung thực.** Nhóm đo trên dữ liệu chưa học, chạy hai lần ra đúng một kết quả, chưa đụng tập thi, và nói rõ chỗ nào còn yếu.

## 1. Chuẩn bị trước giờ trình bày

Làm từ hôm trước, chỉ cần máy chạy Python (không cần Docker cho phần này):

```powershell
pip install -r requirements.txt                       # nếu chưa cài
python -m tools.ai.demo_ai --scenario scan            # chạy thử một lần, mất khoảng 10 giây
```

- Cần có file `models/flow_model.joblib` (2,9 MB, đã được lưu cùng mã nguồn). Thiếu thì học lại: `python -m tools.ai.train --features-dir data/ai/features-v3` (khoảng 7 phút, cần dataset trong `data/`).
- Mở sẵn một cửa sổ terminal cỡ chữ lớn. Chạy thử trước để chắc có kết quả như mục 5.
- Mở sẵn file [docs/ai/ket-qua-danh-gia.md](../ai/ket-qua-danh-gia.md) để tra số khi thầy hỏi.

## 2. Trình tự

| Phút | Phần | Nói gì (tóm tắt) |
|---|---|---|
| 0:00 | 1. Vấn đề | Rule chỉ bắt thứ đã có chữ ký |
| 1:00 | 2. AI làm gì | Gói tin thành flow, thành 40 con số, thành nhãn |
| 3:00 | 3. Câu chuyện quét cổng | Vì sao phải nhìn nhiều flow; điểm số tăng dần |
| 5:00 | 4. Demo | Ba lệnh chạy thật |
| 8:00 | 5. Hybrid và thành thật | AI không thay Snort; còn gì chưa làm |
| 9:00 | 6. Hỏi đáp | Xem mục 7 |

## 3. Lời thoại từng phần

### Phần 1. Vấn đề (1 phút)

> "Phần rule của nhóm giống như một **danh sách người bị truy nã**: thấy đúng mặt trong danh sách thì báo. Rất chính xác, nhưng kẻ tấn công đổi một chút là lọt. Nên nhóm thêm một lớp thứ hai: **nhìn dáng đi**. Không cần biết kẻ đó là ai, chỉ cần thấy hành vi khác thường thì báo. Đó là phần AI."

### Phần 2. AI làm gì (2 phút)

Vẽ hoặc chiếu sơ đồ này:

```
 Gói tin ──▶ Gom thành FLOW ──▶ Tính 40 con số ──▶ Random Forest ──▶ Nhãn
 (từng gói)   (một kết nối)    (độ dài, nhịp, cờ,    (100 cây quyết    BENIGN, PortScan,
                                số cổng đã gõ...)     định bỏ phiếu)    DoS, DDoS, Bot,
                                                                         BruteForce
```

Giải thích bằng lời, theo thứ tự:

- **Flow** là một cuộc "nói chuyện" giữa hai máy: từ lúc bắt tay đến lúc đóng kết nối, gom mọi gói vào một dòng. Engine đã gom flow sẵn cho trang Traffic nên AI dùng lại.
- **40 con số** mô tả cuộc nói chuyện đó: bao nhiêu gói, to hay nhỏ, nhanh hay chậm, bao nhiêu cờ SYN/RST, và một máy đã gõ bao nhiêu cổng khác nhau trong vài giây qua. Không dùng địa chỉ IP, để mô hình không học thuộc "máy này là xấu".
- **Random Forest** (rừng ngẫu nhiên): hình dung 100 chuyên gia, mỗi người hỏi một chuỗi câu có/không ("gói đầu có to không? số cổng đã gõ có nhiều không?") rồi **bỏ phiếu**. Đa số phiếu quyết định nhãn. Ưu điểm: nhỏ (2,9 MB), nhanh, và cho biết cột nào quan trọng, không phải "hộp đen".
- **Học từ đâu:** bộ dữ liệu công khai CIC-IDS2017 (5 ngày lưu lượng thật của một phòng thí nghiệm, đã gắn nhãn tấn công). Nhóm dùng khoảng **1,3 triệu flow** để học và chấm.
- **Phân công với Snort:** AI lo các loại tấn công có *dáng* rõ (quét cổng, DoS, DDoS, botnet, dò mật khẩu). Tấn công web (SQL injection, XSS) khác thường ở **nội dung** chứ không ở dáng, nên để rule Snort lo; AI bỏ lớp này vì chỉ đạt precision khoảng 0,6.

### Phần 3. Câu chuyện quét cổng (2 phút)

Đây là phần hay nhất, kể như một câu chuyện nhỏ:

> "Quét cổng là kẻ tấn công **gõ cửa từng cổng** xem cổng nào mở. Mỗi lần gõ chỉ là hai gói: SYN đi, RST về. Vấn đề: một người dùng bình thường gõ nhầm cổng cũng sinh đúng hai gói đó. **Nhìn từng flow riêng thì kẻ quét và người gõ nhầm giống hệt nhau.** Lần đầu, AI nhận ra kẻ quét chỉ khoảng 59%."

Rồi kể ba bước sửa, mỗi bước có đo:

| Bước | Việc làm | Phát hiện quét cổng (recall) |
|---|---|---|
| Ban đầu | Chỉ nhìn từng flow | khoảng 0,59 (0,74 khi chấm trung thực hơn) |
| 1 | Thêm đặc trưng "máy này đã gõ bao nhiêu cổng khác nhau trong 60 giây qua" | 0,87 |
| 2 | Mở các flow còn lọt ra xem: tất cả nằm ở **20 giây đầu** của đợt quét, vì bộ đếm 60 giây chưa kịp đầy. Thêm đặc trưng cùng ý nhưng chỉ nhìn **5 giây gần nhất** và bỏ hai cột bị "mù" ở đầu đợt | **0,92** |

> "Bài học nhóm rút ra: **không đoán, mà mở dữ liệu ra xem lỗi nằm ở đâu**. Lỗi không ở mô hình, mà ở thông tin ta đưa cho nó."

### Phần 4. Đo có trung thực không (đưa vào một câu hoặc một slide)

- **Chia theo thời gian, không chia ngẫu nhiên:** dữ liệu được cắt thành khối 5 phút; khối nào dùng để chấm thì mô hình **chưa từng thấy**. Chia ngẫu nhiên sẽ cho điểm cao giả, vì các flow sát nhau trong một đợt tấn công rất giống nhau.
- **Chấm 4 lần với 4 cách chia**, gộp lại tính một lần, để một lần chia "may mắn" không quyết định kết luận.
- **Chạy hai lần ra đúng một kết quả** (hai file mô hình giống từng byte).
- **Tập dùng để thi cuối chưa mở.** Sẽ mở đúng một lần, khi chốt mọi thứ.

## 4. Kết quả nên đưa lên màn hình

Bảng ngắn, đủ cho người không chuyên đọc được:

| Nhìn gì | Kết quả | Nghĩa là |
|---|---|---|
| Báo nhầm (FPR) | **0,13%** | Cứ khoảng 800 kết nối bình thường mới có 1 cái bị báo nhầm |
| Quét cổng | **0,92** | Trong 100 kết nối quét, bắt được khoảng 92 |
| DDoS | **0,99** | bắt được khoảng 99 trên 100 |
| Botnet (Bot) | **0,999** | gần như đủ |
| Dò mật khẩu (BruteForce) | **0,996** | gần như đủ |
| DoS | **0,97** | trong đó công cụ DoS không phải Hulk: 0,80 |
| Điểm tổng (macro F1) | **0,986** | thang 0 đến 1; hơn 0,9 là tốt |

*(Số đo trên validation của tập dev; chi tiết ở [ket-qua-danh-gia.md](../ai/ket-qua-danh-gia.md).)*

## 5. Demo (3 phút)

Mô hình chưa nằm trong engine (xem phần thành thật), nên demo chạy một script đưa lưu lượng **qua đúng chuỗi xử lý của engine** rồi gọi mô hình. Lưu lượng là **giả lập bằng code**: một kẻ quét gõ khoảng 1.000 cổng, trong lúc 3 người dùng duyệt web và một người gõ nhầm cổng. Mô hình **chưa từng thấy** chuỗi gói này.

### Demo 1. Quét cổng bị bắt, người thường không bị báo nhầm

```powershell
python -m tools.ai.demo_ai --scenario scan
```

Kết quả chạy thật:

```
Máy               Số flow  Bị báo tấn công        Loại  Báo sau (giây)
172.16.0.1          16001            15980    PortScan             0.0
192.168.10.12          18                0           -               -
192.168.10.13          18                0           -               -
192.168.10.11          17                0           -               -
192.168.10.20           3                0           -               -

SO SÁNH: flow gõ nhầm cổng của 192.168.10.20 và flow quét của 172.16.0.1 đều là 'SYN rồi RST, 60 byte'.
  người gõ nhầm: 0/3 flow bị báo | kẻ quét: 15980/16001 flow bị báo
```

Lời thoại:

> "Dòng đầu là kẻ quét: 16.000 flow, **bị báo gần hết**. Ba máy duyệt web: **không bị báo**. Quan trọng nhất là dòng cuối: người gõ nhầm cổng và kẻ quét sinh ra flow *giống hệt nhau*, nhưng AI **chỉ báo kẻ quét**, vì nó thấy kẻ quét gõ hàng trăm cổng trong vài giây còn người kia chỉ gõ ba lần."

Chỉ vào bảng theo từng 2 giây bên dưới: ngay giây đầu đã báo 99%, không có khoảng "mù" ở đầu đợt quét (đây chính là chỗ nhóm đã sửa ở phần 3).

### Demo 2. Quét chậm hơn nhiều vẫn bị bắt

```powershell
python -m tools.ai.demo_ai --scenario scan --slow 100
```

Kẻ quét chậm hơn 100 lần (còn khoảng 8 flow mỗi giây). Kết quả thật: **543/560 flow bị báo** (97%), người gõ nhầm vẫn 0/3.

> "Kẻ tấn công thường hạ tốc độ để trốn. Ở mức này AI vẫn bắt, vì nó đếm số cổng *khác nhau* chứ không đếm tốc độ."

### Demo 3. Chỉ ra giới hạn (nên làm, thầy đánh giá cao sự thật thà)

```powershell
python -m tools.ai.demo_ai --scenario scan --slow 1600
```

Quét còn **0,5 flow mỗi giây**: chỉ **10/35 flow bị báo**, và báo muộn (sau khoảng 10 giây). Kết quả thật của các mức tốc độ trong lưu lượng giả lập:

| Tốc độ kẻ quét | Flow bị báo |
|---|---|
| 800 flow/giây | 99,9% |
| 80 flow/giây (chậm 10 lần) | 99,7% |
| 8 flow/giây (chậm 100 lần) | 97% |
| 1 flow/giây | 90% |
| 0,5 flow/giây | **29%** |
| 0,2 flow/giây | **29%** |

> "Quét **rất chậm** (vài giây mới một lần) thì AI bắt kém. Đó là lý do hệ thống không chỉ có AI: lớp **phát hiện bất thường theo ngưỡng** trong engine đếm theo thời gian dài hơn, và rule vẫn chạy song song. Mỗi lớp che chỗ yếu của lớp kia."

### Demo 4 (tuỳ chọn, rất đáng làm nếu còn thời gian): dữ liệu thật

```powershell
python -m tools.ai.demo_ai --pcap D:\Tools\PBL4\split\friday\fri_00031_20170708000939.pcap --limit 300000
```

Đọc một đoạn pcap thật của CIC-IDS2017 (khoảng 107.000 gói, mất vài chục giây). Kết quả thật, rút gọn:

```
Máy               Số flow  Bị báo tấn công        Loại  Báo sau (giây)
192.168.10.19        1687                0           -               -
192.168.10.8         1499               36         Bot            29.2
192.168.10.3         1473                0           -               -
192.168.10.15         800               36         Bot            26.2
192.168.10.9          406               18         Bot            37.5
192.168.10.14         397               18         Bot            7.1
192.168.10.5          312               18         Bot            36.5
...
172.16.0.1            157              118    PortScan             0.0
```

Lời thoại:

> "Đây là lưu lượng thật của một phòng thí nghiệm: hàng chục máy làm việc bình thường, trong đó **5 máy bị nhiễm botnet** và một máy ngoài đang **quét cổng**. AI chỉ báo đúng 6 máy: 5 máy nhiễm botnet (`.5`, `.8`, `.9`, `.14`, `.15`, đúng với danh sách máy bot của bộ dữ liệu) và máy quét `172.16.0.1`. **Mười mấy máy còn lại không bị báo nhầm.**"

Điểm cộng nếu thầy hỏi sâu: hai máy `192.168.10.5` và `192.168.10.8` là hai máy bot nhóm **giữ riêng cho kỳ thi**: các flow Bot của chúng bị loại khỏi dữ liệu học, nên mô hình nhận ra chúng mà chưa từng học trên chúng.

**Cẩn thận khi nói:** chunk này nằm trong phần dữ liệu dùng để phát triển, nên đây là **minh hoạ**, không phải bằng chứng; bằng chứng là số đo ở mục 4 và kỳ thi cuối. Nên lấy Demo 1 và 2 làm chính.

## 6. Hybrid và phần thành thật (1 phút)

Nói rõ, đừng để thầy phải hỏi:

> "Về tình trạng: **mô hình đã huấn luyện, đo và lưu xong; chưa gắn vào engine chạy thời gian thực.** Demo vừa rồi chạy script ngoài engine. Bước còn lại là cho `AITrafficWorker` nạp mô hình, sinh cảnh báo loại `AI_ENGINE` hiện lên dashboard. Các ràng buộc kỹ thuật đã ghi sẵn để việc này làm được mà không sửa phần capture hay CSDL."

Những điều **chưa** làm hoặc **còn yếu**, nên chủ động nêu:

- Chưa gắn vào engine; chưa có cảnh báo AI trên dashboard.
- Chưa thi trên tập test (sẽ mở đúng một lần).
- Quét cực chậm và công cụ DoS lạ là điểm yếu (xem hỏi đáp).
- Dữ liệu CIC-IDS2017 là một môi trường cụ thể; chưa thử lại trên lab Docker của nhóm.

## 7. Hỏi đáp dự kiến

**Vì sao không dùng học sâu (deep learning)?**
Dữ liệu ở đây là bảng số, Random Forest làm tốt và nhẹ (2,9 MB, đoán nhanh), lại cho biết cột nào quan trọng nên giải thích được. Học sâu cần nhiều dữ liệu và tính toán hơn mà chưa chắc tốt hơn với dữ liệu dạng bảng.

**AI có thay được Snort không?**
Không, và nhóm không định thay. Tấn công web (SQL injection, XSS) khác ở nội dung; AI chỉ đạt precision khoảng 0,6 cho loại này nên nhóm bỏ nó cho Snort. Ngược lại Snort không nhìn được "một máy gõ hàng trăm cổng". Hai lớp bổ sung nhau.

**Làm sao biết không phải học thuộc lòng (overfitting)?**
Mỗi lần chấm, khối thời gian dùng để chấm không có trong phần học. Nhóm cũng chấm 4 cách chia khác nhau, chạy hai lần cho kết quả y hệt, và còn **một tập thi chưa mở**.

**Vì sao quét cổng chưa đạt 100%?**
Còn khoảng 8% flow quét không bị báo: chủ yếu là những giây đầu của đợt quét (chưa đủ dữ kiện để phân biệt) và dữ liệu học chỉ có một đợt quét lớn. Điều đáng nói hơn là *đợt quét có bị phát hiện không*: khi gom theo cặp máy trong mỗi khối 5 phút, cả 6 nhóm quét đều bị phát hiện.

**Báo nhầm 0,13% là nhiều hay ít?**
Cứ khoảng 800 kết nối bình thường mới có 1 cái bị báo nhầm. Ở mạng nhỏ là ít; ở mạng lớn vẫn thành nhiều cảnh báo, nên bước tích hợp sẽ **gộp cảnh báo theo cặp máy** để người trực không bị ngợp.

**Công cụ tấn công mới, mô hình chưa từng thấy thì sao?**
Đây là thí nghiệm nhóm đã làm: giấu hẳn một công cụ DoS khỏi dữ liệu học rồi đo. GoldenEye và Slowhttptest (hình dạng gần giống thứ đã học) vẫn nhận khoảng 0,67–0,71; slowloris (khác hẳn) chỉ 0,18. Kết luận: mô hình học *dạng flow*, không học tên công cụ; công cụ mới giống thứ đã thấy thì bắt được, khác hẳn thì dễ lọt.

**Kẻ tấn công biết mô hình thì né được không?**
Có thể, ví dụ quét thật chậm. Vì vậy AI chỉ là một lớp trong ba lớp (rule, ngưỡng bất thường, AI), không phải lớp duy nhất.

**Vì sao không dùng địa chỉ IP làm đặc trưng?**
Nếu dùng, mô hình học thuộc "địa chỉ này là kẻ tấn công" của bộ dữ liệu và sẽ vô dụng khi sang mạng khác. Đặc trưng chỉ mô tả *hành vi*.

**Số liệu 0,92 có phải là điểm cuối cùng?**
Không. Đó là điểm trên phần dữ liệu dùng để phát triển. Điểm cuối cùng là điểm trên tập thi, mở một lần ở mốc 30/11.

**Demo dùng lưu lượng giả lập thì có đáng tin không?**
Nó chứng minh mô hình **hoạt động đúng cơ chế** trên chuỗi gói mà nó chưa từng thấy. Nhưng lưu lượng giả lập sạch hơn thật nên **không thay** cho số đo trên dữ liệu thật ở mục 4. Nhóm nói rõ điều này.

## 8. Thuật ngữ (để tra nhanh)

| Từ | Nghĩa dễ hiểu |
|---|---|
| Flow | Một cuộc nói chuyện giữa hai máy, từ lúc mở đến lúc đóng kết nối, gom thành một dòng |
| Đặc trưng | Một con số mô tả flow (độ dài, nhịp, số cờ...) |
| Random Forest | 100 cây quyết định bỏ phiếu để chọn nhãn |
| Recall | Trong các kết nối tấn công thật, bắt được bao nhiêu phần |
| Precision | Trong các lần báo tấn công, đúng bao nhiêu phần |
| FPR | Trong các kết nối bình thường, bị báo nhầm bao nhiêu phần |
| macro F1 | Điểm tổng hợp trên mọi lớp, thang 0 đến 1 |
| Validation / test | Dữ liệu để chấm khi phát triển / dữ liệu để thi cuối, chỉ mở một lần |
| CIC-IDS2017 | Bộ dữ liệu công khai có lưu lượng thật và nhãn tấn công, dùng để học và chấm |

## 9. File liên quan

- Demo: `tools/ai/demo_ai.py` (test ở `tests/tools/test_demo_ai.py`).
- Mô hình: `models/flow_model.joblib`; đặc trưng: `nids/ai/features.py`, `nids/ai/context.py`.
- Học và chấm: `tools/ai/train.py`; kết quả đầy đủ: [docs/ai/ket-qua-danh-gia.md](../ai/ket-qua-danh-gia.md); kế hoạch: [PLAN-010](../plans/2026-11-15-ai-flow-model-tuning.md).
