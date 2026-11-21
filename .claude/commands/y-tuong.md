---
description: Biến một ý tưởng thô thành bản phác thảo bao quát (10 góc nhìn) trong một file md tạm, một lượt hỏi, một lần chốt; chỉ xuất lưu chính thức khi người dùng yêu cầu.
argument-hint: <ý tưởng thô>
---

Ý tưởng: $ARGUMENTS

Quy tắc viết: @.claude/rules/planning.md

Làm đúng 3 bước dưới đây. Không chia thành nhiều luồng con, không gọi subagent phản biện. Bản phác thảo chỉ nằm trong **một file tạm** `.tmp/plans/<tên-ngắn>.md` (gitignore), không dán vào chat và không tạo file nào khác cho tới bước 3.

## Bước 1. Hiểu ý tưởng (tối đa một lượt hỏi)

1. Tự đọc phần hệ thống liên quan: code, quy tắc trong `.claude/rules/` của khu vực bị chạm, tài liệu trong `docs/`. Không hỏi những gì tự tìm được.
2. Nếu còn điều chỉ người dùng quyết được (vấn đề thật, kết quả mong muốn, phần không làm, ràng buộc như hạn nộp hay buổi demo), hỏi **một lượt duy nhất, tối đa 4 câu**, mỗi câu có phương án đề xuất.
3. Ý tưởng để trống thì hỏi ý tưởng. Ý tưởng đã đủ rõ thì bỏ qua bước này.

## Bước 2. Phác thảo bao quát (một file tạm)

Viết bản phác thảo vào `.tmp/plans/<tên-ngắn>.md`. Trong chat chỉ gửi đường dẫn file, tóm tắt 2–3 dòng và các quyết định cần chốt. Viết bằng **tác nhân**: sensor, honeypot SSH/HTTP, bộ chuyển hướng, dashboard, cơ sở dữ liệu, kênh realtime, người quản trị, kẻ tấn công, giảng viên xem demo. Mỗi góc nhìn chỉ vài dòng. Góc nào không liên quan thì ghi "không ảnh hưởng" rồi bỏ qua.

| # | Góc nhìn | Trả lời câu hỏi |
|---|---|---|
| 1 | Vấn đề và mục tiêu | Ai gặp vấn đề gì? Làm xong thì thấy gì khác (đo được)? Phần nào không làm? |
| 2 | Tác nhân và luồng hoạt động | Ai làm gì, theo thứ tự nào? Vẽ sơ đồ tuần tự (Mermaid) khi có từ 3 tác nhân trở lên |
| 3 | Dữ liệu | Cần quan sát hoặc lưu thêm gì? Có hợp nguyên tắc "DB chỉ lưu dữ liệu quan sát được và nhật ký hành động, rule chỉ nằm trong file" không? |
| 4 | Giao diện và giao tiếp | Người quản trị thấy và thao tác gì trên dashboard? Các process báo cho nhau thế nào (qua CSDL chung, file rule, tín hiệu realtime)? |
| 5 | Phát hiện | Dấu hiệu là gì? Lớp nào lo: rule, ngưỡng bất thường hay AI? Báo nhầm có thể đến từ đâu? |
| 6 | An toàn và độ bền | Dữ liệu từ kẻ tấn công có được xử lý an toàn không (honeypot không bao giờ thực thi)? Lỗi CSDL hoặc Redis có làm sập sensor không? Sensor có nguy cơ tự bắt traffic của chính hệ thống không? |
| 7 | Hiệu năng | Có chạm đường xử lý từng gói không? Có làm rớt gói hay chậm engine không? |
| 8 | Demo và kiểm chứng | Trình diễn trước giảng viên thế nào? Kiểm chứng bằng hành vi quan sát được; thêm số đo trên dữ liệu có nhãn nếu liên quan |
| 9 | Quyết định cần chốt và rủi ro | Mỗi quyết định kèm **đề xuất** và lý do; mỗi rủi ro kèm cách giảm |
| 10 | Các bước làm | Chia thành phần giao được độc lập (mỗi phần một pull request), ước lượng nhỏ, vừa hoặc lớn |

Kết thúc bước 2 bằng **lần chốt duy nhất**: người dùng chốt các quyết định ở góc nhìn 9, rồi duyệt hoặc góp ý. Có góp ý thì **sửa ngay trong cùng file đó** (không tạo bản mới) và ghi quyết định đã chốt vào file; không quay lại bước 1.

## Bước 3. Chốt và chọn đầu ra

Sau khi người dùng duyệt, hỏi đúng một câu: có xuất lưu chính thức không?

- **Không** (mặc định): file tạm vẫn nằm trong `.tmp/plans/`.
- **Lưu thành tài liệu** trong `docs/`, theo cấu trúc ở `docs/README.md`.
- **Tạo issue** GitHub (nội dung tiếng Việt, gửi lên chỉ khi người dùng chọn).

Sau đó, nếu người dùng muốn thì bắt đầu làm theo góc nhìn 10. Commit và push vẫn theo `.claude/rules/git-workflow.md`.
