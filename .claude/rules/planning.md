# Viết plan và lên ý tưởng

File này không có `paths:` nên luôn được nạp. Áp dụng cho mọi plan: plan trong hội thoại, plan mode của Claude Code và lệnh `/y-tuong`.

## Quy tắc viết

- **Nói bằng tác nhân và vai trò, không nói bằng code.** Hạn chế tên biến, tên hàm, class, đường dẫn file và đoạn code. Ví dụ, viết "sensor gom gói thành flow rồi gửi cho bộ phân tích AI", không viết tên hàm hay tên class.
- **Tác nhân thường dùng:** sensor (engine bắt và phân tích gói), honeypot SSH/HTTP, bộ chuyển hướng, dashboard, cơ sở dữ liệu, kênh realtime, người quản trị, kẻ tấn công, giảng viên xem demo.
- **Được nêu tên kỹ thuật khi không có cách gọi khác** và người đọc cần nó để quyết định, ví dụ tên công nghệ (Redis, iptables, Random Forest) hoặc tên bảng dữ liệu. Vẫn gọi theo vai trò trước. Nếu thật sự cần danh sách file thì để ở một phụ lục ngắn cuối plan.
- **Đi từ ý tưởng thô:** vấn đề trước, giải pháp sau, chi tiết hiện thực để lúc code.
- **Gọn:** mỗi quyết định cần người dùng chốt phải kèm phương án đề xuất. Không liệt kê phương án mà không định chọn.

## Nơi viết plan

- **Mọi plan viết vào file md tạm** `.tmp/plans/<tên-ngắn>.md` (thư mục bị gitignore). `tên-ngắn` là tiếng Anh, chữ thường, nối bằng `-`, ví dụ `microservice-restructure.md`.
- **Không dán nội dung plan vào chat.** Trong chat chỉ gửi: đường dẫn file, tóm tắt 2–3 dòng, và các quyết định cần chốt (kèm đề xuất).
- **Một plan, một file.** Khi người dùng góp ý hoặc chốt quyết định thì sửa ngay trong file đó. Không tạo file mới, bản v2 hay bản sao. Plan khác chủ đề thì mới tạo file khác.
- **Ghi lại quyết định đã chốt** ngay trong file (đánh dấu "đã chốt"), để file luôn là bản mới nhất.
- **Xuất lưu chính thức chỉ khi người dùng yêu cầu:** chép vào `docs/` (theo cấu trúc ở `docs/README.md`), hoặc tạo issue GitHub. Ngoài thư mục tạm, không tự tạo file plan, đặc tả hay manifest nào khác.
- **Plan mode của Claude Code:** viết vào file plan do harness chỉ định như bình thường, theo đúng quy tắc viết ở trên. Thoát plan mode thì chép sang `.tmp/plans/` nếu người dùng muốn giữ.

Quy tắc này ghi đè thói quen liệt kê file, hàm và dòng code trong plan, kể cả hướng dẫn mặc định của plan mode.

## Lên ý tưởng mới

Ý tưởng hoặc tính năng mới cần nhìn bao quát thì dùng `/y-tuong <ý tưởng thô>`. Lệnh này có 3 bước:

1. hỏi tối đa một lượt;
2. viết bản phác thảo theo 10 góc nhìn vào file tạm;
3. chốt một lần, rồi hỏi có xuất lưu chính thức hay không.
