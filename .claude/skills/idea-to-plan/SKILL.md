---
name: idea-to-plan
description: Dùng khi người dùng có ý tưởng, tính năng hoặc issue cần lên plan trước khi code, hoặc khi thay đổi thuộc diện cần plan theo .claude/rules/planning.md.
argument-hint: <ý tưởng hoặc số issue>
---

Yêu cầu: $ARGUMENTS

Làm lần lượt 7 bước trong `.claude/rules/planning.md`, không bỏ bước. Ý tưởng để trống thì hỏi người dùng trước.

## 1. Làm rõ ý tưởng

Tóm lại ý tưởng trong 2–3 câu: vấn đề gì, ai cần, xong thì thấy gì. Yêu cầu đã rõ thì ghi lại rồi đi tiếp. Còn thiếu điều làm thay đổi thứ sẽ xây thì hỏi từng câu một.

## 2. Khảo sát

- Có số issue thì đọc bằng `gh issue view <số> --json title,body,assignees,labels,comments`. Issue assign cho người khác thì báo người dùng.
- Xem `docs/plans/README.md` để tránh trùng plan đang chạy.
- Đọc code sẽ bị chạm và `.claude/rules/` của khu vực đó. Ghi lại các hàm dùng lại được kèm `file:dòng`.
- Liệt kê mọi nơi thay đổi phải chạm tới: nơi gọi, test, cấu hình, Docker, tài liệu.

## 3. Chọn phương án

Đưa ra 2–3 phương án khác nhau thật sự, kèm chi phí và rủi ro của từng cái, rồi nêu phương án khuyến nghị. Quyết định nào đổi thứ sẽ xây mà chỉ người dùng quyết được thì hỏi bằng `AskUserQuestion`. Quyết định còn lại tự chốt và ghi vào mục 12 là quyết định của Claude.

## 4. Viết plan

1. Lấy ID kế tiếp từ `docs/plans/README.md`: `PLAN-NNN` lớn nhất cộng 1, bắt đầu từ `PLAN-001`.
2. Sao chép `.claude/skills/idea-to-plan/plan-template.md` thành `docs/plans/YYYY-MM-DD-<slug>.md`. `slug` tiếng Anh, chữ thường, nối bằng `-`, 2–4 từ.
3. Điền đủ 12 mục. Mục không áp dụng thì ghi `Không áp dụng` kèm lý do, không xoá mục.
4. Thêm một dòng vào bảng trong `docs/plans/README.md` với trạng thái `DRAFT`.

## 5. Phản biện

Gọi subagent `plan-critic`, truyền đường dẫn file plan. Nếu subagent chưa có trong phiên này, tự đọc `.claude/agents/plan-critic.md` rồi rà plan theo đúng danh sách đó và nói rõ với người dùng rằng phản biện chưa độc lập.

Sửa mọi lỗi `BLOCKER`. Lỗi `WARNING` thì sửa, hoặc ghi lý do giữ nguyên vào mục 12. Kết luận `BLOCK` thì sửa xong gọi lại, tối đa 2 vòng; vẫn `BLOCK` thì dừng và báo người dùng. Qua được thì chuyển sang `REVIEW`.

## 6. Duyệt

Gửi người dùng: đường dẫn plan, tóm tắt 3–5 dòng, các quyết định Claude đã tự chốt, kết luận của `plan-critic` và các lỗi `WARNING` còn giữ. Người dùng duyệt rõ ràng thì chuyển sang `APPROVED`. Có yêu cầu sửa thì quay lại bước 4.

Skill dừng ở đây. Không code trong lượt này trừ khi người dùng yêu cầu.

## 7. Thực hiện và đóng

Khi người dùng cho bắt đầu: chuyển `IN_PROGRESS`, tạo nhánh theo `.claude/rules/git-workflow.md`, làm theo mục 11 và tick từng bước. Xác minh theo mục 8 và 9. Sau khi PR merge thì chuyển `DONE` và điền link PR vào bảng tổng hợp.
