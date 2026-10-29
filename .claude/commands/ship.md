---
description: Commit thay đổi hiện tại lên nhánh riêng, push và tạo pull request vào main theo đúng quy ước của repo.
argument-hint: [số issue, ví dụ 52] [ghi chú thêm]
---

Yêu cầu: $ARGUMENTS

Quy ước bắt buộc: @.claude/rules/git-workflow.md

Người dùng gọi lệnh này nghĩa là đã cho phép commit, push và tạo PR cho thay đổi hiện tại (chỉ lần này). Làm theo đúng mục "Trình tự khi người dùng yêu cầu commit/đẩy code" trong file trên:

1. Xem `git status`, `git diff` và nhánh hiện tại. Đang ở `main` thì tạo nhánh `<loại>/<mô-tả-ngắn>` phù hợp với nội dung thay đổi.
2. Lấy số issue từ `$ARGUMENTS` hoặc tên nhánh. Không có thì hỏi người dùng có issue không; không bịa số.
3. Chạy `pytest`. Fail thì dừng và báo lỗi.
4. Stage từng file liên quan, chia commit nếu thay đổi gồm nhiều việc độc lập. Commit message tiếng Anh, Conventional Commits, tag issue.
5. `git push -u origin <branch>`, rồi `gh pr create --base main`: tiêu đề tiếng Anh, mô tả tiếng Việt (Tóm tắt, Lý do, Cách kiểm thử, `Closes #<số>`).
6. Báo lại tên nhánh, các commit đã tạo và link PR. Không merge PR.
