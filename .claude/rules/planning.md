# Quy trình lên plan

File này không có `paths:` nên luôn được nạp. Plan chính thức nằm trong `docs/plans/`, bảng tổng hợp ở `docs/plans/README.md`. Cách làm chi tiết từng bước nằm trong skill `idea-to-plan` (`/idea-to-plan <ý tưởng>`).

## Khi nào cần plan

Cần plan khi có ít nhất một điều sau:

- Người dùng yêu cầu lên plan hoặc gọi `/idea-to-plan`.
- Thay đổi chạm từ hai khu vực trở lên trong số: engine, api/web, honeypot, db, docker/config, lab.
- Thêm service, dependency, bảng hoặc cột CSDL, hay biến môi trường bắt buộc.

Trường hợp còn lại làm thẳng theo quy trình thường. Thêm rule phát hiện dùng `/them-rule`.

## Quy trình 7 bước

| # | Bước | Xong khi |
|---|------|----------|
| 1 | Làm rõ ý tưởng | Đã biết vấn đề cần giải quyết, kết quả mong muốn và phần không làm |
| 2 | Khảo sát | Đã đọc code liên quan, issue, plan cũ và `.claude/rules/` của khu vực bị chạm |
| 3 | Chọn phương án | Người dùng đã chốt các quyết định chỉ họ mới quyết được |
| 4 | Viết plan | File plan có đủ 12 mục, trạng thái `DRAFT`, đã có dòng trong bảng tổng hợp |
| 5 | Phản biện | `plan-critic` đã đọc plan, mọi lỗi `BLOCKER` đã sửa, trạng thái `REVIEW` |
| 6 | Duyệt | Người dùng duyệt rõ ràng, trạng thái `APPROVED` |
| 7 | Thực hiện và đóng | Code xong theo plan, kiểm thử đạt, PR đã merge, trạng thái `DONE` |

Chưa tới `APPROVED` thì không sửa code, trừ file plan và bảng tổng hợp.

## Vòng đời plan

```
DRAFT → REVIEW → APPROVED → IN_PROGRESS → DONE
          │                      │
          └── cần sửa → DRAFT    └── đổi thiết kế → REVIEW

Plan chưa DONE có thể chuyển sang DROPPED hoặc SUPERSEDED.
```

| Trạng thái | Ý nghĩa |
|------------|---------|
| `DRAFT` | Đang viết hoặc đang sửa |
| `REVIEW` | Đã qua `plan-critic`, chờ người dùng duyệt |
| `APPROVED` | Người dùng đã duyệt, chưa bắt đầu code |
| `IN_PROGRESS` | Đang code trên nhánh riêng |
| `DONE` | PR đã merge và đã xác minh theo mục 9 của plan |
| `DROPPED` | Bỏ không làm; ghi lý do ở mục 12 |
| `SUPERSEDED` | Bị plan khác thay thế; ghi ID plan mới ở mục 12 |

Mỗi lần đổi trạng thái, cập nhật cùng lúc `status` và `updated` trong frontmatter, và dòng tương ứng ở `docs/plans/README.md`. Không xoá plan cũ.

## Quy tắc đi kèm

- Đang ở plan mode thì chỉ sửa được file plan tạm của harness. Viết plan vào đó trước, khi thoát plan mode mới chép sang `docs/plans/`.
- Commit file plan tuân theo `.claude/rules/git-workflow.md`, không tự commit.
- Issue đang assign cho người khác thì báo người dùng ở bước 2, trước khi viết plan.
