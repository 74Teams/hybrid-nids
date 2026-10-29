# Quy trình commit, branch và pull request

File này không có `paths:` nên luôn được nạp. Áp dụng cho mọi thao tác git/GitHub trong repo `74Teams` này.

## Nguyên tắc bắt buộc

- KHÔNG `git commit` / `git push` khi người dùng chưa cho phép rõ ràng trong lượt hiện tại. Được phép một lần không có nghĩa là được phép cho lần sau.
- KHÔNG commit hay push thẳng lên `main`, không merge vào `main` ở local. Mọi thay đổi vào `main` đều đi qua pull request.
- KHÔNG `push --force` lên nhánh đã có người khác dùng; nếu buộc phải ghi đè nhánh của chính mình thì dùng `--force-with-lease` và hỏi trước.
- KHÔNG bỏ qua hook (`--no-verify`) và không thêm dòng `Co-Authored-By` / "Generated with Claude".

## Đặt tên branch

Dạng `<loại>/<mô-tả-ngắn>`: chữ thường, tiếng Anh, nối bằng dấu `-`, 2–4 từ, nói đúng mục đích. Có issue thì thêm số issue vào đầu phần mô tả.

| Loại | Dùng khi | Ví dụ |
|------|----------|-------|
| `feature/` | Tính năng mới | `feature/rule-management`, `feature/52-ai-flow-worker` |
| `bugfix/` | Sửa lỗi | `bugfix/honeypot-test-error` |
| `refactor/` | Đổi cấu trúc, không đổi hành vi | `refactor/nids-package` |
| `docs/` | Chỉ tài liệu | `docs/update-readme-and-plans` |
| `ci/` | GitHub Actions, pipeline | `ci/pytest-actions` |
| `chore/` | Dọn dẹp, dependency, cấu hình | `chore/bump-scapy` |
| `test/` | Chỉ thêm hoặc sửa test | `test/threshold-edge-cases` |

Tên sai: `fix`, `my-branch`, `feature/Update_Rules`, `feature/them-rule-moi` (tiếng Việt), `feature/add-new-rules-and-fix-dashboard-and-docs` (gộp nhiều việc).

## Commit message

Viết **tiếng Anh**, theo Conventional Commits:

```
<type>(<scope>): <summary> (#<issue>)

<body: vì sao thay đổi, không bắt buộc>

Closes #<issue>
```

- `type`: `feat`, `fix`, `refactor`, `docs`, `test`, `ci`, `chore`, `perf`.
- `scope` (không bắt buộc) theo khu vực code: `engine`, `api`, `web`, `honeypot`, `db`, `rules`, `lab`, `docker`, `ai`, `logging`.
- `summary`: thể mệnh lệnh (`add`, không phải `added`/`adds`), chữ thường ở đầu, không chấm cuối, tối đa ~72 ký tự.
- **Tag issue:** có issue liên quan thì ghi `(#<số>)` cuối dòng tiêu đề; nếu commit đóng issue thì thêm footer `Closes #<số>` (hoặc `Fixes #<số>` cho bug). Nhiều issue: `(#44, #45)`. Không có issue thì bỏ, không bịa số.
- Mỗi commit làm một việc. Không trộn sửa lỗi với refactor hoặc đổi format.

Ví dụ đúng:

```
feat(engine): split rules by category with per-SID overrides (#44, #45)
fix(honeypot): keep sensor running when DB write fails

Closes #51
docs: update CLAUDE.md for multi-file rules
```

Ví dụ sai: `cập nhật rule` (tiếng Việt), `fix bug`, `Update files.`, `feat: Added dashboard` (không mệnh lệnh, viết hoa).

## Pull request

- Tạo bằng `gh pr create --base main --head <branch>`. Tiêu đề PR theo cùng dạng với commit message (tiếng Anh, Conventional Commits, kèm `(#issue)` nếu có).
- **Mô tả PR viết tiếng Việt có dấu**, gồm: Tóm tắt thay đổi, Lý do, Cách kiểm thử (lệnh đã chạy và kết quả), và `Closes #<số>` ở cuối nếu PR đóng issue.
- CI (`.github/workflows/tests.yml`) chạy pytest cho mỗi PR vào `main`; PR chỉ merge khi CI xanh.
- Không tự merge PR; để người dùng hoặc thành viên nhóm review và merge.

## Trình tự khi người dùng yêu cầu commit/đẩy code

1. `git status` và `git branch --show-current`. Nếu đang ở `main`: tạo nhánh mới theo quy tắc trên (`git switch -c <loại>/<mô-tả>`) trước khi commit.
2. Hỏi hoặc xác định số issue liên quan (xem tên nhánh, `gh issue list`). Không đoán.
3. Chạy `pytest`. Test fail thì báo người dùng, không commit.
4. `git add` từng file cụ thể (không `git add -A` mù), kiểm tra không có `.env`, `*.db`, `data/`, `rules/state.yaml`, file pcap lớn.
5. Commit theo định dạng trên.
6. `git push -u origin <branch>`.
7. `gh pr create --base main` với tiêu đề tiếng Anh và mô tả tiếng Việt; gửi link PR cho người dùng.
