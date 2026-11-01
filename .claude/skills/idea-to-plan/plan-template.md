---
type: PLAN
plan_id: PLAN-{{NNN}}
title: {{PLAN_TITLE}}
status: DRAFT
issue: {{ISSUE_NUMBER_OR_NONE}}
owner: {{OWNER}}
created: {{YYYY-MM-DD}}
updated: {{YYYY-MM-DD}}
---

# PLAN-{{NNN}}: {{PLAN_TITLE}}

## 1. Bối cảnh

{{Vấn đề hiện tại, vì sao cần làm bây giờ, yêu cầu đến từ đâu (issue, người dùng, giảng viên).}}

## 2. Mục tiêu và tiêu chí thành công

- **Mục tiêu**: {{GOAL}}
- **Xong khi**: {{Kết quả quan sát được, đo được, không phải "code xong"}}

## 3. Phạm vi

- **Trong phạm vi**: {{IN_SCOPE}}
- **Ngoài phạm vi**: {{OUT_OF_SCOPE}}

## 4. Hiện trạng

{{Luồng code liên quan, kèm `file:dòng`. Những gì đã có và dùng lại được.}}

## 5. Các phương án đã cân nhắc

| Phương án | Ưu điểm | Nhược điểm | Kết luận |
| :-------- | :------ | :--------- | :------- |
| {{OPTION_A}} | {{PROS}} | {{CONS}} | Chọn / Loại, vì {{REASON}} |
| {{OPTION_B}} | {{PROS}} | {{CONS}} | Chọn / Loại, vì {{REASON}} |

## 6. Thiết kế đã chọn

{{Luồng dữ liệu, thành phần, các quyết định chính và lý do. Dùng sơ đồ nếu giúp dễ hiểu hơn.}}

## 7. Thay đổi cần làm

| File | Thay đổi | Dùng lại |
| :--- | :------- | :------- |
| `{{PATH}}` | {{CHANGE}} | `{{EXISTING_FUNCTION}}` |

Tài liệu cần cập nhật: {{`CLAUDE.md`, `.claude/rules/...`, `README.md` nếu bị ảnh hưởng}}

## 8. Kiểm thử

| Test | Kiểm tra điều gì |
| :--- | :--------------- |
| `{{TEST_PATH}}` | {{Trường hợp thành công, lỗi và biên}} |

Lệnh: `pytest {{PATH}}`

## 9. Xác minh end-to-end

1. {{Lệnh chạy thật và kết quả mong đợi}}
2. {{Trường hợp lỗi cần thử trên hệ thống thật}}

## 10. Rủi ro và ảnh hưởng tới nhóm

| Rủi ro | Mức độ | Cách xử lý |
| :----- | :----- | :--------- |
| {{RISK}} | Cao / Vừa / Thấp | {{MITIGATION}} |

**Thành viên khác cần làm gì**: {{Sửa `.env`, build lại image, sửa `settings.yaml`, migrate dữ liệu; không có thì ghi "Không"}}

## 11. Các bước thực hiện

Nhánh: `{{loại}}/{{số-issue}}-{{mô-tả-ngắn}}`

- [ ] {{Bước 1, nhỏ và kiểm tra được}}
- [ ] {{Bước 2}}
- [ ] Chạy `pytest`, xác minh theo mục 9
- [ ] Tạo PR, cập nhật bảng tổng hợp

## 12. Quyết định và nhật ký

**Quyết định**

| Ngày | Quyết định | Người chốt | Lý do |
| :--- | :--------- | :--------- | :---- |
| {{YYYY-MM-DD}} | {{DECISION}} | Người dùng / Claude | {{REASON}} |

**Câu hỏi còn mở**: {{OPEN_QUESTIONS hoặc "Không"}}

**Kết quả phản biện**: {{Kết luận của `plan-critic`, các `WARNING` giữ lại và lý do}}
