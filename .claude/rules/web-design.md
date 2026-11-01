---
paths:
  - "nids/api/static/**"
---

# Thiết kế giao diện kiểu shadcn/ui (`nids/api/static/`)

Web console dùng phong cách shadcn/ui (bảng màu zinc, card viền mảnh, bo góc `0.5rem`, tab dạng pill) nhưng viết bằng **CSS thuần**. Nguồn duy nhất của style là `style.css`; ba trang `dashboard.html`, `logs.html`, `rules.html` chỉ dùng lại class có sẵn. Rule về endpoint và hành vi trang nằm ở `api-web.md`.

## Nguyên tắc

- Không thêm React, Tailwind, thư viện component, icon font hay Google Fonts. Lab chạy offline và frontend là HTML/CSS/JS thuần. Font dùng stack hệ thống (`ui-sans-serif, system-ui, ...`), code dùng `var(--mono)`.
- Chỉ giao diện sáng, không có dark mode.
- Không viết màu hex, `px` bo góc hay đổ bóng trực tiếp trong HTML/JS hay selector mới. Dùng biến ở `:root` của `style.css`; cần màu mới thì thêm biến, không thêm giá trị rời.
- Không dùng `style="..."` trong HTML trừ giá trị tính toán lúc chạy (độ rộng thanh `.bar > span`, `style.background` của ô màu chú giải). Ngoại lệ đã có: `max-width` của ô "Số dòng / trang" ở Logs.
- Ưu tiên tái dùng class đã có. Thêm class mới vào `style.css` khi không có class nào hợp, đặt trong đúng nhóm có comment (Header, Card, Bảng, Dashboard, Popup, Rules...).
- Nội dung do attacker kiểm soát (payload, lệnh, URI, tên IP) chỉ được đưa vào DOM bằng `textContent` (helper `el()`), không `innerHTML`.

## Token (`:root`)

| Biến | Giá trị | Dùng cho |
| :--- | :------ | :------- |
| `--background` / `--foreground` | `#fff` / `#09090b` | Nền trang, chữ chính |
| `--card` | `#fff` | Nền card, popup |
| `--muted` / `--muted-foreground` | `#f4f4f5` / `#71717a` | Nền tab, `<pre>`, `<code>`; chữ phụ |
| `--border` / `--input` | `#e4e4e7` | Viền card, bảng, ô nhập |
| `--ring` | `#a1a1aa` | Viền và vòng focus |
| `--primary` / `--primary-foreground` | `#18181b` / `#fafafa` | Nút chính (Apply, Save) |
| `--secondary` / `--accent` | `#f4f4f5` | Nút phụ, hover |
| `--destructive` | `#dc2626` | Nút xoá, lỗi |
| `--link` / `--blue` | `#2563eb` | Link, thanh `.bar`, trạng thái SID đã override |
| `--ok` | `#16a34a` | Đã kết nối, SID đang bật |
| `--p1` / `--p2` / `--p3` | `#dc2626` / `#ea580c` / `#ca8a04` | Priority, theo đúng thứ tự P1 nặng nhất |
| `--radius` | `0.5rem` | Card, popup; nút và ô nhập dùng `calc(var(--radius) - 2px)` |
| `--shadow-sm/md/lg` | | Card, popover/tooltip, popup |

Priority chỉ dùng ba màu `--p1..--p3`; không dùng chúng cho mục đích khác. Hai series biểu đồ (NIDS xanh, Honeypot cam) nằm trong `charts.js` vì SVG cần giá trị thật; đổi màu thì sửa cả `:root` lẫn đầu `charts.js` và kiểm tra độ tương phản trên nền trắng.

## Chữ và khoảng cách

- Chữ nền `14px/1.5`; bảng `13px`; chú thích và nhãn phụ `12–13px` màu `--muted-foreground`. Tiêu đề card `15px`, `font-weight: 600`, `letter-spacing: -.01em`. Số lớn ở tổng quan `30px`, `700`.
- Nhịp khoảng cách theo bội của 4px: card cách nhau `16px` (`main` dùng `gap: 16px`), padding card `16–20px`, ô bảng `10px 12px`.
- Chiều cao điều khiển: nút và ô nhập `36px`; nút trong bảng `28px`; nút phân trang `32px`.

## Ánh xạ component

| shadcn | Class trong repo | Ghi chú |
| :----- | :--------------- | :------ |
| Card | `.panel` + `.panel-head` (hoặc `h2`) + `.panel-body` | Đầu card có viền dưới; không dùng nền đậm |
| Button default | `.btn-primary` | Nền `--primary`, chữ sáng |
| Button outline | `button`, `.btn` (mặc định), `.btn-warning` | Viền `--input`; warning chữ cam |
| Button secondary | `.btn-success` | Nền xám nhạt, không viền (không dùng màu xanh lá cho nút) |
| Button destructive | `.btn-danger` | Chỉ cho thao tác xoá hoặc tắt hàng loạt |
| Button ghost | `.icon-btn`, `.panel-head .toggle` | Nền trong suốt, hover `--accent` |
| Input / Select / Textarea | `input`, `select`, `textarea` | Cao `36px`, vòng focus `--ring`; checkbox có style riêng `16px` |
| Tabs | `.tabs` (điều hướng giữa trang), `.subtabs` (trong popup) | Nền `--muted`, tab đang chọn có class `active` nền trắng và `--shadow-sm` |
| Table | `table` trong `.table-wrap` | Không kẻ sọc; hover nhẹ; tiêu đề cột `12px` màu `--muted-foreground` |
| Badge | `.tag`, `.status` | Hình viên thuốc (`border-radius: 999px`) |
| Alert | `.flash` + `ok` / `err` / `warn` | Nền và viền cùng họ màu nhạt |
| Dialog | `<dialog>` + `.panel-head` + `.panel-body` | Chỉ có một popup chi tiết ở trang Logs |
| Breadcrumb | `.breadcrumb` | Không nền, phần hiện tại in đậm |
| Dropdown menu | `.menu ul` | Popover có viền, `--shadow-md` |
| Tooltip | `.chart-tip` | Cùng kiểu popover |

Ở trang Logs, bấm dòng mở popup `<dialog>`. Không dùng dropdown mở rộng ngay dưới dòng: bản thử trước đó bị đánh giá khó nhìn.

## Khả năng truy cập

- Điều khiển bấm được phải dùng `<button type="button">` hoặc `<a href>`. Không dùng `<a>` không `href` làm nút: không nhận phím bàn phím và đổi hash URL ở một số môi trường (đã gặp ở tab con của popup).
- Giữ `:focus-visible` (vòng `--ring`); không đặt `outline: none` mà thiếu thay thế.
- Biểu tượng chỉ có hình phải có `title` hoặc `aria-label` (xem `iconBtn`, `priIcon`).
- Chữ phụ không nhạt hơn `--muted-foreground` trên nền trắng.

## Cache

Trang HTML và file tĩnh trả `Cache-Control: no-cache`, và các trang trỏ tới `style.css`, `charts.js`, `live.js` bằng `?v=N`. Khi sửa mạnh CSS/JS dùng chung, tăng `N` ở cả ba trang để trình duyệt chắc chắn tải bản mới.

## Kiểm tra khi sửa giao diện

1. `pytest tests/api` (có test trang phục vụ đúng và header cache).
2. Mở cả ba trang `/`, `/logs`, `/rules` (tab Categories và tab Rules); không có trang nào bị vỡ bố cục.
3. Nhìn thử độ rộng hẹp (dưới 640px): form xuống một cột, tổng quan còn 2 cột.
4. Nội dung có `<script>alert(1)</script>` trong lệnh hoặc URI phải hiện nguyên văn.
