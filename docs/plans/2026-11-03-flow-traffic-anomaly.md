---
type: PLAN
plan_id: PLAN-004
title: Tra cứu flow, trang Traffic và phát hiện bất thường theo ngưỡng
status: IN_PROGRESS
issue: 40, 41, 42
owner: Nguyen Minh Chien (nmchien1106)
created: 2026-11-03
updated: 2026-11-03
---

# PLAN-004: Tra cứu flow, trang Traffic và phát hiện bất thường theo ngưỡng

## 1. Bối cảnh

Sau #39, engine ghi mọi flow vào bảng `flows`, nhưng chưa có API đọc (#40) và giao diện chỉ hiện cảnh báo, không thấy traffic bình thường hay traffic chưa có rule (#41). Tấn công không có rule thì không sinh cảnh báo; AI worker (#23) còn xa, nên cần một lớp heuristic thống kê (#42). Khi test `pcap/demo_traffic.pcap`, 16 SYN quét cổng không sinh cảnh báo vì dưới ngưỡng rule `1000107`; đây đúng là loại lỗ hổng #42 lấp. Ba issue đang assign cho `nldd0507`; người dùng (nmchien1106) chọn tự phụ trách và sẽ tự báo hoặc đổi assignee.

## 2. Mục tiêu và tiêu chí thành công

- **Mục tiêu**: Xem được toàn bộ traffic (kể cả chưa khớp rule) qua API và web, và có cảnh báo `ANOMALY` cho scan, flood, cổng hiếm khi rule không bắt.
- **Xong khi**:
  - `GET /api/flows/?matched=false` chỉ trả flow `alert_count = 0`, kèm `X-Total-Count`; `GET /api/flows/stats` trả top talker, top cổng, phân bố protocol, timeline byte/flow/cảnh báo.
  - `/traffic` hiện bảng flow, tab "Chưa khớp rule"; flow có cảnh báo có link sang `/logs`. Dashboard có biểu đồ lưu lượng so với cảnh báo.
  - Replay `pcap/demo_traffic.pcap` sinh đúng 1 cảnh báo `ANOMALY` port scan cho `10.0.0.100` (rule không bắt được).
  - Test: scan và flood dựng sẵn sinh đúng 1 cảnh báo ANOMALY mỗi loại sau khi chặn bớt; traffic bình thường không sinh cảnh báo.

## 3. Phạm vi

- **Trong phạm vi**: API flows và stats; trang Traffic, mục menu, biểu đồ dashboard; module anomaly (scan, flood, cổng/ICMP hiếm bản hẹp); `source_type=ANOMALY` trên API, trang Logs, dashboard; mục `anomaly` trong `settings.example.yaml`.
- **Ngoài phạm vi**: AI/ML (#23); xuất CSV flow; đẩy flow realtime qua Redis (trang Traffic dùng poll); chống trùng giữa cảnh báo rule và ANOMALY (báo cả hai, người dùng chốt); làm giàu honeypot cho ANOMALY; thêm đòn vào `attack_demo.py` (ANOMALY không phải rule nên test lab không bắt buộc).

## 4. Hiện trạng

- Flow: `nids/engine/flow.py:73` `FlowTracker`; ghi lô qua `main.py:102` `FlowLog` → `EventRepository.save_flows` (`nids/db/repository.py:249`). Model `FlowModel` (`nids/db/models.py:46`) có index `first_seen`, `src_ip`, `dst_ip`, `dst_port`, `alert_count`.
- API alerts: `log_filters` (`nids/api/routes/alerts.py:30`) chuẩn hoá `since/until` về UTC naive; `get_alerts` đặt `X-Total-Count` (`alerts.py:133`). Repository: `_apply_filters` (`repository.py:51`), `get_timeline` (`repository.py:205`) chia bucket theo phút.
- Cảnh báo: `handle_alert` (`main.py:218`) → `save_alert` (`repository.py:19`) đã đọc `source_type`, `sid=None`, `matched_content`. `format_alert` (`main.py:35`) in `AI-ANOMALY` khi `sid` là None. `enrich_alert` chỉ áp cho `RULE_ENGINE`.
- Chặn bớt: `ThresholdManager.should_alert` (`nids/engine/threshold.py:16`), khoá `(sid, src, dst, port)`, theo giờ hệ thống.
- Cửa sổ trượt theo `packet.timestamp`: mẫu `_detection_filter_reached` (`nids/engine/detector.py:342`).
- Worker loop: `main.py:288`, gọi `evaluate_with_stream` → `ai_worker.analyze_packet` → `flow_log.on_packet`.
- Web: trang tĩnh qua `_page()` (`nids/api/main.py:83`); navbar lặp ở `dashboard.html`, `logs.html`, `rules.html` (dòng 14); `logs.html:388` điền bộ lọc từ query string; `TABS` ở `logs.html:85`; biểu đồ `timeColumns`/`drawTime` (`static/charts.js:98`).

## 5. Các phương án đã cân nhắc

| Phương án | Ưu điểm | Nhược điểm | Kết luận |
| :-------- | :------ | :--------- | :------- |
| Anomaly theo từng gói, cửa sổ trượt theo `packet.timestamp`, module thuần `anomaly.py` | Phát hiện ngay khi vượt ngưỡng; replay pcap cho kết quả lặp lại; không đụng `FlowTracker` | Thêm một bảng trạng thái theo IP | **Chọn** |
| Anomaly dựa trên flow đã kết thúc (`FlowLog`) | Dùng lại số liệu flow | Flow chỉ xuất sau idle 30 s nên cảnh báo trễ; scan SYN không trả lời chỉ xuất khi hết timeout | Loại, vì quá chậm cho demo |
| Đặt anomaly trong `AITrafficWorker` | Không thêm lời gọi ở worker | Trộn heuristic với stub AI; issue #23 sẽ thay file này | Loại |
| Timeline lưu lượng và cảnh báo tính trong một hàm repository | Bucket thẳng hàng, một request | `stats` của flow đọc cả `events` | **Chọn**: biểu đồ cần hai chuỗi cùng mốc |

## 6. Thiết kế đã chọn

**PR1: #40 + #41 (API flows, trang Traffic, biểu đồ)**

- `GET /api/flows/`: tham số `src_ip, dst_ip, protocol, dst_port, since, until, matched, limit (≤500), offset`. `matched=true` → `alert_count > 0`, `false` → `= 0`. `since/until` so với `first_seen`, sắp `first_seen desc, id desc`. Thời gian trả `iso_utc`.
- Tách phần đổi múi giờ trong `log_filters` thành hàm `to_utc_naive(dt)` để `flow_filters` dùng lại; hành vi `log_filters` giữ nguyên.
- `GET /api/flows/stats?minutes&buckets&top`: lọc `first_seen >= now - minutes`. Trả `top_talkers` (src_ip theo tổng byte, kèm số flow), `top_ports` (dst_port theo số flow), `protocols` (số flow, byte), `buckets` `[{t, bytes, flows, alerts}]`. Byte của flow tính vào bucket chứa `first_seen`; cảnh báo đếm từ `events` cùng mốc.
- `/traffic` (`traffic.html`): tab pill Tất cả / Chưa khớp rule / Có cảnh báo, form lọc, bảng (giờ, thời lượng, protocol, nguồn → đích, gói, byte, cờ, lý do kết thúc, số cảnh báo), phân trang theo `X-Total-Count`, ô "Tự làm mới" poll 10 s. Số cảnh báo > 0 là link `/logs?src_ip=…&dst_ip=…`.
- Menu Status thêm "Traffic" ở mọi trang. Dashboard thêm card "Lưu lượng theo thời gian" ngay dưới biểu đồ cảnh báo, cùng ô chọn khoảng thời gian và cùng mốc cột (small multiples). Hàm mới `trafficColumns` trong `charts.js` dùng lại `mount` và tooltip có sẵn; tooltip mỗi cột hiện byte, số flow và số cảnh báo; có bảng "Xem dạng bảng".

**PR2: #42 (anomaly), làm sau khi PR1 merge để tránh xung đột `dashboard.html`/`logs.html`**

```
worker: evaluate_with_stream → ai_worker → flow_log.on_packet → anomaly.observe(packet)
                                                                   │ vượt ngưỡng
                                         ThresholdManager.should_alert(kind, …) → handle_alert
```

- `nids/engine/anomaly.py`, `AnomalyDetector(cfg: dict, alert_callback)`: module thuần (không biết CSDL hay `SETTINGS`), chỉ worker thread gọi.
  - **Scan**: theo `src_ip`, tập `(dst_ip, dst_port)` của gói mở kết nối (TCP SYN không ACK, UDP, ICMP echo) trong `scan.window` giây; ≥ `scan.ports` cặp hoặc ≥ `scan.hosts` host → P2 `ANOMALY Port scan` hoặc `ANOMALY Host sweep`.
  - **Flood**: theo `dst_ip`, số gói trong `flood.window` ≥ `flood.packets` → P1 `ANOMALY Packet flood`; số SYN không ACK ≥ `flood.syn` → P1 `ANOMALY SYN flood`.
  - **Hiếm (bản hẹp)**: TCP SYN không ACK tới cổng ngoài `common_ports`, UDP tới cổng < 1024 ngoài `common_ports`, ICMP type ngoài {0, 3, 8, 11} → P3 `ANOMALY Rare port/ICMP`. Bỏ qua nếu `src_ip` đang bị đánh dấu scan.
  - Cửa sổ dùng `deque` theo `packet.timestamp` như `_detection_filter_reached`. Bảng trạng thái là `OrderedDict` giới hạn `max_tracked` IP, dọn mục hết cửa sổ mỗi giây (theo giờ gói), giống `FlowTracker`.
  - Chặn bớt: một `ThresholdManager(default_window_seconds=suppress_seconds)` riêng, khoá `(kind, src, dst, port)`. Scan khoá theo `src`, flood theo `dst`, hiếm theo đủ bốn.
  - `alert_data`: `sid=None`, `source_type="ANOMALY"`, `msg`, `severity`, `classtype` (`attempted-recon` / `denial-of-service` / `misc-activity`), IP/cổng/protocol, `matched_content` là bằng chứng (vd `"18 cổng trong 5s: 20,25,30,…"`).
- `main.py`: dựng từ `SETTINGS["anomaly"]` (`enabled: false` thì không dựng); lời gọi `observe` trong worker bọc `try/except` chỉ ghi `logger.error`, như `FlowLog.on_packet`, để lỗi anomaly không dừng worker; `format_alert` in nhãn `ANOMALY` khi `source_type == "ANOMALY"`. `alert_count` của flow vẫn chỉ đếm rule.
- `settings.example.yaml` thêm mục `anomaly` (giá trị mặc định ở mục 7).
- Web: `get_timeline` thêm khoá `anomaly`; `charts.js` thêm chuỗi thứ ba; `logs.html` thêm tab "Anomaly" (`source_type: "ANOMALY"`); nhãn nguồn và ô SID (`–`) ở Logs và dashboard nhận `ANOMALY`.

## 7. Thay đổi cần làm

| File | Thay đổi | Dùng lại |
| :--- | :------- | :------- |
| `nids/api/routes/alerts.py` | Tách `to_utc_naive()` khỏi `log_filters` | `log_filters` |
| `nids/api/routes/flows.py` (mới) | Router `/api/flows`: `/` và `/stats`, `flow_filters` | `to_utc_naive`, `iso_utc` |
| `nids/db/repository.py` | `_apply_flow_filters`, `get_flows`, `count_flows`, `get_flow_stats`; PR2: `get_timeline` thêm `anomaly` | mẫu `_apply_filters`, `get_timeline` |
| `nids/api/main.py` | `include_router(flows.router)`, route `/traffic` | `_page()` |
| `nids/api/static/traffic.html` (mới) | Trang Status › Traffic | style và cấu trúc `logs.html` |
| `nids/api/static/{dashboard,logs,rules}.html` | Mục menu Traffic; dashboard thêm card biểu đồ; PR2: tab và nhãn ANOMALY | |
| `nids/api/static/charts.js` | `trafficColumns`; PR2: chuỗi `anomaly` trong `drawTime` | `mount`, `niceTicks`, `bindTip`, `showTip` |
| `nids/engine/anomaly.py` (mới) | `AnomalyDetector` | `ThresholdManager`, mẫu cửa sổ của `detector.py` |
| `nids/engine/main.py` | Dựng detector, gọi `observe` trong worker, nhãn `format_alert` | `handle_alert` |
| `config/settings.example.yaml` | Mục `anomaly` (xem dưới) | |

Mặc định `anomaly`: `enabled: true`, `suppress_seconds: 60`, `max_tracked: 10000`, `scan: {window: 5, ports: 15, hosts: 10}`, `flood: {window: 1, packets: 500, syn: 100}`, `common_ports: [20, 21, 22, 23, 25, 53, 67, 68, 80, 110, 123, 143, 161, 443, 445, 993, 995, 2222, 3000, 3306, 3389, 5000, 6379, 8000, 8080]`.

Tài liệu cần cập nhật: `CLAUDE.md` (cấu trúc: `anomaly.py`, `routes/flows.py`, trang Traffic; Current Focus), `.claude/rules/api-web.md` (endpoint flows, `/traffic`, giá trị `ANOMALY`, bỏ câu "chưa có endpoint đọc flows"), `.claude/rules/engine.md` (mục Anomaly), `.claude/rules/config-db-docker.md` (mục `anomaly`, `source_type` có `ANOMALY`), `docs/demo/kich-ban-demo.md` (bước xem Traffic và ANOMALY).

## 8. Kiểm thử

| Test | Kiểm tra điều gì |
| :--- | :--------------- |
| `tests/api/test_api_flows.py` (mới) | `matched=false/true` lọc đúng; lọc IP/cổng/protocol/`since` có múi giờ; `X-Total-Count`; `limit > 500` bị từ chối; `stats` đúng top talker, top cổng, protocol, byte và cảnh báo vào đúng bucket; DB rỗng không lỗi |
| `tests/api/test_api_routes.py` | Thêm `/api/flows/`, `/api/flows/stats` vào danh sách route |
| `tests/api/test_api_dashboard.py` | `/traffic` trả HTML có `no-cache`; PR2: timeline có khoá `anomaly`, `source_type=ANOMALY` lọc đúng |
| `tests/engine/test_anomaly.py` (mới) | 30 SYN tới 30 cổng → đúng 1 cảnh báo scan; 300 SYN tới một đích trong 1 s → đúng 1 cảnh báo SYN flood, không có scan; SYN tới 31337 → 1 P3, nhưng không có P3 khi đang scan; traffic bình thường (bắt tay TCP tới 80/443, DNS query/response, ping) → 0 cảnh báo; cổng rải quá cửa sổ → 0; vượt `max_tracked` không phình bộ nhớ |
| `tests/engine/test_main_output.py` | `format_alert` in nhãn `ANOMALY`; `observe` ném lỗi thì worker vẫn xử lý gói tiếp (lỗi chỉ được log) |

Lệnh: `pytest`

## 9. Xác minh end-to-end

1. Local SQLite, offline `pcap/demo_traffic.pcap`: `python -m nids.engine` in 24 cảnh báo SID 1000201 như trước, cộng đúng 1 dòng `ANOMALY Port scan` cho `10.0.0.100` (16 cổng ≥ 15). Không có `ANOMALY SYN flood` vì 50 SYN < ngưỡng 100. Ghi số thật vào PR.
2. `uvicorn nids.api.main:app`: `/api/flows/?matched=false` thấy flow DNS và quét cổng; `/traffic` tab "Chưa khớp rule" thấy chúng; flow HTTP có link sang `/logs` mở đúng bộ lọc; dashboard có biểu đồ lưu lượng; `/logs` tab Anomaly thấy cảnh báo scan.
3. Docker lab: `docker exec -it nids_attacker nmap -sS -p 1-200 172.28.0.50` sinh 1 cảnh báo ANOMALY Port scan (và có thể kèm SID 1000107), không bão cảnh báo trong 60 s.
4. Lỗi: đặt `anomaly.enabled: false` thì engine chạy bình thường không có ANOMALY; DB chết thì cảnh báo ANOMALY vẫn hiện trên terminal (qua `handle_alert`).

## 10. Rủi ro và ảnh hưởng tới nhóm

| Rủi ro | Mức độ | Cách xử lý |
| :----- | :----- | :--------- |
| ANOMALY báo nhầm traffic bình thường (cổng hiếm, burst hợp lệ) | Vừa | Bản hẹp chỉ xét gói mở kết nối; ngưỡng trong `settings.yaml`; chặn bớt 60 s; P3 cho loại hiếm |
| Chi phí CPU/RAM thêm trên worker thread | Thấp | Thao tác O(1) mỗi gói; `max_tracked` giới hạn bảng; dọn theo giờ gói |
| `ThresholdManager` theo giờ hệ thống nên replay pcap dài ghi ít cảnh báo hơn live | Thấp | Ghi `shortcut:` trong code; chấp nhận cho demo |
| `/api/flows/stats` chậm khi bảng lớn | Thấp | Lọc theo `first_seen` có index, `retention_hours` 24 giờ |
| `/api/flows` không xác thực, lộ metadata mọi kết nối cho ai tới được cổng 8000 (kể cả `attacker` qua `172.28.0.20`) | Thấp | Cùng mức với `/api/alerts` hiện có, chỉ đọc, không có payload; ghi nhận, không đổi trong plan này |
| Xung đột với PLAN-001/002/003 đang mở trên `dashboard.html`, `logs.html`, `main.py` | Vừa | Rebase trên `main` trước mỗi PR; PR2 sau PR1 |

**Thành viên khác cần làm gì**: Thêm mục `anomaly` vào `config/settings.yaml` local nếu muốn đổi ngưỡng (thiếu thì dùng mặc định trong code). Không cần migrate: `events.source_type` đã là chuỗi.

## 11. Các bước thực hiện

PR1 — nhánh `feature/40-flow-traffic-view`

- [x] Tách `to_utc_naive`, viết repository flows + `routes/flows.py`, test API
- [x] Route `/traffic`, `traffic.html`, mục menu ở 3 trang
- [x] `trafficColumns` trong `charts.js` (đọc skill `dataviz` trước khi vẽ) và card trên dashboard
- [x] Cập nhật `api-web.md`, `web-design.md`, `CLAUDE.md`; `pytest`; xác minh mục 9 bước 2 (phần API)
- [ ] PR `feat(web): add flow API and traffic page (#40, #41)`, cập nhật bảng tổng hợp

PR2 — nhánh `feature/42-anomaly-detection` (sau khi PR1 merge)

- [ ] `anomaly.py` + `tests/engine/test_anomaly.py`
- [ ] Nối vào `main.py`, `format_alert`, mục `anomaly` trong `settings.example.yaml`
- [ ] `get_timeline` + `charts.js` + Logs/dashboard nhận `ANOMALY`
- [ ] Cập nhật `engine.md`, `config-db-docker.md`, `api-web.md`, `CLAUDE.md`, kịch bản demo
- [ ] `pytest`, xác minh mục 9 bước 1, 3, 4
- [ ] PR `feat(engine): add threshold-based anomaly detection (#42)`, chuyển plan sang `DONE` khi cả hai PR merge

## 12. Quyết định và nhật ký

**Quyết định**

| Ngày | Quyết định | Người chốt | Lý do |
| :--- | :--------- | :--------- | :---- |
| 2026-11-03 | Plan ghi nmchien1106 phụ trách dù issue assign cho nldd0507 | Người dùng | Người dùng tự báo hoặc đổi assignee |
| 2026-11-03 | Một plan, hai PR (#40+#41, rồi #42) | Người dùng | Hai phần độc lập, review dễ |
| 2026-11-03 | Làm heuristic cổng/ICMP hiếm bản hẹp, P3, tắt khi đang scan | Người dùng | Giảm báo nhầm |
| 2026-11-03 | Báo cả rule lẫn ANOMALY khi trùng | Người dùng | Đơn giản; chặn bớt giới hạn số dòng |
| 2026-11-03 | Anomaly theo từng gói với cửa sổ theo `packet.timestamp`, module riêng, không đặt trong `ai.py` | Claude | Phát hiện tức thì, replay lặp lại được, không đụng stub AI |
| 2026-11-03 | `flows/stats` trả cả số cảnh báo theo cùng bucket | Claude | Biểu đồ cần hai chuỗi cùng mốc |
| 2026-11-03 | Link flow → Logs chỉ truyền `src_ip`, `dst_ip` | Claude | `logs.html` điền bộ lọc theo tên ô; `since/until` dạng `datetime-local` cần đổi múi giờ, không đáng thêm logic |
| 2026-11-03 | Trang Traffic poll 10 s, không dùng WebSocket | Claude | Flow chỉ ghi theo lô, không có tín hiệu Redis |
| 2026-11-03 | Đổi biểu đồ dashboard từ hai trục y (cột byte + đường cảnh báo) sang biểu đồ lưu lượng riêng, cùng mốc cột với biểu đồ cảnh báo có sẵn (small multiples), màu aqua `#1baf7a` | Claude | Skill `dataviz` cấm hai trục y trên một khung; `validate_palette.js` cho aqua qua mọi kiểm tra cùng xanh NIDS và cam Honeypot (contrast < 3:1 được bù bằng bảng) |

**Câu hỏi còn mở**: Không.

**Kết quả phản biện**: Không gọi `plan-critic` theo yêu cầu đã lưu của người dùng (không dùng subagent phản biện). Claude tự rà theo danh sách trong `.claude/agents/plan-critic.md`; phản biện này không độc lập. Kết luận tự rà: `PASS_WITH_WARNINGS`. Đã sửa: bọc lỗi `observe` trong worker và thêm test đường lỗi. Giữ lại (WARNING): API flows không xác thực, cùng mức với `/api/alerts` (mục 10). Không có traffic mới nên không đụng `network.bpf_filter`; không thêm service, secret hay cột CSDL.
