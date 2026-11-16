---
type: PLAN
plan_id: PLAN-010
title: Chuyển đổi bộ rule Snort community sang Snort 3 và bật ~2000 rule
status: IN_PROGRESS
issue: ""
owner: nmchien1106
created: 2026-11-16
updated: 2026-11-16
---

# PLAN-010: Chuyển đổi bộ rule Snort community sang Snort 3 và bật ~2000 rule

## 1. Bối cảnh

Engine hiện chạy khoảng 364 rule tự viết, chia theo 6 nhóm (`rules/*.rules`, dải SID `10000xx`–`10005xx`). Nhóm muốn có khoảng 2000 rule để bộ phát hiện giống IDS thật hơn.

`rules/vendor/community.rules` (Talos community, GPL) đã có 4013 rule nhưng viết theo **cú pháp Snort 2.9**: modifier đứng riêng (`content:"x"; nocase; depth:16;`), `fast_pattern:only`, `http_uri`/`http_header` đứng **sau** content, pcre flag `U/H/P/C/M/I`. Đo trên repo:

- Parser hiện tại nhận sạch 340 rule; 3230 rule có option bị bỏ qua, 443 rule lỗi parse.
- Nguy hiểm hơn: `content:"/x.php"; http_uri;` kiểu Snort 2 được parse "thành công" nhưng sai nghĩa (`http_uri` bị coi là sticky buffer cho content **sau** nó).
- Nếu gập modifier vào content, khoảng **2600 rule** chỉ dùng option engine hỗ trợ (SERVER-WEBAPP 796, MALWARE-CNC 514, SERVER-ORACLE 289, SERVER-OTHER 156, SERVER-IIS 125, PROTOCOL-ICMP 106, ...).

Người dùng đã chốt: nguồn là `community.rules` có sẵn (không tải ET Open), chuyển đổi bằng script offline (parser vẫn chỉ hiểu Snort 3), rule mới **bật mặc định**, không gắn issue.

## 2. Mục tiêu và tiêu chí thành công

- **Mục tiêu**: engine nạp mặc định ≥ 2000 rule community đã chuyển sang đúng tập con Snort 3 mà engine hiểu, không sai nghĩa, không tăng báo nhầm rõ rệt.
- **Xong khi**:
  - `python -m nids.tools.snort2_convert` sinh lại các file `rules/community-*.rules` một cách tất định (chạy hai lần không đổi file).
  - Khởi động engine: log `Đã nạp N rule` với N ≥ 2300 (364 tự viết + ≥ 2000 community), **không có dòng `WARNING rules`** nào.
  - `pytest` xanh, gồm test benign có sẵn (`/index.html` không bắn rule nào) chạy với toàn bộ rule mới.
  - Chạy offline `pcap/benign_0900.pcap` trước/sau: số cảnh báo do rule community gây ra được ghi vào mục 12; rule nào báo nhầm hàng loạt thì bị đưa vào danh sách loại của converter.
  - Thông lượng offline trên `pcap/benign_0900.pcap` giảm không quá ~30% so với trước (ghi số đo vào mục 12; issue #102 theo dõi tối ưu tiếp).

## 3. Phạm vi

- **Trong phạm vi**: script chuyển đổi; các file rule sinh ra; dời file nguồn Snort 2 ra khỏi chỗ engine quét; nới test coverage đòn demo cho rule community; nhóm "COMMUNITY" trên API/trang Rules; cập nhật tài liệu.
- **Ngoài phạm vi**: ET Open hay nguồn tải từ mạng; cài thêm option engine (`byte_test`, `isdataat`, `flowbits`, `file_data`, `urilen`, `dce_*`...); viết đòn demo cho rule community; tối ưu tốc độ engine (#102); sửa rule community bằng tay.

## 4. Hiện trạng

- `RuleManager.category_files` ([rule_manager.py:57](nids/engine/rule_manager.py#L57)) quét `rules/*.rules` (bật mặc định) và `rules/vendor/*.rules` (tắt mặc định); thư mục con khác không bị quét. SID trùng: giữ rule nạp trước, rule sau bị bỏ kèm `WARNING`.
- `parse_rule_line` ([rule_manager.py:291](nids/engine/rule_manager.py#L291)) hiểu `content` với modifier sau dấu phẩy, sticky buffer `http_uri/http_header[:field x]/http_client_body/http_method`, `pcre` flag `i s m x`, `flow`, `flags`, `dsize`, `itype/icode`, `detection_filter`, `priority`; `reference/metadata/gid/service` được chấp nhận và bỏ qua.
- `SnortRule.severity` mặc định 2 ([rule.py:69](nids/engine/rule.py#L69)); community rule không có `priority`, nên nếu giữ nguyên thì mọi rule đều P2 và đủ điều kiện cho redirector (`max_priority`).
- Biến `$HOME_NET, $EXTERNAL_NET, $HTTP_SERVERS, $SQL_SERVERS, $SMTP_SERVERS, $TELNET_SERVERS, $SIP_*, $ORACLE_PORTS, $FILE_DATA_PORTS`... đã có trong `DEFAULT_RULE_VARIABLES` ([rule_header.py:21](nids/engine/rule_header.py#L21)).
- `DetectionEngine` dùng Aho-Corasick theo buffer, rule không có content vào `no_content_rules` và bị xét mọi gói ([detector.py:66-93](nids/engine/detector.py#L66-L93)).
- `tests/lab/test_attack_demo.py::test_every_rule_is_covered_by_an_attack` đòi **mọi** rule đang bật có đòn demo.
- API gán nhóm bằng `GROUPS.get((sid - 1000000) // 100, "KHÁC")` ([routes/rules.py:53](nids/api/routes/rules.py#L53)).
- `rules/state.yaml` local có `sid_overrides.enable` chứa vài SID community (105, 108, ...); không có `enabled_categories` nên mọi file ở gốc `rules/` bật mặc định.

## 5. Các phương án đã cân nhắc

| Phương án | Kết luận |
|---|---|
| Mở rộng parser để nhận Snort 2 | Loại: phá quy tắc "parser chỉ hiểu Snort 3", lệch `snort-rules.md` |
| Tải thêm ET Open | Loại (người dùng chọn): license, trùng SID, nhiều cú pháp hơn |
| Để rule ở `rules/vendor/` (tắt mặc định) | Loại (người dùng chọn bật mặc định) |
| **Script chuyển đổi offline, ghi `rules/community-*.rules` ở gốc** | **Chọn**: bật mặc định mà không sửa `RuleManager`, mỗi file là một category tắt được trên trang Rules |

## 6. Thiết kế đã chọn

**Converter** `nids/tools/snort2_convert.py`, chạy `python -m nids.tools.snort2_convert [--source rules/upstream/community.rules] [--out rules]`:

1. Đọc nguồn: dòng `alert ...` và `# alert ...` (rule bị comment sẵn cũng được chuyển và **bật mặc định**: upstream tắt 3452/4013 rule, người dùng muốn bật ~2000 rule). Bỏ action khác `alert`.
2. Tách option bằng `RuleManager._split_options` (dùng lại, không viết parser mới).
3. Dựng lại danh sách content dạng Snort 3:
   - Gập modifier rời vào content ngay trước: `nocase`, `depth:N`, `offset:N`, `distance:N`, `within:N`, `fast_pattern`, `fast_pattern:only` → `fast_pattern` (bỏ `fast_pattern:x,y` offset-length → giữ `fast_pattern`).
   - Buffer modifier Snort 2 đặt **sau** content: `http_uri`, `http_raw_uri` → `http_uri` (buffer của engine chưa URL-decode nên khớp đúng nghĩa raw); `http_header`, `http_raw_header` → `http_header`; `http_client_body`; `http_method`; `http_cookie` → `http_header:field cookie`. Content không có modifier thuộc `pkt_data`.
   - pcre flag buffer: `U`/`I` → `http_uri`, `H`/`D` → `http_header`, `P` → `http_client_body`, `M` → `http_method`, `C` → `http_header:field cookie`; bỏ flag `B`, `O`. Flag `R` (relative) hoặc flag khác → loại rule.
   - Xuất theo thứ tự gốc, chèn tên sticky buffer mỗi khi buffer đổi. Content có `distance`/`within` mà content trước nó ở buffer khác → loại rule (Snort 2 không cùng nghĩa).
4. Option còn lại: giữ `msg, flow, flags, dsize, itype, icode, reference, metadata, classtype, sid, rev, gid`; `metadata: ... service http` → thêm `service:http;`. Option ngoài danh sách (`file_data`, `isdataat`, `byte_test`, `byte_jump`, `flowbits`, `urilen`, `dce_*`, `ssl_state`, `http_stat_code`, `rawbytes`, `icmp_id`...) → loại rule.
5. **Priority theo classtype** (bảng `priority` chuẩn của `classification.config` Snort, hằng trong converter, vd. `attempted-admin`/`trojan-activity`/`web-application-attack` = 1, `attempted-recon`/`bad-unknown` = 2, `misc-activity`/`icmp-event`/`not-suspicious` = 3; classtype lạ = 3). Thêm `priority:N;` trước `sid`.
6. **Kiểm tra lại**: mỗi rule sau khi chuyển được parse bằng `RuleManager.parse_rule_line`; có lỗi hoặc `unsupported_options` → loại.
7. **Danh sách loại** `DENY_SIDS` (hằng trong converter, có comment lý do) cho rule báo nhầm khi chạy `benign_0900.pcap` hoặc test benign.
8. Ghi theo nhóm msg, SID tăng dần, header file ghi nguồn, license GPLv2 và "file sinh tự động, không sửa tay":
   - `community-web.rules`: SERVER-WEBAPP, SERVER-IIS, SERVER-APACHE, BROWSER-*, EXPLOIT-KIT
   - `community-malware.rules`: MALWARE-*, INDICATOR-*, PUA-*
   - `community-server.rules`: SERVER-ORACLE, SERVER-MSSQL, SQL, SERVER-MAIL, SERVER-OTHER, OS-*
   - `community-protocol.rules`: PROTOCOL-*, NETBIOS, X11, APP-DETECT, POLICY-*, phần còn lại
   - In thống kê bằng `logging` (`nids.tools`): đã chuyển / loại theo lý do / theo file.

**Nguồn Snort 2** dời `rules/vendor/community.rules` → `rules/upstream/community.rules` (thư mục không bị quét) để không trùng SID với file sinh ra.

**Nhóm trên API**: rule thuộc category `community-*` → nhóm `COMMUNITY`.

**Tối ưu engine kèm theo**: `DetectionEngine._candidate_sids` cache tập SID theo giao thức (trước đó dựng lại mỗi gói, chiếm ~47% thời gian khi có ~2800 rule).

**Test coverage đòn demo** chỉ áp cho rule không thuộc category `community-*`; rule community được miễn (đã được Talos kiểm, và có test converter riêng).

## 7. Thay đổi cần làm

| File | Thay đổi |
|---|---|
| `nids/tools/__init__.py`, `nids/tools/snort2_convert.py`, `nids/tools/__main__.py` (hoặc `-m` trực tiếp) | Converter mới (mục 6) |
| `rules/upstream/community.rules` | Dời từ `rules/vendor/` (git mv) |
| `rules/community-{web,malware,server,protocol}.rules` | File sinh ra, commit vào repo |
| `tests/engine/test_snort2_convert.py` | Test converter (mục 8) |
| `tests/lab/test_attack_demo.py`, `tests/engine/test_rule_header.py` | Coverage và đếm rule chỉ xét rule không thuộc `community-*`; đường dẫn upstream mới |
| `nids/api/routes/rules.py` | Nhóm `COMMUNITY` cho category `community-*` |
| `nids/engine/detector.py` | Cache SID theo giao thức (`_candidate_sids`) |
| `.claude/rules/snort-rules.md` | Dải SID `< 1000000` = community (sinh tự động, không sửa tay); cách sinh lại |
| `CLAUDE.md`, `README.md` | Số rule, quy tắc "rule mới phải có đòn demo" chỉ cho rule tự viết, lệnh converter |
| `docs/plans/README.md` | Dòng PLAN-010 |

## 8. Kiểm thử

- `tests/engine/test_snort2_convert.py`, mỗi case một dòng Snort 2 → chuỗi Snort 3 mong đợi:
  - gập `nocase; depth:4;` vào content; `fast_pattern:only` → `fast_pattern`
  - `content:"/a.php"; http_uri;` → `http_uri; content:"/a.php";` và rule chuyển xong bắn trên gói HTTP có URI đó, không bắn khi chuỗi chỉ nằm trong body
  - pcre `/x/Ui` → `http_uri; pcre:"/x/i";`
  - `distance` qua hai buffer khác nhau → bị loại; `byte_test`/`file_data`/pcre flag `R` → bị loại
  - `priority` suy từ classtype; rule `# alert` vẫn giữ comment
  - chạy converter hai lần trên `tmp_path` cho ra file giống hệt (tất định)
  - toàn bộ file `rules/community-*.rules` trong repo parse sạch (không lỗi, không `unsupported_options`) và khớp với output chạy converter trên `rules/upstream/community.rules` (chống sửa tay)
- Test có sẵn chạy với rule thật: `test_diverse_rules_engine.py` (benign `/index.html` không bắn gì), `tests/lab/test_demo_rules.py` (gói lành tính không bắn rule tự viết; nếu rule community bắn trên gói lành tính → thêm vào `DENY_SIDS`), `test_attack_demo.py`.

## 9. Xác minh end-to-end

1. `python -m nids.tools.snort2_convert` → log thống kê ≥ 2000 rule; chạy lại → `git status` không đổi.
2. `pytest` xanh.
3. Engine offline với `pcap/benign_0900.pcap`, đo thời gian và số cảnh báo theo SID, trước (checkout main) và sau; ghi vào mục 12.
4. Engine offline với `pcap/portscan_1450.pcap` và `pcap/demo_traffic.pcap`: mọi SID tự viết vẫn bắn như trước.
5. API + trang Rules: thấy 4 category `community-*`, tắt/bật được, nhóm hiện `COMMUNITY`.

## 10. Rủi ro và ảnh hưởng tới nhóm

- **Báo nhầm** (liên quan #101): rule community có header `any` (do `$HOME_NET=any`) → dễ bắn trên traffic thường. Giảm bằng `DENY_SIDS`, priority theo classtype, và có thể tắt cả category trên trang Rules.
- **Redirector**: rule community priority 1/2 cũng góp vào ngưỡng chuyển hướng. Chấp nhận; ghi chú trong tài liệu.
- **Tốc độ** (#102): ~2000 rule thêm vào Aho-Corasick và `no_content_rules` (ICMP header-only ~100 rule). Đo ở bước 9.3.
- **Đổi nghĩa so với Snort thật**: engine khớp content tham lam không quay lui, `flow:established` xấp xỉ → một số rule bắn thiếu. Chấp nhận, ghi trong `snort-rules.md`.
- **Nhóm**: thành viên khác thấy số rule tăng mạnh trên dashboard; `rules/state.yaml` local có `enabled_categories` thì phải bật category mới trên trang Rules.

## 11. Các bước thực hiện

1. Tạo branch `feature/community-ruleset` từ `main` (không làm trên `feature/68-vmware-lab`).
2. `git mv rules/vendor/community.rules rules/upstream/community.rules`.
3. Viết test converter (TDD), rồi viết converter.
4. Sinh file `rules/community-*.rules`, kiểm không có `WARNING rules`.
5. Sửa test coverage, nhóm `COMMUNITY` trên API.
6. Chạy `pytest`, đo pcap benign; bổ sung `DENY_SIDS` đến khi test benign xanh.
7. Cập nhật tài liệu, bảng plan; xin phép người dùng trước khi commit/push/PR.

## 12. Quyết định và nhật ký

- 2026-11-16: Người dùng chốt nguồn `community.rules` có sẵn, script chuyển đổi offline, bật mặc định, không gắn issue.
- 2026-11-16: Kết quả: chuyển được 2792/4013 rule (web 1070, malware 843, server 595, protocol 284); loại chủ yếu do `file_data` 216, `isdataat` 188, `byte_test` 150, `byte_jump` 103, không có content/pcre 90, pcre cờ `R` 37.
- Đo 98.631 gói đầu của `benign_0900.pcap` (không có `state.yaml`): chỉ rule tự viết 40,2 giây; thêm community 51,8 giây (+29%, sau khi cache SID theo giao thức; trước đó 90,5 giây). Rule community chỉ báo 192 lần, toàn bộ là SID 1917 (SSDP) nên đưa vào `DENY_SIDS`.
- Rule tự viết đã bắn 4907 cảnh báo trên cùng đoạn pcap trước khi có community (không do plan này, thuộc #101).
