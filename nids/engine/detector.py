import logging
from collections import deque
from typing import AbstractSet, List, Optional, Callable, Dict, Tuple, Deque
from nids.engine.packet import DecodedPacket
from nids.engine.rule import SnortRule, ContentMatch, PcreMatch, BUFFER_PKT_DATA
from nids.engine.rule_manager import RuleManager
from nids.engine.matcher import MultiPatternMatcher
from nids.engine.stream import StreamView
from nids.engine.threshold import ThresholdManager

logger = logging.getLogger("nids.engine")

# Mã cờ reserved kiểu Snort 2 (1, 2) tương ứng CWR, ECE của Snort 3 / Scapy
_FLAG_ALIASES = {"1": "C", "2": "E"}

PayloadGroups = List[Tuple[Tuple[str, Optional[str]], List[ContentMatch], List[PcreMatch]]]


class DetectionEngine:
    """
    Core Engine so khớp luật thời gian thực (Real-time Multi-Tier Rule Matcher).
    Bóc tách các trường trong DecodedPacket và đối chiếu với tập luật của RuleManager theo kiến trúc phễu lọc 4 tầng:
      1. Phân luồng giao thức & cổng (Protocol & Port Demux)
      2. Lọc mẫu đa chuỗi nhanh (Aho-Corasick Multi-Pattern Pre-filtering) trên fast pattern của rule
      3. Đánh giá ngữ cảnh chi tiết (flags, flow, dsize, itype/icode, content theo buffer, pcre, detection_filter)
      4. Kiểm soát ngưỡng & chống bão cảnh báo (Threshold Suppression)
    """

    def __init__(
        self,
        rule_manager: RuleManager,
        alert_callback: Optional[Callable] = None,
        enable_threshold: bool = True,
        threshold_window_seconds: float = 10.0,
    ):
        self.rule_manager = rule_manager
        self.alert_callback = alert_callback
        self.enable_threshold = enable_threshold
        self.threshold_manager = ThresholdManager(default_window_seconds=threshold_window_seconds)

        self.rules_by_proto: Dict[str, List[SnortRule]] = {}
        # Rule không có fast pattern dùng được cho Aho-Corasick -> luôn được đánh giá ở tầng 3
        self.no_content_rules: List[SnortRule] = []
        self.uri_matcher = MultiPatternMatcher()
        self.header_matcher = MultiPatternMatcher()
        self.body_matcher = MultiPatternMatcher()
        self.raw_matcher = MultiPatternMatcher()

        self._payload_groups: Dict[int, PayloadGroups] = {}
        self._detection_filter_hits: Dict[Tuple[int, str], Deque[float]] = {}

        self.rebuild_index()

    def rebuild_index(self) -> None:
        """Biên dịch và tái cấu trúc toàn bộ chỉ mục luật vào RAM."""
        self.rules_by_proto = {
            "tcp": [],
            "udp": [],
            "icmp": [],
            "ip": [],
        }
        self.no_content_rules = []
        self._payload_groups = {}
        self._detection_filter_hits = {}

        self.uri_matcher = MultiPatternMatcher()
        self.header_matcher = MultiPatternMatcher()
        self.body_matcher = MultiPatternMatcher()
        self.raw_matcher = MultiPatternMatcher()
        matchers = {
            "http_uri": self.uri_matcher,
            "http_header": self.header_matcher,
            "http_client_body": self.body_matcher,
            BUFFER_PKT_DATA: self.raw_matcher,
        }

        for rule in self.rule_manager.rules:
            proto = rule.protocol.lower()
            if proto not in self.rules_by_proto:
                self.rules_by_proto[proto] = []
            self.rules_by_proto[proto].append(rule)
            self._payload_groups[rule.sid] = self._group_by_buffer(rule)

            fast = self._select_fast_pattern(rule, matchers)
            if fast is None:
                self.no_content_rules.append(rule)
                continue

            pattern = fast.pattern.lower() if fast.nocase else fast.pattern
            matchers[fast.buffer].add_pattern(pattern, rule)

        for matcher in matchers.values():
            matcher.build()

    @staticmethod
    def _select_fast_pattern(rule: SnortRule, matchers: Dict[str, MultiPatternMatcher]) -> Optional[ContentMatch]:
        """Chọn content có fast_pattern, nếu không thì content dài nhất (giống Snort)."""
        candidates = [c for c in rule.contents if not c.negated and c.buffer in matchers]
        explicit = [c for c in candidates if c.fast_pattern]
        if explicit:
            return explicit[0]
        return max(candidates, key=lambda c: len(c.pattern), default=None)

    @staticmethod
    def _group_by_buffer(rule: SnortRule) -> PayloadGroups:
        """Gom content/pcre theo (buffer, field), giữ nguyên thứ tự xuất hiện trong rule."""
        groups: Dict[Tuple[str, Optional[str]], Tuple[List[ContentMatch], List[PcreMatch]]] = {}
        for c in rule.contents:
            groups.setdefault((c.buffer, c.field), ([], []))[0].append(c)
        for p in rule.pcres:
            groups.setdefault((p.buffer, p.field), ([], []))[1].append(p)
        return [(key, contents, pcres) for key, (contents, pcres) in groups.items()]

    def evaluate_stream(self, view: StreamView) -> List[SnortRule]:
        """Đánh giá dữ liệu đã ghép; SID đã bắn trên message này không báo lại."""
        matched = self.evaluate_packet(view.packet, skip_sids=view.fired)
        view.fired.update(rule.sid for rule in matched)
        return matched

    @staticmethod
    def _stream_eligible(rule: SnortRule) -> bool:
        """Rule xét được trên dữ liệu đã ghép: có nội dung, không dựa vào thuộc tính của một gói thật.

        dsize và flags chỉ có nghĩa với gói thật; detection_filter đếm số lần khớp nên chạy thêm lượt ghép sẽ đếm đôi.
        """
        return bool(rule.contents or rule.pcres) and not (rule.dsize or rule.flags is not None or rule.detection_filter)

    def evaluate_packet(self, packet: DecodedPacket, skip_sids: AbstractSet[int] = frozenset()) -> List[SnortRule]:
        """Đánh giá gói tin qua kiến trúc phễu lọc đa tầng."""
        pkt_proto = packet.protocol.lower()

        proto_candidates: List[SnortRule] = (
            self.rules_by_proto.get(pkt_proto, []) + self.rules_by_proto.get("ip", [])
        )
        if not proto_candidates:
            return []

        proto_candidate_sids = {r.sid for r in proto_candidates}

        candidate_rules: Dict[int, SnortRule] = {}

        for rule in self.no_content_rules:
            if rule.sid in proto_candidate_sids:
                candidate_rules[rule.sid] = rule

        # Tầng 2: Khớp nhanh fast pattern trên từng buffer
        prefilter_inputs = [(self.raw_matcher, self._buffer_text(packet, BUFFER_PKT_DATA))]
        if packet.http_data:
            prefilter_inputs += [
                (self.uri_matcher, packet.http_data.uri),
                (self.header_matcher, self._buffer_text(packet, "http_header")),
                (self.body_matcher, packet.http_data.body),
            ]

        for matcher, text in prefilter_inputs:
            if not text:
                continue
            for _, rule in matcher.search(text) + matcher.search(text.lower()):
                if rule.sid in proto_candidate_sids:
                    candidate_rules[rule.sid] = rule

        matched_rules: List[SnortRule] = []

        # Tầng 3: Đánh giá chi tiết (Detailed Qualification) trên các rule ứng viên
        for rule in candidate_rules.values():
            if packet.reassembled and (rule.sid in skip_sids or not self._stream_eligible(rule)):
                continue
            if not self._match_port(packet.dst_port, rule.dst_port):
                continue
            if not self._match_port(packet.src_port, rule.src_port):
                continue
            if not self._match_non_payload(packet, rule):
                continue
            if not self._match_payload(packet, rule):
                continue
            if rule.detection_filter and not self._detection_filter_reached(packet, rule):
                continue

            matched_rules.append(rule)

            # Tầng 4: Kiểm soát ngưỡng & Phát cảnh báo
            self._handle_alert_dispatch(packet, rule)

        return matched_rules

    def _match_port(self, packet_port: Optional[int], rule_port: str) -> bool:
        if rule_port == "any" or rule_port == "$HTTP_PORTS":
            if rule_port == "$HTTP_PORTS":
                return packet_port in {80, 8080, 8000, 3000, 5000}
            return True
        if packet_port is None:
            return False
        try:
            return packet_port == int(rule_port)
        except ValueError:
            return True

    def _match_non_payload(self, packet: DecodedPacket, rule: SnortRule) -> bool:
        if rule.flags is not None and not self._match_flags(packet.tcp_flags, rule.flags):
            return False
        if "established" in rule.flow and not self._is_established(packet):
            return False
        if rule.dsize and not self._match_numeric(len(packet.raw_payload), rule.dsize):
            return False
        if rule.itype and not self._match_numeric(packet.icmp_type, rule.itype):
            return False
        if rule.icode and not self._match_numeric(packet.icmp_code, rule.icode):
            return False
        return True

    @staticmethod
    def _is_established(packet: DecodedPacket) -> bool:
        """
        Xấp xỉ flow:established khi chưa có bảng theo dõi phiên TCP:
        gói TCP có ACK và không phải SYN được coi là thuộc phiên đã thiết lập.
        to_server/from_server chưa được kiểm tra (header rule đã giới hạn hướng qua port).
        """
        if packet.protocol.upper() != "TCP":
            return True
        raw = packet.tcp_flags.get("raw_flags", "")
        return "A" in raw and "S" not in raw

    @staticmethod
    def _match_flags(packet_flags: dict, rule_flags: str) -> bool:
        """
        Ngữ nghĩa flags của Snort:
          flags:SF   -> đúng chính xác S và F (không cờ nào khác)
          flags:S+   -> có S, có thể kèm cờ khác
          flags:SF*  -> có ít nhất một trong S, F
          flags:!F   -> không có F
          flags:0    -> không có cờ nào
          flags:S,CE -> bỏ qua cờ C, E khi so sánh
        """
        spec, _, mask = rule_flags.partition(",")
        ignored = {_FLAG_ALIASES.get(ch, ch) for ch in mask}

        modifier = ""
        if spec and spec[0] in "+*!":
            modifier, spec = spec[0], spec[1:]
        elif spec and spec[-1] in "+*!":
            modifier, spec = spec[-1], spec[:-1]

        wanted = set() if spec == "0" else {_FLAG_ALIASES.get(ch, ch) for ch in spec}
        actual = set(packet_flags.get("raw_flags", "")) - ignored

        if modifier == "+":
            return wanted <= actual
        if modifier == "*":
            return bool(wanted & actual)
        if modifier == "!":
            return not (wanted & actual)
        return actual == wanted

    @staticmethod
    def _match_numeric(value: Optional[int], expr: str) -> bool:
        """So khớp biểu thức số kiểu Snort: N, >N, <N, >=N, <=N, !N, A<>B (mở), A<=>B (đóng)."""
        if value is None:
            return False
        if "<=>" in expr:
            low, high = expr.split("<=>")
            return int(low) <= value <= int(high)
        if "<>" in expr:
            low, high = expr.split("<>")
            return int(low) < value < int(high)
        for op, check in (
            (">=", lambda n: value >= n),
            ("<=", lambda n: value <= n),
            (">", lambda n: value > n),
            ("<", lambda n: value < n),
            ("!", lambda n: value != n),
            ("=", lambda n: value == n),
        ):
            if expr.startswith(op):
                return check(int(expr[len(op):]))
        return value == int(expr)

    def _match_payload(self, packet: DecodedPacket, rule: SnortRule) -> bool:
        for (buffer, header_field), contents, pcres in self._payload_groups.get(rule.sid, []):
            text = self._buffer_text(packet, buffer, header_field)
            if text is None:
                return False
            if not self._match_contents(text, contents):
                return False
            if any(not p.regex.search(text) for p in pcres):
                return False
        return True

    @staticmethod
    def _buffer_text(packet: DecodedPacket, buffer: str, header_field: Optional[str] = None) -> Optional[str]:
        """Trả về nội dung của buffer; None nếu gói tin không có buffer đó (vd: không phải HTTP)."""
        if buffer == BUFFER_PKT_DATA:
            return packet.raw_payload.decode("latin-1", errors="replace")

        http = packet.http_data
        if not http:
            return None
        if buffer == "http_uri":
            return http.uri
        if buffer == "http_client_body":
            return http.body
        if buffer == "http_method":
            return http.method
        if buffer == "http_header":
            if header_field:
                return http.headers.get(header_field)
            return "\r\n".join([f"{k}: {v}" for k, v in http.headers.items()])
        return None

    @staticmethod
    def _match_contents(text: str, contents: List[ContentMatch]) -> bool:
        """
        So khớp lần lượt các content trong cùng một buffer.
        offset/depth tính từ đầu buffer; distance/within tính từ cuối lần khớp trước.
        Khớp tham lam (lấy vị trí đầu tiên), không quay lui như Snort.
        """
        lowered = None
        prev_end = 0
        for c in contents:
            if c.nocase:
                if lowered is None:
                    lowered = text.lower()
                haystack, pattern = lowered, c.pattern.lower()
            else:
                haystack, pattern = text, c.pattern

            if c.distance is not None or c.within is not None:
                start = prev_end + (c.distance or 0)
                end = start + c.within if c.within is not None else len(haystack)
            else:
                start = c.offset or 0
                end = start + c.depth if c.depth is not None else len(haystack)

            idx = haystack.find(pattern, max(start, 0), end)
            if c.negated:
                if idx != -1:
                    return False
                continue
            if idx == -1:
                return False
            prev_end = idx + len(pattern)
        return True

    def _detection_filter_reached(self, packet: DecodedPacket, rule: SnortRule) -> bool:
        """Chỉ cho rule bắn khi số lần khớp trong `seconds` giây vượt quá `count`."""
        df = rule.detection_filter
        tracked_ip = packet.src_ip if df.track == "by_src" else packet.dst_ip
        hits = self._detection_filter_hits.setdefault(
            (rule.sid, tracked_ip), deque(maxlen=df.count + 1)
        )
        hits.append(packet.timestamp)
        while hits and packet.timestamp - hits[0] > df.seconds:
            hits.popleft()
        return len(hits) > df.count

    def _handle_alert_dispatch(self, packet: DecodedPacket, rule: SnortRule) -> None:
        suppressed_hits = 0
        if self.enable_threshold:
            allow, suppressed_hits = self.threshold_manager.should_alert(
                sid=rule.sid,
                src_ip=packet.src_ip,
                dst_ip=packet.dst_ip,
                dst_port=packet.dst_port,
            )
            if not allow:
                return

        alert_data = {
            "timestamp": packet.timestamp,
            "sid": rule.sid,
            "msg": rule.msg,
            "severity": rule.severity,
            "classtype": rule.classtype,
            "src_ip": packet.src_ip,
            "src_port": packet.src_port,
            "dst_ip": packet.dst_ip,
            "dst_port": packet.dst_port,
            "protocol": packet.protocol,
            "http_uri": packet.http_data.uri if packet.http_data else None,
            "http_method": packet.http_data.method if packet.http_data else None,
            "suppressed_hits": suppressed_hits,
        }
        if self.alert_callback:
            self.alert_callback(alert_data)
        else:
            logger.debug(
                "Cảnh báo SID %s: %s | %s -> %s", rule.sid, rule.msg, packet.src_ip, packet.dst_ip
            )
