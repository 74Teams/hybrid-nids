import re
import time
from typing import List, Optional, Callable, Dict, Set
from services.ingestion import DecodedPacket
from services.detection import SnortRule
from services.detection.manager_rules import RuleManager
from services.detection.pattern_matcher import MultiPatternMatcher
from services.detection.threshold_manager import ThresholdManager


class DetectionEngine:
    """
    Core Engine so khớp luật thời gian thực (Real-time Multi-Tier Rule Matcher).
    Bóc tách các trường trong DecodedPacket và đối chiếu với tập luật của RuleManager theo kiến trúc phễu lọc 4 tầng:
      1. Phân luồng giao thức & cổng (Protocol & Port Demux)
      2. Lọc mẫu đa chuỗi nhanh (Aho-Corasick Multi-Pattern Pre-filtering)
      3. Đánh giá ngữ cảnh chi tiết (Flags, HTTP Method, Content, PCRE)
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
        self.no_content_rules: List[SnortRule] = []
        self.uri_matcher = MultiPatternMatcher()
        self.header_matcher = MultiPatternMatcher()
        self.body_matcher = MultiPatternMatcher()
        self.raw_matcher = MultiPatternMatcher()

        self.rebuild_index()

    def reload_rules_from_db(self, db_session) -> int:
        """Hot-reload rules trực tiếp từ CSDL và tái biên dịch cây chỉ mục."""
        count = self.rule_manager.reload_rules_from_db(db_session)
        self.rebuild_index()
        return count

    def rebuild_index(self) -> None:
        """Biên dịch và tái cấu trúc toàn bộ chỉ mục luật vào RAM (Zero-Downtime Hot Reload)."""
        self.rules_by_proto = {
            "tcp": [],
            "udp": [],
            "icmp": [],
            "ip": [],
        }
        self.no_content_rules = []

        self.uri_matcher = MultiPatternMatcher()
        self.header_matcher = MultiPatternMatcher()
        self.body_matcher = MultiPatternMatcher()
        self.raw_matcher = MultiPatternMatcher()

        for rule in self.rule_manager.rules:
            if not rule.is_enabled:
                continue

            proto = rule.protocol.lower()
            if proto not in self.rules_by_proto:
                self.rules_by_proto[proto] = []
            self.rules_by_proto[proto].append(rule)

            if not rule.contents:
                self.no_content_rules.append(rule)
                continue

            fast_content = rule.contents[0]
            pattern = fast_content.lower() if rule.nocase else fast_content

            if rule.http_uri:
                self.uri_matcher.add_pattern(pattern, rule)
            elif rule.http_client_body:
                self.body_matcher.add_pattern(pattern, rule)
            elif rule.http_header:
                self.header_matcher.add_pattern(pattern, rule)
            else:
                self.raw_matcher.add_pattern(pattern, rule)

        self.uri_matcher.build()
        self.header_matcher.build()
        self.body_matcher.build()
        self.raw_matcher.build()

    def evaluate_packet(self, packet: DecodedPacket) -> List[SnortRule]:
        """Đánh giá gói tin qua kiến trúc phễu lọc đa tầng."""
        pkt_proto = packet.protocol.lower()

        # Tầng 1: Lọc thô theo Protocol
        proto_candidates: List[SnortRule] = (
            self.rules_by_proto.get(pkt_proto, []) + self.rules_by_proto.get("ip", [])
        )
        if not proto_candidates:
            return []

        proto_candidate_sids = {r.sid for r in proto_candidates}

        # Tầng 2: Thu thập Rule ứng viên qua Aho-Corasick Pre-filtering
        candidate_rules: Dict[int, SnortRule] = {}

        # 2.1. Các rule không có content (rule cờ TCP, quét mạng, ...)
        for rule in self.no_content_rules:
            if rule.sid in proto_candidate_sids:
                candidate_rules[rule.sid] = rule

        # 2.2. Khớp nhanh nội dung HTTP
        if packet.http_data:
            if packet.http_data.uri:
                uri_hits = self.uri_matcher.search(packet.http_data.uri)
                uri_hits_lower = self.uri_matcher.search(packet.http_data.uri.lower())
                for _, rule in (uri_hits + uri_hits_lower):
                    if rule.sid in proto_candidate_sids:
                        candidate_rules[rule.sid] = rule

            if packet.http_data.headers:
                headers_str = "\r\n".join([f"{k}: {v}" for k, v in packet.http_data.headers.items()])
                hdr_hits = self.header_matcher.search(headers_str)
                hdr_hits_lower = self.header_matcher.search(headers_str.lower())
                for _, rule in (hdr_hits + hdr_hits_lower):
                    if rule.sid in proto_candidate_sids:
                        candidate_rules[rule.sid] = rule

            if packet.http_data.body:
                body_hits = self.body_matcher.search(packet.http_data.body)
                body_hits_lower = self.body_matcher.search(packet.http_data.body.lower())
                for _, rule in (body_hits + body_hits_lower):
                    if rule.sid in proto_candidate_sids:
                        candidate_rules[rule.sid] = rule

        # 2.3. Khớp nhanh nội dung Raw Payload
        if packet.raw_payload:
            raw_text = packet.raw_payload.decode("latin-1", errors="replace")
            raw_hits = self.raw_matcher.search(raw_text)
            raw_hits_lower = self.raw_matcher.search(raw_text.lower())
            for _, rule in (raw_hits + raw_hits_lower):
                if rule.sid in proto_candidate_sids:
                    candidate_rules[rule.sid] = rule

        matched_rules: List[SnortRule] = []

        # Tầng 3: Đánh giá chi tiết (Detailed Qualification) trên các rule ứng viên
        for rule in candidate_rules.values():
            if not self._match_port(packet.dst_port, rule.dst_port):
                continue
            if not self._match_port(packet.src_port, rule.src_port):
                continue

            if rule.flags and not self._match_flags(packet.tcp_flags, rule.flags):
                continue

            if rule.http_uri or rule.http_client_body or rule.http_header or rule.http_method:
                if not packet.http_data:
                    continue

                if rule.http_method and packet.http_data.method != rule.http_method:
                    continue

                target_text = ""
                if rule.http_uri:
                    target_text = packet.http_data.uri
                elif rule.http_client_body:
                    target_text = packet.http_data.body
                elif rule.http_header:
                    target_text = "\r\n".join([f"{k}: {v}" for k, v in packet.http_data.headers.items()])

                if not self._match_contents(target_text, rule.contents, rule.nocase):
                    continue

                if rule.pcre and not self._match_pcre(target_text, rule.pcre):
                    continue

            else:
                if rule.contents:
                    raw_text = packet.raw_payload.decode("latin-1", errors="replace")
                    if not self._match_contents(raw_text, rule.contents, rule.nocase):
                        continue
                    if rule.pcre and not self._match_pcre(raw_text, rule.pcre):
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

    def _match_flags(self, packet_flags: dict, rule_flags: str) -> bool:
        raw = packet_flags.get("raw_flags", "")
        if rule_flags == "0":
            return len(raw) == 0
        return all(f in raw for f in rule_flags)

    def _match_contents(self, text: str, contents: List[str], nocase: bool) -> bool:
        if not contents:
            return True
        target = text.lower() if nocase else text
        for c in contents:
            pattern = c.lower() if nocase else c
            if pattern not in target:
                return False
        return True

    def _match_pcre(self, text: str, pcre_str: str) -> bool:
        try:
            flags = 0
            pattern = pcre_str
            if pcre_str.startswith("/") and pcre_str.rfind("/") > 0:
                last_slash = pcre_str.rfind("/")
                pattern = pcre_str[1:last_slash]
                flag_str = pcre_str[last_slash + 1:]
                if "i" in flag_str:
                    flags |= re.IGNORECASE
            return bool(re.search(pattern, text, flags))
        except Exception:
            return False

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
            print(f"[ALERT sid:{rule.sid}] {rule.msg} | {packet.src_ip} -> {packet.dst_ip}")
