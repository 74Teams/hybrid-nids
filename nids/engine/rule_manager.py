import logging
import re
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from nids.engine.rule import (
    SnortRule,
    ContentMatch,
    PcreMatch,
    DetectionFilter,
    BUFFER_PKT_DATA,
    STICKY_BUFFERS,
)

logger = logging.getLogger("nids.rules")

# Option chỉ mang metadata: engine chấp nhận nhưng không dùng khi so khớp
METADATA_OPTIONS = {"reference", "metadata", "gid", "service"}

PCRE_FLAGS = {"i": re.IGNORECASE, "s": re.DOTALL, "m": re.MULTILINE, "x": re.VERBOSE}


class RuleManager:
    """
    Quản lý tập luật (.rules).
    Nguồn nạp duy nhất là file .rules trên disk: load_all_rules().
    """

    def __init__(self, rules_dir: str = "rules"):
        self.rules_dir = Path(rules_dir)
        self.rules: List[SnortRule] = []
        self.rules_by_sid: Dict[int, SnortRule] = {}

    # ── LOAD FROM FILE ───────────────────────────────────────

    def load_all_rules(self) -> int:
        """Đọc và parse tất cả file .rules trong thư mục rules_dir."""
        self.rules.clear()
        self.rules_by_sid.clear()

        if self.rules_dir.exists():
            for rule_file in sorted(self.rules_dir.glob("*.rules")):
                self.load_rule_file(rule_file)

        total = len(self.rules)
        if total:
            logger.info("Đã nạp %d rule từ %s", total, self.rules_dir)
        else:
            logger.warning(
                "Không nạp được rule nào từ %s, engine sẽ không phát hiện được tấn công nào",
                self.rules_dir,
            )
        unsupported = sum(1 for r in self.rules if r.unsupported_options)
        if unsupported:
            logger.warning(
                "%d rule có option không hỗ trợ, bật log_level: DEBUG để xem chi tiết", unsupported
            )
        return total

    def load_rule_file(self, filepath: Path) -> None:
        with open(filepath, "r", encoding="utf-8") as f:
            for line_no, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    rule = self.parse_rule_line(line)
                    if rule:
                        self._register(rule, f"dòng {line_no} trong {filepath.name}")
                except Exception as e:
                    logger.warning("Lỗi dòng %d trong %s: %s", line_no, filepath.name, e)

    def _register(self, rule: SnortRule, location: str) -> None:
        if rule.sid in self.rules_by_sid:
            logger.warning("Bỏ qua SID trùng %d (%s)", rule.sid, location)
            return
        if rule.unsupported_options:
            logger.debug(
                "SID %d: bỏ qua option không hỗ trợ %s (%s)",
                rule.sid, rule.unsupported_options, location,
            )
        self.rules.append(rule)
        self.rules_by_sid[rule.sid] = rule

    # ── PARSER (cú pháp Snort 3) ─────────────────────────────

    def parse_rule_line(self, line: str) -> Optional[SnortRule]:
        """
        Parse một dòng rule cú pháp Snort 3. Ném ValueError nếu rule sai cú pháp.
        """
        line = line.strip()
        if "(" not in line or not line.endswith(")"):
            return None

        header_part, options_part = line.split("(", 1)
        options_part = options_part[:-1].strip()

        header_tokens = header_part.split()
        if len(header_tokens) != 7:
            raise ValueError(f"header phải có 7 thành phần, nhận được {len(header_tokens)}")

        action, protocol, src_ip, src_port, direction, dst_ip, dst_port = header_tokens
        rule = SnortRule(
            action=action.lower(),
            protocol=protocol.lower(),
            src_ip=src_ip,
            src_port=src_port,
            direction=direction,
            dst_ip=dst_ip,
            dst_port=dst_port,
            raw_rule=line,
        )

        # Sticky buffer hiện hành: mọi content/pcre phía sau sẽ gắn vào buffer này
        buffer, header_field = BUFFER_PKT_DATA, None

        for name, value in self._split_options(options_part):
            if name in STICKY_BUFFERS:
                buffer, header_field = name, None
                if value:
                    parts = value.split()
                    if name != "http_header" or len(parts) != 2 or parts[0] != "field":
                        raise ValueError(f"tham số không hợp lệ cho {name}: {value}")
                    header_field = parts[1].lower()
            elif name == "content":
                rule.contents.append(self._parse_content(value, buffer, header_field))
            elif name == "pcre":
                rule.pcres.append(self._parse_pcre(value, buffer, header_field))
            elif name == "msg":
                rule.msg = self._unquote(value)
            elif name == "sid":
                rule.sid = int(value)
            elif name == "rev":
                rule.rev = int(value)
            elif name == "classtype":
                rule.classtype = value
            elif name == "priority":
                rule.severity = int(value)
            elif name == "flags":
                rule.flags = value.replace(" ", "")
            elif name == "flow":
                rule.flow = [t.strip().lower() for t in value.split(",") if t.strip()]
            elif name == "dsize":
                rule.dsize = value.replace(" ", "")
            elif name == "itype":
                rule.itype = value.replace(" ", "")
            elif name == "icode":
                rule.icode = value.replace(" ", "")
            elif name == "detection_filter":
                rule.detection_filter = self._parse_detection_filter(value)
            elif name in METADATA_OPTIONS:
                pass
            else:
                rule.unsupported_options.append(name)

        if not rule.sid:
            raise ValueError("rule thiếu sid")

        return rule

    @staticmethod
    def _split_options(text: str) -> List[Tuple[str, str]]:
        """Tách phần (...) thành các cặp (name, value) theo dấu ';' nằm NGOÀI dấu ngoặc kép."""
        options: List[Tuple[str, str]] = []
        buf: List[str] = []
        in_quotes = escaped = False

        for ch in text:
            if escaped:
                buf.append(ch)
                escaped = False
            elif ch == "\\":
                buf.append(ch)
                escaped = True
            elif ch == '"':
                buf.append(ch)
                in_quotes = not in_quotes
            elif ch == ";" and not in_quotes:
                opt = "".join(buf).strip()
                if opt:
                    name, _, value = opt.partition(":")
                    options.append((name.strip().lower(), value.strip()))
                buf = []
            else:
                buf.append(ch)

        if in_quotes:
            raise ValueError("thiếu dấu ngoặc kép đóng")
        if "".join(buf).strip():
            raise ValueError("option cuối cùng phải kết thúc bằng ';'")
        return options

    @staticmethod
    def _split_quoted(value: str) -> Tuple[str, str]:
        """Tách '"inner",rest' thành (inner chưa giải escape, rest)."""
        value = value.strip()
        if not value.startswith('"'):
            raise ValueError(f"giá trị phải nằm trong dấu ngoặc kép: {value}")
        i = 1
        while i < len(value):
            if value[i] == "\\":
                i += 2
                continue
            if value[i] == '"':
                return value[1:i], value[i + 1:]
            i += 1
        raise ValueError(f"thiếu dấu ngoặc kép đóng: {value}")

    @classmethod
    def _unquote(cls, value: str) -> str:
        if not value.startswith('"'):
            return value
        inner, _ = cls._split_quoted(value)
        return re.sub(r"\\(.)", r"\1", inner)

    @staticmethod
    def _decode_content(inner: str) -> str:
        """Giải mã escape (\\" \\; \\\\) và đoạn hex |0d 0a| thành chuỗi latin-1."""
        out: List[str] = []
        hex_buf = ""
        in_hex = False
        i = 0
        while i < len(inner):
            ch = inner[i]
            if in_hex:
                if ch == "|":
                    out.append(bytes.fromhex(hex_buf).decode("latin-1"))
                    hex_buf, in_hex = "", False
                else:
                    hex_buf += ch
            elif ch == "\\" and i + 1 < len(inner):
                out.append(inner[i + 1])
                i += 1
            elif ch == "|":
                in_hex = True
            else:
                out.append(ch)
            i += 1
        if in_hex:
            raise ValueError("đoạn hex trong content thiếu dấu '|' đóng")
        return "".join(out)

    def _parse_content(self, value: str, buffer: str, header_field: Optional[str]) -> ContentMatch:
        """content:[!]"pattern"[,nocase][,offset N][,depth N][,distance N][,within N][,fast_pattern]"""
        value = value.strip()
        negated = value.startswith("!")
        if negated:
            value = value[1:].lstrip()

        inner, rest = self._split_quoted(value)
        cm = ContentMatch(
            pattern=self._decode_content(inner),
            buffer=buffer,
            field=header_field,
            negated=negated,
        )
        if not cm.pattern:
            raise ValueError("content rỗng")

        for mod in rest.split(","):
            mod = mod.strip()
            if mod:
                key, _, arg = mod.partition(" ")
                self._apply_content_modifier(cm, key.lower(), arg.strip())
        return cm

    @staticmethod
    def _apply_content_modifier(cm: ContentMatch, name: str, arg: str) -> None:
        if name == "nocase":
            cm.nocase = True
        elif name == "fast_pattern":
            cm.fast_pattern = True
        elif name in ("offset", "depth", "distance", "within"):
            setattr(cm, name, int(arg))
        else:
            raise ValueError(f"modifier content không hỗ trợ: {name}")

    def _parse_pcre(self, value: str, buffer: str, header_field: Optional[str]) -> PcreMatch:
        """pcre:"/regex/flags" — hỗ trợ flag i, s, m, x."""
        value = value.strip()
        if value.startswith('"'):
            inner, rest = self._split_quoted(value)
            if rest.strip():
                raise ValueError(f"pcre có phần thừa sau dấu ngoặc kép: {rest}")
        else:
            inner = value  # Cú pháp cũ không có ngoặc kép
        last_slash = inner.rfind("/")
        if not inner.startswith("/") or last_slash == 0:
            raise ValueError(f"pcre phải có dạng /regex/flags: {inner}")

        flags = 0
        for flag in inner[last_slash + 1:]:
            if flag not in PCRE_FLAGS:
                raise ValueError(f"flag pcre không hỗ trợ: {flag}")
            flags |= PCRE_FLAGS[flag]

        return PcreMatch(
            pattern=inner,
            regex=re.compile(inner[1:last_slash], flags),
            buffer=buffer,
            field=header_field,
        )

    @staticmethod
    def _parse_detection_filter(value: str) -> DetectionFilter:
        """detection_filter:track by_src, count 10, seconds 1"""
        params = {}
        for part in value.split(","):
            key, _, arg = part.strip().partition(" ")
            params[key] = arg.strip()
        if params.get("track") not in ("by_src", "by_dst") or "count" not in params or "seconds" not in params:
            raise ValueError(f"detection_filter không hợp lệ: {value}")
        return DetectionFilter(
            track=params["track"],
            count=int(params["count"]),
            seconds=int(params["seconds"]),
        )
