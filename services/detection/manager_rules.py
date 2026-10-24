import re
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from services.detection import (
    SnortRule,
    ContentMatch,
    PcreMatch,
    DetectionFilter,
    BUFFER_PKT_DATA,
    STICKY_BUFFERS,
)

# Modifier của content (Snort 3 viết sau dấu phẩy: content:"x",nocase,depth 5)
CONTENT_MODIFIERS = {"nocase", "fast_pattern", "offset", "depth", "distance", "within"}

# Option chỉ mang metadata: engine chấp nhận nhưng không dùng khi so khớp
METADATA_OPTIONS = {"reference", "metadata", "gid", "service"}

PCRE_FLAGS = {"i": re.IGNORECASE, "s": re.DOTALL, "m": re.MULTILINE, "x": re.VERBOSE}


class RuleManager:
    """
    Quản lý tập luật (.rules).
    Hỗ trợ 2 nguồn nạp:
    - load_all_rules()  : Đọc từ file .rules trên disk (dùng khi startup ban đầu / testing)
    - load_from_db()    : Đọc từ DB (MySQL/SQLite) – nguồn sự thật chính sau khi có DB
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

        if not self.rules_dir.exists():
            return 0

        for rule_file in sorted(self.rules_dir.glob("*.rules")):
            self.load_rule_file(rule_file)

        return len(self.rules)

    def load_rule_file(self, filepath: Path) -> None:
        with open(filepath, "r", encoding="utf-8") as f:
            for line_no, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    rule = self.parse_rule_line(line)
                    if rule:
                        self._register(rule, f"dong {line_no} trong {filepath.name}")
                except Exception as e:
                    print(f"[RuleParser] Loi dong {line_no} trong {filepath.name}: {e}")

    def _register(self, rule: SnortRule, location: str) -> None:
        if rule.sid in self.rules_by_sid:
            print(f"[RuleParser] Bo qua SID trung {rule.sid} ({location})")
            return
        if rule.unsupported_options:
            print(
                f"[RuleParser] SID {rule.sid}: bo qua option khong ho tro "
                f"{rule.unsupported_options} ({location})"
            )
        self.rules.append(rule)
        self.rules_by_sid[rule.sid] = rule

    # ── LOAD FROM DB ─────────────────────────────────────────

    def load_from_db(self, db_session) -> int:
        """
        Nạp rules từ DB vào RAM, thay thế toàn bộ rules hiện tại.
        Chỉ load các rule có is_enabled = True.

        Args:
            db_session: SQLAlchemy Session đang hoạt động.

        Returns:
            Số rule được nạp vào RAM.
        """
        from services.database.models import RuleModel

        self.rules.clear()
        self.rules_by_sid.clear()

        db_rules = (
            db_session.query(RuleModel)
            .filter(RuleModel.is_enabled == True)
            .order_by(RuleModel.sid.asc())
            .all()
        )

        for db_rule in db_rules:
            try:
                rule = self.parse_rule_line(db_rule.raw_rule)
                if rule:
                    rule.is_enabled = db_rule.is_enabled
                    self._register(rule, "DB")
            except Exception as e:
                print(f"[RuleManager] Loi khi parse rule SID={db_rule.sid} tu DB: {e}")

        return len(self.rules)

    def reload_rules_from_db(self, db_session) -> int:
        """
        Hot-reload: Xóa toàn bộ rules trong RAM và nạp lại từ DB.
        Được gọi sau mỗi thao tác CRUD qua API.

        Returns:
            Số rule được nạp sau hot-reload.
        """
        count = self.load_from_db(db_session)
        print(f"[RuleManager] Hot-reload hoan tat: {count} rules dang hoat dong.")
        return count

    # ── PARSER (cú pháp Snort 3) ─────────────────────────────

    def parse_rule_line(self, line: str) -> Optional[SnortRule]:
        """
        Parse một dòng rule cú pháp Snort 3. Ném ValueError nếu rule sai cú pháp.

        Vẫn chấp nhận cú pháp cũ đang nằm trong DB: modifier đứng riêng sau content
        (content:"x"; nocase;), severity:N và http_method:"POST".
        """
        line = line.strip()
        if "(" not in line or not line.endswith(")"):
            return None

        header_part, options_part = line.split("(", 1)
        options_part = options_part[:-1].strip()

        header_tokens = header_part.split()
        if len(header_tokens) != 7:
            raise ValueError(f"header phai co 7 thanh phan, nhan duoc {len(header_tokens)}")

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
            if name == "http_method" and value:
                # Cú pháp cũ: http_method:"POST"
                rule.contents.append(
                    ContentMatch(pattern=self._unquote(value).upper(), buffer="http_method")
                )
            elif name in STICKY_BUFFERS:
                buffer, header_field = name, None
                if value:
                    parts = value.split()
                    if name != "http_header" or len(parts) != 2 or parts[0] != "field":
                        raise ValueError(f"tham so khong hop le cho {name}: {value}")
                    header_field = parts[1].lower()
            elif name == "content":
                rule.contents.append(self._parse_content(value, buffer, header_field))
            elif name == "pcre":
                rule.pcres.append(self._parse_pcre(value, buffer, header_field))
            elif name in CONTENT_MODIFIERS:
                # Cú pháp cũ kiểu Snort 2: modifier là option riêng, áp cho content ngay trước
                if not rule.contents:
                    raise ValueError(f"{name} khong co content dung truoc")
                self._apply_content_modifier(rule.contents[-1], name, value)
            elif name == "msg":
                rule.msg = self._unquote(value)
            elif name == "sid":
                rule.sid = int(value)
            elif name == "rev":
                rule.rev = int(value)
            elif name == "classtype":
                rule.classtype = value
            elif name in ("priority", "severity"):
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
            raise ValueError("rule thieu sid")

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
            raise ValueError("thieu dau ngoac kep dong")
        if "".join(buf).strip():
            raise ValueError("option cuoi cung phai ket thuc bang ';'")
        return options

    @staticmethod
    def _split_quoted(value: str) -> Tuple[str, str]:
        """Tách '"inner",rest' thành (inner chưa giải escape, rest)."""
        value = value.strip()
        if not value.startswith('"'):
            raise ValueError(f"gia tri phai nam trong dau ngoac kep: {value}")
        i = 1
        while i < len(value):
            if value[i] == "\\":
                i += 2
                continue
            if value[i] == '"':
                return value[1:i], value[i + 1:]
            i += 1
        raise ValueError(f"thieu dau ngoac kep dong: {value}")

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
            raise ValueError("doan hex trong content thieu dau '|' dong")
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
            raise ValueError("content rong")

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
            raise ValueError(f"modifier content khong ho tro: {name}")

    def _parse_pcre(self, value: str, buffer: str, header_field: Optional[str]) -> PcreMatch:
        """pcre:"/regex/flags" — hỗ trợ flag i, s, m, x."""
        value = value.strip()
        if value.startswith('"'):
            inner, rest = self._split_quoted(value)
            if rest.strip():
                raise ValueError(f"pcre co phan thua sau dau ngoac kep: {rest}")
        else:
            inner = value  # Cú pháp cũ không có ngoặc kép
        last_slash = inner.rfind("/")
        if not inner.startswith("/") or last_slash == 0:
            raise ValueError(f"pcre phai co dang /regex/flags: {inner}")

        flags = 0
        for flag in inner[last_slash + 1:]:
            if flag not in PCRE_FLAGS:
                raise ValueError(f"flag pcre khong ho tro: {flag}")
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
            raise ValueError(f"detection_filter khong hop le: {value}")
        return DetectionFilter(
            track=params["track"],
            count=int(params["count"]),
            seconds=int(params["seconds"]),
        )
