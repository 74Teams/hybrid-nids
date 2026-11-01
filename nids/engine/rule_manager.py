import logging
import os
import re
import shutil
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import yaml

from nids.config import get_rule_variables
from nids.engine.rule_header import parse_addrs, parse_ports
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

STATE_FILE = "state.yaml"
VENDOR_DIR = "vendor"
CUSTOM_CATEGORY = "custom"
CUSTOM_SID_MIN = 2000000

# Dòng "# alert ..." là rule bị tắt sẵn (kiểu bộ rule vendor), không phải comment thường
COMMENTED_RULE = re.compile(r"#\s*((?:alert|log|pass|drop|reject|sdrop)\s.*)$")


class RuleManager:
    """
    Quản lý tập luật (.rules).
    Mỗi file .rules là một category: file ở gốc rules_dir mặc định bật, file trong rules_dir/vendor/ mặc định tắt.
    Category bật/tắt và override theo SID lưu trong rules_dir/state.yaml (thiếu file = mặc định).
    """

    def __init__(self, rules_dir: str = "rules", variables: Optional[Dict[str, str]] = None):
        # Biến header rule: mặc định lấy từ settings.yaml (detection.variables), test có thể truyền riêng
        self.variables = dict(variables) if variables is not None else get_rule_variables()
        self.rules_dir = Path(rules_dir)
        self.state_path = self.rules_dir / STATE_FILE
        self.rules: List[SnortRule] = []                # Rule đang bật, đưa vào DetectionEngine
        self.rules_by_sid: Dict[int, SnortRule] = {}
        self.catalog: Dict[str, List[SnortRule]] = {}   # Mọi rule đã parse theo category, kể cả rule đang tắt
        self.category_paths: Dict[str, Path] = {}
        self.enabled_categories: set = set()

    # ── LOAD FROM FILE ───────────────────────────────────────

    def category_files(self) -> Dict[str, Path]:
        """Category -> file: tên file bỏ đuôi .rules, file vendor có tiền tố vendor/."""
        files: Dict[str, Path] = {}
        if self.rules_dir.exists():
            for path in sorted(self.rules_dir.glob("*.rules")):
                files[path.stem] = path
            for path in sorted((self.rules_dir / VENDOR_DIR).glob("*.rules")):
                files[f"{VENDOR_DIR}/{path.stem}"] = path
        return files

    def load_all_rules(self) -> int:
        """Parse mọi file .rules vào catalog, chỉ đưa rule đang bật (theo state.yaml) vào self.rules."""
        self.rules.clear()
        self.rules_by_sid.clear()
        self.catalog = {}
        self.category_paths = self.category_files()

        state = self.load_state()
        enabled = state.get("enabled_categories")
        if enabled is None:
            self.enabled_categories = {c for c in self.category_paths if not c.startswith(VENDOR_DIR + "/")}
        else:
            self.enabled_categories = set(enabled)
            for missing in sorted(self.enabled_categories - set(self.category_paths)):
                logger.warning("Category %s được bật trong %s nhưng không có file rule", missing, STATE_FILE)
        overrides = state.get("sid_overrides") or {}
        force_on, force_off = set(overrides.get("enable") or []), set(overrides.get("disable") or [])

        seen: Dict[int, str] = {}
        for category, path in self.category_paths.items():
            self.catalog[category] = []
            for rule in self._parse_file(path, category, seen):
                on = rule.sid in force_on or (rule.default_enabled and rule.sid not in force_off)
                rule.enabled = category in self.enabled_categories and on
                self.catalog[category].append(rule)
                if rule.enabled:
                    self._register(rule)

        total = len(self.rules)
        if total:
            logger.info("Đã nạp %d rule từ %s", total, self.rules_dir)
            loaded = ", ".join(
                f"{c} {sum(r.enabled for r in rs)}" for c, rs in self.catalog.items() if c in self.enabled_categories
            )
            disabled = ", ".join(c for c in self.catalog if c not in self.enabled_categories) or "không có"
            logger.info("Theo category: %s; category đang tắt: %s", loaded, disabled)
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

    def _parse_file(self, filepath: Path, category: str, seen: Dict[int, str]) -> List[SnortRule]:
        rules: List[SnortRule] = []
        with open(filepath, "r", encoding="utf-8") as f:
            for line_no, line in enumerate(f, 1):
                line = line.strip()
                commented = COMMENTED_RULE.match(line)
                if not line or (line.startswith("#") and not commented):
                    continue
                location = f"dòng {line_no} trong {filepath.name}"
                try:
                    rule = self.parse_rule_line(commented.group(1) if commented else line)
                except Exception as e:
                    # Rule bị comment sẵn hoặc thuộc category đang tắt: lỗi parse không ảnh hưởng engine, chỉ ghi DEBUG
                    quiet = commented or category not in self.enabled_categories
                    (logger.debug if quiet else logger.warning)("Lỗi dòng %d trong %s: %s", line_no, filepath.name, e)
                    continue
                if not rule:
                    continue
                if rule.sid in seen:
                    logger.warning("Bỏ qua SID trùng %d (%s, đã có ở %s)", rule.sid, location, seen[rule.sid])
                    continue
                seen[rule.sid] = location
                rule.category = category
                rule.default_enabled = not commented
                rules.append(rule)
        return rules

    def _register(self, rule: SnortRule) -> None:
        if rule.unsupported_options:
            logger.debug(
                "SID %d: bỏ qua option không hỗ trợ %s (category %s)",
                rule.sid, rule.unsupported_options, rule.category,
            )
        self.rules.append(rule)
        self.rules_by_sid[rule.sid] = rule

    def signature(self) -> Tuple[Tuple[str, int], ...]:
        """Dấu thời gian sửa đổi của các file rule và state.yaml, để engine biết khi nào cần nạp lại."""
        paths = list(self.category_files().values()) + [self.state_path]
        return tuple((str(p), p.stat().st_mtime_ns) for p in paths if p.exists())

    # ── TRẠNG THÁI BẬT/TẮT (state.yaml) ──────────────────────

    def load_state(self) -> Dict[str, Any]:
        if not self.state_path.exists():
            return {}
        try:
            data = yaml.safe_load(self.state_path.read_text(encoding="utf-8"))
        except Exception as e:
            logger.error("Không đọc được %s, dùng trạng thái mặc định: %s", self.state_path, e)
            return {}
        return data if isinstance(data, dict) else {}

    def save_state(self, state: Dict[str, Any]) -> None:
        self._write_atomic(self.state_path, yaml.safe_dump(state, allow_unicode=True, sort_keys=False))

    @staticmethod
    def _write_atomic(path: Path, text: str) -> None:
        # Ghi file tạm rồi đổi tên để engine không bao giờ đọc phải file ghi dở
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_text(text, encoding="utf-8")
        os.replace(tmp, path)

    def all_rules(self) -> List[SnortRule]:
        return [r for rules in self.catalog.values() for r in rules]

    def list_categories(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": c,
                "enabled": c in self.enabled_categories,
                "rule_count": len(rules),
                "active_count": sum(r.enabled for r in rules),
                "vendor": c.startswith(VENDOR_DIR + "/"),
                "editable": c == CUSTOM_CATEGORY,
            }
            for c, rules in self.catalog.items()
        ]

    def category_rules(self, category: str) -> List[SnortRule]:
        if category not in self.catalog:
            raise KeyError(category)
        return self.catalog[category]

    def set_enabled_categories(self, names: Iterable[str]) -> None:
        names = set(names)
        unknown = names - set(self.catalog)
        if unknown:
            raise ValueError(f"category không tồn tại: {', '.join(sorted(unknown))}")
        state = self.load_state()
        state["enabled_categories"] = [c for c in self.catalog if c in names]
        self.save_state(state)
        self.load_all_rules()

    def set_sid_state(self, enable: Iterable[int] = (), disable: Iterable[int] = ()) -> None:
        """Ghi override; SID được đặt về đúng trạng thái mặc định thì xoá override cho gọn."""
        changes = [(sid, True) for sid in enable] + [(sid, False) for sid in disable]
        known = {r.sid: r for r in self.all_rules()}
        unknown = sorted({sid for sid, _ in changes if sid not in known})
        if unknown:
            raise ValueError(f"SID không tồn tại: {', '.join(map(str, unknown))}")
        state = self.load_state()
        overrides = state.get("sid_overrides") or {}
        on, off = set(overrides.get("enable") or []), set(overrides.get("disable") or [])
        for sid, want in changes:
            on.discard(sid)
            off.discard(sid)
            if want != known[sid].default_enabled:
                (on if want else off).add(sid)
        self._save_overrides(state, on, off)

    def reset_overrides(self, category: Optional[str] = None) -> None:
        """Xoá override của mọi SID (Reset All) hoặc chỉ của một category (Reset Current)."""
        state = self.load_state()
        overrides = state.get("sid_overrides") or {}
        on, off = set(overrides.get("enable") or []), set(overrides.get("disable") or [])
        if category is None:
            on, off = set(), set()
        else:
            sids = {r.sid for r in self.category_rules(category)}
            on, off = on - sids, off - sids
        self._save_overrides(state, on, off)

    def set_category_rules(self, category: str, enabled: bool) -> None:
        """Enable All / Disable All trong một category."""
        sids = [r.sid for r in self.category_rules(category)]
        self.set_sid_state(enable=sids if enabled else (), disable=() if enabled else sids)

    def _save_overrides(self, state: Dict[str, Any], on: set, off: set) -> None:
        state["sid_overrides"] = {"enable": sorted(on), "disable": sorted(off)}
        self.save_state(state)
        self.load_all_rules()

    # ── CUSTOM RULES (sửa từ web) ────────────────────────────

    @property
    def custom_path(self) -> Path:
        return self.rules_dir / f"{CUSTOM_CATEGORY}.rules"

    def validate_custom(self, text: str) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """Kiểm tra nội dung custom.rules, trả về (lỗi, cảnh báo) theo số dòng."""
        errors: List[Dict[str, Any]] = []
        warnings: List[Dict[str, Any]] = []
        others = {r.sid: c for c, rules in self.catalog.items() if c != CUSTOM_CATEGORY for r in rules}
        seen: set = set()
        for line_no, line in enumerate(text.splitlines(), 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                rule = self.parse_rule_line(line)
                if rule is None:
                    raise ValueError("rule phải có dạng: header (option; option;)")
            except Exception as e:
                errors.append({"line": line_no, "error": str(e)})
                continue
            if rule.sid < CUSTOM_SID_MIN:
                errors.append({"line": line_no, "error": f"SID {rule.sid} nằm ngoài dải custom (≥ {CUSTOM_SID_MIN})"})
            elif rule.sid in seen:
                errors.append({"line": line_no, "error": f"SID {rule.sid} bị trùng trong custom.rules"})
            elif rule.sid in others:
                errors.append({"line": line_no, "error": f"SID {rule.sid} đã có trong category {others[rule.sid]}"})
            seen.add(rule.sid)
            if rule.unsupported_options:
                warnings.append({"line": line_no, "warning": "option chưa hỗ trợ: " + ", ".join(rule.unsupported_options)})
        return errors, warnings

    def write_custom(self, text: str) -> None:
        """Ghi custom.rules (đã validate), giữ bản trước ở custom.rules.bak."""
        if self.custom_path.exists():
            shutil.copyfile(self.custom_path, self.custom_path.with_name(self.custom_path.name + ".bak"))
        self._write_atomic(self.custom_path, text)
        self.load_all_rules()

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
        if direction not in ("->", "<>"):
            raise ValueError(f"hướng phải là '->' hoặc '<>', nhận được '{direction}'")
        rule = SnortRule(
            action=action.lower(),
            protocol=protocol.lower(),
            src_ip=src_ip,
            src_port=src_port,
            direction=direction,
            dst_ip=dst_ip,
            dst_port=dst_port,
            src_addrs=parse_addrs(src_ip, self.variables),
            src_ports=parse_ports(src_port, self.variables),
            dst_addrs=parse_addrs(dst_ip, self.variables),
            dst_ports=parse_ports(dst_port, self.variables),
            raw_rule=line,
        )
        rule.header_any = (rule.src_addrs.wildcard and rule.src_ports.wildcard
                           and rule.dst_addrs.wildcard and rule.dst_ports.wildcard)

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
