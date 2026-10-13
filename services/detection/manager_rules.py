import re
from pathlib import Path
from typing import List, Dict, Optional
from services.detection import SnortRule


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

        for rule_file in self.rules_dir.glob("*.rules"):
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
                        self.rules.append(rule)
                        if rule.sid:
                            self.rules_by_sid[rule.sid] = rule
                except Exception as e:
                    print(f"[RuleParser] Loi dong {line_no} trong {filepath.name}: {e}")

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
                    self.rules.append(rule)
                    if rule.sid:
                        self.rules_by_sid[rule.sid] = rule
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

    # ── PARSER ───────────────────────────────────────────────

    def parse_rule_line(self, line: str) -> Optional[SnortRule]:
        if "(" not in line or not line.endswith(")"):
            return None

        header_part, options_part = line.split("(", 1)
        options_part = options_part.rstrip(")").strip()

        header_tokens = header_part.strip().split()
        if len(header_tokens) < 7:
            return None

        action = header_tokens[0].lower()
        protocol = header_tokens[1].lower()
        src_ip = header_tokens[2]
        src_port = header_tokens[3]
        direction = header_tokens[4]
        dst_ip = header_tokens[5]
        dst_port = header_tokens[6]

        rule = SnortRule(
            action=action,
            protocol=protocol,
            src_ip=src_ip,
            src_port=src_port,
            direction=direction,
            dst_ip=dst_ip,
            dst_port=dst_port,
            raw_rule=line,
        )

        options = [opt.strip() for opt in options_part.split(";") if opt.strip()]
        for opt in options:
            if ":" in opt:
                key, val = opt.split(":", 1)
                key = key.strip().lower()
                val = val.strip().strip('"')

                if key == "msg":
                    rule.msg = val
                elif key == "sid":
                    rule.sid = int(val)
                elif key == "rev":
                    rule.rev = int(val)
                elif key == "classtype":
                    rule.classtype = val
                elif key == "severity" or key == "priority":
                    rule.severity = int(val)
                elif key == "content":
                    rule.contents.append(val)
                elif key == "flags":
                    rule.flags = val
                elif key == "pcre":
                    rule.pcre = val
                elif key == "http_method":
                    rule.http_method = val.upper()
            else:
                flag = opt.strip().lower()
                if flag == "nocase":
                    rule.nocase = True
                elif flag == "http_uri":
                    rule.http_uri = True
                elif flag == "http_client_body":
                    rule.http_client_body = True
                elif flag == "http_header":
                    rule.http_header = True

        return rule
