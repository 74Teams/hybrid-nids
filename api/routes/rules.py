from typing import Any, Dict, List
from fastapi import APIRouter
from config.config import SETTINGS
from services.detection.manager_rules import RuleManager

router = APIRouter(prefix="/api/rules", tags=["Rules"])

# Dải SID theo .claude/rules/snort-rules.md: (sid - 1000000) // 100
GROUPS = {0: "WEB-ATTACK", 1: "SCAN", 2: "DOS", 3: "AUTH", 4: "MALWARE-C2", 5: "RECON"}


@router.get("/")
def list_rules() -> List[Dict[str, Any]]:
    """Rule đang có trong rules/ (chỉ đọc; sửa file rồi khởi động lại engine để áp dụng)."""
    manager = RuleManager(SETTINGS.get("detection", {}).get("rules_dir", "rules"))
    manager.load_all_rules()
    return [
        {
            "sid": r.sid, "rev": r.rev, "msg": r.msg, "action": r.action, "protocol": r.protocol,
            "src_ip": r.src_ip, "src_port": r.src_port, "direction": r.direction,
            "dst_ip": r.dst_ip, "dst_port": r.dst_port, "classtype": r.classtype,
            "severity": r.severity, "group": GROUPS.get((r.sid - 1000000) // 100, "KHÁC"),
            "unsupported_options": r.unsupported_options, "raw_rule": r.raw_rule,
        }
        for r in sorted(manager.rules, key=lambda r: r.sid)
    ]
