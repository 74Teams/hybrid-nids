"""Bảng lệnh demo thủ công trong docs/demo/kich-ban-demo.md phải khớp với SID có thật trong rules/local.rules."""
import re
from pathlib import Path

from services.detection.manager_rules import RuleManager

DOC_PATH = Path(__file__).resolve().parent.parent / "docs" / "demo" / "kich-ban-demo.md"
SECTION_HEADING = "Demo gõ lệnh thủ công"
SID_PATTERN = re.compile(r"\b(1000\d{3})\b")


def _section_text() -> str:
    text = DOC_PATH.read_text(encoding="utf-8")
    start = text.find(SECTION_HEADING)
    assert start != -1, f"Không tìm thấy mục '{SECTION_HEADING}' trong {DOC_PATH}"
    next_heading = re.search(r"^## ", text[start:], re.MULTILINE)
    end = start + next_heading.start() if next_heading else len(text)
    return text[start:end]


def _manual_command_sids() -> set:
    table_lines = "\n".join(
        line for line in _section_text().splitlines() if line.strip().startswith("|")
    )
    return {int(sid) for sid in SID_PATTERN.findall(table_lines)}


def test_manual_command_sids_exist_in_ruleset():
    manager = RuleManager("rules")
    manager.load_all_rules()
    sids = _manual_command_sids()
    missing = sids - set(manager.rules_by_sid)
    assert not missing, f"SID trong bảng lệnh demo không có trong rules/local.rules: {sorted(missing)}"


def test_manual_command_section_is_non_empty():
    sids = _manual_command_sids()
    assert len(sids) >= 20, f"Mục '{SECTION_HEADING}' chỉ có {len(sids)} SID, cần ít nhất 20"
