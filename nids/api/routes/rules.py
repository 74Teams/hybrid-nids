"""
Quản lý rule: xem, bật/tắt category (file .rules), override theo SID và sửa custom.rules.

API chỉ ghi file trong rules/ (state.yaml, custom.rules); engine tự nạp lại khi thấy file đổi
(nids/engine/main.py::RuleReloader), nên mọi thao tác ghi trả về "reload": "pending".
"""
import os
import secrets
import threading
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Body, Depends, Header, HTTPException, Request
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel

from nids.config import SETTINGS
from nids.engine.rule_manager import RuleManager

router = APIRouter(prefix="/api/rules", tags=["Rules"])

# Dải SID theo .claude/rules/snort-rules.md: (sid - 1000000) // 100
GROUPS = {0: "WEB-ATTACK", 1: "SCAN", 2: "DOS", 3: "AUTH", 4: "MALWARE-C2", 5: "RECON"}

API_KEY_ENV = "NIDS_API_KEY"
MAX_CUSTOM_BYTES = 1_000_000
PENDING = {"reload": "pending"}

# Các thao tác ghi đều là đọc-sửa-ghi state.yaml: khoá để hai request đồng thời không ghi đè nhau
_write_lock = threading.Lock()


def require_api_key(x_api_key: Optional[str] = Header(None)) -> None:
    """Thao tác ghi rule cần header X-API-Key khớp biến môi trường NIDS_API_KEY."""
    # shortcut: chỉ bảo vệ các endpoint ghi rule; DELETE /api/alerts vẫn mở cho tới khi có xác thực chung (#15)
    expected = os.environ.get(API_KEY_ENV)
    if not expected:
        raise HTTPException(503, f"Chưa đặt biến môi trường {API_KEY_ENV} nên chức năng sửa rule đang bị khoá")
    if not x_api_key or not secrets.compare_digest(x_api_key, expected):
        raise HTTPException(401, "Sai hoặc thiếu API key (header X-API-Key)")


def _manager() -> RuleManager:
    manager = RuleManager(SETTINGS.get("detection", {}).get("rules_dir", "rules"))
    manager.load_all_rules()
    return manager


def _rule_dict(r, overridden: set) -> Dict[str, Any]:
    return {
        "sid": r.sid, "rev": r.rev, "msg": r.msg, "action": r.action, "protocol": r.protocol,
        "src_ip": r.src_ip, "src_port": r.src_port, "direction": r.direction,
        "dst_ip": r.dst_ip, "dst_port": r.dst_port, "classtype": r.classtype,
        "severity": r.severity, "group": GROUPS.get((r.sid - 1000000) // 100, "KHÁC"),
        "category": r.category, "enabled": r.enabled, "default_enabled": r.default_enabled,
        "overridden": r.sid in overridden,
        "unsupported_options": r.unsupported_options, "raw_rule": r.raw_rule,
    }


@router.get("/")
def list_rules(category: Optional[str] = None, enabled: Optional[bool] = None,
               q: Optional[str] = None) -> List[Dict[str, Any]]:
    """Rule trong rules/ kèm category và trạng thái bật/tắt; lọc theo category, enabled, q (SID/mô tả/classtype)."""
    manager = _manager()
    if category is not None and category not in manager.catalog:
        raise HTTPException(404, f"Không có category {category}")
    overrides = manager.load_state().get("sid_overrides") or {}
    overridden = set(overrides.get("enable") or []) | set(overrides.get("disable") or [])
    rules = manager.catalog[category] if category is not None else manager.all_rules()
    needle = (q or "").strip().lower()
    return [
        _rule_dict(r, overridden)
        for r in sorted(rules, key=lambda r: r.sid)
        if (enabled is None or r.enabled == enabled)
        and (not needle or needle in str(r.sid) or needle in r.msg.lower() or needle in r.classtype.lower())
    ]


@router.get("/categories")
def list_categories() -> List[Dict[str, Any]]:
    """Mỗi file .rules là một category: trạng thái bật, số rule, số rule đang chạy."""
    return _manager().list_categories()


class CategoriesBody(BaseModel):
    enabled: List[str]


@router.put("/categories", dependencies=[Depends(require_api_key)])
def save_categories(body: CategoriesBody) -> Dict[str, Any]:
    """Lưu danh sách category được nạp (ô tick + Save ở tab Categories)."""
    with _write_lock:
        manager = _manager()
        try:
            manager.set_enabled_categories(body.enabled)
        except ValueError as e:
            raise HTTPException(400, str(e))
    return {**PENDING, "categories": manager.list_categories()}


class SidsBody(BaseModel):
    enable: List[int] = []
    disable: List[int] = []


@router.post("/sids", dependencies=[Depends(require_api_key)])
def apply_sids(body: SidsBody) -> Dict[str, Any]:
    """Nút Apply: gửi một lần mọi thay đổi bật/tắt SID."""
    if set(body.enable) & set(body.disable):
        raise HTTPException(400, "Một SID không thể vừa bật vừa tắt")
    with _write_lock:
        manager = _manager()
        try:
            manager.set_sid_state(enable=body.enable, disable=body.disable)
        except ValueError as e:
            raise HTTPException(400, str(e))
    return {**PENDING, "active": len(manager.rules)}


class ResetBody(BaseModel):
    category: Optional[str] = None


@router.post("/sids/reset", dependencies=[Depends(require_api_key)])
def reset_sids(body: ResetBody = Body(default_factory=ResetBody)) -> Dict[str, Any]:
    """Reset All (category rỗng) hoặc Reset Current: xoá override, trả rule về trạng thái mặc định trong file."""
    with _write_lock:
        manager = _manager()
        try:
            manager.reset_overrides(body.category)
        except KeyError:
            raise HTTPException(404, f"Không có category {body.category}")
    return {**PENDING, "active": len(manager.rules)}


class ToggleBody(BaseModel):
    enabled: bool


@router.post("/categories/{name:path}/all", dependencies=[Depends(require_api_key)])
def toggle_category_rules(name: str, body: ToggleBody) -> Dict[str, Any]:
    """Enable All / Disable All mọi rule trong một category."""
    with _write_lock:
        manager = _manager()
        try:
            manager.set_category_rules(name, body.enabled)
        except KeyError:
            raise HTTPException(404, f"Không có category {name}")
    return {**PENDING, "active": len(manager.rules)}


@router.get("/custom", response_class=PlainTextResponse)
def read_custom() -> str:
    """Toàn văn custom.rules (rule người dùng tự viết)."""
    path = _manager().custom_path
    return path.read_text(encoding="utf-8") if path.exists() else ""


@router.put("/custom", dependencies=[Depends(require_api_key)])
async def write_custom(request: Request) -> Dict[str, Any]:
    """Ghi toàn văn custom.rules (text/plain). Có dòng lỗi thì từ chối cả file, trả 422 kèm số dòng."""
    raw = await request.body()
    if len(raw) > MAX_CUSTOM_BYTES:
        raise HTTPException(413, f"custom.rules tối đa {MAX_CUSTOM_BYTES} byte")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(400, "Nội dung phải là UTF-8")
    with _write_lock:
        manager = _manager()
        errors, warnings = manager.validate_custom(text)
        if errors:
            raise HTTPException(422, {"errors": errors, "warnings": warnings})
        manager.write_custom(text if text.endswith("\n") or not text else text + "\n")
    return {**PENDING, "rules": len(manager.catalog.get("custom", [])), "warnings": warnings}
