"""
Rules CRUD API – 6 endpoints quản lý tập luật phát hiện xâm nhập.
"""
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from api.dependencies import get_db
from services.database.repository import RuleRepository
from services.database.schemas import (
    RuleCreate,
    RuleUpdate,
    RuleResponse,
    RuleListResponse,
)

router = APIRouter(prefix="/api/rules", tags=["Rules Management"])


def _rule_not_found(sid: int):
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Rule SID {sid} khong tim thay trong CSDL.",
    )


# ── 1. GET ALL ────────────────────────────────────────────────────────────────

@router.get("/", response_model=RuleListResponse, summary="Lay danh sach tat ca rules")
def get_all_rules(
    enabled_only: bool = False,
    db: Session = Depends(get_db),
):
    """
    Lấy toàn bộ rules trong CSDL.
    - **enabled_only=true**: Chỉ lấy các rule đang được bật.
    """
    rules = RuleRepository.get_all(db, enabled_only=enabled_only)
    enabled_count = sum(1 for r in rules if r.is_enabled)
    return RuleListResponse(
        total=len(rules),
        enabled=enabled_count,
        disabled=len(rules) - enabled_count,
        rules=[RuleResponse.model_validate(r) for r in rules],
    )


# ── 2. GET BY SID ─────────────────────────────────────────────────────────────

@router.get("/{sid}", response_model=RuleResponse, summary="Lay chi tiet 1 rule theo SID")
def get_rule_by_sid(sid: int, db: Session = Depends(get_db)):
    """Lấy chi tiết một rule theo **SID** (Snort ID)."""
    rule = RuleRepository.get_by_sid(db, sid)
    if not rule:
        _rule_not_found(sid)
    return RuleResponse.model_validate(rule)


# ── 3. CREATE ─────────────────────────────────────────────────────────────────

@router.post(
    "/",
    response_model=RuleResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Tao rule moi",
)
def create_rule(data: RuleCreate, db: Session = Depends(get_db)):
    """
    Tạo một rule phát hiện mới.
    - SID được **tự động sinh** (max SID hiện tại + 1, bắt đầu từ 2000001).
    - Rule sẽ ngay lập tức có hiệu lực trong Detection Engine sau hot-reload.
    """
    rule = RuleRepository.create(db, data)

    # Hot-reload Detection Engine nếu có trong app state
    _try_hot_reload(db)

    return RuleResponse.model_validate(rule)


# ── 4. UPDATE ─────────────────────────────────────────────────────────────────

@router.put("/{sid}", response_model=RuleResponse, summary="Cap nhat rule theo SID")
def update_rule(sid: int, data: RuleUpdate, db: Session = Depends(get_db)):
    """
    Cập nhật một hoặc nhiều field của rule (partial update).
    - `rev` được **tự động tăng** nếu không truyền tường minh.
    - `raw_rule` được **tự động rebuild** sau khi cập nhật.
    """
    rule = RuleRepository.update(db, sid, data)
    if not rule:
        _rule_not_found(sid)

    _try_hot_reload(db)

    return RuleResponse.model_validate(rule)


# ── 5. DELETE ─────────────────────────────────────────────────────────────────

@router.delete(
    "/{sid}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Xoa rule theo SID",
)
def delete_rule(sid: int, db: Session = Depends(get_db)):
    """
    Xóa vĩnh viễn một rule khỏi CSDL theo SID.
    Rule sẽ ngay lập tức bị loại khỏi Detection Engine.
    """
    deleted = RuleRepository.delete(db, sid)
    if not deleted:
        _rule_not_found(sid)

    _try_hot_reload(db)


# ── 6. TOGGLE ENABLE/DISABLE ─────────────────────────────────────────────────

@router.patch(
    "/{sid}/toggle",
    response_model=RuleResponse,
    summary="Bat/tat nhanh rule theo SID",
)
def toggle_rule(sid: int, db: Session = Depends(get_db)):
    """
    Bật/tắt nhanh một rule mà không cần xóa.
    - Rule bị tắt sẽ **không** được nạp vào Detection Engine.
    - Tiện lợi khi debug hoặc tạm vô hiệu hóa một rule gây nhiều false positive.
    """
    rule = RuleRepository.toggle_enabled(db, sid)
    if not rule:
        _rule_not_found(sid)

    _try_hot_reload(db)

    return RuleResponse.model_validate(rule)


# ── 7. RELOAD & SYNC ─────────────────────────────────────────────────────────

@router.post("/reload", summary="Hot-reload Detection Engine tu CSDL")
def reload_rules(db: Session = Depends(get_db)):
    """Buộc nạp lại toàn bộ rules đang kích hoạt từ CSDL vào Detection Engine trong RAM."""
    from api.main import get_detection_engine
    engine = get_detection_engine()
    if not engine:
        return {"status": "ok", "message": "Detection engine chua duoc gan vao API server (running standalone)."}
    count = engine.reload_rules_from_db(db)
    return {"status": "ok", "message": f"Da hot-reload thanh cong {count} rules vao Detection Engine."}


@router.post("/sync-files", summary="Dong bo rules tu cac file disk vao CSDL")
def sync_rules_from_files(db: Session = Depends(get_db)):
    """Quét toàn bộ thư mục rules/ và import các rule mới vào CSDL, sau đó hot-reload."""
    from services.detection.manager_rules import RuleManager
    from config.config import SETTINGS
    rules_dir = SETTINGS.get("detection", {}).get("rules_dir", "rules")
    manager = RuleManager(rules_dir)
    manager.load_all_rules()
    imported = RuleRepository.import_from_snort_rules(db, manager.rules)
    _try_hot_reload(db)
    total_in_db = len(RuleRepository.get_all(db))
    return {
        "status": "ok",
        "imported": imported,
        "total_in_db": total_in_db,
        "message": f"Da import/cap nhat {imported} rules tu file. Tong so rules trong CSDL: {total_in_db}."
    }


# ─────────────────────────────────────────────────────────────────────────────
# INTERNAL HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _try_hot_reload(db: Session) -> None:
    """
    Hot-reload Detection Engine từ DB sau mỗi thao tác write.
    Nếu engine chưa được khởi tạo (chạy API độc lập), bỏ qua.
    """
    try:
        from api.main import get_detection_engine
        engine = get_detection_engine()
        if engine:
            engine.reload_rules_from_db(db)
    except Exception:
        pass  # API có thể chạy độc lập không cần engine

