from typing import Any, Dict, List

from fastapi import APIRouter, Query

from nids.db.models import iso_utc
from nids.db.repository import EventRepository

router = APIRouter(prefix="/api/redirects", tags=["Redirects"])

# Số dòng lịch sử tối đa trả về khi `active=false`
REDIRECT_LIMIT = 200


def _to_dict(row) -> Dict[str, Any]:
    return {"id": row.id, "ip": row.ip, "created_at": iso_utc(row.created_at), "expires_at": iso_utc(row.expires_at),
            "removed_at": iso_utc(row.removed_at), "alert_count": row.alert_count, "reason": row.reason}


@router.get("/", summary="IP đang bị chuyển hướng sang honeypot")
def list_redirects(active: bool = Query(True, description="true: chỉ lượt đang hiệu lực; false: cả đã gỡ")) -> List[Dict[str, Any]]:
    """Chỉ đọc. Mới đến cũ; `active=false` giới hạn 200 dòng gần nhất."""
    return [_to_dict(row) for row in EventRepository.list_redirects(active_only=active, limit=REDIRECT_LIMIT)]
