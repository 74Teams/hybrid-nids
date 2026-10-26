

from fastapi import APIRouter
from typing import List, Dict, Any
from services.database.repository import EventRepository

router = APIRouter(prefix="/api/alerts", tags=["Alerts"])

@router.get("/stats")
def get_stats() -> Dict[str, Any]:
    """Thống kê cảnh báo cho dashboard: tổng, theo priority, top loại tấn công."""
    return EventRepository.get_stats()


@router.delete("/")
def clear_alerts() -> Dict[str, int]:
    """Xoá toàn bộ cảnh báo để bắt đầu lượt demo mới."""
    return {"deleted": EventRepository.clear_events()}


@router.get("/")
def get_alerts(limit: int = 50) -> List[Dict[str, Any]]:
    """Lấy danh sách các cảnh báo vi phạm gần nhất."""
    events = EventRepository.get_recent_events(limit=limit)
    return [
        {
            "id": e.id,
            "timestamp": e.timestamp.isoformat() if e.timestamp else None,
            "sid": e.sid,
            "source_type": e.source_type,
            "attack_type": e.attack_type,
            "severity": e.severity,
            "src_ip": e.src_ip,
            "src_port": e.src_port,
            "dst_ip": e.dst_ip,
            "dst_port": e.dst_port,
            "protocol": e.protocol,
            "http_method": e.http_method,
            "http_uri": e.http_uri,
            "summary": e.summary,
            "status": e.status,
        }
        for e in events
    ]
