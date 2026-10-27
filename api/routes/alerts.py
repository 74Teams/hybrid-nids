import csv
import io
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Query, Response
from typing import List, Dict, Any, Optional
from services.database.repository import EventRepository

router = APIRouter(prefix="/api/alerts", tags=["Alerts"])

# shortcut: CSV xuất tối đa ngần này dòng trong bộ nhớ; cần nhiều hơn thì chuyển sang StreamingResponse theo trang
EXPORT_LIMIT = 10000

FIELDS = ["id", "timestamp", "sid", "source_type", "attack_type", "severity", "src_ip", "src_port",
          "dst_ip", "dst_port", "protocol", "http_method", "http_uri", "summary", "status"]


def log_filters(source_type: Optional[str] = None, protocol: Optional[str] = None,
                src_ip: Optional[str] = None, dst_ip: Optional[str] = None, sid: Optional[int] = None,
                severity: Optional[int] = None, since: Optional[datetime] = None,
                until: Optional[datetime] = None, q: Optional[str] = None) -> Dict[str, Any]:
    """Bộ lọc dùng chung cho danh sách, xoá và xuất CSV; chuỗi rỗng coi như không lọc."""
    return {k: (v or None) if isinstance(v, str) else v for k, v in locals().items()}


def _to_dict(e) -> Dict[str, Any]:
    d = {f: getattr(e, f) for f in FIELDS}
    d["timestamp"] = e.timestamp.isoformat() if e.timestamp else None
    return d


@router.get("/stats")
def get_stats() -> Dict[str, Any]:
    """Thống kê cảnh báo cho dashboard: tổng, theo priority, top loại tấn công."""
    return EventRepository.get_stats()


@router.get("/attackers")
def get_attackers(limit: int = 20) -> List[Dict[str, Any]]:
    """IP tấn công: số sự kiện honeypot và số cảnh báo NIDS của từng IP."""
    return EventRepository.get_attackers(limit=limit)


@router.get("/timeline")
def get_timeline(minutes: int = Query(60, ge=1, le=1440), buckets: int = Query(30, ge=1, le=120)) -> Dict[str, Any]:
    """Số cảnh báo theo nguồn (NIDS / honeypot) theo thời gian, cho biểu đồ cột trên dashboard."""
    return EventRepository.get_timeline(minutes=minutes, buckets=buckets)


@router.delete("/")
def clear_alerts(filters: Dict[str, Any] = Depends(log_filters)) -> Dict[str, int]:
    """Xoá cảnh báo khớp bộ lọc; không truyền bộ lọc thì xoá toàn bộ (bắt đầu lượt demo mới)."""
    return {"deleted": EventRepository.clear_events(**filters)}


@router.get("/")
def get_alerts(response: Response, limit: int = 50, offset: int = 0,
               filters: Dict[str, Any] = Depends(log_filters)) -> List[Dict[str, Any]]:
    """Danh sách cảnh báo mới nhất theo bộ lọc; tổng số khớp nằm ở header X-Total-Count."""
    response.headers["X-Total-Count"] = str(EventRepository.count_events(**filters))
    return [_to_dict(e) for e in EventRepository.get_recent_events(limit=limit, offset=offset, **filters)]


@router.get("/export.csv")
def export_alerts(filters: Dict[str, Any] = Depends(log_filters)) -> Response:
    """Xuất cảnh báo khớp bộ lọc ra file CSV."""
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=FIELDS)
    writer.writeheader()
    for e in EventRepository.get_recent_events(limit=EXPORT_LIMIT, **filters):
        writer.writerow(_to_dict(e))
    # BOM để Excel đọc đúng tiếng Việt
    return Response("﻿" + buf.getvalue(), media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": 'attachment; filename="nids-logs.csv"'})


@router.get("/{event_id}")
def get_alert(event_id: int) -> Dict[str, Any]:
    """Chi tiết một cảnh báo kèm payload thô (matched_content, header, body, hex)."""
    event = EventRepository.get_event(event_id)
    if event is None:
        raise HTTPException(status_code=404, detail="Không tìm thấy cảnh báo")
    return {**_to_dict(event), "payload": EventRepository.get_payload(event_id)}


@router.delete("/{event_id}")
def delete_alert(event_id: int) -> Dict[str, int]:
    """Xoá một cảnh báo."""
    if not EventRepository.delete_event(event_id):
        raise HTTPException(status_code=404, detail="Không tìm thấy cảnh báo")
    return {"deleted": 1}
