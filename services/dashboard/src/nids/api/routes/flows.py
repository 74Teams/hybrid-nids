from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Query, Response

from nids.api.routes.alerts import to_utc_naive
from nids.db.models import iso_utc
from nids.db.repository import EventRepository

router = APIRouter(prefix="/api/flows", tags=["Flows"])

FIELDS = ["id", "protocol", "src_ip", "src_port", "dst_ip", "dst_port", "duration", "fwd_packets", "bwd_packets",
          "fwd_bytes", "bwd_bytes", "tcp_flags", "alert_count", "end_reason"]


def flow_filters(src_ip: Optional[str] = None, dst_ip: Optional[str] = None, protocol: Optional[str] = None,
                 dst_port: Optional[int] = Query(None, ge=0, le=65535), since: Optional[datetime] = None,
                 until: Optional[datetime] = None, matched: Optional[bool] = None) -> Dict[str, Any]:
    """Bộ lọc trang Traffic; chuỗi rỗng coi như không lọc, `since`/`until` so với `first_seen`."""
    filters = {k: (v or None) if isinstance(v, str) else v for k, v in locals().items()}
    filters["since"], filters["until"] = to_utc_naive(since), to_utc_naive(until)
    return filters


def _to_dict(f) -> Dict[str, Any]:
    d = {k: getattr(f, k) for k in FIELDS}
    d["first_seen"] = iso_utc(f.first_seen)
    d["last_seen"] = iso_utc(f.last_seen)
    return d


@router.get("/stats")
def get_flow_stats(minutes: int = Query(60, ge=1, le=1440), buckets: int = Query(30, ge=1, le=120),
                   top: int = Query(8, ge=1, le=50)) -> Dict[str, Any]:
    """Top talker, top cổng đích, phân bố protocol và byte/flow/cảnh báo theo thời gian (cùng mốc cột)."""
    return EventRepository.get_flow_stats(minutes=minutes, buckets=buckets, top=top)


@router.get("/")
def get_flows(response: Response, limit: int = Query(50, ge=1, le=500), offset: int = Query(0, ge=0),
              filters: Dict[str, Any] = Depends(flow_filters)) -> List[Dict[str, Any]]:
    """Danh sách flow mới nhất theo bộ lọc; `matched=false` là traffic chưa khớp rule nào. Tổng ở header X-Total-Count."""
    response.headers["X-Total-Count"] = str(EventRepository.count_flows(**filters))
    return [_to_dict(f) for f in EventRepository.get_flows(limit=limit, offset=offset, **filters)]
