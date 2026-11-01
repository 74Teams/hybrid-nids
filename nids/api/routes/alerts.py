import asyncio
import csv
import io
import logging
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Query, Response, WebSocket, WebSocketDisconnect
from typing import List, Dict, Any, Optional
from nids import realtime
from nids.config import get_redis_settings
from nids.db.models import iso_utc
from nids.db.repository import EventRepository

logger = logging.getLogger("nids.api")
router = APIRouter(prefix="/api/alerts", tags=["Alerts"])

# Mỗi WebSocket giữ một subscriber Redis riêng, nên giới hạn số kết nối
MAX_WS_CLIENTS = 20
_ws_clients = 0

# shortcut: CSV xuất tối đa ngần này dòng trong bộ nhớ; cần nhiều hơn thì chuyển sang StreamingResponse theo trang
EXPORT_LIMIT = 10000

FIELDS = ["id", "timestamp", "sid", "source_type", "attack_type", "severity", "src_ip", "src_port",
          "dst_ip", "dst_port", "protocol", "http_method", "http_uri", "summary", "status"]


def log_filters(source_type: Optional[str] = None, protocol: Optional[str] = None,
                src_ip: Optional[str] = None, dst_ip: Optional[str] = None, sid: Optional[int] = None,
                severity: Optional[int] = None, since: Optional[datetime] = None,
                until: Optional[datetime] = None, q: Optional[str] = None) -> Dict[str, Any]:
    """Bộ lọc dùng chung cho danh sách, xoá và xuất CSV; chuỗi rỗng coi như không lọc.

    `since`/`until` được đổi về UTC naive để so với cột timestamp (CSDL lưu UTC); giờ không kèm múi giờ coi là UTC.
    """
    filters = {k: (v or None) if isinstance(v, str) else v for k, v in locals().items()}
    for key in ("since", "until"):
        if filters[key] is not None and filters[key].tzinfo is not None:
            filters[key] = filters[key].astimezone(timezone.utc).replace(tzinfo=None)
    return filters


def _to_dict(e) -> Dict[str, Any]:
    d = {f: getattr(e, f) for f in FIELDS}
    d["timestamp"] = iso_utc(e.timestamp)
    return d


async def _relay(pubsub, ws: WebSocket) -> None:
    async for message in pubsub.listen():
        if message["type"] == "message":
            await ws.send_text(str(message["data"]))


async def _until_closed(ws: WebSocket) -> None:
    while True:
        await ws.receive_text()


async def _quietly(coro) -> None:
    try:
        await coro
    except Exception:
        pass


@router.websocket("/ws")
async def alerts_ws(ws: WebSocket) -> None:
    """Gửi id mỗi cảnh báo mới (từ Redis) để trình duyệt tải lại qua REST. Redis tắt hoặc lỗi thì đóng với 1013.

    Phải subscribe xong rồi mới accept: trình duyệt tải dữ liệu ở `onopen`, đăng ký muộn sẽ lỡ cảnh báo đến giữa chừng.
    """
    global _ws_clients
    cfg = get_redis_settings()
    if cfg is None or _ws_clients >= MAX_WS_CLIENTS:
        await ws.close(code=1013)
        return
    _ws_clients += 1
    client = pubsub = None
    tasks: List[asyncio.Task] = []
    try:
        client = realtime.async_client(cfg)
        pubsub = client.pubsub()
        await pubsub.subscribe(realtime.CHANNEL)
        if await pubsub.get_message(timeout=1) is None:
            raise ConnectionError("không nhận được xác nhận subscribe")
        await ws.accept()
        tasks = [asyncio.create_task(_relay(pubsub, ws)), asyncio.create_task(_until_closed(ws))]
        done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            if task.exception() and not isinstance(task.exception(), WebSocketDisconnect):
                raise task.exception()
    except Exception as e:
        logger.warning("WebSocket cảnh báo bị đóng do lỗi Redis: %s", e)
        await _quietly(ws.close(code=1013))
    finally:
        _ws_clients -= 1
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        if pubsub is not None:
            await _quietly(pubsub.aclose())
        if client is not None:
            await _quietly(client.aclose())


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
