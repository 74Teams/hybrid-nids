import time
from datetime import datetime, timedelta
from typing import Dict, Any, Iterable, List, Optional, Set, Tuple
from sqlalchemy import String, case, cast, distinct, func
from sqlalchemy.orm import joinedload
from nids.db.models import EventModel, EventPayloadModel, FlowModel, RedirectModel, iso_utc, utc_from_epoch, utc_now
from nids.engine.flow import Flow
from nids.realtime import publish_alert


# ─────────────────────────────────────────────────────────────
# EVENT REPOSITORY
# ─────────────────────────────────────────────────────────────

class EventRepository:
    """Quản lý thao tác CRUD các sự kiện cảnh báo trong CSDL."""

    @staticmethod
    def save_alert(alert_data: Dict[str, Any]) -> EventModel:
        from nids.db import SessionLocal
        session = SessionLocal()
        try:
            event = EventModel(
                timestamp=utc_from_epoch(alert_data.get("timestamp", time.time())),
                sid=alert_data.get("sid"),
                source_type=alert_data.get("source_type", "RULE_ENGINE"),
                attack_type=alert_data.get("classtype") or "UNKNOWN_ATTACK",
                severity=alert_data.get("severity", 2),
                src_ip=alert_data.get("src_ip", ""),
                src_port=alert_data.get("src_port"),
                dst_ip=alert_data.get("dst_ip", ""),
                dst_port=alert_data.get("dst_port"),
                protocol=alert_data.get("protocol", "TCP"),
                http_method=alert_data.get("http_method"),
                http_uri=alert_data.get("http_uri"),
                summary=alert_data.get("msg", ""),
                status="NEW",
                session_id=alert_data.get("session_id")
            )
            if alert_data.get("matched_content"):
                event.payload = EventPayloadModel(matched_content=alert_data["matched_content"])
            session.add(event)
            session.commit()
            session.refresh(event)
            publish_alert(event.id)
            return event
        finally:
            session.close()

    @staticmethod
    def _apply_filters(query, source_type: Optional[str] = None, protocol: Optional[str] = None,
                       src_ip: Optional[str] = None, dst_ip: Optional[str] = None, sid: Optional[int] = None,
                       severity: Optional[int] = None, since: Optional[datetime] = None,
                       until: Optional[datetime] = None, q: Optional[str] = None):
        """Áp bộ lọc trang Logs; tham số None nghĩa là không lọc theo trường đó."""
        if source_type:
            query = query.filter(EventModel.source_type == source_type)
        if protocol:
            query = query.filter(func.lower(EventModel.protocol) == protocol.lower())
        if src_ip:
            query = query.filter(EventModel.src_ip == src_ip)
        if dst_ip:
            query = query.filter(EventModel.dst_ip == dst_ip)
        if sid is not None:
            query = query.filter(EventModel.sid == sid)
        if severity is not None:
            query = query.filter(EventModel.severity == severity)
        if since:
            query = query.filter(EventModel.timestamp >= since)
        if until:
            query = query.filter(EventModel.timestamp <= until)
        if q:
            query = query.filter(EventModel.summary.contains(q))
        return query

    @staticmethod
    def get_recent_events(limit: int = 50, source_type: Optional[str] = None, offset: int = 0,
                          **filters) -> List[EventModel]:
        from nids.db import SessionLocal
        session = SessionLocal()
        try:
            query = EventRepository._apply_filters(session.query(EventModel), source_type=source_type, **filters)
            return query.order_by(EventModel.timestamp.desc(), EventModel.id.desc()).offset(offset).limit(limit).all()
        finally:
            session.close()

    @staticmethod
    def get_session_events(session_id: str, limit: int = 1000) -> List[EventModel]:
        """Sự kiện của một phiên honeypot (kèm payload), cũ đến mới."""
        from nids.db import SessionLocal
        session = SessionLocal()
        try:
            return (session.query(EventModel).options(joinedload(EventModel.payload))
                    .filter(EventModel.session_id == session_id)
                    .order_by(EventModel.timestamp.asc(), EventModel.id.asc()).limit(limit).all())
        finally:
            session.close()

    # Sự kiện không có session_id (rule engine, honeypot cũ) tự thành nhóm một dòng, khoá là id của nó
    _GROUP_KEY = func.coalesce(EventModel.session_id, cast(EventModel.id, String))

    @staticmethod
    def get_session_groups(limit: int = 50, offset: int = 0, **filters) -> List[Dict[str, Any]]:
        """Danh sách theo nhóm (phiên hoặc sự kiện lẻ), nhóm hoạt động gần nhất ở trên.

        Bộ lọc áp lên từng sự kiện trước khi gom; mỗi nhóm trả sự kiện đầu tiên cùng số sự kiện khớp,
        thời điểm sự kiện cuối và priority nặng nhất (số nhỏ nhất).
        """
        from nids.db import SessionLocal
        last_ts = func.max(EventModel.timestamp)
        session = SessionLocal()
        try:
            groups = (EventRepository._apply_filters(
                          session.query(func.min(EventModel.id), func.count(EventModel.id), last_ts,
                                        func.min(EventModel.severity)), **filters)
                      .group_by(EventRepository._GROUP_KEY).order_by(last_ts.desc(), func.max(EventModel.id).desc())
                      .offset(offset).limit(limit).all())
            firsts = {e.id: e for e in session.query(EventModel).filter(EventModel.id.in_([g[0] for g in groups]))}
            return [{"event": firsts[first_id], "event_count": n, "last_timestamp": last, "severity": severity}
                    for first_id, n, last, severity in groups]
        finally:
            session.close()

    @staticmethod
    def count_session_groups(**filters) -> int:
        from nids.db import SessionLocal
        session = SessionLocal()
        try:
            query = session.query(func.count(distinct(EventRepository._GROUP_KEY)))
            return EventRepository._apply_filters(query, **filters).scalar() or 0
        finally:
            session.close()

    @staticmethod
    def count_events(**filters) -> int:
        from nids.db import SessionLocal
        session = SessionLocal()
        try:
            return EventRepository._apply_filters(session.query(func.count(EventModel.id)), **filters).scalar() or 0
        finally:
            session.close()

    @staticmethod
    def get_payload(event_id: int) -> Optional[Dict[str, Any]]:
        """Payload thô của một sự kiện (None nếu sự kiện không có payload)."""
        from nids.db import SessionLocal
        session = SessionLocal()
        try:
            p = session.query(EventPayloadModel).filter(EventPayloadModel.event_id == event_id).first()
            if p is None:
                return None
            return {"matched_content": p.matched_content, "http_headers": p.http_headers,
                    "http_body": p.http_body, "packet_raw_hex": p.packet_raw_hex}
        finally:
            session.close()

    @staticmethod
    def get_event(event_id: int) -> Optional[EventModel]:
        from nids.db import SessionLocal
        session = SessionLocal()
        try:
            return session.get(EventModel, event_id)
        finally:
            session.close()

    @staticmethod
    def honeypot_attacker_ips(window_seconds: int = 3600) -> Set[str]:
        """IP đã chạm honeypot trong `window_seconds` giây gần nhất (honeypot không có người dùng hợp lệ)."""
        from nids.db import SessionLocal
        session = SessionLocal()
        try:
            since = utc_now() - timedelta(seconds=window_seconds)
            rows = (session.query(EventModel.src_ip)
                    .filter(EventModel.source_type == "HONEYPOT", EventModel.timestamp >= since)
                    .distinct().all())
            return {r[0] for r in rows}
        finally:
            session.close()

    @staticmethod
    def get_attackers(limit: int = 20) -> List[Dict[str, Any]]:
        """Tổng hợp theo IP nguồn: số sự kiện honeypot, số cảnh báo NIDS, lần đầu/cuối thấy."""
        from nids.db import SessionLocal
        session = SessionLocal()
        try:
            hp = func.sum(case((EventModel.source_type == "HONEYPOT", 1), else_=0))
            rows = (
                session.query(EventModel.src_ip, hp.label("hp"), func.count(EventModel.id).label("n"),
                              func.min(EventModel.timestamp).label("first"),
                              func.max(EventModel.timestamp).label("last"))
                .group_by(EventModel.src_ip)
                .order_by(func.count(EventModel.id).desc())
                .limit(limit)
                .all()
            )
            return [
                {"src_ip": r.src_ip, "honeypot_events": int(r.hp or 0), "nids_alerts": r.n - int(r.hp or 0),
                 "first_seen": iso_utc(r.first), "last_seen": iso_utc(r.last)}
                for r in rows
            ]
        finally:
            session.close()

    @staticmethod
    def get_timeline(minutes: int = 60, buckets: int = 30) -> Dict[str, Any]:
        """Số cảnh báo NIDS / honeypot trong `minutes` phút gần nhất, chia đều thành `buckets` cột (cột trống = 0)."""
        from nids.db import SessionLocal
        step = minutes * 60 / buckets
        start = utc_now() - timedelta(minutes=minutes)
        session = SessionLocal()
        try:
            rows = (session.query(EventModel.timestamp, EventModel.source_type)
                    .filter(EventModel.timestamp >= start).all())
        finally:
            session.close()
        cols = [{"t": iso_utc(start + timedelta(seconds=i * step), "seconds"), "nids": 0, "honeypot": 0}
                for i in range(buckets)]
        for ts, source in rows:
            i = min(int((ts - start).total_seconds() // step), buckets - 1)
            cols[i]["honeypot" if source == "HONEYPOT" else "nids"] += 1
        return {"step_seconds": step, "buckets": cols}

    @staticmethod
    def get_stats(top: int = 8) -> Dict[str, Any]:
        """Thống kê cho dashboard: tổng cảnh báo, số cảnh báo theo priority và top loại tấn công."""
        from nids.db import SessionLocal
        session = SessionLocal()
        try:
            total = session.query(func.count(EventModel.id)).scalar() or 0
            by_severity = {"1": 0, "2": 0, "3": 0}
            for severity, count in session.query(EventModel.severity, func.count(EventModel.id)).group_by(EventModel.severity):
                by_severity[str(severity)] = count
            rows = (
                session.query(EventModel.summary, EventModel.sid, func.count(EventModel.id).label("n"))
                .group_by(EventModel.summary, EventModel.sid)
                .order_by(func.count(EventModel.id).desc())
                .limit(top)
                .all()
            )
            return {
                "total": total,
                "by_severity": by_severity,
                "top_attacks": [{"summary": r.summary, "sid": r.sid, "count": r.n} for r in rows],
            }
        finally:
            session.close()

    @staticmethod
    def save_flows(flows: Iterable[Flow]) -> int:
        """Ghi một lô flow đã kết thúc trong một giao dịch; trả về số flow đã ghi."""
        from nids.db import SessionLocal
        rows = [
            FlowModel(
                first_seen=utc_from_epoch(f.first_seen), last_seen=utc_from_epoch(f.last_seen),
                duration=f.duration, protocol=f.protocol, src_ip=f.src_ip, src_port=f.src_port,
                dst_ip=f.dst_ip, dst_port=f.dst_port, fwd_packets=f.fwd_packets, bwd_packets=f.bwd_packets,
                fwd_bytes=f.fwd_bytes, bwd_bytes=f.bwd_bytes, tcp_flags=f.tcp_flags,
                alert_count=f.alert_count, end_reason=f.end_reason,
            )
            for f in flows
        ]
        if not rows:
            return 0
        session = SessionLocal()
        try:
            session.add_all(rows)
            session.commit()
            return len(rows)
        finally:
            session.close()

    @staticmethod
    def delete_flows_before(cutoff: datetime) -> int:
        """Xoá flow được ghi trước `cutoff` (UTC naive); tính theo thời điểm ghi, không theo giờ của gói."""
        from nids.db import SessionLocal
        session = SessionLocal()
        try:
            deleted = session.query(FlowModel).filter(FlowModel.created_at < cutoff).delete()
            session.commit()
            return deleted
        finally:
            session.close()

    @staticmethod
    def delete_event(event_id: int) -> bool:
        """Xoá một cảnh báo cùng payload của nó; False nếu không có."""
        from nids.db import SessionLocal
        session = SessionLocal()
        try:
            session.query(EventPayloadModel).filter(EventPayloadModel.event_id == event_id).delete()
            deleted = session.query(EventModel).filter(EventModel.id == event_id).delete()
            session.commit()
            return bool(deleted)
        finally:
            session.close()

    @staticmethod
    def clear_events(**filters) -> int:
        """Xoá cảnh báo khớp bộ lọc (không lọc = xoá hết, dùng reset giữa các lượt demo); trả về số đã xoá."""
        from nids.db import SessionLocal
        session = SessionLocal()
        try:
            if not any(v is not None for v in filters.values()):
                session.query(EventPayloadModel).delete()
                deleted = session.query(EventModel).delete()
                session.commit()
                return deleted
            ids = [r[0] for r in EventRepository._apply_filters(session.query(EventModel.id), **filters)]
            if not ids:
                return 0
            session.query(EventPayloadModel).filter(EventPayloadModel.event_id.in_(ids)).delete(synchronize_session=False)
            deleted = session.query(EventModel).filter(EventModel.id.in_(ids)).delete(synchronize_session=False)
            session.commit()
            return deleted
        finally:
            session.close()

    # ── Chuyển hướng IP đáng ngờ sang honeypot (nids.redirector) ──

    @staticmethod
    def suspicious_ips(window_seconds: int, min_alerts: int, max_priority: int) -> List[Tuple[str, int]]:
        """IP có ít nhất `min_alerts` cảnh báo rule engine mức `max_priority` trở lên (số nhỏ = nặng) trong cửa sổ; kèm số cảnh báo."""
        from nids.db import SessionLocal
        session = SessionLocal()
        try:
            since = utc_now() - timedelta(seconds=window_seconds)
            count = func.count(EventModel.id)
            rows = (session.query(EventModel.src_ip, count)
                    .filter(EventModel.source_type == "RULE_ENGINE", EventModel.severity <= max_priority,
                            EventModel.timestamp >= since)
                    .group_by(EventModel.src_ip).having(count >= min_alerts).all())
            return [(ip, n) for ip, n in rows]
        finally:
            session.close()

    @staticmethod
    def add_redirect(ip: str, ttl_seconds: int, alert_count: int = 0, reason: str = "") -> RedirectModel:
        from nids.db import SessionLocal
        session = SessionLocal()
        try:
            now = utc_now()
            row = RedirectModel(ip=ip, created_at=now, expires_at=now + timedelta(seconds=ttl_seconds),
                                alert_count=alert_count, reason=reason)
            session.add(row)
            session.commit()
            session.refresh(row)
            return row
        finally:
            session.close()

    @staticmethod
    def active_redirects() -> List[RedirectModel]:
        """Các lượt chuyển hướng chưa gỡ và chưa hết hạn, cũ đến mới."""
        from nids.db import SessionLocal
        session = SessionLocal()
        try:
            return (session.query(RedirectModel)
                    .filter(RedirectModel.removed_at.is_(None), RedirectModel.expires_at > utc_now())
                    .order_by(RedirectModel.id).all())
        finally:
            session.close()

    @staticmethod
    def expire_redirects() -> List[str]:
        """Đánh dấu đã gỡ các lượt chuyển hướng hết hạn; trả về IP của chúng."""
        from nids.db import SessionLocal
        session = SessionLocal()
        try:
            now = utc_now()
            rows = (session.query(RedirectModel)
                    .filter(RedirectModel.removed_at.is_(None), RedirectModel.expires_at <= now).all())
            for row in rows:
                row.removed_at = now
            session.commit()
            return [row.ip for row in rows]
        finally:
            session.close()

    @staticmethod
    def release_redirects() -> int:
        """Gỡ mọi lượt chuyển hướng đang hiệu lực (khi redirector dừng); trả về số dòng đã gỡ."""
        from nids.db import SessionLocal
        session = SessionLocal()
        try:
            now = utc_now()
            rows = session.query(RedirectModel).filter(RedirectModel.removed_at.is_(None)).all()
            for row in rows:
                row.removed_at = now
            session.commit()
            return len(rows)
        finally:
            session.close()

    @staticmethod
    def list_redirects(active_only: bool = True, limit: int = 200) -> List[RedirectModel]:
        """Danh sách chuyển hướng mới đến cũ; `active_only` chỉ lấy dòng đang hiệu lực."""
        from nids.db import SessionLocal
        session = SessionLocal()
        try:
            query = session.query(RedirectModel)
            if active_only:
                query = query.filter(RedirectModel.removed_at.is_(None), RedirectModel.expires_at > utc_now())
            return query.order_by(RedirectModel.id.desc()).limit(limit).all()
        finally:
            session.close()
