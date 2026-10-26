from datetime import datetime
from datetime import timedelta
from typing import Dict, Any, List, Optional, Set
from sqlalchemy import case, func
from services.database.models import EventModel, EventPayloadModel


# ─────────────────────────────────────────────────────────────
# EVENT REPOSITORY
# ─────────────────────────────────────────────────────────────

class EventRepository:
    """Quản lý thao tác CRUD các sự kiện cảnh báo trong CSDL."""

    @staticmethod
    def save_alert(alert_data: Dict[str, Any]) -> EventModel:
        from services.database import SessionLocal
        session = SessionLocal()
        try:
            event = EventModel(
                timestamp=datetime.fromtimestamp(alert_data.get("timestamp", datetime.utcnow().timestamp())),
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
                status="NEW"
            )
            if alert_data.get("matched_content"):
                event.payload = EventPayloadModel(matched_content=alert_data["matched_content"])
            session.add(event)
            session.commit()
            session.refresh(event)
            return event
        finally:
            session.close()

    @staticmethod
    def get_recent_events(limit: int = 50, source_type: Optional[str] = None) -> List[EventModel]:
        from services.database import SessionLocal
        session = SessionLocal()
        try:
            query = session.query(EventModel)
            if source_type:
                query = query.filter(EventModel.source_type == source_type)
            return query.order_by(EventModel.timestamp.desc()).limit(limit).all()
        finally:
            session.close()

    @staticmethod
    def honeypot_attacker_ips(window_seconds: int = 3600) -> Set[str]:
        """IP đã chạm honeypot trong `window_seconds` giây gần nhất (honeypot không có người dùng hợp lệ)."""
        from services.database import SessionLocal
        session = SessionLocal()
        try:
            since = datetime.utcnow() - timedelta(seconds=window_seconds)
            rows = (session.query(EventModel.src_ip)
                    .filter(EventModel.source_type == "HONEYPOT", EventModel.timestamp >= since)
                    .distinct().all())
            return {r[0] for r in rows}
        finally:
            session.close()

    @staticmethod
    def get_attackers(limit: int = 20) -> List[Dict[str, Any]]:
        """Tổng hợp theo IP nguồn: số sự kiện honeypot, số cảnh báo NIDS, lần đầu/cuối thấy."""
        from services.database import SessionLocal
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
                 "first_seen": r.first.isoformat(), "last_seen": r.last.isoformat()}
                for r in rows
            ]
        finally:
            session.close()

    @staticmethod
    def get_stats(top: int = 8) -> Dict[str, Any]:
        """Thống kê cho dashboard: tổng cảnh báo, số cảnh báo theo priority và top loại tấn công."""
        from services.database import SessionLocal
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
    def clear_events() -> int:
        """Xoá toàn bộ cảnh báo (dùng để reset giữa các lượt demo); trả về số cảnh báo đã xoá."""
        from services.database import SessionLocal
        session = SessionLocal()
        try:
            session.query(EventPayloadModel).delete()
            deleted = session.query(EventModel).delete()
            session.commit()
            return deleted
        finally:
            session.close()
