from datetime import datetime
from typing import Dict, Any, List
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
            session.add(event)
            session.commit()
            session.refresh(event)
            return event
        finally:
            session.close()

    @staticmethod
    def get_recent_events(limit: int = 50) -> List[EventModel]:
        from services.database import SessionLocal
        session = SessionLocal()
        try:
            return session.query(EventModel).order_by(EventModel.timestamp.desc()).limit(limit).all()
        finally:
            session.close()
