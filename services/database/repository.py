from datetime import datetime
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from services.database.models import EventModel, EventPayloadModel, RuleModel
from services.database.schemas import RuleCreate, RuleUpdate


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


# ─────────────────────────────────────────────────────────────
# RULE REPOSITORY
# ─────────────────────────────────────────────────────────────

class RuleRepository:
    """Quản lý thao tác CRUD tập luật phát hiện xâm nhập trong CSDL."""

    @staticmethod
    def _build_raw_rule(data: RuleCreate, sid: int) -> str:
        """
        Tự động build chuỗi raw rule theo cú pháp Snort từ các field.
        Ví dụ: alert tcp any any -> any 80 (msg:"XSS"; http_uri; content:"<script>"; sid:1000010; rev:1;)
        """
        header = (
            f"{data.action} {data.protocol} "
            f"{data.src_ip} {data.src_port} "
            f"{data.direction} "
            f"{data.dst_ip} {data.dst_port}"
        )

        options_parts = []

        # msg
        options_parts.append(f'msg:"{data.msg}"')

        # HTTP modifiers
        if data.http_uri:
            options_parts.append("http_uri")
        if data.http_client_body:
            options_parts.append("http_client_body")
        if data.http_header:
            options_parts.append("http_header")
        if data.http_method:
            options_parts.append(f'http_method:"{data.http_method.upper()}"')

        # Content patterns
        for content in data.contents:
            options_parts.append(f'content:"{content}"')
        if data.nocase and data.contents:
            options_parts.append("nocase")

        # TCP flags
        if data.flags is not None:
            options_parts.append(f"flags:{data.flags}")

        # PCRE
        if data.pcre:
            options_parts.append(f"pcre:{data.pcre}")

        # Classtype & severity
        if data.classtype:
            options_parts.append(f"classtype:{data.classtype}")
        options_parts.append(f"severity:{data.severity}")

        # SID & rev
        options_parts.append(f"sid:{sid}")
        options_parts.append(f"rev:{data.rev}")

        options_str = "; ".join(options_parts) + ";"
        return f"{header} ({options_str})"

    @staticmethod
    def _rebuild_raw_rule(rule: RuleModel) -> str:
        """Rebuild raw_rule string từ các field hiện tại của RuleModel (sau update)."""
        create_data = RuleCreate(
            action=rule.action,
            protocol=rule.protocol,
            src_ip=rule.src_ip,
            src_port=rule.src_port,
            direction=rule.direction,
            dst_ip=rule.dst_ip,
            dst_port=rule.dst_port,
            msg=rule.msg,
            classtype=rule.classtype,
            severity=rule.severity,
            rev=rule.rev,
            contents=[],  # content patterns không lưu riêng trong model, lấy từ raw_rule
        )
        return RuleRepository._build_raw_rule(create_data, rule.sid)

    @staticmethod
    def _next_sid(db: Session) -> int:
        """Tự động sinh SID tiếp theo = max(sid) + 1, bắt đầu từ 2000001."""
        from sqlalchemy import func
        max_sid = db.query(func.max(RuleModel.sid)).scalar()
        return (max_sid + 1) if max_sid else 2000001

    # ── CREATE ───────────────────────────────────────────────

    @staticmethod
    def create(db: Session, data: RuleCreate) -> RuleModel:
        """Tạo rule mới, tự động sinh SID tiếp theo."""
        sid = RuleRepository._next_sid(db)
        raw_rule = RuleRepository._build_raw_rule(data, sid)

        rule = RuleModel(
            sid=sid,
            rev=data.rev,
            action=data.action,
            protocol=data.protocol,
            src_ip=data.src_ip,
            src_port=data.src_port,
            direction=data.direction,
            dst_ip=data.dst_ip,
            dst_port=data.dst_port,
            msg=data.msg,
            classtype=data.classtype,
            severity=data.severity,
            raw_rule=raw_rule,
            is_enabled=True,
        )
        db.add(rule)
        db.commit()
        db.refresh(rule)
        return rule

    # ── READ ─────────────────────────────────────────────────

    @staticmethod
    def get_all(db: Session, enabled_only: bool = False) -> List[RuleModel]:
        """Lấy toàn bộ rules, tùy chọn lọc chỉ rule đang bật."""
        query = db.query(RuleModel)
        if enabled_only:
            query = query.filter(RuleModel.is_enabled == True)
        return query.order_by(RuleModel.sid.asc()).all()

    @staticmethod
    def get_by_sid(db: Session, sid: int) -> Optional[RuleModel]:
        """Lấy rule theo SID."""
        return db.query(RuleModel).filter(RuleModel.sid == sid).first()

    @staticmethod
    def get_by_id(db: Session, rule_id: int) -> Optional[RuleModel]:
        """Lấy rule theo primary key ID."""
        return db.query(RuleModel).filter(RuleModel.id == rule_id).first()

    # ── UPDATE ───────────────────────────────────────────────

    @staticmethod
    def update(db: Session, sid: int, data: RuleUpdate) -> Optional[RuleModel]:
        """Cập nhật các field được cung cấp (partial update). Tăng rev tự động."""
        rule = RuleRepository.get_by_sid(db, sid)
        if not rule:
            return None

        update_fields = data.model_dump(exclude_none=True)

        for field, value in update_fields.items():
            setattr(rule, field, value)

        # Tăng rev nếu không được chỉ định tường minh
        if "rev" not in update_fields:
            rule.rev = (rule.rev or 1) + 1

        rule.updated_at = datetime.utcnow()

        # Rebuild raw_rule sau khi cập nhật
        rule.raw_rule = RuleRepository._rebuild_raw_rule(rule)

        db.commit()
        db.refresh(rule)
        return rule

    # ── DELETE ───────────────────────────────────────────────

    @staticmethod
    def delete(db: Session, sid: int) -> bool:
        """Xóa rule theo SID. Trả về True nếu xóa thành công."""
        rule = RuleRepository.get_by_sid(db, sid)
        if not rule:
            return False
        db.delete(rule)
        db.commit()
        return True

    # ── TOGGLE ───────────────────────────────────────────────

    @staticmethod
    def toggle_enabled(db: Session, sid: int) -> Optional[RuleModel]:
        """Bật/tắt rule. Trả về rule đã cập nhật hoặc None nếu không tìm thấy."""
        rule = RuleRepository.get_by_sid(db, sid)
        if not rule:
            return None
        rule.is_enabled = not rule.is_enabled
        rule.updated_at = datetime.utcnow()
        db.commit()
        db.refresh(rule)
        return rule

    # ── IMPORT FROM FILE ─────────────────────────────────────

    @staticmethod
    def import_from_snort_rules(db: Session, snort_rules: list) -> int:
        """
        Import hàng loạt SnortRule (đã parse từ file) vào DB.
        Bỏ qua các rule đã tồn tại (theo SID). Trả về số rule được import.
        """
        imported = 0
        for rule in snort_rules:
            if not rule.sid:
                continue
            existing = RuleRepository.get_by_sid(db, rule.sid)
            if existing:
                continue  # Skip duplicate

            db_rule = RuleModel(
                sid=rule.sid,
                rev=rule.rev,
                action=rule.action,
                protocol=rule.protocol,
                src_ip=rule.src_ip,
                src_port=rule.src_port,
                direction=rule.direction,
                dst_ip=rule.dst_ip,
                dst_port=rule.dst_port,
                msg=rule.msg,
                classtype=rule.classtype or "",
                severity=rule.severity,
                raw_rule=rule.raw_rule,
                is_enabled=True,
            )
            db.add(db_rule)
            imported += 1

        if imported > 0:
            db.commit()

        return imported
