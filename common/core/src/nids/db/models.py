from datetime import datetime, timezone
from typing import Optional
from sqlalchemy import BigInteger, Column, Float, Integer, String, Text, DateTime, ForeignKey
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


def utc_now() -> datetime:
    """Giờ UTC hiện tại, dạng naive (không kèm múi giờ) vì CSDL luôn lưu UTC."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def utc_from_epoch(ts: float) -> datetime:
    """Đổi epoch (giây) sang UTC naive để lưu CSDL."""
    return datetime.fromtimestamp(ts, timezone.utc).replace(tzinfo=None)


def iso_utc(value: Optional[datetime], timespec: str = "auto") -> Optional[str]:
    """Chuỗi ISO 8601 kèm `Z` cho giá trị UTC naive, để trình duyệt tự đổi sang giờ người xem."""
    return value.isoformat(timespec=timespec) + "Z" if value else None


class EventModel(Base):
    __tablename__ = "events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=utc_now, nullable=False, index=True)
    sid = Column(Integer, nullable=True)
    source_type = Column(String(20), default="RULE_ENGINE")  
    attack_type = Column(String(100), nullable=False)
    severity = Column(Integer, nullable=False)
    src_ip = Column(String(45), nullable=False)
    src_port = Column(Integer, nullable=True)
    dst_ip = Column(String(45), nullable=False)
    dst_port = Column(Integer, nullable=True)
    protocol = Column(String(10), nullable=False)
    http_method = Column(String(10), nullable=True)
    http_uri = Column(Text, nullable=True)
    summary = Column(Text, nullable=False)
    status = Column(String(20), default="NEW")
    session_id = Column(String(32), nullable=True, index=True)   # phiên honeypot; NULL với cảnh báo rule engine

    payload = relationship("EventPayloadModel", back_populates="event", uselist=False)

class FlowModel(Base):
    """Một flow đã kết thúc (mọi traffic, không chỉ traffic có cảnh báo)."""
    __tablename__ = "flows"

    id = Column(Integer, primary_key=True, autoincrement=True)
    first_seen = Column(DateTime, nullable=False, index=True)
    last_seen = Column(DateTime, nullable=False)
    duration = Column(Float, nullable=False)  # giây, giữ cả phần lẻ vì DateTime của MySQL chỉ đến giây
    protocol = Column(String(10), nullable=False)
    src_ip = Column(String(45), nullable=False, index=True)
    src_port = Column(Integer, nullable=True)
    dst_ip = Column(String(45), nullable=False, index=True)
    dst_port = Column(Integer, nullable=True, index=True)
    fwd_packets = Column(Integer, nullable=False, default=0)
    bwd_packets = Column(Integer, nullable=False, default=0)
    fwd_bytes = Column(BigInteger, nullable=False, default=0)
    bwd_bytes = Column(BigInteger, nullable=False, default=0)
    tcp_flags = Column(String(16), nullable=False, default="")
    alert_count = Column(Integer, nullable=False, default=0, index=True)  # 0 = không khớp rule nào
    end_reason = Column(String(16), nullable=False, default="")
    created_at = Column(DateTime, default=utc_now, nullable=False, index=True)  # dọn flow cũ theo mốc này


class RedirectModel(Base):
    """Nhật ký chuyển hướng IP đáng ngờ sang honeypot (do `nids.redirector` ghi); mỗi dòng là một lượt chuyển hướng."""
    __tablename__ = "redirects"

    id = Column(Integer, primary_key=True, autoincrement=True)
    ip = Column(String(45), nullable=False, index=True)
    created_at = Column(DateTime, default=utc_now, nullable=False)
    expires_at = Column(DateTime, nullable=False, index=True)
    removed_at = Column(DateTime, nullable=True)   # NULL = đang hiệu lực
    alert_count = Column(Integer, nullable=False, default=0)
    reason = Column(Text, nullable=True)


class EventPayloadModel(Base):
    __tablename__ = "event_payloads"

    id = Column(Integer, primary_key=True, autoincrement=True)
    event_id = Column(Integer, ForeignKey("events.id"), nullable=False)
    matched_content = Column(Text, nullable=True)
    http_headers = Column(Text, nullable=True)
    http_body = Column(Text, nullable=True)
    packet_raw_hex = Column(Text, nullable=True)

    event = relationship("EventModel", back_populates="payload")
