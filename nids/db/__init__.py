import logging

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import sessionmaker, Session
from typing import Generator
from nids.config import get_db_url
from nids.db.models import Base, EventModel

logger = logging.getLogger("nids.db")

db_url = get_db_url()

engine = create_engine(
    db_url,
    connect_args={"check_same_thread": False} if "sqlite" in db_url else {},
    pool_pre_ping=True,   # Tự động kiểm tra kết nối trước khi dùng (quan trọng với MySQL)
    echo=False,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db() -> Generator[Session, None, None]:
    """
    FastAPI Dependency: Tạo và quản lý vòng đời DB session cho mỗi request.
    Đảm bảo session luôn được đóng sau khi request kết thúc.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _add_missing_columns() -> None:
    """
    Thêm cột và index còn thiếu của bảng events, vì create_all không sửa bảng đã có.
    Nhiều process cùng thêm thì process đến sau nhận lỗi trùng và rơi vào vòng retry của init_db.
    """
    if "session_id" not in {c["name"] for c in inspect(engine).get_columns("events")}:
        with engine.begin() as conn:
            conn.execute(text("ALTER TABLE events ADD COLUMN session_id VARCHAR(32)"))
    existing = {i["name"] for i in inspect(engine).get_indexes("events")}
    for index in EventModel.__table__.indexes:
        if index.name not in existing:
            index.create(bind=engine)


def init_db(max_retries: int = 15, delay: float = 2.0) -> None:
    """
    Khởi tạo toàn bộ bảng trong cơ sở dữ liệu nếu chưa tồn tại và thêm cột còn thiếu vào bảng cũ.
    Tự động retry tối đa 15 lần (30s) trong môi trường Docker khi MySQL cần thời gian khởi động.
    """
    import time
    for attempt in range(1, max_retries + 1):
        try:
            Base.metadata.create_all(bind=engine)
            _add_missing_columns()
            logger.info("Kết nối và khởi tạo CSDL thành công")
            return
        except Exception as e:
            if attempt == max_retries:
                logger.error("Không thể kết nối CSDL sau %d lần thử: %s", max_retries, e)
                raise
            logger.warning(
                "CSDL chưa sẵn sàng (lần %d/%d), thử lại sau %ss", attempt, max_retries, delay
            )
            time.sleep(delay)
