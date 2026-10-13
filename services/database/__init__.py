from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from typing import Generator
from config.config import get_db_url
from services.database.models import Base

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


def init_db() -> None:
    """Khởi tạo toàn bộ bảng trong cơ sở dữ liệu nếu chưa tồn tại."""
    Base.metadata.create_all(bind=engine)
