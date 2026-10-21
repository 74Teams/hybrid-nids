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


def init_db(max_retries: int = 15, delay: float = 2.0) -> None:
    """
    Khởi tạo toàn bộ bảng trong cơ sở dữ liệu nếu chưa tồn tại.
    Tự động retry tối đa 15 lần (30s) trong môi trường Docker khi MySQL cần thời gian khởi động.
    """
    import time
    for attempt in range(1, max_retries + 1):
        try:
            Base.metadata.create_all(bind=engine)
            print("[DB] Ket noi va khoi tao CSDL thanh cong!")
            return
        except Exception as e:
            if attempt == max_retries:
                print(f"[DB] [Loi Ket Noi] Khong the ket noi CSDL sau {max_retries} lan thu: {e}")
                raise
            print(f"[DB] [Attempt {attempt}/{max_retries}] CSDL chua san sang khoi dong. Thu lai sau {delay}s...")
            time.sleep(delay)
