"""
FastAPI Dependency Injection.
Cung cấp DB session được quản lý vòng đời tự động cho mỗi request.
"""
from typing import Generator
from sqlalchemy.orm import Session
from services.database import get_db as _get_db

# Re-export để các route import gọn hơn: from api.dependencies import get_db
def get_db() -> Generator[Session, None, None]:
    yield from _get_db()

