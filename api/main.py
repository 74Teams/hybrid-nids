"""
Điểm khởi chạy ứng dụng FastAPI – Hybrid NIDS API Server.

Luồng khởi động (startup lifespan): init_db() tạo bảng trong CSDL nếu chưa có.
Rule chỉ đọc từ rules/local.rules bởi process engine (main.py), không đi qua API.
"""
import logging
from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

from api.routes import alerts
from config.logger import setup_logging

logger = logging.getLogger("nids.api")


# ─────────────────────────────────────────────────────────────
# LIFESPAN – Startup & Shutdown
# ─────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Thực hiện các tác vụ khởi tạo khi server bắt đầu."""
    from config.config import SETTINGS
    from services.database import init_db

    setup_logging(SETTINGS.get("system", {}).get("log_level", "INFO"))
    logger.info("Khởi động NIDS API Server")
    init_db()
    logger.info("NIDS API Server sẵn sàng, Swagger UI: http://localhost:8000/docs")

    yield  # Server đang chạy

    logger.info("Đóng NIDS API Server")


# ─────────────────────────────────────────────────────────────
# APP INSTANCE
# ─────────────────────────────────────────────────────────────

app = FastAPI(
    title="Hybrid NIDS – Management API",
    description=(
        "Backend API phục vụ quan sát lưu lượng mạng và xem cảnh báo theo thời gian thực."
    ),
    version="1.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─────────────────────────────────────────────────────────────
# ROUTERS
# ─────────────────────────────────────────────────────────────

app.include_router(alerts.router)

DASHBOARD_FILE = Path(__file__).parent / "static" / "dashboard.html"


@app.get("/", include_in_schema=False)
def dashboard():
    """Trang dashboard theo dõi cảnh báo theo thời gian thực."""
    return FileResponse(DASHBOARD_FILE)


@app.get("/health", tags=["System"])
def health_check():
    """Kiểm tra trạng thái server."""
    return {"status": "ok", "service": "NIDS_API"}
