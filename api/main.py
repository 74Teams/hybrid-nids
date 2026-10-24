"""
FastAPI Application Entry Point – Hybrid NIDS API Server.

Luồng khởi động (startup lifespan): init_db() tạo bảng trong CSDL nếu chưa có.
Rule chỉ đọc từ rules/local.rules bởi process engine (main.py), không đi qua API.
"""
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.routes import alerts


# ─────────────────────────────────────────────────────────────
# LIFESPAN – Startup & Shutdown
# ─────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Thực hiện các tác vụ khởi tạo khi server bắt đầu."""
    from services.database import init_db

    print("[API] Khoi dong NIDS API Server...")
    init_db()
    print("[API] NIDS API Server san sang! Swagger UI: http://localhost:8000/docs")

    yield  # Server dang chay

    print("[API] Dang dong NIDS API Server...")


# ─────────────────────────────────────────────────────────────
# APP INSTANCE
# ─────────────────────────────────────────────────────────────

app = FastAPI(
    title="Hybrid NIDS – Management API",
    description=(
        "Backend API phuc vu quan sat luu luong mang, xem canh bao theo thoi gian thuc."
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


@app.get("/health", tags=["System"])
def health_check():
    """Kiểm tra trạng thái server."""
    return {"status": "ok", "service": "NIDS_API"}
