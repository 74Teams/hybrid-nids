"""
FastAPI Application Entry Point – Hybrid NIDS API Server.

Luồng khởi động (startup lifespan):
  1. init_db()        → Tạo bảng trong MySQL nếu chưa có
  2. Import rules     → Đọc file .rules → upsert vào DB (chạy 1 lần)
  3. Load to RAM      → RuleManager.load_from_db() nạp rules vào Detection Engine
"""
from contextlib import asynccontextmanager
from typing import Optional
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.routes import alerts, rules as rules_router


# ─────────────────────────────────────────────────────────────
# GLOBAL STATE (Detection Engine singleton cho hot-reload)
# ─────────────────────────────────────────────────────────────

_detection_engine = None


def get_detection_engine():
    """Trả về DetectionEngine singleton hiện tại (nếu đã được khởi tạo)."""
    return _detection_engine


def set_detection_engine(engine) -> None:
    """Đặt DetectionEngine singleton (được gọi từ main.py khi khởi chạy toàn hệ thống)."""
    global _detection_engine
    _detection_engine = engine


# ─────────────────────────────────────────────────────────────
# LIFESPAN – Startup & Shutdown
# ─────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Thực hiện các tác vụ khởi tạo khi server bắt đầu."""
    from services.database import init_db, get_db
    from services.database.repository import RuleRepository
    from services.detection.manager_rules import RuleManager
    from config.config import SETTINGS

    print("[API] Khoi dong NIDS API Server...")

    # 1. Khoi tao CSDL
    print("[API] [1/3] Ket noi va khoi tao CSDL...")
    init_db()

    # 2. Import rules tu file .rules vao DB (them moi, hoac ghi de neu rev trong file lon hon)
    rules_dir = SETTINGS.get("detection", {}).get("rules_dir", "rules")
    print(f"[API] [2/3] Import rules tu thu muc '{rules_dir}' vao DB (neu chua co)...")
    try:
        manager = RuleManager(rules_dir)
        manager.load_all_rules()  # Doc tu file

        db = next(get_db())
        try:
            imported = RuleRepository.import_from_snort_rules(db, manager.rules)
            total_in_db = len(RuleRepository.get_all(db))
            print(f"[API]       -> Da import/cap nhat {imported} rules. Tong trong DB: {total_in_db} rules.")
        finally:
            db.close()
    except Exception as e:
        print(f"[API] [Warning] Khong the import rules tu file: {e}")

    # 3. Thong bao san sang
    print("[API] [3/3] NIDS API Server san sang!")
    print("[API] Swagger UI: http://localhost:8000/docs")

    yield  # Server dang chay

    print("[API] Dang dong NIDS API Server...")


# ─────────────────────────────────────────────────────────────
# APP INSTANCE
# ─────────────────────────────────────────────────────────────

app = FastAPI(
    title="Hybrid NIDS – Management API",
    description=(
        "Backend API phuc vu quan sat luu luong mang, quan ly rules phát hiện xam nhap, "
        "va xem canh bao theo thoi gian thuc."
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
app.include_router(rules_router.router)


@app.get("/health", tags=["System"])
def health_check():
    """Kiểm tra trạng thái server."""
    engine_status = "running" if _detection_engine else "not_attached"
    return {
        "status": "ok",
        "service": "NIDS_API",
        "detection_engine": engine_status,
    }
