import os
import yaml
from pathlib import Path
from typing import Any, Dict
from urllib.parse import quote_plus

ROOT_DIR = Path(__file__).resolve().parents[1]
CONFIG_DIR = ROOT_DIR / "config"
DEFAULT_SETTINGS_PATH = CONFIG_DIR / "settings.yaml"

def load_settings(path: Path = DEFAULT_SETTINGS_PATH) -> Dict[str, Any]:
    """Tải file cấu hình YAML."""
    if not path.exists():
        raise FileNotFoundError(f"Không tìm thấy file cấu hình tại: {path}")
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}

SETTINGS = load_settings()

def get_db_url() -> str:
    """Tự động sinh chuỗi kết nối Database chuẩn từ settings.yaml."""
    db_cfg = SETTINGS.get("database", {})
    db_type = db_cfg.get("type", "mysql")
    
    if db_type == "mysql":
        user = os.getenv("NIDS_DB_USER", db_cfg.get("user", "root"))
        password = str(
            os.getenv("NIDS_DB_PASSWORD", db_cfg.get("password", "")) or ""
        )
        host = os.getenv("NIDS_DB_HOST", db_cfg.get("host", "localhost"))
        port = int(os.getenv("NIDS_DB_PORT", db_cfg.get("port", 3306)))
        name = os.getenv("NIDS_DB_NAME", db_cfg.get("name", "nids_db"))
        
        auth = f"{user}:{quote_plus(password)}" if password else user
        return f"mysql+pymysql://{auth}@{host}:{port}/{name}?charset=utf8mb4"
    
    return db_cfg.get("db_url", "sqlite:///./nids_events.db")
