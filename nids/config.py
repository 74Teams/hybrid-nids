import ipaddress
import logging
import os
import yaml
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import quote_plus

from nids.engine.rule_header import DEFAULT_RULE_VARIABLES

ROOT_DIR = Path(__file__).resolve().parents[1]
CONFIG_DIR = ROOT_DIR / "config"
DEFAULT_SETTINGS_PATH = CONFIG_DIR / "settings.yaml"
EXAMPLE_SETTINGS_PATH = CONFIG_DIR / "settings.example.yaml"

def load_settings(path: Optional[Path] = None) -> Dict[str, Any]:
    """Tải file cấu hình YAML."""
    if path is None:
        path = DEFAULT_SETTINGS_PATH
        # Bản clone mới/CI chưa có settings.yaml (đã bỏ khỏi git) nên dùng file mẫu
        if not path.exists():
            path = EXAMPLE_SETTINGS_PATH
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


def get_rule_variables() -> Dict[str, str]:
    """Biến dùng trong header rule ($HTTP_PORTS, $HOME_NET...): giá trị mặc định chồng bởi `detection.variables`.

    Giá trị YAML dạng list được nối bằng dấu phẩy. Đọc từ SETTINGS nên đổi biến cần khởi động lại engine và API.
    """
    variables = dict(DEFAULT_RULE_VARIABLES)
    configured = (SETTINGS.get("detection") or {}).get("variables") or {}
    for name, value in configured.items():
        if isinstance(value, (list, tuple)):
            value = ",".join(str(v) for v in value)
        variables[str(name)] = str(value)
    return variables


def get_redis_settings() -> Optional[Dict[str, Any]]:
    """Cấu hình Redis đẩy cảnh báo; None khi host rỗng (tắt). Biến môi trường NIDS_REDIS_* ghi đè settings."""
    cfg = SETTINGS.get("redis") or {}
    host = os.getenv("NIDS_REDIS_HOST", cfg.get("host", "")) or ""
    if not host:
        return None
    return {
        "host": host,
        "port": int(os.getenv("NIDS_REDIS_PORT", cfg.get("port", 6379))),
        "password": os.getenv("NIDS_REDIS_PASSWORD", cfg.get("password", "")) or None,
    }


DEFAULT_REDIRECT_PORTS = {22: 2222, 80: 8080}
# IP hạ tầng của lab (gateway, MySQL, API, Redis, victim) và loopback: không bao giờ bị chuyển hướng
DEFAULT_REDIRECT_ALLOWLIST = ["127.0.0.0/8", "172.28.0.1", "172.28.0.10", "172.28.0.20", "172.28.0.30", "172.28.0.50"]


@dataclass
class RedirectSettings:
    """Cấu hình `nids.redirector` (mục `redirect` trong settings.yaml)."""
    enabled: bool = False
    window_seconds: int = 60
    min_alerts: int = 5
    max_priority: int = 2
    ttl_seconds: int = 600
    poll_interval: float = 5.0
    ports: Dict[int, int] = field(default_factory=lambda: dict(DEFAULT_REDIRECT_PORTS))
    allowlist: List[str] = field(default_factory=lambda: list(DEFAULT_REDIRECT_ALLOWLIST))


def get_redirect_settings(cfg: Optional[Dict[str, Any]] = None) -> RedirectSettings:
    """Đọc mục `redirect`; giá trị sai thì ghi ERROR và dùng mặc định của riêng trường đó (không dừng process)."""
    logger = logging.getLogger("nids.redirector")
    cfg = SETTINGS.get("redirect") if cfg is None else cfg
    cfg = cfg if isinstance(cfg, dict) else {}
    result = RedirectSettings()

    for name, cast in (("window_seconds", int), ("min_alerts", int), ("max_priority", int),
                       ("ttl_seconds", int), ("poll_interval", float)):
        if name not in cfg:
            continue
        try:
            value = cast(cfg[name])
            if isinstance(cfg[name], bool) or value <= 0:
                raise ValueError
            setattr(result, name, value)
        except (TypeError, ValueError):
            logger.error("redirect.%s=%r không hợp lệ (cần số dương), dùng mặc định %s",
                         name, cfg[name], getattr(result, name))
    result.enabled = cfg.get("enabled", False) is True

    if "ports" in cfg:
        ports = {}
        for src, dst in (cfg["ports"].items() if isinstance(cfg["ports"], dict) else []):
            try:
                src, dst = int(src), int(dst)
            except (TypeError, ValueError):
                logger.error("redirect.ports: bỏ qua cặp %r -> %r (không phải số)", src, dst)
                continue
            if 1 <= src <= 65535 and 1 <= dst <= 65535:
                ports[src] = dst
            else:
                logger.error("redirect.ports: bỏ qua cặp %s -> %s (cổng ngoài 1-65535)", src, dst)
        if ports:
            result.ports = ports
        else:
            logger.error("redirect.ports không có cặp hợp lệ, dùng mặc định %s", DEFAULT_REDIRECT_PORTS)

    if "allowlist" in cfg:
        entries = cfg["allowlist"] if isinstance(cfg["allowlist"], list) else []
        valid = []
        for entry in entries:
            try:
                ipaddress.ip_network(str(entry), strict=False)
                valid.append(str(entry))
            except ValueError:
                logger.error("redirect.allowlist: bỏ qua %r (không phải IP hoặc CIDR)", entry)
        result.allowlist = valid
    return result
