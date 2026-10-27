"""
Ghi sự kiện honeypot vào bảng events chung của NIDS qua EventRepository.

Mỗi sự kiện mang source_type = "HONEYPOT"; dữ liệu thô (mật khẩu, lệnh, user-agent)
đi vào event_payloads. Lỗi ghi CSDL không bao giờ được làm sập nids.honeypot.
"""
import logging
import time
from typing import Optional

from nids.db.repository import EventRepository

logger = logging.getLogger("nids.honeypot")

# Priority theo loại sự kiện (1 = nghiêm trọng nhất); loại lạ mặc định P2
SEVERITY = {
    "ssh.auth.attempt": 3,
    "ssh.command": 2,
    "ssh.exec": 2,
    "http.login": 2,
    "http.login.sqli": 1,
}


def log_event(protocol: str, event_type: str, src_ip: str, *, src_port: Optional[int] = None,
              dst_ip: str = "", dst_port: Optional[int] = None, username: Optional[str] = None,
              password: Optional[str] = None, command: Optional[str] = None,
              user_agent: Optional[str] = None, http_method: Optional[str] = None,
              http_uri: Optional[str] = None, attack_tag: Optional[str] = None) -> None:
    """Ghi 1 sự kiện honeypot; nuốt mọi lỗi CSDL (chỉ ghi log)."""
    kind = f"{event_type}.{attack_tag}" if attack_tag else event_type
    detail = command if command is not None else f"{username}:{password}"
    evidence = " | ".join(f"{k}={v}" for k, v in
                          (("user", username), ("password", password), ("command", command),
                           ("user_agent", user_agent)) if v is not None)
    try:
        EventRepository.save_alert({
            "timestamp": time.time(),
            "source_type": "HONEYPOT",
            "classtype": event_type,
            "severity": SEVERITY.get(kind, 2),
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "protocol": protocol,
            "http_method": http_method,
            "http_uri": http_uri,
            "msg": f"HONEYPOT {event_type} {detail}"[:500],
            "matched_content": evidence,
        })
    except Exception as e:
        logger.error("Không thể lưu sự kiện honeypot vào CSDL: %s", e)
