"""
Process chuyển hướng IP đáng ngờ sang honeypot:

    python -m nids.redirector

Chạy chung network namespace với victim (cần NET_ADMIN và gói iptables). `redirect.enabled: false` thì thoát mã 0;
iptables không dùng được thì thoát mã 1.
"""
import logging
import signal
import sys
import threading

from nids.config import SETTINGS, get_redirect_settings
from nids.db import init_db
from nids.logger import setup_logging

from .firewall import FirewallError, IptablesFirewall
from .service import Redirector

logger = logging.getLogger("nids.redirector")


def main() -> int:
    setup_logging(SETTINGS.get("system", {}).get("log_level", "INFO"))
    settings = get_redirect_settings()
    if not settings.enabled:
        logger.warning("Chuyển hướng đang tắt: đặt `redirect.enabled: true` trong config/settings.yaml "
                       "(xem mục redirect trong settings.example.yaml) rồi chạy lại")
        return 0

    init_db()
    stop_event = threading.Event()
    redirector = Redirector(settings, IptablesFirewall(settings.ports), stop_event)
    try:
        redirector.start()
    except FirewallError as e:
        logger.error("iptables không dùng được (cần chạy trong Docker lab với NET_ADMIN): %s", e)
        return 1

    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop_event.set())
    redirector.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
