"""
CLI chạy một honeypot mỗi tiến trình:

    python -m honeypot ssh [-a ADDR] [-p PORT] [-u USER -pw PASS]
    python -m honeypot http [-a ADDR] [-p PORT] [-u USER -pw PASS]

Tham số không truyền thì lấy từ honeypot/settings.py (biến môi trường HONEYPY_*).
"""
import argparse
import logging

from config.config import SETTINGS
from config.logger import setup_logging
from services.database import init_db

from .settings import settings
from .ssh_honeypot import honeypot
from .web_honeypot import run_web_honeypot

logger = logging.getLogger("nids.honeypot")


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(description="Honeypot SSH/HTTP của Hybrid NIDS")
    parser.add_argument("kind", choices=["ssh", "http"])
    parser.add_argument("-a", "--address", default=settings.bind_address)
    parser.add_argument("-p", "--port", type=int)
    parser.add_argument("-u", "--username")
    parser.add_argument("-pw", "--password")
    args = parser.parse_args(argv)

    setup_logging(SETTINGS.get("system", {}).get("log_level", "INFO"))
    init_db()

    try:
        if args.kind == "ssh":
            # Không truyền username/password thì honeypot chấp nhận mọi mật khẩu
            honeypot(args.address, args.port or settings.ssh_port, args.username, args.password)
        else:
            run_web_honeypot(host=args.address, port=args.port or settings.http_port,
                             input_username=args.username or settings.http_username,
                             input_password=args.password or settings.http_password)
    except KeyboardInterrupt:
        logger.info("Dừng honeypot")


if __name__ == "__main__":
    main()
