import logging
import os
import sys
from typing import Optional, TextIO

RESET = "\033[0m"
LEVEL_COLORS = {
    logging.DEBUG: "2",
    logging.INFO: "32",
    logging.WARNING: "33",
    logging.ERROR: "31",
    logging.CRITICAL: "1;31",
}
AREA_COLOR = "36"
PRIORITY_COLORS = {1: "1;31", 2: "33", 3: "34"}
VALID_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}


def _paint(text: str, code: str) -> str:
    return f"\033[{code}m{text}{RESET}"


class ColorFormatter(logging.Formatter):
    """Định dạng mỗi dòng log: giờ, mức độ, khu vực, nội dung. Có màu khi use_color là True."""

    def __init__(self, use_color: bool):
        super().__init__(datefmt="%H:%M:%S")
        self.use_color = use_color

    def format(self, record: logging.LogRecord) -> str:
        area = record.name.removeprefix("nids.")
        message = record.getMessage()
        level_text = record.levelname
        area_text = area

        if self.use_color:
            level_text = _paint(level_text, LEVEL_COLORS.get(record.levelno, "0"))
            area_text = _paint(area_text, AREA_COLOR)
            priority_code = PRIORITY_COLORS.get(getattr(record, "priority", None))
            if priority_code:
                message = _paint(message, priority_code)

        # Đệm khoảng trắng theo độ dài chữ gốc để cột thẳng hàng dù có mã màu
        level_pad = " " * max(8 - len(record.levelname), 0)
        area_pad = " " * max(8 - len(area), 0)
        line = f"{self.formatTime(record, self.datefmt)} {level_text}{level_pad} {area_text}{area_pad} {message}"

        if record.exc_info:
            line += "\n" + self.formatException(record.exc_info)
        return line


def setup_logging(level: str = "INFO", stream: Optional[TextIO] = None) -> logging.Logger:
    """Cấu hình logger gốc "nids". Gọi nhiều lần vẫn chỉ có đúng một handler."""
    logger = logging.getLogger("nids")
    for handler in list(logger.handlers):
        logger.removeHandler(handler)

    if stream is None:
        stream = sys.stdout
        if hasattr(stream, "reconfigure"):
            # Terminal Windows cũ mặc định cp1252 sẽ lỗi khi in tiếng Việt có dấu
            stream.reconfigure(encoding="utf-8", errors="replace")

    use_color = stream.isatty() and "NO_COLOR" not in os.environ
    if use_color and sys.platform == "win32":
        # shortcut: os.system("") bật ANSI trên Windows 10+, không chạy được trên conhost đời cũ; nâng cấp bằng ctypes SetConsoleMode nếu cần
        os.system("")

    handler = logging.StreamHandler(stream)
    handler.setFormatter(ColorFormatter(use_color))
    logger.addHandler(handler)
    logger.propagate = False

    level_name = str(level).upper()
    invalid = level_name not in VALID_LEVELS
    logger.setLevel(logging.INFO if invalid else getattr(logging, level_name))
    if invalid:
        logger.warning("log_level '%s' không hợp lệ, dùng INFO", level)
    return logger
