import io
import logging
import sys

import pytest

from config.logger import ColorFormatter, setup_logging


@pytest.fixture(autouse=True)
def reset_nids_logger():
    yield
    logger = logging.getLogger("nids")
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
    logger.propagate = True
    logger.setLevel(logging.NOTSET)


def make_record(name="nids.rules", level=logging.INFO, msg="Đã nạp 30 rule", **extra):
    record = logging.LogRecord(name, level, __file__, 1, msg, None, None)
    for key, value in extra.items():
        setattr(record, key, value)
    return record


def test_plain_format():
    line = ColorFormatter(use_color=False).format(make_record())
    assert __import__("re").match(r"^\d\d:\d\d:\d\d INFO     rules    Đã nạp 30 rule$", line)


def test_colored_level_and_area():
    line = ColorFormatter(use_color=True).format(make_record())
    assert "\033[32mINFO" in line
    assert "\033[36mrules" in line


def test_alert_priority_colors():
    formatter = ColorFormatter(use_color=True)
    p1 = formatter.format(make_record("nids.alert", logging.WARNING, "A", priority=1))
    p2 = formatter.format(make_record("nids.alert", logging.WARNING, "A", priority=2))
    p3 = formatter.format(make_record("nids.alert", logging.WARNING, "A", priority=3))
    p4 = formatter.format(make_record("nids.alert", logging.WARNING, "A", priority=4))
    assert "\033[1;31mA" in p1
    assert "\033[33mA" in p2
    assert "\033[34mA" in p3
    assert "\033[1;31mA" not in p4
    assert "\033[34mA" not in p4
    assert p4.endswith(" A")


def test_non_tty_stream_has_no_color():
    stream = io.StringIO()
    setup_logging("INFO", stream=stream)
    logging.getLogger("nids.alert").warning("Cảnh báo", extra={"priority": 1})
    assert "\033" not in stream.getvalue()
    assert "Cảnh báo" in stream.getvalue()


def test_level_and_idempotent_setup():
    stream = io.StringIO()
    setup_logging("DEBUG", stream=stream)
    setup_logging("DEBUG", stream=stream)
    logger = logging.getLogger("nids")
    assert logger.level == logging.DEBUG
    assert len(logger.handlers) == 1
    assert logger.propagate is False
    logging.getLogger("nids.x").debug("chi tiết")
    assert stream.getvalue().count("chi tiết") == 1


def test_invalid_level_falls_back_to_info():
    stream = io.StringIO()
    setup_logging("VERBOSE", stream=stream)
    assert logging.getLogger("nids").level == logging.INFO
    assert "log_level" in stream.getvalue()


def test_utf8_on_legacy_encoding(monkeypatch):
    legacy = io.TextIOWrapper(io.BytesIO(), encoding="cp1252")
    monkeypatch.setattr(sys, "stdout", legacy)
    setup_logging("INFO")
    logging.getLogger("nids.rules").info("Đã nạp rule từ tệp")
    assert sys.stdout.encoding.lower().replace("-", "") == "utf8"
