"""Kiểm tra docker-compose.yml không chứa mật khẩu cứng, lấy từ .env."""

import re
from pathlib import Path

import yaml

COMPOSE_PATH = Path(__file__).resolve().parents[2] / "docker-compose.yml"


def _text():
    return COMPOSE_PATH.read_text(encoding="utf-8")


def test_compose_has_no_literal_passwords():
    # Không ghi mật khẩu cũ vào test: mọi dòng *PASSWORD phải là biến ${...}
    lines = [l for l in _text().splitlines() if re.match(r"\s*\w*PASSWORD:", l)]
    assert lines
    assert all(re.search(r':\s*"\$\{\w+:\?', l) for l in lines), lines


def test_compose_requires_password_variables():
    text = _text()
    assert "${MYSQL_ROOT_PASSWORD:?" in text
    assert "${NIDS_DB_PASSWORD:?" in text


def test_healthcheck_escapes_dollar():
    assert "$$MYSQL_ROOT_PASSWORD" in _text()


def test_redis_requires_password_and_is_not_published():
    services = yaml.safe_load(_text())["services"]
    assert "${NIDS_REDIS_PASSWORD:?" in services["redis"]["command"]
    assert "ports" not in services["redis"]  # chỉ trong mạng lab, không mở ra host


def test_sensors_do_not_depend_on_redis():
    services = yaml.safe_load(_text())["services"]
    for name, service in services.items():
        assert "redis" not in (service.get("depends_on") or {}), name
