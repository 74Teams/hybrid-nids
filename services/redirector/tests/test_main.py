"""Điểm vào `python -m nids.redirector`: mã thoát và log khi tắt hoặc iptables không dùng được."""
import logging

import pytest

from nids.config import RedirectSettings
from nids.redirector import __main__ as entry
from nids.redirector.firewall import FirewallError


@pytest.fixture(autouse=True)
def no_real_init(monkeypatch):
    monkeypatch.setattr(entry, "init_db", lambda: None)
    monkeypatch.setattr(entry, "setup_logging", lambda level: None)


def test_disabled_exits_zero_with_warning(monkeypatch, caplog):
    monkeypatch.setattr(entry, "get_redirect_settings", lambda: RedirectSettings(enabled=False))
    caplog.set_level(logging.WARNING, logger="nids.redirector")
    assert entry.main() == 0
    assert any("đang tắt" in r.getMessage() for r in caplog.records)


def test_unusable_iptables_exits_one_with_error(monkeypatch, caplog):
    monkeypatch.setattr(entry, "get_redirect_settings", lambda: RedirectSettings(enabled=True))

    def unavailable(self):
        raise FirewallError("không có iptables")

    monkeypatch.setattr(entry.Redirector, "start", unavailable)
    caplog.set_level(logging.ERROR, logger="nids.redirector")
    assert entry.main() == 1
    assert any("iptables không dùng được" in r.getMessage() for r in caplog.records)
    assert not any(r.exc_info for r in caplog.records)   # không traceback
