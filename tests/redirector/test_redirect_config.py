"""get_redirect_settings: giá trị sai không làm dừng process mà rơi về mặc định kèm ERROR."""
import logging

from nids.config import DEFAULT_REDIRECT_ALLOWLIST, DEFAULT_REDIRECT_PORTS, get_redirect_settings


def errors(caplog):
    return [r.getMessage() for r in caplog.records if r.name == "nids.redirector" and r.levelno == logging.ERROR]


def test_missing_section_gives_disabled_defaults():
    s = get_redirect_settings({})
    assert s.enabled is False and s.ports == DEFAULT_REDIRECT_PORTS and s.allowlist == DEFAULT_REDIRECT_ALLOWLIST


def test_valid_section_is_applied():
    s = get_redirect_settings({"enabled": True, "min_alerts": 3, "ttl_seconds": 30, "poll_interval": 1.5,
                               "ports": {21: 2121}, "allowlist": ["10.0.0.0/8"]})
    assert (s.enabled, s.min_alerts, s.ttl_seconds, s.poll_interval) == (True, 3, 30, 1.5)
    assert s.ports == {21: 2121} and s.allowlist == ["10.0.0.0/8"]


def test_bad_numbers_fall_back_with_error(caplog):
    s = get_redirect_settings({"min_alerts": -1, "ttl_seconds": "abc", "window_seconds": 0})
    assert (s.min_alerts, s.ttl_seconds, s.window_seconds) == (5, 600, 60)
    assert len(errors(caplog)) == 3


def test_bad_ports_are_dropped(caplog):
    s = get_redirect_settings({"ports": {22: 70000, "x": 1, 80: 8080}})
    assert s.ports == {80: 8080}
    assert len(errors(caplog)) == 2


def test_ports_without_valid_pair_use_default(caplog):
    assert get_redirect_settings({"ports": {0: 1}}).ports == DEFAULT_REDIRECT_PORTS
    assert errors(caplog)


def test_invalid_allowlist_entries_are_dropped(caplog):
    s = get_redirect_settings({"allowlist": ["10.0.0.1", "not-an-ip", "10.0.0.0/99"]})
    assert s.allowlist == ["10.0.0.1"]
    assert len(errors(caplog)) == 2


def test_enabled_must_be_true_boolean():
    assert get_redirect_settings({"enabled": "false"}).enabled is False
