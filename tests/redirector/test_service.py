"""Redirector: chọn IP theo ngưỡng, allowlist, hết TTL, khôi phục khi rule bị xoá và chịu lỗi."""
import logging
import time

import pytest

from nids.config import RedirectSettings
from nids.db.repository import EventRepository
from nids.redirector.firewall import FirewallError, IptablesFirewall
from nids.redirector.service import RedirectPolicy, Redirector

from fake_iptables import FakeIptables

ATTACKER = "172.28.0.100"


def alert(ip, severity=1, source_type="RULE_ENGINE", age=0.0):
    return {"timestamp": time.time() - age, "sid": 1000001, "msg": "x", "severity": severity,
            "classtype": "web-application-attack", "src_ip": ip, "dst_ip": "172.28.0.50", "protocol": "TCP",
            "source_type": source_type}


def attack(ip, n=5, **kwargs):
    for _ in range(n):
        EventRepository.save_alert(alert(ip, **kwargs))


def make(**overrides):
    settings = RedirectSettings(enabled=True, **{"ttl_seconds": 600, **overrides})
    fake = FakeIptables()
    redirector = Redirector(settings, IptablesFirewall(settings.ports, runner=fake))
    redirector.start()
    return redirector, fake


def test_ip_over_threshold_is_redirected_once():
    redirector, fake = make()
    attack(ATTACKER)
    redirector.run_once()
    redirector.run_once()
    assert len(fake.rules_for(ATTACKER)) == 2
    rows = EventRepository.list_redirects()
    assert [(r.ip, r.alert_count) for r in rows] == [(ATTACKER, 5)]


@pytest.mark.parametrize("kwargs", [
    {"n": 4},                         # thiếu một cảnh báo
    {"age": 120},                     # ngoài cửa sổ 60 giây
    {"severity": 3},                  # priority thấp
    {"source_type": "HONEYPOT"},      # sự kiện honeypot không được đếm
])
def test_ip_below_criteria_is_not_redirected(kwargs):
    redirector, fake = make()
    attack(ATTACKER, **kwargs)
    redirector.run_once()
    assert fake.rules_for(ATTACKER) == [] and EventRepository.list_redirects() == []


@pytest.mark.parametrize("ip", ["172.28.0.20", "172.28.0.10", "127.0.0.5"])
def test_allowlisted_ip_is_never_redirected(ip):
    redirector, fake = make(allowlist=["127.0.0.0/8", "172.28.0.10", "172.28.0.20"])
    attack(ip, n=50)
    redirector.run_once()
    assert fake.rules_for(ip) == [] and EventRepository.list_redirects() == []


def test_non_ipv4_source_is_skipped_without_error():
    redirector, fake = make()
    attack("not-an-ip")
    redirector.run_once()
    assert EventRepository.list_redirects() == []


def test_policy_accepts_cidr_and_single_ip():
    policy = RedirectPolicy(["10.0.0.0/8", "192.168.1.1"])
    assert not policy.allows("10.9.9.9") and not policy.allows("192.168.1.1")
    assert policy.allows("192.168.1.2") and not policy.allows("::1")


def test_expiry_marks_row_removed():
    redirector, fake = make()
    EventRepository.add_redirect(ATTACKER, ttl_seconds=-1)
    redirector.run_once()
    assert EventRepository.active_redirects() == []
    assert EventRepository.list_redirects(active_only=False)[0].removed_at is not None


def test_expiry_removes_rules_from_firewall():
    redirector, fake = make()
    EventRepository.add_redirect(ATTACKER, ttl_seconds=-1)
    fake.chains["NIDS_REDIRECT"] = [("-s", ATTACKER, "-p", "tcp", "--dport", "22", "-j", "REDIRECT", "--to-ports", "2222")]
    redirector.run_once()
    assert fake.rules_for(ATTACKER) == []


def test_rules_are_restored_when_flushed_externally():
    redirector, fake = make()
    attack(ATTACKER)
    redirector.run_once()
    fake.chains.clear()
    fake.chains["PREROUTING"] = []   # tương đương `iptables -t nat -F` rồi xoá chain
    redirector.run_once()
    assert fake.chains["PREROUTING"] == [("-j", "NIDS_REDIRECT")]
    assert len(fake.rules_for(ATTACKER)) == 2


def test_start_flushes_stale_rules_and_closes_expired_rows():
    fake = FakeIptables()
    firewall = IptablesFirewall({22: 2222}, runner=fake)
    firewall.ensure_setup()
    firewall.add("9.9.9.9")   # rule mồ côi từ lần chạy trước
    EventRepository.add_redirect(ATTACKER, ttl_seconds=-1)
    Redirector(RedirectSettings(enabled=True), firewall).start()
    assert fake.chains["NIDS_REDIRECT"] == []
    assert EventRepository.list_redirects(active_only=False)[0].removed_at is not None


def test_active_rows_survive_restart():
    redirector, fake = make()
    attack(ATTACKER)
    redirector.run_once()
    fake.chains["NIDS_REDIRECT"].clear()
    restarted = Redirector(redirector.settings, IptablesFirewall(redirector.settings.ports, runner=fake))
    restarted.start()
    restarted.run_once()
    assert len(fake.rules_for(ATTACKER)) == 2
    assert len(EventRepository.list_redirects()) == 1   # không nhân đôi dòng


def test_stop_flushes_chain_and_releases_rows():
    redirector, fake = make()
    attack(ATTACKER)
    redirector.run_once()
    redirector.stop()
    assert fake.chains["NIDS_REDIRECT"] == []
    assert EventRepository.active_redirects() == []


def test_firewall_error_does_not_raise_and_next_cycle_retries(caplog):
    redirector, fake = make()
    attack(ATTACKER)
    fake.fail_on = lambda argv: argv[4] == "-A"
    caplog.set_level(logging.ERROR, logger="nids.redirector")
    redirector.run_once()   # không được ném lỗi
    assert fake.rules_for(ATTACKER) == []
    assert any("sẽ thử lại" in r.getMessage() for r in caplog.records)
    fake.fail_on = None
    redirector.run_once()
    assert len(fake.rules_for(ATTACKER)) == 2


def test_failed_removal_is_retried(caplog):
    redirector, fake = make()
    EventRepository.add_redirect(ATTACKER, ttl_seconds=-1)
    fake.chains["NIDS_REDIRECT"] = [("-s", ATTACKER, "-p", "tcp", "--dport", "22", "-j", "REDIRECT", "--to-ports", "2222")]
    fake.fail_on = lambda argv: argv[4] == "-D"
    redirector.run_once()
    assert len(fake.rules_for(ATTACKER)) == 1
    fake.fail_on = None
    redirector.run_once()
    assert fake.rules_for(ATTACKER) == []


def test_database_errors_do_not_raise(monkeypatch, caplog):
    redirector, fake = make()

    def boom(*args, **kwargs):
        raise RuntimeError("db down")

    for name in ("expire_redirects", "active_redirects", "suspicious_ips", "add_redirect"):
        monkeypatch.setattr(EventRepository, name, boom)
    caplog.set_level(logging.ERROR, logger="nids.redirector")
    redirector.run_once()
    assert len([r for r in caplog.records if r.levelno == logging.ERROR]) >= 3


def test_run_stops_on_event_and_cleans_up():
    redirector, fake = make(poll_interval=0.01)
    attack(ATTACKER)
    redirector.stop_event.set()
    redirector.run()
    assert fake.chains["NIDS_REDIRECT"] == []
