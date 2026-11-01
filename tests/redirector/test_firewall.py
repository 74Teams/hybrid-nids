"""IptablesFirewall với iptables giả: argv đúng, idempotent, từ chối IP lạ và không bao giờ ném lỗi ngoài FirewallError."""
import subprocess

import pytest

from nids.redirector.firewall import FirewallError, IptablesFirewall

from fake_iptables import FakeIptables

PORTS = {22: 2222, 80: 8080}


@pytest.fixture
def fake():
    return FakeIptables()


@pytest.fixture
def firewall(fake):
    return IptablesFirewall(PORTS, runner=fake)


def test_ensure_setup_creates_chain_and_jump_once(firewall, fake):
    firewall.ensure_setup()
    firewall.ensure_setup()
    assert "NIDS_REDIRECT" in fake.chains
    assert fake.chains["PREROUTING"] == [("-j", "NIDS_REDIRECT")]


def test_add_builds_redirect_rule_for_each_port(firewall, fake):
    firewall.ensure_setup()
    firewall.add("1.2.3.4")
    assert fake.chains["NIDS_REDIRECT"] == [
        ("-s", "1.2.3.4", "-p", "tcp", "--dport", "22", "-j", "REDIRECT", "--to-ports", "2222"),
        ("-s", "1.2.3.4", "-p", "tcp", "--dport", "80", "-j", "REDIRECT", "--to-ports", "8080"),
    ]


def test_add_twice_does_not_duplicate_rules(firewall, fake):
    firewall.ensure_setup()
    firewall.add("1.2.3.4")
    firewall.add("1.2.3.4")
    assert len(fake.rules_for("1.2.3.4")) == 2


def test_remove_deletes_only_that_ip(firewall, fake):
    firewall.ensure_setup()
    firewall.add("1.2.3.4")
    firewall.add("5.6.7.8")
    firewall.remove("1.2.3.4")
    assert fake.rules_for("1.2.3.4") == [] and len(fake.rules_for("5.6.7.8")) == 2


def test_remove_missing_ip_is_noop(firewall, fake):
    firewall.ensure_setup()
    firewall.remove("1.2.3.4")
    assert not [c for c in fake.calls if c[4] == "-D"]


def test_flush_clears_rules_but_keeps_chain_and_jump(firewall, fake):
    firewall.ensure_setup()
    firewall.add("1.2.3.4")
    firewall.flush()
    assert fake.chains["NIDS_REDIRECT"] == [] and fake.chains["PREROUTING"] == [("-j", "NIDS_REDIRECT")]


def test_flush_without_chain_does_nothing(firewall, fake):
    firewall.flush()
    assert fake.mutating_calls() == []


@pytest.mark.parametrize("bad", ["1.2.3.4; reboot", "1.2.3.4 -j ACCEPT", "1.2.3.4\n", "", "::1", "2001:db8::1", "abc", None])
def test_rejects_invalid_ip_without_running_anything(firewall, fake, bad):
    with pytest.raises(FirewallError):
        firewall.add(bad)
    with pytest.raises(FirewallError):
        firewall.remove(bad)
    assert fake.calls == []


def test_runner_oserror_becomes_firewall_error(fake):
    fake.fail_on = lambda argv: True
    with pytest.raises(FirewallError, match="Không chạy được"):
        IptablesFirewall(PORTS, runner=fake).check_available()


def test_timeout_becomes_firewall_error():
    def hang(argv):
        raise subprocess.TimeoutExpired(argv, 5)
    with pytest.raises(FirewallError):
        IptablesFirewall(PORTS, runner=hang).ensure_setup()


def test_nonzero_exit_becomes_firewall_error():
    def denied(argv):
        return subprocess.CompletedProcess(argv, 4, "", "Permission denied")
    with pytest.raises(FirewallError, match="Permission denied"):
        IptablesFirewall(PORTS, runner=denied).check_available()


def test_commands_use_wait_flag_and_no_shell(firewall, fake):
    firewall.ensure_setup()
    firewall.add("1.2.3.4")
    assert all(c[:4] == ["iptables", "-w", "-t", "nat"] for c in fake.calls)
