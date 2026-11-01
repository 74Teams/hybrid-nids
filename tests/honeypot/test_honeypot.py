"""Honeypot ghi vào CSDL chung của NIDS và làm giàu cảnh báo của engine."""
import importlib

import paramiko
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import nids.engine.main as main
from nids.honeypot import store
from nids.honeypot.settings import Settings, settings
from nids.honeypot.web_honeypot import web_honeypot
from nids.db import models
from nids.db.repository import EventRepository


@pytest.fixture(autouse=True)
def memory_db(monkeypatch):
    """Mỗi test dùng SQLite trong bộ nhớ, không đụng CSDL thật."""
    from sqlalchemy.pool import StaticPool
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    models.Base.metadata.create_all(engine)
    import nids.db as db
    monkeypatch.setattr(db, "SessionLocal", sessionmaker(bind=engine))


def test_log_event_saved_as_honeypot_with_payload():
    store.log_event("ssh", "ssh.auth.attempt", "10.0.0.9", src_port=5555, dst_ip="10.0.0.1",
                    dst_port=2222, username="root", password="toor")
    event = EventRepository.get_recent_events()[0]
    assert (event.source_type, event.src_ip, event.dst_port, event.severity) == ("HONEYPOT", "10.0.0.9", 2222, 3)
    import nids.db as db
    with db.SessionLocal() as session:
        payload = session.query(models.EventPayloadModel).one()
    assert "password=toor" in payload.matched_content


def test_log_event_never_raises(monkeypatch):
    def boom(_):
        raise RuntimeError("db down")
    monkeypatch.setattr(EventRepository, "save_alert", boom)
    store.log_event("ssh", "ssh.command", "10.0.0.9", command="id")


def test_web_login_sqli_is_p1():
    client = web_honeypot().test_client()
    client.post("/wp-admin-login", data={"username": "a' OR 1=1--", "password": "x"})
    client.post("/wp-admin-login", data={"username": "admin", "password": "bad"})
    sqli, plain = sorted(EventRepository.get_recent_events(), key=lambda e: e.severity)
    assert (sqli.severity, plain.severity) == (1, 2)
    assert sqli.http_method == "POST" and sqli.http_uri == "/wp-admin-login"


def test_source_type_filter_and_attackers():
    store.log_event("http", "http.login", "10.0.0.9", username="a", password="b")
    EventRepository.save_alert({"msg": "rule", "classtype": "x", "severity": 2, "src_ip": "10.0.0.9", "dst_ip": "10.0.0.1"})
    assert len(EventRepository.get_recent_events(source_type="HONEYPOT")) == 1
    (attacker,) = EventRepository.get_attackers()
    assert (attacker["src_ip"], attacker["honeypot_events"], attacker["nids_alerts"]) == ("10.0.0.9", 1, 1)


def test_enrich_alert_raises_priority_only_for_honeypot_ips(monkeypatch):
    monkeypatch.setattr(main, "honeypot_ips", {"10.0.0.9"})
    alert = {"severity": 3, "msg": "X", "src_ip": "10.0.0.9"}
    assert main.enrich_alert(alert) == {"severity": 2, "msg": "X [honeypot-confirmed]", "src_ip": "10.0.0.9"}
    assert main.enrich_alert({**alert, "severity": 1})["severity"] == 1
    assert main.enrich_alert({**alert, "src_ip": "10.0.0.8"}) == {**alert, "src_ip": "10.0.0.8"}


def test_honeypot_ip_cache_reads_db_once_per_ttl():
    store.log_event("ssh", "ssh.command", "10.0.0.9", command="id")
    cache = main.HoneypotIPCache(ttl=60)
    assert "10.0.0.9" in cache and "10.0.0.8" not in cache


def test_settings_env_override(monkeypatch, tmp_path):
    monkeypatch.setenv("HONEYPY_SSH_PORT", "2022")
    monkeypatch.setenv("HONEYPY_DATA_DIR", str(tmp_path))
    s = Settings()
    assert s.ssh_port == 2022 and s.host_key_path == tmp_path.resolve() / "server.key"


def test_importing_sensors_has_no_side_effects(tmp_path, monkeypatch):
    # Trỏ vào thư mục tạm để data/server.key có sẵn trên máy dev không làm test fail
    monkeypatch.setattr(settings, "host_key_path", tmp_path / "server.key")
    import nids.honeypot.ssh_honeypot as ssh, nids.honeypot.web_honeypot as web
    importlib.reload(ssh)
    importlib.reload(web)
    assert not settings.host_key_path.exists()


class FakeChannel:
    def __init__(self, data):
        self.data, self.sent = list(data), b""

    def recv(self, _):
        return bytes([self.data.pop(0)]) if self.data else b""

    def send(self, data):
        self.sent += data

    def close(self):
        pass


def test_shell_backspace_removes_whole_utf8_char(monkeypatch):
    """Bộ gõ Telex gõ 'w' thành 'ư' (2 byte) rồi backspace: lệnh vẫn phải khớp."""
    from nids.honeypot import ssh_honeypot
    monkeypatch.setattr(ssh_honeypot, "log_event", lambda *a, **k: None)
    channel = FakeChannel("ư".encode() + b"\x7fwhoami\rexit\r")
    ssh_honeypot.emulated_shell(channel, {"src_ip": "10.0.0.9"})
    assert b"corpuser1" in channel.sent and b"command not found" not in channel.sent


def test_fake_response_recon_commands():
    from nids.honeypot.ssh_honeypot import fake_response
    out, status = fake_response("uname  -a")
    assert status == 0 and out.startswith("Linux corporate-jumpbox2 6.8.0-45-generic")
    assert fake_response("nmap") == ("bash: nmap: command not found", 127)
    assert fake_response("  ") == (None, 0)


def test_host_key_generated_once(monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "host_key_path", tmp_path / "server.key")
    from nids.honeypot.ssh_honeypot import load_host_key
    k1, k2 = load_host_key(), load_host_key()
    assert isinstance(k1, paramiko.RSAKey) and k1.get_fingerprint() == k2.get_fingerprint()
