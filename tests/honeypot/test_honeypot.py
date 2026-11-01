"""Honeypot ghi vào CSDL chung của NIDS và làm giàu cảnh báo của engine."""
import importlib
import re
import socket
import threading

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


def test_compute_hassh_matches_known_md5():
    from nids.honeypot.ssh_honeypot import compute_hassh
    # md5sum của chuỗi "k1,k2;c1;m1,m2;none"
    assert compute_hassh(["k1", "k2"], ["c1"], ["m1", "m2"], ["none"]) == "091e3b57f41272dfe6bf065e78a5cc52"


def kexinit_message(kex):
    """KEXINIT của client; thứ tự mỗi cặp danh sách là client→server rồi server→client."""
    m = paramiko.Message()
    m.add_bytes(bytes(16))
    for algos in (kex, ["ssh-rsa"], ["c1"], ["c2"], ["m1"], ["m2"], ["none"], ["zlib"], [""], [""]):
        m.add_list(algos)
    m.add_boolean(False)
    m.add_int(0)
    m.rewind()
    return m


def test_hassh_keeps_extension_markers_and_ignores_rekey():
    """Theo chuẩn HASSH, ext-info-* và kex-strict-* vẫn nằm trong danh sách kex."""
    from nids.honeypot.ssh_honeypot import HasshTransport, compute_hassh
    conn = {"src_ip": "10.0.0.9"}
    left, right = socket.socketpair()
    try:
        transport = HasshTransport(left, conn)
        transport._really_parse_kex_init(kexinit_message(["k1", "ext-info-c", "kex-strict-c-v00@openssh.com"]))
        transport._really_parse_kex_init(kexinit_message(["k2"]))
    finally:
        left.close()
        right.close()
    assert conn["hassh"] == compute_hassh(["k1", "ext-info-c", "kex-strict-c-v00@openssh.com"],
                                          ["c1"], ["m1"], ["none"])


def test_identify_client_prefers_known_hassh_then_banner():
    from nids.honeypot.ssh_honeypot import identify_client
    assert identify_client("015322ee8471fa8338c558a918183b11", "SSH-2.0-OpenSSH_9.9") == "hydra/libssh"
    assert identify_client("0" * 32, "SSH-2.0-Go") == "Go"
    assert identify_client("0" * 32, "") == "không rõ"


def test_bruteforce_tracker_alerts_once_per_burst_and_per_key():
    from nids.honeypot.ssh_honeypot import BruteForceTracker
    tracker = BruteForceTracker(threshold=3, window=60)
    assert [tracker.hit("a", now=t) for t in (0, 10, 20, 30)] == [False, False, True, False]
    assert tracker.hit("b", now=31) is False       # key khác đếm riêng
    assert tracker.hit("a", now=91) is False       # đúng bằng window: vẫn cùng đợt
    assert [tracker.hit("a", now=t) for t in (200, 210, 220)] == [False, False, True]   # đợt mới
    assert "b" not in tracker.bursts               # đợt đã hết được dọn


def test_repeated_logins_raise_one_bruteforce_event(monkeypatch):
    from nids.honeypot import ssh_honeypot
    monkeypatch.setattr(ssh_honeypot, "bruteforce", ssh_honeypot.BruteForceTracker(3, 60))
    conn = {"src_ip": "10.0.0.9", "src_port": 5555, "dst_ip": "10.0.0.1", "dst_port": 2222,
            "hassh": "0" * 32, "client_tool": "hydra/libssh"}
    for password in ("a", "b", "c", "d"):          # mỗi mật khẩu một kết nối, như hydra
        ssh_honeypot.Server(dict(conn)).check_auth_password("root", password)
    events = [e for e in EventRepository.get_recent_events() if e.attack_type == "ssh.bruteforce"]
    assert len(events) == 1 and events[0].severity == 2 and "[hydra/libssh]" in events[0].summary


def ssh_session(disabled_algorithms=None):
    """Chạy một phiên SSH thật vào client_handle: đăng nhập rồi exec một lệnh."""
    from nids.honeypot.ssh_honeypot import client_handle
    listener = socket.create_server(("127.0.0.1", 0))
    port = listener.getsockname()[1]

    def serve():
        sock, addr = listener.accept()
        client_handle(sock, addr, None, None, paramiko.RSAKey.generate(2048))

    server = threading.Thread(target=serve, daemon=True)
    server.start()
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect("127.0.0.1", port, username="root", password="toor", look_for_keys=False,
                       allow_agent=False, disabled_algorithms=disabled_algorithms)
        _, stdout, _ = client.exec_command("id")
        stdout.read()
    finally:
        client.close()
        server.join(10)
        listener.close()


def test_ssh_events_carry_hassh_that_differs_between_clients():
    ssh_session()
    ssh_session(disabled_algorithms={"ciphers": ["aes128-ctr"]})
    import nids.db as db
    with db.SessionLocal() as session:
        evidence = [p.matched_content for p in
                    session.query(models.EventPayloadModel).order_by(models.EventPayloadModel.id)]
    hashes = [re.search(r"hassh=([0-9a-f]{32})", text).group(1) for text in evidence]
    assert len(hashes) == 4                       # mỗi phiên có ssh.auth.attempt và ssh.exec
    assert hashes[0] == hashes[1] and hashes[2] == hashes[3] and hashes[0] != hashes[2]
    assert all("tool=paramiko" in text for text in evidence)   # HASSH lạ thì lấy tên từ banner
