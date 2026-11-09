"""Honeypot ghi vào CSDL chung của NIDS và làm giàu cảnh báo của engine."""
import importlib
import re
import socket
import threading
import time
from contextlib import contextmanager

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


@contextmanager
def ssh_shell():
    """Phiên shell SSH thật vào client_handle, mở suốt khối with."""
    from nids.honeypot.ssh_honeypot import client_handle
    listener = socket.create_server(("127.0.0.1", 0))

    def serve():
        sock, addr = listener.accept()
        client_handle(sock, addr, None, None, paramiko.RSAKey.generate(2048))

    server = threading.Thread(target=serve, daemon=True)
    server.start()
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect("127.0.0.1", listener.getsockname()[1], username="root", password="toor",
                       look_for_keys=False, allow_agent=False)
        channel = client.invoke_shell()
        channel.settimeout(10)
        read_until_prompt(channel)
        yield channel
    finally:
        client.close()
        server.join(10)
        listener.close()


def read_until_prompt(channel):
    """Shell giả ghi sự kiện rồi mới in prompt, nên thấy prompt nghĩa là sự kiện đã vào CSDL."""
    output = b""
    while not output.endswith((b"$ ", b"# ")):
        chunk = channel.recv(4096)
        assert chunk, "phiên SSH đóng trước khi có prompt"
        output += chunk


def run_command(channel, command):
    channel.send(command + "\r")
    read_until_prompt(channel)


def test_all_events_of_ssh_session_share_one_id():
    with ssh_shell() as channel:
        for command in ("pwd", "id", "whoami"):
            run_command(channel, command)
    events = sorted(EventRepository.get_recent_events(), key=lambda e: e.id)
    assert [e.attack_type for e in events] == ["ssh.auth.attempt"] + ["ssh.command"] * 3
    assert len({e.session_id for e in events}) == 1 and re.fullmatch("[0-9a-f]{32}", events[0].session_id)
    assert [e.summary.rsplit(" ", 1)[1] for e in events[1:]] == ["pwd", "id", "whoami"]


def test_parallel_ssh_sessions_from_one_ip_are_not_mixed():
    with ssh_shell() as first, ssh_shell() as second:
        run_command(first, "pwd")
        run_command(second, "id")
        run_command(first, "whoami")
        run_command(second, "uptime")
    by_session = {}
    for event in sorted(EventRepository.get_recent_events(), key=lambda e: e.id):
        if event.attack_type == "ssh.command":
            by_session.setdefault(event.session_id, []).append(event.summary.rsplit(" ", 1)[1])
    assert sorted(by_session.values()) == [["id", "uptime"], ["pwd", "whoami"]]


def web_login(client, **kwargs):
    client.post("/wp-admin-login", data={"username": "admin", "password": "bad"}, **kwargs)
    return EventRepository.get_recent_events(limit=1)[0].session_id


def test_web_cookie_keeps_session_across_requests():
    client = web_honeypot().test_client()
    client.get("/")                                # cookie được cấp ngay ở trang login
    cookie = client.get_cookie("wordpress_sess")
    assert cookie.http_only and cookie.same_site == "Lax"
    assert web_login(client) == web_login(client) == cookie.value
    assert web_login(web_honeypot().test_client()) != cookie.value   # client khác là phiên khác


@pytest.mark.parametrize("value", ["abc", "0" * 33, "Z" * 32, "'; DROP TABLE events; --"])
def test_web_rejects_malformed_session_cookie(value):
    client = web_honeypot().test_client()
    client.set_cookie("wordpress_sess", value)
    session_id = web_login(client)
    assert re.fullmatch("[0-9a-f]{32}", session_id) and client.get_cookie("wordpress_sess").value == session_id


def test_web_rejects_session_cookie_with_trailing_newline():
    """Regex có `$` hoặc re.match sẽ để lọt giá trị này và vượt cột String(32)."""
    from nids.honeypot.web_honeypot import SESSION_ID
    assert SESSION_ID.fullmatch("0" * 32) and not SESSION_ID.fullmatch("0" * 32 + "\n")


# ---- Giới hạn tài nguyên (PLAN-006, issue #27) ----

def wait_until(condition, seconds=5):
    deadline = time.monotonic() + seconds
    while not condition() and time.monotonic() < deadline:
        time.sleep(0.02)
    return condition()


def test_resource_limit_settings_defaults_and_env(monkeypatch):
    s = Settings()
    assert (s.ssh_max_connections, s.ssh_max_connections_per_ip) == (100, 20)
    assert (s.ssh_handshake_timeout, s.ssh_auth_timeout, s.ssh_idle_timeout) == (30, 90, 120)
    assert (s.http_threads, s.http_max_connections, s.http_max_body_bytes) == (8, 100, 16 * 1024)
    monkeypatch.setenv("HONEYPY_SSH_MAX_CONNECTIONS", "5")
    monkeypatch.setenv("HONEYPY_HTTP_REQUEST_TIMEOUT", "7")
    s = Settings()
    assert s.ssh_max_connections == 5 and s.http_request_timeout == 7


def test_connection_limiter_total_and_per_ip():
    from nids.honeypot.ssh_honeypot import ConnectionLimiter
    lim = ConnectionLimiter(max_total=3, max_per_ip=2)
    assert lim.acquire("a") and lim.acquire("a")
    assert not lim.acquire("a")                    # chạm trần theo IP
    assert lim.acquire("b")                        # IP khác vẫn được
    assert not lim.acquire("c")                    # chạm trần tổng
    lim.release("a")
    assert lim.acquire("c")                        # trả chỗ thì dùng lại được


def test_connection_limiter_zero_disables_and_cleans_up():
    from nids.honeypot.ssh_honeypot import ConnectionLimiter
    lim = ConnectionLimiter(max_total=0, max_per_ip=0)
    assert all(lim.acquire("a") for _ in range(500))
    for _ in range(500):
        lim.release("a")
    assert lim.total == 0 and lim.per_ip == {}     # không để lại khoá khi hết kết nối


def test_connection_limiter_rejection_log_is_rate_limited():
    from nids.honeypot.ssh_honeypot import ConnectionLimiter
    lim = ConnectionLimiter(1, 1)
    assert lim.should_log_rejection("a", now=0) is True
    assert lim.should_log_rejection("a", now=5) is False
    assert lim.should_log_rejection("b", now=5) is True
    assert lim.should_log_rejection("a", now=11) is True


class FakeSocket:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True


def test_accept_connection_rejects_over_limit_and_closes_socket():
    from nids.honeypot.ssh_honeypot import ConnectionLimiter, accept_connection
    lim = ConnectionLimiter(1, 0)
    gate = threading.Event()

    def handler(*args):
        gate.wait(5)

    first, second = FakeSocket(), FakeSocket()
    assert accept_connection(first, ("10.0.0.9", 1), None, None, None, lim, handler) is True
    assert accept_connection(second, ("10.0.0.9", 2), None, None, None, lim, handler) is False
    assert second.closed and not first.closed and lim.total == 1
    gate.set()
    assert wait_until(lambda: lim.total == 0)      # release chạy sau handler, trong finally của thread
    assert lim.per_ip == {}


def test_accept_connection_releases_slot_when_handler_raises():
    from nids.honeypot.ssh_honeypot import ConnectionLimiter, accept_connection
    lim = ConnectionLimiter(1, 0)

    def handler(*args):
        raise RuntimeError("boom")

    assert accept_connection(FakeSocket(), ("10.0.0.9", 1), None, None, None, lim, handler)
    assert wait_until(lambda: lim.total == 0)


def test_accept_connection_rolls_back_when_thread_cannot_start(monkeypatch):
    from nids.honeypot import ssh_honeypot
    lim = ssh_honeypot.ConnectionLimiter(1, 0)

    def cannot_start(self):
        raise RuntimeError("cannot start new thread")

    monkeypatch.setattr(threading.Thread, "start", cannot_start)
    sock = FakeSocket()
    assert ssh_honeypot.accept_connection(sock, ("10.0.0.9", 1), None, None, None, lim, lambda *a: None) is False
    assert sock.closed and lim.total == 0 and lim.per_ip == {}


class TimingOutChannel(FakeChannel):
    """Channel hết dữ liệu thì recv ném socket.timeout, như khi hết settimeout."""

    def __init__(self, data=b""):
        super().__init__(data)
        self.timeouts, self.closed = [], False

    def settimeout(self, value):
        self.timeouts.append(value)

    def recv(self, n):
        if self.data:
            return super().recv(n)
        raise socket.timeout()

    def close(self):
        self.closed = True


def test_shell_closes_on_idle_timeout(monkeypatch):
    from nids.honeypot import ssh_honeypot
    monkeypatch.setattr(ssh_honeypot, "log_event", lambda *a, **k: None)
    channel = TimingOutChannel(b"id\r")
    ssh_honeypot.emulated_shell(channel, {"src_ip": "10.0.0.9"}, idle_timeout=5, session_max_seconds=0)
    assert channel.closed and channel.timeouts[0] == 5 and b"timed out" in channel.sent


def test_shell_closes_when_command_too_long(monkeypatch):
    from nids.honeypot import ssh_honeypot
    logged = []
    monkeypatch.setattr(ssh_honeypot, "log_event", lambda *a, **k: logged.append(a))
    channel = FakeChannel(b"A" * 50)               # không có Enter
    ssh_honeypot.emulated_shell(channel, {"src_ip": "10.0.0.9"}, max_command_bytes=10, idle_timeout=0,
                                session_max_seconds=0)
    assert not logged and b"timed out" in channel.sent


def test_shell_closes_after_session_deadline(monkeypatch):
    from nids.honeypot import ssh_honeypot
    monkeypatch.setattr(ssh_honeypot, "log_event", lambda *a, **k: None)
    ticks = iter([0, 0, 100, 100, 100])             # monotonic: tính deadline, rồi đã quá hạn
    monkeypatch.setattr(ssh_honeypot.time, "monotonic", lambda: next(ticks))
    channel = TimingOutChannel(b"a" * 5)
    ssh_honeypot.emulated_shell(channel, {"src_ip": "10.0.0.9"}, idle_timeout=0, session_max_seconds=10)
    assert channel.closed and b"timed out" in channel.sent


def tcp_socketpair():
    """Cặp socket TCP loopback. socketpair() trên Linux là AF_UNIX nên getsockname() không có (ip, port)."""
    listener = socket.create_server(("127.0.0.1", 0))
    client = socket.create_connection(listener.getsockname())
    server, _ = listener.accept()
    listener.close()
    return server, client


def test_silent_client_is_dropped_after_handshake_timeout():
    """Kết nối mở rồi im lặng không được giữ thread mãi."""
    from nids.honeypot.ssh_honeypot import client_handle
    server_side, client_side = tcp_socketpair()
    started = time.monotonic()
    try:
        client_handle(server_side, ("10.0.0.9", 1), None, None, paramiko.RSAKey.generate(2048),
                      handshake_timeout=0.5, auth_timeout=0.5)
        assert time.monotonic() - started < 5
        assert server_side.fileno() == -1          # socket đã được đóng
    finally:
        client_side.close()


def test_dropping_silent_client_does_not_log_paramiko_traceback(caplog):
    """Đóng kết nối đang bắt tay làm thread paramiko báo 'Bad file descriptor'; đó không phải lỗi thật."""
    import logging
    from nids.honeypot.ssh_honeypot import client_handle
    server_side, client_side = tcp_socketpair()
    try:
        with caplog.at_level(logging.INFO):
            client_handle(server_side, ("10.0.0.9", 1), None, None, paramiko.RSAKey.generate(2048),
                          handshake_timeout=0.3, auth_timeout=0.3)
            time.sleep(0.5)                        # chờ thread paramiko thoát
    finally:
        client_side.close()
    assert not [r for r in caplog.records if r.name == "paramiko.transport" and r.levelno >= logging.ERROR]


def test_log_event_clips_attacker_controlled_fields():
    store.log_event("http", "http.login", "10.0.0.9", dst_ip="h" * 300, username="u" * 5000,
                    password="p" * 5000, user_agent="a" * 5000, http_uri="/" + "x" * 5000)
    event = EventRepository.get_recent_events()[0]
    assert len(event.dst_ip) == store.MAX_IP_LEN and len(event.http_uri) <= store.MAX_FIELD_LEN
    import nids.db as db
    with db.SessionLocal() as session:
        payload = session.query(models.EventPayloadModel).one()
    assert len(payload.matched_content) <= store.MAX_EVIDENCE_LEN


def test_run_web_honeypot_passes_limits_to_waitress(monkeypatch):
    from nids.honeypot import web_honeypot as web
    seen = {}
    monkeypatch.setattr(web, "serve", lambda app, **kw: seen.update(kw))
    web.run_web_honeypot(host="127.0.0.1", port=1234)
    assert seen == {"host": "127.0.0.1", "port": 1234, "threads": settings.http_threads,
                    "connection_limit": settings.http_max_connections,
                    "channel_timeout": settings.http_request_timeout,
                    "max_request_body_size": settings.http_max_body_bytes}


@contextmanager
def waitress_server(**options):
    """Honeypot HTTP chạy bằng waitress thật trên cổng tạm."""
    from waitress import create_server
    server = create_server(web_honeypot(), host="127.0.0.1", port=0, **options)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    try:
        yield server.effective_port
    finally:
        server.close()
        thread.join(5)


def test_waitress_rejects_oversized_body_and_still_logs_normal_login():
    import http.client
    form = {"Content-Type": "application/x-www-form-urlencoded"}
    with waitress_server(max_request_body_size=1024) as port:
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        conn.request("POST", "/wp-admin-login", body="username=" + "a" * 5000, headers=form)
        assert conn.getresponse().status == 413
        assert EventRepository.get_recent_events() == []          # body quá lớn không sinh sự kiện
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        conn.request("POST", "/wp-admin-login", body="username=admin&password=bad", headers=form)
        assert conn.getresponse().status == 200
    (event,) = EventRepository.get_recent_events()
    assert event.attack_type == "http.login" and event.dst_ip == "127.0.0.1"
    assert event.src_port is not None


def test_waitress_closes_silent_connection_after_channel_timeout():
    with waitress_server(channel_timeout=1, cleanup_interval=1) as port:
        sock = socket.create_connection(("127.0.0.1", port))
        sock.settimeout(10)
        started = time.monotonic()
        try:
            assert sock.recv(1) == b""                            # server đóng kết nối im lặng
        finally:
            sock.close()
        assert time.monotonic() - started < 8
