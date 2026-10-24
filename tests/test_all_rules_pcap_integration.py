from pathlib import Path
from scapy.all import rdpcap
from services.ingestion.packet_decoder import PacketDecoder
from services.detection.manager_rules import RuleManager
from services.detection.ids_realtime import DetectionEngine

def test_all_rule_categories_in_demo_pcap():
    pcap_path = Path("pcap_samples/demo_attacks.pcap")
    assert pcap_path.exists()

    manager = RuleManager("rules")
    loaded_rules = manager.load_all_rules()
    assert loaded_rules >= 20

    engine = DetectionEngine(manager, enable_threshold=False)
    triggered_sids = set()
    engine.alert_callback = lambda a: triggered_sids.add(a["sid"])

    scapy_packets = rdpcap(str(pcap_path))
    for pkt in scapy_packets:
        decoded = PacketDecoder.decode(pkt)
        if decoded:
            engine.evaluate_packet(decoded)

    # Đảm bảo tất cả các domain tấn công đều được phát hiện trong file PCAP
    assert 1000001 in triggered_sids  # SQLi (Web Attacks)
    assert 1000010 in triggered_sids  # XSS (Web Attacks)
    assert 1000100 in triggered_sids  # Xmas Scan (Network Scans)
    assert 1000201 in triggered_sids  # SYN Flood (DoS)
    assert 1000202 in triggered_sids  # Slowloris (DoS)
    assert 1000203 in triggered_sids  # Ping of Death (DoS)
    assert 1000301 in triggered_sids  # SSH Probe (Brute Force)
    assert 1000302 in triggered_sids  # FTP Anonymous (Brute Force)
    assert 1000401 in triggered_sids  # Webshell (Malware)
    assert 1000402 in triggered_sids  # Reverse Shell (Malware)
    assert 1000404 in triggered_sids  # SQLMap User-Agent (C2 Tool)
    assert 1000501 in triggered_sids  # SNMP Public Probe (UDP Recon)
    assert 1000502 in triggered_sids  # DNS Tunneling (UDP Recon)

