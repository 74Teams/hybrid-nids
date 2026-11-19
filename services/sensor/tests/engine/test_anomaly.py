from nids.engine.anomaly import AnomalyDetector
from nids.engine.packet import DecodedPacket

T0 = 1700000000.0


def tcp(src, dst, dport, ts, flags="S", sport=40000):
    return DecodedPacket(timestamp=ts, src_ip=src, dst_ip=dst, src_port=sport, dst_port=dport, protocol="TCP",
                         tcp_flags={"SYN": "S" in flags, "ACK": "A" in flags, "raw_flags": flags})


def udp(src, dst, sport, dport, ts):
    return DecodedPacket(timestamp=ts, src_ip=src, dst_ip=dst, src_port=sport, dst_port=dport, protocol="UDP")


def icmp(src, dst, itype, ts):
    return DecodedPacket(timestamp=ts, src_ip=src, dst_ip=dst, src_port=None, dst_port=None, protocol="ICMP", icmp_type=itype)


def run(packets, **cfg):
    alerts = []
    det = AnomalyDetector(cfg, alert_callback=alerts.append)
    for p in packets:
        det.observe(p)
    return alerts, det


def kinds(alerts):
    return [a["msg"].split(" (")[0] for a in alerts]


def test_port_scan_raises_exactly_one_suppressed_alert():
    ports = [22, 80, 443] + list(range(1000, 1027))   # 30 cổng, mở đầu bằng cổng phổ biến
    alerts, _ = run([tcp("10.0.0.100", "10.0.0.5", p, T0 + i * 0.01) for i, p in enumerate(ports)])
    scans = [a for a in alerts if a["msg"].startswith("ANOMALY Port scan")]
    assert len(scans) == 1
    a = scans[0]
    assert (a["source_type"], a["sid"], a["severity"], a["src_ip"]) == ("ANOMALY", None, 2, "10.0.0.100")
    assert "15 cổng" in a["matched_content"]
    # Trước khi đủ ngưỡng, các cổng hiếm đầu tiên chỉ sinh đúng một cảnh báo P3; sau khi bị đánh dấu scan thì không còn
    assert kinds(alerts).count("ANOMALY Rare port/ICMP type") == 1


def test_syn_flood_to_one_target_is_one_alert_and_not_a_scan():
    pkts = [tcp(f"10.1.{i // 250}.{i % 250}", "10.0.0.5", 80, T0 + i * 0.003, sport=1024 + i) for i in range(300)]
    alerts, _ = run(pkts)
    assert kinds(alerts) == ["ANOMALY SYN flood"]
    assert alerts[0]["severity"] == 1 and alerts[0]["dst_ip"] == "10.0.0.5"


def test_packet_flood_counts_every_packet_to_the_target():
    pkts = [udp("10.0.0.7", "10.0.0.5", 5353, 9999, T0 + i * 0.001) for i in range(600)]
    alerts, _ = run(pkts)
    assert kinds(alerts) == ["ANOMALY Packet flood"]


def test_host_sweep_with_ping():
    alerts, _ = run([icmp("10.0.0.100", f"10.0.0.{i}", 8, T0 + i * 0.05) for i in range(1, 13)])
    assert kinds(alerts) == ["ANOMALY Host sweep"]


def test_rare_port_and_rare_icmp_type():
    alerts, _ = run([tcp("10.0.0.9", "10.0.0.5", 31337, T0), icmp("10.0.0.8", "10.0.0.5", 13, T0 + 1)])
    assert kinds(alerts) == ["ANOMALY Rare port/ICMP type"] * 2
    assert all(a["severity"] == 3 for a in alerts)


def test_normal_traffic_raises_nothing():
    pkts = []
    for i in range(40):   # 40 client duyệt web và hỏi DNS, server trả lời
        c, ts = f"192.168.1.{i + 10}", T0 + i * 0.2
        pkts += [tcp(c, "10.0.0.5", 443, ts, sport=50000 + i), tcp("10.0.0.5", c, 50000 + i, ts + 0.001, flags="SA", sport=443),
                 tcp(c, "10.0.0.5", 443, ts + 0.002, flags="A", sport=50000 + i),
                 udp(c, "8.8.8.8", 40000 + i, 53, ts + 0.003), udp("8.8.8.8", c, 53, 40000 + i, ts + 0.004),
                 icmp(c, "10.0.0.5", 8, ts + 0.005), icmp("10.0.0.5", c, 0, ts + 0.006)]
    alerts, _ = run(pkts)
    assert alerts == []


def test_ports_spread_beyond_the_window_are_not_a_scan():
    alerts, _ = run([tcp("10.0.0.100", "10.0.0.5", p, T0 + i * 1.0) for i, p in enumerate(range(1000, 1030))], scan={"window": 5})
    assert not any(a["msg"].startswith("ANOMALY Port scan") for a in alerts)


def test_state_is_bounded_and_idle_sources_are_dropped():
    _, det = run([tcp(f"10.{i // 65536}.{i // 256 % 256}.{i % 256}", "10.0.0.5", 80, T0 + i * 1e-5) for i in range(500)],
                 max_tracked=100, flood={"syn": 10**6, "packets": 10**6})
    assert len(det._scans) <= 100
    det.observe(tcp("10.9.9.9", "10.0.0.6", 80, T0 + 60))   # một phút sau: mục cũ hết cửa sổ phải bị dọn
    assert len(det._scans) == 1 and len(det._floods) == 1


def test_thresholds_come_from_config():
    alerts, _ = run([tcp("10.0.0.100", "10.0.0.5", p, T0 + i * 0.01) for i, p in enumerate([22, 80, 443, 445, 3389])],
                    scan={"ports": 5})
    assert "ANOMALY Port scan" in kinds(alerts)
