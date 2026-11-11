import time

from nids.engine.anomaly import AnomalyDetector
from nids.engine.packet import DecodedPacket
from nids.engine.threshold import ThresholdManager

T2017 = 1499447340.0   # 7/7/2017 17:09 UTC, giờ của gói khi replay CIC-IDS2017


def test_by_dst_suppresses_even_when_ports_change():
    # rule flood track by_dst: gói trả lời DNS tới cổng ngẫu nhiên vẫn là cùng một khoá
    tm = ThresholdManager(default_window_seconds=10)
    allowed = [tm.should_alert(1000205, f"10.0.0.{i % 5}", "192.168.10.3", 40000 + i, now=T2017 + i * 0.01,
                               track="by_dst")[0] for i in range(100)]
    assert allowed.count(True) == 1


def test_by_src_groups_by_source_only():
    tm = ThresholdManager(default_window_seconds=10)
    first = tm.should_alert(1000107, "172.16.0.1", "192.168.10.50", 22, now=T2017, track="by_src")[0]
    second = tm.should_alert(1000107, "172.16.0.1", "192.168.10.51", 80, now=T2017 + 1, track="by_src")[0]
    other = tm.should_alert(1000107, "172.16.0.2", "192.168.10.50", 22, now=T2017 + 1, track="by_src")[0]
    assert (first, second, other) == (True, False, True)


def test_normal_rule_keeps_the_old_key_with_port():
    tm = ThresholdManager(default_window_seconds=10)
    assert tm.should_alert(1000001, "1.1.1.1", "2.2.2.2", 80, now=T2017)[0]
    assert tm.should_alert(1000001, "1.1.1.1", "2.2.2.2", 8080, now=T2017)[0]   # cổng khác: khoá khác
    assert not tm.should_alert(1000001, "1.1.1.1", "2.2.2.2", 80, now=T2017 + 1)[0]


def test_window_uses_packet_time_not_wall_clock():
    tm = ThresholdManager(default_window_seconds=10)
    assert tm.should_alert(1, "a", "b", 1, now=T2017)[0]
    assert not tm.should_alert(1, "a", "b", 1, now=T2017 + 9.9)[0]
    allow, suppressed = tm.should_alert(1, "a", "b", 1, now=T2017 + 11)
    assert allow and suppressed == 1          # hết cửa sổ theo giờ gói, dù giờ máy mới trôi vài micro giây


def test_without_now_falls_back_to_wall_clock():
    tm = ThresholdManager(default_window_seconds=10)
    assert tm.should_alert(1, "a", "b", 1)[0]
    assert not tm.should_alert(1, "a", "b", 1)[0]


def test_cleanup_works_with_old_packet_times():
    # giờ gói năm 2017 nhỏ hơn giờ máy; trước đây _last_cleanup = time.time() nên cache không bao giờ được dọn
    tm = ThresholdManager(default_window_seconds=10)
    for i in range(50):
        tm.should_alert(1, f"10.0.0.{i}", "b", 1, now=T2017 + i)
    assert len(tm._cache) == 50
    tm.should_alert(1, "x", "b", 1, now=T2017 + 200)   # quá 60 giây kể từ lần dọn trước, mục cũ quá 30 giây bị xoá
    assert len(tm._cache) == 1


def test_cleanup_mark_resets_when_time_goes_back():
    tm = ThresholdManager(default_window_seconds=10)
    tm.should_alert(1, "a", "b", 1, now=time.time())
    tm.should_alert(1, "a", "b", 1, now=T2017)   # chuyển sang replay pcap cũ
    assert tm._last_cleanup == T2017


# ── ANOMALY dùng giờ của gói ───────────────────────────────────────────────

def syn(src, dst, dport, ts):
    return DecodedPacket(timestamp=ts, src_ip=src, dst_ip=dst, src_port=40000, dst_port=dport, protocol="TCP",
                         tcp_flags={"SYN": True, "ACK": False})


def scan_alerts():
    alerts = []
    detector = AnomalyDetector({}, alert_callback=alerts.append)
    # quét 30 cổng hiếm trong 3 giây, lặp lại 3 lần cách nhau 100 giây (giờ gói)
    for round_no in range(3):
        for port in range(30):
            detector.observe(syn("172.16.0.1", "192.168.10.50", 20000 + port, T2017 + round_no * 100 + port * 0.1))
    return [(a["msg"], a["timestamp"]) for a in alerts]


def test_anomaly_replay_gives_the_same_alerts_every_time():
    first = scan_alerts()
    time.sleep(0.05)
    assert scan_alerts() == first


def test_anomaly_suppression_follows_packet_time():
    # mỗi đợt quét cách nhau 100 giây > suppress_seconds mặc định (60), nên mỗi đợt có cảnh báo riêng.
    # Trước đây cửa sổ tính theo giờ máy, cả ba đợt replay trong vài mili giây nên chỉ ra một cảnh báo.
    scans = [a for a in scan_alerts() if "Port scan" in a[0]]
    assert len(scans) == 3
