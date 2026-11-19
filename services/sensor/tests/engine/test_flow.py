from nids.engine.flow import FlowTracker, flow_key
from nids.engine.packet import DecodedPacket

CLIENT = ("10.0.0.5", 50000)
SERVER = ("10.0.0.9", 80)


def pkt(src, dst, ts, flags="", size=100, protocol="TCP"):
    """Dựng DecodedPacket; size là số byte của cả gói."""
    tcp_flags = {}
    if protocol == "TCP":
        tcp_flags = {"SYN": "S" in flags, "ACK": "A" in flags, "FIN": "F" in flags, "RST": "R" in flags,
                     "PSH": "P" in flags, "URG": "U" in flags, "raw_flags": flags}
    return DecodedPacket(timestamp=ts, src_ip=src[0], dst_ip=dst[0], src_port=src[1], dst_port=dst[1],
                         protocol=protocol, tcp_flags=tcp_flags, raw_packet=b"x" * size)


def icmp(src_ip, dst_ip, ts):
    return DecodedPacket(timestamp=ts, src_ip=src_ip, dst_ip=dst_ip, src_port=None, dst_port=None,
                         protocol="ICMP", raw_packet=b"x" * 64)


def test_flow_key_is_the_same_in_both_directions():
    assert flow_key(pkt(CLIENT, SERVER, 0)) == flow_key(pkt(SERVER, CLIENT, 1))
    assert flow_key(pkt(CLIENT, SERVER, 0)) != flow_key(pkt(CLIENT, ("10.0.0.9", 81), 0))
    assert flow_key(pkt(CLIENT, SERVER, 0, protocol="UDP")) != flow_key(pkt(CLIENT, SERVER, 0))


def test_both_directions_land_in_one_flow_with_counters_per_direction():
    tracker = FlowTracker()
    for p in (pkt(CLIENT, SERVER, 0, "S", 60), pkt(SERVER, CLIENT, 1, "SA", 60), pkt(CLIENT, SERVER, 2, "A", 52),
              pkt(CLIENT, SERVER, 3, "PA", 300), pkt(SERVER, CLIENT, 4, "PA", 1200)):
        assert tracker.update(p) == []
    assert len(tracker) == 1
    [flow] = tracker.flush()
    assert (flow.src_ip, flow.src_port, flow.dst_ip, flow.dst_port) == (*CLIENT, *SERVER)
    assert (flow.fwd_packets, flow.bwd_packets) == (3, 2)
    assert (flow.fwd_bytes, flow.bwd_bytes) == (60 + 52 + 300, 60 + 1200)
    assert flow.first_seen == 0 and flow.last_seen == 4 and flow.duration == 4
    assert flow.tcp_flags == "APS"   # hợp các cờ đã thấy, sắp theo chữ cái


def test_fin_from_both_sides_closes_after_final_ack_without_ghost_flow():
    tracker = FlowTracker(closing_timeout=2)
    for p in (pkt(CLIENT, SERVER, 0, "S"), pkt(SERVER, CLIENT, 0.1, "SA"), pkt(CLIENT, SERVER, 0.2, "A"),
              pkt(CLIENT, SERVER, 1.0, "FA"), pkt(SERVER, CLIENT, 1.1, "FA"), pkt(CLIENT, SERVER, 1.2, "A")):
        assert tracker.update(p) == []
    assert len(tracker) == 1          # ACK cuối vào cùng flow, không mở flow mới
    assert tracker.expire(2.0) == []  # chưa đủ closing_timeout kể từ lúc FIN thứ hai
    [flow] = tracker.expire(3.2)
    assert flow.end_reason == "fin" and flow.fwd_packets == 4 and flow.bwd_packets == 2
    assert len(tracker) == 0


def test_rst_closes_flow():
    tracker = FlowTracker(closing_timeout=2)
    tracker.update(pkt(CLIENT, SERVER, 0, "S"))
    tracker.update(pkt(SERVER, CLIENT, 0.1, "RA"))
    [flow] = tracker.expire(5)
    assert flow.end_reason == "rst" and flow.fwd_packets == 1 and flow.bwd_packets == 1


def test_idle_timeout_is_measured_by_packet_time():
    tracker = FlowTracker(idle_timeout=30)
    tracker.update(pkt(CLIENT, SERVER, 0, "A"))
    assert tracker.expire(29) == []
    [flow] = tracker.expire(30)
    assert flow.end_reason == "idle"


def test_packet_after_idle_timeout_starts_a_new_flow():
    tracker = FlowTracker(idle_timeout=30)
    tracker.update(pkt(CLIENT, SERVER, 0, "A"))
    finished = tracker.update(pkt(CLIENT, SERVER, 31, "A"))
    assert [f.end_reason for f in finished] == ["idle"]
    assert len(tracker) == 1


def test_sweep_inside_update_exports_other_idle_flows():
    tracker = FlowTracker(idle_timeout=30)
    tracker.update(pkt(CLIENT, SERVER, 0, "A"))
    finished = tracker.update(pkt(("10.0.0.7", 40000), SERVER, 45, "A"))
    assert [(f.src_ip, f.end_reason) for f in finished] == [("10.0.0.5", "idle")]


def test_active_timeout_splits_a_long_flow():
    tracker = FlowTracker(idle_timeout=30, active_timeout=120)
    finished = []
    for t in range(0, 130, 10):
        finished += tracker.update(pkt(CLIENT, SERVER, t, "A"))
    assert [f.end_reason for f in finished] == ["active"]
    assert finished[0].fwd_packets == 12      # t = 0..110
    [rest] = tracker.flush()
    assert rest.fwd_packets == 1 and rest.first_seen == 120


def test_max_flows_is_never_exceeded_and_oldest_flow_goes_first():
    tracker = FlowTracker(max_flows=2)
    tracker.update(pkt(("1.1.1.1", 1), SERVER, 0))
    tracker.update(pkt(("2.2.2.2", 2), SERVER, 1))
    tracker.update(pkt(("1.1.1.1", 1), SERVER, 2))            # cập nhật nên 1.1.1.1 không còn là flow lâu nhất
    finished = tracker.update(pkt(("3.3.3.3", 3), SERVER, 3))
    assert [(f.src_ip, f.end_reason) for f in finished] == [("2.2.2.2", "evicted")]
    assert len(tracker) == 2


def test_new_syn_on_a_closing_flow_opens_a_new_flow():
    tracker = FlowTracker(closing_timeout=2)
    tracker.update(pkt(CLIENT, SERVER, 0, "S"))
    tracker.update(pkt(CLIENT, SERVER, 0.1, "R"))
    finished = tracker.update(pkt(CLIENT, SERVER, 0.5, "S"))  # cùng cổng nguồn, kết nối mới
    assert [f.end_reason for f in finished] == ["rst"]
    assert len(tracker) == 1


def test_syn_ack_first_makes_the_receiver_the_client():
    tracker = FlowTracker()
    tracker.update(pkt(SERVER, CLIENT, 0, "SA"))
    [flow] = tracker.flush()
    assert (flow.src_ip, flow.dst_ip) == (CLIENT[0], SERVER[0])
    assert (flow.fwd_packets, flow.bwd_packets) == (0, 1)


def test_udp_and_icmp_flows_are_grouped():
    tracker = FlowTracker()
    tracker.update(pkt(("10.0.0.5", 5353), ("8.8.8.8", 53), 0, protocol="UDP"))
    tracker.update(pkt(("8.8.8.8", 53), ("10.0.0.5", 5353), 0.1, protocol="UDP"))
    tracker.update(icmp("10.0.0.5", "10.0.0.9", 1))
    tracker.update(icmp("10.0.0.9", "10.0.0.5", 1.1))
    flows = {f.protocol: f for f in tracker.flush()}
    assert (flows["UDP"].fwd_packets, flows["UDP"].bwd_packets, flows["UDP"].tcp_flags) == (1, 1, "")
    assert (flows["ICMP"].fwd_packets, flows["ICMP"].bwd_packets) == (1, 1)
    assert flows["ICMP"].src_port is None


def test_alert_count_accumulates_and_unmatched_flow_stays_zero():
    tracker = FlowTracker()
    tracker.update(pkt(CLIENT, SERVER, 0, "A"), alert_count=0)
    tracker.update(pkt(CLIENT, SERVER, 1, "PA"), alert_count=2)
    tracker.update(pkt(SERVER, CLIENT, 2, "PA"), alert_count=1)
    tracker.update(pkt(("10.0.0.7", 1), SERVER, 3, "A"))
    counts = {f.src_ip: f.alert_count for f in tracker.flush()}
    assert counts == {"10.0.0.5": 3, "10.0.0.7": 0}


def test_flush_keeps_close_reason_and_marks_open_flows_shutdown():
    tracker = FlowTracker(closing_timeout=60)
    tracker.update(pkt(CLIENT, SERVER, 0, "R"))
    tracker.update(pkt(("10.0.0.7", 1), SERVER, 0, "A"))
    assert sorted(f.end_reason for f in tracker.flush()) == ["rst", "shutdown"]
