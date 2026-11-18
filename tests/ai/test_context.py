from nids.ai.context import FlowContext
from nids.engine.flow import Flow, FlowTracker
from nids.engine.packet import DecodedPacket


def _flow(src, dport, last_seen, dst="10.0.0.2", packets=2):
    return Flow(protocol="TCP", src_ip=src, src_port=40000, dst_ip=dst, dst_port=dport,
                first_seen=last_seen, last_seen=last_seen, fwd_packets=1, bwd_packets=packets - 1)


def test_one_ip_scanning_five_ports():
    context = FlowContext()
    result = None
    for index, port in enumerate([21, 22, 23, 25, 80]):
        result = context.update(_flow("172.16.0.1", port, 100.0 + index * 0.01))
    assert result["src_flows_60s"] == 5
    assert result["src_dst_ports_60s"] == 5
    assert result["src_dst_hosts_60s"] == 1
    assert result["src_short_ratio_60s"] == 1.0          # cả 5 flow chỉ có 2 gói
    assert result["dst_flows_60s"] == 5


def test_first_flow_counts_itself_and_long_flow_lowers_short_ratio():
    context = FlowContext()
    first = context.update(_flow("10.0.0.5", 80, 1.0, packets=50))
    assert first["src_flows_60s"] == 1 and first["src_short_ratio_60s"] == 0.0
    second = context.update(_flow("10.0.0.5", 81, 2.0, packets=2))
    assert second["src_short_ratio_60s"] == 0.5


def test_entries_older_than_window_leave_the_window():
    context = FlowContext(window=60.0)
    context.update(_flow("10.0.0.5", 80, 0.0))
    assert context.update(_flow("10.0.0.5", 81, 59.9))["src_flows_60s"] == 2
    assert context.update(_flow("10.0.0.5", 82, 60.0))["src_flows_60s"] == 2      # mốc 0,0 vừa ra khỏi cửa sổ
    assert context.update(_flow("10.0.0.5", 83, 200.0))["src_flows_60s"] == 1


def test_clock_never_goes_back_when_a_flow_arrives_late():
    # flow idle ra sau flow RST nên last_seen của nó nhỏ hơn đồng hồ; mốc của nó là giá trị đồng hồ
    context = FlowContext(window=60.0)
    context.update(_flow("10.0.0.5", 80, 100.0))
    late = context.update(_flow("10.0.0.5", 81, 40.0))
    assert late["src_flows_60s"] == 2                                              # không bị loại ngay
    assert context.update(_flow("10.0.0.5", 82, 159.0))["src_flows_60s"] == 3      # cả hai mốc 100 vẫn trong cửa sổ
    # hai mốc 100 đã ra khỏi cửa sổ; còn mốc 159 và flow vừa nhận
    assert context.update(_flow("10.0.0.5", 83, 161.0))["src_flows_60s"] == 2


def test_max_per_ip_drops_oldest_and_counters_follow():
    context = FlowContext(max_per_ip=3)
    result = None
    for port in (1, 2, 3, 4, 5):
        result = context.update(_flow("10.0.0.5", port, 10.0))
    assert result["src_flows_60s"] == 3
    assert result["src_dst_ports_60s"] == 3                # cổng 1 và 2 đã bị bỏ, bộ đếm cổng giảm theo


def test_max_tracked_drops_least_recent_ip_without_error():
    context = FlowContext(max_tracked=2)
    context.update(_flow("1.1.1.1", 80, 1.0, dst="9.9.9.1"))
    context.update(_flow("2.2.2.2", 80, 2.0, dst="9.9.9.2"))
    context.update(_flow("3.3.3.3", 80, 3.0, dst="9.9.9.3"))
    assert len(context) == 2
    assert context.update(_flow("1.1.1.1", 80, 4.0, dst="9.9.9.1"))["src_flows_60s"] == 1      # đã bị quên


def test_idle_ips_are_swept():
    context = FlowContext(window=60.0)
    context.update(_flow("1.1.1.1", 80, 0.0))
    context.update(_flow("2.2.2.2", 80, 100.0))
    assert len(context) == 1


def test_same_sequence_gives_same_result():
    def run():
        context = FlowContext()
        return [context.update(_flow("172.16.0.1", port, 100.0 + port * 0.01)) for port in range(1, 40)]
    assert run() == run()


def _tcp(ts, src, sport, dst, dport, flags):
    return DecodedPacket(
        timestamp=ts, src_ip=src, dst_ip=dst, src_port=sport, dst_port=dport, protocol="TCP",
        tcp_flags={"SYN": "S" in flags, "ACK": "A" in flags, "FIN": "F" in flags, "RST": "R" in flags,
                   "PSH": "P" in flags, "URG": "U" in flags, "raw_flags": flags},
        raw_packet=b"x" * 60,
    )


def test_flow_tracker_export_order_is_locked():
    """Thứ tự FlowTracker xuất flow là một phần hợp đồng với mô hình AI (đặc trưng ngữ cảnh dựa vào nó).

    Ai viết lại `FlowTracker.expire` (PLAN-009 PR7) mà làm đổi thứ tự này sẽ thấy test này đỏ: khi đó phải dựng
    lại dataset AI và học lại mô hình.
    """
    tracker = FlowTracker()
    exported = []
    packets = [
        _tcp(0.0, "10.0.0.1", 1000, "10.0.0.2", 80, "S"),       # A: bị RST, ra sau closing_timeout
        _tcp(0.1, "10.0.0.2", 80, "10.0.0.1", 1000, "R"),
        _tcp(0.5, "10.0.0.4", 3000, "10.0.0.2", 80, "S"),       # C: sống lâu, ra vì active_timeout
        _tcp(1.0, "10.0.0.3", 2000, "10.0.0.2", 80, "S"),       # B: im lặng, ra vì idle_timeout
    ]
    packets += [_tcp(float(t), "10.0.0.4", 3000, "10.0.0.2", 80, "A") for t in range(10, 131, 10)]
    for packet in packets:
        exported += tracker.update(packet)
    exported += tracker.flush()
    assert [(flow.src_port, flow.end_reason) for flow in exported] == [
        (1000, "rst"), (2000, "idle"), (3000, "active"), (3000, "shutdown")]


def test_short_window_is_full_from_the_first_seconds_of_a_scan():
    # 40 flow gõ 40 cổng khác nhau trong 4 giây: cửa sổ 5 giây đã thấy đủ, cửa sổ 60 giây cũng đếm như nhau
    context = FlowContext()
    result = None
    for index in range(40):
        result = context.update(_flow("172.16.0.1", 1000 + index, 100.0 + index * 0.1))
    assert result["src_flows_5s"] == 40 and result["src_dst_ports_5s"] == 40
    assert result["src_port_diversity_5s"] == 1.0                    # mỗi flow một cổng khác nhau


def test_short_window_forgets_while_long_window_remembers():
    context = FlowContext()
    for index in range(10):
        context.update(_flow("172.16.0.1", 2000 + index, 100.0))
    later = context.update(_flow("172.16.0.1", 3000, 110.0))         # 10 giây sau: ngoài cửa sổ 5 giây
    assert later["src_flows_5s"] == 1 and later["src_flows_60s"] == 11
    assert later["dst_flows_5s"] == 1 and later["dst_flows_60s"] == 11


def test_port_diversity_separates_scanning_from_browsing():
    scan, browse = FlowContext(), FlowContext()
    for index in range(30):
        scan_result = scan.update(_flow("10.9.9.9", 5000 + index, 50.0 + index * 0.05))
        browse_result = browse.update(_flow("10.8.8.8", 443, 50.0 + index * 0.05))
    assert scan_result["src_port_diversity_5s"] == 1.0
    assert browse_result["src_port_diversity_5s"] == 1 / 30           # một cổng cho 30 flow


def test_short_window_rate_does_not_depend_on_how_long_the_scan_has_run():
    # cùng tốc độ 100 flow/giây: 2 giây đầu và 20 giây sau đều cho cột 5 giây ngang nhau, còn cột 60 giây thì tăng
    context = FlowContext()
    early = late = None
    for index in range(2000):
        result = context.update(_flow("172.16.0.1", 1 + index % 900, 200.0 + index * 0.01))
        if index == 299:
            early = result
        late = result
    assert early["src_flows_5s"] == 300 and late["src_flows_5s"] == 500       # 5 giây * 100 flow/giây = 500
    assert early["src_dst_ports_5s"] == 300 and late["src_dst_ports_5s"] == 500
    assert late["src_flows_60s"] == 2000
