import pytest

from nids.ai.features import FEATURE_NAMES, extract_features
from nids.engine.flow import FlowTracker
from nids.engine.packet import DecodedPacket


def _tcp(ts, src, sport, dst, dport, flags, size):
    return DecodedPacket(
        timestamp=ts, src_ip=src, dst_ip=dst, src_port=sport, dst_port=dport, protocol="TCP",
        tcp_flags={"SYN": "S" in flags, "ACK": "A" in flags, "FIN": "F" in flags, "RST": "R" in flags,
                   "PSH": "P" in flags, "URG": "U" in flags, "raw_flags": flags},
        raw_packet=b"x" * size,
    )


def test_handshake_features():
    tracker = FlowTracker()
    tracker.update(_tcp(100.0, "10.0.0.1", 5000, "10.0.0.2", 80, "S", 60))
    tracker.update(_tcp(100.1, "10.0.0.2", 80, "10.0.0.1", 5000, "SA", 60))
    tracker.update(_tcp(100.3, "10.0.0.1", 5000, "10.0.0.2", 80, "A", 54))
    features = extract_features(tracker.flush()[0])

    assert list(features) == FEATURE_NAMES
    assert features["flow_duration"] == pytest.approx(0.3)
    assert (features["fwd_packets"], features["bwd_packets"]) == (2, 1)
    assert features["fwd_len_mean"] == pytest.approx(57)
    assert features["fwd_len_std"] == pytest.approx(3)
    assert features["flow_iat_mean"] == pytest.approx(0.15)
    assert features["flow_iat_std"] == pytest.approx(0.05)
    assert features["flow_packets_per_s"] == pytest.approx(10)
    assert (features["syn_count"], features["ack_count"]) == (2, 2)


def test_single_packet_flow_has_no_infinity():
    tracker = FlowTracker()
    tracker.update(_tcp(5.0, "10.0.0.1", 5000, "10.0.0.2", 22, "S", 60))
    features = extract_features(tracker.flush()[0])
    assert features["flow_packets_per_s"] == 0.0
    assert all(value == value and abs(value) != float("inf") for value in features.values())


def test_context_columns_are_zero_without_context_and_filled_with_it():
    tracker = FlowTracker()
    tracker.update(_tcp(5.0, "10.0.0.1", 5000, "10.0.0.2", 22, "S", 60))
    flow = tracker.flush()[0]
    bare = extract_features(flow)
    assert bare["src_flows_5s"] == 0 and bare["dst_flows_60s"] == 0
    filled = extract_features(flow, {"src_flows_5s": 7, "src_dst_ports_5s": 5, "dst_flows_60s": 9,
                                     "src_flows_60s": 99})
    assert filled["src_flows_5s"] == 7 and filled["src_dst_ports_5s"] == 5 and filled["dst_flows_60s"] == 9
    assert "src_flows_60s" not in filled          # cột này FlowContext vẫn tính nhưng mô hình không dùng
    assert list(filled) == FEATURE_NAMES


def test_udp_flow_has_no_tcp_flag_counts():
    tracker = FlowTracker()
    for ts, src, sport, dst, dport in ((1.0, "10.0.0.1", 5353, "10.0.0.2", 53), (1.2, "10.0.0.2", 53, "10.0.0.1", 5353)):
        tracker.update(DecodedPacket(timestamp=ts, src_ip=src, dst_ip=dst, src_port=sport, dst_port=dport,
                                     protocol="UDP", raw_packet=b"x" * 80, raw_payload=b"x" * 40))
    features = extract_features(tracker.flush()[0])
    assert features["protocol"] == 17
    assert features["syn_count"] == features["ack_count"] == features["fin_count"] == 0
    assert features["fwd_payload_bytes"] == 40 and features["bwd_payload_bytes"] == 40
    assert features["flow_iat_mean"] == pytest.approx(0.2)


def test_syn_ack_first_flips_direction_so_client_is_the_source():
    tracker = FlowTracker()
    tracker.update(_tcp(10.0, "10.0.0.2", 80, "10.0.0.1", 5000, "SA", 60))      # bắt được giữa chừng
    tracker.update(_tcp(10.1, "10.0.0.1", 5000, "10.0.0.2", 80, "A", 54))
    flow = tracker.flush()[0]
    assert (flow.src_ip, flow.dst_port) == ("10.0.0.1", 80)
    features = extract_features(flow)
    assert features["dst_port"] == 80
    assert (features["fwd_packets"], features["bwd_packets"]) == (1, 1)


def test_one_direction_flow_has_zero_ratio_and_no_division_error():
    tracker = FlowTracker()
    for index in range(3):
        tracker.update(_tcp(1.0 + index * 0.1, "10.0.0.1", 5000, "10.0.0.2", 22, "S", 60))
    features = extract_features(tracker.flush()[0])
    assert features["bwd_packets"] == 0 and features["down_up_ratio"] == 0.0
    assert features["bwd_len_min"] == 0 and features["bwd_iat_mean"] == 0.0
    assert all(value == value and abs(value) != float("inf") for value in features.values())
