from datetime import datetime, timezone

import pytest

from nids.engine.flow import Flow, flow_key
from nids.engine.packet import DecodedPacket
from tools.cic.labels import (
    BENIGN,
    UNLABELED,
    cic_flow_key,
    find_label_files,
    flow_key_of,
    group_label,
    load_labels,
    parse_cic_timestamp,
)


def utc(*args) -> float:
    return datetime(*args, tzinfo=timezone.utc).timestamp()


# ── Giờ CIC: 12 giờ không AM/PM, giờ ADT (UTC-3) ────────────────────────────

def test_afternoon_hour_without_am_pm_becomes_utc():
    # 2:09 trong file buổi chiều là 14:09 ADT = 17:09 UTC
    assert parse_cic_timestamp("7/7/2017 2:09") == utc(2017, 7, 7, 17, 9)


def test_morning_hour_stays_morning():
    assert parse_cic_timestamp("7/7/2017 9:30") == utc(2017, 7, 7, 12, 30)


def test_noon_is_not_shifted():
    assert parse_cic_timestamp("7/7/2017 12:05") == utc(2017, 7, 7, 15, 5)


def test_monday_format_with_seconds():
    assert parse_cic_timestamp("03/07/2017 08:55:58") == utc(2017, 7, 3, 11, 55, 58)


def test_explicit_am_pm_is_respected():
    assert parse_cic_timestamp("7/7/2017 2:09:00 PM") == utc(2017, 7, 7, 17, 9)
    assert parse_cic_timestamp("7/7/2017 12:30:00 AM") == utc(2017, 7, 7, 3, 30)


def test_bad_timestamp_raises():
    with pytest.raises(ValueError):
        parse_cic_timestamp("2017-07-07 14:09")


# ── Khoá flow ───────────────────────────────────────────────────────────────

def test_key_is_the_same_in_both_directions():
    assert cic_flow_key("1.1.1.1", 5, "2.2.2.2", 80, 6) == cic_flow_key("2.2.2.2", 80, "1.1.1.1", 5, 6)


def test_key_matches_engine_flow_key():
    packet = DecodedPacket(timestamp=0.0, src_ip="192.168.10.5", dst_ip="205.174.165.73",
                           src_port=50000, dst_port=8080, protocol="TCP")
    assert cic_flow_key("205.174.165.73", 8080, "192.168.10.5", 50000, 6) == flow_key(packet)


def test_key_accepts_float_and_missing_ports():
    assert cic_flow_key("1.1.1.1", 5.0, "2.2.2.2", 80.0, 6.0) == cic_flow_key("1.1.1.1", 5, "2.2.2.2", 80, 6)
    packet = DecodedPacket(timestamp=0.0, src_ip="1.1.1.1", dst_ip="2.2.2.2", src_port=None, dst_port=None,
                           protocol="ICMP")
    assert cic_flow_key("1.1.1.1", float("nan"), "2.2.2.2", 0, 1) == flow_key(packet)


def test_flow_key_of_matches_packet_key():
    packet = DecodedPacket(timestamp=0.0, src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=1234, dst_port=53,
                           protocol="UDP")
    flow = Flow(protocol="UDP", src_ip="10.0.0.2", src_port=53, dst_ip="10.0.0.1", dst_port=1234,
                first_seen=0.0, last_seen=1.0)
    assert flow_key_of(flow) == flow_key(packet)


# ── Gộp nhãn ────────────────────────────────────────────────────────────────

def test_group_label_handles_broken_encoding():
    # File WebAttacks đọc bằng latin-1 có ký tự rác giữa "Web Attack" và "Brute Force"
    assert group_label("Web Attack \x96 Brute Force") == "WebAttack"
    assert group_label("DoS Hulk") == "DoS"
    assert group_label(" BENIGN ") == BENIGN


def test_unknown_label_is_kept():
    assert group_label("NewAttack") == "NewAttack"
    assert group_label("New  Attack") == "New Attack"  # chỉ gộp khoảng trắng thừa


# ── Đọc CSV và tra nhãn ─────────────────────────────────────────────────────

HEADER = "Flow ID, Source IP, Source Port, Destination IP, Destination Port, Protocol, Timestamp, Flow Duration, Label\n"


def write_csv(path, rows):
    lines = [HEADER] + [",".join(str(v) for v in row) + "\n" for row in rows]
    path.write_bytes("".join(lines).encode("latin-1"))
    return path


@pytest.fixture
def index(tmp_path):
    rows = [
        # PortScan từ kẻ tấn công lúc 14:09 ADT
        ("f1", "172.16.0.1", 40000, "192.168.10.50", 22, 6, "7/7/2017 2:09", 10, "PortScan"),
        # cùng khoá, BENIGN lúc 14:12
        ("f2", "172.16.0.1", 40000, "192.168.10.50", 22, 6, "7/7/2017 2:12", 10, "BENIGN"),
        # DNS bình thường
        ("f3", "192.168.10.14", 53000, "192.168.10.3", 53, 17, "7/7/2017 2:10", 5, "BENIGN"),
        # máy nhiễm gọi về máy điều khiển, CSV ghi BENIGN
        ("f4", "192.168.10.5", 50000, "205.174.165.73", 8080, 6, "7/7/2017 2:11", 1, "BENIGN"),
        # nhãn có ký tự lỗi mã hoá
        ("f5", "172.16.0.1", 41000, "192.168.10.50", 80, 6, "7/7/2017 9:20", 3, "Web Attack \x96 XSS"),
        # dòng rỗng ở cuối file, CIC có loại dòng này
        ("", "", "", "", "", "", "", "", ""),
    ]
    return load_labels([write_csv(tmp_path / "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv", rows)])


def test_load_skips_empty_rows(index):
    assert len(index) == 5


def test_lookup_attack_inside_window(index):
    key = cic_flow_key("192.168.10.50", 22, "172.16.0.1", 40000, 6)
    t = utc(2017, 7, 7, 17, 9, 30)
    assert index.lookup(key, t, t + 5) == ("PortScan", "PortScan")


def test_lookup_benign_only(index):
    key = cic_flow_key("192.168.10.14", 53000, "192.168.10.3", 53, 17)
    t = utc(2017, 7, 7, 17, 10, 20)
    assert index.lookup(key, t, t + 1) == (BENIGN, BENIGN)


def test_lookup_outside_tolerance_is_unlabeled(index):
    key = cic_flow_key("192.168.10.14", 53000, "192.168.10.3", 53, 17)
    t = utc(2017, 7, 7, 17, 15)  # cách dòng 17:10 năm phút, quá dung sai 120 giây
    assert index.lookup(key, t, t + 1) == (UNLABELED, UNLABELED)


def test_lookup_unknown_key_is_unlabeled(index):
    key = cic_flow_key("9.9.9.9", 1, "8.8.8.8", 2, 6)
    assert index.lookup(key, 0.0, 1e10) == (UNLABELED, UNLABELED)


def test_c2_traffic_is_corrected_to_bot(index):
    key = cic_flow_key("192.168.10.5", 50000, "205.174.165.73", 8080, 6)
    t = utc(2017, 7, 7, 17, 11)
    assert index.lookup(key, t, t) == ("Bot", BENIGN)


def test_broken_encoding_label_is_grouped(index):
    key = cic_flow_key("172.16.0.1", 41000, "192.168.10.50", 80, 6)
    t = utc(2017, 7, 7, 12, 20)
    assert index.lookup(key, t, t) == ("WebAttack", "Web Attack XSS")


def test_lookup_flow_uses_flow_fields(index):
    flow = Flow(protocol="TCP", src_ip="172.16.0.1", src_port=40000, dst_ip="192.168.10.50", dst_port=22,
                first_seen=utc(2017, 7, 7, 17, 9, 10), last_seen=utc(2017, 7, 7, 17, 9, 20))
    assert index.lookup_flow(flow) == ("PortScan", "PortScan")


def test_attack_windows_split_by_gap(tmp_path):
    rows = [
        ("a", "172.16.0.1", 1000 + i, "192.168.10.50", 80, 6, stamp, 1, "PortScan")
        for i, stamp in enumerate(["7/7/2017 1:55", "7/7/2017 1:56", "7/7/2017 1:59", "7/7/2017 2:14"])
    ]
    index = load_labels([write_csv(tmp_path / "Friday-PortScan.csv", rows)])
    windows = index.attack_windows("PortScan")
    assert windows == [
        (utc(2017, 7, 7, 16, 55), utc(2017, 7, 7, 17, 0)),   # 13:55-13:59 ADT, cộng 60 giây ở cuối
        (utc(2017, 7, 7, 17, 14), utc(2017, 7, 7, 17, 15)),
    ]


def test_missing_column_raises(tmp_path):
    path = tmp_path / "bad.csv"
    path.write_text("Source IP, Label\n1.1.1.1,BENIGN\n", encoding="latin-1")
    with pytest.raises(ValueError):
        load_labels([path])


def test_find_label_files_filters_by_day(tmp_path):
    for name in ("Friday-A.csv", "Monday-B.csv", "friday-c.csv"):
        (tmp_path / name).write_text(HEADER, encoding="latin-1")
    assert [p.name for p in find_label_files(tmp_path, "friday")] == ["Friday-A.csv", "friday-c.csv"]
    with pytest.raises(FileNotFoundError):
        find_label_files(tmp_path, "sunday")
