import json
from datetime import datetime, timezone

import pytest
from scapy.all import IP, TCP, Ether, wrpcap

from tools.cic import manifest as mf
from tools.cic.labels import load_labels

HEADER = " Source IP, Source Port, Destination IP, Destination Port, Protocol, Timestamp, Label\n"


def utc(*args) -> float:
    return datetime(*args, tzinfo=timezone.utc).timestamp()


def write_pcap(path, start_ts, count=3, step=1.0):
    packets = []
    for i in range(count):
        p = Ether() / IP(src="172.16.0.1", dst="192.168.10.50") / TCP(sport=40000 + i, dport=22, flags="S")
        p.time = start_ts + i * step
        packets.append(p)
    wrpcap(str(path), packets)
    return path


def write_csv(path, rows):
    path.write_bytes((HEADER + "".join(",".join(map(str, r)) + "\n" for r in rows)).encode("latin-1"))
    return path


def chunk(index, first, last, packets=10, file=None):
    return mf.ChunkInfo(index=index, file=file or f"c{index}.pcap", packets=packets, first_ts=first, last_ts=last)


# ── Hàm nhỏ ─────────────────────────────────────────────────────────────────

def test_chunk_set_uses_start_time():
    assert mf.chunk_set("14:59", mf.FRIDAY_TEST_STARTS) == "test"
    assert mf.chunk_set("14:49", mf.FRIDAY_TEST_STARTS) == "dev"


def test_adt_clock():
    # 17:09:39 UTC = 14:09 ADT
    assert mf.adt_clock(utc(2017, 7, 7, 17, 9, 39)) == "14:09"


def test_bot_test_hosts_are_sorted_by_number_not_text():
    hosts = ["192.168.10.14", "192.168.10.9", "192.168.10.5", "192.168.10.15"]
    assert mf.pick_bot_test_hosts(hosts) == ["192.168.10.5", "192.168.10.9"]
    assert mf.pick_bot_test_hosts(reversed(hosts)) == ["192.168.10.5", "192.168.10.9"]


def test_check_chunks_accepts_consecutive_chunks():
    mf.check_chunks([chunk(0, 0, 599), chunk(1, 600, 1199)], expect_packets=20)


def test_check_chunks_rejects_wrong_total():
    with pytest.raises(mf.ManifestError, match="khác"):
        mf.check_chunks([chunk(0, 0, 599)], expect_packets=11)


def test_check_chunks_rejects_overlapping_sets():
    # bộ cắt theo số gói nằm chồng lên bộ cắt theo 10 phút
    with pytest.raises(mf.ManifestError, match="chồng"):
        mf.check_chunks([chunk(0, 0, 599), chunk(1, 300, 500)], expect_packets=None)


def test_check_chunks_rejects_chunk_longer_than_ten_minutes():
    with pytest.raises(mf.ManifestError, match="quá"):
        mf.check_chunks([chunk(0, 0, 3600)], expect_packets=None)


def test_check_chunks_rejects_empty_directory():
    with pytest.raises(mf.ManifestError):
        mf.check_chunks([], expect_packets=None)


# ── Đọc pcap và lập manifest ────────────────────────────────────────────────

def test_scan_pcap_counts_packets_and_times(tmp_path):
    start = utc(2017, 7, 7, 17, 9, 39)
    info = mf.scan_pcap(str(write_pcap(tmp_path / "a.pcap", start, count=4, step=2.0)))
    assert info["packets"] == 4
    assert info["first_ts"] == pytest.approx(start)
    assert info["last_ts"] == pytest.approx(start + 6.0)


@pytest.fixture
def friday(tmp_path):
    split = tmp_path / "split"
    split.mkdir()
    # chunk 14:09 (dev) và 14:59 (test), giờ ADT
    # gói cách nhau 200 giây để mỗi chunk dài gần 7 phút, giống chunk thật
    write_pcap(split / "fri_00000.pcap", utc(2017, 7, 7, 17, 9, 39), step=200.0)
    write_pcap(split / "fri_00001.pcap", utc(2017, 7, 7, 17, 59, 39), step=200.0)
    rows = [
        ("172.16.0.1", 40000, "192.168.10.50", 22, 6, "7/7/2017 2:10", "PortScan"),
        ("192.168.10.14", 53000, "192.168.10.3", 53, 17, "7/7/2017 2:11", "BENIGN"),
        ("192.168.10.14", 50000, "205.174.165.73", 8080, 6, "7/7/2017 3:00", "BENIGN"),
        ("192.168.10.9", 50001, "205.174.165.73", 8080, 6, "7/7/2017 3:01", "Bot"),
        ("192.168.10.5", 50002, "205.174.165.73", 8080, 6, "7/7/2017 2:12", "BENIGN"),
    ]
    labels = tmp_path / "labels"
    labels.mkdir()
    write_csv(labels / "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv", rows)
    return split, labels


def test_build_manifest_assigns_sets_labels_and_bot_hosts(friday):
    split, labels = friday
    index = load_labels(list(labels.glob("*.csv")))
    result = mf.build_manifest(split, index, "friday", mf.FRIDAY_TEST_STARTS, expect_packets=6, jobs=1)

    chunks = result["chunks"]
    assert [c["start_adt"] for c in chunks] == ["14:09", "14:59"]
    assert [c["set"] for c in chunks] == ["dev", "test"]
    assert chunks[0]["labels"]["PortScan"] == 1 and chunks[0]["labels"]["BENIGN"] == 1
    assert chunks[0]["labels"]["Bot"] == 1       # máy .5 lúc 14:12, CSV ghi BENIGN nhưng được sửa thành Bot
    assert chunks[1]["labels"]["Bot"] == 2
    assert result["bot_hosts"] == ["192.168.10.5", "192.168.10.9", "192.168.10.14"]
    assert result["bot_test_hosts"] == ["192.168.10.5", "192.168.10.9"]
    assert chunks[1]["bot_by_host"] == {"192.168.10.9": 1, "192.168.10.14": 1}
    assert result["total_packets"] == 6


def test_build_manifest_is_deterministic(friday):
    split, labels = friday
    index = load_labels(list(labels.glob("*.csv")))
    first = mf.build_manifest(split, index, "friday", mf.FRIDAY_TEST_STARTS, expect_packets=None, jobs=1)
    second = mf.build_manifest(split, index, "friday", mf.FRIDAY_TEST_STARTS, expect_packets=None, jobs=1)
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)
    assert mf.render_markdown(first) == mf.render_markdown(second)


def test_markdown_lists_every_chunk(friday):
    split, labels = friday
    index = load_labels(list(labels.glob("*.csv")))
    text = mf.render_markdown(mf.build_manifest(split, index, "friday", mf.FRIDAY_TEST_STARTS, None, jobs=1))
    assert "| 0 | 14:09 |" in text and "| 1 | 14:59 |" in text
    assert "**test**" in text
    assert "`192.168.10.5`, `192.168.10.9`" in text


def test_main_writes_outputs(friday, tmp_path):
    split, labels = friday
    out, summary = tmp_path / "out" / "m.json", tmp_path / "out" / "m.md"
    code = mf.main(["--split-dir", str(split), "--labels-dir", str(labels), "--expect-packets", "6",
                    "--out", str(out), "--summary", str(summary), "--jobs", "1"])
    assert code == 0
    assert json.loads(out.read_text(encoding="utf-8"))["total_packets"] == 6
    assert summary.read_text(encoding="utf-8").startswith("# Manifest CIC-IDS2017: friday")


def test_main_fails_when_packet_total_differs(friday, tmp_path):
    split, labels = friday
    code = mf.main(["--split-dir", str(split), "--labels-dir", str(labels), "--out", str(tmp_path / "m.json"),
                    "--summary", str(tmp_path / "m.md"), "--jobs", "1"])  # mặc định đòi 9.997.874 gói
    assert code == 1
    assert not (tmp_path / "m.json").exists()


def test_main_requires_test_starts_for_other_days(friday, tmp_path):
    split, labels = friday
    assert mf.main(["--split-dir", str(split), "--labels-dir", str(labels), "--day", "monday"]) == 2
