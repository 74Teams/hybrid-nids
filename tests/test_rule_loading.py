import time

from services.detection.ids_realtime import DetectionEngine
from services.detection.manager_rules import RuleManager
from services.ingestion import DecodedPacket

R1 = 'alert tcp any any -> any 80 (msg:"a"; content:"aaa"; sid:1; rev:1;)'
R2 = 'alert tcp any any -> any 80 (msg:"b"; content:"bbb"; sid:2; rev:1;)'


def load(tmp_path, text):
    (tmp_path / "local.rules").write_bytes(text.encode("utf-8"))
    return RuleManager(str(tmp_path)).load_all_rules()


def test_crlf_lines_are_parsed(tmp_path):
    assert load(tmp_path, R1 + "\r\n" + R2 + "\r\n") == 2


def test_commented_rule_is_skipped(tmp_path):
    assert load(tmp_path, "# " + R1 + "\n" + R2 + "\n") == 1


def test_missing_dir_loads_zero_and_engine_runs(tmp_path):
    manager = RuleManager(str(tmp_path / "none"))
    assert manager.load_all_rules() == 0
    packet = DecodedPacket(
        timestamp=time.time(),
        src_ip="192.168.1.100",
        dst_ip="10.0.0.5",
        src_port=50000,
        dst_port=80,
        protocol="TCP",
        tcp_flags={"SYN": False, "ACK": True, "raw_flags": "A"},
        raw_payload=b"",
        http_data=None,
    )
    assert DetectionEngine(manager).evaluate_packet(packet) == []


def test_bad_line_and_duplicate_sid_do_not_stop_loading(tmp_path):
    bad = 'alert tcp any any -> any 80 (msg:"bad"; content:"x"; sid:9; rev:1)'
    dup = 'alert tcp any any -> any 80 (msg:"dup"; content:"ccc"; sid:1; rev:1;)'
    assert load(tmp_path, "\n".join([bad, R1, dup, R2]) + "\n") == 2
