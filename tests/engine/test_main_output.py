import ast
import logging
from collections import Counter
from pathlib import Path

import nids.engine.main as main
from nids.engine.main import DropCounter, format_alert, format_summary, handle_alert

ROOT = Path(__file__).resolve().parents[2]

ALERT = {
    "severity": 1,
    "sid": 1000001,
    "msg": "X",
    "src_ip": "1.1.1.1",
    "src_port": 5,
    "dst_ip": "2.2.2.2",
    "dst_port": 80,
}


def test_format_alert_with_ports():
    assert format_alert(ALERT) == "[P1] SID 1000001  X  1.1.1.1:5 → 2.2.2.2:80"


def test_format_alert_icmp_and_ai():
    alert = {**ALERT, "severity": 2, "sid": None, "src_port": None, "dst_port": None}
    assert format_alert(alert) == "[P2] AI-ANOMALY  X  1.1.1.1 → 2.2.2.2"


def test_format_summary():
    assert format_summary(10, Counter({1: 2, 3: 1})) == "Hoàn tất: 10 gói, 3 cảnh báo (P1: 2, P2: 0, P3: 1)"
    assert format_summary(5, Counter()) == "Hoàn tất: 5 gói, 0 cảnh báo (P1: 0, P2: 0, P3: 0)"
    assert format_summary(1, Counter({4: 1})) == "Hoàn tất: 1 gói, 1 cảnh báo (P1: 0, P2: 0, P3: 0, P4: 1)"


def test_drop_counter():
    counter = DropCounter(interval=5.0)
    assert counter.record(0.0) == 1
    assert counter.record(1.0) is None
    assert counter.record(2.0) is None
    assert counter.record(6.0) == 3


def test_drop_counter_keeps_total_even_when_not_reported():
    counter = DropCounter(interval=5.0)
    counter.record(0.0)
    counter.record(1.0)
    counter.record(2.0)
    assert counter.total == 3


def test_alert_shown_even_if_db_fails(monkeypatch, caplog):
    def db_down(alert_data):
        raise Exception("db down")

    monkeypatch.setattr(main.EventRepository, "save_alert", db_down)
    caplog.set_level(logging.DEBUG, logger="nids")
    handle_alert(ALERT)

    alerts = [r for r in caplog.records if r.name == "nids.alert" and r.levelno == logging.WARNING]
    assert len(alerts) == 1
    assert "SID 1000001" in alerts[0].getMessage() and alerts[0].priority == 1
    errors = [r for r in caplog.records if r.levelno == logging.ERROR]
    assert any("db down" in r.getMessage() for r in errors)


def test_no_print_calls_left():
    files = []
    for folder in ("nids",):
        files += (ROOT / folder).rglob("*.py")
    offenders = []
    for path in files:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "print":
                offenders.append(f"{path.relative_to(ROOT)}:{node.lineno}")
    assert offenders == []


def _reloader_fixture(tmp_path, first_rules):
    from nids.engine.detector import DetectionEngine
    from nids.engine.main import RuleReloader
    from nids.engine.rule_manager import RuleManager

    path = tmp_path / "web.rules"
    path.write_text(first_rules, encoding="utf-8")
    manager = RuleManager(str(tmp_path))
    manager.load_all_rules()
    engine = DetectionEngine(manager)
    return path, engine, RuleReloader(manager, engine, interval=1.0)


def _rewrite(path, data):
    """Ghi file rồi đẩy mtime lên 5 giây để chữ ký đổi dù hệ thống file làm tròn thời gian."""
    import os
    path.write_bytes(data)
    stat = path.stat()
    os.utime(path, ns=(stat.st_atime_ns, stat.st_mtime_ns + 5_000_000_000))


RULE_A = 'alert tcp any any -> any 80 (msg:"a"; content:"aaa"; sid:1; rev:1;)\n'
RULE_B = 'alert tcp any any -> any 80 (msg:"b"; content:"bbb"; sid:2; rev:1;)\n'
RULE_BAD = 'alert tcp any any -> any [80 (msg:"bad"; content:"ccc"; sid:3; rev:1;)\n'


def test_rule_reloader_activates_new_rule_file_while_running(tmp_path):
    path, engine, reloader = _reloader_fixture(tmp_path, RULE_A)
    assert [r.sid for r in engine.rules_by_proto["tcp"]] == [1]
    (tmp_path / "extra.rules").write_text(RULE_B, encoding="utf-8")
    assert reloader.check(now=reloader._checked_at + 5)
    assert sorted(r.sid for r in engine.rules_by_proto["tcp"]) == [1, 2]


def test_rule_reloader_does_not_touch_packets_waiting_in_the_queue(tmp_path):
    import queue
    path, engine, reloader = _reloader_fixture(tmp_path, RULE_A)
    waiting = queue.Queue()
    for i in range(5):
        waiting.put(i)
    _rewrite(path, (RULE_A + RULE_B).encode("utf-8"))
    assert reloader.check(now=reloader._checked_at + 5)
    assert waiting.qsize() == 5 and [waiting.get() for _ in range(5)] == [0, 1, 2, 3, 4]


def test_rule_reloader_drops_only_the_line_that_became_invalid(tmp_path):
    path, engine, reloader = _reloader_fixture(tmp_path, RULE_A + RULE_B)
    _rewrite(path, (RULE_A + RULE_BAD).replace("sid:3", "sid:2").encode("utf-8"))
    assert reloader.check(now=reloader._checked_at + 5)
    assert [r.sid for r in engine.rules_by_proto["tcp"]] == [1]


def test_rule_reloader_keeps_old_index_when_a_file_cannot_be_read(tmp_path):
    path, engine, reloader = _reloader_fixture(tmp_path, RULE_A)
    _rewrite(path, b"\xff\xfe\x00 not utf-8")
    assert not reloader.check(now=reloader._checked_at + 5)
    assert [r.sid for r in engine.rules_by_proto["tcp"]] == [1]


def test_rule_reloader_picks_up_state_change(tmp_path):
    from nids.engine.detector import DetectionEngine
    from nids.engine.main import RuleReloader
    from nids.engine.rule_manager import RuleManager

    (tmp_path / "web.rules").write_text(
        'alert tcp any any -> any 80 (msg:"a"; content:"aaa"; sid:1; rev:1;)\n', encoding="utf-8")
    manager = RuleManager(str(tmp_path))
    manager.load_all_rules()
    engine = DetectionEngine(manager)
    reloader = RuleReloader(manager, engine, interval=1.0)
    assert not reloader.check(now=reloader._checked_at + 5)  # chưa có gì đổi
    RuleManager(str(tmp_path)).save_state({"sid_overrides": {"enable": [], "disable": [1]}})
    assert not reloader.check(now=reloader._checked_at + 0.5)  # chưa tới lượt kiểm tra
    assert reloader.check(now=reloader._checked_at + 5)
    assert engine.rules_by_proto["tcp"] == []
