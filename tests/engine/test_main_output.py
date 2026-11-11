import ast
import logging
from collections import Counter
from pathlib import Path

import pytest

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


def test_format_alert_threshold_anomaly():
    alert = {**ALERT, "severity": 2, "sid": None, "source_type": "ANOMALY", "dst_port": None}
    assert format_alert(alert) == "[P2] ANOMALY  X  1.1.1.1:5 → 2.2.2.2"


def test_anomaly_error_is_logged_and_does_not_escape(caplog):
    class Broken:
        def observe(self, packet):
            raise RuntimeError("hỏng")

    with caplog.at_level(logging.ERROR, logger="nids.engine"):
        main.observe_anomaly(Broken(), object())
        main.observe_anomaly(None, object())
    assert "hỏng" in caplog.text


def test_format_summary():
    assert format_summary(10, Counter({1: 2, 3: 1})) == "Hoàn tất: 10 gói, 3 cảnh báo (P1: 2, P2: 0, P3: 1)"
    assert format_summary(5, Counter()) == "Hoàn tất: 5 gói, 0 cảnh báo (P1: 0, P2: 0, P3: 0)"
    assert format_summary(1, Counter({4: 1})) == "Hoàn tất: 1 gói, 1 cảnh báo (P1: 0, P2: 0, P3: 0, P4: 1)"


def test_format_summary_with_speed():
    assert format_summary(3000, Counter({1: 1}), 1.5) == (
        "Hoàn tất: 3000 gói, 1 cảnh báo (P1: 1, P2: 0, P3: 0) trong 1.5 giây (2000 gói/giây)")


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
    for folder in ("nids", "tools"):
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


# ── Đọc pcap không vứt gói (PLAN-009 T4) ────────────────────────────────────

def test_enqueue_live_drops_and_counts_when_full():
    import queue
    import threading

    from nids.engine.main import enqueue_packet

    q, drops, stop = queue.Queue(maxsize=1), DropCounter(), threading.Event()
    assert enqueue_packet(q, "a", True, stop, lambda: True, drops)
    assert not enqueue_packet(q, "b", True, stop, lambda: True, drops)   # live: đầy thì bỏ, không chờ
    assert drops.total == 1 and q.qsize() == 1


def test_enqueue_offline_waits_for_free_slot():
    import queue
    import threading
    import time

    from nids.engine.main import enqueue_packet

    q, drops, stop = queue.Queue(maxsize=1), DropCounter(), threading.Event()
    q.put("a")
    threading.Timer(0.2, q.get).start()            # worker lấy gói ra sau 0,2 giây
    started = time.monotonic()
    assert enqueue_packet(q, "b", False, stop, lambda: True, drops)
    assert time.monotonic() - started >= 0.15       # đã chờ chứ không bỏ gói
    assert drops.total == 0 and q.get_nowait() == "b"


def test_enqueue_offline_stops_when_worker_is_dead(monkeypatch):
    import queue
    import threading

    from nids.engine.main import enqueue_packet

    monkeypatch.setattr(main, "OFFLINE_PUT_TIMEOUT", 0.05)
    q, drops, stop = queue.Queue(maxsize=1), DropCounter(), threading.Event()
    q.put("a")
    assert not enqueue_packet(q, "b", False, stop, lambda: False, drops)
    assert stop.is_set() and drops.total == 0


def test_wait_until_processed_returns_false_when_worker_is_dead():
    import queue

    from nids.engine.main import wait_until_processed

    q = queue.Queue()
    q.put("a")
    assert not wait_until_processed(q, lambda: False, poll=0.05)
    q.get()
    q.task_done()
    assert wait_until_processed(q, lambda: False, poll=0.05)


def _offline_engine(monkeypatch, tmp_path, count=200, queue_size=2):
    """Chạy main.main() offline trên pcap `count` gói, CSDL SQLite dạng file, hàng đợi rất nhỏ.

    Dùng file chứ không dùng in-memory + StaticPool vì flow và cảnh báo được ghi từ hai thread khác nhau.
    """
    from scapy.all import IP, TCP, Ether, wrpcap
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    import nids.db as database
    from nids.db.models import Base

    db = create_engine(f"sqlite:///{tmp_path / 'test.db'}", connect_args={"check_same_thread": False, "timeout": 30})
    Base.metadata.create_all(db)
    monkeypatch.setattr(database, "SessionLocal", sessionmaker(bind=db))
    packets = []
    for i in range(count):
        p = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=40000, dport=80, flags="A", seq=i)
        p.time = 1700000000 + i * 0.001
        packets.append(p)
    pcap = tmp_path / "many.pcap"
    wrpcap(str(pcap), packets)
    monkeypatch.setattr(main, "init_db", lambda: None)
    monkeypatch.setattr(main, "setup_logging", lambda level: None)   # giữ log đi tới caplog
    monkeypatch.setattr(logging.getLogger("nids"), "propagate", True)
    monkeypatch.setattr(main, "SETTINGS", {
        "network": {"capture_mode": "offline", "pcap_file": str(pcap), "bpf_filter": "ip"},
        "detection": {"rules_dir": str(ROOT / "rules"), "queue_max_size": queue_size},
        "flow": {"retention_hours": 0},
        "anomaly": {"enabled": False},
    })


def _finishes(target, timeout=60.0) -> bool:
    import threading

    thread = threading.Thread(target=target, daemon=True)
    thread.start()
    thread.join(timeout)
    return not thread.is_alive()


def _messages(caplog):
    return [r.getMessage() for r in caplog.records]


def test_offline_small_queue_processes_every_packet(monkeypatch, tmp_path, caplog):
    import time

    _offline_engine(monkeypatch, tmp_path)
    seen = []
    original = main.evaluate_with_stream

    def slow(engine, reassembler, packet):
        time.sleep(0.001)          # worker chậm hơn phía đọc pcap, nên hàng đợi 2 chỗ luôn đầy
        seen.append(packet)
        return original(engine, reassembler, packet)

    monkeypatch.setattr(main, "evaluate_with_stream", slow)
    caplog.set_level(logging.INFO, logger="nids")
    assert _finishes(main.main)
    assert len(seen) == 200
    assert not any("Queue đầy" in m for m in _messages(caplog))
    assert any(m.startswith("Hoàn tất: 200 gói") for m in _messages(caplog))


def test_packet_error_does_not_stop_the_worker(monkeypatch, tmp_path, caplog):
    _offline_engine(monkeypatch, tmp_path)

    def broken(engine, reassembler, packet):
        raise ValueError("gói hỏng")

    monkeypatch.setattr(main, "evaluate_with_stream", broken)
    caplog.set_level(logging.INFO, logger="nids")
    assert _finishes(main.main)
    messages = _messages(caplog)
    assert any("Lỗi khi phân tích gói" in m and "gói hỏng" in m for m in messages)
    assert any("200 gói bị bỏ qua vì lỗi khi phân tích" in m for m in messages)
    assert any(m.startswith("Hoàn tất: 200 gói") for m in messages)


# worker thread cố ý chết vì exception, pytest báo cảnh báo thread khi dọn dẹp: đó là điều test muốn tạo ra
@pytest.mark.filterwarnings("ignore::pytest.PytestUnhandledThreadExceptionWarning")
def test_dead_worker_stops_offline_reading_instead_of_hanging(monkeypatch, tmp_path, caplog):
    _offline_engine(monkeypatch, tmp_path)
    monkeypatch.setattr(main, "OFFLINE_PUT_TIMEOUT", 0.05)

    class DeadReloader:
        def __init__(self, *args, **kwargs):
            pass

        def check(self, now):
            raise RuntimeError("worker chết")   # lỗi ngoài khối try của từng gói: worker thread dừng hẳn

    monkeypatch.setattr(main, "RuleReloader", DeadReloader)
    caplog.set_level(logging.INFO, logger="nids")
    assert _finishes(main.main, timeout=30)
    messages = _messages(caplog)
    assert any("Worker thread đã dừng, ngừng đọc pcap" in m for m in messages)
    assert any("dừng trước khi xử lý hết hàng đợi" in m for m in messages)
