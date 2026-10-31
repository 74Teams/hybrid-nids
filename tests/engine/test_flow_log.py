from datetime import timedelta
from pathlib import Path

import pytest
from scapy.all import Ether, IP, Raw, TCP, UDP, wrpcap
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import nids.db as database
import nids.engine.main as main
from nids.db.models import Base, FlowModel, utc_now
from nids.db.repository import EventRepository
from nids.engine.flow import Flow, FlowTracker
from nids.engine.main import FlowLog
from tests.engine.test_flow import CLIENT, SERVER, pkt

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def db(monkeypatch):
    """SQLite in-memory dùng chung cho EventRepository; trả về sessionmaker để đọc kết quả."""
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    monkeypatch.setattr(database, "SessionLocal", factory)
    return factory


def rows(db):
    session = db()
    try:
        return session.query(FlowModel).order_by(FlowModel.id).all()
    finally:
        session.close()


def test_save_flows_stores_utc_times_duration_and_counters(db):
    flow = Flow("TCP", "10.0.0.5", 50000, "10.0.0.9", 80, first_seen=1700000000.0, last_seen=1700000001.5,
                fwd_packets=3, bwd_packets=2, fwd_bytes=412, bwd_bytes=1260, tcp_flags="APS",
                alert_count=2, end_reason="fin")
    assert EventRepository.save_flows([flow]) == 1
    [row] = rows(db)
    assert row.first_seen.isoformat() == "2023-11-14T22:13:20"
    assert row.duration == 1.5 and row.alert_count == 2 and row.end_reason == "fin"
    assert (row.src_port, row.dst_port, row.fwd_bytes, row.bwd_bytes) == (50000, 80, 412, 1260)
    assert EventRepository.save_flows([]) == 0


def test_flows_are_written_in_batches_and_close_writes_the_rest(db):
    log = FlowLog(FlowTracker(max_flows=2), batch_size=2, flush_interval=3600, retention_hours=0)
    log.on_packet(pkt(("1.1.1.1", 1), SERVER, 0, "A"))
    log.on_packet(pkt(("2.2.2.2", 2), SERVER, 1, "A"))
    assert rows(db) == []                                    # chưa có flow nào kết thúc
    log.on_packet(pkt(("3.3.3.3", 3), SERVER, 2, "A"))       # đẩy 1 flow ra, chưa đủ batch
    log.on_packet(pkt(("4.4.4.4", 4), SERVER, 3, "A"))       # đẩy flow thứ hai, đủ batch
    assert [r.src_ip for r in rows(db)] == ["1.1.1.1", "2.2.2.2"]
    log.close()
    assert sorted(r.src_ip for r in rows(db)) == ["1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"]


def test_tick_expires_flows_when_no_packets_arrive(db):
    log = FlowLog(FlowTracker(idle_timeout=30), batch_size=1, retention_hours=0)
    log.on_packet(pkt(CLIENT, SERVER, 100, "A"))
    log.tick(120)
    assert rows(db) == []
    log.tick(131)
    assert [r.end_reason for r in rows(db)] == ["idle"]


def test_database_error_does_not_crash_and_drops_only_that_batch(db, monkeypatch):
    calls = []

    def broken(flows):
        calls.append(len(flows))
        raise RuntimeError("CSDL tắt")

    monkeypatch.setattr(EventRepository, "save_flows", staticmethod(broken))
    log = FlowLog(FlowTracker(), batch_size=1, retention_hours=0)
    log.on_packet(pkt(CLIENT, SERVER, 0, "A"))
    log.close()                                              # không được ném lỗi
    assert calls == [1]


def test_tracker_error_does_not_escape_on_packet(db):
    class Broken(FlowTracker):
        def update(self, packet, alert_count=0):
            raise ValueError("lỗi")

    FlowLog(Broken(), retention_hours=0).on_packet(pkt(CLIENT, SERVER, 0, "A"))


def test_cleanup_uses_write_time_not_packet_time(db):
    """Flow của pcap cũ vừa được ghi không được bị dọn ngay."""
    session = db()
    session.add(FlowModel(first_seen=utc_now(), last_seen=utc_now(), duration=0, protocol="TCP", src_ip="9.9.9.9",
                          dst_ip="9.9.9.8", created_at=utc_now() - timedelta(hours=48)))
    session.commit()
    session.close()
    log = FlowLog(FlowTracker(), batch_size=1, retention_hours=24)
    log.on_packet(pkt(CLIENT, SERVER, 1_000_000, "R"))       # packet.timestamp từ năm 1970
    log.close()
    assert [r.src_ip for r in rows(db)] == [CLIENT[0]]       # flow 48 giờ trước bị dọn, flow vừa ghi còn


def test_replaying_a_pcap_logs_flows_with_and_without_alerts(db, monkeypatch, tmp_path):
    """Điều kiện 'xong khi' của issue #39: flow không sinh cảnh báo vẫn nằm trong bảng flows."""
    base = 1700000000

    def tcp(src, sport, dst, dport, flags, t, payload=b""):
        p = Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags)
        p = p / Raw(payload) if payload else p
        p.time = base + t
        return p

    attack = b"GET /?q=union+select+1 HTTP/1.1\r\nHost: victim\r\n\r\n"
    benign = b"GET /index.html HTTP/1.1\r\nHost: victim\r\n\r\n"
    packets = [
        tcp("10.0.0.5", 50000, "10.0.0.9", 80, "S", 0), tcp("10.0.0.9", 80, "10.0.0.5", 50000, "SA", 0.01),
        tcp("10.0.0.5", 50000, "10.0.0.9", 80, "A", 0.02), tcp("10.0.0.5", 50000, "10.0.0.9", 80, "PA", 0.03, attack),
        tcp("10.0.0.5", 50000, "10.0.0.9", 80, "FA", 0.04), tcp("10.0.0.9", 80, "10.0.0.5", 50000, "FA", 0.05),
        tcp("10.0.0.5", 50000, "10.0.0.9", 80, "A", 0.06),
        tcp("10.0.0.6", 50001, "10.0.0.9", 80, "S", 1), tcp("10.0.0.9", 80, "10.0.0.6", 50001, "SA", 1.01),
        tcp("10.0.0.6", 50001, "10.0.0.9", 80, "A", 1.02), tcp("10.0.0.6", 50001, "10.0.0.9", 80, "PA", 1.03, benign),
        Ether() / IP(src="10.0.0.6", dst="8.8.8.8") / UDP(sport=5353, dport=53) / Raw(b"\x00\x01"),
    ]
    packets[-1].time = base + 2
    pcap = tmp_path / "flows.pcap"
    wrpcap(str(pcap), packets)

    monkeypatch.setattr(main, "init_db", lambda: None)
    monkeypatch.setattr(main, "SETTINGS", {
        "network": {"capture_mode": "offline", "pcap_file": str(pcap), "bpf_filter": "ip"},
        "detection": {"rules_dir": str(ROOT / "rules")},
        "flow": {"retention_hours": 0},
    })
    main.main()

    flows = {(r.src_ip, r.protocol): r for r in rows(db)}
    assert len(flows) == 3
    attack_flow = flows[("10.0.0.5", "TCP")]
    assert attack_flow.alert_count >= 1 and (attack_flow.fwd_packets, attack_flow.bwd_packets) == (5, 2)
    assert attack_flow.end_reason == "fin"
    assert flows[("10.0.0.6", "TCP")].alert_count == 0
    assert flows[("10.0.0.6", "UDP")].alert_count == 0
    assert EventRepository.count_events() >= 1
