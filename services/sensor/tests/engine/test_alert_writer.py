import logging
import threading
import time

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import nids.db as database
import nids.db.repository as repository
from nids.db.models import Base, EventModel
from nids.db.repository import EventRepository
from nids.engine.alert_writer import AlertWriter


def alert(i):
    return {"timestamp": 1700000000.0 + i, "sid": 1000001, "msg": f"cảnh báo {i}", "severity": 1,
            "src_ip": "10.0.0.5", "src_port": 50000, "dst_ip": "10.0.0.9", "dst_port": 80, "protocol": "TCP"}


class Recorder:
    def __init__(self, delay=0.0, fail_first=False):
        self.batches = []
        self.delay = delay
        self.fail_first = fail_first
        self.lock = threading.Lock()

    def __call__(self, batch):
        if self.delay:
            time.sleep(self.delay)
        with self.lock:
            if self.fail_first:
                self.fail_first = False
                raise RuntimeError("db down")
            self.batches.append(list(batch))


def test_batches_by_size_and_flushes_rest_on_close():
    saved = Recorder()
    writer = AlertWriter(saved, batch_size=200, flush_interval=60).start()
    for i in range(450):
        assert writer.submit(alert(i))
    writer.close()
    assert [len(b) for b in saved.batches] == [200, 200, 50]
    assert [a["msg"] for b in saved.batches for a in b] == [f"cảnh báo {i}" for i in range(450)]  # giữ thứ tự
    assert writer.written == 450


def test_flushes_by_time_without_waiting_for_close():
    saved = Recorder()
    writer = AlertWriter(saved, batch_size=200, flush_interval=0.1).start()
    writer.submit(alert(0))
    deadline = time.monotonic() + 3
    while not saved.batches and time.monotonic() < deadline:
        time.sleep(0.02)
    assert [len(b) for b in saved.batches] == [1]
    writer.close()


def test_db_error_is_logged_and_next_batch_still_written(caplog):
    saved = Recorder(fail_first=True)
    writer = AlertWriter(saved, batch_size=1, flush_interval=60).start()
    caplog.set_level(logging.ERROR, logger="nids")
    writer.submit(alert(0))
    writer.submit(alert(1))
    writer.close()
    assert writer.failed_batches == 1
    assert [b[0]["msg"] for b in saved.batches] == ["cảnh báo 1"]
    assert any("db down" in r.getMessage() for r in caplog.records)


def test_live_mode_drops_and_counts_when_queue_is_full():
    saved = Recorder(delay=0.5)
    writer = AlertWriter(saved, batch_size=1, flush_interval=60, max_queue=1, block=False).start()
    results = [writer.submit(alert(i)) for i in range(10)]
    assert not all(results)                         # có cảnh báo bị bỏ, nhưng submit không bao giờ chờ
    assert writer.dropped.total == results.count(False)
    writer.close()


def test_offline_mode_waits_instead_of_dropping():
    saved = Recorder(delay=0.05)
    writer = AlertWriter(saved, batch_size=1, flush_interval=60, max_queue=1, block=True, put_timeout=0.05).start()
    assert all(writer.submit(alert(i)) for i in range(10))
    writer.close()
    assert writer.dropped.total == 0 and sum(len(b) for b in saved.batches) == 10


def test_offline_submit_gives_up_when_thread_is_dead():
    writer = AlertWriter(Recorder(), block=True, put_timeout=0.05)   # không start(): thread không chạy
    assert not writer.submit(alert(0))
    assert writer.dropped.total == 1


def test_close_twice_and_submit_after_close():
    writer = AlertWriter(Recorder()).start()
    writer.close()
    writer.close()
    assert not writer.submit(alert(0))


# ── EventRepository.save_alerts ─────────────────────────────────────────────

@pytest.fixture
def memory_db(monkeypatch):
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    monkeypatch.setattr(database, "SessionLocal", factory)
    return factory


def test_save_alerts_writes_one_batch_and_publishes_after_commit(memory_db, monkeypatch):
    published = []
    monkeypatch.setattr(repository, "publish_alert", published.append)
    ids = EventRepository.save_alerts([alert(0), {**alert(1), "matched_content": "union select"}, alert(2)])
    assert len(ids) == 3 and published == ids
    session = memory_db()
    try:
        events = session.query(EventModel).order_by(EventModel.id).all()
        assert [e.id for e in events] == ids
        assert [e.summary for e in events] == ["cảnh báo 0", "cảnh báo 1", "cảnh báo 2"]
        assert events[1].payload.matched_content == "union select"
    finally:
        session.close()


def test_save_alerts_empty_batch_does_nothing(memory_db, monkeypatch):
    published = []
    monkeypatch.setattr(repository, "publish_alert", published.append)
    assert EventRepository.save_alerts([]) == [] and published == []
