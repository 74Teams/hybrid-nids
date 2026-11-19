import queue
import threading
import time

import pytest

from nids import realtime as rt


class FakeClient:
    def __init__(self, fail_first=False):
        self.sent = queue.Queue()
        self.fail_first = fail_first
        self.gate = None  # đặt Event để giả lập publish bị treo

    def publish(self, channel, message):
        if self.gate is not None:
            self.gate.wait(5)
        if self.fail_first:
            self.fail_first = False
            raise ConnectionError("Redis chết")
        self.sent.put((channel, message))


@pytest.fixture
def fresh(monkeypatch):
    """Hàng đợi và thread publish mới cho từng test; RETRY_SECONDS = 0 để test lỗi không phải ngủ."""
    monkeypatch.setattr(rt, "_queue", queue.Queue(maxsize=3))
    monkeypatch.setattr(rt, "_thread", None)
    monkeypatch.setattr(rt, "RETRY_SECONDS", 0)
    monkeypatch.setattr(rt, "get_redis_settings", lambda: {"host": "h", "port": 1, "password": None})


def test_disabled_is_noop(fresh, monkeypatch):
    monkeypatch.setattr(rt, "get_redis_settings", lambda: None)
    rt.publish_alert(1)
    assert rt._thread is None and rt._queue.empty()


def test_publishes_event_id_on_channel(fresh, monkeypatch):
    client = FakeClient()
    monkeypatch.setattr(rt, "_sync_client", lambda cfg: client)
    rt.publish_alert(7)
    assert client.sent.get(timeout=2) == (rt.CHANNEL, 7)


def test_hung_redis_never_blocks_caller_and_full_queue_is_silent(fresh, monkeypatch):
    client = FakeClient()
    client.gate = threading.Event()
    monkeypatch.setattr(rt, "_sync_client", lambda cfg: client)
    start = time.perf_counter()
    for i in range(10):  # nhiều hơn queue (3) + 1 tin đang bị treo trong publish
        rt.publish_alert(i)
    assert time.perf_counter() - start < 1
    client.gate.set()


def test_publish_error_keeps_thread_alive(fresh, monkeypatch):
    client = FakeClient(fail_first=True)
    monkeypatch.setattr(rt, "_sync_client", lambda cfg: client)
    rt.publish_alert(1)  # tin này mất vì Redis lỗi
    time.sleep(0.2)
    rt.publish_alert(2)
    assert client.sent.get(timeout=2) == (rt.CHANNEL, 2)
    assert rt._thread.is_alive()


def test_failure_drops_stale_backlog(fresh, monkeypatch):
    client = FakeClient(fail_first=True)
    client.gate = threading.Event()
    monkeypatch.setattr(rt, "_sync_client", lambda cfg: client)
    for event_id in (1, 2, 3):  # tin 1 bị treo trong publish, tin 2 và 3 nằm trong hàng đợi
        rt.publish_alert(event_id)
    time.sleep(0.2)
    client.gate.set()  # tin 1 lỗi -> backlog (2, 3) bị bỏ
    deadline = time.time() + 2
    while not rt._queue.empty() and time.time() < deadline:
        time.sleep(0.01)
    time.sleep(0.1)
    rt.publish_alert(4)
    assert client.sent.get(timeout=2) == (rt.CHANNEL, 4)
    assert client.sent.empty()


def test_publish_alert_never_raises(fresh, monkeypatch):
    def boom():
        raise RuntimeError("cấu hình hỏng")
    monkeypatch.setattr(rt, "get_redis_settings", boom)
    rt.publish_alert(1)
