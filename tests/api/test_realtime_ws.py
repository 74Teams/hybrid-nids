import asyncio
import threading
import time

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from starlette.websockets import WebSocketDisconnect

import nids.db as database
from nids import realtime as rt
from nids.api.routes import alerts
from nids.db.models import Base
from nids.db.repository import EventRepository

WS = "/api/alerts/ws"


class FakePubSub:
    def __init__(self, messages=(), confirm=True, fail_subscribe=False, fail_listen=False):
        self.messages, self.confirm = list(messages), confirm
        self.fail_subscribe, self.fail_listen = fail_subscribe, fail_listen
        self.subscribed = self.closed = False

    async def subscribe(self, channel):
        if self.fail_subscribe:
            raise ConnectionError("Redis chết")
        assert channel == rt.CHANNEL
        self.subscribed = True

    async def get_message(self, timeout=0):
        return {"type": "subscribe", "data": 1} if self.confirm else None

    async def listen(self):
        for m in self.messages:
            yield m
        if self.fail_listen:
            raise ConnectionError("đứt giữa chừng")
        await asyncio.sleep(3600)

    async def aclose(self):
        self.closed = True


class FakeClient:
    def __init__(self, pubsub):
        self._pubsub, self.closed = pubsub, False

    def pubsub(self):
        return self._pubsub

    async def aclose(self):
        self.closed = True


@pytest.fixture
def db(monkeypatch):
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    monkeypatch.setattr(database, "SessionLocal", sessionmaker(bind=engine))


@pytest.fixture
def client(db, monkeypatch):
    monkeypatch.setattr(alerts, "_ws_clients", 0)
    monkeypatch.setattr(alerts, "get_redis_settings", lambda: {"host": "h", "port": 1, "password": None})
    from nids.api.main import app
    return TestClient(app)


def use_pubsub(monkeypatch, pubsub):
    redis_client = FakeClient(pubsub)
    monkeypatch.setattr(rt, "async_client", lambda cfg: redis_client)
    return redis_client


def recv(ws, timeout=3):
    """receive_text của TestClient không có timeout: chạy ở thread để test lỗi thì fail thay vì treo CI."""
    box = []
    thread = threading.Thread(target=lambda: box.append(ws.receive_text()), daemon=True)
    thread.start()
    thread.join(timeout)
    assert box, f"không nhận được tin trong {timeout}s"
    return box[0]


def wait_for(cond, timeout=2):
    end = time.time() + timeout
    while time.time() < end and not cond():
        time.sleep(0.02)
    return cond()


def test_relays_ids_and_ignores_non_message(client, monkeypatch):
    pubsub = FakePubSub([{"type": "pong", "data": "x"}, {"type": "message", "data": "7"},
                         {"type": "message", "data": "8"}])
    redis_client = use_pubsub(monkeypatch, pubsub)
    with client.websocket_connect(WS) as ws:
        assert pubsub.subscribed  # subscribe xong trước khi accept, nếu không sẽ lỡ cảnh báo đến giữa chừng
        assert recv(ws) == "7"
        assert recv(ws) == "8"
    assert wait_for(lambda: alerts._ws_clients == 0 and pubsub.closed and redis_client.closed)


def test_redis_disabled_closes_with_1013(client, monkeypatch):
    monkeypatch.setattr(alerts, "get_redis_settings", lambda: None)
    with pytest.raises(WebSocketDisconnect) as exc:
        with client.websocket_connect(WS):
            pass
    assert exc.value.code == 1013


@pytest.mark.parametrize("pubsub", [FakePubSub(fail_subscribe=True), FakePubSub(confirm=False)],
                         ids=["subscribe-error", "no-confirmation"])
def test_subscribe_problems_close_before_accept(client, monkeypatch, pubsub):
    redis_client = use_pubsub(monkeypatch, pubsub)
    with pytest.raises(WebSocketDisconnect) as exc:
        with client.websocket_connect(WS):
            pass
    assert exc.value.code == 1013
    assert wait_for(lambda: alerts._ws_clients == 0 and redis_client.closed)


def test_missing_redis_library_closes_with_1013(client, monkeypatch):
    def no_library(cfg):
        raise ImportError("No module named 'redis'")
    monkeypatch.setattr(rt, "async_client", no_library)
    with pytest.raises(WebSocketDisconnect) as exc:
        with client.websocket_connect(WS):
            pass
    assert exc.value.code == 1013
    assert alerts._ws_clients == 0


def test_listen_error_midway_closes_with_1013(client, monkeypatch):
    pubsub = FakePubSub([{"type": "message", "data": "7"}], fail_listen=True)
    use_pubsub(monkeypatch, pubsub)
    with client.websocket_connect(WS) as ws:
        assert recv(ws) == "7"
        with pytest.raises(WebSocketDisconnect) as exc:
            ws.receive_text()
        assert exc.value.code == 1013
    assert wait_for(lambda: alerts._ws_clients == 0 and pubsub.closed)


def test_client_limit_then_slot_is_freed(client, monkeypatch):
    monkeypatch.setattr(alerts, "MAX_WS_CLIENTS", 1)
    use_pubsub(monkeypatch, FakePubSub())
    with client.websocket_connect(WS):
        with pytest.raises(WebSocketDisconnect) as exc:
            with client.websocket_connect(WS):
                pass
        assert exc.value.code == 1013
    assert wait_for(lambda: alerts._ws_clients == 0)
    with client.websocket_connect(WS):
        pass


def _alert():
    return {"timestamp": time.time(), "sid": 1, "msg": "SQLi", "severity": 1, "classtype": "web-application-attack",
            "src_ip": "1.1.1.1", "dst_ip": "2.2.2.2", "protocol": "TCP"}


def test_save_alert_publishes_committed_event_id(db, monkeypatch):
    published = []
    monkeypatch.setattr("nids.db.repository.publish_alert", published.append)
    event = EventRepository.save_alert(_alert())
    assert published == [event.id]


def test_honeypot_event_publishes_too(db, monkeypatch):
    from nids.honeypot.store import log_event
    published = []
    monkeypatch.setattr("nids.db.repository.publish_alert", published.append)
    log_event("ssh", "ssh.auth.attempt", "9.9.9.9", username="root", password="x")
    assert len(published) == 1


def test_save_alert_survives_broken_publisher(db, monkeypatch):
    def boom():
        raise RuntimeError("cấu hình hỏng")
    monkeypatch.setattr(rt, "get_redis_settings", boom)
    assert EventRepository.save_alert(_alert()).id is not None
