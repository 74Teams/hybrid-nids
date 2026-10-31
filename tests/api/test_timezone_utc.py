"""Issue #14: CSDL lưu giờ UTC, so sánh và hiển thị nhất quán bất kể múi giờ của máy chạy engine."""
import os
import time
from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import nids.db as database
from nids.db.models import Base
from nids.db.repository import EventRepository

# 2023-11-14 22:13:20 UTC
FIXED_EPOCH = 1700000000


@pytest.fixture(params=["local", "ICT-7", "EST5"])
def tz(request):
    """Chạy test ở múi giờ thật của máy, UTC+7 và UTC-5 (chuỗi POSIX nên không cần gói tzdata).

    time.tzset chỉ có trên Linux/macOS, nên hai múi giờ giả lập bị bỏ qua trên Windows.
    """
    if request.param == "local":
        yield request.param
        return
    if not hasattr(time, "tzset"):
        pytest.skip("time.tzset không có trên nền tảng này")
    old = os.environ.get("TZ")
    os.environ["TZ"] = request.param
    time.tzset()
    yield request.param
    if old is None:
        os.environ.pop("TZ", None)
    else:
        os.environ["TZ"] = old
    time.tzset()


@pytest.fixture
def client(monkeypatch, tz):
    """TestClient dùng SQLite in-memory; không chạy lifespan nên không đụng DB thật."""
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    monkeypatch.setattr(database, "SessionLocal", sessionmaker(bind=engine))
    from nids.api.main import app
    return TestClient(app)


def _alert(**extra):
    return {"timestamp": time.time(), "sid": 1, "msg": "x", "severity": 2, "classtype": "web-application-attack",
            "src_ip": "1.1.1.1", "dst_ip": "2.2.2.2", "protocol": "TCP", **extra}


def test_save_alert_stores_utc(client):
    event = EventRepository.save_alert(_alert(timestamp=FIXED_EPOCH))
    assert event.timestamp == datetime(2023, 11, 14, 22, 13, 20)


def test_save_alert_without_timestamp_uses_current_utc(client):
    event = EventRepository.save_alert({k: v for k, v in _alert().items() if k != "timestamp"})
    assert abs(event.timestamp - datetime.utcnow()) < timedelta(seconds=5)


def test_honeypot_ip_recognised_right_after_touching_honeypot(client):
    EventRepository.save_alert(_alert(source_type="HONEYPOT", src_ip="9.9.9.9"))
    assert "9.9.9.9" in EventRepository.honeypot_attacker_ips()


def test_honeypot_ip_expires_after_window(client):
    EventRepository.save_alert(_alert(source_type="HONEYPOT", src_ip="9.9.9.9", timestamp=time.time() - 2 * 3600))
    EventRepository.save_alert(_alert(source_type="HONEYPOT", src_ip="8.8.8.8", timestamp=time.time() - 1800))
    assert EventRepository.honeypot_attacker_ips() == {"8.8.8.8"}


def test_api_returns_iso_utc_with_z(client):
    EventRepository.save_alert(_alert(timestamp=FIXED_EPOCH))
    alert = client.get("/api/alerts/").json()[0]
    assert alert["timestamp"] == "2023-11-14T22:13:20Z"
    assert client.get(f"/api/alerts/{alert['id']}").json()["timestamp"] == "2023-11-14T22:13:20Z"
    attacker = client.get("/api/alerts/attackers").json()[0]
    assert attacker["first_seen"] == attacker["last_seen"] == "2023-11-14T22:13:20Z"


def test_timeline_buckets_are_utc(client):
    EventRepository.save_alert(_alert())
    data = client.get("/api/alerts/timeline?minutes=60&buckets=30").json()
    assert sum(b["nids"] for b in data["buckets"]) == 1
    assert all(b["t"].endswith("Z") for b in data["buckets"])
    first = datetime.strptime(data["buckets"][0]["t"], "%Y-%m-%dT%H:%M:%SZ")
    assert abs(first - (datetime.utcnow() - timedelta(minutes=60))) < timedelta(seconds=5)


@pytest.mark.parametrize("since, expected", [
    ("2023-11-14T22:00:00Z", 1),
    ("2023-11-14T23:00:00Z", 0),
    ("2023-11-15T05:00:00+07:00", 1),   # = 22:00 UTC
    ("2023-11-15T06:00:00+07:00", 0),   # = 23:00 UTC
    ("2023-11-14T22:00:00", 1),         # không có múi giờ thì coi là UTC
    ("2023-11-14T23:00:00", 0),
])
def test_since_filter_converts_to_utc(client, since, expected):
    EventRepository.save_alert(_alert(timestamp=FIXED_EPOCH))
    resp = client.get("/api/alerts/", params={"since": since})
    assert resp.headers["X-Total-Count"] == str(expected)


@pytest.mark.parametrize("until, expected", [
    ("2023-11-14T23:00:00Z", 1),
    ("2023-11-14T22:00:00Z", 0),
    ("2023-11-15T06:00:00+07:00", 1),   # = 23:00 UTC
    ("2023-11-15T05:00:00+07:00", 0),   # = 22:00 UTC
])
def test_until_filter_converts_to_utc(client, until, expected):
    EventRepository.save_alert(_alert(timestamp=FIXED_EPOCH))
    resp = client.get("/api/alerts/", params={"until": until})
    assert resp.headers["X-Total-Count"] == str(expected)


def test_time_filter_applies_to_csv_and_delete(client):
    EventRepository.save_alert(_alert(timestamp=FIXED_EPOCH))
    csv_text = client.get("/api/alerts/export.csv", params={"since": "2023-11-15T06:00:00+07:00"}).text
    assert len(csv_text.lstrip("﻿").strip().splitlines()) == 1   # chỉ còn dòng tiêu đề
    assert client.delete("/api/alerts/", params={"since": "2023-11-15T06:00:00+07:00"}).json() == {"deleted": 0}
    assert client.delete("/api/alerts/", params={"since": "2023-11-15T05:00:00+07:00"}).json() == {"deleted": 1}
