import time

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import services.database as database
from services.database.models import Base
from services.database.repository import EventRepository


def _alert(sid, msg, severity):
    return {
        "timestamp": time.time(), "sid": sid, "msg": msg, "severity": severity,
        "classtype": "web-application-attack", "src_ip": "1.1.1.1", "dst_ip": "2.2.2.2",
        "protocol": "TCP",
    }


@pytest.fixture
def client(monkeypatch):
    """TestClient dùng SQLite in-memory; không chạy lifespan nên không đụng DB thật."""
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    monkeypatch.setattr(database, "SessionLocal", sessionmaker(bind=engine))
    from api.main import app
    return TestClient(app)


def test_stats_empty(client):
    data = client.get("/api/alerts/stats").json()
    assert data["total"] == 0
    assert data["by_severity"] == {"1": 0, "2": 0, "3": 0}
    assert data["top_attacks"] == []


def test_stats_counts_by_severity_and_top_attacks(client):
    for _ in range(3):
        EventRepository.save_alert(_alert(1, "SQLi", 1))
    EventRepository.save_alert(_alert(2, "Scan", 2))
    EventRepository.save_alert(_alert(3, "Ping", 3))
    data = client.get("/api/alerts/stats").json()
    assert data["total"] == 5
    assert data["by_severity"] == {"1": 3, "2": 1, "3": 1}
    assert data["top_attacks"][0] == {"summary": "SQLi", "sid": 1, "count": 3}


def test_delete_alerts_clears_everything(client):
    EventRepository.save_alert(_alert(1, "SQLi", 1))
    assert client.delete("/api/alerts/").json() == {"deleted": 1}
    assert client.get("/api/alerts/").json() == []
    assert client.get("/api/alerts/stats").json()["total"] == 0


def test_dashboard_page_is_served(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    assert "Hybrid NIDS" in resp.text
