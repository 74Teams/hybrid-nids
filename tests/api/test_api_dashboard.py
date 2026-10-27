import time

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import nids.db as database
from nids.db.models import Base
from nids.db.repository import EventRepository


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
    from nids.api.main import app
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


def _seed():
    EventRepository.save_alert({**_alert(1, "SQL Injection", 1), "src_ip": "9.9.9.9", "matched_content": "' OR 1=1"})
    EventRepository.save_alert(_alert(2, "Port Scan", 2))
    EventRepository.save_alert(_alert(3, "Ping", 3))


def test_list_filters_and_total_header(client):
    _seed()
    resp = client.get("/api/alerts/?src_ip=9.9.9.9")
    assert resp.headers["X-Total-Count"] == "1"
    assert [a["sid"] for a in resp.json()] == [1]
    assert [a["sid"] for a in client.get("/api/alerts/?severity=2").json()] == [2]
    assert [a["sid"] for a in client.get("/api/alerts/?q=Scan").json()] == [2]
    # chuỗi rỗng từ form lọc không được lọc gì
    assert client.get("/api/alerts/?src_ip=&q=").headers["X-Total-Count"] == "3"
    page = client.get("/api/alerts/?limit=2&offset=2")
    assert page.headers["X-Total-Count"] == "3" and len(page.json()) == 1


def test_alert_detail_includes_payload(client):
    _seed()
    sqli = client.get("/api/alerts/?sid=1").json()[0]
    detail = client.get(f"/api/alerts/{sqli['id']}").json()
    assert detail["summary"] == "SQL Injection"
    assert detail["payload"]["matched_content"] == "' OR 1=1"
    assert client.get("/api/alerts/99999").status_code == 404


def test_delete_with_filter_only_removes_matching(client):
    _seed()
    assert client.delete("/api/alerts/?src_ip=9.9.9.9").json() == {"deleted": 1}
    assert sorted(a["sid"] for a in client.get("/api/alerts/").json()) == [2, 3]
    assert client.delete("/api/alerts/?src_ip=8.8.8.8").json() == {"deleted": 0}


def test_export_csv_respects_filter(client):
    _seed()
    resp = client.get("/api/alerts/export.csv?severity=1")
    assert resp.headers["content-type"].startswith("text/csv")
    lines = resp.text.lstrip("\ufeff").strip().splitlines()
    assert lines[0].startswith("id,timestamp,sid") and len(lines) == 2


def test_logs_page_and_stylesheet_are_served(client):
    assert "text/html" in client.get("/logs").headers["content-type"]
    assert client.get("/static/style.css").status_code == 200


def test_delete_single_alert_removes_payload_too(client):
    _seed()
    sqli = client.get("/api/alerts/?sid=1").json()[0]
    assert client.delete(f"/api/alerts/{sqli['id']}").json() == {"deleted": 1}
    assert client.get(f"/api/alerts/{sqli['id']}").status_code == 404
    assert client.get("/api/alerts/").headers["X-Total-Count"] == "2"
    assert client.delete("/api/alerts/99999").status_code == 404


def test_rules_api_lists_rules_with_group(client):
    rules = client.get("/api/rules/").json()
    assert len(rules) >= 60
    by_sid = {r["sid"]: r for r in rules}
    assert by_sid[1000001]["group"] == "WEB-ATTACK"
    assert by_sid[1000100]["group"] == "SCAN"
    assert all(r["group"] and r["raw_rule"].startswith("alert") for r in rules)


def test_rules_page_is_served(client):
    resp = client.get("/rules")
    assert resp.status_code == 200 and "text/html" in resp.headers["content-type"]


def test_timeline_counts_by_source_and_ignores_old_events(client):
    EventRepository.save_alert(_alert(1, "SQLi", 1))
    EventRepository.save_alert({**_alert(None, "ssh login", 3), "source_type": "HONEYPOT"})
    EventRepository.save_alert({**_alert(2, "old", 2), "timestamp": time.time() - 7200})
    data = client.get("/api/alerts/timeline?minutes=60&buckets=30").json()
    assert len(data["buckets"]) == 30 and data["step_seconds"] == 120
    assert sum(b["nids"] for b in data["buckets"]) == 1
    assert sum(b["honeypot"] for b in data["buckets"]) == 1
    assert client.get("/api/alerts/timeline?minutes=0").status_code == 422
