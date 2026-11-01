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


def test_session_returns_events_oldest_first_without_other_sessions(client):
    a, b = "a" * 32, "b" * 32
    for msg, session_id in (("ls", a), ("whoami", b), ("id", a)):
        EventRepository.save_alert({**_alert(None, msg, 2), "timestamp": 1000.0, "session_id": session_id})
    EventRepository.save_alert({**_alert(None, "cuối", 2), "timestamp": 2000.0, "session_id": a})
    EventRepository.save_alert({**_alert(None, "đầu", 2), "timestamp": 500.0, "session_id": a})
    events = client.get(f"/api/alerts/sessions/{a}").json()
    assert [e["summary"] for e in events] == ["đầu", "ls", "id", "cuối"]
    assert {e["session_id"] for e in events} == {a}


def test_session_not_found_returns_404(client):
    EventRepository.save_alert(_alert(1, "SQLi", 1))     # cảnh báo rule engine không có phiên
    assert client.get("/api/alerts/sessions/" + "0" * 32).status_code == 404


def test_session_stops_at_limit(client, monkeypatch):
    from nids.api.routes import alerts
    monkeypatch.setattr(alerts, "SESSION_EVENT_LIMIT", 2)
    for msg in ("một", "hai", "ba"):
        EventRepository.save_alert({**_alert(None, msg, 2), "session_id": "a" * 32})
    assert [e["summary"] for e in client.get("/api/alerts/sessions/" + "a" * 32).json()] == ["một", "hai"]


def _session_event(msg, session_id, ts, severity=2, **extra):
    return EventRepository.save_alert({**_alert(None, msg, severity), "timestamp": ts, "session_id": session_id, **extra})


def test_by_session_collapses_each_session_into_one_row(client):
    a, b = "a" * 32, "b" * 32
    _session_event("đăng nhập", a, 1000.0, severity=3)
    _session_event("tải file", a, 1020.0, severity=1)
    _session_event("ls", a, 1010.0)
    _session_event("whoami", b, 1500.0)
    EventRepository.save_alert({**_alert(7, "SQLi", 1), "timestamp": 1200.0})
    resp = client.get("/api/alerts/?by_session=true")
    rows = resp.json()
    assert resp.headers["X-Total-Count"] == "3"
    assert [r["summary"] for r in rows] == ["whoami", "SQLi", "đăng nhập"]       # theo hoạt động mới nhất
    session_a = rows[2]
    assert session_a["event_count"] == 3 and session_a["severity"] == 1          # priority nặng nhất
    assert session_a["session_id"] == a and session_a["timestamp"].startswith("1970-01-01T00:16:40")
    assert session_a["last_timestamp"].startswith("1970-01-01T00:17:00")
    assert rows[1]["event_count"] == 1 and rows[1]["session_id"] is None          # cảnh báo NIDS vẫn một dòng


def test_by_session_keeps_events_without_session_as_separate_rows(client):
    for _ in range(2):
        EventRepository.save_alert(_alert(1, "SQLi", 1))
    resp = client.get("/api/alerts/?by_session=true")
    assert resp.headers["X-Total-Count"] == "2" and len(resp.json()) == 2


def test_by_session_paginates_by_group(client):
    for i in range(3):
        for j in range(2):
            _session_event(f"s{i}", f"{i}" * 32, 1000.0 + i * 10 + j)
    page = client.get("/api/alerts/?by_session=true&limit=2&offset=2")
    assert page.headers["X-Total-Count"] == "3"
    assert [r["summary"] for r in page.json()] == ["s0"]


def test_by_session_filter_counts_only_matching_events(client):
    a = "a" * 32
    _session_event("ls", a, 1000.0)
    _session_event("cat passwd", a, 1010.0)
    _session_event("whoami", "b" * 32, 1020.0)
    resp = client.get("/api/alerts/?by_session=true&q=passwd")
    assert resp.headers["X-Total-Count"] == "1"
    assert resp.json()[0]["event_count"] == 1 and resp.json()[0]["session_id"] == a


def test_without_by_session_list_stays_per_event(client):
    for msg in ("ls", "id"):
        _session_event(msg, "a" * 32, 1000.0)
    resp = client.get("/api/alerts/")
    assert resp.headers["X-Total-Count"] == "2" and "event_count" not in resp.json()[0]


def test_session_raw_has_full_evidence_in_order(client):
    a = "a" * 32
    long_cmd = "echo " + "x" * 600
    _session_event("late", a, 2000.0, matched_content="command=" + long_cmd + " | hassh=ab12 | tool=OpenSSH_8.9")
    _session_event("first", a, 1000.0, matched_content="user=root | password=123")
    _session_event("other", "b" * 32, 1500.0, matched_content="command=whoami")
    resp = client.get(f"/api/alerts/sessions/{a}/raw")
    assert resp.headers["content-type"].startswith("text/plain")
    lines = resp.text.splitlines()
    assert len(lines) == 2 and "user=root | password=123" in lines[0]
    assert long_cmd in lines[1] and "hassh=ab12" in lines[1] and "tool=OpenSSH_8.9" in lines[1]
    assert "whoami" not in resp.text


def test_session_raw_cannot_forge_extra_log_lines(client):
    a = "a" * 32
    _session_event("x", a, 1000.0, matched_content="command=ls\n2026-01-01T00:00:00Z ssh.command fake")
    assert len(client.get(f"/api/alerts/sessions/{a}/raw").text.splitlines()) == 1


def test_session_raw_not_found_returns_404(client):
    assert client.get("/api/alerts/sessions/" + "0" * 32 + "/raw").status_code == 404


def test_detail_and_csv_include_session_id(client):
    event = EventRepository.save_alert({**_alert(None, "ls", 2), "session_id": "a" * 32})
    assert client.get(f"/api/alerts/{event.id}").json()["session_id"] == "a" * 32
    header, row = client.get("/api/alerts/export.csv").text.lstrip("﻿").strip().splitlines()
    assert header.endswith(",session_id") and row.endswith("a" * 32)


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
    assert client.get("/static/style.css").headers["cache-control"] == "no-cache"   # sửa CSS phải có hiệu lực ngay
    for page in ("/", "/logs", "/rules"):
        assert client.get(page).headers["cache-control"] == "no-cache"


def test_logs_page_updates_live_by_default(client):
    html = client.get("/logs").text
    assert 'id="auto" checked' in html  # tắt mặc định thì cảnh báo mới chỉ hiện khi tải lại trang
    assert "syncLive();" in html


def test_live_script_is_served_and_loaded_by_both_pages(client):
    assert client.get("/static/live.js").status_code == 200
    assert "/static/live.js" in client.get("/").text
    assert "/static/live.js" in client.get("/logs").text


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


def test_redirects_lists_only_active_by_default(client):
    EventRepository.add_redirect("1.1.1.1", ttl_seconds=60, alert_count=5, reason="thử")
    EventRepository.add_redirect("2.2.2.2", ttl_seconds=-1)
    EventRepository.expire_redirects()
    rows = client.get("/api/redirects/").json()
    assert [r["ip"] for r in rows] == ["1.1.1.1"]
    assert rows[0]["alert_count"] == 5 and rows[0]["removed_at"] is None
    assert rows[0]["created_at"].endswith("Z") and rows[0]["expires_at"].endswith("Z")


def test_redirects_active_false_includes_history_newest_first(client):
    EventRepository.add_redirect("1.1.1.1", ttl_seconds=60)
    EventRepository.add_redirect("2.2.2.2", ttl_seconds=-1)
    EventRepository.expire_redirects()
    rows = client.get("/api/redirects/?active=false").json()
    assert [r["ip"] for r in rows] == ["2.2.2.2", "1.1.1.1"]
    assert rows[0]["removed_at"].endswith("Z")


def test_redirects_empty_when_none(client):
    assert client.get("/api/redirects/").json() == []
