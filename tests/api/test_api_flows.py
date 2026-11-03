import time

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import nids.db as database
from nids.db.models import Base
from nids.db.repository import EventRepository
from nids.engine.flow import Flow


@pytest.fixture
def client(monkeypatch):
    """TestClient dùng SQLite in-memory; không chạy lifespan nên không đụng DB thật."""
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    monkeypatch.setattr(database, "SessionLocal", sessionmaker(bind=engine))
    from nids.api.main import app
    return TestClient(app)


def _flow(src="10.0.0.5", dst="10.0.0.9", dport=80, proto="TCP", alerts=0, ts=None, fwd_bytes=100, bwd_bytes=50):
    ts = time.time() if ts is None else ts
    return Flow(proto, src, 40000, dst, dport, first_seen=ts, last_seen=ts + 1, fwd_packets=2, bwd_packets=1,
                fwd_bytes=fwd_bytes, bwd_bytes=bwd_bytes, tcp_flags="AS", alert_count=alerts, end_reason="fin")


def _alert(ts):
    return {"timestamp": ts, "sid": 1, "msg": "x", "severity": 1, "classtype": "c",
            "src_ip": "1.1.1.1", "dst_ip": "2.2.2.2", "protocol": "TCP"}


def test_matched_false_returns_only_flows_without_alerts(client):
    EventRepository.save_flows([_flow(dport=80, alerts=2), _flow(dport=53, proto="UDP"), _flow(dport=22)])
    r = client.get("/api/flows/?matched=false")
    assert r.status_code == 200
    assert r.headers["X-Total-Count"] == "2"
    assert sorted(f["dst_port"] for f in r.json()) == [22, 53]
    assert all(f["alert_count"] == 0 for f in r.json())

    matched = client.get("/api/flows/?matched=true").json()
    assert [(f["dst_port"], f["alert_count"]) for f in matched] == [(80, 2)]


def test_filters_by_ip_port_protocol_and_since_with_timezone(client):
    now = time.time()
    EventRepository.save_flows([
        _flow(src="10.0.0.1", dport=80, ts=now - 7200),
        _flow(src="10.0.0.1", dport=443, ts=now),
        _flow(src="10.0.0.2", dport=53, proto="UDP", ts=now),
    ])
    assert [f["dst_port"] for f in client.get("/api/flows/?src_ip=10.0.0.1").json()] == [443, 80]
    assert [f["dst_port"] for f in client.get("/api/flows/?protocol=udp").json()] == [53]
    assert [f["src_ip"] for f in client.get("/api/flows/?dst_port=443").json()] == ["10.0.0.1"]
    # Mốc 1 giờ trước viết theo giờ Việt Nam (+07:00) vẫn phải loại flow 2 giờ trước
    since = time.strftime("%Y-%m-%dT%H:%M:%S+07:00", time.gmtime(now - 3600 + 7 * 3600))
    r = client.get("/api/flows/", params={"since": since, "src_ip": "10.0.0.1"})
    assert [f["dst_port"] for f in r.json()] == [443]
    assert r.json()[0]["first_seen"].endswith("Z")


def test_pagination_and_limit_cap(client):
    EventRepository.save_flows([_flow(dport=p) for p in range(1, 6)])
    r = client.get("/api/flows/?limit=2&offset=2")
    assert r.headers["X-Total-Count"] == "5" and len(r.json()) == 2
    assert client.get("/api/flows/?limit=501").status_code == 422
    assert client.get("/api/flows/?dst_port=70000").status_code == 422


def test_stats_top_lists_protocols_and_aligned_buckets(client):
    now = time.time()
    EventRepository.save_flows([
        _flow(src="10.0.0.1", dport=80, fwd_bytes=1000, bwd_bytes=0, ts=now),
        _flow(src="10.0.0.1", dport=80, fwd_bytes=1000, bwd_bytes=0, ts=now),
        _flow(src="10.0.0.2", dport=53, proto="UDP", fwd_bytes=10, bwd_bytes=10, ts=now),
        _flow(src="10.0.0.3", dport=22, ts=now - 3 * 3600),   # ngoài cửa sổ 60 phút
    ])
    EventRepository.save_alert(_alert(now))
    EventRepository.save_alert(_alert(now - 3 * 3600))

    stats = client.get("/api/flows/stats?minutes=60&buckets=6").json()
    assert stats["top_talkers"][0] == {"ip": "10.0.0.1", "bytes": 2000, "flows": 2}
    assert [t["ip"] for t in stats["top_talkers"]] == ["10.0.0.1", "10.0.0.2"]
    assert stats["top_ports"][0] == {"port": 80, "flows": 2}
    assert {p["protocol"]: p["flows"] for p in stats["protocols"]} == {"TCP": 2, "UDP": 1}
    assert len(stats["buckets"]) == 6 and stats["step_seconds"] == 600
    last = stats["buckets"][-1]
    assert (last["bytes"], last["flows"], last["alerts"]) == (2020, 3, 1)
    assert sum(b["flows"] for b in stats["buckets"]) == 3


def test_empty_database_returns_empty_results(client):
    r = client.get("/api/flows/")
    assert r.json() == [] and r.headers["X-Total-Count"] == "0"
    stats = client.get("/api/flows/stats").json()
    assert stats["top_talkers"] == [] and stats["protocols"] == []
    assert all(b["bytes"] == 0 and b["alerts"] == 0 for b in stats["buckets"])


def test_traffic_page_is_served_without_cache(client):
    r = client.get("/traffic")
    assert r.status_code == 200 and "text/html" in r.headers["content-type"]
    assert r.headers["cache-control"] == "no-cache"
