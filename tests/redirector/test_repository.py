"""Truy vấn chọn IP đáng ngờ và vòng đời bảng redirects."""
import time

from nids.db.models import utc_now
from nids.db.repository import EventRepository


def alert(ip, severity=1, source_type="RULE_ENGINE", age=0.0):
    return {"timestamp": time.time() - age, "sid": 1000001, "msg": "x", "severity": severity,
            "classtype": "web-application-attack", "src_ip": ip, "dst_ip": "172.28.0.50", "protocol": "TCP",
            "source_type": source_type}


def save(n, **kwargs):
    for _ in range(n):
        EventRepository.save_alert(alert(**kwargs))


def test_ip_with_enough_alerts_is_suspicious_with_count():
    save(5, ip="1.1.1.1")
    assert EventRepository.suspicious_ips(60, 5, 2) == [("1.1.1.1", 5)]


def test_below_threshold_is_not_suspicious():
    save(4, ip="1.1.1.1")
    assert EventRepository.suspicious_ips(60, 5, 2) == []


def test_alerts_outside_window_are_ignored():
    save(5, ip="1.1.1.1", age=120)
    assert EventRepository.suspicious_ips(60, 5, 2) == []


def test_low_priority_alerts_are_ignored():
    save(5, ip="1.1.1.1", severity=3)
    assert EventRepository.suspicious_ips(60, 5, 2) == []


def test_honeypot_events_are_not_counted():
    save(5, ip="1.1.1.1", source_type="HONEYPOT")
    assert EventRepository.suspicious_ips(60, 5, 2) == []


def test_counts_each_ip_separately():
    save(3, ip="1.1.1.1")
    save(3, ip="2.2.2.2")
    assert EventRepository.suspicious_ips(60, 5, 2) == []


def test_redirect_lifecycle_active_then_expired():
    EventRepository.add_redirect("1.1.1.1", ttl_seconds=60, alert_count=5, reason="test")
    EventRepository.add_redirect("2.2.2.2", ttl_seconds=-1)
    assert [r.ip for r in EventRepository.active_redirects()] == ["1.1.1.1"]
    assert EventRepository.expire_redirects() == ["2.2.2.2"]
    assert EventRepository.expire_redirects() == []   # chỉ gỡ một lần
    assert [r.ip for r in EventRepository.list_redirects(active_only=False)] == ["2.2.2.2", "1.1.1.1"]


def test_release_redirects_marks_all_active_rows():
    EventRepository.add_redirect("1.1.1.1", ttl_seconds=60)
    EventRepository.add_redirect("2.2.2.2", ttl_seconds=60)
    assert EventRepository.release_redirects() == 2
    assert EventRepository.active_redirects() == []
    assert all(r.removed_at is not None and r.removed_at <= utc_now()
               for r in EventRepository.list_redirects(active_only=False))


def test_list_redirects_is_limited():
    for i in range(5):
        EventRepository.add_redirect(f"10.0.0.{i}", ttl_seconds=60)
    assert len(EventRepository.list_redirects(limit=3)) == 3
