from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from services.database.models import Base, EventModel


def test_no_rules_routes_remain():
    from api.main import app
    paths = list(app.openapi()["paths"])
    assert not any(p.startswith("/api/rules") for p in paths)
    assert "/api/alerts/" in paths
    assert "/health" in paths


def test_health_has_no_engine_field():
    from api.main import health_check
    assert health_check() == {"status": "ok", "service": "NIDS_API"}


def test_rules_table_is_gone():
    assert "rules" not in Base.metadata.tables
    assert not hasattr(EventModel, "rule_id")


def test_event_can_be_saved_without_rule_table():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as s:
        s.add(EventModel(attack_type="x", severity=1, src_ip="1.1.1.1",
                         dst_ip="2.2.2.2", protocol="TCP", summary="t"))
        s.commit()
        assert s.query(EventModel).one().attack_type == "x"
