from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from nids.db.models import Base, EventModel


def test_rules_api_routes():
    from nids.api.main import app
    paths = app.openapi()["paths"]
    rule_paths = {p: set(ops) for p, ops in paths.items() if p.startswith("/api/rules")}
    assert rule_paths == {
        "/api/rules/": {"get"},
        "/api/rules/categories": {"get", "put"},
        "/api/rules/sids": {"post"},
        "/api/rules/sids/reset": {"post"},
        "/api/rules/categories/{name}/all": {"post"},
        "/api/rules/custom": {"get", "put"},
    }
    assert "/api/alerts/" in paths
    assert "/health" in paths


def test_health_has_no_engine_field():
    from nids.api.main import health_check
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
