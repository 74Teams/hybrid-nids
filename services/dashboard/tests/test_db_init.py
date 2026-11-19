import logging

import pytest
from sqlalchemy import create_engine, inspect, text

import nids.db as database


def db_records(caplog, levelno):
    return [r.getMessage() for r in caplog.records if r.name == "nids.db" and r.levelno == levelno]


def test_init_db_retries_then_succeeds(monkeypatch, caplog):
    calls = {"n": 0}

    def flaky(bind=None):
        calls["n"] += 1
        if calls["n"] == 1:
            raise Exception("down")

    monkeypatch.setattr(database.Base.metadata, "create_all", flaky)
    monkeypatch.setattr(database, "_add_missing_columns", lambda: None)
    caplog.set_level(logging.DEBUG, logger="nids")
    database.init_db(max_retries=3, delay=0)
    assert any("lần 1/3" in m for m in db_records(caplog, logging.WARNING))
    assert any("thành công" in m for m in db_records(caplog, logging.INFO))


def test_init_db_logs_error_and_raises_when_exhausted(monkeypatch, caplog):
    def always_down(bind=None):
        raise Exception("down")

    monkeypatch.setattr(database.Base.metadata, "create_all", always_down)
    caplog.set_level(logging.DEBUG, logger="nids")
    with pytest.raises(Exception, match="down"):
        database.init_db(max_retries=2, delay=0)
    assert any("2 lần" in m for m in db_records(caplog, logging.ERROR))


@pytest.fixture
def old_db(monkeypatch, tmp_path):
    """CSDL SQLite có bảng events kiểu cũ (chưa có session_id, chưa có index) và một dòng dữ liệu."""
    engine = create_engine(f"sqlite:///{tmp_path / 'old.db'}")
    with engine.begin() as conn:
        conn.execute(text("CREATE TABLE events (id INTEGER PRIMARY KEY, timestamp DATETIME NOT NULL, summary TEXT)"))
        conn.execute(text("INSERT INTO events (timestamp, summary) VALUES ('2026-01-01 00:00:00', 'cũ')"))
    monkeypatch.setattr(database, "engine", engine)
    yield engine
    engine.dispose()


def event_columns(engine):
    return {c["name"] for c in inspect(engine).get_columns("events")}


def event_indexes(engine):
    return {i["name"] for i in inspect(engine).get_indexes("events")}


def test_init_db_upgrades_old_events_table_and_is_idempotent(old_db):
    database.init_db(max_retries=1, delay=0)
    database.init_db(max_retries=1, delay=0)
    assert "session_id" in event_columns(old_db)
    assert {"ix_events_session_id", "ix_events_timestamp"} <= event_indexes(old_db)
    with old_db.connect() as conn:
        assert conn.execute(text("SELECT summary, session_id FROM events")).all() == [("cũ", None)]


def test_add_missing_columns_adds_only_missing_index(old_db):
    """DDL của MySQL không nằm trong transaction nên lần trước có thể dừng giữa cột và index."""
    with old_db.begin() as conn:
        conn.execute(text("ALTER TABLE events ADD COLUMN session_id VARCHAR(32)"))
    database._add_missing_columns()
    assert {"ix_events_session_id", "ix_events_timestamp"} <= event_indexes(old_db)


def test_init_db_retries_when_another_process_added_column_first(monkeypatch, old_db):
    real = database._add_missing_columns
    calls = {"n": 0}

    def lost_race():
        calls["n"] += 1
        if calls["n"] == 1:
            raise Exception("duplicate column name: session_id")
        real()

    monkeypatch.setattr(database, "_add_missing_columns", lost_race)
    database.init_db(max_retries=2, delay=0)
    assert calls["n"] == 2 and "session_id" in event_columns(old_db)


def test_init_db_raises_when_upgrade_keeps_failing(monkeypatch, old_db, caplog):
    def denied():
        raise Exception("ALTER command denied")

    monkeypatch.setattr(database, "_add_missing_columns", denied)
    caplog.set_level(logging.DEBUG, logger="nids")
    with pytest.raises(Exception, match="denied"):
        database.init_db(max_retries=2, delay=0)
    assert any("2 lần" in m for m in db_records(caplog, logging.ERROR))


def test_init_db_creates_redirects_table_and_is_idempotent(monkeypatch, tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'new.db'}")
    monkeypatch.setattr(database, "engine", engine)
    database.init_db(max_retries=1, delay=0)
    database.init_db(max_retries=1, delay=0)
    assert {"ip", "expires_at", "removed_at"} <= {c["name"] for c in inspect(engine).get_columns("redirects")}
    engine.dispose()
