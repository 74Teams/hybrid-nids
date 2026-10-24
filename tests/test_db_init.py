import logging

import pytest

import services.database as database


def db_records(caplog, levelno):
    return [r.getMessage() for r in caplog.records if r.name == "nids.db" and r.levelno == levelno]


def test_init_db_retries_then_succeeds(monkeypatch, caplog):
    calls = {"n": 0}

    def flaky(bind=None):
        calls["n"] += 1
        if calls["n"] == 1:
            raise Exception("down")

    monkeypatch.setattr(database.Base.metadata, "create_all", flaky)
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
