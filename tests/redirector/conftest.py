import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import nids.db as db
from nids.db import models


@pytest.fixture(autouse=True)
def memory_db(monkeypatch):
    """Mỗi test dùng SQLite trong bộ nhớ, không đụng CSDL thật."""
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    models.Base.metadata.create_all(engine)
    monkeypatch.setattr(db, "SessionLocal", sessionmaker(bind=engine))
