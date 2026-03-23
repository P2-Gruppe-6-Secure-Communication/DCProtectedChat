"""
Shared pytest fixtures for server tests.
Uses SQLite in-memory DB for speed — no Postgres required for unit tests.
"""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

# Patch the database before importing the app
import app.db as _db_module

_TEST_ENGINE = create_engine(
    "sqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)

# Enable FK constraints in SQLite
@event.listens_for(_TEST_ENGINE, "connect")
def _set_sqlite_pragma(dbapi_conn, _):
    cursor = dbapi_conn.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()

_TestSession = sessionmaker(bind=_TEST_ENGINE, autoflush=False, autocommit=False)

# Monkey-patch before importing app.main
_db_module.engine = _TEST_ENGINE
_db_module.SessionLocal = _TestSession

from app.models import Base
from app.main import app, get_db


@pytest.fixture(autouse=True)
def fresh_db():
    """Recreate all tables before each test and drop after."""
    Base.metadata.create_all(bind=_TEST_ENGINE)
    yield
    Base.metadata.drop_all(bind=_TEST_ENGINE)


@pytest.fixture
def client(fresh_db):
    def _override_get_db():
        db = _TestSession()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = _override_get_db
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()
