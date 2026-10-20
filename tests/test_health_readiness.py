"""Regression tests for API liveness and readiness endpoints."""

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.exc import SQLAlchemyError

from api.main import app
from database import db


def test_health_remains_a_liveness_check():
    response = TestClient(app).get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_readiness_succeeds_when_database_is_available(monkeypatch):
    test_engine = create_engine("sqlite:///:memory:")
    monkeypatch.setattr(db, "engine", test_engine)

    try:
        response = TestClient(app).get("/ready")

        assert response.status_code == 200
        assert response.json() == {
            "status": "ready",
            "database": "ok",
        }
    finally:
        test_engine.dispose()


def test_readiness_returns_503_when_database_fails(monkeypatch):
    class BrokenEngine:
        def connect(self):
            raise SQLAlchemyError("database password=secret")

    monkeypatch.setattr(db, "engine", BrokenEngine())

    response = TestClient(app).get("/ready")

    assert response.status_code == 503
    assert response.json() == {"detail": "Service not ready"}
    assert "secret" not in response.text
