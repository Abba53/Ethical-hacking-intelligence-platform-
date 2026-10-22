"""Regression test for database initialization during API startup."""

from fastapi.testclient import TestClient
from sqlalchemy import create_engine, inspect

from api.main import create_app
from database import db


def test_api_startup_initializes_tables_in_temporary_database(
    tmp_path, monkeypatch
):
    database_file = tmp_path / "startup-test.db"
    test_engine = create_engine(f"sqlite:///{database_file}")

    monkeypatch.setattr(db, "engine", test_engine)
    monkeypatch.setattr(db, "DATABASE_URL", str(database_file))

    try:
        with TestClient(create_app()) as client:
            response = client.get("/health")
            assert response.status_code == 200

        tables = set(inspect(test_engine).get_table_names())
        assert {
            "rss_entries",
            "threatfox_iocs",
            "chainabuse_reports",
            "extracted_iocs",
            "ioc_scores",
        }.issubset(tables)
    finally:
        test_engine.dispose()


def test_api_startup_fails_when_database_initialization_fails(monkeypatch):
    def fail_database_initialization():
        raise RuntimeError("simulated database initialization failure")

    monkeypatch.setattr(
        "api.main.init_db",
        fail_database_initialization,
    )

    try:
        with TestClient(create_app()) as client:
            client.get("/health")
    except RuntimeError as exc:
        assert str(exc) == "simulated database initialization failure"
    else:
        raise AssertionError(
            "Application startup should fail when database initialization fails"
        )
