"""Regression tests for SQLite database path initialization."""

from sqlalchemy import inspect

from database.db import _create_engine


def test_create_engine_creates_missing_sqlite_parent_directory(tmp_path):
    database_file = tmp_path / "nested" / "data" / "platform.db"
    engine = _create_engine(f"sqlite:///{database_file}")

    try:
        assert database_file.parent.is_dir()

        with engine.begin() as connection:
            connection.exec_driver_sql("SELECT 1")

        assert inspect(engine).dialect.name == "sqlite"
        assert database_file.is_file()
    finally:
        engine.dispose()


def test_create_engine_supports_sqlite_memory_database():
    engine = _create_engine("sqlite:///:memory:")

    try:
        with engine.begin() as connection:
            result = connection.exec_driver_sql("SELECT 1")

        assert result.scalar_one() == 1
    finally:
        engine.dispose()
