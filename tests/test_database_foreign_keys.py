"""Regression tests for SQLite foreign-key enforcement."""

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import IntegrityError

from database.db import _create_engine
from database.models import Base


def test_sqlite_foreign_keys_are_enabled(tmp_path):
    engine = _create_engine(f"sqlite:///{tmp_path / 'foreign-keys.db'}")

    try:
        Base.metadata.create_all(engine)

        with engine.connect() as connection:
            enabled = connection.exec_driver_sql(
                "PRAGMA foreign_keys"
            ).scalar_one()

        assert enabled == 1
    finally:
        engine.dispose()


def test_sqlite_rejects_extracted_ioc_without_source(tmp_path):
    engine = _create_engine(f"sqlite:///{tmp_path / 'invalid-reference.db'}")

    try:
        Base.metadata.create_all(engine)

        with pytest.raises(IntegrityError):
            with engine.begin() as connection:
                connection.execute(
                    text(
                        "INSERT INTO extracted_iocs "
                        "(ioc_type, value, source_entry_id) "
                        "VALUES (:ioc_type, :value, :source_entry_id)"
                    ),
                    {
                        "ioc_type": "domain",
                        "value": "example.com",
                        "source_entry_id": 999999,
                    },
                )
    finally:
        engine.dispose()
