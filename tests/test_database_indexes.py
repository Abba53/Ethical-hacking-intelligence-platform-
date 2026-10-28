"""Regression tests for safe, repeatable SQLite index upgrades."""

from sqlalchemy import create_engine, inspect, text

from database import db
from database.models import Base, RSSEntry


EXPECTED_INDEXES = {
    "rss_entries": {"ix_rss_entries_collected_at"},
    "extracted_iocs": {
        "ix_extracted_iocs_extracted_at",
        "ix_extracted_iocs_source_entry_id",
    },
    "ioc_scores": {"ix_ioc_scores_score"},
}


def test_init_db_creates_expected_indexes(tmp_path, monkeypatch):
    database_file = tmp_path / "indexes.db"
    test_engine = create_engine(f"sqlite:///{database_file}")
    monkeypatch.setattr(db, "engine", test_engine)

    try:
        db.init_db()

        inspector = inspect(test_engine)
        for table, expected in EXPECTED_INDEXES.items():
            actual = {index["name"] for index in inspector.get_indexes(table)}
            assert expected.issubset(actual)
    finally:
        test_engine.dispose()


def test_init_db_index_upgrade_is_repeatable_and_preserves_data(
    tmp_path, monkeypatch
):
    database_file = tmp_path / "existing.db"
    test_engine = create_engine(f"sqlite:///{database_file}")
    monkeypatch.setattr(db, "engine", test_engine)

    try:
        Base.metadata.create_all(test_engine)
        with test_engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO rss_entries "
                    "(source_url, title, link, published, summary, collected_at) "
                    "VALUES ('https://example.com/feed', 'Existing record', "
                    "'https://example.com/item', NULL, NULL, "
                    "'2026-01-01 00:00:00')"
                )
            )
            connection.exec_driver_sql(
                "DROP INDEX IF EXISTS ix_rss_entries_collected_at"
            )

        db.init_db()
        db.init_db()

        with test_engine.connect() as connection:
            row = connection.execute(
                text("SELECT title, link FROM rss_entries")
            ).one()

        assert row == ("Existing record", "https://example.com/item")

        inspector = inspect(test_engine)
        for table, expected in EXPECTED_INDEXES.items():
            actual = {index["name"] for index in inspector.get_indexes(table)}
            assert expected.issubset(actual)
    finally:
        test_engine.dispose()


def test_index_upgrade_skips_non_sqlite_engines():
    class NonSQLiteEngine:
        class Dialect:
            name = "postgresql"

        dialect = Dialect()

    db._upgrade_sqlite_indexes(NonSQLiteEngine())


def test_index_upgrade_fails_if_required_tables_are_missing(tmp_path):
    test_engine = create_engine(f"sqlite:///{tmp_path / 'empty.db'}")

    try:
        try:
            db._upgrade_sqlite_indexes(test_engine)
        except RuntimeError as exc:
            assert "required tables are missing" in str(exc)
        else:
            raise AssertionError("Expected missing-table upgrade to fail")
    finally:
        test_engine.dispose()
