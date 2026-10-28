"""
database/db.py

Database engine and session management.

Design notes:
- DATABASE_URL is read from environment (.env), defaulting to local
  SQLite if not set. This is the single point of change needed to
  later migrate to PostgreSQL (Phase 7 future work).
- init_db() creates all tables defined in models.py if they don't
  already exist. Safe to call every time the app starts — it does
  NOT recreate or wipe existing tables/data.
- get_session() returns a fresh session for a single unit of work;
  callers are responsible for closing it (we use a context manager
  pattern via contextlib for this).
"""

import logging
import os
from pathlib import Path
from contextlib import contextmanager

from dotenv import load_dotenv
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, sessionmaker

from database.models import Base

logger = logging.getLogger(__name__)

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///data/platform.db")

# echo=False keeps SQLAlchemy quiet by default; flip to True temporarily
# for deep debugging if you ever need to see every raw SQL statement.
def _create_engine(database_url: str):
    """Create a database engine with SQLite foreign keys enforced."""
    if database_url.startswith("sqlite:///") and not database_url.startswith(
        "sqlite:///:memory:"
    ):
        database_path = database_url.removeprefix("sqlite:///").split("?", 1)[0]
        if database_path and database_path != ":memory:":
            Path(database_path).parent.mkdir(parents=True, exist_ok=True)

    db_engine = create_engine(database_url, echo=False)

    if db_engine.dialect.name == "sqlite":
        @event.listens_for(db_engine, "connect")
        def _enable_sqlite_foreign_keys(dbapi_connection, connection_record):
            cursor = dbapi_connection.cursor()
            try:
                cursor.execute("PRAGMA foreign_keys=ON")
            finally:
                cursor.close()

    return db_engine


engine = _create_engine(DATABASE_URL)

SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)


def _upgrade_sqlite_indexes(db_engine) -> None:
    """Create performance indexes safely on existing SQLite databases."""
    if db_engine.dialect.name != "sqlite":
        return

    indexes = (
        "CREATE INDEX IF NOT EXISTS ix_rss_entries_collected_at "
        "ON rss_entries (collected_at)",
        "CREATE INDEX IF NOT EXISTS ix_extracted_iocs_extracted_at "
        "ON extracted_iocs (extracted_at)",
        "CREATE INDEX IF NOT EXISTS ix_extracted_iocs_source_entry_id "
        "ON extracted_iocs (source_entry_id)",
        "CREATE INDEX IF NOT EXISTS ix_ioc_scores_score "
        "ON ioc_scores (score)",
    )

    with db_engine.begin() as connection:
        existing_tables = set(
            connection.exec_driver_sql(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).scalars()
        )
        required_tables = {
            "rss_entries",
            "extracted_iocs",
            "ioc_scores",
        }
        if not required_tables.issubset(existing_tables):
            raise RuntimeError(
                "Cannot upgrade database indexes: required tables are missing"
            )

        for statement in indexes:
            connection.exec_driver_sql(statement)


def init_db() -> None:
    """Create tables and apply safe, repeatable SQLite index upgrades."""
    Base.metadata.create_all(engine)
    _upgrade_sqlite_indexes(engine)
    logger.info("Database initialized successfully (dialect=%s)", engine.dialect.name)


@contextmanager
def get_session():
    """
    Provides a database session as a context manager, e.g.:

        with get_session() as session:
            session.add(some_object)
            session.commit()

    Automatically closes the session when the 'with' block ends,
    even if an exception occurs.
    """
    session: Session = SessionLocal()
    try:
        yield session
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


if __name__ == "__main__":
    logging.basicConfig(
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        level=logging.INFO,
    )
    init_db()
    print(f"\n✅ Database ready (dialect: {engine.dialect.name})")
