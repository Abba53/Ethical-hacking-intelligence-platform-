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
from contextlib import contextmanager

from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from database.models import Base

logger = logging.getLogger(__name__)

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///data/platform.db")

# echo=False keeps SQLAlchemy quiet by default; flip to True temporarily
# for deep debugging if you ever need to see every raw SQL statement.
engine = create_engine(DATABASE_URL, echo=False)

SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)


def init_db() -> None:
    """Creates all tables defined in models.py if they don't already exist."""
    Base.metadata.create_all(engine)
    logger.info("Database initialized at %s", DATABASE_URL)


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
    finally:
        session.close()


if __name__ == "__main__":
    logging.basicConfig(
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        level=logging.INFO,
    )
    init_db()
    print(f"\n✅ Database ready at: {DATABASE_URL}")
