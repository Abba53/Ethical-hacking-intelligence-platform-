"""
database/models.py

SQLAlchemy ORM model definitions for the platform's persistent storage.

Design notes:
- One table per distinct data source (RSS entries, ThreatFox IOCs,
  Chainabuse reports) — these are genuinely different shapes of data,
  not forced into one generic table.
- Each table enforces a database-level UNIQUE constraint on its natural
  identifying field(s), so deduplication is guaranteed by the database
  itself, not just by application logic that could have bugs.
- 'collected_at' records when OUR system first saw the item, distinct
  from the source's own timestamp fields (published, first_seen, etc.).
"""

from datetime import datetime, timezone

from sqlalchemy import (
    DateTime,
    Float,
    Integer,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from sqlalchemy import ForeignKey, Text

class Base(DeclarativeBase):
    """Base class that all our table models inherit from."""
    pass


def utcnow() -> datetime:
    """Returns the current UTC time. Used as a default for collected_at."""
    return datetime.now(timezone.utc)


class RSSEntry(Base):
    __tablename__ = "rss_entries"
    __table_args__ = (UniqueConstraint("link", name="uq_rss_entries_link"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    source_url: Mapped[str] = mapped_column(String(500), nullable=False)
    title: Mapped[str] = mapped_column(String(1000), nullable=False)
    link: Mapped[str] = mapped_column(String(1000), nullable=False)
    published: Mapped[str] = mapped_column(String(200), nullable=True)
    summary: Mapped[str] = mapped_column(String(5000), nullable=True)
    collected_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    def __repr__(self) -> str:
        return f"<RSSEntry id={self.id} title={self.title!r}>"


class ThreatFoxIOC(Base):
    __tablename__ = "threatfox_iocs"
    __table_args__ = (UniqueConstraint("ioc", name="uq_threatfox_iocs_ioc"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ioc: Mapped[str] = mapped_column(String(500), nullable=False)
    ioc_type: Mapped[str] = mapped_column(String(100), nullable=True)
    threat_type: Mapped[str] = mapped_column(String(200), nullable=True)
    malware: Mapped[str] = mapped_column(String(200), nullable=True)
    confidence_level: Mapped[float] = mapped_column(Float, nullable=True)
    first_seen: Mapped[str] = mapped_column(String(200), nullable=True)
    collected_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    def __repr__(self) -> str:
        return f"<ThreatFoxIOC id={self.id} ioc={self.ioc!r}>"


class ChainabuseReport(Base):
    __tablename__ = "chainabuse_reports"
    __table_args__ = (
        UniqueConstraint(
            "address", "category", "reported_at",
            name="uq_chainabuse_reports_address_category_reported",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    address: Mapped[str] = mapped_column(String(200), nullable=False)
    category: Mapped[str] = mapped_column(String(200), nullable=True)
    chain: Mapped[str] = mapped_column(String(100), nullable=True)
    description: Mapped[str] = mapped_column(String(2000), nullable=True)
    reported_at: Mapped[str] = mapped_column(String(200), nullable=True)
    collected_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    def __repr__(self) -> str:
          return f"<ChainabuseReport id={self.id} address={self.address!r}>"

class ExtractedIOC(Base):
    __tablename__ = "extracted_iocs"
    __table_args__ = (
        UniqueConstraint(
            "ioc_type", "value", "source_entry_id",
            name="uq_extracted_ioc_type_value_source",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ioc_type: Mapped[str] = mapped_column(String(50), nullable=False)
    value: Mapped[str] = mapped_column(String(1000), nullable=False)
    source_entry_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("rss_entries.id"), nullable=False
    )
    extracted_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    def __repr__(self) -> str:
        return f"<ExtractedIOC id={self.id} type={self.ioc_type!r} value={self.value!r}>"

