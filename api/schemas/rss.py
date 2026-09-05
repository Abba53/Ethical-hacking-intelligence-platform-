"""
api/schemas/rss.py

Pydantic response model for RSS entries, matching the real columns of
database.models.RSSEntry exactly (confirmed by reading that file directly
— not guessed).
"""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict


class RSSEntryOut(BaseModel):
    # from_attributes=True is what allows this model to be built directly
    # from a SQLAlchemy RSSEntry object's attributes (entry.title, etc.)
    # instead of only from a plain dict.
    model_config = ConfigDict(from_attributes=True)

    id: int
    source_url: str
    title: str
    link: str
    published: Optional[str] = None
    summary: Optional[str] = None
    collected_at: datetime
