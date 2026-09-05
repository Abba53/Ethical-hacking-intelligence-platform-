"""
api/schemas/ioc.py

Pydantic response models for extracted IOCs, joined with their source
RSS article. Matches database.models.ExtractedIOC and RSSEntry columns
exactly (confirmed by reading models.py directly).
"""

from datetime import datetime

from pydantic import BaseModel, ConfigDict


class SourceArticleOut(BaseModel):
    """The RSS article an IOC was extracted from — minimal fields only."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    title: str
    link: str


class ExtractedIOCOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    ioc_type: str
    value: str
    extracted_at: datetime
    source: SourceArticleOut
