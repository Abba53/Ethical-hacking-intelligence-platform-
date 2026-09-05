"""
api/schemas/report.py

Matches reports.pdf_generator.PDFGenerator.generate()'s EXACT real
signature: generate(*, target: str, document: str) -> str. This is a
thin wrapper schema — no report-formatting logic lives here, matching
the real function's own separation of concerns (it lays out text,
it doesn't compose it).
"""

from pydantic import BaseModel, Field


class PDFReportRequest(BaseModel):
    target: str = Field(..., min_length=1, max_length=512)
    document: str = Field(..., min_length=1, max_length=50_000)
