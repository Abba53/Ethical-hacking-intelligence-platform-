"""
api/schemas/score.py

Response model matching EXACTLY what scoring.threat_scorer.get_top_threats()
returns — confirmed by reading that function's real return statement, not
guessed from database.models.IocScore's full column list. Notably:
scored_at is already a plain string (str(t.scored_at) in the real code),
and signals/id/updated_at are NOT included, because get_top_threats()
doesn't select them.
"""

from enum import Enum

from pydantic import BaseModel


class Severity(str, Enum):
    """Confirmed real values from scoring/threat_scorer.py's severity labels."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class IocScoreOut(BaseModel):
    ioc_value: str
    ioc_type: str
    score: float
    severity: str
    explanation: str
    scored_at: str
