"""
api/schemas/ai_analysis.py

Request/response shapes for the AI analysis endpoint.

analysis is now STRICTLY typed as ThreatReportOut, based on the REAL,
empirically-confirmed fields from a genuine successful OpenRouter call
(not guessed from database.models or ai_analysis.py's source alone —
the AI provider's actual output shape, observed directly).
"""

from typing import Any, Optional

from pydantic import BaseModel, Field


class ThreatAnalysisRequest(BaseModel):
    target: str = Field(..., min_length=1, max_length=512)
    threat_score: float
    severity: str
    ioc_type: str
    signals: dict[str, Any] = Field(default_factory=dict)


class ThreatReportOut(BaseModel):
    """
    Matches analysis.models.threat_report.ThreatReport's real fields,
    confirmed empirically via a genuine AIAnalyst.analyze_threat() call
    (see api/routers/ai_analysis.py's history / project notes). Fields
    are plain (non-Optional) types because the model's own convention,
    observed directly, is to fill unknowns with a descriptive string
    like "Unknown" rather than omit the field.
    """

    executive_summary: str
    threat_assessment: str
    attack_stage: str
    confidence: str
    malware: str
    threat_actor: str
    mitre_attack: list[str]
    recommendations: list[str]
    detection_opportunities: list[str]
    priority: str


class AIAnalysisResponseOut(BaseModel):
    success: bool
    provider: Optional[str] = None
    report_type: str
    analysis: Optional[ThreatReportOut] = None
    error: Optional[str] = None
    execution_time_ms: Optional[int] = None
