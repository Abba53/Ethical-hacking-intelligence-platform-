"""
api/routers/scores.py

Phase 12 — Threat scoring endpoint.

Deliberately does NOT write a new database query. scoring.threat_scorer
already has get_top_threats(limit, min_severity) — tested, existing logic
(per Rule 8: reuse existing interfaces before creating new ones). This
router is a thin HTTP wrapper around that real function.
"""

from fastapi import APIRouter, Depends, Query
from starlette.concurrency import run_in_threadpool

from scoring.threat_scorer import get_top_threats
from api.schemas.score import IocScoreOut, Severity
from api.security import require_api_key

router = APIRouter(
    prefix="/api/v1/scores",
    tags=["scores"],
    dependencies=[Depends(require_api_key)],
)


@router.get("/top", response_model=list[IocScoreOut])
async def top_threats(
    limit: int = Query(default=10, ge=1, le=200),
    min_severity: Severity = Severity.MEDIUM,
):
    """
    Returns the highest-scoring IOCs, calling the real scoring engine's
    own get_top_threats() function — not a reimplemented query.
    """
    results = await run_in_threadpool(get_top_threats, limit, min_severity.value)
    return results
