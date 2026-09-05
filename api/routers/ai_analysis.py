"""
api/routers/ai_analysis.py

Phase 12 — AI analysis endpoint (the ANALYZE pipeline stage).

COST WARNING, confirmed by reading analysis/providers/openrouter_provider.py:
every successful call here makes a REAL, BILLED request to OpenRouter, with
NO max_tokens cap and NO request timeout set in that provider file. This
router adds its OWN stricter, endpoint-specific rate limit on top of the
usual require_api_key auth, because a valid key here grants spending
ability, not just read access to local data.

This limiter is in-memory and single-process only — correct for local dev,
NOT sufficient for a multi-worker production deployment (each worker would
have its own separate counter). A shared store (e.g. Redis) would be
needed at that point — deliberately not built here.
"""

import time
from collections import deque
from dataclasses import asdict, is_dataclass

from fastapi import APIRouter, Depends, HTTPException, status

from analysis.ai_analysis import AIAnalyst
from api.schemas.ai_analysis import AIAnalysisResponseOut, ThreatAnalysisRequest
from api.security import require_api_key

router = APIRouter(
    prefix="/api/v1/analysis",
    tags=["analysis"],
    dependencies=[Depends(require_api_key)],
)

_MAX_CALLS_PER_WINDOW = 5
_WINDOW_SECONDS = 60
_call_timestamps: deque[float] = deque()


def _enforce_ai_rate_limit() -> None:
    now = time.monotonic()
    while _call_timestamps and now - _call_timestamps[0] > _WINDOW_SECONDS:
        _call_timestamps.popleft()

    if len(_call_timestamps) >= _MAX_CALLS_PER_WINDOW:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=(
                f"AI analysis rate limit reached "
                f"({_MAX_CALLS_PER_WINDOW} calls / {_WINDOW_SECONDS}s). "
                "This endpoint makes real, billed API calls to OpenRouter — "
                "slow down."
            ),
        )
    _call_timestamps.append(now)


@router.post("/threat", response_model=AIAnalysisResponseOut)
async def analyze_threat(payload: ThreatAnalysisRequest):
    """
    Calls the REAL AIAnalyst.analyze_threat() — a genuine OpenRouter API
    call that costs real money on success. Rate-limited above BEFORE any
    call is attempted, so a rejected request never incurs cost.
    """
    _enforce_ai_rate_limit()

    analyst = AIAnalyst()
    response = await analyst.analyze_threat(
        target=payload.target,
        threat_score=payload.threat_score,
        severity=payload.severity,
        ioc_type=payload.ioc_type,
        signals=payload.signals,
    )

    analysis_dict = None
    if response.analysis is not None:
        analysis_dict = (
            asdict(response.analysis)
            if is_dataclass(response.analysis)
            else response.analysis
        )

    return AIAnalysisResponseOut(
        success=response.success,
        provider=response.provider,
        report_type=response.report_type,
        analysis=analysis_dict,
        error=response.error,
        execution_time_ms=response.execution_time_ms,
    )
