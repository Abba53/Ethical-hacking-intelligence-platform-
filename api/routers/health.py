"""Liveness and readiness endpoints."""

import asyncio
import logging

from fastapi import APIRouter, HTTPException
from fastapi.concurrency import run_in_threadpool
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from database import db

logger = logging.getLogger(__name__)

router = APIRouter(tags=["health"])

READINESS_TIMEOUT_SECONDS = 3.0


def _check_database() -> None:
    """Blocking database probe; always run off the event loop."""
    with db.engine.connect() as connection:
        connection.execute(text("SELECT 1"))


@router.get("/health")
async def health():
    """Confirm that the API process is responding."""
    return {"status": "ok"}


@router.get("/ready")
async def readiness():
    """Confirm that the API can reach its database, within a bounded time."""
    try:
        await asyncio.wait_for(
            run_in_threadpool(_check_database),
            timeout=READINESS_TIMEOUT_SECONDS,
        )
    except asyncio.TimeoutError:
        logger.warning("Readiness check timed out after %.1fs", READINESS_TIMEOUT_SECONDS)
        raise HTTPException(status_code=503, detail="Service not ready") from None
    except SQLAlchemyError:
        logger.warning("Readiness check failed: database unavailable")
        raise HTTPException(status_code=503, detail="Service not ready") from None

    return {"status": "ready", "database": "ok"}
