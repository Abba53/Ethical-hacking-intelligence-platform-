"""Liveness and readiness endpoints."""

import logging

from fastapi import APIRouter, HTTPException
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from database import db

logger = logging.getLogger(__name__)

router = APIRouter(tags=["health"])


@router.get("/health")
async def health():
    """Confirm that the API process is responding."""
    return {"status": "ok"}


@router.get("/ready")
async def readiness():
    """Confirm that the API can reach its database."""
    try:
        with db.engine.connect() as connection:
            connection.execute(text("SELECT 1"))
    except SQLAlchemyError:
        logger.warning("Readiness check failed: database unavailable")
        raise HTTPException(
            status_code=503,
            detail="Service not ready",
        ) from None

    return {"status": "ready", "database": "ok"}
