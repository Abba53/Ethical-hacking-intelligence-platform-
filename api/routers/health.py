"""
api/routers/health.py

The health check endpoint. This is intentionally the FIRST endpoint we
build, and it requires no authentication and touches no other layer
of the platform yet.
"""

from fastapi import APIRouter

# APIRouter is FastAPI's way of grouping related endpoints together.
# We'll have one router per feature area later (iocs.py, scans.py, etc.)
# — health.py is the simplest possible example of that pattern.
router = APIRouter(tags=["health"])


@router.get("/health")
async def health():
    """
    Returns a simple JSON object proving the server is alive.

    "async def" (not just "def") means this function can run without
    blocking other requests while it waits — even though this specific
    function does no waiting yet, we use async consistently everywhere
    in this API because later endpoints (that call your workflows) DO
    need to wait on things like network requests and subprocess calls.
    """
    return {"status": "ok"}
