from fastapi import APIRouter, Depends, Query          # <-- CHANGED: added Query
from starlette.concurrency import run_in_threadpool

from database.db import get_session
from database.models import RSSEntry
from api.schemas.rss import RSSEntryOut
from api.security import require_api_key

router = APIRouter(
    prefix="/api/v1/threat-intel",
    tags=["threat-intel"],
    dependencies=[Depends(require_api_key)],
)


def _fetch_rss_entries(limit: int, offset: int) -> list[RSSEntry]:
    with get_session() as session:
        return (
            session.query(RSSEntry)
            .order_by(RSSEntry.collected_at.desc())
            .limit(limit)
            .offset(offset)
            .all()
        )


@router.get("/rss", response_model=list[RSSEntryOut])
async def list_rss_entries(
    limit: int = Query(default=50, ge=1, le=200),           # <-- CHANGED
    offset: int = Query(default=0, ge=0),                     # <-- CHANGED
):
    entries = await run_in_threadpool(_fetch_rss_entries, limit, offset)
    return entries
