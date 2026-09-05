from fastapi import APIRouter, Depends, Query          # <-- CHANGED: added Query
from starlette.concurrency import run_in_threadpool

from database.db import get_session
from database.models import ExtractedIOC, RSSEntry
from api.schemas.ioc import ExtractedIOCOut
from api.security import require_api_key

router = APIRouter(
    prefix="/api/v1/iocs",
    tags=["iocs"],
    dependencies=[Depends(require_api_key)],
)


def _fetch_extracted_iocs(limit: int, offset: int) -> list[tuple[ExtractedIOC, RSSEntry]]:
    with get_session() as session:
        return (
            session.query(ExtractedIOC, RSSEntry)
            .join(RSSEntry, ExtractedIOC.source_entry_id == RSSEntry.id)
            .order_by(ExtractedIOC.extracted_at.desc())
            .limit(limit)
            .offset(offset)
            .all()
        )


@router.get("", response_model=list[ExtractedIOCOut])
async def list_extracted_iocs(
    limit: int = Query(default=50, ge=1, le=200),           # <-- CHANGED
    offset: int = Query(default=0, ge=0),                     # <-- CHANGED
):
    rows = await run_in_threadpool(_fetch_extracted_iocs, limit, offset)

    results = []
    for ioc, article in rows:
        results.append(
            {
                "id": ioc.id,
                "ioc_type": ioc.ioc_type,
                "value": ioc.value,
                "extracted_at": ioc.extracted_at,
                "source": {
                    "id": article.id,
                    "title": article.title,
                    "link": article.link,
                },
            }
        )
    return results
