"""
api/main.py

FastAPI application entry point.
"""

import hashlib
import time
from collections import OrderedDict, deque

from dotenv import load_dotenv

load_dotenv()

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware
from fastapi.responses import JSONResponse

from api.config import get_settings
from api.routers import (
    ai_analysis,
    health,
    iocs,
    lookups,
    reports,
    scans,
    scores,
    threat_intel,
)

_RATE_WINDOW_SECONDS = 60
_MAX_RATE_LIMIT_BUCKETS = 10_000

_rate_buckets: OrderedDict[str, deque[float]] = OrderedDict()


def _rate_limit_key(request: Request) -> str:
    """
    Identify the caller for rate limiting.

    API-key callers are isolated from one another.
    Requests without an API key use the connection address.
    """
    api_key = request.headers.get("X-API-Key")

    if api_key:
        digest = hashlib.sha256(api_key.encode("utf-8")).hexdigest()
        return f"key:{digest}"

    client = request.client
    host = client.host if client else "unknown"

    return f"client:{host}"


def _enforce_rate_limit(request: Request, limit: int) -> bool:
    """Return True when this caller remains within the request limit."""
    if limit <= 0:
        return True

    now = time.monotonic()
    key = _rate_limit_key(request)

    timestamps = _rate_buckets.get(key)

    if timestamps is None:
        if len(_rate_buckets) >= _MAX_RATE_LIMIT_BUCKETS:
            _rate_buckets.popitem(last=False)

        timestamps = deque()
        _rate_buckets[key] = timestamps
    else:
        _rate_buckets.move_to_end(key)

    while timestamps and now - timestamps[0] >= _RATE_WINDOW_SECONDS:
        timestamps.popleft()

    if len(timestamps) >= limit:
        return False

    timestamps.append(now)
    return True


def create_app() -> FastAPI:
    settings = get_settings()

    app = FastAPI(
        title=settings.APP_NAME,
        version=settings.API_VERSION,
    )

    if settings.FORCE_HTTPS:
        app.add_middleware(HTTPSRedirectMiddleware)

    if settings.cors_origin_list:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_origin_list,
            allow_credentials=False,
            allow_methods=[
                "GET",
                "POST",
                "PUT",
                "PATCH",
                "DELETE",
                "OPTIONS",
            ],
            allow_headers=[
                "X-API-Key",
                "Content-Type",
                "Accept",
            ],
        )

    @app.middleware("http")
    async def security_middleware(request: Request, call_next):
        if not _enforce_rate_limit(
            request,
            settings.RATE_LIMIT_PER_MINUTE,
        ):
            return JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded. Try again later."},
            )

        response = await call_next(request)

        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"

        return response

    app.include_router(health.router)
    app.include_router(threat_intel.router)
    app.include_router(iocs.router)
    app.include_router(scores.router)
    app.include_router(ai_analysis.router)
    app.include_router(reports.router)
    app.include_router(scans.router)
    app.include_router(lookups.router)

    return app


app = create_app()
