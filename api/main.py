"""
api/main.py

The FastAPI application entry point — the "front door" of the API.
"""

from dotenv import load_dotenv

load_dotenv()

from fastapi import FastAPI
from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware

from api.config import get_settings
from api.routers import ai_analysis, health, iocs, reports, scores, threat_intel   # <-- CHANGED


def create_app() -> FastAPI:
    settings = get_settings()

    app = FastAPI(
        title=settings.APP_NAME,
        version=settings.API_VERSION,
    )

    if settings.FORCE_HTTPS:
        app.add_middleware(HTTPSRedirectMiddleware)

    app.include_router(health.router)
    app.include_router(threat_intel.router)
    app.include_router(iocs.router)
    app.include_router(scores.router)
    app.include_router(ai_analysis.router)
    app.include_router(reports.router)                                            # <-- NEW line

    return app


app = create_app()
