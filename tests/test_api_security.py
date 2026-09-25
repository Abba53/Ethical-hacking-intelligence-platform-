"""
tests/test_api_security.py

Targeted API security regression tests for Phase 13.2.
"""

from api.config import get_settings
from api.main import _rate_buckets, create_app, app
from fastapi.testclient import TestClient


def test_security_headers_present():
    client = TestClient(app)

    response = client.get("/health")

    assert response.status_code == 200
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Referrer-Policy"] == "no-referrer"
    assert response.headers["Cache-Control"] == "no-store"


def test_cors_allows_configured_origin():
    settings = get_settings()
    original_origins = settings.CORS_ORIGINS

    try:
        settings.CORS_ORIGINS = "https://example.com"
        test_app = create_app()
        client = TestClient(test_app)

        response = client.options(
            "/health",
            headers={
                "Origin": "https://example.com",
                "Access-Control-Request-Method": "GET",
            },
        )

        assert response.status_code == 200
        assert response.headers["access-control-allow-origin"] == "https://example.com"
    finally:
        settings.CORS_ORIGINS = original_origins


def test_cors_rejects_unconfigured_origin():
    settings = get_settings()
    original_origins = settings.CORS_ORIGINS

    try:
        settings.CORS_ORIGINS = "https://example.com"
        test_app = create_app()
        client = TestClient(test_app)

        response = client.options(
            "/health",
            headers={
                "Origin": "https://evil.example",
                "Access-Control-Request-Method": "GET",
            },
        )

        assert response.status_code == 400
    finally:
        settings.CORS_ORIGINS = original_origins


def test_per_client_rate_limit_returns_429():
    settings = get_settings()
    original_limit = settings.RATE_LIMIT_PER_MINUTE

    try:
        settings.RATE_LIMIT_PER_MINUTE = 1
        _rate_buckets.clear()

        client = TestClient(app)
        headers = {"X-API-Key": "rate-limit-test-key"}

        first = client.get("/health", headers=headers)
        second = client.get("/health", headers=headers)
        other = client.get(
            "/health",
            headers={"X-API-Key": "different-rate-limit-client"},
        )

        assert first.status_code == 200
        assert second.status_code == 429
        assert second.json() == {
            "detail": "Rate limit exceeded. Try again later."
        }
        assert other.status_code == 200
    finally:
        settings.RATE_LIMIT_PER_MINUTE = original_limit
        _rate_buckets.clear()
