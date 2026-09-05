"""
tests/test_api_smoke.py

Smoke tests for the FastAPI backend — confirms the basic contract of
every endpoint built so far still holds: auth enforcement, valid-request
success, and boundary validation. Runs against the REAL app and REAL
database (read-only endpoints only, so this is safe).

Run with:
    pytest tests/test_api_smoke.py -v
"""

import os

from fastapi.testclient import TestClient

from api.main import app

client = TestClient(app)

# Read the real key the same way our manual curl commands have all
# session — from .env, never hard-coded, never printed.
with open(".env") as f:
    for line in f:
        if line.startswith("API_KEYS="):
            REAL_API_KEY = line.strip().split("=", 1)[1]
            break

AUTH_HEADERS = {"X-API-Key": REAL_API_KEY}


# ---------------------------------------------------------------------------
# /health — no auth required
# ---------------------------------------------------------------------------

def test_health_no_auth_needed():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


# ---------------------------------------------------------------------------
# /api/v1/threat-intel/rss
# ---------------------------------------------------------------------------

def test_rss_requires_auth():
    response = client.get("/api/v1/threat-intel/rss")
    assert response.status_code == 401


def test_rss_wrong_key_rejected():
    response = client.get(
        "/api/v1/threat-intel/rss", headers={"X-API-Key": "definitely-wrong"}
    )
    assert response.status_code == 401


def test_rss_valid_key_succeeds():
    response = client.get("/api/v1/threat-intel/rss?limit=3", headers=AUTH_HEADERS)
    assert response.status_code == 200
    body = response.json()
    assert isinstance(body, list)
    assert len(body) <= 3


def test_rss_limit_over_bound_rejected():
    response = client.get(
        "/api/v1/threat-intel/rss?limit=999999999", headers=AUTH_HEADERS
    )
    assert response.status_code == 422


# ---------------------------------------------------------------------------
# /api/v1/iocs
# ---------------------------------------------------------------------------

def test_iocs_requires_auth():
    response = client.get("/api/v1/iocs")
    assert response.status_code == 401


def test_iocs_valid_key_succeeds_with_source_join():
    response = client.get("/api/v1/iocs?limit=3", headers=AUTH_HEADERS)
    assert response.status_code == 200
    body = response.json()
    if body:  # only check shape if there's real data
        first = body[0]
        assert "source" in first
        assert "title" in first["source"]
        assert "link" in first["source"]


def test_iocs_limit_over_bound_rejected():
    response = client.get("/api/v1/iocs?limit=201", headers=AUTH_HEADERS)
    assert response.status_code == 422


# ---------------------------------------------------------------------------
# /api/v1/scores/top
# ---------------------------------------------------------------------------

def test_scores_requires_auth():
    response = client.get("/api/v1/scores/top")
    assert response.status_code == 401


def test_scores_valid_key_succeeds():
    response = client.get("/api/v1/scores/top?limit=3", headers=AUTH_HEADERS)
    assert response.status_code == 200


def test_scores_invalid_severity_rejected():
    response = client.get(
        "/api/v1/scores/top?min_severity=SEVERE", headers=AUTH_HEADERS
    )
    assert response.status_code == 422


def test_scores_valid_severity_accepted():
    response = client.get(
        "/api/v1/scores/top?min_severity=CRITICAL", headers=AUTH_HEADERS
    )
    assert response.status_code == 200
