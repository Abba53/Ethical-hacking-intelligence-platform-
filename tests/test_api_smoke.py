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
# ---------------------------------------------------------------------------
# Admin key — same never-hardcode, read-from-.env pattern as REAL_API_KEY
# ---------------------------------------------------------------------------

with open(".env") as f:
    for line in f:
        if line.startswith("ADMIN_API_KEYS="):
            REAL_ADMIN_KEY = line.strip().split("=", 1)[1]
            break

ADMIN_AUTH_HEADERS = {"X-API-Key": REAL_ADMIN_KEY}


# ---------------------------------------------------------------------------
# /api/v1/scans — submit
# ---------------------------------------------------------------------------

def test_scans_requires_auth():
    response = client.post("/api/v1/scans", json={})
    assert response.status_code == 401


def test_scans_invalid_action_rejected():
    response = client.post(
        "/api/v1/scans",
        json={"target": "example.com", "scan_type": "recon", "action": "not_real", "user_id": 1},
        headers=AUTH_HEADERS,
    )
    assert response.status_code == 422  # caught by ScanRequest's own model_validator


def test_scans_denied_user_returns_structured_response():
    """
    Safe to run repeatedly: is_authorized() denies this BEFORE any real
    subprocess (Nmap/Subfinder/etc.) launches — confirmed by hand, this
    returns quickly, not after a 60+ second scan timeout.
    """
    response = client.post(
        "/api/v1/scans",
        json={
            "target": "example.com", "scan_type": "network_scan",
            "action": "quick", "user_id": 999999,
        },
        headers=AUTH_HEADERS,
    )
    assert response.status_code == 200
    body = response.json()
    assert body["success"] is False
    assert "Authorization denied" in body["error"]


# ---------------------------------------------------------------------------
# /api/v1/scans/authorize and /deauthorize — the regular-vs-admin key split
# This is the exact test that would have caught the real dependency-
# stacking bug found and fixed this session.
# ---------------------------------------------------------------------------

def test_authorize_requires_auth():
    response = client.post("/api/v1/scans/authorize", json={})
    assert response.status_code == 403  # require_admin_key's own missing-header code


def test_authorize_rejects_regular_key():
    response = client.post(
        "/api/v1/scans/authorize",
        json={"target": "test-example.invalid", "authorized_by": 1},
        headers=AUTH_HEADERS,  # regular key — must NOT work here
    )
    assert response.status_code == 403


def test_authorize_accepts_admin_key():
    response = client.post(
        "/api/v1/scans/authorize",
        json={"target": "test-example.invalid", "authorized_by": 1},
        headers=ADMIN_AUTH_HEADERS,
    )
    assert response.status_code == 200
    assert response.json()["target"] == "test-example.invalid"


def test_deauthorize_rejects_regular_key():
    response = client.post(
        "/api/v1/scans/deauthorize",
        json={"target": "test-example.invalid", "authorized_by": 1},
        headers=AUTH_HEADERS,  # regular key — must NOT work here
    )
    assert response.status_code == 403


def test_deauthorize_accepts_admin_key():
    # Cleans up the target authorized by test_authorize_accepts_admin_key,
    # so the test suite doesn't leave permanent state behind in
    # AUTHORIZED_SCAN_TARGETS between runs.
    response = client.post(
        "/api/v1/scans/deauthorize",
        json={"target": "test-example.invalid", "authorized_by": 1},
        headers=ADMIN_AUTH_HEADERS,
    )
    assert response.status_code == 200

# ---------------------------------------------------------------------------
# /api/v1/lookups
# ---------------------------------------------------------------------------

def test_lookups_requires_auth():
    response = client.post("/api/v1/lookups", json={})
    assert response.status_code == 401


def test_lookups_detect_type_succeeds():
    """
    Safe to run repeatedly: IOCService.detect_type() is synchronous, local
    pattern matching only — no external API call, no cost, no rate limit.
    """
    response = client.post(
        "/api/v1/lookups",
        json={"target": "8.8.8.8", "service": "ioc", "action": "detect_type"},
        headers=AUTH_HEADERS,
    )
    assert response.status_code == 200
    body = response.json()
    assert body["success"] is True
    assert body["data"]["ioc_type"] == "ipv4"


def test_lookups_invalid_action_rejected():
    response = client.post(
        "/api/v1/lookups",
        json={"target": "8.8.8.8", "service": "ioc", "action": "not_a_real_action"},
        headers=AUTH_HEADERS,
    )
    assert response.status_code == 422


def test_lookups_virustotal_requires_ioc_type():
    """
    Confirms the one distinctive validation rule in this router:
    NetworkService.virustotal()'s real signature requires an extra
    ioc_type argument the other 8 lookup methods don't take.
    """
    response = client.post(
        "/api/v1/lookups",
        json={"target": "8.8.8.8", "service": "network", "action": "virustotal"},
        headers=AUTH_HEADERS,
    )
    assert response.status_code == 422
