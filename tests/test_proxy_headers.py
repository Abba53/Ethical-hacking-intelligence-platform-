"""Regression tests for trusted reverse-proxy HTTPS handling."""

from fastapi.testclient import TestClient
import pytest

from api.config import get_settings
from api.main import create_app


@pytest.fixture
def proxy_environment(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("FORCE_HTTPS", "true")
    monkeypatch.setenv("TLS_CERTFILE", "")
    monkeypatch.setenv("TLS_KEYFILE", "")
    monkeypatch.setenv("TRUST_PROXY_HEADERS", "true")
    monkeypatch.setenv("TRUSTED_PROXY_HOSTS", "127.0.0.1")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def test_trusted_proxy_forwarded_https_does_not_redirect(proxy_environment):
    app = create_app()
    with TestClient(app, client=("127.0.0.1", 12345)) as client:
        response = client.get("/health", headers={"X-Forwarded-Proto": "https"})
    assert response.status_code == 200


def test_untrusted_client_cannot_override_scheme(proxy_environment):
    app = create_app()
    with TestClient(
        app,
        client=("192.0.2.10", 12345),
        follow_redirects=False,
    ) as client:
        response = client.get("/health", headers={"X-Forwarded-Proto": "https"})
    assert response.status_code == 307
    assert response.headers["location"].startswith("https://")


def test_wildcard_trusted_proxy_configuration_is_rejected(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("TRUST_PROXY_HEADERS", "true")
    monkeypatch.setenv("TRUSTED_PROXY_HOSTS", "*")
    get_settings.cache_clear()
    try:
        with pytest.raises(RuntimeError, match="explicit IP addresses"):
            get_settings()
    finally:
        get_settings.cache_clear()
