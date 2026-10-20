"""Regression tests for production configuration safeguards."""

import pytest

from api.config import get_settings


def test_production_requires_api_keys(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("API_KEYS", "")
    get_settings.cache_clear()

    try:
        with pytest.raises(RuntimeError, match="no API_KEYS configured"):
            get_settings()
    finally:
        get_settings.cache_clear()


def test_production_accepts_api_keys(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("API_KEYS", "production-test-key")
    monkeypatch.setenv("FORCE_HTTPS", "false")
    get_settings.cache_clear()

    try:
        settings = get_settings()
        assert settings.is_production
        assert "production-test-key" in settings.api_key_set
    finally:
        get_settings.cache_clear()


def test_https_requires_tls_or_trusted_proxy(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("FORCE_HTTPS", "true")
    monkeypatch.setenv("TLS_CERTFILE", "")
    monkeypatch.setenv("TLS_KEYFILE", "")
    monkeypatch.setenv("TRUST_PROXY_HEADERS", "false")
    get_settings.cache_clear()

    try:
        with pytest.raises(RuntimeError, match="FORCE_HTTPS=true"):
            get_settings()
    finally:
        get_settings.cache_clear()


def test_https_accepts_trusted_tls_proxy(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("FORCE_HTTPS", "true")
    monkeypatch.setenv("TLS_CERTFILE", "")
    monkeypatch.setenv("TLS_KEYFILE", "")
    monkeypatch.setenv("TRUST_PROXY_HEADERS", "true")
    get_settings.cache_clear()

    try:
        assert get_settings().FORCE_HTTPS is True
    finally:
        get_settings.cache_clear()
