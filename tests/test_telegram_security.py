"""
Telegram security regression tests.
"""

import importlib

import services.active.auth as active_auth
import services.telegram_auth as telegram_auth


def test_telegram_admin_requires_explicit_configuration(monkeypatch):
    monkeypatch.setenv("TELEGRAM_ADMIN_USERS", "")

    importlib.reload(telegram_auth)

    assert telegram_auth.is_telegram_admin(123456789) is False


def test_telegram_admin_accepts_configured_user(monkeypatch):
    monkeypatch.setenv(
        "TELEGRAM_ADMIN_USERS",
        "123456789,987654321",
    )

    importlib.reload(telegram_auth)

    assert telegram_auth.is_telegram_admin(123456789) is True
    assert telegram_auth.is_telegram_admin(987654321) is True
    assert telegram_auth.is_telegram_admin(111111111) is False


def test_invalid_telegram_admin_configuration_fails_closed(monkeypatch):
    monkeypatch.setenv(
        "TELEGRAM_ADMIN_USERS",
        "123456789,not-a-number",
    )

    importlib.reload(telegram_auth)

    assert telegram_auth.is_telegram_admin(123456789) is False


def test_active_scan_authorization_missing_config_fails_closed(monkeypatch):
    monkeypatch.delenv("SCAN_AUTHORIZED_USERS", raising=False)

    assert active_auth._load_authorized_users() == set()


def test_active_scan_authorization_invalid_config_fails_closed(monkeypatch):
    monkeypatch.setenv(
        "SCAN_AUTHORIZED_USERS",
        "not-a-number",
    )

    assert active_auth._load_authorized_users() == set()
