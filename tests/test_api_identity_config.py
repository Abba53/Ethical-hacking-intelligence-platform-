import pytest
from fastapi import HTTPException

from api.config import Settings
from api.security import (
    resolve_api_key_identity,
    resolve_admin_key_identity,
)


def test_regular_identity_mapping_preserves_key_order():
    settings = Settings(
        _env_file=None,
        API_KEYS="regular-a,regular-b",
        API_KEY_IDENTITIES="101,202",
    )

    assert settings.api_key_identity_map == {
        "regular-a": 101,
        "regular-b": 202,
    }


def test_admin_identity_mapping_is_separate():
    settings = Settings(
        _env_file=None,
        API_KEYS="regular-a",
        API_KEY_IDENTITIES="101",
        ADMIN_API_KEYS="admin-a",
        ADMIN_API_KEY_IDENTITIES="202",
    )

    assert settings.api_key_identity_map == {"regular-a": 101}
    assert settings.admin_api_key_identity_map == {"admin-a": 202}


@pytest.mark.parametrize("raw", ["101,", ",101", "101,,202"])
def test_empty_identity_entries_are_rejected(raw):
    with pytest.raises(ValueError):
        Settings._parse_identity_mapping(raw, 2 if raw == "101,,202" else 1)


@pytest.mark.parametrize("raw", ["abc", "0", "-1"])
def test_invalid_identity_values_are_rejected(raw):
    with pytest.raises(ValueError):
        Settings._parse_identity_mapping(raw, 1)


def test_identity_count_must_match_key_count():
    with pytest.raises(ValueError, match="count must exactly match"):
        Settings._parse_identity_mapping("101", 2)


def test_missing_regular_identity_fails_closed():
    settings = Settings(
        _env_file=None,
        API_KEYS="regular-a",
        API_KEY_IDENTITIES="",
    )

    with pytest.raises(HTTPException) as exc:
        resolve_api_key_identity("regular-a", settings)

    assert exc.value.status_code == 403


def test_missing_admin_identity_fails_closed():
    settings = Settings(
        _env_file=None,
        ADMIN_API_KEYS="admin-a",
        ADMIN_API_KEY_IDENTITIES="",
    )

    with pytest.raises(HTTPException) as exc:
        resolve_admin_key_identity("admin-a", settings)

    assert exc.value.status_code == 403
