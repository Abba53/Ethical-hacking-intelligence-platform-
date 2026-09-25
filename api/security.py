"""
api/security.py

Phase 12.6 — Authentication & authorization (simple API-key auth).

Every protected endpoint depends on require_api_key, which reads the
X-API-Key header and checks it against settings.api_key_set — the same
Settings object we built and tested in Phase 12.2/12.3, reading real
generated keys from .env.
"""

import hmac

from fastapi import Depends, Header, HTTPException, status

from api.config import Settings, get_settings


def _constant_time_in(candidate: str, valid_keys: set[str]) -> bool:
    """
    Checks membership using constant-time comparison for EACH key, so
    the total time taken doesn't leak information about how close a
    wrong guess was to any valid key.
    """
    return any(hmac.compare_digest(candidate, key) for key in valid_keys)


async def require_api_key(
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    settings: Settings = Depends(get_settings),
) -> str:
    """
    FastAPI dependency. Add via `dependencies=[Depends(require_api_key)]`
    on a router or endpoint to require a valid X-API-Key header.
    Raises 401 and stops the request if missing or invalid.
    """
    if not x_api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing X-API-Key header.",
        )

    if not _constant_time_in(x_api_key, settings.api_key_set):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key.",
        )

    return x_api_key


async def require_admin_key(
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    settings: Settings = Depends(get_settings),
) -> str:
    """
    Stricter dependency for admin-only actions (e.g. granting scan
    authorization). Checks against settings.admin_api_key_set — a
    SEPARATE pool from the regular API_KEYS, not a privilege flag on
    the same key. Raises 403 (not 401): the caller may be a valid
    regular API user, just not privileged enough for this action.
    """
    if not x_api_key:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Missing X-API-Key header (admin key required).",
        )

    if not _constant_time_in(x_api_key, settings.admin_api_key_set):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid or insufficient API key — admin key required.",
        )

    return x_api_key


def resolve_api_key_identity(
    api_key: str,
    settings: Settings,
) -> int:
    """Resolve a regular authenticated API key to its configured Telegram identity."""
    try:
        return settings.api_key_identity_map[api_key]
    except KeyError:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="API key has no configured scanner identity.",
        ) from None


def resolve_admin_key_identity(
    api_key: str,
    settings: Settings,
) -> int:
    """Resolve an admin authenticated API key to its configured Telegram identity."""
    try:
        return settings.admin_api_key_identity_map[api_key]
    except KeyError:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin API key has no configured identity.",
        ) from None


async def require_api_key_identity(
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    settings: Settings = Depends(get_settings),
) -> int:
    """Authenticate a regular API key and return its configured identity."""
    if not x_api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing X-API-Key header.",
        )

    if not _constant_time_in(x_api_key, settings.api_key_set):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key.",
        )

    return resolve_api_key_identity(x_api_key, settings)


async def require_admin_key_identity(
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    settings: Settings = Depends(get_settings),
) -> int:
    """Authenticate an admin API key and return its configured identity."""
    if not x_api_key:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Missing X-API-Key header (admin key required).",
        )

    if not _constant_time_in(x_api_key, settings.admin_api_key_set):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid or insufficient API key — admin key required.",
        )

    return resolve_admin_key_identity(x_api_key, settings)
