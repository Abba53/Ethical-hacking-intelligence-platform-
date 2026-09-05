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
