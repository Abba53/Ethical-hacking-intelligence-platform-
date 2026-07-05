"""
services/active/__init__.py

Active scanning services — tools that send traffic to target systems.

AUTHORIZATION REQUIRED: All active services enforce two-layer authorization:
1. User must be in AUTHORIZED_SCAN_USERS (Telegram user IDs)
2. Target must be in AUTHORIZED_SCAN_TARGETS (explicitly pre-authorized)

This is enforced in ActiveBaseService, inherited by all active services.
Legal note: Only run active scans against systems you own or have explicit
written permission to test. Unauthorized scanning is illegal in most
jurisdictions regardless of intent.
"""

from services.active.auth import (
    AUTHORIZED_SCAN_USERS,
    authorize_target,
    deauthorize_target,
    is_authorized,
)

__all__ = [
    "AUTHORIZED_SCAN_USERS",
    "authorize_target",
    "deauthorize_target",
    "is_authorized",
]
