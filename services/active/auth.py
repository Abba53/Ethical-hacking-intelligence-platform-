"""
services/active/auth.py

Authorization layer for active scanning services.

Two-layer authorization model:
  1. User authorization: AUTHORIZED_SCAN_USERS — Telegram user IDs
     allowed to run any active scan at all.
  2. Target authorization: AUTHORIZED_SCAN_TARGETS — specific targets
     that have been explicitly pre-authorized for scanning.

Design notes:
- AUTHORIZED_SCAN_USERS is loaded from environment variable
  SCAN_AUTHORIZED_USERS (comma-separated Telegram user IDs).
  Falls back to a hardcoded set containing only your own user ID.
- AUTHORIZED_SCAN_TARGETS is an in-memory set, populated at runtime
  via the /authorize bot command. It resets on bot restart — this is
  deliberate: authorization should be an active, conscious decision
  each session, not a persistent blanket permission.
- Future FastAPI migration: these functions become middleware checks
  on the /api/v1/scan/* endpoint family.
"""

import logging
import os

from dotenv import load_dotenv

logger = logging.getLogger(__name__)
load_dotenv()

# ---------------------------------------------------------------------------
# User authorization — who can run active scans at all
# ---------------------------------------------------------------------------

def _load_authorized_users() -> set[int]:
    """
    Loads authorized Telegram user IDs from environment.
    Falls back to your known user ID if env var not set.
    """
    raw = os.getenv("SCAN_AUTHORIZED_USERS", "")
    if raw.strip():
        try:
            ids = {int(uid.strip()) for uid in raw.split(",") if uid.strip()}
            logger.info("Loaded %d authorized scan user(s) from env", len(ids))
            return ids
        except ValueError:
            logger.warning(
                "SCAN_AUTHORIZED_USERS contains non-integer values — "
                "falling back to default"
            )
    # Fallback: your own Telegram user ID confirmed in Phase 4
    return {7094450571}


AUTHORIZED_SCAN_USERS: set[int] = _load_authorized_users()

# ---------------------------------------------------------------------------
# Target authorization — what can be scanned
# ---------------------------------------------------------------------------

# In-memory set — resets on restart (deliberate design choice)
AUTHORIZED_SCAN_TARGETS: set[str] = set()


def authorize_target(target: str, authorized_by: int) -> bool:
    """
    Adds a target to the authorized scan set.

    Returns True if newly authorized, False if already present.
    Always audit-logs the authorization action.
    """
    from audit.audit_logger import log_operation
    normalized = target.strip().lower()
    already_present = normalized in AUTHORIZED_SCAN_TARGETS
    AUTHORIZED_SCAN_TARGETS.add(normalized)
    log_operation(
        operation_type="authorization",
        tool_name="auth",
        target=normalized,
        user_id=authorized_by,
        result_summary="target_authorized" if not already_present else "already_authorized",
        duration_ms=0,
        success=True,
        metadata={"authorized_by": authorized_by, "was_new": not already_present},
    )
    logger.info(
        "Target authorized: %s by user_id=%s", normalized, authorized_by
    )
    return not already_present


def deauthorize_target(target: str, authorized_by: int) -> bool:
    """
    Removes a target from the authorized scan set.

    Returns True if removed, False if wasn't present.
    """
    from audit.audit_logger import log_operation
    normalized = target.strip().lower()
    was_present = normalized in AUTHORIZED_SCAN_TARGETS
    AUTHORIZED_SCAN_TARGETS.discard(normalized)
    log_operation(
        operation_type="authorization",
        tool_name="auth",
        target=normalized,
        user_id=authorized_by,
        result_summary="target_deauthorized" if was_present else "target_not_found",
        duration_ms=0,
        success=True,
        metadata={"authorized_by": authorized_by},
    )
    return was_present


def is_authorized(user_id: int, target: str) -> tuple[bool, str]:
    """
    Checks both authorization layers for a proposed scan.

    Returns (authorized: bool, reason: str).
    Reason explains why authorization was denied, or confirms it.
    """
    if user_id not in AUTHORIZED_SCAN_USERS:
        return False, f"user_id={user_id} is not in the authorized scanner list"

    normalized = target.strip().lower()
    if normalized not in AUTHORIZED_SCAN_TARGETS:
        return False, (
            f"target '{target}' has not been authorized for scanning. "
            f"Use /authorize {target} first."
        )

    return True, f"authorized: user={user_id} target={normalized}"
