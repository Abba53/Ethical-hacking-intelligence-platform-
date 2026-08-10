"""
services/active/auth.py

Authorization layer for active scanning services.

Two-layer authorization model:
  1. User authorization: AUTHORIZED_SCAN_USERS — Telegram user IDs
     allowed to run any active scan at all.
  2. Target authorization: AUTHORIZED_SCAN_TARGETS — specific targets
     explicitly pre-authorized for scanning.

Debug additions:
- Logs authorization state after adding/removing targets.
- Logs every authorization check.
- Logs memory identity of AUTHORIZED_SCAN_TARGETS to detect
  duplicate module/state issues.
"""

import logging
import os

from dotenv import load_dotenv
from services.active.target_utils import extract_hostname

logger = logging.getLogger(__name__)

load_dotenv()


# ---------------------------------------------------------------------------
# User authorization — who can run active scans
# ---------------------------------------------------------------------------

def _load_authorized_users() -> set[int]:
    """
    Loads authorized Telegram user IDs from environment.
    Falls back to known user ID if env variable is missing.
    """
    raw = os.getenv("SCAN_AUTHORIZED_USERS", "")

    if raw.strip():
        try:
            ids = {
                int(uid.strip())
                for uid in raw.split(",")
                if uid.strip()
            }

            logger.info(
                "Loaded %d authorized scan user(s) from env",
                len(ids),
            )

            return ids

        except ValueError:
            logger.warning(
                "SCAN_AUTHORIZED_USERS contains invalid values — using fallback"
            )

    return {7094450571}


AUTHORIZED_SCAN_USERS: set[int] = _load_authorized_users()


# ---------------------------------------------------------------------------
# Target authorization — what can be scanned
# ---------------------------------------------------------------------------

# Runtime memory storage. Resets when bot restarts.
AUTHORIZED_SCAN_TARGETS: set[str] = set()


logger.info(
    "AUTH MODULE LOADED | module=%s | auth_set_id=%s",
    __name__,
    id(AUTHORIZED_SCAN_TARGETS),
)


def authorize_target(target: str, authorized_by: int) -> bool:
    """
    Adds target to authorized scan list.
    """

    from audit.audit_logger import log_operation

    normalized = extract_hostname(target)

    already_present = normalized in AUTHORIZED_SCAN_TARGETS

    AUTHORIZED_SCAN_TARGETS.add(normalized)

    logger.info(
        "DEBUG AUTHORIZE | target=%r | normalized=%r | auth_set=%r | auth_set_id=%s",
        target,
        normalized,
        AUTHORIZED_SCAN_TARGETS,
        id(AUTHORIZED_SCAN_TARGETS),
    )

    log_operation(
        operation_type="authorization",
        tool_name="auth",
        target=normalized,
        user_id=authorized_by,
        result_summary=(
            "target_authorized"
            if not already_present
            else "already_authorized"
        ),
        duration_ms=0,
        success=True,
        metadata={
            "authorized_by": authorized_by,
            "was_new": not already_present,
        },
    )

    logger.info(
        "Target authorized: %s by user_id=%s",
        normalized,
        authorized_by,
    )

    return not already_present


def deauthorize_target(target: str, authorized_by: int) -> bool:
    """
    Removes target from authorized scan list.
    """

    from audit.audit_logger import log_operation

    normalized = extract_hostname(target)

    was_present = normalized in AUTHORIZED_SCAN_TARGETS

    AUTHORIZED_SCAN_TARGETS.discard(normalized)

    logger.info(
        "DEBUG DEAUTHORIZE | target=%r | normalized=%r | auth_set=%r | auth_set_id=%s",
        target,
        normalized,
        AUTHORIZED_SCAN_TARGETS,
        id(AUTHORIZED_SCAN_TARGETS),
    )

    log_operation(
        operation_type="authorization",
        tool_name="auth",
        target=normalized,
        user_id=authorized_by,
        result_summary=(
            "target_deauthorized"
            if was_present
            else "target_not_found"
        ),
        duration_ms=0,
        success=True,
        metadata={
            "authorized_by": authorized_by
        },
    )

    return was_present


def is_authorized(
    user_id: int,
    target: str
) -> tuple[bool, str]:
    """
    Checks user and target authorization.
    """

    logger.info(
        "DEBUG USER CHECK | user=%s | allowed_users=%r",
        user_id,
        AUTHORIZED_SCAN_USERS,
    )

    if user_id not in AUTHORIZED_SCAN_USERS:
        return False, (
            f"user_id={user_id} is not in the authorized scanner list"
        )


    normalized = extract_hostname(target)

    logger.info(
        "DEBUG TARGET CHECK | user=%s | target=%r | normalized=%r | auth_set=%r | auth_set_id=%s",
        user_id,
        target,
        normalized,
        AUTHORIZED_SCAN_TARGETS,
        id(AUTHORIZED_SCAN_TARGETS),
    )


    if normalized not in AUTHORIZED_SCAN_TARGETS:

        logger.warning(
            "AUTHORIZATION FAILED | normalized=%r not found in auth_set=%r",
            normalized,
            AUTHORIZED_SCAN_TARGETS,
        )

        return False, (
            f"target '{target}' has not been authorized for scanning. "
            f"Use /authorize {target} first."
        )


    logger.info(
        "AUTHORIZATION SUCCESS | user=%s target=%s",
        user_id,
        normalized,
    )

    return True, (
        f"authorized: user={user_id} target={normalized}"
    )
