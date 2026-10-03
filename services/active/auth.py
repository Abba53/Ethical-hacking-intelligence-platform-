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
    Fails closed when the environment variable is missing or invalid.
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
                "SCAN_AUTHORIZED_USERS contains invalid values — denying scanner access"
            )

    return set()


AUTHORIZED_SCAN_USERS: set[int] = _load_authorized_users()


# ---------------------------------------------------------------------------
# Target authorization — what can be scanned
# ---------------------------------------------------------------------------

# Runtime memory storage. Resets when bot restarts.
AUTHORIZED_SCAN_TARGETS: set[str] = set()

# Runtime per-user/per-target grants.
# Each grant allows one specific user to scan one specific globally
# authorized target. Resets when the process restarts.
AUTHORIZED_SCAN_GRANTS: set[tuple[int, str]] = set()


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


def grant_scan_access(user_id: int, target: str, granted_by: int) -> bool:
    """
    Grant one specific user permission to scan one globally authorized target.
    Returns True when a new grant was created.
    """
    from audit.audit_logger import log_operation

    normalized = extract_hostname(target)

    if normalized not in AUTHORIZED_SCAN_TARGETS:
        logger.warning(
            "GRANT DENIED | target=%r normalized=%r is not globally authorized",
            target,
            normalized,
        )
        return False

    grant = (int(user_id), normalized)
    already_present = grant in AUTHORIZED_SCAN_GRANTS
    AUTHORIZED_SCAN_GRANTS.add(grant)

    log_operation(
        operation_type="authorization",
        tool_name="auth",
        target=normalized,
        user_id=granted_by,
        result_summary=(
            "scan_access_granted"
            if not already_present
            else "scan_access_already_granted"
        ),
        duration_ms=0,
        success=True,
        metadata={
            "granted_by": granted_by,
            "granted_user_id": int(user_id),
            "was_new": not already_present,
        },
    )

    logger.info(
        "Scan access granted | user_id=%s target=%s by admin=%s",
        user_id,
        normalized,
        granted_by,
    )

    return not already_present


def revoke_scan_access(user_id: int, target: str, revoked_by: int) -> bool:
    """
    Revoke one specific user's permission for one target.
    Returns True when an existing grant was removed.
    """
    from audit.audit_logger import log_operation

    normalized = extract_hostname(target)
    grant = (int(user_id), normalized)
    was_present = grant in AUTHORIZED_SCAN_GRANTS
    AUTHORIZED_SCAN_GRANTS.discard(grant)

    log_operation(
        operation_type="authorization",
        tool_name="auth",
        target=normalized,
        user_id=revoked_by,
        result_summary=(
            "scan_access_revoked"
            if was_present
            else "scan_access_grant_not_found"
        ),
        duration_ms=0,
        success=True,
        metadata={
            "revoked_by": revoked_by,
            "revoked_user_id": int(user_id),
        },
    )

    logger.info(
        "Scan access revoked | user_id=%s target=%s by admin=%s",
        user_id,
        normalized,
        revoked_by,
    )

    return was_present


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


def is_authorized(user_id: int, target: str) -> tuple[bool, str]:
    """
    Checks target authorization plus either global user authorization
    or an explicit per-user/per-target grant.
    """
    normalized = extract_hostname(target)

    logger.info(
        "DEBUG AUTH CHECK | user=%s | target=%r | normalized=%r | "
        "global_users=%r | grants=%r | targets=%r",
        user_id,
        target,
        normalized,
        AUTHORIZED_SCAN_USERS,
        AUTHORIZED_SCAN_GRANTS,
        AUTHORIZED_SCAN_TARGETS,
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

    global_user_allowed = user_id in AUTHORIZED_SCAN_USERS
    explicit_grant = (user_id, normalized) in AUTHORIZED_SCAN_GRANTS

    if not global_user_allowed and not explicit_grant:
        logger.warning(
            "AUTHORIZATION FAILED | user=%s has no permission for target=%s",
            user_id,
            normalized,
        )
        return False, (
            f"user_id={user_id} is not authorized to scan target '{normalized}'. "
            f"An administrator must grant this user access."
        )

    authorization_source = (
        "global_user_authorization"
        if global_user_allowed
        else "explicit_user_target_grant"
    )

    logger.info(
        "AUTHORIZATION SUCCESS | user=%s target=%s source=%s",
        user_id,
        normalized,
        authorization_source,
    )

    return True, (
        f"authorized: user={user_id} target={normalized} "
        f"source={authorization_source}"
    )
