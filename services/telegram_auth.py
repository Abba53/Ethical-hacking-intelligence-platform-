"""
services/telegram_auth.py

Telegram command authorization helpers.

Admin identities are explicitly configured through:
    TELEGRAM_ADMIN_USERS=123456789,987654321

Authorization fails closed when the variable is missing or malformed.
"""

import logging
import os

from dotenv import load_dotenv

logger = logging.getLogger(__name__)

load_dotenv()


def _parse_user_ids(raw: str) -> set[int]:
    """Parse comma-separated positive Telegram user IDs."""
    if not raw.strip():
        return set()

    try:
        user_ids = {
            int(value.strip())
            for value in raw.split(",")
            if value.strip()
        }
    except ValueError:
        logger.warning("Telegram user ID configuration contains invalid values")
        return set()

    if any(user_id <= 0 for user_id in user_ids):
        logger.warning("Telegram user ID configuration contains non-positive IDs")
        return set()

    return user_ids


def get_telegram_admin_users() -> set[int]:
    """Return all explicitly configured Telegram administrator IDs."""
    return _parse_user_ids(
        os.getenv("TELEGRAM_ADMIN_USERS", "")
    )


def is_telegram_admin(user_id: int) -> bool:
    """Return True only when user_id is explicitly configured as a Telegram admin."""
    return user_id in _parse_user_ids(
        os.getenv("TELEGRAM_ADMIN_USERS", "")
    )
