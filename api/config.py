"""
api/config.py

Phase 12.2 — Application configuration
Phase 12.3 — Environment / secrets management

Rules carried over from the platform spec (Section 25):
    - Secrets ONLY come from environment variables / .env
    - .env is never committed
    - .env.example documents every required variable
    - No provider SDK or scanner logic lives here — config only
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import List, Optional

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    """
    Centralized, validated configuration for the FastAPI backend.

    This does NOT replace bot.py's configuration — it is the API's own
    view of the same environment, so both entry points (Telegram bot,
    FastAPI backend) can run side by side against one .env file.
    """

    model_config = SettingsConfigDict(
        env_file=str(BASE_DIR / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # --- App metadata ---
    APP_NAME: str = "Ethical Hacking Intelligence Automation Platform API"
    APP_ENV: str = Field(default="development")  # development | staging | production
    API_VERSION: str = "12.0.0"
    DEBUG: bool = False

    # --- Server ---
    HOST: str = "0.0.0.0"
    PORT: int = 8000

    # --- TLS / encryption in transit ---
    TLS_CERTFILE: str = Field(default="")
    TLS_KEYFILE: str = Field(default="")
    FORCE_HTTPS: bool = False
    TRUST_PROXY_HEADERS: bool = False

    # --- Database (Phase 6/7 SQLite layer) ---
    DATABASE_PATH: str = str(BASE_DIR / "data" / "platform.db")

    # --- Auth (Phase 12.6) ---
    API_KEYS: str = Field(default="")
    ADMIN_API_KEYS: str = Field(default="")

    # --- Rate limiting (Phase 12.13) ---
    RATE_LIMIT_PER_MINUTE: int = 60
    RATE_LIMIT_ACTIVE_SCAN_PER_HOUR: int = 10

    # --- CORS ---
    CORS_ORIGINS: str = Field(default="")

    # --- AI provider selection (Phase 10/11 — read-through only) ---
    AI_PROVIDER: str = Field(default="openrouter")

    # --- Authorization boundary (Section 22) ---
    ACTIVE_SCANS_ENABLED: bool = True

    # --- Background jobs (Phase 12.11) ---
    MAX_CONCURRENT_JOBS: int = 5
    JOB_RESULT_TTL_SECONDS: int = 86400

    # --- Audit logging (Phase 12.12) ---
    AUDIT_LOG_PATH: str = str(BASE_DIR / "data" / "audit.log")

    @field_validator("APP_ENV")
    @classmethod
    def _validate_env(cls, v: str) -> str:
        allowed = {"development", "staging", "production"}
        if v not in allowed:
            raise ValueError(f"APP_ENV must be one of {allowed}, got {v!r}")
        return v

    @property
    def api_key_set(self) -> set[str]:
        return {k.strip() for k in self.API_KEYS.split(",") if k.strip()}

    @property
    def admin_api_key_set(self) -> set[str]:
        return {k.strip() for k in self.ADMIN_API_KEYS.split(",") if k.strip()}

    @property
    def cors_origin_list(self) -> List[str]:
        return [o.strip() for o in self.CORS_ORIGINS.split(",") if o.strip()]

    @property
    def is_production(self) -> bool:
        return self.APP_ENV == "production"

    @property
    def tls_enabled_directly(self) -> bool:
        """True when Uvicorn itself should terminate TLS (Pattern A)."""
        return bool(self.TLS_CERTFILE and self.TLS_KEYFILE)


@lru_cache
def get_settings() -> Settings:
    """Cached settings singleton — read once, reused across the app."""
    settings = Settings()
    if settings.is_production and not settings.api_key_set:
        raise RuntimeError(
            "Refusing to start in production with no API_KEYS configured. "
            "Set API_KEYS in your environment/.env."
        )
    if settings.FORCE_HTTPS and not settings.tls_enabled_directly and not settings.TRUST_PROXY_HEADERS:
        raise RuntimeError(
            "FORCE_HTTPS=true but neither TLS_CERTFILE/TLS_KEYFILE (direct TLS) "
            "nor TRUST_PROXY_HEADERS=true (behind a TLS-terminating proxy) is "
            "set. Uvicorn would have no way to ever see an HTTPS request, and "
            "FORCE_HTTPS would redirect every request forever."
        )
    return settings
