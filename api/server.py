"""Validated Uvicorn entry point for the FastAPI application."""

from __future__ import annotations

from pathlib import Path

import uvicorn

from api.config import get_settings


def build_server_options() -> dict:
    """Build Uvicorn options from validated application settings."""
    settings = get_settings()

    certfile = settings.TLS_CERTFILE.strip()
    keyfile = settings.TLS_KEYFILE.strip()

    if bool(certfile) != bool(keyfile):
        raise RuntimeError(
            "Direct TLS requires both TLS_CERTFILE and TLS_KEYFILE."
        )

    options = {
        "app": "api.main:app",
        "host": settings.HOST,
        "port": settings.PORT,
    }

    if certfile and keyfile:
        cert_path = Path(certfile).expanduser().resolve()
        key_path = Path(keyfile).expanduser().resolve()

        if not cert_path.is_file():
            raise RuntimeError("TLS certificate file does not exist.")
        if not key_path.is_file():
            raise RuntimeError("TLS private key file does not exist.")

        options["ssl_certfile"] = str(cert_path)
        options["ssl_keyfile"] = str(key_path)

    return options


def main() -> None:
    """Start Uvicorn using validated configuration."""
    uvicorn.run(**build_server_options())


if __name__ == "__main__":
    main()
