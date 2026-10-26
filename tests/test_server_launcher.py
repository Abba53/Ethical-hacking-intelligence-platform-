"""Regression tests for the validated API server launcher."""

from api import server


def test_launcher_uses_configured_host_and_port(monkeypatch):
    monkeypatch.setattr(
        server,
        "get_settings",
        lambda: type(
            "Settings",
            (),
            {
                "TLS_CERTFILE": "",
                "TLS_KEYFILE": "",
                "HOST": "127.0.0.1",
                "PORT": 8123,
            },
        )(),
    )

    options = server.build_server_options()

    assert options == {
        "app": "api.main:app",
        "host": "127.0.0.1",
        "port": 8123,
    }


def test_launcher_rejects_incomplete_tls_pair(monkeypatch):
    monkeypatch.setattr(
        server,
        "get_settings",
        lambda: type(
            "Settings",
            (),
            {
                "TLS_CERTFILE": "/tmp/cert.pem",
                "TLS_KEYFILE": "",
                "HOST": "127.0.0.1",
                "PORT": 8000,
            },
        )(),
    )

    import pytest

    with pytest.raises(RuntimeError, match="both TLS_CERTFILE and TLS_KEYFILE"):
        server.build_server_options()


def test_launcher_rejects_missing_tls_files(monkeypatch, tmp_path):
    cert = tmp_path / "cert.pem"
    key = tmp_path / "key.pem"
    cert.write_text("test certificate", encoding="utf-8")

    monkeypatch.setattr(
        server,
        "get_settings",
        lambda: type(
            "Settings",
            (),
            {
                "TLS_CERTFILE": str(cert),
                "TLS_KEYFILE": str(key),
                "HOST": "127.0.0.1",
                "PORT": 8000,
            },
        )(),
    )

    import pytest

    with pytest.raises(RuntimeError, match="TLS private key file does not exist"):
        server.build_server_options()


def test_launcher_passes_existing_tls_files(monkeypatch, tmp_path):
    cert = tmp_path / "cert.pem"
    key = tmp_path / "key.pem"
    cert.write_text("test certificate", encoding="utf-8")
    key.write_text("test private key", encoding="utf-8")

    monkeypatch.setattr(
        server,
        "get_settings",
        lambda: type(
            "Settings",
            (),
            {
                "TLS_CERTFILE": str(cert),
                "TLS_KEYFILE": str(key),
                "HOST": "127.0.0.1",
                "PORT": 8000,
            },
        )(),
    )

    options = server.build_server_options()

    assert options["ssl_certfile"] == str(cert.resolve())
    assert options["ssl_keyfile"] == str(key.resolve())
