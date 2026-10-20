"""Regression tests preventing database connection credentials leaking into logs."""

import logging

from database import db


def test_init_db_does_not_log_database_url(monkeypatch, caplog):
    secret_url = "postgresql://user:supersecret@db.example:5432/platform"

    monkeypatch.setattr(db, "DATABASE_URL", secret_url)
    monkeypatch.setattr(db, "Base", type("BaseStub", (), {
        "metadata": type("MetadataStub", (), {
            "create_all": staticmethod(lambda engine: None)
        })()
    }))

    with caplog.at_level(logging.INFO, logger="database.db"):
        db.init_db()

    assert secret_url not in caplog.text
    assert "supersecret" not in caplog.text
    assert "Database initialized successfully" in caplog.text


def test_database_script_status_message_does_not_include_database_url():
    import ast
    from pathlib import Path

    source = Path("database/db.py").read_text()
    tree = ast.parse(source)

    print_calls = [
        node for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "print"
    ]

    assert print_calls
    assert all(
        "DATABASE_URL" not in ast.unparse(node)
        for node in print_calls
    )
