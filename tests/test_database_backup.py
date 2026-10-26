"""Tests for SQLite backup and integrity verification."""

import sqlite3

import pytest

from database.backup import (
    backup_database,
    integrity_check,
    resolve_sqlite_path,
    restore_database,
)


def create_database(path):
    connection = sqlite3.connect(path)
    try:
        connection.execute(
            "CREATE TABLE sample (id INTEGER PRIMARY KEY, value TEXT NOT NULL)"
        )
        connection.execute(
            "INSERT INTO sample (value) VALUES (?)",
            ("backup-test",),
        )
        connection.commit()
    finally:
        connection.close()


def test_backup_preserves_data_and_passes_integrity_check(tmp_path):
    source = tmp_path / "source.db"
    backup_dir = tmp_path / "backups"
    create_database(source)

    result = backup_database(
        f"sqlite:///{source}",
        backup_dir,
    )

    assert result.is_file()
    assert result.parent == backup_dir.resolve()
    integrity_check(result)

    connection = sqlite3.connect(result)
    try:
        row = connection.execute(
            "SELECT value FROM sample WHERE id = 1"
        ).fetchone()
        assert row == ("backup-test",)
    finally:
        connection.close()

    original = sqlite3.connect(source)
    try:
        assert original.execute(
            "SELECT value FROM sample WHERE id = 1"
        ).fetchone() == ("backup-test",)
    finally:
        original.close()


def test_missing_source_fails_without_creating_backup(tmp_path):
    source = tmp_path / "missing.db"
    backup_dir = tmp_path / "backups"

    with pytest.raises(FileNotFoundError):
        backup_database(f"sqlite:///{source}", backup_dir)

    assert not backup_dir.exists()


def test_non_sqlite_database_is_rejected():
    with pytest.raises(ValueError, match="Only SQLite"):
        resolve_sqlite_path("postgresql://user:pass@localhost/example")


def test_in_memory_sqlite_is_rejected():
    with pytest.raises(ValueError, match="file-backed"):
        resolve_sqlite_path("sqlite:///:memory:")


def test_integrity_check_rejects_missing_file(tmp_path):
    with pytest.raises(FileNotFoundError):
        integrity_check(tmp_path / "missing.db")


def test_backup_contains_independent_copy(tmp_path):
    source = tmp_path / "source.db"
    create_database(source)

    backup = backup_database(
        f"sqlite:///{source}",
        tmp_path / "backups",
    )

    connection = sqlite3.connect(source)
    try:
        connection.execute("UPDATE sample SET value = 'changed'")
        connection.commit()
    finally:
        connection.close()

    connection = sqlite3.connect(backup)
    try:
        assert connection.execute(
            "SELECT value FROM sample WHERE id = 1"
        ).fetchone() == ("backup-test",)
    finally:
        connection.close()


def test_restore_preserves_data_and_passes_integrity_check(tmp_path):
    source = tmp_path / "source.db"
    create_database(source)
    backup = backup_database(
        f"sqlite:///{source}", tmp_path / "backups"
    )
    destination = tmp_path / "restored.db"

    result = restore_database(backup, destination)

    assert result == destination.resolve()
    integrity_check(result)
    connection = sqlite3.connect(result)
    try:
        assert connection.execute(
            "SELECT value FROM sample WHERE id = 1"
        ).fetchone() == ("backup-test",)
    finally:
        connection.close()


def test_restore_rejects_missing_backup(tmp_path):
    destination = tmp_path / "restored.db"
    with pytest.raises(FileNotFoundError):
        restore_database(tmp_path / "missing.db", destination)
    assert not destination.exists()


def test_restore_rejects_corrupt_backup(tmp_path):
    backup = tmp_path / "corrupt.db"
    backup.write_bytes(b"this is not a valid SQLite database")
    destination = tmp_path / "restored.db"

    with pytest.raises((sqlite3.DatabaseError, RuntimeError)):
        restore_database(backup, destination)

    assert not destination.exists()


def test_restore_refuses_to_overwrite_existing_destination(tmp_path):
    source = tmp_path / "source.db"
    create_database(source)
    backup = backup_database(
        f"sqlite:///{source}", tmp_path / "backups"
    )
    destination = tmp_path / "existing.db"
    destination.write_text("preserve this file")

    with pytest.raises(FileExistsError):
        restore_database(backup, destination)

    assert destination.read_text() == "preserve this file"


def test_restore_rejects_same_source_and_destination(tmp_path):
    source = tmp_path / "source.db"
    create_database(source)

    with pytest.raises(ValueError, match="different files"):
        restore_database(source, source)

    connection = sqlite3.connect(source)
    try:
        assert connection.execute(
            "SELECT value FROM sample WHERE id = 1"
        ).fetchone() == ("backup-test",)
    finally:
        connection.close()
