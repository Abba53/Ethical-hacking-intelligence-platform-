"""Safe SQLite database backup and integrity verification."""
import argparse
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from sqlalchemy.engine import make_url

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_BACKUP_DIR = ROOT / "backups"


def resolve_sqlite_path(database_url: str) -> Path:
    url = make_url(database_url)
    if url.drivername not in {"sqlite", "sqlite+pysqlite"}:
        raise ValueError("Only SQLite databases are supported.")
    database = url.database
    if not database or database == ":memory:":
        raise ValueError("A file-backed SQLite database is required.")
    path = Path(database).expanduser()
    if not path.is_absolute():
        path = Path.cwd() / path
    return path.resolve()


def integrity_check(database_path: Path) -> None:
    path = Path(database_path).resolve()
    if not path.is_file():
        raise FileNotFoundError(f"Database file not found: {path}")
    connection = sqlite3.connect(
        f"{path.as_uri()}?mode=ro", uri=True, timeout=30
    )
    try:
        result = connection.execute("PRAGMA integrity_check").fetchone()
        if not result or result[0] != "ok":
            detail = result[0] if result else "No integrity result"
            raise RuntimeError(f"Database integrity check failed: {detail}")
    finally:
        connection.close()


def backup_database(database_url: str, backup_dir: Path = DEFAULT_BACKUP_DIR) -> Path:
    source_path = resolve_sqlite_path(database_url)
    if not source_path.is_file():
        raise FileNotFoundError(f"Source database not found: {source_path}")
    integrity_check(source_path)
    destination_dir = Path(backup_dir).resolve()
    destination_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    destination = destination_dir / f"platform-{timestamp}.sqlite3"
    if destination.exists():
        raise FileExistsError("Backup destination already exists.")
    source = sqlite3.connect(
        f"{source_path.as_uri()}?mode=ro", uri=True, timeout=30
    )
    target = None
    try:
        target = sqlite3.connect(destination, timeout=30)
        source.backup(target)
        target.close()
        target = None
        try:
            destination.chmod(0o600)
        except OSError:
            pass
        integrity_check(destination)
        return destination
    except Exception:
        if target is not None:
            target.close()
        destination.unlink(missing_ok=True)
        raise
    finally:
        source.close()



def restore_database(backup_path: Path, destination_path: Path) -> Path:
    """Restore a verified backup to a new file without overwriting data."""
    backup = Path(backup_path).expanduser().resolve()
    destination = Path(destination_path).expanduser().resolve()

    if backup == destination:
        raise ValueError("Backup and destination must be different files.")
    if not backup.is_file():
        raise FileNotFoundError(f"Backup file not found: {backup}")
    if destination.exists():
        raise FileExistsError(f"Destination already exists: {destination}")

    integrity_check(backup)
    destination.parent.mkdir(parents=True, exist_ok=True)

    source = sqlite3.connect(
        f"{backup.as_uri()}?mode=ro", uri=True, timeout=30
    )
    target = None
    try:
        target = sqlite3.connect(destination, timeout=30)
        source.backup(target)
        target.close()
        target = None
        try:
            destination.chmod(0o600)
        except OSError:
            pass
        integrity_check(destination)
        return destination
    except Exception:
        if target is not None:
            target.close()
        destination.unlink(missing_ok=True)
        raise
    finally:
        source.close()

def main() -> int:
    parser = argparse.ArgumentParser(description="Create or verify a SQLite backup.")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("backup")
    verify_parser = commands.add_parser("verify")
    verify_parser.add_argument("path", type=Path)
    restore_parser = commands.add_parser("restore")
    restore_parser.add_argument("backup_path", type=Path)
    restore_parser.add_argument("destination_path", type=Path)
    args = parser.parse_args()
    try:
        if args.command == "backup":
            from database.db import DATABASE_URL
            destination = backup_database(DATABASE_URL)
            print("Backup created and verified.")
            print(f"File: {destination}")
        elif args.command == "verify":
            integrity_check(args.path)
            print("Integrity check passed.")
            print(f"File: {args.path.resolve()}")
        else:
            destination = restore_database(
                args.backup_path, args.destination_path
            )
            print("Database restored and verified.")
            print(f"File: {destination}")
        return 0
    except Exception as exc:
        print(f"Backup operation failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
