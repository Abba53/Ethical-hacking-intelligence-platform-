"""
audit/audit_logger.py

Centralized audit logging for all security operations.

Every security tool invocation — passive or active — is recorded here with:
- timestamp
- operation type (passive_lookup, active_scan, etc.)
- tool name
- target (what was investigated)
- user_id (who requested it, from Telegram)
- result summary (success/failure, finding count)
- duration_ms (how long it took)

Design notes:
- Audit records are written to both the database (for querying) and a
  structured log file (for external SIEM integration later).
- This module has NO dependencies on other platform modules — it is the
  foundation layer. Nothing it imports can import from audit/.
- Future FastAPI migration: audit endpoints will expose this data via
  GET /audit/logs with filtering by user, operation, target, date range.
"""

import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

# Audit log file — structured JSONL (one JSON object per line)
# JSONL format is intentional: each line is valid JSON, making it easy
# to stream into external tools (Splunk, ELK, etc.) without parsing
# a full JSON array.
AUDIT_LOG_PATH = Path("data/audit.jsonl")


def _ensure_audit_file() -> None:
    """Creates the audit log file and parent directory if they don't exist."""
    AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    if not AUDIT_LOG_PATH.exists():
        AUDIT_LOG_PATH.touch()


def log_operation(
    operation_type: str,
    tool_name: str,
    target: str,
    user_id: int | str,
    result_summary: str,
    duration_ms: int,
    success: bool = True,
    metadata: dict | None = None,
) -> None:
    """
    Records a security operation to the audit log.

    Args:
        operation_type: 'passive_lookup' | 'active_scan' | 'collection' | 'extraction'
        tool_name: name of the tool/service (e.g. 'abuseipdb', 'nmap', 'nuclei')
        target: what was investigated (IP, domain, URL — NOT credentials)
        user_id: Telegram user ID who triggered this operation
        result_summary: human-readable outcome (e.g. '3 findings', 'clean', 'error: timeout')
        duration_ms: how long the operation took in milliseconds
        success: whether the operation completed without error
        metadata: optional additional structured data (finding counts, severity, etc.)
    """
    _ensure_audit_file()

    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "operation_type": operation_type,
        "tool_name": tool_name,
        "target": target,
        "user_id": str(user_id),
        "result_summary": result_summary,
        "duration_ms": duration_ms,
        "success": success,
        "metadata": metadata or {},
    }

    # Write to JSONL file
    try:
        with open(AUDIT_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")
    except OSError as e:
        # Never let audit logging failure crash the main operation
        logger.error("Failed to write audit log: %s", e)

    # Also emit to the standard logger at INFO level
    logger.info(
        "AUDIT | %s | tool=%s | target=%s | user=%s | %s | %dms",
        operation_type,
        tool_name,
        target,
        user_id,
        result_summary,
        duration_ms,
    )


class AuditTimer:
    """
    Context manager for timing operations and automatically logging them.

    Usage:
        with AuditTimer("passive_lookup", "abuseipdb", "8.8.8.8", user_id=123) as t:
            result = await get_abuseipdb_report("8.8.8.8")
            t.result_summary = f"score={result['abuse_confidence_score']}"
            t.metadata = {"score": result["abuse_confidence_score"]}
    """

    def __init__(
        self,
        operation_type: str,
        tool_name: str,
        target: str,
        user_id: int | str = "system",
    ):
        self.operation_type = operation_type
        self.tool_name = tool_name
        self.target = target
        self.user_id = user_id
        self.result_summary = "completed"
        self.metadata: dict = {}
        self.success = True
        self._start: float = 0.0

    def __enter__(self) -> "AuditTimer":
        self._start = time.monotonic()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> bool:
        duration_ms = int((time.monotonic() - self._start) * 1000)
        if exc_type is not None:
            self.success = False
            self.result_summary = f"error: {exc_val}"
        log_operation(
            operation_type=self.operation_type,
            tool_name=self.tool_name,
            target=self.target,
            user_id=self.user_id,
            result_summary=self.result_summary,
            duration_ms=duration_ms,
            success=self.success,
            metadata=self.metadata,
        )
        return False  # don't suppress exceptions


def read_recent_audit_logs(limit: int = 20) -> list[dict]:
    """
    Reads the most recent audit log entries.

    Used by a future /auditlog bot command or FastAPI endpoint.
    Returns entries in reverse chronological order (newest first).
    """
    if not AUDIT_LOG_PATH.exists():
        return []

    try:
        lines = AUDIT_LOG_PATH.read_text(encoding="utf-8").strip().splitlines()
        records = []
        for line in reversed(lines[-limit * 2:]):
            try:
                records.append(json.loads(line))
                if len(records) >= limit:
                    break
            except json.JSONDecodeError:
                continue
        return records
    except OSError as e:
        logger.error("Failed to read audit log: %s", e)
        return []
