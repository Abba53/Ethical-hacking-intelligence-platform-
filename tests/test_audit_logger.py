"""Regression tests for audit logging and log retrieval."""

import json

import pytest

import audit.audit_logger as audit_logger


def test_log_operation_creates_valid_jsonl(tmp_path, monkeypatch):
    log_path = tmp_path / "data" / "audit.jsonl"
    monkeypatch.setattr(audit_logger, "AUDIT_LOG_PATH", log_path)

    audit_logger.log_operation(
        operation_type="active_scan",
        tool_name="test",
        target="example.com",
        user_id=123,
        result_summary="completed",
        duration_ms=25,
    )

    records = audit_logger.read_recent_audit_logs(limit=1)
    assert len(records) == 1
    assert records[0]["operation_type"] == "active_scan"
    assert records[0]["user_id"] == "123"


def test_log_operation_does_not_raise_when_file_creation_fails(
    tmp_path, monkeypatch
):
    blocked_parent = tmp_path / "blocked"
    blocked_parent.write_text("not a directory")
    monkeypatch.setattr(
        audit_logger, "AUDIT_LOG_PATH", blocked_parent / "audit.jsonl"
    )

    audit_logger.log_operation(
        operation_type="active_scan",
        tool_name="test",
        target="example.com",
        user_id=123,
        result_summary="completed",
        duration_ms=25,
    )


def test_read_recent_audit_logs_zero_limit_returns_empty(tmp_path, monkeypatch):
    log_path = tmp_path / "audit.jsonl"
    log_path.write_text('{"event": "test"}\n')
    monkeypatch.setattr(audit_logger, "AUDIT_LOG_PATH", log_path)

    assert audit_logger.read_recent_audit_logs(limit=0) == []


@pytest.mark.parametrize("limit", [-1, True, 1.5, "10", None])
def test_read_recent_audit_logs_rejects_invalid_limit(limit):
    with pytest.raises(ValueError, match="non-negative integer"):
        audit_logger.read_recent_audit_logs(limit=limit)


def test_read_recent_audit_logs_skips_malformed_lines(tmp_path, monkeypatch):
    log_path = tmp_path / "audit.jsonl"
    log_path.write_text(
        '{"event": "old"}\nnot-json\n{"event": "new"}\n'
    )
    monkeypatch.setattr(audit_logger, "AUDIT_LOG_PATH", log_path)

    records = audit_logger.read_recent_audit_logs(limit=2)
    assert [record["event"] for record in records] == ["new", "old"]
