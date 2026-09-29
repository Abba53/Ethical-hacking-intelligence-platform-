from pathlib import Path

import audit.audit_logger as audit_logger


def test_audit_timer_persists_authenticated_identity(monkeypatch, tmp_path):
    audit_path = tmp_path / "audit.jsonl"
    monkeypatch.setattr(audit_logger, "AUDIT_LOG_PATH", Path(audit_path))

    authenticated_identity = 123456789

    with audit_logger.AuditTimer(
        "passive_lookup",
        "identity-integrity-test",
        "example.com",
        user_id=authenticated_identity,
    ) as timer:
        timer.result_summary = "identity-integrity-test"

    records = audit_logger.read_recent_audit_logs(limit=1)

    assert len(records) == 1
    assert records[0]["user_id"] == str(authenticated_identity)
    assert records[0]["operation_type"] == "passive_lookup"
    assert records[0]["tool_name"] == "identity-integrity-test"
    assert records[0]["target"] == "example.com"
