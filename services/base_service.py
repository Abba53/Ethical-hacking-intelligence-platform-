"""
services/base_service.py

Abstract base class for all platform services.

Every service in services/passive/ and services/active/ inherits from
BaseService, which provides:
- Standardized audit logging via AuditTimer
- Consistent result envelope format
- Classification metadata (passive vs. active, requires_auth flag)
- Future FastAPI migration path (service methods become endpoint handlers)

Design notes:
- Services are STATELESS — no instance variables that persist between calls.
  All state lives in the database or is passed as arguments.
- Services depend ONLY on tools/ and extractors/ via defined interfaces,
  never on each other directly. Cross-service calls go through bot.py
  or (later) the FastAPI router layer.
- The result envelope format is fixed: every service method returns a dict
  with at least: {success, data, error, tool_name, operation_type}
  This makes bot formatting and API serialization uniform across all services.
"""

from abc import ABC, abstractmethod
from typing import Any

from audit.audit_logger import AuditTimer


class BaseService(ABC):
    """
    Abstract base for all platform services.

    Subclasses must define:
      - service_name: str — identifies the service in audit logs
      - operation_type: str — 'passive_lookup' or 'active_scan'
      - requires_authorization: bool — True for active scanning tools

    Subclasses should implement async methods that:
      1. Use AuditTimer as a context manager for every external call
      2. Return the standard result envelope via _ok() or _err()
    """

    service_name: str = "base"
    operation_type: str = "passive_lookup"
    requires_authorization: bool = False

    def _ok(self, data: Any, summary: str = "success") -> dict:
        """Returns a successful result envelope."""
        return {
            "success": True,
            "data": data,
            "error": None,
            "tool_name": self.service_name,
            "operation_type": self.operation_type,
            "summary": summary,
        }

    def _err(self, error: str, data: Any = None) -> dict:
        """Returns a failed result envelope."""
        return {
            "success": False,
            "data": data,
            "error": error,
            "tool_name": self.service_name,
            "operation_type": self.operation_type,
            "summary": f"error: {error}",
        }

    def audit_timer(
        self, target: str, user_id: int | str = "system"
    ) -> AuditTimer:
        """
        Returns a pre-configured AuditTimer for this service.

        Usage in subclass:
            with self.audit_timer(target, user_id) as t:
                result = await some_api_call(target)
                t.result_summary = f"found {len(result)} items"
                t.metadata = {"count": len(result)}
        """
        return AuditTimer(
            operation_type=self.operation_type,
            tool_name=self.service_name,
            target=target,
            user_id=user_id,
        )
