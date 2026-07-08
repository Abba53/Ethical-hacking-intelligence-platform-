"""
services/active/mobile_service.py

Mobile application security assessment service.

Tools (planned):
  - Frida: dynamic instrumentation toolkit
  - Objection: runtime mobile exploration (built on Frida)
  - MobSF: mobile security framework (requires Docker)

PLATFORM NOTE: Frida requires native ARM64 compilation which fails
on Python 3.14. Objection depends on Frida. MobSF requires Docker.
Full mobile testing requires either:
  1. A rooted Android device with frida-server installed
  2. A Linux server running MobSF in Docker (Phase 12)

Current status: Architecture stub with correct interface.

Interface contract:
    MobileService().frida_inspect(package, user_id) -> dict
    MobileService().objection_explore(package, user_id) -> dict

Future FastAPI migration:
    POST /api/v1/scan/mobile/frida      {package: str}
    POST /api/v1/scan/mobile/objection  {package: str}
"""

import logging

from audit.audit_logger import log_operation
from services.base_service import BaseService

logger = logging.getLogger(__name__)

PLATFORM_NOTE = (
    "Mobile security tools (Frida/Objection/MobSF) require either a "
    "rooted Android device with frida-server, or a Linux server running "
    "MobSF in Docker. Full support planned for Phase 12 server deployment."
)


class MobileService(BaseService):
    service_name = "mobile_service"
    operation_type = "active_scan"
    requires_authorization = True

    async def frida_inspect(
        self, package: str, user_id: int | str = "system"
    ) -> dict:
        """
        Runs Frida dynamic instrumentation on a mobile app package.
        STUB: Requires rooted device with frida-server or Linux+Docker.
        """
        log_operation(
            operation_type="active_scan",
            tool_name="frida",
            target=package,
            user_id=user_id,
            result_summary="stub: platform_not_supported",
            duration_ms=0,
            success=False,
            metadata={"platform_note": PLATFORM_NOTE},
        )
        return self._err(
            f"Frida not available on current platform. {PLATFORM_NOTE}"
        )

    async def objection_explore(
        self, package: str, user_id: int | str = "system"
    ) -> dict:
        """
        Runs Objection runtime mobile exploration on a package.
        STUB: Requires Frida (see frida_inspect).
        """
        log_operation(
            operation_type="active_scan",
            tool_name="objection",
            target=package,
            user_id=user_id,
            result_summary="stub: platform_not_supported",
            duration_ms=0,
            success=False,
            metadata={"platform_note": PLATFORM_NOTE},
        )
        return self._err(
            f"Objection not available on current platform. {PLATFORM_NOTE}"
        )
