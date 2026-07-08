"""
services/active/cloud_service.py

Cloud infrastructure security assessment service.

Tools (planned):
  - ScoutSuite: multi-cloud security auditing (AWS/GCP/Azure)
  - Prowler: AWS security best practices assessment

PLATFORM NOTE: ScoutSuite and Prowler require grpcio which fails to
compile on ARM64/Android (Python 3.14). These tools are designed for
Linux servers. This service will be fully functional in Phase 12
when deployed to a Linux server environment.

Current status: Architecture stub with correct interface.
Credentials loaded from .env (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY,
AWS_DEFAULT_REGION, GCP_PROJECT_ID, AZURE_SUBSCRIPTION_ID).

Interface contract:
    CloudService().scout_aws(user_id) -> dict
    CloudService().prowler_aws(user_id) -> dict

Future FastAPI migration:
    POST /api/v1/scan/cloud/scout  {provider: str}
    POST /api/v1/scan/cloud/prowler {}
"""

import logging
import os

from dotenv import load_dotenv
from audit.audit_logger import log_operation
from services.active.auth import is_authorized
from services.base_service import BaseService

logger = logging.getLogger(__name__)
load_dotenv()

AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")
AWS_DEFAULT_REGION = os.getenv("AWS_DEFAULT_REGION", "us-east-1")
GCP_PROJECT_ID = os.getenv("GCP_PROJECT_ID")
AZURE_SUBSCRIPTION_ID = os.getenv("AZURE_SUBSCRIPTION_ID")

PLATFORM_NOTE = (
    "Cloud scanning tools (ScoutSuite/Prowler) require a Linux server "
    "environment. This service will be fully operational in Phase 12. "
    "Current platform: Termux/ARM64/Python 3.14 (grpcio incompatible)."
)


class CloudService(BaseService):
    service_name = "cloud_service"
    operation_type = "active_scan"
    requires_authorization = True

    def _check_aws_credentials(self) -> tuple[bool, str]:
        if not AWS_ACCESS_KEY_ID or not AWS_SECRET_ACCESS_KEY:
            return False, "AWS credentials not configured in .env"
        return True, "ok"

    async def scout_aws(self, user_id: int | str = "system") -> dict:
        """
        Runs ScoutSuite AWS security audit.
        STUB: Requires Linux server environment (Phase 12).
        """
        log_operation(
            operation_type="active_scan",
            tool_name="scoutsuite",
            target="aws",
            user_id=user_id,
            result_summary="stub: platform_not_supported",
            duration_ms=0,
            success=False,
            metadata={"platform_note": PLATFORM_NOTE},
        )
        return self._err(
            f"ScoutSuite not available on current platform. {PLATFORM_NOTE}"
        )

    async def prowler_aws(self, user_id: int | str = "system") -> dict:
        """
        Runs Prowler AWS security assessment.
        STUB: Requires Linux server environment (Phase 12).
        """
        log_operation(
            operation_type="active_scan",
            tool_name="prowler",
            target="aws",
            user_id=user_id,
            result_summary="stub: platform_not_supported",
            duration_ms=0,
            success=False,
            metadata={"platform_note": PLATFORM_NOTE},
        )
        return self._err(
            f"Prowler not available on current platform. {PLATFORM_NOTE}"
        )
