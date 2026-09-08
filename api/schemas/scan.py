"""
api/schemas/scan.py

Phase 12.9 — Active scanning request/response shapes.

Every action set below is copied EXACTLY from real method
signatures/parameters read directly from:
    workflows/recon_workflow.py
    services/active/webapp_service.py
    services/active/network_scan_service.py
    services/active/web_service.py

user_id is required for every active scan type — it is NOT proof of
authorization itself. is_authorized(user_id, target) runs INSIDE the
real service methods (services/active/auth.py) and can still deny the
request; this schema only guarantees the request is well-formed enough
to reach that real check.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field, model_validator


class ScanType(str, Enum):
    RECON = "recon"
    NETWORK_SCAN = "network_scan"
    WEB_SCAN = "web_scan"
    WEBAPP_SCAN = "webapp_scan"


# Confirmed against workflows/recon_workflow.py
RECON_ACTIONS = {"subfinder", "amass", "full_recon"}

# Confirmed against services/active/network_scan_service.py's scan(profile=...)
NETWORK_SCAN_ACTIONS = {"quick", "standard", "full"}

# Confirmed against services/active/web_service.py:
# nuclei_scan(profile="safe"|"standard"|"full") PLUS a separate
# header_check(target, user_id) method with no profile parameter.
WEB_SCAN_ACTIONS = {"safe", "standard", "full", "header_check"}

# Confirmed against services/active/webapp_service.py
WEBAPP_ACTIONS = {"ffuf_scan", "sqli_scan"}

ACTIONS_BY_SCAN_TYPE: dict[ScanType, set[str]] = {
    ScanType.RECON: RECON_ACTIONS,
    ScanType.NETWORK_SCAN: NETWORK_SCAN_ACTIONS,
    ScanType.WEB_SCAN: WEB_SCAN_ACTIONS,
    ScanType.WEBAPP_SCAN: WEBAPP_ACTIONS,
}


class ScanRequest(BaseModel):
    target: str = Field(..., min_length=1, max_length=512)
    scan_type: ScanType
    action: str
    user_id: int = Field(
        ..., description="Telegram user ID checked by is_authorized() inside the real service."
    )
    options: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _validate_action(self) -> "ScanRequest":
        allowed = ACTIONS_BY_SCAN_TYPE[self.scan_type]
        if self.action not in allowed:
            raise ValueError(
                f"action={self.action!r} is not valid for scan_type="
                f"{self.scan_type.value!r}. Valid actions: {sorted(allowed)}"
            )
        return self


class ScanResultOut(BaseModel):
    success: bool
    target: str
    scan_type: ScanType
    action: str
    data: Optional[dict[str, Any]] = None
    error: Optional[str] = None
    summary: Optional[str] = None


class AuthorizeTargetRequest(BaseModel):
    target: str = Field(..., min_length=1, max_length=512)
    authorized_by: int


class AuthorizeTargetResponse(BaseModel):
    target: str
    was_new: bool
    message: str
