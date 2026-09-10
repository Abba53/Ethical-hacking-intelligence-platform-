"""
api/schemas/lookup.py

Phase 12 — Passive lookup endpoint shapes.

Confirmed against real source (services/passive/{ioc,network,blockchain}_service.py):
all methods share the BaseService {success, data, error, tool_name,
operation_type, summary} envelope EXCEPT IOCService.detect_type(), which
is synchronous and returns a bare string — handled as a deliberate,
documented special case below, not papered over.

No authorization boundary applies here (every real service class sets
requires_authorization = False) — this endpoint needs only the regular
API key, no admin tier, unlike /api/v1/scans.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field, model_validator


class LookupService(str, Enum):
    IOC = "ioc"
    NETWORK = "network"
    BLOCKCHAIN = "blockchain"


# Confirmed against real method names in each service class.
IOC_ACTIONS = {"lookup", "detect_type"}
NETWORK_ACTIONS = {"investigate", "ip_geo", "ip_reputation", "virustotal"}
BLOCKCHAIN_ACTIONS = {"investigate", "evm", "solana"}

ACTIONS_BY_SERVICE: dict[LookupService, set[str]] = {
    LookupService.IOC: IOC_ACTIONS,
    LookupService.NETWORK: NETWORK_ACTIONS,
    LookupService.BLOCKCHAIN: BLOCKCHAIN_ACTIONS,
}


class LookupRequest(BaseModel):
    target: str = Field(..., min_length=1, max_length=512)
    service: LookupService
    action: str
    user_id: int | str = Field(default="system")
    # Only used by service=network, action=virustotal, which requires an
    # extra ioc_type argument the other 8 methods don't take.
    options: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _validate_action(self) -> "LookupRequest":
        allowed = ACTIONS_BY_SERVICE[self.service]
        if self.action not in allowed:
            raise ValueError(
                f"action={self.action!r} is not valid for service={self.service.value!r}. "
                f"Valid actions: {sorted(allowed)}"
            )
        if self.service == LookupService.NETWORK and self.action == "virustotal":
            if "ioc_type" not in self.options:
                raise ValueError(
                    "options.ioc_type is required for service=network, action=virustotal "
                    "(matches NetworkService.virustotal()'s real signature)."
                )
        return self


class LookupResultOut(BaseModel):
    success: bool
    target: str
    service: LookupService
    action: str
    data: Optional[Any] = None
    error: Optional[str] = None
    summary: Optional[str] = None
