"""
api/routers/lookups.py

Phase 12 — Passive lookup endpoints.

CONFIRMED (services/passive/{ioc,network,blockchain}_service.py, read in
full): every real service class sets requires_authorization = False —
no is_authorized() check exists anywhere in this code path, matching
Section 22 of the platform spec (passive lookups never touch a target
actively, so no authorization boundary applies). Only the regular API
key is required here — no admin tier, unlike /api/v1/scans.

IOCService.detect_type() is the one confirmed exception to the uniform
{success, data, error, ...} envelope: it is SYNCHRONOUS and returns a
bare string. Handled explicitly below, not forced into a shape it
doesn't have.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status

from api.schemas.lookup import LookupRequest, LookupResultOut, LookupService
from api.security import require_api_key

router = APIRouter(
    prefix="/api/v1/lookups",
    tags=["lookups"],
    dependencies=[Depends(require_api_key)],
)


async def _dispatch(payload: LookupRequest) -> dict[str, Any]:
    target, action, user_id, options = (
        payload.target, payload.action, payload.user_id, payload.options,
    )

    if payload.service == LookupService.IOC:
        from services.passive.ioc_service import IOCService

        svc = IOCService()
        if action == "lookup":
            return await svc.lookup(target, user_id)
        if action == "detect_type":
            # Confirmed exception: sync, no envelope, no audit logging.
            ioc_type = svc.detect_type(target)
            return {"success": True, "data": {"ioc_type": ioc_type}, "error": None, "summary": ioc_type}

    if payload.service == LookupService.NETWORK:
        from services.passive.network_service import NetworkService

        svc = NetworkService()
        if action == "investigate":
            return await svc.investigate(target, user_id)
        if action == "ip_geo":
            return await svc.ip_geo(target, user_id)
        if action == "ip_reputation":
            return await svc.ip_reputation(target, user_id)
        if action == "virustotal":
            # options["ioc_type"] presence already enforced by the schema's
            # model_validator — safe to read directly here.
            return await svc.virustotal(target, options["ioc_type"], user_id)

    if payload.service == LookupService.BLOCKCHAIN:
        from services.passive.blockchain_service import BlockchainService

        svc = BlockchainService()
        if action == "investigate":
            return await svc.investigate(target, user_id)
        if action == "evm":
            return await svc.evm(target, user_id)
        if action == "solana":
            return await svc.solana(target, user_id)

    raise HTTPException(
        status.HTTP_400_BAD_REQUEST,
        f"Unhandled service/action combination: {payload.service.value}/{action}",
    )


@router.post("", response_model=LookupResultOut)
async def submit_lookup(payload: LookupRequest):
    """
    Runs a REAL passive lookup (local DB + Chainabuse for IOC; IP geo/
    AbuseIPDB/VirusTotal for network; Ethplorer/Helius for blockchain).
    No authorization boundary applies — every real service class sets
    requires_authorization = False.
    """
    try:
        result = await _dispatch(payload)
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR, "Internal lookup service error."
        )

    return LookupResultOut(
        success=bool(result.get("success", False)),
        target=payload.target,
        service=payload.service,
        action=payload.action,
        data=result.get("data"),
        error=result.get("error"),
        summary=result.get("summary"),
    )
