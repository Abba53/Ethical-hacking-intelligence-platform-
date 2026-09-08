"""
api/routers/scans.py

Phase 12.9 — Active scanning endpoints.

CONFIRMED authorization model (services/active/auth.py, read in full):
is_authorized(user_id, target) — two-layer check (user in
AUTHORIZED_SCAN_USERS env set, target in runtime AUTHORIZED_SCAN_TARGETS)
— runs INSIDE each real service method below, NOT in this router. A
denied request still returns HTTP 200 with success=False and the real
denial message — that is a legitimate completed outcome, not an API error.

No run_in_threadpool anywhere here: ReconWorkflow, WebAppService,
NetworkScanService, and WebService methods are all genuinely async
(they await asyncio subprocess calls internally, confirmed by reading
recon_service.py's _run_subprocess) — no sync/blocking bridge needed.

Security model
---------------
1. POST /scans requires the regular API key (require_api_key), applied
   directly on that route only — NOT at the router level, because
   /authorize and /deauthorize below require the SEPARATE admin key
   pool instead. Stacking both dependencies on every route (an earlier,
   real bug caught during testing) would make /authorize impossible to
   satisfy, since a valid admin key is not also a valid regular key.
2. /authorize and /deauthorize require ONLY the admin key.
3. RECON and WEBAPP_SCAN actions are explicitly allowlisted via dict
   dispatch (no getattr() on API-supplied strings).
4. NETWORK_SCAN profiles and WEB_SCAN nuclei profiles are validated as
   non-empty strings here, then passed to the already-reviewed real
   service (NetworkScanService.scan() / WebService.nuclei_scan()),
   which validates the specific profile value itself and returns a
   clear error for anything unrecognized — delegated, not unvalidated.
5. Client-supplied wordlist_path values are rejected outright (path
   traversal / arbitrary file read prevention). Only a logical
   `wordlist` NAME may be supplied, resolved against a server-side
   allowlist (WORDLISTS). If no name is given, wordlist_path=None is
   passed through, letting WebAppService's own DEFAULT_WORDLISTS
   fallback apply (confirmed real behavior).
6. Concurrent scan execution is capped via an in-process semaphore to
   protect host resources. NOTE: this limit is per-process — if this
   API ever runs multiple Uvicorn workers, each has its own separate
   counter, so the true system-wide cap would be higher than
   MAX_CONCURRENT_SCANS. Fine for a single-process deployment; revisit
   with a shared store if that ever changes.
7. Unexpected internal exceptions are logged with full detail
   server-side and converted to a generic HTTP 500 — never leaking
   internals to the client.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, status

from api.schemas.scan import (
    AuthorizeTargetRequest,
    AuthorizeTargetResponse,
    ScanRequest,
    ScanResultOut,
    ScanType,
)
from api.security import require_admin_key, require_api_key

logger = logging.getLogger(__name__)

# No router-level `dependencies=` here — see security model note #1 above.
router = APIRouter(prefix="/api/v1/scans", tags=["scans"] )


# ---------------------------------------------------------------------------
# Concurrency control — protects host resources from unlimited parallel scans
# ---------------------------------------------------------------------------

MAX_CONCURRENT_SCANS = 3
_scan_semaphore = asyncio.Semaphore(MAX_CONCURRENT_SCANS)


# ---------------------------------------------------------------------------
# Allowed actions — RECON and WEBAPP_SCAN are explicitly allowlisted here.
# NETWORK_SCAN/WEB_SCAN nuclei profiles are validated as non-empty strings
# only; the real service validates the specific value (see module docstring).
# ---------------------------------------------------------------------------

RECON_ACTIONS = frozenset({"subfinder", "amass", "full_recon"})
WEBAPP_ACTIONS = frozenset({"ffuf_scan", "sqli_scan"})

ACTIONS_BY_SCAN_TYPE: dict[ScanType, frozenset[str] | None] = {
    ScanType.RECON: RECON_ACTIONS,
    ScanType.WEBAPP_SCAN: WEBAPP_ACTIONS,
    ScanType.NETWORK_SCAN: None,  # delegated to NetworkScanService.scan()
    ScanType.WEB_SCAN: None,      # delegated to WebService.nuclei_scan() / header_check
}


# ---------------------------------------------------------------------------
# Server-side wordlist allowlist. Currently empty: the two conventional
# paths were checked directly against this device and neither exists
# (confirmed via `ls`). Add real, confirmed-existing paths here as they
# become available. Until then, ffuf_scan falls back to its own
# DEFAULT_WORDLISTS (see services/active/webapp_service.py).
# ---------------------------------------------------------------------------

WORDLISTS: dict[str, str] = {}


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

def _validate_target(target: str) -> str:
    target = target.strip()

    if not target:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Target cannot be empty.")

    if len(target) > 2048:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Target is too long.")

    if any(ch in target for ch in ("\x00", "\r", "\n")):
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY, "Target contains invalid control characters."
        )

    if "://" in target:
        parsed = urlparse(target)
        if parsed.scheme.lower() not in {"http", "https"}:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY, "Only HTTP and HTTPS targets are supported."
            )
        if not parsed.netloc:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Invalid target URL.")

    return target


def _validate_action(scan_type: ScanType, action: str) -> str:
    action = action.strip()
    if not action:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Scan action is required.")

    allowed = ACTIONS_BY_SCAN_TYPE[scan_type]
    if allowed is not None and action not in allowed:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"Unsupported action {action!r} for scan_type={scan_type.value!r}. "
            f"Allowed: {sorted(allowed)}",
        )
    return action


def _get_wordlist_path(options: dict[str, Any]) -> str | None:
    """
    Never accepts a client-supplied filesystem path directly — only a
    logical name resolved against the server-side WORDLISTS allowlist.
    Returns None (not an error) when no name is given, letting
    WebAppService's own fallback logic apply.
    """
    if not options:
        return None

    if "wordlist_path" in options:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "Arbitrary wordlist_path values are not permitted. Use a configured wordlist name "
            "via the 'wordlist' option instead.",
        )

    name = options.get("wordlist")
    if name is None:
        return None
    if not isinstance(name, str):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "wordlist must be a string.")

    name = name.strip().lower()
    if name not in WORDLISTS:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"Unsupported wordlist {name!r}. Available: {sorted(WORDLISTS)}",
        )
    return WORDLISTS[name]


def _normalize_workflow_result(result: Any) -> dict[str, Any]:
    """Converts a WorkflowResult (workflows/base_workflow.py) into the same
    plain-dict shape the *Service classes already return directly."""
    errors = getattr(result, "errors", None)
    return {
        "success": bool(getattr(result, "success", False)),
        "data": getattr(result, "data", None),
        "error": str(errors[0]) if errors else None,
        "summary": getattr(result, "message", None),
    }


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------

async def _dispatch(payload: ScanRequest) -> dict[str, Any]:
    target = _validate_target(payload.target)
    action = _validate_action(payload.scan_type, payload.action)
    user_id = payload.user_id
    options = payload.options or {}

    if payload.scan_type == ScanType.RECON:
        from workflows.recon_workflow import ReconWorkflow

        workflow = ReconWorkflow()
        # Explicit dict dispatch — no getattr() on an API-supplied string.
        recon_methods = {
            "subfinder": workflow.subfinder,
            "amass": workflow.amass,
            "full_recon": workflow.full_recon,
        }
        result = await recon_methods[action](target, user_id)
        return _normalize_workflow_result(result)

    if payload.scan_type == ScanType.WEBAPP_SCAN:
        from services.active.webapp_service import WebAppService

        svc = WebAppService()
        if action == "ffuf_scan":
            wordlist_path = _get_wordlist_path(options)
            return await svc.ffuf_scan(target, wordlist_path=wordlist_path, user_id=user_id)
        return await svc.sqli_scan(target, user_id)  # action == "sqli_scan"

    if payload.scan_type == ScanType.NETWORK_SCAN:
        from services.active.network_scan_service import NetworkScanService

        svc = NetworkScanService()
        return await svc.scan(target, profile=action, user_id=user_id)

    if payload.scan_type == ScanType.WEB_SCAN:
        from services.active.web_service import WebService

        svc = WebService()
        if action == "header_check":
            return await svc.header_check(target, user_id=user_id)
        return await svc.nuclei_scan(target, profile=action, user_id=user_id)

    raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Unhandled scan_type {payload.scan_type!r}")


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.post(
    "",
    response_model=ScanResultOut,
    dependencies=[Depends(require_api_key)],  # regular key ONLY — see security model #1
)
async def submit_scan(payload: ScanRequest):
    """
    Runs a REAL active scan against a target. is_authorized() inside the
    real service decides whether it actually executes — a denial is a
    normal 200 response with success=False, not an HTTP error.
    """
    try:
        async with _scan_semaphore:
            result = await _dispatch(payload)
    except HTTPException:
        raise
    except asyncio.CancelledError:
        logger.warning(
            "Scan request cancelled: scan_type=%s action=%s", payload.scan_type, payload.action
        )
        raise
    except Exception:
        logger.exception(
            "Unexpected scan error: scan_type=%s action=%s target=%s",
            payload.scan_type, payload.action, payload.target,
        )
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Internal scan service error.")

    return ScanResultOut(
        success=bool(result.get("success", False)),
        target=payload.target,
        scan_type=payload.scan_type,
        action=payload.action,
        data=result.get("data"),
        error=result.get("error"),
        summary=result.get("summary"),
    )


@router.post(
    "/authorize",
    response_model=AuthorizeTargetResponse,
    dependencies=[Depends(require_admin_key)],  # admin key ONLY
)
async def authorize(payload: AuthorizeTargetRequest):
    """Maps directly to services.active.auth.authorize_target(target, authorized_by)."""
    from services.active.auth import authorize_target

    target = _validate_target(payload.target)
    was_new = authorize_target(target, payload.authorized_by)
    return AuthorizeTargetResponse(
        target=target,
        was_new=was_new,
        message="Target authorized." if was_new else "Target was already authorized.",
    )


@router.post(
    "/deauthorize",
    response_model=AuthorizeTargetResponse,
    dependencies=[Depends(require_admin_key)],  # admin key ONLY
)
async def deauthorize(payload: AuthorizeTargetRequest):
    """Maps directly to services.active.auth.deauthorize_target(target, authorized_by)."""
    from services.active.auth import deauthorize_target

    target = _validate_target(payload.target)
    was_present = deauthorize_target(target, payload.authorized_by)
    return AuthorizeTargetResponse(
        target=target,
        was_new=was_present,
        message="Target deauthorized." if was_present else "Target was not authorized.",
    )
