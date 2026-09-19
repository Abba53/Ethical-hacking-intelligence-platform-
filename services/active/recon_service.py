"""
services/active/recon_service.py

Active reconnaissance service — subdomain discovery and enumeration.

Tools:
  - Subfinder v2.14.0: fast passive subdomain discovery via APIs/sources
  - Amass v4.2.0: deep subdomain enumeration with DNS brute-forcing

Classification: ACTIVE — sends DNS queries and API requests targeting
the specified domain. Requires explicit authorization before running.

Authorization: two-layer check (user + target) via services/active/auth.py
Every invocation is audit-logged regardless of authorization outcome.

Interface contract:
    ReconService().subfinder(domain, user_id) -> dict
    ReconService().amass(domain, user_id) -> dict
    ReconService().full_recon(domain, user_id) -> dict

Future FastAPI migration:
    POST /api/v1/scan/recon/subfinder  {target: str}
    POST /api/v1/scan/recon/amass      {target: str}
    POST /api/v1/scan/recon/full       {target: str}
"""
import asyncio
import logging

from audit.audit_logger import log_operation
from services.active.auth import is_authorized
from services.base_service import BaseService
from services.subprocess_runner import run_subprocess

logger = logging.getLogger(__name__)

# Timeouts for subprocess calls (seconds)
SUBFINDER_TIMEOUT = 60
AMASS_TIMEOUT = 180  # Amass is slower — deep DNS enumeration




class ReconService(BaseService):
    service_name = "recon_service"
    operation_type = "active_scan"
    requires_authorization = True

    async def subfinder(
        self, domain: str, user_id: int | str = "system"
    ) -> dict:
        """
        Runs Subfinder passive subdomain discovery against a domain.

        Subfinder queries certificate transparency logs, DNS aggregators,
        and other passive sources — it does NOT brute-force DNS directly,
        making it lower-risk than Amass for most authorization contexts.
        """
        # Authorization check — first, before anything else
        authorized, reason = is_authorized(int(user_id), domain)
        if not authorized:
            log_operation(
                operation_type="active_scan",
                tool_name="subfinder",
                target=domain,
                user_id=user_id,
                result_summary=f"DENIED: {reason}",
                duration_ms=0,
                success=False,
            )
            return self._err(f"Authorization denied: {reason}")

        with self.audit_timer(domain, user_id) as t:
            t.metadata["tool"] = "subfinder"

            cmd = [
                "subfinder",
                "-d", domain,
                "-silent",
                "-o", "/dev/stdout",
            ]

            returncode, stdout, stderr = await run_subprocess(
                cmd, SUBFINDER_TIMEOUT
            )

            if returncode == -2:
                t.result_summary = f"timeout after {SUBFINDER_TIMEOUT}s"
                t.success = False
                return self._err(
                    f"subfinder timed out after {SUBFINDER_TIMEOUT}s"
                )

            if returncode == -1:
                t.result_summary = f"execution error: {stderr[:100]}"
                t.success = False
                return self._err(
                    f"subfinder execution failed: {stderr[:200]}"
                )

            if returncode != 0 and not stdout:
                t.result_summary = f"error: {stderr[:100]}"
                t.success = False
                return self._err(f"subfinder failed: {stderr[:200]}")

            subdomains = sorted(set(
                s.strip() for s in stdout.splitlines()
                if s.strip() and "." in s
            ))

            t.result_summary = f"found {len(subdomains)} subdomains"
            t.metadata["subdomain_count"] = len(subdomains)

        return self._ok(
            {
                "domain": domain,
                "tool": "subfinder",
                "subdomains": subdomains,
                "count": len(subdomains),
            },
            summary=t.result_summary,
        )

    async def amass(
        self, domain: str, user_id: int | str = "system"
    ) -> dict:
        """
        Runs Amass subdomain enumeration against a domain.

        Amass is more thorough than Subfinder but slower — it performs
        active DNS resolution and brute-forcing in addition to passive
        source queries. Use when deeper coverage is needed.
        """
        authorized, reason = is_authorized(int(user_id), domain)
        if not authorized:
            log_operation(
                operation_type="active_scan",
                tool_name="amass",
                target=domain,
                user_id=user_id,
                result_summary=f"DENIED: {reason}",
                duration_ms=0,
                success=False,
            )
            return self._err(f"Authorization denied: {reason}")

        with self.audit_timer(domain, user_id) as t:
            t.metadata["tool"] = "amass"

            cmd = [
                "amass", "enum",
                "-passive",
                "-d", domain,
                "-o", "/dev/stdout",
            ]

            returncode, stdout, stderr = await run_subprocess(
                cmd, AMASS_TIMEOUT
            )

            if returncode == -2:
                t.result_summary = f"timeout after {AMASS_TIMEOUT}s"
                t.success = False
                return self._err(
                    f"amass timed out after {AMASS_TIMEOUT}s"
                )

            if returncode == -1:
                t.result_summary = f"execution error: {stderr[:100]}"
                t.success = False
                return self._err(
                    f"amass execution failed: {stderr[:200]}"
                )

            if returncode != 0 and not stdout:
                t.result_summary = f"error: {stderr[:100]}"
                t.success = False
                return self._err(f"amass failed: {stderr[:200]}")

            subdomains = [
                s.strip() for s in stdout.splitlines()
                if s.strip() and "." in s
            ]

            t.result_summary = f"found {len(subdomains)} subdomains"
            t.metadata["subdomain_count"] = len(subdomains)

        return self._ok(
            {
                "domain": domain,
                "tool": "amass",
                "subdomains": subdomains,
                "count": len(subdomains),
            },
            summary=t.result_summary,
        )

    async def full_recon(
        self, domain: str, user_id: int | str = "system"
    ) -> dict:
        """
        Runs both Subfinder and Amass, merges and deduplicates results.

        Subfinder runs first (faster) to give early results while
        Amass completes its deeper enumeration.
        """
        authorized, reason = is_authorized(int(user_id), domain)
        if not authorized:
            log_operation(
                operation_type="active_scan",
                tool_name="full_recon",
                target=domain,
                user_id=user_id,
                result_summary=f"DENIED: {reason}",
                duration_ms=0,
                success=False,
            )
            return self._err(f"Authorization denied: {reason}")

        with self.audit_timer(domain, user_id) as t:
            t.metadata["tool"] = "subfinder+amass"

            sf_result, am_result = await asyncio.gather(
                self.subfinder(domain, user_id),
                self.amass(domain, user_id),
            )

            sf_subs = set(
                sf_result.get("data", {}).get("subdomains", [])
                if sf_result["success"] else []
            )
            am_subs = set(
                am_result.get("data", {}).get("subdomains", [])
                if am_result["success"] else []
            )

            all_subs = sorted(sf_subs | am_subs)

            # Both tools failing (timeout, execution error, etc.) is a
            # genuine failure of full_recon itself — previously this was
            # silently reported as success with an empty, misleadingly
            # "clean" result, indistinguishable from a real zero-subdomain
            # finding. Only report success when at least one tool
            # actually produced a real result.
            if not sf_result["success"] and not am_result["success"]:
                t.result_summary = (
                    f"both tools failed: subfinder={sf_result['error']} "
                    f"amass={am_result['error']}"
                )
                t.success = False
                return self._err(
                    f"full_recon failed: subfinder error: {sf_result['error']}; "
                    f"amass error: {am_result['error']}"
                )

            t.result_summary = (
                f"subfinder={len(sf_subs)} amass={len(am_subs)} "
                f"unique={len(all_subs)}"
            )
            t.metadata.update({
                "subfinder_count": len(sf_subs),
                "amass_count": len(am_subs),
                "unique_count": len(all_subs),
            })

        return self._ok(
            {
                "domain": domain,
                "subdomains": all_subs,
                "count": len(all_subs),
                "subfinder_count": len(sf_subs),
                "amass_count": len(am_subs),
            },
            summary=t.result_summary,
        )    
