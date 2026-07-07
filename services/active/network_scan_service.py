"""
services/active/network_scan_service.py

Active network scanning service using Nmap.

Tool: Nmap 7.99 (installed via pkg)
Classification: ACTIVE — sends TCP/UDP packets to target hosts.
Requires explicit authorization before running.

Scan profiles (from least to most intrusive):
  - 'quick': top 100 ports, no OS detection (-F)
  - 'standard': top 1000 ports, service version detection (-sV)
  - 'full': all 65535 ports (slow, use sparingly)

Authorization: two-layer check (user + target) enforced before any scan.
Every invocation is audit-logged regardless of authorization outcome.

Interface contract:
    NetworkScanService().scan(target, profile, user_id) -> dict
    NetworkScanService().quick_scan(target, user_id) -> dict
    NetworkScanService().service_scan(target, user_id) -> dict

Future FastAPI migration:
    POST /api/v1/scan/nmap  {target: str, profile: str}
"""

import logging
import re

from audit.audit_logger import log_operation
from services.active.auth import is_authorized
from services.active.recon_service import _run_subprocess
from services.base_service import BaseService

logger = logging.getLogger(__name__)

NMAP_QUICK_TIMEOUT = 60
NMAP_STANDARD_TIMEOUT = 120
NMAP_FULL_TIMEOUT = 600

# Safe output parser — extracts port/state/service from nmap text output
PORT_LINE_RE = re.compile(
    r"(\d+)/(tcp|udp)\s+(open|closed|filtered)\s+(\S+)"
)


def _parse_nmap_output(output: str) -> list[dict]:
    """
    Parses nmap's text output into structured port records.

    We use nmap's default text output rather than -oX (XML) because
    XML parsing introduces lxml/defusedxml dependencies. Text parsing
    with a strict regex is safer and simpler for our use case.
    """
    ports = []
    for line in output.splitlines():
        match = PORT_LINE_RE.search(line)
        if match:
            port, proto, state, service = match.groups()
            ports.append({
                "port": int(port),
                "protocol": proto,
                "state": state,
                "service": service,
            })
    return ports


class NetworkScanService(BaseService):
    service_name = "network_scan_service"
    operation_type = "active_scan"
    requires_authorization = True

    async def quick_scan(
        self, target: str, user_id: int | str = "system"
    ) -> dict:
        """
        Fast scan of top 100 ports. No service detection.
        Best for quick triage — is this host alive, what's open?
        """
        return await self.scan(target, profile="quick", user_id=user_id)

    async def service_scan(
        self, target: str, user_id: int | str = "system"
    ) -> dict:
        """
        Standard scan of top 1000 ports with service version detection.
        Identifies what software is running on open ports.
        """
        return await self.scan(target, profile="standard", user_id=user_id)

    async def scan(
        self,
        target: str,
        profile: str = "quick",
        user_id: int | str = "system",
    ) -> dict:
        """
        Runs an Nmap scan against a target with the specified profile.

        Profiles:
          quick    — top 100 ports, fast (-F -T4)
          standard — top 1000 ports + service versions (-sV -T4)
          full     — all 65535 ports (-p- -T4, very slow)
        """
        authorized, reason = is_authorized(int(user_id), target)
        if not authorized:
            log_operation(
                operation_type="active_scan",
                tool_name="nmap",
                target=target,
                user_id=user_id,
                result_summary=f"DENIED: {reason}",
                duration_ms=0,
                success=False,
            )
            return self._err(f"Authorization denied: {reason}")

        # Build nmap command based on profile
        if profile == "quick":
            cmd = ["nmap", "-F", "-T4", "--open", target]
            timeout = NMAP_QUICK_TIMEOUT
        elif profile == "standard":
            cmd = ["nmap", "-sV", "-T4", "--open", target]
            timeout = NMAP_STANDARD_TIMEOUT
        elif profile == "full":
            cmd = ["nmap", "-p-", "-T4", "--open", target]
            timeout = NMAP_FULL_TIMEOUT
        else:
            return self._err(f"Unknown scan profile: {profile}")

        with self.audit_timer(target, user_id) as t:
            t.metadata["profile"] = profile

            returncode, stdout, stderr = await _run_subprocess(cmd, timeout)

            if returncode != 0 and not stdout:
                t.result_summary = f"error: {stderr[:100]}"
                t.success = False
                return self._err(f"nmap failed: {stderr[:200]}")

            ports = _parse_nmap_output(stdout)
            open_ports = [p for p in ports if p["state"] == "open"]

            t.result_summary = (
                f"profile={profile} open_ports={len(open_ports)}"
            )
            t.metadata.update({
                "profile": profile,
                "open_ports": len(open_ports),
                "total_ports_seen": len(ports),
            })

        return self._ok(
            {
                "target": target,
                "profile": profile,
                "ports": ports,
                "open_count": len(open_ports),
                "raw_output": stdout[:2000],
            },
            summary=t.result_summary,
        )
