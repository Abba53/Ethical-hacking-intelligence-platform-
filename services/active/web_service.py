"""
services/active/web_service.py

Active web security scanning service using Nuclei.
Requires explicit authorization before running.
"""

import json
import logging
import os

def _nuclei_templates_path() -> str:
    """Returns the path to the nuclei-templates directory."""
    home = os.path.expanduser("~")
    return f"{home}/nuclei-templates"

from audit.audit_logger import log_operation
from services.active.auth import is_authorized
from services.active.recon_service import _run_subprocess
from services.base_service import BaseService

logger = logging.getLogger(__name__)

NUCLEI_SAFE_TIMEOUT = 120
NUCLEI_STANDARD_TIMEOUT = 300
NUCLEI_FULL_TIMEOUT = 600


def _parse_nuclei_output(stdout: str) -> list[dict]:
    findings = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            finding = json.loads(line)
            findings.append({
                "template_id": finding.get("template-id", ""),
                "name": finding.get("info", {}).get("name", ""),
                "severity": finding.get("info", {}).get("severity", ""),
                "host": finding.get("host", ""),
                "matched_at": finding.get("matched-at", ""),
                "description": finding.get("info", {}).get("description", "")[:200],
            })
        except (json.JSONDecodeError, KeyError):
            continue
    return findings


class WebService(BaseService):
    service_name = "web_service"
    operation_type = "active_scan"
    requires_authorization = True

    async def nuclei_scan(
        self,
        target: str,
        profile: str = "safe",
        user_id: int | str = "system",
    ) -> dict:
        authorized, reason = is_authorized(int(user_id), target)
        if not authorized:
            log_operation(
                operation_type="active_scan",
                tool_name="nuclei",
                target=target,
                user_id=user_id,
                result_summary=f"DENIED: {reason}",
                duration_ms=0,
                success=False,
            )
            return self._err(f"Authorization denied: {reason}")

        if profile == "safe":
            severity = "info,low"
            timeout = NUCLEI_SAFE_TIMEOUT
        elif profile == "standard":
            severity = "low,medium,high"
            timeout = NUCLEI_STANDARD_TIMEOUT
        elif profile == "full":
            severity = "info,low,medium,high,critical"
            timeout = NUCLEI_FULL_TIMEOUT
        else:
            return self._err(f"Unknown profile: {profile}")

       # Use focused template directories rather than full 13k+ template
        # library — running all templates over mobile network always times out.
        # ssl/ + http/misconfiguration/ covers the most security-relevant checks.
        template_dirs = [
            f"{_nuclei_templates_path()}/ssl",
            f"{_nuclei_templates_path()}/http/misconfiguration",
        ]
        cmd = [
            "nuclei",
            "-u", target,
            "-severity", severity,
            "-jsonl",
            "-silent",
            "-no-interactsh",
        ]
        for tdir in template_dirs:
            cmd += ["-t", tdir]

        with self.audit_timer(target, user_id) as t:
            t.metadata["profile"] = profile
            returncode, stdout, stderr = await _run_subprocess(cmd, timeout)

            if returncode not in (0, 1) and not stdout:
                t.result_summary = f"error: {stderr[:100]}"
                t.success = False
                return self._err(f"nuclei failed: {stderr[:200]}")

            findings = _parse_nuclei_output(stdout)
            by_severity: dict[str, int] = {}
            for f in findings:
                sev = f["severity"]
                by_severity[sev] = by_severity.get(sev, 0) + 1

            t.result_summary = (
                f"profile={profile} findings={len(findings)} "
                f"by_severity={by_severity}"
            )
            t.metadata.update({
                "finding_count": len(findings),
                "by_severity": by_severity,
            })

        return self._ok(
            {
                "target": target,
                "profile": profile,
                "findings": findings,
                "count": len(findings),
                "by_severity": by_severity,
            },
            summary=t.result_summary,
        )

    async def header_check(
        self, target: str, user_id: int | str = "system"
    ) -> dict:
        authorized, reason = is_authorized(int(user_id), target)
        if not authorized:
            log_operation(
                operation_type="active_scan",
                tool_name="nuclei_headers",
                target=target,
                user_id=user_id,
                result_summary=f"DENIED: {reason}",
                duration_ms=0,
                success=False,
            )
            return self._err(f"Authorization denied: {reason}")

        cmd = [
            "nuclei",
            "-u", target,
            "-t", f"{_nuclei_templates_path()}/ssl",
            "-t", f"{_nuclei_templates_path()}/http/misconfiguration",
            "-tags", "headers,misconfig",
            "-severity", "info,low,medium",
            "-jsonl",
            "-silent",
            "-no-interactsh",
        ]

        with self.audit_timer(target, user_id) as t:
            t.metadata["check_type"] = "headers"
            returncode, stdout, stderr = await _run_subprocess(
                cmd, NUCLEI_SAFE_TIMEOUT
            )

            if returncode not in (0, 1) and not stdout:
                t.result_summary = f"error: {stderr[:100]}"
                t.success = False
                return self._err(f"nuclei header check failed: {stderr[:200]}")

            findings = _parse_nuclei_output(stdout)
            missing_headers = [
                f["name"] for f in findings
                if any(kw in f["name"].lower() for kw in ["header", "hsts", "csp"])
            ]

            t.result_summary = f"findings={len(findings)}"
            t.metadata["finding_count"] = len(findings)

        return self._ok(
            {
                "target": target,
                "findings": findings,
                "count": len(findings),
                "missing_headers": missing_headers,
            },
            summary=t.result_summary,
        )
