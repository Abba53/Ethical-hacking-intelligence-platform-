"""
services/active/webapp_service.py

Active web application security testing service.

Tools:
  - ffuf v2.1.0: fast web fuzzer for directory/endpoint discovery
  - SQLMap 1.10.7: SQL injection detection and exploitation

Classification: ACTIVE — sends HTTP requests to target URLs.
Requires explicit authorization before running.

Note: wfuzz is NOT supported on Python 3.14/ARM64 due to pycurl
compilation failures. ffuf covers the same use cases.

Interface contract:
    WebAppService().ffuf_scan(target, wordlist, user_id) -> dict
    WebAppService().sqli_scan(target_url, user_id) -> dict

Future FastAPI migration:
    POST /api/v1/scan/webapp/ffuf   {target: str, wordlist: str}
    POST /api/v1/scan/webapp/sqli   {target: str}
"""

import logging
import os

from audit.audit_logger import log_operation
from services.active.auth import is_authorized
from services.active.recon_service import _run_subprocess
from services.base_service import BaseService

logger = logging.getLogger(__name__)

FFUF_TIMEOUT = 120
SQLMAP_TIMEOUT = 180

# Default wordlist — Termux's common locations
DEFAULT_WORDLISTS = [
    "/data/data/com.termux/files/usr/share/wordlists/dirb/common.txt",
    "/data/data/com.termux/files/home/wordlists/common.txt",
    os.path.expanduser("~/wordlists/common.txt"),
]


def _find_wordlist(custom_path: str | None = None) -> str | None:
    """Returns the first available wordlist path."""
    candidates = ([custom_path] if custom_path else []) + DEFAULT_WORDLISTS
    for path in candidates:
        if path and os.path.isfile(path):
            return path
    return None


def _parse_ffuf_output(stdout: str) -> list[dict]:
    """Parses ffuf JSON output into structured results."""
    import json
    results = []
    try:
        data = json.loads(stdout)
        for r in data.get("results", []):
            results.append({
                "url": r.get("url", ""),
                "status": r.get("status", 0),
                "length": r.get("length", 0),
                "words": r.get("words", 0),
                "input": r.get("input", {}).get("FUZZ", ""),
            })
    except (json.JSONDecodeError, KeyError):
        pass
    return results


class WebAppService(BaseService):
    service_name = "webapp_service"
    operation_type = "active_scan"
    requires_authorization = True

    async def ffuf_scan(
        self,
        target: str,
        wordlist_path: str | None = None,
        user_id: int | str = "system",
    ) -> dict:
        """
        Runs ffuf directory/endpoint discovery against a target URL.

        Appends FUZZ to the target URL if not already present.
        Uses the first available wordlist from DEFAULT_WORDLISTS.
        """
        authorized, reason = is_authorized(int(user_id), target)
        if not authorized:
            log_operation(
                operation_type="active_scan",
                tool_name="ffuf",
                target=target,
                user_id=user_id,
                result_summary=f"DENIED: {reason}",
                duration_ms=0,
                success=False,
            )
            return self._err(f"Authorization denied: {reason}")

        wordlist = _find_wordlist(wordlist_path)
        if not wordlist:
            return self._err(
                "No wordlist found. Install one at ~/wordlists/common.txt "
                "or provide a custom path."
            )

        fuzz_target = target if "FUZZ" in target else f"{target.rstrip('/')}/FUZZ"

        cmd = [
            "ffuf",
            "-u", fuzz_target,
            "-w", wordlist,
            "-o", "/dev/stdout",
            "-of", "json",
            "-mc", "200,201,204,301,302,307,401,403,405",
            "-t", "50",
            "-timeout", "10",
            "-silent",
        ]

        with self.audit_timer(target, user_id) as t:
            t.metadata["tool"] = "ffuf"
            returncode, stdout, stderr = await _run_subprocess(cmd, FFUF_TIMEOUT)

            if returncode not in (0, 1) and not stdout:
                t.result_summary = f"error: {stderr[:100]}"
                t.success = False
                return self._err(f"ffuf failed: {stderr[:200]}")

            results = _parse_ffuf_output(stdout)
            t.result_summary = f"found {len(results)} paths"
            t.metadata["path_count"] = len(results)

        return self._ok(
            {
                "target": target,
                "wordlist": wordlist,
                "results": results,
                "count": len(results),
            },
            summary=t.result_summary,
        )

    async def sqli_scan(
        self,
        target_url: str,
        user_id: int | str = "system",
    ) -> dict:
        """
        Runs SQLMap SQL injection detection against a target URL.

        Uses --batch (non-interactive), --level=1 (least intrusive),
        and --risk=1 (safest) for initial detection.

        IMPORTANT: target_url must include a testable parameter,
        e.g. http://target/page.php?id=1
        """
        authorized, reason = is_authorized(int(user_id), target_url)
        if not authorized:
            log_operation(
                operation_type="active_scan",
                tool_name="sqlmap",
                target=target_url,
                user_id=user_id,
                result_summary=f"DENIED: {reason}",
                duration_ms=0,
                success=False,
            )
            return self._err(f"Authorization denied: {reason}")

        cmd = [
            "sqlmap",
            "-u", target_url,
            "--batch",
            "--level=1",
            "--risk=1",
            "--output-dir=/tmp/sqlmap_output",
            "--forms",
            "--crawl=1",
        ]

        with self.audit_timer(target_url, user_id) as t:
            t.metadata["tool"] = "sqlmap"
            returncode, stdout, stderr = await _run_subprocess(cmd, SQLMAP_TIMEOUT)

            if returncode not in (0, 1) and not stdout:
                t.result_summary = f"error: {stderr[:100]}"
                t.success = False
                return self._err(f"sqlmap failed: {stderr[:200]}")

            vulnerable = "injectable" in stdout.lower() or "sql injection" in stdout.lower()
            t.result_summary = f"vulnerable={vulnerable}"
            t.metadata["vulnerable"] = vulnerable

        return self._ok(
            {
                "target": target_url,
                "vulnerable": vulnerable,
                "output_summary": stdout[-1000:] if stdout else "",
            },
            summary=t.result_summary,
        )
