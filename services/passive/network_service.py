"""
services/passive/network_service.py

Passive network intelligence service.

Wraps tools/network_security.py with:
- Standardized audit logging via BaseService.audit_timer()
- Standard result envelope (_ok / _err)
- Clear passive classification (no active scanning, no target modification)

Interface contract (for future FastAPI migration):
    NetworkService().investigate(value, user_id) -> dict
    NetworkService().ip_geo(ip, user_id) -> dict
    NetworkService().ip_reputation(ip, user_id) -> dict
    NetworkService().virustotal(value, ioc_type, user_id) -> dict

Each method is independently callable — bot.py and future API routes
can call individual methods rather than always running the full stack.
"""

from services.base_service import BaseService
from tools.network_security import (
    get_abuseipdb_report,
    get_ip_geo,
    get_virustotal_report,
    investigate_network,
)


class NetworkService(BaseService):
    service_name = "network_service"
    operation_type = "passive_lookup"
    requires_authorization = False

    async def investigate(self, value: str, user_id: int | str = "system") -> dict:
        """
        Full network investigation: geo + reputation + VirusTotal.
        Wraps investigate_network() with audit logging and result envelope.
        """
        with self.audit_timer(value, user_id) as t:
            raw = await investigate_network(value)

            if "error" in raw:
                t.result_summary = f"error: {raw['error']}"
                t.success = False
                return self._err(raw["error"])

            ioc_type = raw.get("ioc_type", "unknown")
            vt = raw.get("virustotal", {})
            abuse = raw.get("abuseipdb", {})

            mal = vt.get("malicious", 0)
            score = abuse.get("abuse_confidence_score", 0)

            t.result_summary = (
                f"type={ioc_type} vt_malicious={mal} abuse_score={score}"
            )
            t.metadata = {
                "ioc_type": ioc_type,
                "vt_malicious": mal,
                "abuse_score": score,
            }

        return self._ok(raw, summary=t.result_summary)

    async def ip_geo(self, ip: str, user_id: int | str = "system") -> dict:
        """Geolocation and hosting context for a single IP."""
        with self.audit_timer(ip, user_id) as t:
            raw = await get_ip_geo(ip)
            if "error" in raw:
                t.result_summary = f"error: {raw['error']}"
                t.success = False
                return self._err(raw["error"])
            t.result_summary = f"{raw.get('country_code')} | {raw.get('isp')}"
            t.metadata = {"country": raw.get("country"), "isp": raw.get("isp")}
        return self._ok(raw, summary=t.result_summary)

    async def ip_reputation(self, ip: str, user_id: int | str = "system") -> dict:
        """AbuseIPDB reputation check for a single IP."""
        with self.audit_timer(ip, user_id) as t:
            raw = await get_abuseipdb_report(ip)
            if "error" in raw:
                t.result_summary = f"error: {raw['error']}"
                t.success = False
                return self._err(raw["error"])
            score = raw.get("abuse_confidence_score", 0)
            t.result_summary = f"score={score}%"
            t.metadata = {
                "abuse_confidence_score": score,
                "total_reports": raw.get("total_reports"),
            }
        return self._ok(raw, summary=t.result_summary)

    async def virustotal(
        self, value: str, ioc_type: str, user_id: int | str = "system"
    ) -> dict:
        """VirusTotal multi-vendor check for IP or domain."""
        with self.audit_timer(value, user_id) as t:
            raw = await get_virustotal_report(value, ioc_type)
            if "error" in raw:
                t.result_summary = f"error: {raw['error']}"
                t.success = False
                return self._err(raw["error"])
            mal = raw.get("malicious", 0)
            t.result_summary = f"malicious={mal}"
            t.metadata = {
                "malicious": mal,
                "suspicious": raw.get("suspicious", 0),
                "harmless": raw.get("harmless", 0),
            }
        return self._ok(raw, summary=t.result_summary)
