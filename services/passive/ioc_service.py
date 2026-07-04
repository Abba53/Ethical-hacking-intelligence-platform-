"""
services/passive/ioc_service.py

Passive IOC intelligence service.

Wraps extractors/ioc_lookup.py with audit logging and
standard result envelope.

Interface contract:
    IOCService().lookup(value, user_id) -> dict
    IOCService().detect_type(value) -> str
"""

from services.base_service import BaseService
from extractors.ioc_lookup import detect_ioc_type, lookup_ioc


class IOCService(BaseService):
    service_name = "ioc_service"
    operation_type = "passive_lookup"
    requires_authorization = False

    async def lookup(
        self, value: str, user_id: int | str = "system"
    ) -> dict:
        """
        Full IOC lookup: detect type, query local DB, live Chainabuse
        check for crypto addresses.
        """
        with self.audit_timer(value, user_id) as t:
            raw = await lookup_ioc(value)
            ioc_type = raw.get("ioc_type", "unknown")
            tf_hits = len(raw.get("local", {}).get("threatfox", []))
            ex_hits = len(raw.get("local", {}).get("extracted", []))
            ca_hits = len(raw.get("chainabuse", []))
            t.result_summary = (
                f"type={ioc_type} threatfox={tf_hits} "
                f"extracted={ex_hits} chainabuse={ca_hits}"
            )
            t.metadata = {
                "ioc_type": ioc_type,
                "threatfox_hits": tf_hits,
                "extracted_hits": ex_hits,
                "chainabuse_hits": ca_hits,
            }
        return self._ok(raw, summary=t.result_summary)

    def detect_type(self, value: str) -> str:
        """
        Synchronous IOC type detection — no external calls, no audit needed.
        Returns the IOC type string directly (not wrapped in envelope).
        """
        return detect_ioc_type(value)
