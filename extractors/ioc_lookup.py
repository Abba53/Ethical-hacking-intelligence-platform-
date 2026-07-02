"""
extractors/ioc_lookup.py

Universal IOC lookup: detects IOC type from a raw value string,
then queries local database and (for crypto addresses) live Chainabuse API.

Used by the /lookup bot command (Phase 9.1).
"""

import logging
import os

import httpx
from dotenv import load_dotenv

from database.db import get_session
from database.models import ExtractedIOC, ThreatFoxIOC
from extractors.ioc_extractor import (
    CVE_RE,
    DOMAIN_RE,
    ETH_RE,
    IPV4_RE,
    MD5_RE,
    SHA1_RE,
    SHA256_RE,
    SOL_RE,
    refang,
)

logger = logging.getLogger(__name__)
load_dotenv()

CHAINABUSE_API_KEY = os.getenv("CHAINABUSE_API_KEY")
CHAINABUSE_URL = "https://api.chainabuse.com/v0/reports"
REQUEST_TIMEOUT = 10


# ---------------------------------------------------------------------------
# IOC type detection
# ---------------------------------------------------------------------------

def detect_ioc_type(value: str) -> str:
    """
    Detects the IOC type of a raw string value.

    Returns one of: ipv4, domain, sha256, sha1, md5, cve,
    eth_address, sol_address, or 'unknown'.

    Order matters: more specific patterns are checked before
    broader ones (e.g. SHA256 before MD5 before domain).
    """
    value = value.strip()
    clean = refang(value)

    # Check most specific / least ambiguous first
    if ETH_RE.fullmatch(clean):
        return "eth_address"
    if SHA256_RE.fullmatch(clean):
        return "sha256"
    if SHA1_RE.fullmatch(clean):
        return "sha1"
    if MD5_RE.fullmatch(clean):
        return "md5"
    if CVE_RE.fullmatch(clean):
        return "cve"
    if IPV4_RE.fullmatch(clean):
        return "ipv4"
    if SOL_RE.fullmatch(clean):
        return "sol_address"
    if DOMAIN_RE.fullmatch(clean):
        return "domain"

    return "unknown"


# ---------------------------------------------------------------------------
# Local database lookup
# ---------------------------------------------------------------------------

def lookup_local(value: str, ioc_type: str) -> dict:
    """
    Queries local database for an IOC value.

    Checks both threatfox_iocs (directly collected IOCs) and
    extracted_iocs (IOCs extracted from RSS article text).

    Returns a dict with findings from both tables.
    """
    value = refang(value.strip())
    results = {
        "threatfox": [],
        "extracted": [],
    }

    with get_session() as session:
        # Check ThreatFox IOC table
        tf_matches = (
            session.query(ThreatFoxIOC)
            .filter(ThreatFoxIOC.ioc == value)
            .all()
        )
        for match in tf_matches:
            results["threatfox"].append({
                "ioc": match.ioc,
                "ioc_type": match.ioc_type,
                "threat_type": match.threat_type,
                "malware": match.malware,
                "confidence_level": match.confidence_level,
                "first_seen": match.first_seen,
            })

        # Check extracted IOCs table
        ex_matches = (
            session.query(ExtractedIOC)
            .filter(
                ExtractedIOC.value == value,
                ExtractedIOC.ioc_type == ioc_type,
            )
            .all()
        )
        for match in ex_matches:
            results["extracted"].append({
                "ioc_type": match.ioc_type,
                "value": match.value,
                "source_entry_id": match.source_entry_id,
                "extracted_at": str(match.extracted_at),
            })

    return results


# ---------------------------------------------------------------------------
# Live Chainabuse lookup (for crypto addresses only)
# ---------------------------------------------------------------------------

async def lookup_chainabuse(address: str) -> list[dict]:
    """
    Makes a live Chainabuse API call to check a crypto address.

    Only called for eth_address and sol_address types — not worth
    calling for IPs, domains, hashes etc. which Chainabuse doesn't cover.

    Returns list of report dicts (empty if clean/not reported).
    """
    if not CHAINABUSE_API_KEY:
        logger.warning("CHAINABUSE_API_KEY not set — skipping live lookup")
        return []

    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                CHAINABUSE_URL,
                params={"address": address},
                auth=(CHAINABUSE_API_KEY, CHAINABUSE_API_KEY),
                timeout=REQUEST_TIMEOUT,
            )
            response.raise_for_status()
            result = response.json()
    except (httpx.TimeoutException, httpx.HTTPStatusError,
            httpx.RequestError) as exc:
        logger.warning("Chainabuse lookup failed for %s: %s", address, exc)
        return []

    reports = result if isinstance(result, list) else result.get("reports", [])
    return [
        {
            "category": r.get("category", ""),
            "chain": r.get("chain", ""),
            "description": r.get("description", ""),
            "reported_at": r.get("createdAt", ""),
        }
        for r in reports
    ]


# ---------------------------------------------------------------------------
# Main lookup orchestrator
# ---------------------------------------------------------------------------

async def lookup_ioc(value: str) -> dict:
    """
    Full IOC lookup: detect type, query local DB, live check if crypto.

    Returns a structured dict with all findings, ready for bot formatting.
    """
    value = value.strip()
    ioc_type = detect_ioc_type(value)

    local = lookup_local(value, ioc_type)

    chainabuse = []
    if ioc_type in ("eth_address", "sol_address"):
        chainabuse = await lookup_chainabuse(value)

    return {
        "value": value,
        "ioc_type": ioc_type,
        "local": local,
        "chainabuse": chainabuse,
    }
