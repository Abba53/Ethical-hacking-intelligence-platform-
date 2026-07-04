"""
tools/network_security.py

Network security investigation tools for IP addresses and domains.

Sources:
  - ip-api.com: free geolocation + ASN + proxy/hosting detection (no key)
    Limit: 45 req/min, non-commercial use
  - AbuseIPDB: community IP abuse reputation score
    Limit: 1,000 req/day (free tier), requires ABUSEIPDB_API_KEY
  - VirusTotal: multi-vendor URL/domain/IP analysis
    Limit: 4 req/min, 500 req/day (free tier), requires VIRUSTOTAL_API_KEY

Used by the /netinfo bot command (Phase 9.3).

Security note: user-supplied values are validated via detect_ioc_type()
before being sent to external APIs — prevents SSRF-class misuse.
"""

import logging
import os

import httpx
from dotenv import load_dotenv

from extractors.ioc_lookup import detect_ioc_type

logger = logging.getLogger(__name__)
load_dotenv()

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

IPAPI_URL = "http://ip-api.com/json/{ip}"
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
VT_IP_URL = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"
VT_DOMAIN_URL = "https://www.virustotal.com/api/v3/domains/{domain}"

REQUEST_TIMEOUT = 15


# ---------------------------------------------------------------------------
# ip-api.com — geolocation and hosting context (no key required)
# ---------------------------------------------------------------------------

async def get_ip_geo(ip: str) -> dict:
    """
    Fetches IP geolocation, ISP, ASN, and proxy/hosting flags from ip-api.com.

    Returns clean dict or error. Free, no key, 45 req/min limit.
    Safe to call on every IP lookup as the primary enrichment layer.
    """
    url = IPAPI_URL.format(ip=ip)
    fields = (
        "status,message,country,countryCode,regionName,"
        "city,isp,org,as,proxy,hosting,query"
    )

    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                url,
                params={"fields": fields},
                timeout=REQUEST_TIMEOUT,
            )
            response.raise_for_status()
            data = response.json()
    except (httpx.TimeoutException, httpx.HTTPStatusError,
            httpx.RequestError) as exc:
        logger.warning("ip-api.com error for %s: %s", ip, exc)
        return {"error": str(exc)}

    if data.get("status") == "fail":
        return {"error": data.get("message", "ip-api failed")}

    return {
        "ip": ip,
        "country": data.get("country", ""),
        "country_code": data.get("countryCode", ""),
        "region": data.get("regionName", ""),
        "city": data.get("city", ""),
        "isp": data.get("isp", ""),
        "org": data.get("org", ""),
        "asn": data.get("as", ""),
        "is_proxy": data.get("proxy", False),
        "is_hosting": data.get("hosting", False),
    }


# ---------------------------------------------------------------------------
# AbuseIPDB — community abuse reputation score
# ---------------------------------------------------------------------------

async def get_abuseipdb_report(ip: str) -> dict:
    """
    Checks an IP address against AbuseIPDB's community report database.

    Returns abuse confidence score (0-100), report count, and last seen.
    Score > 25 warrants investigation; > 75 is strongly malicious.
    """
    if not ABUSEIPDB_API_KEY:
        logger.warning("ABUSEIPDB_API_KEY not set — skipping AbuseIPDB check")
        return {"error": "no_api_key"}

    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json",
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90,
        "verbose": "",
    }

    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                ABUSEIPDB_URL,
                headers=headers,
                params=params,
                timeout=REQUEST_TIMEOUT,
            )
            response.raise_for_status()
            data = response.json()
    except (httpx.TimeoutException, httpx.HTTPStatusError,
            httpx.RequestError) as exc:
        logger.warning("AbuseIPDB error for %s: %s", ip, exc)
        return {"error": str(exc)}

    report = data.get("data", {})
    return {
        "abuse_confidence_score": report.get("abuseConfidenceScore", 0),
        "total_reports": report.get("totalReports", 0),
        "last_reported_at": report.get("lastReportedAt", ""),
        "country_code": report.get("countryCode", ""),
        "isp": report.get("isp", ""),
        "usage_type": report.get("usageType", ""),
        "domain": report.get("domain", ""),
    }


# ---------------------------------------------------------------------------
# VirusTotal — multi-vendor reputation for IPs and domains
# ---------------------------------------------------------------------------

async def get_virustotal_report(value: str, ioc_type: str) -> dict:
    """
    Checks an IP or domain against VirusTotal's 70+ vendor database.

    Returns malicious/suspicious/clean vendor counts and categories.
    Free tier: 4 req/min, 500/day — use judiciously.
    """
    if not VIRUSTOTAL_API_KEY:
        logger.warning("VIRUSTOTAL_API_KEY not set — skipping VirusTotal check")
        return {"error": "no_api_key"}

    if ioc_type == "ipv4":
        url = VT_IP_URL.format(ip=value)
    elif ioc_type == "domain":
        url = VT_DOMAIN_URL.format(domain=value)
    else:
        return {"error": f"unsupported_type_{ioc_type}"}

    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                url,
                headers=headers,
                timeout=REQUEST_TIMEOUT,
            )
            response.raise_for_status()
            data = response.json()
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code == 404:
            return {"error": "not_found"}
        logger.warning("VirusTotal HTTP error for %s: %s", value, exc)
        return {"error": f"http_{exc.response.status_code}"}
    except (httpx.TimeoutException, httpx.RequestError) as exc:
        logger.warning("VirusTotal network error for %s: %s", value, exc)
        return {"error": str(exc)}

    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    categories = attrs.get("categories", {})

    return {
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "categories": list(set(categories.values()))[:3],
        "reputation": attrs.get("reputation", 0),
    }


# ---------------------------------------------------------------------------
# Unified entry point
# ---------------------------------------------------------------------------

async def investigate_network(value: str) -> dict:
    """
    Full network investigation for an IP or domain.

    Routes to appropriate sources based on detected IOC type.
    Validates type before hitting any external API (SSRF defense).
    """
    ioc_type = detect_ioc_type(value)

    if ioc_type not in ("ipv4", "domain"):
        return {
            "error": "unsupported_type",
            "ioc_type": ioc_type,
            "message": (
                f"'{ioc_type}' is not supported for network investigation. "
                "Provide an IPv4 address or domain name."
            ),
        }

    result = {
        "value": value,
        "ioc_type": ioc_type,
        "geo": {},
        "abuseipdb": {},
        "virustotal": {},
    }

    if ioc_type == "ipv4":
        result["geo"] = await get_ip_geo(value)
        result["abuseipdb"] = await get_abuseipdb_report(value)

    result["virustotal"] = await get_virustotal_report(value, ioc_type)

    return result
