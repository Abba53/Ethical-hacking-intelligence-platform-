"""
collectors/threat_feed_collector.py

Fetches structured threat intelligence from two sources:
  - ThreatFox (abuse.ch): general malware/botnet IOCs (IPs, domains, hashes)
  - Chainabuse: reported malicious crypto addresses/URLs (Web3-focused)

Design notes:
- Same fetch/parse separation pattern as collectors/rss_collector.py.
- Both APIs return JSON directly — no XML/feedparser involved, and
  therefore no XXE-class concern here (JSON has no entity/DTD mechanism).
- Credentials are loaded from environment variables only; never hardcoded.
"""

import asyncio
import logging
import os

import httpx
from dotenv import load_dotenv

from sqlalchemy.exc import IntegrityError

from database.db import get_session
from database.models import ChainabuseReport, ThreatFoxIOC

logger = logging.getLogger(__name__)

load_dotenv()

THREATFOX_AUTH_KEY = os.getenv("THREATFOX_AUTH_KEY")
CHAINABUSE_API_KEY = os.getenv("CHAINABUSE_API_KEY")

THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"
CHAINABUSE_URL = "https://api.chainabuse.com/v0/reports"

REQUEST_TIMEOUT_SECONDS = 15


async def fetch_threatfox_iocs(client: httpx.AsyncClient, days: int = 1) -> list[dict]:
    """
    Fetches recent IOCs from ThreatFox.

    Returns a list of structured IOC dicts, or an empty list on failure.
    """
    if not THREATFOX_AUTH_KEY:
        logger.error("THREATFOX_AUTH_KEY is not set. Skipping ThreatFox fetch.")
        return []

    headers = {"Auth-Key": THREATFOX_AUTH_KEY}
    payload = {"query": "get_iocs", "days": days}

    try:
        response = await client.post(
            THREATFOX_URL,
            headers=headers,
            json=payload,
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        result = response.json()
    except httpx.TimeoutException:
        logger.warning("Timeout fetching ThreatFox IOCs.")
        return []
    except httpx.HTTPStatusError as exc:
        logger.warning("ThreatFox HTTP error: status %s", exc.response.status_code)
        return []
    except httpx.RequestError as exc:
        logger.warning("ThreatFox network error: %s", exc)
        return []

    if result.get("query_status") != "ok":
        logger.warning("ThreatFox query_status not ok: %s", result.get("query_status"))
        return []

    iocs = []
    for item in result.get("data", []):
        iocs.append(
            {
                "source": "threatfox",
                "ioc": item.get("ioc", ""),
                "ioc_type": item.get("ioc_type", ""),
                "threat_type": item.get("threat_type", ""),
                "malware": item.get("malware_printable", ""),
                "confidence_level": item.get("confidence_level", 0),
                "first_seen": item.get("first_seen", ""),
            }
        )

    logger.info("Fetched %d IOCs from ThreatFox", len(iocs))
    return iocs


async def fetch_chainabuse_report(
    client: httpx.AsyncClient, address: str, chain: str | None = None
) -> list[dict]:
    """
    Screens a single crypto address against Chainabuse's reports.

    Returns a list of matching report dicts (empty if not reported,
    or on failure).
    """
    if not CHAINABUSE_API_KEY:
        logger.error("CHAINABUSE_API_KEY is not set. Skipping Chainabuse fetch.")
        return []

    params = {"address": address}
    if chain:
        params["chain"] = chain

    try:
        response = await client.get(
            CHAINABUSE_URL,
            params=params,
            auth=(CHAINABUSE_API_KEY, CHAINABUSE_API_KEY),
            timeout=REQUEST_TIMEOUT_SECONDS,
        )

        response.raise_for_status()
        result = response.json()
    except httpx.TimeoutException:
        logger.warning("Timeout fetching Chainabuse report for %s", address)
        return []
    except httpx.HTTPStatusError as exc:
        logger.warning(
            "Chainabuse HTTP error for %s: status %s", address, exc.response.status_code
        )
        return []
    except httpx.RequestError as exc:
        logger.warning("Chainabuse network error for %s: %s", address, exc)
        return []

    # The API returns a list of reports directly (empty list if unreported).
    reports = result if isinstance(result, list) else result.get("reports", [])

    parsed_reports = []
    for report in reports:
        parsed_reports.append(
            {
                "source": "chainabuse",
                "address": address,
                "category": report.get("category", ""),
                "chain": report.get("chain", ""),
                "description": report.get("description", ""),
                "reported_at": report.get("createdAt", ""),
            }
        )

    logger.info(
        "Fetched %d Chainabuse report(s) for %s", len(parsed_reports), address
    )
    return parsed_reports

def save_threatfox_to_db(iocs: list[dict]) -> dict:
    """
    Saves ThreatFox IOCs to the database.

    Skips IOCs whose 'ioc' value already exists (deduplication via
    the database's UNIQUE constraint). Returns a summary count.
    """
    inserted = 0
    skipped = 0

    with get_session() as session:
        for item in iocs:
            existing = (
                session.query(ThreatFoxIOC)
                .filter_by(ioc=item["ioc"])
                .first()
            )
            if existing:
                skipped += 1
                continue

            db_ioc = ThreatFoxIOC(
                ioc=item["ioc"],
                ioc_type=item["ioc_type"],
                threat_type=item["threat_type"],
                malware=item["malware"],
                confidence_level=item["confidence_level"],
                first_seen=item["first_seen"],
            )
            session.add(db_ioc)

            try:
                session.commit()
                inserted += 1
            except IntegrityError:
                session.rollback()
                skipped += 1

    logger.info(
        "Saved %d new ThreatFox IOCs (%d duplicates skipped)", inserted, skipped
    )
    return {"inserted": inserted, "skipped": skipped}


def save_chainabuse_to_db(reports: list[dict]) -> dict:
    """
    Saves Chainabuse reports to the database.

    Skips reports whose (address, category, reported_at) combination
    already exists. Returns a summary count.
    """
    inserted = 0
    skipped = 0

    with get_session() as session:
        for item in reports:
            existing = (
                session.query(ChainabuseReport)
                .filter_by(
                    address=item["address"],
                    category=item["category"],
                    reported_at=item["reported_at"],
                )
                .first()
            )
            if existing:
                skipped += 1
                continue

            db_report = ChainabuseReport(
                address=item["address"],
                category=item["category"],
                chain=item["chain"],
                description=item["description"],
                reported_at=item["reported_at"],
            )
            session.add(db_report)

            try:
                session.commit()
                inserted += 1
            except IntegrityError:
                session.rollback()
                skipped += 1

    logger.info(
        "Saved %d new Chainabuse reports (%d duplicates skipped)", inserted, skipped
    )
    return {"inserted": inserted, "skipped": skipped}

async def collect_threat_feeds() -> dict:
    """
    Orchestrates both threat feed sources.

    Chainabuse requires a specific address to check, so for this initial
    test we screen one well-known, publicly-documented scam address
    (safe to use as a connectivity/parsing test — it is not a secret
    and not user-supplied).
    """
    KNOWN_TEST_ADDRESS = "0x0000000000000000000000000000000000dead"

    async with httpx.AsyncClient() as client:
        threatfox_task = fetch_threatfox_iocs(client, days=1)
        chainabuse_task = fetch_chainabuse_report(client, KNOWN_TEST_ADDRESS)

        threatfox_results, chainabuse_results = await asyncio.gather(
            threatfox_task, chainabuse_task
        )

    return {
        "threatfox": threatfox_results,
        "chainabuse": chainabuse_results,
    }


if __name__ == "__main__":
    logging.basicConfig(
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        level=logging.INFO,
    )
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)

    results = asyncio.run(collect_threat_feeds())

    tf_summary = save_threatfox_to_db(results["threatfox"])
    ca_summary = save_chainabuse_to_db(results["chainabuse"])

    print(f"\nThreatFox IOCs: {len(results['threatfox'])} fetched, "
          f"{tf_summary['inserted']} new, {tf_summary['skipped']} duplicates")

    for ioc in results["threatfox"][:5]:
        print(f"- [{ioc['ioc_type']}] {ioc['ioc']} ({ioc['malware']})")

    print(f"Chainabuse reports for test address: {len(results['chainabuse'])} fetched, "
          f"{ca_summary['inserted']} new, {ca_summary['skipped']} duplicates")
    for report in results["chainabuse"][:5]:
        print(f"- [{report['category']}] {report['description'][:80]}")
