"""
extractors/ioc_extractor.py

Extracts structured IOCs from collected RSS entry text using regex patterns.

IOC types extracted:
  - IPv4 addresses
  - Domains
  - SHA256 hashes (64 hex chars)
  - SHA1 hashes (40 hex chars)
  - MD5 hashes (32 hex chars)
  - CVE identifiers
  - Ethereum wallet addresses (0x...)
  - Solana wallet addresses (base58, 32-44 chars)

Design notes:
- Patterns are deliberately conservative to minimize false positives.
  A missed real IOC is less dangerous than acting on a wrong indicator.
- Text is refanged before matching (strips [.], hxxp, etc.).
- Each extracted IOC is linked back to its source rss_entry via FK.
"""

import logging
import re

from sqlalchemy.exc import IntegrityError

from database.db import get_session, init_db
from database.models import ExtractedIOC, RSSEntry

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Refanging — converts defanged IOCs back to canonical form before matching
# ---------------------------------------------------------------------------

def refang(text: str) -> str:
    """
    Restores defanged IOCs to their original form.

    Threat intel authors commonly write 'malicious[.]com' or
    'hxxp://example.com' to prevent accidental clicks or DNS lookups.
    We strip these before running regex patterns so we match real IOCs.
    """
    if not text:
        return ""
    text = text.replace("[.]", ".")
    text = text.replace("[dot]", ".")
    text = text.replace("(dot)", ".")
    text = text.replace("[:]", ":")
    text = text.replace("hxxps://", "https://")
    text = text.replace("hxxp://", "http://")
    text = text.replace("[/]", "/")
    return text


# ---------------------------------------------------------------------------
# Regex patterns — one per IOC type
# ---------------------------------------------------------------------------

# IPv4: four octets, each 0-255, not preceded/followed by digits or dots
# (avoids matching inside version strings like "2.0.51.3")
IPV4_RE = re.compile(
    r"(?<![.\d])"
    r"(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)"
    r"(?![.\d])"
)

# Domain: hostname with TLD, at least one dot, no spaces
# Excludes pure IP addresses (already caught above)
# Minimum: 'a.bc' — requires at least 2-char TLD
DOMAIN_RE = re.compile(
    r"(?<![/@\w])"           # not preceded by / @ or word char (avoids emails/URLs)
    r"(?:[a-zA-Z0-9]"        # start with alphanumeric
    r"(?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?"  # optional middle
    r"\.)+"                   # at least one dot-separated label
    r"[a-zA-Z]{2,}"           # TLD: at least 2 letters
    r"(?![.\w])"              # not followed by dot or word char
)

# SHA256: exactly 64 lowercase or uppercase hex characters
SHA256_RE = re.compile(r"\b[0-9a-fA-F]{64}\b")

# SHA1: exactly 40 hex characters
SHA1_RE = re.compile(r"\b[0-9a-fA-F]{40}\b")

# MD5: exactly 32 hex characters
MD5_RE = re.compile(r"\b[0-9a-fA-F]{32}\b")

# CVE: standard format CVE-YYYY-NNNNN (4-digit year, 4+ digit ID)
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)

# Ethereum address: 0x followed by exactly 40 hex characters
ETH_RE = re.compile(r"\b0x[0-9a-fA-F]{40}\b")

# Solana address: base58 characters, 32-44 chars long, must contain
# at least one uppercase letter (eliminates browser extension IDs,
# which are always 32-char all-lowercase strings)
# Base58 alphabet: 123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz
SOL_RE = re.compile(
    r"\b(?=[1-9A-HJ-NP-Za-km-z]{32,44}\b)"   # lookahead: correct length/chars
    r"(?=[^a-z]*[A-Z])"                         # lookahead: must have uppercase
    r"[1-9A-HJ-NP-Za-km-z]{32,44}\b"
)


PATTERNS: dict[str, re.Pattern] = {
    "ipv4": IPV4_RE,
    "domain": DOMAIN_RE,
    "sha256": SHA256_RE,
    "sha1": SHA1_RE,
    "md5": MD5_RE,
    "cve": CVE_RE,
    "eth_address": ETH_RE,
    "sol_address": SOL_RE,
}

# TLDs we explicitly ignore to cut down on domain false positives
# (version strings, file extensions, and other common non-domain patterns)
IGNORED_TLDS = {
    "py", "js", "ts", "go", "rb", "sh", "bat", "ps1",
    "txt", "csv", "log", "cfg", "ini", "xml", "json",
    "png", "jpg", "gif", "svg", "ico", "pdf", "zip",
    "exe", "dll", "sys", "tmp", "bak",
}


# ---------------------------------------------------------------------------
# Core extraction function
# ---------------------------------------------------------------------------

def extract_iocs(text: str, source_entry_id: int) -> list[dict]:
    """
    Extracts all IOC types from a single text string.

    Returns a list of dicts: {ioc_type, value, source_entry_id}
    Ready to be inserted into the extracted_iocs table.
    """
    if not text:
        return []

    clean_text = refang(text)
    found: list[dict] = []
    seen: set[tuple] = set()   # dedup within a single article

    for ioc_type, pattern in PATTERNS.items():
        for match in pattern.finditer(clean_text):
            value = match.group(0).strip()

            # Skip domain matches whose TLD is a known file extension
            if ioc_type == "domain":
                tld = value.rsplit(".", 1)[-1].lower()
                if tld in IGNORED_TLDS:
                    continue

            # Skip short Solana matches that are more likely random words
            if ioc_type == "sol_address" and len(value) < 32:
                continue

            key = (ioc_type, value)
            if key in seen:
                continue
            seen.add(key)

            found.append({
                "ioc_type": ioc_type,
                "value": value,
                "source_entry_id": source_entry_id,
            })

    return found


# ---------------------------------------------------------------------------
# Database integration
# ---------------------------------------------------------------------------

def process_rss_entries(limit: int = 50) -> dict:
    """
    Reads unprocessed RSS entries from the database, extracts IOCs
    from each, and saves results to extracted_iocs.

    'Unprocessed' means: rss_entries that have no corresponding rows
    in extracted_iocs yet (checked via a LEFT JOIN / subquery).

    limit: max entries to process per call (avoids very long runs).
    Returns: summary dict with counts.
    """
    total_extracted = 0
    total_skipped = 0
    entries_processed = 0

    with get_session() as session:
        # Find RSS entries not yet processed for IOC extraction
        from sqlalchemy import select
        processed_ids = select(
            ExtractedIOC.source_entry_id
        ).distinct().scalar_subquery()

        unprocessed = (
            session.query(RSSEntry)
            .filter(~RSSEntry.id.in_(processed_ids))
            .limit(limit)
            .all()
        )

        logger.info(
            "Found %d unprocessed RSS entries (limit=%d)",
            len(unprocessed), limit
        )

        for entry in unprocessed:
            text = f"{entry.title} {entry.summary or ''}"
            iocs = extract_iocs(text, entry.id)
            entries_processed += 1

            for ioc in iocs:
                db_ioc = ExtractedIOC(
                    ioc_type=ioc["ioc_type"],
                    value=ioc["value"],
                    source_entry_id=ioc["source_entry_id"],
                )
                session.add(db_ioc)
                try:
                    session.commit()
                    total_extracted += 1
                except IntegrityError:
                    session.rollback()
                    total_skipped += 1

    logger.info(
        "Extraction complete: %d entries processed, "
        "%d IOCs extracted, %d duplicates skipped",
        entries_processed, total_extracted, total_skipped
    )
    return {
        "entries_processed": entries_processed,
        "extracted": total_extracted,
        "skipped": total_skipped,
    }


# ---------------------------------------------------------------------------
# Standalone test runner
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        level=logging.INFO,
    )
    logging.getLogger("sqlalchemy").setLevel(logging.WARNING)

    init_db()

    # Quick self-test against known IOC strings before touching real data
    TEST_TEXT = (
        "Malware C2 at 192.168.1.100 and evil[.]domain.com "
        "hash: a3f5b2c1d4e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2 "
        "MD5: 098f6bcd4621d373cade4e832627b4f6 "
        "CVE-2026-12345 affects all versions. "
        "Eth wallet: 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045 "
        "hxxp://malicious.example.com/payload"
    )

    print("\n--- Self-test against known IOC string ---")
    test_results = extract_iocs(TEST_TEXT, source_entry_id=0)
    for r in test_results:
        print(f"  [{r['ioc_type']}] {r['value']}")

    print(f"\n--- Processing real RSS entries from database ---")
    summary = process_rss_entries(limit=50)
    print(f"  Entries processed: {summary['entries_processed']}")
    print(f"  IOCs extracted:    {summary['extracted']}")
    print(f"  Duplicates:        {summary['skipped']}")

    # Show sample from database
    with get_session() as session:
        samples = session.query(ExtractedIOC).limit(10).all()
        if samples:
            print(f"\n--- Sample extracted IOCs from DB ---")
            for s in samples:
                print(f"  [{s.ioc_type}] {s.value} (entry_id={s.source_entry_id})")
        else:
            print("\n  No IOCs in DB yet.")
