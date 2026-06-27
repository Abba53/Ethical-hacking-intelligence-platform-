"""
collectors/rss_collector.py

Fetches and parses RSS/Atom feeds from a configured list of CTI sources.

Design notes:
- Fetching and parsing are deliberately separate functions (separation
  of concerns) so fetch logic can be reused by future collectors
  (e.g. Phase 6 threat-feed collectors) regardless of content format.
- Fetching is async so multiple feeds can be retrieved concurrently
  rather than one-by-one.
- feedparser is used for parsing; its safety against XXE-style attacks
  was explicitly verified in Phase 5.2 (see project history / commit log).
"""

import asyncio
import logging
from typing import Optional

import feedparser
import httpx

logger = logging.getLogger(__name__)

# Verified, live CTI RSS feed sources (Phase 5.1).
FEED_URLS: list[str] = [
    "https://krebsonsecurity.com/feed/",
    "https://blog.talosintelligence.com/rss",
    "http://thehackernews.com/feeds/posts/default",
    "https://www.darkreading.com/rss.xml",
    "http://www.malware-traffic-analysis.net/blog-entries.rss",
]

# A real User-Agent header. Some sites block requests with no/blank
# User-Agent, treating them as suspicious bot traffic.
REQUEST_HEADERS = {
    "User-Agent": "EthicalHackingIntelPlatform/0.1 (CTI feed collector)"
}

REQUEST_TIMEOUT_SECONDS = 15


async def fetch_feed_content(
    client: httpx.AsyncClient, url: str
) -> Optional[bytes]:
    """
    Fetches raw content from a single feed URL.

    Returns the raw response body as bytes, or None if the fetch failed
    for any reason (network error, timeout, non-200 status).
    """
    try:
        response = await client.get(
            url, headers=REQUEST_HEADERS, timeout=REQUEST_TIMEOUT_SECONDS
        )
        response.raise_for_status()
        return response.content
    except httpx.TimeoutException:
        logger.warning("Timeout fetching feed: %s", url)
    except httpx.HTTPStatusError as exc:
        logger.warning(
            "HTTP error fetching feed %s: status %s", url, exc.response.status_code
        )
    except httpx.RequestError as exc:
        logger.warning("Network error fetching feed %s: %s", url, exc)

    return None


def parse_feed_content(raw_content: bytes, source_url: str) -> list[dict]:
    """
    Parses raw feed bytes into a list of structured entry dictionaries.

    If the feed is malformed (feedparser's 'bozo' flag), we log it but
    still return whatever entries feedparser was able to recover —
    real-world feeds are often imperfect, and partial data is better
    than none.
    """
    parsed = feedparser.parse(raw_content)

    if parsed.bozo:
        logger.warning(
            "Feed at %s had parsing issues: %s",
            source_url,
            parsed.bozo_exception,
        )

    entries = []
    for entry in parsed.entries:
        entries.append(
            {
                "source_url": source_url,
                "title": entry.get("title", "(no title)"),
                "link": entry.get("link", ""),
                "published": entry.get("published", ""),
                "summary": entry.get("summary", ""),
            }
        )

    return entries


async def collect_all_feeds() -> list[dict]:
    """
    Fetches and parses every feed in FEED_URLS concurrently.

    Returns a combined, flat list of entry dictionaries from all
    feeds that were successfully fetched and parsed.
    """
    async with httpx.AsyncClient(follow_redirects=True) as client:
        fetch_tasks = [fetch_feed_content(client, url) for url in FEED_URLS]
        raw_results = await asyncio.gather(*fetch_tasks)

    all_entries: list[dict] = []
    for url, raw_content in zip(FEED_URLS, raw_results):
        if raw_content is None:
            logger.warning("Skipping feed (fetch failed): %s", url)
            continue

        entries = parse_feed_content(raw_content, url)
        logger.info("Parsed %d entries from %s", len(entries), url)
        all_entries.extend(entries)

    return all_entries


if __name__ == "__main__":
    logging.basicConfig(
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        level=logging.INFO,
    )

    results = asyncio.run(collect_all_feeds())

    print(f"\nTotal entries collected: {len(results)}\n")
    for item in results[:5]:
        print(f"- [{item['source_url']}] {item['title']}")
