"""
services/active/target_utils.py

Shared target-string normalization helpers.

Different tools need different shapes of the same target:
  - nmap, subfinder, and IOC/network lookups need a bare hostname
    or IP (no scheme, no path).
  - nuclei, ffuf, and other HTTP-based tools need a full URL
    (scheme + host, optionally path).

Authorization is checked against the bare hostname form so that
authorizing "https://example.com" and authorizing "example.com"
are treated as the same target.
"""

from urllib.parse import urlparse


def extract_hostname(target: str) -> str:
    """
    Returns the bare hostname/IP from a target, stripping any
    scheme, path, query string, or port. If the target has no
    scheme, it's assumed to already be a bare host and is returned
    lowercased/stripped as-is.
    """
    target = target.strip()

    if "://" in target:
        parsed = urlparse(target)
        return (parsed.hostname or target).strip().lower()

    # No scheme — could still have a path (e.g. "example.com/page")
    # or port (e.g. "example.com:8080"); take just the host part.
    host = target.split("/", 1)[0].split(":", 1)[0]
    return host.strip().lower()


def ensure_scheme(target: str, default_scheme: str = "http") -> str:
    """
    Returns target with a URL scheme, adding one if missing.
    Used for tools (nuclei, ffuf) that require a full URL.
    """
    target = target.strip()

    if "://" in target:
        return target

    return f"{default_scheme}://{target}"
