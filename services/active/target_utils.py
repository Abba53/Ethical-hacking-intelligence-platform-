"""
services/active/target_utils.py

Shared target-string normalization and destination-safety helpers.
"""

import ipaddress
import socket
from urllib.parse import urlparse


def extract_hostname(target: str) -> str:
    """
    Return the bare hostname/IP from a target.

    Schemes, paths, queries, and ports are removed.
    """
    target = target.strip()

    if "://" in target:
        parsed = urlparse(target)
        return (parsed.hostname or target).strip().lower()

    host = target.split("/", 1)[0].split(":", 1)[0]
    return host.strip().lower()


def ensure_scheme(target: str, default_scheme: str = "http") -> str:
    """
    Return target with a URL scheme.
    """
    target = target.strip()

    if "://" in target:
        return target

    return f"{default_scheme}://{target}"


def _is_public_ip(address: str) -> bool:
    """
    Return True only for globally routable IP addresses.

    Private, loopback, link-local, multicast, reserved, unspecified,
    and documentation/non-global addresses are rejected.
    """
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False

    return ip.is_global


def _resolve_addresses(hostname: str) -> set[str]:
    """
    Resolve a hostname to IPv4/IPv6 addresses.
    """
    results = socket.getaddrinfo(
        hostname,
        None,
        type=socket.SOCK_STREAM,
    )

    return {
        result[4][0]
        for result in results
        if result[4]
    }


def validate_target_syntax(target: str) -> tuple[bool, str]:
    """
    Validate target syntax without performing DNS resolution.

    Only HTTP/HTTPS URLs or bare host/IP targets are accepted.
    """
    target = target.strip()

    if not target:
        return False, "target is empty"

    if len(target) > 2048:
        return False, "target exceeds maximum length"

    if any(char in target for char in "\x00\r\n"):
        return False, "target contains forbidden control characters"

    if "://" in target:
        parsed = urlparse(target)

        if parsed.scheme.lower() not in {"http", "https"}:
            return False, "only http and https targets are allowed"

        if not parsed.hostname:
            return False, "target URL has no hostname"

        return True, "valid"

    hostname = extract_hostname(target)

    if not hostname:
        return False, "target has no hostname"

    return True, "valid"


def validate_public_target(target: str) -> tuple[bool, str]:
    """
    Validate that a target resolves only to globally routable addresses.

    This is an application-level SSRF defense. It does not replace
    network-level egress controls.
    """
    valid, reason = validate_target_syntax(target)

    if not valid:
        return False, reason

    hostname = extract_hostname(target)

    try:
        ip = ipaddress.ip_address(hostname)

        if not _is_public_ip(str(ip)):
            return False, f"target resolves to non-public address: {ip}"

        return True, "target is publicly routable"

    except ValueError:
        pass

    try:
        addresses = _resolve_addresses(hostname)
    except socket.gaierror:
        return False, f"hostname could not be resolved: {hostname}"
    except OSError as exc:
        return False, f"hostname resolution failed: {exc}"

    if not addresses:
        return False, f"hostname resolved to no addresses: {hostname}"

    unsafe = sorted(
        address
        for address in addresses
        if not _is_public_ip(address)
    )

    if unsafe:
        return False, (
            f"hostname resolves to non-public address(es): "
            f"{', '.join(unsafe)}"
        )

    return True, "target is publicly routable"
