"""
Regression tests for active-scan target validation.
"""

import pytest

from services.active.target_utils import (
    validate_target_syntax,
    validate_public_target,
)


def test_target_syntax_accepts_https():
    valid, reason = validate_target_syntax("https://example.com/path")
    assert valid is True
    assert reason == "valid"


def test_target_syntax_rejects_non_http_scheme():
    valid, reason = validate_target_syntax("ftp://example.com")
    assert valid is False
    assert "http" in reason


@pytest.mark.asyncio
async def test_public_target_rejects_loopback_ip():
    valid, reason = validate_public_target("127.0.0.1")
    assert valid is False
    assert "non-public" in reason


@pytest.mark.asyncio
async def test_public_target_rejects_private_ip():
    valid, reason = validate_public_target("192.168.1.10")
    assert valid is False
    assert "non-public" in reason


@pytest.mark.asyncio
async def test_public_target_rejects_link_local_ip():
    valid, reason = validate_public_target("169.254.169.254")
    assert valid is False
    assert "non-public" in reason


@pytest.mark.asyncio
async def test_public_target_rejects_non_public_dns_resolution(monkeypatch):
    monkeypatch.setattr(
        "services.active.target_utils._resolve_addresses",
        lambda hostname: {"127.0.0.1"},
    )

    valid, reason = validate_public_target("example.com")

    assert valid is False
    assert "non-public" in reason


@pytest.mark.asyncio
async def test_public_target_accepts_public_dns_resolution(monkeypatch):
    monkeypatch.setattr(
        "services.active.target_utils._resolve_addresses",
        lambda hostname: {"93.184.216.34"},
    )

    valid, reason = validate_public_target("example.com")

    assert valid is True
    assert reason == "target is publicly routable"


@pytest.mark.parametrize(
    "target",
    [
        "",
        "   ",
        "http:///missing-host",
        "https://example.com:invalid/",
        "https://example.com:99999/",
        "https://user@:80/",
        "https://example.com/\n/path",
        "https://example.com/" + "a" * 2049,
    ],
)
def test_target_syntax_rejects_malformed_targets(target):
    valid, reason = validate_target_syntax(target)

    assert valid is False
    assert reason


def test_target_syntax_rejects_invalid_ipv6_url():
    valid, reason = validate_target_syntax("http://[invalid-ipv6]/")

    assert valid is False
    assert reason
