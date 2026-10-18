import pytest
from fastapi import HTTPException

from api.routers.ai_analysis import (
    _call_timestamps,
    _enforce_ai_rate_limit,
)


@pytest.fixture(autouse=True)
def reset_ai_rate_limit():
    _call_timestamps.clear()
    yield
    _call_timestamps.clear()


def test_ai_rate_limit_allows_five_calls(monkeypatch):
    monkeypatch.setattr(
        "api.routers.ai_analysis.time.monotonic",
        lambda: 100.0,
    )

    for _ in range(5):
        _enforce_ai_rate_limit()

    assert len(_call_timestamps) == 5


def test_ai_rate_limit_rejects_sixth_call(monkeypatch):
    monkeypatch.setattr(
        "api.routers.ai_analysis.time.monotonic",
        lambda: 100.0,
    )

    for _ in range(5):
        _enforce_ai_rate_limit()

    with pytest.raises(HTTPException) as exc:
        _enforce_ai_rate_limit()

    assert exc.value.status_code == 429
    assert "real, billed API calls" in exc.value.detail
    assert len(_call_timestamps) == 5


def test_ai_rate_limit_expires_old_calls(monkeypatch):
    now = [100.0]
    monkeypatch.setattr(
        "api.routers.ai_analysis.time.monotonic",
        lambda: now[0],
    )

    for _ in range(5):
        _enforce_ai_rate_limit()

    now[0] = 161.0
    _enforce_ai_rate_limit()

    assert len(_call_timestamps) == 1
