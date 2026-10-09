"""Regression tests for database session transaction handling."""

from database import db


class TrackingSession:
    def __init__(self):
        self.rollback_called = False
        self.close_called = False

    def rollback(self):
        self.rollback_called = True

    def close(self):
        self.close_called = True


def test_get_session_rolls_back_and_closes_on_exception(monkeypatch):
    session = TrackingSession()
    monkeypatch.setattr(db, "SessionLocal", lambda: session)

    try:
        with db.get_session():
            raise RuntimeError("simulated database failure")
    except RuntimeError:
        pass

    assert session.rollback_called is True
    assert session.close_called is True
