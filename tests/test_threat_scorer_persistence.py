"""Regression tests for threat-scoring database persistence."""

import json

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

from database.models import Base, IocScore, ThreatFoxIOC
from scoring import threat_scorer


@pytest.fixture
def scorer_db(tmp_path, monkeypatch):
    """Give each test an isolated SQLite database."""
    engine = create_engine(f"sqlite:///{tmp_path / 'scorer-test.db'}")

    if engine.dialect.name == "sqlite":
        @event.listens_for(engine, "connect")
        def enable_foreign_keys(connection, _record):
            cursor = connection.cursor()
            try:
                cursor.execute("PRAGMA foreign_keys=ON")
            finally:
                cursor.close()

    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, expire_on_commit=False)

    from contextlib import contextmanager

    @contextmanager
    def isolated_session():
        session = session_factory()
        try:
            yield session
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    monkeypatch.setattr(threat_scorer, "get_session", isolated_session)

    try:
        yield session_factory
    finally:
        engine.dispose()


def add_ioc(session_factory, value, ioc_type="domain"):
    with session_factory() as session:
        session.add(
            ThreatFoxIOC(
                ioc=value,
                ioc_type=ioc_type,
                threat_type="phishing",
                malware="unknown malware",
                confidence_level=80,
                first_seen="2026-10-12 00:00:00 UTC",
            )
        )
        session.commit()


def test_batch_scoring_persists_successful_iocs(scorer_db):
    add_ioc(scorer_db, "first.example")
    add_ioc(scorer_db, "second.example")

    result = threat_scorer.process_unscored_iocs(limit=10)

    assert result == {"scored": 2, "updated": 0, "errors": 0}

    with scorer_db() as session:
        scores = session.query(IocScore).order_by(IocScore.ioc_value).all()

    assert [score.ioc_value for score in scores] == [
        "first.example",
        "second.example",
    ]


def test_failed_ioc_does_not_erase_successful_scores(
    scorer_db, monkeypatch
):
    add_ioc(scorer_db, "first.example")
    add_ioc(scorer_db, "second.example")

    original_compute = threat_scorer.compute_score

    def compute_with_failure(ioc):
        if ioc.ioc == "second.example":
            raise ValueError("simulated scoring failure")
        return original_compute(ioc)

    monkeypatch.setattr(threat_scorer, "compute_score", compute_with_failure)

    result = threat_scorer.process_unscored_iocs(limit=10)

    assert result == {"scored": 1, "updated": 0, "errors": 1}

    with scorer_db() as session:
        persisted = {
            score.ioc_value
            for score in session.query(IocScore).all()
        }

    assert persisted == {"first.example"}


def test_scored_ioc_signals_are_valid_json(scorer_db):
    add_ioc(scorer_db, "signals.example")

    result = threat_scorer.process_unscored_iocs(limit=10)

    assert result["errors"] == 0

    with scorer_db() as session:
        score = session.query(IocScore).filter_by(
            ioc_value="signals.example"
        ).one()

    signals = json.loads(score.signals)
    assert "threatfox_confidence" in signals
    assert 0 <= score.score <= 100


@pytest.mark.parametrize("limit", [0, -1])
def test_invalid_batch_limit_is_rejected(limit):
    with pytest.raises(ValueError):
        threat_scorer.process_unscored_iocs(limit=limit)
