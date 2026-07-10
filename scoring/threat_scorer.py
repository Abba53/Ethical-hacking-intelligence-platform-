"""
scoring/threat_scorer.py

Threat scoring engine for collected IOCs.

Scoring model:
  Each IOC receives a score from 0-100 based on weighted signals:

  Signal                    Weight  Source
  ─────────────────────────────────────────────────
  ThreatFox confidence      35%     threatfox_iocs.confidence_level
  Threat type severity      25%     threat_type classification
  IOC type actionability    15%     ip:port > domain > url > hash
  Recency                   15%     days since first_seen
  Malware family danger     10%     known high-risk malware families

  Score → Severity mapping:
    80-100  CRITICAL
    60-79   HIGH
    40-59   MEDIUM
    20-39   LOW
    0-19    INFO

Every scored IOC gets a human-readable explanation built from
the signals that contributed to its score — not just a number.

Design notes:
- Scoring is purely local — no external API calls needed.
  All signals come from data already in our database.
- Scores are stored in ioc_scores table and updated on re-scoring.
- process_unscored_iocs() is the main entry point for batch scoring.
"""

import json
import logging
from datetime import datetime, timezone

from sqlalchemy.exc import IntegrityError

from database.db import get_session
from database.models import IocScore, ThreatFoxIOC
from sqlalchemy import select
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Threat type severity weights (0-1 scale)
# Higher = more severe
# ---------------------------------------------------------------------------

THREAT_TYPE_WEIGHTS = {
    "botnet_cc":          1.0,   # Active C2 — highest risk
    "payload_delivery":   0.9,   # Serving malware
    "exploit":            0.9,   # Active exploitation
    "ransomware":         0.95,  # Ransomware infrastructure
    "infostealer":        0.85,  # Data theft
    "backdoor":           0.85,  # Persistent access
    "trojan":             0.80,
    "rat":                0.80,  # Remote access trojan
    "cryptominer":        0.60,
    "phishing":           0.75,
    "spam":               0.40,
    "scanner":            0.35,
    "brute_force":        0.45,
}

# ---------------------------------------------------------------------------
# IOC type actionability weights
# More specific/actionable = higher weight
# ---------------------------------------------------------------------------

IOC_TYPE_WEIGHTS = {
    "ip:port":   1.0,   # Most specific — active service on known port
    "ip":        0.85,
    "domain":    0.80,
    "url":       0.75,
    "md5":       0.70,
    "sha1":      0.70,
    "sha256":    0.70,
}

# ---------------------------------------------------------------------------
# High-risk malware families (additional score boost)
# ---------------------------------------------------------------------------

HIGH_RISK_MALWARE = {
    "lockbit", "blackcat", "alphv", "ransomhub", "clop", "black basta",
    "conti", "revil", "darkside", "ryuk",         # ransomware
    "cobalt strike", "cobaltstrike", "sliver",     # offensive frameworks
    "emotet", "trickbot", "qakbot", "bazarloader", # loaders/droppers
    "remcos", "asyncrat", "njrat", "xworm",        # RATs
    "redline", "vidar", "raccoon", "lumma",        # infostealers
    "mirai", "botnet",                             # botnets
}


def _score_recency(first_seen_str: str) -> float:
    """
    Returns a recency score (0-1) based on how recently the IOC was first seen.

    Logic: IOCs seen in the last 24h score 1.0, degrading to 0.1 at 30 days.
    After 30 days, score stays at 0.1 (old IOCs still matter, just less urgent).
    """
    if not first_seen_str:
        return 0.3  # Unknown recency — moderate score

    try:
        # ThreatFox format: "2026-07-08 14:23:00 UTC"
        first_seen_str = first_seen_str.replace(" UTC", "").strip()
        dt = datetime.strptime(first_seen_str, "%Y-%m-%d %H:%M:%S")
        dt = dt.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        age_days = (now - dt).total_seconds() / 86400

        if age_days <= 1:
            return 1.0
        elif age_days <= 7:
            return 0.8
        elif age_days <= 14:
            return 0.6
        elif age_days <= 30:
            return 0.4
        else:
            return 0.1
    except (ValueError, TypeError):
        return 0.3


def _score_malware(malware_str: str) -> float:
    """
    Returns a malware danger score (0-1) based on known high-risk families.
    """
    if not malware_str:
        return 0.3
    malware_lower = malware_str.lower()
    for family in HIGH_RISK_MALWARE:
        if family in malware_lower:
            return 1.0
    return 0.5  # Unknown malware — moderate risk


def compute_score(ioc: ThreatFoxIOC) -> dict:
    """
    Computes a threat score for a single ThreatFoxIOC database record.

    Returns a dict with score (0-100), severity label, explanation string,
    and signals dict (for storage and debugging).
    """
    signals = {}

    # Signal 1: ThreatFox confidence level (35% weight)
    tf_confidence = float(ioc.confidence_level or 0) / 100.0
    signals["threatfox_confidence"] = round(tf_confidence, 3)

    # Signal 2: Threat type severity (25% weight)
    threat_type_lower = (ioc.threat_type or "").lower().replace(" ", "_")
    threat_weight = THREAT_TYPE_WEIGHTS.get(threat_type_lower, 0.5)
    signals["threat_type_weight"] = threat_weight
    signals["threat_type"] = ioc.threat_type or "unknown"

    # Signal 3: IOC type actionability (15% weight)
    ioc_type_lower = (ioc.ioc_type or "").lower()
    ioc_type_weight = IOC_TYPE_WEIGHTS.get(ioc_type_lower, 0.5)
    signals["ioc_type_weight"] = ioc_type_weight
    signals["ioc_type"] = ioc.ioc_type or "unknown"

    # Signal 4: Recency (15% weight)
    recency_score = _score_recency(ioc.first_seen or "")
    signals["recency_score"] = recency_score
    signals["first_seen"] = ioc.first_seen or "unknown"

    # Signal 5: Malware family danger (10% weight)
    malware_score = _score_malware(ioc.malware or "")
    signals["malware_score"] = malware_score
    signals["malware"] = ioc.malware or "unknown"

    # Weighted combination
    raw_score = (
        tf_confidence   * 0.35 +
        threat_weight   * 0.25 +
        ioc_type_weight * 0.15 +
        recency_score   * 0.15 +
        malware_score   * 0.10
    )

    # Normalize to 0-100
    score = round(min(max(raw_score * 100, 0), 100), 1)

    # Severity label
    if score >= 80:
        severity = "CRITICAL"
    elif score >= 60:
        severity = "HIGH"
    elif score >= 40:
        severity = "MEDIUM"
    elif score >= 20:
        severity = "LOW"
    else:
        severity = "INFO"

    # Human-readable explanation
    explanation_parts = []

    if tf_confidence >= 0.75:
        explanation_parts.append(
            f"High ThreatFox confidence ({int(tf_confidence*100)}%)"
        )
    elif tf_confidence >= 0.5:
        explanation_parts.append(
            f"Moderate ThreatFox confidence ({int(tf_confidence*100)}%)"
        )

    if ioc.threat_type:
        explanation_parts.append(f"classified as {ioc.threat_type}")

    if ioc.malware and ioc.malware.lower() != "unknown malware":
        explanation_parts.append(f"associated with {ioc.malware}")

    if recency_score >= 0.8:
        explanation_parts.append("seen within last 7 days")
    elif recency_score <= 0.2:
        explanation_parts.append("older indicator (>30 days)")

    if ioc.ioc_type == "ip:port":
        explanation_parts.append("active service on specific port")

    explanation = ". ".join(explanation_parts) if explanation_parts else "Scored from available signals"

    return {
        "score": score,
        "severity": severity,
        "explanation": explanation,
        "signals": json.dumps(signals),
    }

def process_unscored_iocs(limit: int = 100) -> dict:
    """
    Scores ThreatFox IOCs that do not yet have a score in ioc_scores.

    Args:
        limit: Maximum number of IOCs to process in one batch.

    Returns:
        Summary of scoring execution.
    """

    scored = 0
    updated = 0
    errors = 0

    with get_session() as session:
        try:
            # Get already scored IOC values
            scored_ioc_values = select(
                IocScore.ioc_value
            ).scalar_subquery()

            # Fetch unscored IOCs
            unscored = (
                session.query(ThreatFoxIOC)
                .filter(
                    ~ThreatFoxIOC.ioc.in_(scored_ioc_values)
                )
                .limit(limit)
                .all()
            )

            logger.info(
                "Found %d unscored ThreatFox IOCs (limit=%d)",
                len(unscored),
                limit,
            )

            if not unscored:
                return {
                    "scored": 0,
                    "updated": 0,
                    "errors": 0,
                }

            for ioc in unscored:
                try:
                    result = compute_score(ioc)

                    db_score = IocScore(
                        ioc_value=ioc.ioc,
                        ioc_type=ioc.ioc_type or "unknown",
                        score=result["score"],
                        severity=result["severity"],
                        explanation=result["explanation"],
                        signals=result["signals"],
                    )

                    session.add(db_score)
                    scored += 1

                except IntegrityError:
                    session.rollback()

                    existing = (
                        session.query(IocScore)
                        .filter_by(ioc_value=ioc.ioc)
                        .first()
                    )

                    if existing:
                        result = compute_score(ioc)

                        existing.score = result["score"]
                        existing.severity = result["severity"]
                        existing.explanation = result["explanation"]
                        existing.signals = result["signals"]
                        existing.updated_at = datetime.now(timezone.utc)

                        updated += 1

                except Exception as exc:
                    session.rollback()

                    logger.error(
                        "Error scoring IOC %s: %s",
                        ioc.ioc,
                        exc,
                    )

                    errors += 1

            session.commit()

        except Exception as exc:
            session.rollback()

            logger.exception(
                "Batch scoring failed: %s",
                exc,
            )

            return {
                "scored": scored,
                "updated": updated,
                "errors": errors + 1,
            }

    logger.info(
        "Scoring complete: %d scored, %d updated, %d errors",
        scored,
        updated,
        errors,
    )

    return {
        "scored": scored,
        "updated": updated,
        "errors": errors,
    }


def process_all_unscored_iocs(batch_size: int = 100) -> dict:
    total_scored = 0
    total_updated = 0
    total_errors = 0

    while True:
        result = process_unscored_iocs(limit=batch_size)

        total_scored += result["scored"]
        total_updated += result["updated"]
        total_errors += result["errors"]

        if result["scored"] == 0 and result["updated"] == 0:
            break

    logger.info(
        "All IOC scoring complete: %d scored, %d updated, %d errors",
        total_scored,
        total_updated,
        total_errors,
    )

    return {
        "scored": total_scored,
        "updated": total_updated,
        "errors": total_errors,
    }

def get_top_threats(limit: int = 10, min_severity: str = "MEDIUM") -> list[dict]:
    """
    Returns the highest-scoring IOCs from the database.

    min_severity filters to MEDIUM and above by default —
    INFO/LOW findings are usually not worth alerting on.
    """
    severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    min_score = {
        "CRITICAL": 80, "HIGH": 60, "MEDIUM": 40, "LOW": 20, "INFO": 0
    }.get(min_severity, 40)

    with get_session() as session:
        top = (
            session.query(IocScore)
            .filter(IocScore.score >= min_score)
            .order_by(IocScore.score.desc())
            .limit(limit)
            .all()
        )

        return [
            {
                "ioc_value": t.ioc_value,
                "ioc_type": t.ioc_type,
                "score": t.score,
                "severity": t.severity,
                "explanation": t.explanation,
                "scored_at": str(t.scored_at),
            }
            for t in top
        ]
