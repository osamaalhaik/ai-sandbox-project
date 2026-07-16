from __future__ import annotations

from typing import Final


RISK_LOW: Final = "low"
RISK_SUSPICIOUS: Final = "suspicious"
RISK_HIGH: Final = "high"
RISK_CRITICAL: Final = "critical"

RISK_LEVELS: Final = (
    RISK_LOW,
    RISK_SUSPICIOUS,
    RISK_HIGH,
    RISK_CRITICAL,
)

RISK_LEVEL_ALIASES: Final = {
    "minimal": RISK_LOW,
    "normal": RISK_LOW,
    "safe": RISK_LOW,
    "informational": RISK_LOW,
    "info": RISK_LOW,
    "medium": RISK_SUSPICIOUS,
    "warning": RISK_SUSPICIOUS,
}

ALLOW: Final = "allow"
ALLOW_WITH_MONITORING: Final = "allow_with_monitoring"
REVIEW: Final = "review"
REQUIRE_CONFIRMATION: Final = "require_confirmation"
BLOCK_CRITICAL: Final = "block_critical"
BLOCK_OR_INVESTIGATE: Final = "block_or_investigate"
UNKNOWN_DECISION: Final = "unknown"

SECURITY_DECISIONS: Final = (
    ALLOW,
    ALLOW_WITH_MONITORING,
    REVIEW,
    REQUIRE_CONFIRMATION,
    BLOCK_CRITICAL,
    BLOCK_OR_INVESTIGATE,
)

ALLOW_DECISIONS: Final = frozenset(
    {
        ALLOW,
        ALLOW_WITH_MONITORING,
    }
)

REVIEW_DECISIONS: Final = frozenset(
    {
        REVIEW,
        REQUIRE_CONFIRMATION,
    }
)

BLOCK_DECISIONS: Final = frozenset(
    {
        BLOCK_CRITICAL,
        BLOCK_OR_INVESTIGATE,
    }
)


def normalize_risk_level(
    value: object,
    default: str = RISK_LOW,
) -> str:
    normalized = str(value or "").strip().lower()

    if normalized in RISK_LEVELS:
        return normalized

    return RISK_LEVEL_ALIASES.get(
        normalized,
        default,
    )


def risk_level_for(score: int | float) -> str:
    normalized_score = max(
        0.0,
        min(
            100.0,
            float(score or 0),
        ),
    )

    if normalized_score >= 90:
        return RISK_CRITICAL

    if normalized_score >= 70:
        return RISK_HIGH

    if normalized_score >= 30:
        return RISK_SUSPICIOUS

    return RISK_LOW


def normalize_security_decision(
    value: object,
    default: str = UNKNOWN_DECISION,
) -> str:
    normalized = str(value or "").strip().lower()

    if normalized in SECURITY_DECISIONS:
        return normalized

    return default


def decision_bucket(value: object) -> str:
    normalized = normalize_security_decision(value)

    if normalized in ALLOW_DECISIONS:
        return ALLOW

    if normalized in REVIEW_DECISIONS:
        return REVIEW

    if normalized in BLOCK_DECISIONS:
        return "block"

    return UNKNOWN_DECISION
