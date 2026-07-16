import unittest

from app.security.taxonomy import (
    ALLOW,
    ALLOW_WITH_MONITORING,
    BLOCK_CRITICAL,
    BLOCK_OR_INVESTIGATE,
    REQUIRE_CONFIRMATION,
    REVIEW,
    RISK_LEVELS,
    decision_bucket,
    normalize_risk_level,
    normalize_security_decision,
    risk_level_for,
)


class SecurityTaxonomyTests(unittest.TestCase):
    def test_canonical_risk_levels(self):
        self.assertEqual(
            RISK_LEVELS,
            (
                "low",
                "suspicious",
                "high",
                "critical",
            ),
        )

    def test_score_thresholds(self):
        cases = {
            0: "low",
            29: "low",
            30: "suspicious",
            69: "suspicious",
            70: "high",
            89: "high",
            90: "critical",
            100: "critical",
        }

        for score, expected in cases.items():
            with self.subTest(score=score):
                self.assertEqual(
                    risk_level_for(score),
                    expected,
                )

    def test_legacy_risk_aliases(self):
        self.assertEqual(
            normalize_risk_level("minimal"),
            "low",
        )
        self.assertEqual(
            normalize_risk_level("medium"),
            "suspicious",
        )
        self.assertEqual(
            normalize_risk_level("informational"),
            "low",
        )

    def test_allow_decision_bucket(self):
        self.assertEqual(
            decision_bucket(ALLOW),
            "allow",
        )
        self.assertEqual(
            decision_bucket(
                ALLOW_WITH_MONITORING
            ),
            "allow",
        )

    def test_review_decision_bucket(self):
        self.assertEqual(
            decision_bucket(REVIEW),
            "review",
        )
        self.assertEqual(
            decision_bucket(
                REQUIRE_CONFIRMATION
            ),
            "review",
        )

    def test_block_decision_bucket(self):
        self.assertEqual(
            decision_bucket(BLOCK_CRITICAL),
            "block",
        )
        self.assertEqual(
            decision_bucket(
                BLOCK_OR_INVESTIGATE
            ),
            "block",
        )

    def test_unknown_decision_bucket(self):
        self.assertEqual(
            decision_bucket("unsupported"),
            "unknown",
        )

    def test_security_decision_normalization(self):
        self.assertEqual(
            normalize_security_decision(
                " REQUIRE_CONFIRMATION "
            ),
            REQUIRE_CONFIRMATION,
        )


if __name__ == "__main__":
    unittest.main()
