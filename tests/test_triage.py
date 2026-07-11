"""Unit tests for keyword triage scoring."""

from __future__ import annotations

import unittest

from triage import is_suspicious, score_email


SEED_RULES = [
    {"keyword": "urgent", "weight": 2, "enabled": True},
    {"keyword": "verify", "weight": 2, "enabled": True},
    {"keyword": "invoice", "weight": 2, "enabled": True},
    {"keyword": "bank", "weight": 3, "enabled": True},
    {"keyword": "payment", "weight": 3, "enabled": True},
    {"keyword": "password", "weight": 4, "enabled": True},
    {"keyword": "account suspended", "weight": 5, "enabled": True},
    {"keyword": "wire transfer", "weight": 5, "enabled": True},
    {"keyword": "gift card", "weight": 5, "enabled": True},
    {"keyword": "crypto", "weight": 4, "enabled": True},
]


class TestScoreEmail(unittest.TestCase):
    def test_benign_email_scores_zero(self) -> None:
        result = score_email(
            "Lunch tomorrow?",
            "Want to grab tacos at noon?",
            SEED_RULES,
        )
        self.assertEqual(result.threat_score, 0)
        self.assertEqual(result.matched_keywords, [])
        self.assertFalse(is_suspicious(result))

    def test_phishing_subject_matches_keywords(self) -> None:
        result = score_email(
            "URGENT: verify your password",
            "Your account needs attention.",
            SEED_RULES,
        )
        self.assertGreaterEqual(result.threat_score, 1)
        self.assertTrue(is_suspicious(result))
        matched = {k.lower() for k in result.matched_keywords}
        self.assertIn("urgent", matched)
        self.assertIn("verify", matched)
        self.assertIn("password", matched)

    def test_phrase_match_in_body(self) -> None:
        result = score_email(
            "Action required",
            "Please complete a wire transfer today.",
            SEED_RULES,
        )
        self.assertIn("wire transfer", [k.lower() for k in result.matched_keywords])
        self.assertEqual(result.threat_score, 5)

    def test_case_insensitive(self) -> None:
        result = score_email("Gift Card Offer", "Redeem now", SEED_RULES)
        self.assertEqual(result.threat_score, 5)

    def test_disabled_rules_ignored(self) -> None:
        rules = [{"keyword": "urgent", "weight": 10, "enabled": False}]
        result = score_email("URGENT notice", "hello", rules)
        self.assertEqual(result.threat_score, 0)

    def test_weights_accumulate(self) -> None:
        result = score_email(
            "invoice payment",
            "",
            SEED_RULES,
        )
        self.assertEqual(result.threat_score, 5)  # invoice 2 + payment 3

    def test_common_test_subjects_that_should_quarantine(self) -> None:
        """Subjects users often use when manually testing the scanner."""
        samples = [
            "Urgent: verify your bank password",
            "Account suspended — confirm payment",
            "Wire transfer invoice for crypto gift card",
        ]
        for subject in samples:
            with self.subTest(subject=subject):
                result = score_email(subject, "", SEED_RULES)
                self.assertTrue(
                    is_suspicious(result),
                    f"Expected quarantine for {subject!r}, got score={result.threat_score}",
                )

    def test_subjects_without_keywords_not_quarantined(self) -> None:
        samples = [
            "Hello from SOAR test",
            "Test email 1",
            "Meeting notes",
        ]
        for subject in samples:
            with self.subTest(subject=subject):
                result = score_email(subject, "just checking", SEED_RULES)
                self.assertFalse(
                    is_suspicious(result),
                    f"Unexpected quarantine for {subject!r}",
                )


if __name__ == "__main__":
    unittest.main()
