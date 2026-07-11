"""Unit tests for scan decision logic with mocked Gmail + DB."""

from __future__ import annotations

import unittest
from typing import Any
from unittest.mock import MagicMock, patch

from gmail_client import EmailMessage
from triage import is_suspicious, score_email


def decide_quarantine(
    subject: str,
    body: str,
    rules: list[dict[str, Any]],
    threshold: int = 1,
) -> tuple[bool, int, list[str]]:
    """Mirror scan_inbox scoring so tests can assert quarantine decisions."""
    result = score_email(subject, body, rules)
    return is_suspicious(result, threshold), result.threat_score, result.matched_keywords


class TestScanDecisions(unittest.TestCase):
    def test_unread_phishing_is_quarantined(self) -> None:
        ok, score, matched = decide_quarantine(
            "Urgent password reset",
            "Click to verify your account",
            [{"keyword": "urgent", "weight": 2, "enabled": True},
             {"keyword": "password", "weight": 4, "enabled": True},
             {"keyword": "verify", "weight": 2, "enabled": True}],
        )
        self.assertTrue(ok)
        self.assertEqual(score, 8)
        self.assertEqual(len(matched), 3)

    def test_unread_benign_is_clean(self) -> None:
        ok, score, _ = decide_quarantine(
            "Team sync",
            "See you at 3pm",
            [{"keyword": "urgent", "weight": 2, "enabled": True}],
        )
        self.assertFalse(ok)
        self.assertEqual(score, 0)


class TestScanInboxMocked(unittest.TestCase):
    @patch("app.insert_alert")
    @patch("app.fetch_keyword_rules")
    @patch("app.GmailClient")
    def test_scan_quarantines_matching_unseen(
        self,
        mock_gmail_cls: MagicMock,
        mock_rules: MagicMock,
        mock_insert: MagicMock,
    ) -> None:
        from app import scan_inbox
        from config import Settings

        mock_rules.return_value = [
            {"keyword": "urgent", "weight": 2, "enabled": True},
        ]
        mock_insert.return_value = {"gmail_uid": "99"}

        gmail = MagicMock()
        mock_gmail_cls.return_value.__enter__.return_value = gmail
        gmail._require_conn.return_value.uid.return_value = ("OK", [b"1 2"])
        gmail.fetch_unseen.return_value = [
            EmailMessage(
                gmail_uid="1",
                message_id="<a@b>",
                sender="phish@evil.test",
                subject="URGENT action",
                body="Please respond",
            ),
            EmailMessage(
                gmail_uid="2",
                message_id="<c@d>",
                sender="friend@example.com",
                subject="Hello",
                body="How are you?",
            ),
        ]
        gmail.move_message.return_value = "99"

        settings = Settings(
            supabase_url="https://example.supabase.co",
            supabase_key="key",
            gmail_user="user@example.com",
            gmail_app_password="pass",
        )
        client = MagicMock()
        stats = scan_inbox(settings, client)

        self.assertEqual(stats["scanned"], 2)
        self.assertEqual(stats["quarantined"], 1)
        self.assertEqual(stats["clean"], 1)
        gmail.move_message.assert_called_once()
        mock_insert.assert_called_once()

    @patch("app.fetch_keyword_rules")
    @patch("app.GmailClient")
    def test_scan_with_no_unseen_mail(
        self,
        mock_gmail_cls: MagicMock,
        mock_rules: MagicMock,
    ) -> None:
        from app import scan_inbox
        from config import Settings

        mock_rules.return_value = [
            {"keyword": "urgent", "weight": 2, "enabled": True},
        ]
        gmail = MagicMock()
        mock_gmail_cls.return_value.__enter__.return_value = gmail
        gmail.fetch_unseen.return_value = []
        # Cheap UNSEEN count path
        gmail._require_conn.return_value.uid.return_value = ("OK", [b""])

        settings = Settings(
            supabase_url="https://example.supabase.co",
            supabase_key="key",
            gmail_user="user@example.com",
            gmail_app_password="pass",
        )
        stats = scan_inbox(settings, MagicMock())
        self.assertEqual(stats["scanned"], 0)
        self.assertEqual(stats["quarantined"], 0)
        self.assertEqual(stats["clean"], 0)
        gmail.move_message.assert_not_called()


if __name__ == "__main__":
    unittest.main()
