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
        gmail.fetch_unseen_in_recent.return_value = (
            [
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
            ],
            {"recent_total": 50, "unseen_in_lookback": 2},
        )
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
        self.assertEqual(stats["lookback"], 50)
        gmail.fetch_unseen_in_recent.assert_called_once_with(lookback=50)
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
        gmail.fetch_unseen_in_recent.return_value = (
            [],
            {"recent_total": 50, "unseen_in_lookback": 0},
        )

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


class TestFetchUnseenInRecent(unittest.TestCase):
    def test_intersects_unseen_with_newest_lookback(self) -> None:
        from gmail_client import GmailClient

        client = GmailClient.__new__(GmailClient)
        conn = MagicMock()
        conn.untagged_responses = {"EXISTS": [b"10"]}
        # FETCH seq UID FLAGS for messages 6:10
        conn.fetch.return_value = (
            "OK",
            [
                b"6 (UID 106 FLAGS (\\Seen))",
                b"7 (UID 107 FLAGS ())",
                b"8 (UID 108 FLAGS (\\Recent))",
                b"9 (UID 109 FLAGS (\\Seen \\Recent))",
                b"10 (UID 110 FLAGS ())",
            ],
        )
        client._conn = conn
        client._fetch_uid = MagicMock(  # type: ignore[method-assign]
            side_effect=lambda uid: EmailMessage(
                gmail_uid=uid,
                message_id=f"<{uid}>",
                sender="a@b",
                subject=f"s{uid}",
                body="",
            )
        )

        messages, meta = client.fetch_unseen_in_recent(lookback=5)
        self.assertEqual(meta["recent_total"], 5)
        self.assertEqual([m.gmail_uid for m in messages], ["107", "108", "110"])
        self.assertEqual(meta["unseen_in_lookback"], 3)
        conn.fetch.assert_called_once_with("6:10", "(UID FLAGS)")


class TestUidsWithoutSeen(unittest.TestCase):
    def test_parses_flags(self) -> None:
        from gmail_client import _uids_without_seen

        data = [
            b"1 (UID 10 FLAGS (\\Seen))",
            b"2 (UID 11 FLAGS ())",
            (b"3 (UID 12 FLAGS (\\Recent))", b""),
        ]
        self.assertEqual(_uids_without_seen(data), ["11", "12"])


if __name__ == "__main__":
    unittest.main()
