"""Unit tests for IMAP LIST mailbox name parsing and quoting."""

from __future__ import annotations

import unittest

from gmail_client import _mailbox_from_list_line, _quote_mailbox


class TestMailboxFromListLine(unittest.TestCase):
    def test_quoted_name_with_space(self) -> None:
        line = '(\\HasNoChildren) "/" "SOAR Review"'
        self.assertEqual(_mailbox_from_list_line(line), "SOAR Review")

    def test_unquoted_inbox(self) -> None:
        line = '(\\HasNoChildren) "/" INBOX'
        self.assertEqual(_mailbox_from_list_line(line), "INBOX")

    def test_naive_rsplit_would_break_spaced_names(self) -> None:
        line = '(\\HasNoChildren) "/" "SOAR Review"'
        naive = line.rsplit(" ", 1)[-1].strip().strip('"')
        self.assertEqual(naive, "Review")
        self.assertNotEqual(naive, "SOAR Review")
        self.assertEqual(_mailbox_from_list_line(line), "SOAR Review")

    def test_empty_line(self) -> None:
        self.assertEqual(_mailbox_from_list_line(""), "")
        self.assertEqual(_mailbox_from_list_line("   "), "")


class TestQuoteMailbox(unittest.TestCase):
    def test_inbox_unquoted(self) -> None:
        self.assertEqual(_quote_mailbox("INBOX"), "INBOX")

    def test_spaces_quoted(self) -> None:
        self.assertEqual(_quote_mailbox("SOAR Review"), '"SOAR Review"')

    def test_already_quoted(self) -> None:
        self.assertEqual(_quote_mailbox('"SOAR Review"'), '"SOAR Review"')

    def test_simple_atom(self) -> None:
        self.assertEqual(_quote_mailbox("SOAR_Review"), "SOAR_Review")


if __name__ == "__main__":
    unittest.main()
