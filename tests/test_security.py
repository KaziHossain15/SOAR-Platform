"""Regression tests for security hardening (IMAP injection, keys, logging)."""

from __future__ import annotations

import base64
import json
import logging
import unittest
from unittest.mock import MagicMock

from gmail_client import (
    GmailClient,
    GmailError,
    _require_uid,
    _safe_message_id,
)


def _header_fetch(uid: str, message_id: str) -> tuple[str, list]:
    return (
        "OK",
        [(f"{uid} (UID {uid} BODY[HEADER.FIELDS (MESSAGE-ID)]".encode(),
          f"Message-ID: {message_id}\r\n\r\n".encode())],
    )


class TestSafeMessageId(unittest.TestCase):
    def test_accepts_normal_ids(self) -> None:
        self.assertEqual(_safe_message_id(" <abc.123@mail.example.com> "),
                         "<abc.123@mail.example.com>")

    def test_rejects_search_criteria_injection(self) -> None:
        self.assertIsNone(_safe_message_id("<x> OR ALL ALL"))

    def test_rejects_crlf_command_injection(self) -> None:
        self.assertIsNone(_safe_message_id("<x>\r\na1 UID STORE 1:* +FLAGS (\\Deleted)"))

    def test_rejects_quotes_and_backslashes(self) -> None:
        self.assertIsNone(_safe_message_id('<a"b@c>'))
        self.assertIsNone(_safe_message_id("<a\\b@c>"))

    def test_rejects_missing_brackets_and_empty(self) -> None:
        self.assertIsNone(_safe_message_id("abc@example.com"))
        self.assertIsNone(_safe_message_id(""))
        self.assertIsNone(_safe_message_id(None))


class TestRequireUid(unittest.TestCase):
    def test_accepts_digits(self) -> None:
        self.assertEqual(_require_uid(" 42 "), "42")
        self.assertEqual(_require_uid(7), "7")

    def test_rejects_sequence_sets_and_injection(self) -> None:
        for bad in ("1:*", "1,2", "1 +FLAGS", "1\r\nA LOGOUT", "", "uid-5"):
            with self.assertRaises(GmailError):
                _require_uid(bad)


class TestFindUidByMessageId(unittest.TestCase):
    def _client(self, conn: MagicMock) -> GmailClient:
        client = GmailClient.__new__(GmailClient)
        client._conn = conn
        client.select_folder = MagicMock(return_value=1)  # type: ignore[method-assign]
        return client

    def test_search_argument_is_quoted(self) -> None:
        conn = MagicMock()

        def uid(cmd, *args):
            if cmd == "search":
                return ("OK", [b"5"])
            return _header_fetch("5", "<a@b>")

        conn.uid.side_effect = uid
        client = self._client(conn)
        self.assertEqual(client.find_uid_by_message_id("<a@b>", "SOAR Review"), "5")
        search_call = conn.uid.call_args_list[0]
        self.assertEqual(search_call.args[-1], '"<a@b>"')

    def test_ambiguous_duplicate_message_id_returns_none(self) -> None:
        conn = MagicMock()

        def uid(cmd, *args):
            if cmd == "search":
                return ("OK", [b"5 9"])
            return _header_fetch(args[0], "<dup@x>")

        conn.uid.side_effect = uid
        client = self._client(conn)
        self.assertIsNone(client.find_uid_by_message_id("<dup@x>", "SOAR Review"))

    def test_malicious_message_id_never_reaches_imap(self) -> None:
        conn = MagicMock()
        client = self._client(conn)
        self.assertIsNone(client.find_uid_by_message_id("<x> OR ALL ALL", "SOAR Review"))
        conn.uid.assert_not_called()


class TestResolveUid(unittest.TestCase):
    def test_rejects_stored_uid_whose_message_id_changed(self) -> None:
        client = GmailClient.__new__(GmailClient)
        conn = MagicMock()

        def uid(cmd, *args):
            if cmd == "search":
                return ("OK", [b""])
            return _header_fetch(args[0], "<other@x>")

        conn.uid.side_effect = uid
        client._conn = conn
        client.select_folder = MagicMock(return_value=1)  # type: ignore[method-assign]
        with self.assertRaises(GmailError):
            client._resolve_uid("5", "SOAR Review", "<expected@x>")


class TestSupabaseKeyRole(unittest.TestCase):
    @staticmethod
    def _jwt(role: str) -> str:
        payload = base64.urlsafe_b64encode(json.dumps({"role": role}).encode())
        return f"eyJhbGciOiJIUzI1NiJ9.{payload.decode().rstrip('=')}.sig"

    def test_detects_roles(self) -> None:
        from config import _supabase_key_role

        self.assertEqual(_supabase_key_role(self._jwt("anon")), "anon")
        self.assertEqual(_supabase_key_role(self._jwt("service_role")), "service_role")
        self.assertEqual(_supabase_key_role("sb_publishable_abc"), "anon")
        self.assertEqual(_supabase_key_role("sb_secret_abc"), "service_role")
        self.assertIsNone(_supabase_key_role("not-a-key"))


class TestLogRedaction(unittest.TestCase):
    def test_registered_secret_is_masked(self) -> None:
        from logger import _RedactingFilter, mask_email, register_secret

        register_secret("supersecretvalue123")
        record = logging.LogRecord(
            "t", logging.INFO, __file__, 1, "token=%s", ("supersecretvalue123",), None
        )
        _RedactingFilter().filter(record)
        self.assertNotIn("supersecretvalue123", record.getMessage())
        self.assertEqual(mask_email("jane@example.com"), "j***@example.com")


if __name__ == "__main__":
    unittest.main()
