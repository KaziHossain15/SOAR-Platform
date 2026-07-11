#!/usr/bin/env python3
"""Live diagnostic: why Scan Inbox may miss a test email.

Reads .env, connects to Gmail + Supabase, and prints:
  - enabled keyword rules
  - whether SOAR Review exists / can be created
  - UNSEEN (unread) INBOX messages and their triage scores
  - a sample of recent SEEN messages (already-read mail is never scanned)

Usage:
  python diagnose_inbox.py
"""

from __future__ import annotations

import sys

from config import SOAR_REVIEW_FOLDER, ConfigurationError, load_settings
from database import DatabaseError, fetch_keyword_rules, get_client
from gmail_client import GmailClient, GmailError
from logger import get_logger, setup_logging
from triage import is_suspicious, score_email

setup_logging()
logger = get_logger(__name__)

QUARANTINE_THRESHOLD = 1
RECENT_SEEN_LIMIT = 10
UNSEEN_DIAG_LIMIT = 25


def _print_section(title: str) -> None:
    print()
    print("=" * 60)
    print(title)
    print("=" * 60)


def main() -> int:
    try:
        settings = load_settings()
    except ConfigurationError as exc:
        print(f"CONFIG ERROR: {exc}")
        return 1

    try:
        client = get_client(settings)
        rules = fetch_keyword_rules(client, enabled_only=True)
    except DatabaseError as exc:
        print(f"DATABASE ERROR: {exc}")
        return 1

    _print_section(f"Enabled keyword rules ({len(rules)})")
    if not rules:
        print("WARNING: No enabled rules — every email will score 0 (clean).")
    else:
        for rule in rules:
            print(f"  - {rule.get('keyword')!r}  weight={rule.get('weight')}")

    try:
        with GmailClient(settings) as gmail:
            _print_section(f"Folder check: {SOAR_REVIEW_FOLDER!r}")
            gmail.ensure_folder(SOAR_REVIEW_FOLDER)
            print(f"OK — folder ready: {SOAR_REVIEW_FOLDER}")

            gmail.select_folder("INBOX", readonly=True)

            # Count UNSEEN cheaply before downloading bodies
            conn = gmail._require_conn()
            status, data = conn.uid("search", None, "UNSEEN")
            all_unseen = []
            if status == "OK" and data and data[0]:
                all_unseen = data[0].decode("utf-8", errors="replace").split()
            print(f"\nINBOX UNSEEN count: {len(all_unseen)}")

            unseen = gmail.fetch_unseen(limit=UNSEEN_DIAG_LIMIT)

            _print_section(
                f"Newest UNSEEN (unread) — showing {len(unseen)} of {len(all_unseen)}"
            )
            if not unseen:
                print(
                    "No unread messages. Scan Inbox only processes UNSEEN mail.\n"
                    "If your test email is already opened/read, mark it unread "
                    "in Gmail (right-click → Mark as unread) and re-run."
                )
            else:
                for msg in unseen:
                    result = score_email(msg.subject, msg.body, rules)
                    flag = "QUARANTINE" if is_suspicious(result, QUARANTINE_THRESHOLD) else "CLEAN"
                    print(f"  [{flag}] score={result.threat_score}  from={msg.sender}")
                    print(f"           subject={msg.subject!r}")
                    print(f"           matches={result.matched_keywords}")
                    print(f"           uid={msg.gmail_uid}  message_id={msg.message_id}")

            # Recent SEEN messages help explain "I sent a test but scan found 0"
            _print_section(f"Recent SEEN (already read) — up to {RECENT_SEEN_LIMIT}")
            print("(fetching newest read messages…)")
            seen_msgs = gmail.fetch_recent_seen(limit=RECENT_SEEN_LIMIT)
            if not seen_msgs:
                print("(none found)")
            else:
                for msg in seen_msgs:
                    result = score_email(msg.subject, msg.body, rules)
                    would = "would QUARANTINE" if is_suspicious(result, QUARANTINE_THRESHOLD) else "would be CLEAN"
                    print(f"  [{would}] score={result.threat_score}  subject={msg.subject!r}")
                    print(f"             from={msg.sender}  matches={result.matched_keywords}")

    except GmailError as exc:
        print(f"GMAIL ERROR: {exc}")
        return 1

    _print_section("Summary")
    print(
        "Scan Inbox picks up only UNSEEN mail whose score >= "
        f"{QUARANTINE_THRESHOLD} against enabled rules.\n"
        "Common misses:\n"
        "  1) Test email was opened → mark unread and scan again\n"
        "  2) Subject/body has none of the enabled keywords above\n"
        "  3) Message landed in Spam (not INBOX)\n"
        "  4) Matching rules were disabled in the sidebar"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
