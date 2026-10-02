#!/usr/bin/env python3
"""Headless Scan Inbox run for schedulers (cron, AWS EventBridge + ECS task).

Runs the same scan / quarantine pipeline as the dashboard's Scan Inbox
button and exits non-zero on failure so the scheduler can alert.

Usage:
  python scan_job.py
"""

from __future__ import annotations

import sys

from config import ConfigurationError, load_settings
from database import DatabaseError, get_client
from gmail_client import GmailError
from logger import get_logger, setup_logging

setup_logging()
logger = get_logger("scan_job")


def main() -> int:
    from app import scan_inbox

    try:
        settings = load_settings()
        client = get_client(settings)
        stats = scan_inbox(settings, client)
    except (ConfigurationError, DatabaseError, GmailError) as exc:
        logger.error("Scheduled scan failed: %s", exc)
        return 1
    except Exception:
        logger.exception("Scheduled scan failed unexpectedly")
        return 1

    logger.info("Scheduled scan complete stats=%s", stats)
    return 0


if __name__ == "__main__":
    sys.exit(main())
