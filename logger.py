"""Structured logging for the SOAR platform.

Never logs credentials or secrets. Use get_logger(__name__) in each module.
"""

from __future__ import annotations

import logging
import sys
from typing import Optional

_CONFIGURED = False

# Fields that must never appear in log output
_SENSITIVE_KEYS = frozenset(
    {
        "password",
        "app_password",
        "gmail_app_password",
        "supabase_key",
        "api_key",
        "secret",
        "token",
        "authorization",
        "credential",
    }
)


_REDACTED = "***REDACTED***"
_SECRET_VALUES: set[str] = set()


def register_secret(value: Optional[str]) -> None:
    """Mask ``value`` wherever it appears in subsequent log output."""
    if value and len(value) >= 6:
        _SECRET_VALUES.add(value)


def mask_email(address: Optional[str]) -> str:
    """Return ``j***@example.com`` style masking for log output."""
    if not address or "@" not in address:
        return "***"
    local, _, domain = address.partition("@")
    return f"{local[:1]}***@{domain}"


class _RedactingFilter(logging.Filter):
    """Redact secret extras and any registered secret values in messages."""

    def filter(self, record: logging.LogRecord) -> bool:
        for key in list(record.__dict__):
            if key.lower() in _SENSITIVE_KEYS:
                record.__dict__[key] = _REDACTED
        if _SECRET_VALUES:
            try:
                message = record.getMessage()
            except Exception:
                return True
            redacted = message
            for secret in _SECRET_VALUES:
                if secret in redacted:
                    redacted = redacted.replace(secret, _REDACTED)
            if redacted != message:
                record.msg = redacted
                record.args = None
        return True


def setup_logging(level: int = logging.INFO) -> None:
    """Configure root logger once for the application process."""
    global _CONFIGURED
    if _CONFIGURED:
        return

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(
        logging.Formatter(
            fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
    )
    handler.addFilter(_RedactingFilter())

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)

    # Quiet noisy third-party loggers
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)

    _CONFIGURED = True


def get_logger(name: Optional[str] = None) -> logging.Logger:
    """Return a named logger, ensuring logging is configured."""
    setup_logging()
    return logging.getLogger(name or "soar")
