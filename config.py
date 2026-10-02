"""Configuration and environment loading for the SOAR platform.

Credentials are never hardcoded. Values are loaded from environment
variables first, then Streamlit secrets as a fallback.
"""

from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass
from typing import Optional

from logger import get_logger, mask_email, register_secret

logger = get_logger(__name__)

# Load .env when present (local / Docker Compose). Never overrides existing env.
try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass

# Folder used for quarantined messages
SOAR_REVIEW_FOLDER = "SOAR Review"

# Alert status values (must match Supabase constraints)
STATUS_PENDING = "PENDING"
STATUS_APPROVED = "APPROVED"
STATUS_DELETED = "DELETED"

VALID_STATUSES = frozenset({STATUS_PENDING, STATUS_APPROVED, STATUS_DELETED})

# Threat score color thresholds
SCORE_LOW_MAX = 2
SCORE_MEDIUM_MAX = 4

# Keyword weight bounds for rule management
WEIGHT_MIN = 1
WEIGHT_MAX = 10

# IMAP
IMAP_HOST = "imap.gmail.com"
IMAP_PORT = 993
IMAP_TIMEOUT_SECONDS = 60


class ConfigurationError(Exception):
    """Raised when required configuration is missing or invalid."""


@dataclass(frozen=True)
class Settings:
    """Immutable application settings loaded from the environment."""

    supabase_url: str
    supabase_key: str
    gmail_user: str
    gmail_app_password: str
    virustotal_api_key: str = ""
    app_password: str = ""


def _supabase_key_role(key: str) -> Optional[str]:
    """Best-effort role detection for a Supabase API key (no verification)."""
    if key.startswith("sb_publishable_"):
        return "anon"
    if key.startswith("sb_secret_"):
        return "service_role"
    parts = key.split(".")
    if len(parts) != 3:
        return None
    try:
        padded = parts[1] + "=" * (-len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded))
        role = payload.get("role")
        return str(role) if role else None
    except Exception:
        return None


def _read_secret(key: str) -> Optional[str]:
    """Read a value from os.environ, then st.secrets if available."""
    value = os.environ.get(key)
    if value:
        return value.strip()

    try:
        import streamlit as st

        secrets = getattr(st, "secrets", None)
        if secrets is not None and key in secrets:
            raw = secrets[key]
            if raw is not None:
                return str(raw).strip()
    except Exception:
        # Streamlit may not be initialized outside the UI process
        pass

    return None


def load_settings() -> Settings:
    """Load and validate required configuration.

    Raises:
        ConfigurationError: If any required value is missing.
    """
    required = (
        "SUPABASE_URL",
        "SUPABASE_KEY",
        "GMAIL_USER",
        "GMAIL_APP_PASSWORD",
    )
    missing = [key for key in required if not _read_secret(key)]
    if missing:
        joined = ", ".join(missing)
        message = (
            f"Missing required configuration: {joined}. "
            "Set environment variables or Streamlit secrets "
            "(SUPABASE_URL, SUPABASE_KEY, GMAIL_USER, GMAIL_APP_PASSWORD)."
        )
        logger.error("Configuration incomplete: missing %s", joined)
        raise ConfigurationError(message)

    supabase_key = _read_secret("SUPABASE_KEY") or ""
    if _supabase_key_role(supabase_key) == "anon":
        logger.error("SUPABASE_KEY is a public anon/publishable key; refusing to start")
        raise ConfigurationError(
            "SUPABASE_KEY is the public anon/publishable key. Tables are locked "
            "down to the service role — set SUPABASE_KEY to the service_role / "
            "secret key (Supabase → Project Settings → API) and keep it server-side."
        )

    vt_key = _read_secret("VIRUSTOTAL_API_KEY") or ""
    settings = Settings(
        supabase_url=_read_secret("SUPABASE_URL") or "",
        supabase_key=supabase_key,
        gmail_user=_read_secret("GMAIL_USER") or "",
        gmail_app_password=_read_secret("GMAIL_APP_PASSWORD") or "",
        virustotal_api_key=vt_key,
        app_password=_read_secret("APP_PASSWORD") or "",
    )
    for secret in (
        settings.supabase_key,
        settings.gmail_app_password,
        settings.virustotal_api_key,
        settings.app_password,
    ):
        register_secret(secret)

    logger.info(
        "Configuration loaded for Gmail user=%s supabase_host=%s virustotal=%s",
        mask_email(settings.gmail_user),
        settings.supabase_url.split("//")[-1].split("/")[0] if settings.supabase_url else "unknown",
        "configured" if settings.virustotal_api_key else "disabled",
    )
    return settings
