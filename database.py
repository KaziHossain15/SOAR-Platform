"""Supabase PostgreSQL operations for the SOAR platform.

All database I/O is isolated here. Uses parameterized Supabase client calls.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from supabase import Client, create_client

from config import (
    STATUS_APPROVED,
    STATUS_DELETED,
    STATUS_PENDING,
    Settings,
)
from logger import get_logger

logger = get_logger(__name__)

TABLE_ALERTS = "alerts"
TABLE_KEYWORD_RULES = "keyword_rules"


class DatabaseError(Exception):
    """Raised when a Supabase operation fails."""


def get_client(settings: Settings) -> Client:
    """Create a Supabase client from settings."""
    try:
        client = create_client(settings.supabase_url, settings.supabase_key)
        logger.info("Supabase client initialized")
        return client
    except Exception as exc:
        logger.exception("Failed to initialize Supabase client")
        raise DatabaseError(f"Could not connect to Supabase: {exc}") from exc


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Keyword rules
# ---------------------------------------------------------------------------


def fetch_keyword_rules(
    client: Client,
    *,
    enabled_only: bool = False,
    search: Optional[str] = None,
) -> list[dict[str, Any]]:
    """Load keyword rules from Supabase.

    Args:
        client: Supabase client.
        enabled_only: If True, return only enabled rules.
        search: Optional case-insensitive keyword substring filter.
    """
    try:
        query = client.table(TABLE_KEYWORD_RULES).select("*")
        if enabled_only:
            query = query.eq("enabled", True)
        if search:
            query = query.ilike("keyword", f"%{search}%")
        response = query.order("keyword").execute()
        rows = response.data or []
        logger.info(
            "Fetched %d keyword rules (enabled_only=%s)",
            len(rows),
            enabled_only,
        )
        return rows
    except Exception as exc:
        logger.exception("Failed to fetch keyword rules")
        raise DatabaseError(f"Failed to load detection rules: {exc}") from exc


def insert_keyword_rule(
    client: Client,
    keyword: str,
    weight: int,
    enabled: bool = True,
) -> dict[str, Any]:
    """Insert a new keyword rule."""
    payload = {
        "keyword": keyword.strip(),
        "weight": weight,
        "enabled": enabled,
        "created_at": _utc_now_iso(),
    }
    try:
        response = client.table(TABLE_KEYWORD_RULES).insert(payload).execute()
        row = (response.data or [None])[0]
        logger.info("Created keyword rule keyword=%r weight=%s", keyword, weight)
        return row or payload
    except Exception as exc:
        logger.exception("Failed to insert keyword rule")
        raise DatabaseError(f"Failed to add rule: {exc}") from exc


def update_keyword_rule(
    client: Client,
    rule_id: str,
    *,
    keyword: Optional[str] = None,
    weight: Optional[int] = None,
    enabled: Optional[bool] = None,
) -> dict[str, Any]:
    """Update an existing keyword rule by id."""
    updates: dict[str, Any] = {}
    if keyword is not None:
        updates["keyword"] = keyword.strip()
    if weight is not None:
        updates["weight"] = weight
    if enabled is not None:
        updates["enabled"] = enabled
    if not updates:
        raise DatabaseError("No fields provided to update")

    try:
        response = (
            client.table(TABLE_KEYWORD_RULES)
            .update(updates)
            .eq("id", rule_id)
            .execute()
        )
        row = (response.data or [None])[0]
        logger.info("Updated keyword rule id=%s fields=%s", rule_id, list(updates))
        return row or updates
    except Exception as exc:
        logger.exception("Failed to update keyword rule id=%s", rule_id)
        raise DatabaseError(f"Failed to update rule: {exc}") from exc


def delete_keyword_rule(client: Client, rule_id: str) -> None:
    """Delete a keyword rule by id."""
    try:
        client.table(TABLE_KEYWORD_RULES).delete().eq("id", rule_id).execute()
        logger.info("Deleted keyword rule id=%s", rule_id)
    except Exception as exc:
        logger.exception("Failed to delete keyword rule id=%s", rule_id)
        raise DatabaseError(f"Failed to delete rule: {exc}") from exc


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------


def alert_exists(client: Client, gmail_uid: str) -> bool:
    """Return True if an alert with the given Gmail UID already exists."""
    try:
        response = (
            client.table(TABLE_ALERTS)
            .select("gmail_uid")
            .eq("gmail_uid", gmail_uid)
            .limit(1)
            .execute()
        )
        return bool(response.data)
    except Exception as exc:
        logger.exception("Failed to check alert existence uid=%s", gmail_uid)
        raise DatabaseError(f"Failed to check for duplicate alert: {exc}") from exc


def insert_alert(
    client: Client,
    *,
    gmail_uid: str,
    message_id: str,
    sender: str,
    subject: str,
    threat_score: int,
    matched_keywords: list[str],
    status: str = STATUS_PENDING,
    vt_score: int = 0,
    vt_malicious: int = 0,
    vt_suspicious: int = 0,
    vt_total: int = 0,
    vt_urls: Optional[list[str]] = None,
    vt_link: Optional[str] = None,
) -> Optional[dict[str, Any]]:
    """Insert a new alert, skipping silently if the UID already exists.

    Returns:
        Inserted row, or None if a duplicate was skipped.
    """
    if alert_exists(client, gmail_uid):
        logger.warning("Skipping duplicate alert gmail_uid=%s", gmail_uid)
        return None

    now = _utc_now_iso()
    payload = {
        "gmail_uid": gmail_uid,
        "message_id": message_id,
        "sender": sender,
        "subject": subject,
        "threat_score": threat_score,
        "matched_keywords": matched_keywords,
        "vt_score": int(vt_score or 0),
        "vt_malicious": int(vt_malicious or 0),
        "vt_suspicious": int(vt_suspicious or 0),
        "vt_total": int(vt_total or 0),
        "vt_urls": list(vt_urls or []),
        "vt_link": vt_link,
        "status": status,
        "created_at": now,
        "updated_at": now,
    }
    try:
        response = client.table(TABLE_ALERTS).insert(payload).execute()
        row = (response.data or [None])[0]
        logger.info(
            "Inserted alert gmail_uid=%s score=%s vt=%s status=%s",
            gmail_uid,
            threat_score,
            vt_score,
            status,
        )
        return row
    except Exception as exc:
        # Race: unique constraint may still fire
        err_text = str(exc).lower()
        if "duplicate" in err_text or "unique" in err_text or "23505" in err_text:
            logger.warning("Duplicate alert rejected by DB gmail_uid=%s", gmail_uid)
            return None
        logger.exception("Failed to insert alert gmail_uid=%s", gmail_uid)
        raise DatabaseError(f"Failed to create alert: {exc}") from exc


def fetch_pending_alerts(
    client: Client,
    *,
    sender_query: Optional[str] = None,
    subject_query: Optional[str] = None,
    sort_by: str = "created_at",
    ascending: bool = False,
) -> list[dict[str, Any]]:
    """Fetch PENDING alerts with optional filters and sorting."""
    allowed_sort = {"created_at", "threat_score", "sender", "subject"}
    if sort_by not in allowed_sort:
        sort_by = "created_at"

    try:
        query = (
            client.table(TABLE_ALERTS)
            .select("*")
            .eq("status", STATUS_PENDING)
        )
        if sender_query:
            query = query.ilike("sender", f"%{sender_query}%")
        if subject_query:
            query = query.ilike("subject", f"%{subject_query}%")
        response = query.order(sort_by, desc=not ascending).execute()
        rows = response.data or []
        logger.info("Fetched %d pending alerts", len(rows))
        return rows
    except Exception as exc:
        logger.exception("Failed to fetch pending alerts")
        raise DatabaseError(f"Failed to load alerts: {exc}") from exc


def update_alert_status(
    client: Client,
    gmail_uid: str,
    status: str,
) -> dict[str, Any]:
    """Update alert status and updated_at timestamp."""
    if status not in {STATUS_PENDING, STATUS_APPROVED, STATUS_DELETED}:
        raise DatabaseError(f"Invalid status: {status}")

    try:
        response = (
            client.table(TABLE_ALERTS)
            .update({"status": status, "updated_at": _utc_now_iso()})
            .eq("gmail_uid", gmail_uid)
            .execute()
        )
        row = (response.data or [None])[0]
        logger.info(
            "Alert state transition gmail_uid=%s -> %s",
            gmail_uid,
            status,
        )
        return row or {"gmail_uid": gmail_uid, "status": status}
    except Exception as exc:
        logger.exception("Failed to update alert status uid=%s", gmail_uid)
        raise DatabaseError(f"Failed to update alert status: {exc}") from exc


def update_alert_vt(
    client: Client,
    gmail_uid: str,
    *,
    vt_score: int = 0,
    vt_malicious: int = 0,
    vt_suspicious: int = 0,
    vt_total: int = 0,
    vt_urls: Optional[list[str]] = None,
    vt_link: Optional[str] = None,
) -> dict[str, Any]:
    """Persist VirusTotal fields for an existing alert."""
    payload = {
        "vt_score": int(vt_score or 0),
        "vt_malicious": int(vt_malicious or 0),
        "vt_suspicious": int(vt_suspicious or 0),
        "vt_total": int(vt_total or 0),
        "vt_urls": list(vt_urls or []),
        "vt_link": vt_link,
        "updated_at": _utc_now_iso(),
    }
    try:
        response = (
            client.table(TABLE_ALERTS)
            .update(payload)
            .eq("gmail_uid", gmail_uid)
            .execute()
        )
        row = (response.data or [None])[0]
        logger.info(
            "Updated VT fields gmail_uid=%s vt_score=%s urls=%s",
            gmail_uid,
            vt_score,
            len(vt_urls or []),
        )
        return row or {"gmail_uid": gmail_uid, **payload}
    except Exception as exc:
        logger.exception("Failed to update VT fields uid=%s", gmail_uid)
        raise DatabaseError(f"Failed to update VirusTotal fields: {exc}") from exc


def count_alerts_by_status(client: Client) -> dict[str, int]:
    """Return alert counts keyed by status (PENDING / APPROVED / DELETED)."""
    counts = {
        STATUS_PENDING: 0,
        STATUS_APPROVED: 0,
        STATUS_DELETED: 0,
    }
    try:
        for status in list(counts):
            response = (
                client.table(TABLE_ALERTS)
                .select("gmail_uid", count="exact")
                .eq("status", status)
                .execute()
            )
            counts[status] = int(response.count or 0)
        counts["total"] = sum(
            counts[s] for s in (STATUS_PENDING, STATUS_APPROVED, STATUS_DELETED)
        )
        logger.info("Alert counts=%s", counts)
        return counts
    except Exception as exc:
        logger.exception("Failed to count alerts")
        raise DatabaseError(f"Failed to count alerts: {exc}") from exc


def purge_resolved_alerts(
    client: Client,
    *,
    older_than_days: int = 0,
) -> int:
    """Delete APPROVED/DELETED alert rows (optionally older than N days).

    Args:
        older_than_days: If > 0, only delete rows with created_at older than
            this many days. If 0, delete all resolved alerts.

    Returns:
        Number of rows deleted (best-effort from response payload).
    """
    from datetime import timedelta

    try:
        query = (
            client.table(TABLE_ALERTS)
            .delete()
            .in_("status", [STATUS_APPROVED, STATUS_DELETED])
        )
        if older_than_days > 0:
            cutoff = datetime.now(timezone.utc) - timedelta(days=int(older_than_days))
            query = query.lt("created_at", cutoff.isoformat())

        response = query.execute()
        deleted = len(response.data or [])
        logger.info(
            "Purged %d resolved alerts (older_than_days=%s)",
            deleted,
            older_than_days,
        )
        return deleted
    except Exception as exc:
        logger.exception("Failed to purge resolved alerts")
        raise DatabaseError(f"Failed to purge resolved alerts: {exc}") from exc


def fetch_stale_pending_alerts(
    client: Client,
    *,
    older_than_days: int = 7,
) -> list[dict[str, Any]]:
    """Return PENDING alerts older than ``older_than_days``."""
    from datetime import timedelta

    if older_than_days < 1:
        raise DatabaseError("older_than_days must be >= 1 for pending expiry")

    cutoff = datetime.now(timezone.utc) - timedelta(days=int(older_than_days))
    try:
        response = (
            client.table(TABLE_ALERTS)
            .select("*")
            .eq("status", STATUS_PENDING)
            .lt("created_at", cutoff.isoformat())
            .order("created_at")
            .execute()
        )
        rows = response.data or []
        logger.info(
            "Found %d stale PENDING alerts older than %d days",
            len(rows),
            older_than_days,
        )
        return rows
    except Exception as exc:
        logger.exception("Failed to fetch stale pending alerts")
        raise DatabaseError(f"Failed to load stale pending alerts: {exc}") from exc


def delete_alert_row(client: Client, gmail_uid: str) -> bool:
    """Hard-delete an alert row from Supabase."""
    try:
        response = (
            client.table(TABLE_ALERTS)
            .delete()
            .eq("gmail_uid", gmail_uid)
            .execute()
        )
        deleted = bool(response.data)
        logger.info("Hard-deleted alert row gmail_uid=%s deleted=%s", gmail_uid, deleted)
        return deleted
    except Exception as exc:
        logger.exception("Failed to hard-delete alert uid=%s", gmail_uid)
        raise DatabaseError(f"Failed to delete alert row: {exc}") from exc


def purge_stale_pending_alerts(
    client: Client,
    *,
    older_than_days: int = 7,
) -> int:
    """Hard-delete PENDING alert rows older than N days (DB only)."""
    from datetime import timedelta

    if older_than_days < 1:
        raise DatabaseError("older_than_days must be >= 1 for pending expiry")

    cutoff = datetime.now(timezone.utc) - timedelta(days=int(older_than_days))
    try:
        response = (
            client.table(TABLE_ALERTS)
            .delete()
            .eq("status", STATUS_PENDING)
            .lt("created_at", cutoff.isoformat())
            .execute()
        )
        deleted = len(response.data or [])
        logger.info(
            "Purged %d stale PENDING alerts (older_than_days=%s)",
            deleted,
            older_than_days,
        )
        return deleted
    except Exception as exc:
        logger.exception("Failed to purge stale pending alerts")
        raise DatabaseError(f"Failed to purge stale pending alerts: {exc}") from exc


def clear_vt_fields_on_resolved(
    client: Client,
    *,
    older_than_days: int = 0,
) -> int:
    """Clear bulky VirusTotal URL fields on resolved alerts to reclaim space."""
    from datetime import timedelta

    payload = {
        "vt_urls": [],
        "vt_link": None,
        "updated_at": _utc_now_iso(),
    }
    try:
        query = (
            client.table(TABLE_ALERTS)
            .update(payload)
            .in_("status", [STATUS_APPROVED, STATUS_DELETED])
        )
        if older_than_days > 0:
            cutoff = datetime.now(timezone.utc) - timedelta(days=int(older_than_days))
            query = query.lt("created_at", cutoff.isoformat())

        response = query.execute()
        updated = len(response.data or [])
        logger.info(
            "Cleared VT URL fields on %d resolved alerts (older_than_days=%s)",
            updated,
            older_than_days,
        )
        return updated
    except Exception as exc:
        logger.exception("Failed to clear VT fields on resolved alerts")
        raise DatabaseError(f"Failed to clear VirusTotal fields: {exc}") from exc
