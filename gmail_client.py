"""Gmail IMAP client for email ingestion and quarantine workflows.

Uses SSL IMAP against imap.gmail.com. Prefers UID MOVE when available;
falls back to COPY + verify + DELETE + EXPUNGE.
"""

from __future__ import annotations

import email
import imaplib
import re
from dataclasses import dataclass
from email.header import decode_header, make_header
from email.message import Message
from typing import Optional

from config import (
    IMAP_HOST,
    IMAP_PORT,
    IMAP_TIMEOUT_SECONDS,
    SOAR_REVIEW_FOLDER,
    Settings,
)
from logger import get_logger

logger = get_logger(__name__)


class GmailError(Exception):
    """Raised when an IMAP / Gmail operation fails."""


@dataclass
class EmailMessage:
    """Parsed email fields used by the triage pipeline."""

    gmail_uid: str
    message_id: str
    sender: str
    subject: str
    body: str


class GmailClient:
    """Context-managed Gmail IMAP client."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._conn: Optional[imaplib.IMAP4_SSL] = None

    def __enter__(self) -> "GmailClient":
        self.connect()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.disconnect()

    # ------------------------------------------------------------------
    # Connection lifecycle
    # ------------------------------------------------------------------

    def connect(self) -> None:
        """Open an SSL IMAP session and authenticate."""
        try:
            logger.info(
                "Connecting to IMAP host=%s port=%s user=%s",
                IMAP_HOST,
                IMAP_PORT,
                self._settings.gmail_user,
            )
            self._conn = imaplib.IMAP4_SSL(
                IMAP_HOST,
                IMAP_PORT,
                timeout=IMAP_TIMEOUT_SECONDS,
            )
            self._conn.login(
                self._settings.gmail_user,
                self._settings.gmail_app_password,
            )
            logger.info("IMAP authentication succeeded")
        except imaplib.IMAP4.error as exc:
            logger.exception("IMAP authentication failed")
            raise GmailError(
                "Gmail authentication failed. Verify GMAIL_USER and "
                "GMAIL_APP_PASSWORD (use an App Password, not your account password)."
            ) from exc
        except (TimeoutError, OSError) as exc:
            logger.exception("IMAP network failure")
            raise GmailError(
                f"Could not reach Gmail IMAP ({IMAP_HOST}): {exc}"
            ) from exc
        except Exception as exc:
            logger.exception("Unexpected IMAP connection error")
            raise GmailError(f"IMAP connection failed: {exc}") from exc

    def disconnect(self) -> None:
        """Logout and close the IMAP connection if open."""
        if self._conn is None:
            return
        try:
            self._conn.logout()
            logger.info("IMAP session closed")
        except Exception:
            logger.warning("IMAP logout failed; connection may already be closed")
        finally:
            self._conn = None

    def _require_conn(self) -> imaplib.IMAP4_SSL:
        if self._conn is None:
            raise GmailError("IMAP client is not connected")
        return self._conn

    # ------------------------------------------------------------------
    # Folder helpers
    # ------------------------------------------------------------------

    def ensure_folder(self, folder: str = SOAR_REVIEW_FOLDER) -> None:
        """Create a mailbox folder if it does not already exist."""
        conn = self._require_conn()
        try:
            status, data = conn.list()
            if status != "OK":
                raise GmailError(f"Failed to list mailboxes: {status}")

            existing = set()
            for raw in data or []:
                if not raw:
                    continue
                line = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else str(raw)
                # IMAP LIST ends with the mailbox name (possibly quoted)
                name = line.rsplit(" ", 1)[-1].strip().strip('"')
                existing.add(name)

            if folder in existing:
                logger.info("Folder already exists: %s", folder)
                return

            create_status, _ = conn.create(folder)
            if create_status != "OK":
                # Race: another process may have created it
                logger.warning("CREATE returned %s for folder=%s", create_status, folder)
            else:
                logger.info("Created folder: %s", folder)
        except GmailError:
            raise
        except Exception as exc:
            logger.exception("Failed to ensure folder=%s", folder)
            raise GmailError(f"Could not create folder '{folder}': {exc}") from exc

    def select_folder(self, folder: str = "INBOX", readonly: bool = False) -> int:
        """Select a mailbox and return the message count."""
        conn = self._require_conn()
        try:
            status, data = conn.select(folder, readonly=readonly)
            if status != "OK":
                raise GmailError(f"Could not select folder '{folder}': {status}")
            count = int(data[0]) if data and data[0] else 0
            logger.info("Selected folder=%s messages=%s readonly=%s", folder, count, readonly)
            return count
        except GmailError:
            raise
        except Exception as exc:
            logger.exception("Failed to select folder=%s", folder)
            raise GmailError(f"Failed to select folder '{folder}': {exc}") from exc

    # ------------------------------------------------------------------
    # Fetch / parse
    # ------------------------------------------------------------------

    def fetch_unseen(self) -> list[EmailMessage]:
        """Fetch all UNSEEN messages from the currently selected folder."""
        conn = self._require_conn()
        try:
            status, data = conn.uid("search", None, "UNSEEN")
            if status != "OK":
                raise GmailError(f"UID SEARCH UNSEEN failed: {status}")

            uid_blob = data[0] if data else b""
            if not uid_blob:
                logger.info("No unseen messages found")
                return []

            uids = uid_blob.decode("utf-8", errors="replace").split()
            messages: list[EmailMessage] = []
            for uid in uids:
                parsed = self._fetch_uid(uid)
                if parsed is not None:
                    messages.append(parsed)

            logger.info("Fetched %d unseen messages", len(messages))
            return messages
        except GmailError:
            raise
        except Exception as exc:
            logger.exception("Failed to fetch unseen messages")
            raise GmailError(f"Failed to fetch unread emails: {exc}") from exc

    def _fetch_uid(self, uid: str) -> Optional[EmailMessage]:
        conn = self._require_conn()
        status, data = conn.uid("fetch", uid, "(RFC822)")
        if status != "OK" or not data or data[0] is None:
            logger.warning("Could not fetch UID=%s status=%s", uid, status)
            return None

        raw = data[0][1] if isinstance(data[0], tuple) else None
        if not isinstance(raw, (bytes, bytearray)):
            logger.warning("Unexpected FETCH payload for UID=%s", uid)
            return None

        msg = email.message_from_bytes(bytes(raw))
        return EmailMessage(
            gmail_uid=str(uid),
            message_id=_header_value(msg, "Message-ID") or f"uid-{uid}",
            sender=_header_value(msg, "From") or "unknown",
            subject=_header_value(msg, "Subject") or "(no subject)",
            body=_extract_body(msg),
        )

    # ------------------------------------------------------------------
    # Move / delete
    # ------------------------------------------------------------------

    def move_message(
        self,
        uid: str,
        destination: str,
        source: str = "INBOX",
        message_id: Optional[str] = None,
    ) -> str:
        """Move a message by UID from source to destination.

        Prefers UID MOVE. Falls back to COPY → verify → DELETE → EXPUNGE.
        Never deletes the original unless the copy succeeds.

        Returns:
            UID of the message in the destination folder (IMAP UIDs are
            per-mailbox; the destination UID often differs from ``uid``).
        """
        self.select_folder(source, readonly=False)
        conn = self._require_conn()

        # Prefer MOVE extension
        try:
            status, _ = conn.uid("MOVE", uid, destination)
            if status == "OK":
                logger.info(
                    "Moved UID=%s from %s to %s via MOVE",
                    uid,
                    source,
                    destination,
                )
                dest_uid = self.find_uid_by_message_id(message_id, destination) if message_id else None
                return dest_uid or uid
            logger.warning("UID MOVE returned %s; falling back to COPY/DELETE", status)
        except Exception as exc:
            logger.warning("UID MOVE unsupported or failed (%s); using COPY/DELETE", exc)

        return self._copy_then_delete(uid, destination, source, message_id)

    def _copy_then_delete(
        self,
        uid: str,
        destination: str,
        source: str,
        message_id: Optional[str] = None,
    ) -> str:
        conn = self._require_conn()
        self.select_folder(source, readonly=False)

        copy_status, _ = conn.uid("COPY", uid, destination)
        if copy_status != "OK":
            raise GmailError(
                f"Failed to copy UID={uid} to '{destination}': {copy_status}. "
                "Original left untouched."
            )

        dest_uid = None
        if message_id:
            dest_uid = self.find_uid_by_message_id(message_id, destination)
        if dest_uid is None:
            logger.warning(
                "Could not resolve destination UID after COPY for source UID=%s "
                "folder=%s; trusting COPY OK status",
                uid,
                destination,
            )

        # Re-select source before deleting the original
        self.select_folder(source, readonly=False)
        store_status, _ = conn.uid("STORE", uid, "+FLAGS", r"(\Deleted)")
        if store_status != "OK":
            raise GmailError(
                f"Copy succeeded but could not mark UID={uid} deleted: {store_status}"
            )

        expunge_status, _ = conn.expunge()
        if expunge_status != "OK":
            logger.warning("EXPUNGE returned %s after deleting UID=%s", expunge_status, uid)

        logger.info(
            "Moved UID=%s from %s to %s via COPY/DELETE/EXPUNGE (dest_uid=%s)",
            uid,
            source,
            destination,
            dest_uid,
        )
        return dest_uid or uid

    def find_uid_by_message_id(
        self,
        message_id: str,
        folder: str,
    ) -> Optional[str]:
        """Locate a message UID in ``folder`` by Message-ID header."""
        if not message_id:
            return None
        conn = self._require_conn()
        try:
            self.select_folder(folder, readonly=True)
            # HEADER search is widely supported on Gmail
            status, data = conn.uid("search", None, "HEADER", "Message-ID", message_id)
            if status == "OK" and data and data[0]:
                uids = data[0].decode("utf-8", errors="replace").split()
                if uids:
                    return uids[-1]

            # Fallback: scan recent messages' Message-ID headers
            status, data = conn.uid("search", None, "ALL")
            if status != "OK" or not data or not data[0]:
                return None
            uids = data[0].decode("utf-8", errors="replace").split()
            needle = message_id.encode("utf-8")
            for candidate in reversed(uids[-50:]):
                status, fetched = conn.uid(
                    "fetch",
                    candidate,
                    "(BODY.PEEK[HEADER.FIELDS (MESSAGE-ID)])",
                )
                if status != "OK" or not fetched:
                    continue
                blob = b""
                for part in fetched:
                    if isinstance(part, tuple) and len(part) > 1:
                        blob = part[1] or b""
                        break
                if needle in blob:
                    return candidate
            return None
        except Exception:
            logger.warning(
                "Message-ID lookup failed message_id=%s folder=%s",
                message_id,
                folder,
            )
            return None

    def delete_message(
        self,
        uid: str,
        folder: str = SOAR_REVIEW_FOLDER,
        message_id: Optional[str] = None,
    ) -> None:
        """Permanently delete a message from the given folder."""
        conn = self._require_conn()
        try:
            resolved = uid
            if message_id:
                found = self.find_uid_by_message_id(message_id, folder)
                if found:
                    resolved = found
            self.select_folder(folder, readonly=False)
            store_status, _ = conn.uid("STORE", resolved, "+FLAGS", r"(\Deleted)")
            if store_status != "OK":
                raise GmailError(f"Failed to mark UID={resolved} deleted: {store_status}")
            expunge_status, _ = conn.expunge()
            if expunge_status != "OK":
                raise GmailError(f"EXPUNGE failed for UID={resolved}: {expunge_status}")
            logger.info("Permanently deleted UID=%s from %s", resolved, folder)
        except GmailError:
            raise
        except Exception as exc:
            logger.exception("Failed to delete UID=%s from %s", uid, folder)
            raise GmailError(f"Failed to delete email: {exc}") from exc

    def return_to_inbox(
        self,
        uid: str,
        folder: str = SOAR_REVIEW_FOLDER,
        message_id: Optional[str] = None,
    ) -> None:
        """Move a quarantined message back to INBOX."""
        self.ensure_folder(folder)
        resolved = uid
        if message_id:
            found = self.find_uid_by_message_id(message_id, folder)
            if found:
                resolved = found
        self.move_message(
            resolved,
            destination="INBOX",
            source=folder,
            message_id=message_id,
        )
        logger.info("Returned UID=%s from %s to INBOX", resolved, folder)


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------


def _header_value(msg: Message, name: str) -> str:
    raw = msg.get(name, "")
    if not raw:
        return ""
    try:
        return str(make_header(decode_header(raw))).strip()
    except Exception:
        return str(raw).strip()


def _extract_body(msg: Message) -> str:
    """Extract a plain-text body, falling back to stripped HTML."""
    plain_parts: list[str] = []
    html_parts: list[str] = []

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            disposition = str(part.get("Content-Disposition") or "")
            if "attachment" in disposition.lower():
                continue
            payload = _decode_payload(part)
            if not payload:
                continue
            if content_type == "text/plain":
                plain_parts.append(payload)
            elif content_type == "text/html":
                html_parts.append(payload)
    else:
        payload = _decode_payload(msg)
        if msg.get_content_type() == "text/html":
            html_parts.append(payload)
        else:
            plain_parts.append(payload)

    if plain_parts:
        return "\n".join(plain_parts).strip()
    if html_parts:
        return _strip_html("\n".join(html_parts)).strip()
    return ""


def _decode_payload(part: Message) -> str:
    payload = part.get_payload(decode=True)
    if payload is None:
        raw = part.get_payload()
        return raw if isinstance(raw, str) else ""
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="replace")
    except Exception:
        return payload.decode("utf-8", errors="replace")


def _strip_html(html: str) -> str:
    text = re.sub(r"(?is)<(script|style).*?>.*?</\1>", " ", html)
    text = re.sub(r"(?s)<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text)
    return text
