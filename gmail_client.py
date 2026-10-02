"""Gmail IMAP client for email ingestion and quarantine workflows.

Uses SSL IMAP against imap.gmail.com. Prefers UID MOVE when available;
falls back to COPY + verify + DELETE + EXPUNGE.
"""

from __future__ import annotations

import email
import imaplib
import re
from dataclasses import dataclass, field
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
from logger import get_logger, mask_email

logger = get_logger(__name__)

# Partial-fetch cap so a single oversized message cannot exhaust memory/CPU.
MAX_MESSAGE_BYTES = 5 * 1024 * 1024
# Cap HTML fed to regex-based tag stripping (pathological markup is quadratic).
MAX_HTML_CHARS = 1_000_000

# Message-IDs are attacker-controlled and are sent to IMAP SEARCH; only allow
# the RFC 5322 msg-id shape with printable ASCII and no quote/backslash.
_MSGID_RE = re.compile(r"^<[\x21-\x7e]{1,900}>$")
_UID_RE = re.compile(r"^\d{1,20}$")


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
    html: str = ""
    urls: list[str] = field(default_factory=list)


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
                mask_email(self._settings.gmail_user),
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
                name = _mailbox_from_list_line(line)
                if name:
                    existing.add(name)

            if folder in existing:
                logger.info("Folder already exists: %s", folder)
                return

            create_status, create_data = conn.create(_quote_mailbox(folder))
            if create_status != "OK":
                detail = " ".join(
                    d.decode("utf-8", errors="replace") if isinstance(d, bytes) else str(d)
                    for d in (create_data or [])
                )
                if "ALREADYEXISTS" in detail.upper():
                    logger.info("Folder already exists (CREATE race): %s", folder)
                else:
                    logger.warning(
                        "CREATE returned %s for folder=%s data=%s",
                        create_status,
                        folder,
                        create_data,
                    )
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
            status, data = conn.select(_quote_mailbox(folder), readonly=readonly)
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

    def fetch_unseen(self, limit: Optional[int] = None) -> list[EmailMessage]:
        """Fetch UNSEEN messages without marking them as read.

        Args:
            limit: If set, only return the newest N unseen messages
                (avoids downloading a huge backlog on large inboxes).
        """
        return self._fetch_by_search("UNSEEN", limit=limit)

    def fetch_unseen_in_recent(
        self,
        lookback: int = 50,
    ) -> tuple[list[EmailMessage], dict[str, int]]:
        """Fetch UNSEEN messages among the newest ``lookback`` emails.

        Uses sequence-number FETCH for only the recent window — never
        ``SEARCH ALL`` / full-mailbox ``SEARCH UNSEEN``, which OOM on
        large Gmail inboxes (50k+ messages).
        """
        conn = self._require_conn()
        meta = {"recent_total": 0, "unseen_in_lookback": 0}
        try:
            exists = self._selected_message_count()
            if exists <= 0:
                return [], meta

            start = max(1, exists - lookback + 1)
            end = exists
            seq_set = f"{start}:{end}"
            status, data = conn.fetch(seq_set, "(UID FLAGS)")
            if status != "OK" or not data:
                raise GmailError(f"FETCH {seq_set} UID FLAGS failed: {status}")

            unseen_uids = _uids_without_seen(data)
            meta["recent_total"] = end - start + 1
            meta["unseen_in_lookback"] = len(unseen_uids)

            messages: list[EmailMessage] = []
            for uid in unseen_uids:
                parsed = self._fetch_uid(uid)
                if parsed is not None:
                    messages.append(parsed)

            logger.info(
                "Lookback=%d seq=%s recent=%d unseen_in_window=%d fetched=%d",
                lookback,
                seq_set,
                meta["recent_total"],
                meta["unseen_in_lookback"],
                len(messages),
            )
            return messages, meta
        except GmailError:
            raise
        except Exception as exc:
            logger.exception("Failed fetch_unseen_in_recent lookback=%s", lookback)
            raise GmailError(
                f"Failed to fetch recent unread emails: {exc}"
            ) from exc

    def _selected_message_count(self) -> int:
        """Return EXISTS count for the currently selected mailbox."""
        conn = self._require_conn()
        # imaplib stores the last EXISTS in untagged_responses after SELECT
        raw = conn.untagged_responses.get("EXISTS", [b"0"])[-1]
        try:
            return int(raw)
        except (TypeError, ValueError):
            return 0

    def fetch_recent_seen(self, limit: int = 10) -> list[EmailMessage]:
        """Fetch the most recent SEEN messages (diagnostic: already-read mail)."""
        return self._fetch_by_search("SEEN", limit=limit)

    def _fetch_by_search(
        self,
        criterion: str,
        limit: Optional[int] = None,
    ) -> list[EmailMessage]:
        conn = self._require_conn()
        try:
            status, data = conn.uid("search", None, criterion)
            if status != "OK":
                raise GmailError(f"UID SEARCH {criterion} failed: {status}")

            uid_blob = data[0] if data else b""
            if not uid_blob:
                logger.info("No messages matched SEARCH %s", criterion)
                return []

            uids = uid_blob.decode("utf-8", errors="replace").split()
            if limit is not None and limit > 0:
                uids = uids[-limit:]

            messages: list[EmailMessage] = []
            for uid in uids:
                parsed = self._fetch_uid(uid)
                if parsed is not None:
                    messages.append(parsed)

            logger.info(
                "Fetched %d messages for SEARCH %s (limit=%s)",
                len(messages),
                criterion,
                limit,
            )
            return messages
        except GmailError:
            raise
        except Exception as exc:
            logger.exception("Failed SEARCH %s", criterion)
            raise GmailError(f"Failed to fetch emails ({criterion}): {exc}") from exc

    def _fetch_uid(self, uid: str) -> Optional[EmailMessage]:
        """Fetch a message by UID without setting \\Seen (BODY.PEEK)."""
        uid = _require_uid(uid)
        conn = self._require_conn()
        # RFC822 sets \\Seen; BODY.PEEK[] leaves unread mail unread so a
        # clean score does not silently remove the message from UNSEEN.
        status, data = conn.uid("fetch", uid, f"(BODY.PEEK[]<0.{MAX_MESSAGE_BYTES}>)")
        if status != "OK" or not data or data[0] is None:
            logger.warning("Could not fetch UID=%s status=%s", uid, status)
            return None

        raw = _extract_fetch_bytes(data)
        if raw is None:
            logger.warning("Unexpected FETCH payload for UID=%s", uid)
            return None

        msg = email.message_from_bytes(raw)
        subject = _header_value(msg, "Subject") or "(no subject)"
        body, html = _extract_body_and_html(msg)
        from virustotal import extract_urls

        urls = extract_urls(subject, body, html, limit=20)
        return EmailMessage(
            gmail_uid=str(uid),
            message_id=_safe_message_id(_header_value(msg, "Message-ID")) or f"uid-{uid}",
            sender=_header_value(msg, "From") or "unknown",
            subject=subject,
            body=body,
            html=html,
            urls=urls,
        )

    # ------------------------------------------------------------------
    # Move / delete
    # ------------------------------------------------------------------

    def fetch_message(
        self,
        uid: str,
        folder: str = SOAR_REVIEW_FOLDER,
        message_id: Optional[str] = None,
    ) -> Optional[EmailMessage]:
        """Fetch a single message from ``folder`` by UID (Message-ID fallback)."""
        try:
            resolved = self._resolve_uid(uid, folder, message_id)
        except GmailError as exc:
            logger.warning("fetch_message could not resolve uid=%s: %s", uid, exc)
            return None
        self.select_folder(folder, readonly=True)
        return self._fetch_uid(resolved)

    def _message_id_at_uid(self, uid: str) -> Optional[str]:
        """Return the Message-ID at ``uid`` in the selected folder.

        Returns ``None`` if the UID does not exist, ``""`` if the message has
        no usable Message-ID header.
        """
        conn = self._require_conn()
        status, fetched = conn.uid(
            "fetch",
            _require_uid(uid),
            "(BODY.PEEK[HEADER.FIELDS (MESSAGE-ID)])",
        )
        if status != "OK" or not fetched:
            return None
        blob = _extract_fetch_bytes(fetched)
        if blob is None:
            return None
        header_msg = email.message_from_bytes(blob)
        return _safe_message_id(_header_value(header_msg, "Message-ID")) or ""

    def _resolve_uid(
        self,
        uid: str,
        folder: str,
        message_id: Optional[str] = None,
    ) -> str:
        """Resolve the UID to act on in ``folder``, verifying its identity.

        The stored UID is preferred and accepted only if the message there
        still carries the expected Message-ID. Message-ID lookup is a fallback
        and must match exactly one message, so a spoofed duplicate
        Message-ID cannot redirect approve/delete to a different email.
        """
        safe_mid = _safe_message_id(message_id)
        self.select_folder(folder, readonly=True)

        if _UID_RE.match(str(uid).strip()):
            current = self._message_id_at_uid(str(uid).strip())
            if current is not None and (safe_mid is None or current == safe_mid):
                return str(uid).strip()

        if safe_mid:
            found = self.find_uid_by_message_id(safe_mid, folder)
            if found:
                return found

        raise GmailError(
            f"Could not locate the quarantined message (uid={str(uid)[:20]}) "
            f"in '{folder}'. It may have been moved or deleted in Gmail."
        )

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
        uid = _require_uid(uid)
        self.select_folder(source, readonly=False)
        conn = self._require_conn()

        # Prefer MOVE extension
        try:
            status, _ = conn.uid("MOVE", uid, _quote_mailbox(destination))
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
        uid = _require_uid(uid)
        conn = self._require_conn()
        self.select_folder(source, readonly=False)

        copy_status, _ = conn.uid("COPY", uid, _quote_mailbox(destination))
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
        """Locate a message UID in ``folder`` by exact Message-ID match.

        Returns ``None`` when the Message-ID is malformed, not found, or
        ambiguous (more than one message carries it).
        """
        safe_mid = _safe_message_id(message_id)
        if not safe_mid:
            return None
        conn = self._require_conn()
        try:
            self.select_folder(folder, readonly=True)
            # HEADER search is a substring match; confirm each hit exactly.
            status, data = conn.uid(
                "search", None, "HEADER", "Message-ID", f'"{safe_mid}"'
            )
            candidates: list[str] = []
            if status == "OK" and data and data[0]:
                candidates = _parse_uid_list(data[0])
            if not candidates:
                # Fallback: scan the newest messages' Message-ID headers
                status, data = conn.uid("search", None, "ALL")
                if status != "OK" or not data or not data[0]:
                    return None
                candidates = _parse_uid_list(data[0])[-50:]

            matches = [
                uid for uid in candidates if self._message_id_at_uid(uid) == safe_mid
            ]
            if len(matches) == 1:
                return matches[0]
            if len(matches) > 1:
                logger.warning(
                    "Ambiguous Message-ID in folder=%s (%d matches); refusing to pick one",
                    folder,
                    len(matches),
                )
            return None
        except Exception:
            logger.warning("Message-ID lookup failed folder=%s", folder)
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
            resolved = self._resolve_uid(uid, folder, message_id)
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
        resolved = self._resolve_uid(uid, folder, message_id)
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


def _safe_message_id(value: Optional[str]) -> Optional[str]:
    """Return ``value`` if it is a well-formed, IMAP-safe Message-ID."""
    v = (value or "").strip()
    if not _MSGID_RE.match(v) or '"' in v or "\\" in v:
        return None
    return v


def _require_uid(uid: object) -> str:
    """Validate an IMAP UID before it is interpolated into a command."""
    s = str(uid).strip()
    if not _UID_RE.match(s):
        raise GmailError(f"Invalid IMAP UID: {s[:40]!r}")
    return s


def _parse_uid_list(blob: bytes | str) -> list[str]:
    text = blob.decode("utf-8", errors="replace") if isinstance(blob, bytes) else str(blob)
    return [u for u in text.split() if _UID_RE.match(u)]


def _quote_mailbox(name: str) -> str:
    """Quote an IMAP mailbox name when required.

    Modern CPython imaplib concatenates CREATE/SELECT args without quoting,
    so names with spaces (e.g. ``SOAR Review``) must be quoted by callers.
    """
    if not name or name.upper() == "INBOX":
        return name or "INBOX"
    stripped = name.strip()
    if len(stripped) >= 2 and stripped[0] == '"' and stripped[-1] == '"':
        return stripped
    escaped = stripped.replace("\\", "\\\\").replace('"', '\\"')
    if re.search(r'[\s(){%*\\\"]', stripped):
        return f'"{escaped}"'
    return stripped


def _extract_fetch_bytes(data: list) -> Optional[bytes]:
    """Pull raw message bytes from an IMAP FETCH response payload."""
    for item in data or []:
        if isinstance(item, tuple) and len(item) >= 2:
            payload = item[1]
            if isinstance(payload, (bytes, bytearray)):
                return bytes(payload)
    return None


def _uids_without_seen(fetch_data: list) -> list[str]:
    """Parse ``FETCH (UID FLAGS)`` rows and return UIDs missing \\Seen.

    Preserves ascending sequence order (oldest → newest within the window).
    """
    uids: list[str] = []
    for item in fetch_data or []:
        if item is None or item == b")":
            continue
        if isinstance(item, tuple):
            header = item[0]
        else:
            header = item
        if not isinstance(header, (bytes, bytearray)):
            continue
        line = header.decode("utf-8", errors="replace")
        uid_match = re.search(r"\bUID\s+(\d+)\b", line, re.IGNORECASE)
        if not uid_match:
            continue
        flags_match = re.search(r"FLAGS\s*\(([^)]*)\)", line, re.IGNORECASE)
        flags = (flags_match.group(1) if flags_match else "").upper()
        if "\\SEEN" in flags:
            continue
        uids.append(uid_match.group(1))
    return uids


def _mailbox_from_list_line(line: str) -> str:
    """Extract the mailbox name from an IMAP LIST response line.

    Formats look like: ``(\\HasNoChildren) "/" "SOAR Review"`` or
    ``(\\HasNoChildren) "/" INBOX``. A naive ``rsplit`` breaks on spaces
    inside quoted names.
    """
    line = line.strip()
    if not line:
        return ""

    # Prefer a trailing quoted mailbox (handles spaces).
    if line.endswith('"'):
        i = len(line) - 2
        while i >= 0:
            if line[i] == '"' and (i == 0 or line[i - 1] != "\\"):
                raw = line[i + 1 : -1]
                return raw.replace('\\"', '"').replace("\\\\", "\\")
            i -= 1

    return line.rsplit(" ", 1)[-1].strip().strip('"')


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
    body, _html = _extract_body_and_html(msg)
    return body


def _extract_body_and_html(msg: Message) -> tuple[str, str]:
    """Return ``(plain_or_stripped_text, raw_html)`` for link scanning."""
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

    html = "\n".join(html_parts).strip()
    if plain_parts:
        body = "\n".join(plain_parts).strip()
    elif html:
        body = _strip_html(html).strip()
    else:
        body = ""
    return body, html


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
    """Strip tags but keep discovered http(s) links appended for triage/VT."""
    from virustotal import extract_urls

    html = html[:MAX_HTML_CHARS]
    preserved = extract_urls(html, limit=50)
    text = re.sub(r"(?is)<(script|style).*?>.*?</\1>", " ", html)
    text = re.sub(r"(?s)<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    if preserved:
        # Ensure link destinations survive even if only present in href=.
        text = f"{text}\n" + "\n".join(preserved)
    return text
