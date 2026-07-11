"""SOAR Platform — Streamlit UI and orchestration.

Scan Gmail, triage with keyword rules, quarantine to SOAR Review,
and support human approve / delete workflows.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

import streamlit as st
from supabase import Client

from config import (
    SCORE_LOW_MAX,
    SCORE_MEDIUM_MAX,
    SOAR_REVIEW_FOLDER,
    STATUS_APPROVED,
    STATUS_DELETED,
    WEIGHT_MAX,
    WEIGHT_MIN,
    ConfigurationError,
    Settings,
    load_settings,
)
from database import (
    DatabaseError,
    delete_keyword_rule,
    fetch_keyword_rules,
    fetch_pending_alerts,
    get_client,
    insert_alert,
    insert_keyword_rule,
    update_alert_status,
    update_keyword_rule,
)
from gmail_client import GmailClient, GmailError
from logger import get_logger, setup_logging
from triage import is_suspicious, score_email

setup_logging()
logger = get_logger(__name__)

# Quarantine when score meets this threshold
QUARANTINE_THRESHOLD = 1

PAGE_TITLE = "SOAR Email Triage"
PAGE_ICON = "🛡️"


# ---------------------------------------------------------------------------
# Bootstrap
# ---------------------------------------------------------------------------


def _init_page() -> None:
    st.set_page_config(
        page_title=PAGE_TITLE,
        page_icon=PAGE_ICON,
        layout="wide",
        initial_sidebar_state="expanded",
    )
    st.markdown(
        """
        <style>
        .alert-card {
            border: 1px solid #d0d7de;
            border-radius: 10px;
            padding: 1rem 1.25rem;
            margin-bottom: 1rem;
            background: #ffffff;
        }
        .kw-badge {
            display: inline-block;
            padding: 0.15rem 0.55rem;
            margin: 0.15rem 0.25rem 0.15rem 0;
            border-radius: 999px;
            background: #eef2ff;
            color: #3730a3;
            font-size: 0.85rem;
            border: 1px solid #c7d2fe;
        }
        .score-green { color: #15803d; font-weight: 700; }
        .score-yellow { color: #a16207; font-weight: 700; }
        .score-red { color: #b91c1c; font-weight: 700; }
        </style>
        """,
        unsafe_allow_html=True,
    )


@st.cache_resource(show_spinner=False)
def _cached_settings() -> Settings:
    return load_settings()


@st.cache_resource(show_spinner=False)
def _cached_db(url: str, key: str) -> Client:
    return get_client(Settings(url, key, gmail_user="", gmail_app_password=""))


def get_runtime() -> tuple[Settings, Client]:
    """Load settings and Supabase client, surfacing friendly errors."""
    try:
        settings = _cached_settings()
        client = _cached_db(settings.supabase_url, settings.supabase_key)
        return settings, client
    except ConfigurationError as exc:
        st.error(str(exc))
        st.stop()
        raise  # unreachable; satisfies type checkers
    except DatabaseError as exc:
        st.error(str(exc))
        st.stop()
        raise


# ---------------------------------------------------------------------------
# Display helpers
# ---------------------------------------------------------------------------


def score_css_class(score: int) -> str:
    if score <= SCORE_LOW_MAX:
        return "score-green"
    if score <= SCORE_MEDIUM_MAX:
        return "score-yellow"
    return "score-red"


def score_emoji(score: int) -> str:
    if score <= SCORE_LOW_MAX:
        return "🟢"
    if score <= SCORE_MEDIUM_MAX:
        return "🟡"
    return "🔴"


def format_timestamp(value: Any) -> str:
    if not value:
        return "—"
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d %H:%M:%S UTC")
    text = str(value)
    try:
        cleaned = text.replace("Z", "+00:00")
        dt = datetime.fromisoformat(cleaned)
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return text


def _html(text: str) -> str:
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def render_keyword_badges(keywords: Optional[list[str]]) -> str:
    if not keywords:
        return "<em>None</em>"
    return " ".join(f'<span class="kw-badge">{_html(k)}</span>' for k in keywords)


# ---------------------------------------------------------------------------
# Scan / quarantine orchestration
# ---------------------------------------------------------------------------


def scan_inbox(settings: Settings, client: Client) -> dict[str, int]:
    """Scan UNSEEN mail, score with fresh rules, quarantine suspicious mail.

    Rules are always reloaded from Supabase — never cached between scans.
    """
    stats = {"scanned": 0, "quarantined": 0, "skipped_dup": 0, "clean": 0}

    rules = fetch_keyword_rules(client, enabled_only=True)
    logger.info("Scan starting with %d enabled rules", len(rules))

    with GmailClient(settings) as gmail:
        gmail.ensure_folder(SOAR_REVIEW_FOLDER)
        gmail.select_folder("INBOX", readonly=False)
        messages = gmail.fetch_unseen()
        stats["scanned"] = len(messages)

        for msg in messages:
            result = score_email(msg.subject, msg.body, rules)
            if not is_suspicious(result, QUARANTINE_THRESHOLD):
                stats["clean"] += 1
                continue

            # Move first; persist the destination UID (IMAP UIDs are per-folder)
            dest_uid = gmail.move_message(
                msg.gmail_uid,
                destination=SOAR_REVIEW_FOLDER,
                source="INBOX",
                message_id=msg.message_id,
            )
            # Re-select INBOX for subsequent unseen processing
            gmail.select_folder("INBOX", readonly=False)

            inserted = insert_alert(
                client,
                gmail_uid=dest_uid,
                message_id=msg.message_id,
                sender=msg.sender,
                subject=msg.subject,
                threat_score=result.threat_score,
                matched_keywords=result.matched_keywords,
            )
            if inserted is None:
                stats["skipped_dup"] += 1
            else:
                stats["quarantined"] += 1
                logger.info(
                    "Quarantined uid=%s score=%s keywords=%s",
                    dest_uid,
                    result.threat_score,
                    result.matched_keywords,
                )

    return stats


def approve_alert(settings: Settings, client: Client, alert: dict[str, Any]) -> None:
    """Return email to Inbox and mark alert APPROVED."""
    uid = alert["gmail_uid"]
    message_id = alert.get("message_id") or ""
    with GmailClient(settings) as gmail:
        gmail.return_to_inbox(uid, folder=SOAR_REVIEW_FOLDER, message_id=message_id)
    update_alert_status(client, uid, STATUS_APPROVED)


def delete_alert(settings: Settings, client: Client, alert: dict[str, Any]) -> None:
    """Permanently delete email from SOAR Review and mark alert DELETED."""
    uid = alert["gmail_uid"]
    message_id = alert.get("message_id") or ""
    with GmailClient(settings) as gmail:
        gmail.delete_message(
            uid,
            folder=SOAR_REVIEW_FOLDER,
            message_id=message_id,
        )
    update_alert_status(client, uid, STATUS_DELETED)


# ---------------------------------------------------------------------------
# Sidebar — Detection Rules
# ---------------------------------------------------------------------------


def render_detection_rules_sidebar(client: Client) -> None:
    st.sidebar.header("Detection Rules")
    st.sidebar.caption("Manage keyword rules without code changes.")

    search = st.sidebar.text_input(
        "Search rules",
        key="rule_search",
        placeholder="Filter keywords…",
    )

    try:
        rules = fetch_keyword_rules(client, search=search or None)
    except DatabaseError as exc:
        st.sidebar.error(str(exc))
        return

    if rules:
        display_rows = [
            {
                "Keyword": r.get("keyword", ""),
                "Weight": r.get("weight", 0),
                "Enabled": bool(r.get("enabled", True)),
            }
            for r in rules
        ]
        st.sidebar.dataframe(display_rows, use_container_width=True, hide_index=True)
    else:
        st.sidebar.info("No rules found. Add one below.")

    st.sidebar.divider()

    with st.sidebar.expander("➕ Add Rule", expanded=False):
        with st.form("add_rule_form", clear_on_submit=True):
            new_kw = st.text_input("Keyword")
            new_weight = st.number_input(
                "Weight",
                min_value=WEIGHT_MIN,
                max_value=WEIGHT_MAX,
                value=2,
                step=1,
            )
            new_enabled = st.checkbox("Enabled", value=True)
            if st.form_submit_button("Save Rule", use_container_width=True):
                if not new_kw.strip():
                    st.warning("Keyword is required.")
                else:
                    try:
                        insert_keyword_rule(
                            client,
                            new_kw.strip(),
                            int(new_weight),
                            new_enabled,
                        )
                        st.success(f"Added rule: {new_kw.strip()}")
                        st.rerun()
                    except DatabaseError as exc:
                        st.error(str(exc))

    with st.sidebar.expander("✏ Edit Rule", expanded=False):
        if not rules:
            st.caption("No rules to edit.")
        else:
            options = {
                f"{r.get('keyword')} (weight={r.get('weight')})": r for r in rules
            }
            selected_label = st.selectbox(
                "Select rule",
                list(options.keys()),
                key="edit_select",
            )
            selected = options[selected_label]
            with st.form("edit_rule_form"):
                edit_kw = st.text_input("Keyword", value=selected.get("keyword", ""))
                edit_weight = st.number_input(
                    "Weight",
                    min_value=WEIGHT_MIN,
                    max_value=WEIGHT_MAX,
                    value=int(selected.get("weight") or 1),
                    step=1,
                )
                edit_enabled = st.checkbox(
                    "Enabled",
                    value=bool(selected.get("enabled", True)),
                )
                if st.form_submit_button("Update Rule", use_container_width=True):
                    try:
                        update_keyword_rule(
                            client,
                            selected["id"],
                            keyword=edit_kw.strip(),
                            weight=int(edit_weight),
                            enabled=edit_enabled,
                        )
                        st.success("Rule updated.")
                        st.rerun()
                    except DatabaseError as exc:
                        st.error(str(exc))

    with st.sidebar.expander("🗑 Delete Rule", expanded=False):
        if not rules:
            st.caption("No rules to delete.")
        else:
            del_options = {
                f"{r.get('keyword')} (id={str(r.get('id'))[:8]}…)": r for r in rules
            }
            del_label = st.selectbox(
                "Select rule",
                list(del_options.keys()),
                key="del_select",
            )
            if st.button("Confirm Delete", type="primary", use_container_width=True):
                try:
                    delete_keyword_rule(client, del_options[del_label]["id"])
                    st.success("Rule deleted.")
                    st.rerun()
                except DatabaseError as exc:
                    st.error(str(exc))

    with st.sidebar.expander("Toggle Enabled", expanded=False):
        if not rules:
            st.caption("No rules to toggle.")
        else:
            for rule in rules:
                rid = rule["id"]
                label = f"{rule.get('keyword')} (w={rule.get('weight')})"
                current = bool(rule.get("enabled", True))
                new_val = st.checkbox(label, value=current, key=f"toggle_{rid}")
                if new_val != current:
                    try:
                        update_keyword_rule(client, rid, enabled=new_val)
                        logger.info("Toggled rule id=%s enabled=%s", rid, new_val)
                        st.rerun()
                    except DatabaseError as exc:
                        st.error(str(exc))


# ---------------------------------------------------------------------------
# Main dashboard
# ---------------------------------------------------------------------------


def render_filters() -> tuple[str, str, str, bool, bool]:
    st.subheader("Pending Alerts")
    c1, c2, c3, c4 = st.columns([2, 2, 2, 1])
    with c1:
        sender_q = st.text_input(
            "Search by sender",
            key="sender_q",
            placeholder="sender@…",
        )
    with c2:
        subject_q = st.text_input(
            "Search by subject",
            key="subject_q",
            placeholder="subject…",
        )
    with c3:
        sort_choice = st.selectbox(
            "Sort by",
            options=[
                "Date (newest)",
                "Date (oldest)",
                "Threat score (high→low)",
                "Threat score (low→high)",
            ],
            index=0,
        )
    with c4:
        st.write("")
        st.write("")
        refresh = st.button("Manual Refresh", use_container_width=True)

    if sort_choice.startswith("Threat score"):
        sort_by = "threat_score"
        ascending = "low→high" in sort_choice
    else:
        sort_by = "created_at"
        ascending = "oldest" in sort_choice

    return sender_q.strip(), subject_q.strip(), sort_by, ascending, refresh


def render_alert_card(
    settings: Settings,
    client: Client,
    alert: dict[str, Any],
) -> None:
    uid = alert.get("gmail_uid", "")
    score = int(alert.get("threat_score") or 0)
    keywords = alert.get("matched_keywords") or []
    css = score_css_class(score)

    st.markdown(
        f"""
        <div class="alert-card">
            <div><strong>Sender:</strong> {_html(alert.get("sender") or "—")}</div>
            <div><strong>Subject:</strong> {_html(alert.get("subject") or "—")}</div>
            <div>
                <strong>Threat Score:</strong>
                <span class="{css}">{score_emoji(score)} {score}</span>
            </div>
            <div><strong>Status:</strong> {_html(alert.get("status") or "PENDING")}</div>
            <div><strong>Created:</strong> {_html(format_timestamp(alert.get("created_at")))}</div>
            <div style="margin-top:0.5rem;">
                <strong>Matched</strong><br/>
                {render_keyword_badges(keywords)}
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    a1, a2, _ = st.columns([2, 2, 4])
    with a1:
        if st.button(
            "✅ Approve (Return to Inbox)",
            key=f"approve_{uid}",
            use_container_width=True,
        ):
            try:
                with st.spinner("Returning email to Inbox…"):
                    approve_alert(settings, client, alert)
                st.success("Alert approved and email returned to Inbox.")
                st.rerun()
            except (GmailError, DatabaseError) as exc:
                logger.exception("Approve failed uid=%s", uid)
                st.error(str(exc))
            except Exception as exc:
                logger.exception("Unexpected approve failure uid=%s", uid)
                st.error(f"Unexpected error while approving: {exc}")

    with a2:
        confirm_key = f"confirm_delete_{uid}"
        if st.session_state.get(confirm_key):
            st.warning("Permanently delete this email?")
            d1, d2 = st.columns(2)
            with d1:
                if st.button("Confirm Delete", key=f"yes_del_{uid}", type="primary"):
                    try:
                        with st.spinner("Deleting email…"):
                            delete_alert(settings, client, alert)
                        st.session_state[confirm_key] = False
                        st.success("Email deleted permanently.")
                        st.rerun()
                    except (GmailError, DatabaseError) as exc:
                        logger.exception("Delete failed uid=%s", uid)
                        st.error(str(exc))
                    except Exception as exc:
                        logger.exception("Unexpected delete failure uid=%s", uid)
                        st.error(f"Unexpected error while deleting: {exc}")
            with d2:
                if st.button("Cancel", key=f"no_del_{uid}"):
                    st.session_state[confirm_key] = False
                    st.rerun()
        else:
            if st.button(
                "🗑 Delete Permanently",
                key=f"delete_{uid}",
                use_container_width=True,
            ):
                st.session_state[confirm_key] = True
                st.rerun()


def main() -> None:
    _init_page()
    logger.info("Application startup")

    st.title(f"{PAGE_ICON} {PAGE_TITLE}")
    st.caption(
        "Local Security Orchestration, Automation, and Response — "
        "Gmail triage with configurable detection rules."
    )

    settings, client = get_runtime()
    render_detection_rules_sidebar(client)

    scan_col, info_col = st.columns([1, 3])
    with scan_col:
        scan_clicked = st.button(
            "🔄 Scan Inbox",
            type="primary",
            use_container_width=True,
        )
    with info_col:
        st.caption(
            f"Unread mail is scored with live Supabase rules. "
            f"Suspicious messages (score ≥ {QUARANTINE_THRESHOLD}) move to "
            f"**{SOAR_REVIEW_FOLDER}**."
        )

    if scan_clicked:
        try:
            with st.spinner("Scanning inbox and applying detection rules…"):
                stats = scan_inbox(settings, client)
            st.success(
                f"Scan complete — scanned {stats['scanned']}, "
                f"quarantined {stats['quarantined']}, "
                f"clean {stats['clean']}, "
                f"duplicates skipped {stats['skipped_dup']}."
            )
        except ConfigurationError as exc:
            st.error(str(exc))
        except GmailError as exc:
            logger.exception("Scan IMAP failure")
            st.error(str(exc))
        except DatabaseError as exc:
            logger.exception("Scan database failure")
            st.error(str(exc))
        except Exception as exc:
            logger.exception("Unexpected scan failure")
            st.error(f"Scan failed unexpectedly: {exc}")

    st.divider()

    sender_q, subject_q, sort_by, ascending, refresh = render_filters()
    if refresh:
        st.rerun()

    try:
        alerts = fetch_pending_alerts(
            client,
            sender_query=sender_q or None,
            subject_query=subject_q or None,
            sort_by=sort_by,
            ascending=ascending,
        )
    except DatabaseError as exc:
        st.error(str(exc))
        return

    if not alerts:
        st.info("No pending alerts. Click **Scan Inbox** to triage unread mail.")
        return

    st.write(f"**{len(alerts)}** pending alert(s)")
    for alert in alerts:
        render_alert_card(settings, client, alert)


if __name__ == "__main__":
    main()
