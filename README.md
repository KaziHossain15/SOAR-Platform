# SOAR Email Triage Platform

Local **Security Orchestration, Automation, and Response** for Gmail: scan unread mail, score it with configurable keyword rules, optionally check links with VirusTotal, quarantine suspicious messages, and approve or delete them from a Streamlit dashboard.

---

## What it does

1. Connects to Gmail over IMAP (App Password).
2. Looks at unread messages among the **newest 50** inbox emails.
3. Scores each message with keyword rules stored in **Supabase**.
4. Optionally extracts links (including HTML `href`/`src`) and queries **VirusTotal**.
5. Moves suspicious mail to a Gmail label/folder named **`SOAR Review`**.
6. Creates a pending alert in Supabase for human review.
7. Lets you **approve** (return to Inbox) or **delete** permanently from the UI.

```text
Gmail INBOX ──scan──► Keyword triage (+ VirusTotal)
                           │
                           ▼
                    SOAR Review folder
                           │
                           ▼
                    Supabase alerts ──► Streamlit UI
                           │
              ┌────────────┴────────────┐
              ▼                         ▼
           Approve                   Delete
        (back to Inbox)          (permanent)
```

---

## Features

| Area | Details |
|------|---------|
| **Detection rules** | Add, edit, enable/disable, and delete keywords (weight 1–10) in the sidebar — no code changes. |
| **Threat score** | Sum of matched rule weights; quarantine when score ≥ 1 (or VirusTotal reports malicious links). |
| **VirusTotal** | Optional API key; shows malicious engine count next to threat score; **Rescan VT** per alert. |
| **Lookback** | Only the newest 50 inbox messages are considered (avoids huge unread backlogs). |
| **Quarantine** | IMAP move to `SOAR Review`; UIDs tracked per folder. |
| **Pending retention** | Pending alerts older than **7 days** are auto-expired: mail returns to Inbox, Supabase row is deleted. |
| **Database cleanup** | Sidebar tools to purge resolved alerts and free Supabase storage on the free tier. |
| **Diagnostics** | `diagnose_inbox.py` and unit tests under `tests/`. |

---

## Stack

- **Python 3.11**
- **Streamlit** — dashboard (`app.py`)
- **Supabase** — `keyword_rules` + `alerts` tables
- **Gmail IMAP** — ingest / quarantine / restore / delete
- **VirusTotal API v3** — optional URL reputation
- **Docker Compose** — one-service deploy on port `8501`

---

## Project layout

```text
app.py                 Streamlit UI + scan / approve / delete orchestration
config.py              Environment / secrets loading
database.py            Supabase access for rules and alerts
gmail_client.py        IMAP client (peek, move, folder create, body/HTML parse)
triage.py              Keyword scoring engine
virustotal.py          URL extraction + VirusTotal lookups
diagnose_inbox.py      Live inbox / rules diagnostic CLI
schema.sql             Full Supabase schema + seed rules
migrate_vt.sql         Add VirusTotal columns to an existing alerts table
seed_rules.sql         Optional keyword seed only
fix_grants.sql         RLS / grant helpers
docker-compose.yml     App service
Dockerfile
tests/                 Unit tests (triage, IMAP parsing, scan mocks, VT)
.env.example           Required environment variables
```

---

## Prerequisites

- A [Supabase](https://supabase.com/) project
- A Gmail account with **IMAP enabled** and a [Google App Password](https://myaccount.google.com/apppasswords)
- Docker (recommended) **or** Python 3.11+
- Optional: [VirusTotal API key](https://www.virustotal.com/gui/my-apikey)

---

## Setup

### 1. Clone and configure env

```bash
cp .env.example .env
```

Edit `.env`:

| Variable | Required | Description |
|----------|----------|-------------|
| `SUPABASE_URL` | Yes | Project URL (`https://xxxx.supabase.co`) |
| `SUPABASE_KEY` | Yes | Anon or service role key |
| `GMAIL_USER` | Yes | Gmail address |
| `GMAIL_APP_PASSWORD` | Yes | 16-character app password |
| `VIRUSTOTAL_API_KEY` | No | Enables link scanning |

Never commit `.env`.

### 2. Create the database

In the Supabase SQL Editor, run **`schema.sql`** once.  
If you already created tables before VirusTotal support, also run **`migrate_vt.sql`**.

That creates:

- `keyword_rules` — detection keywords, weights, enabled flag  
- `alerts` — quarantined mail metadata, threat score, VirusTotal fields, status  

and seeds a starter set of phishing-related keywords.

### 3. Run the app

**Docker (recommended):**

```bash
docker compose up --build
```

Open **http://localhost:8501**.

**Local:**

```bash
pip install -r requirements.txt
streamlit run app.py
```

---

## Using the dashboard

1. **Detection Rules (sidebar)** — review or tune keywords before scanning.
2. **Scan Inbox** — scores unread mail in the newest 50 messages; quarantines hits to `SOAR Review`.
3. **Pending Alerts** — each card shows sender, subject, threat score, VirusTotal score, and matched keywords.
4. **View email body** — load the quarantined message on demand.
5. **Rescan VT** — re-extract links and refresh VirusTotal results for that alert.
6. **Approve** — return the message to Inbox and mark the alert `APPROVED`.
7. **Delete** — permanently remove from `SOAR Review` and mark `DELETED`.
8. **Database Cleanup (sidebar)** — view alert counts; purge `APPROVED` / `DELETED` rows; optionally clear VirusTotal URL payloads on resolved alerts; manually expire stale pending alerts; **Clear pending alerts** (see below).

### Clear pending alerts

Use **Clear pending alerts** (sidebar → Database Cleanup) when the Gmail side is already gone but Supabase still shows pending cards — for example you moved or deleted mail from **`SOAR Review` in Gmail** instead of using Approve / Delete in the UI.

- Removes all **`PENDING`** rows from Supabase so they disappear from the dashboard.
- Does **not** change Gmail (no move to Inbox, no delete).
- Requires the confirmation checkbox before the button runs.

Do **not** use this as a substitute for Approve/Delete when you still want the app to handle the message in Gmail.

### Pending alert retention

Pending alerts older than **7 days** expire automatically (on each **Scan Inbox**, and once per browser session):

1. The quarantined message is **moved from `SOAR Review` back to Inbox** (same as Approve).
2. The Supabase alert row is **hard-deleted**.

This keeps the free-tier database small without permanently deleting mail you never reviewed. You can also trigger expiry from **Database Cleanup**.

---

## How scoring works

### Keywords

- Case-insensitive match against subject + body (and links preserved from HTML).
- Weights of all matching **enabled** rules are summed → **threat score**.
- Default quarantine threshold: **score ≥ 1**.

### VirusTotal

When `VIRUSTOTAL_API_KEY` is set:

- Links are taken from plain text and HTML `href`/`src`.
- Up to a small number of URLs per email / scan are looked up (rate-limit aware).
- UI shows something like **`3/70 malicious`** next to the threat score.
- Malicious links can quarantine even when keyword score is 0.

Without a key (or with no links), the UI shows `n/a` with a short reason.

---

## Testing and diagnostics

```bash
# Unit tests
python -m unittest discover -s tests -v

# Live check: rules, SOAR Review folder, unread vs read mail, scores
python diagnose_inbox.py
```

---

## Troubleshooting

| Symptom | Likely cause | What to try |
|---------|--------------|-------------|
| Config / missing env errors | Incomplete `.env` | Fill all required vars; recreate containers so Compose reloads `.env` |
| IMAP auth failed | Wrong app password / IMAP off | Create a new App Password; enable IMAP in Gmail settings |
| Folder create / BAD parse | Older bug with spaces in `SOAR Review` | Use latest `main`; folder name must be quoted for IMAP |
| Scan finds nothing | Mail already read, or outside newest 50 | Mark test mail **unread**; keep it recent in Inbox |
| White / blank UI | Theme + old HTML cards (fixed) | Refresh after latest image rebuild |
| VirusTotal always `n/a` | Key missing, alert predates VT, or no links | Set key, restart Docker, click **Rescan VT**; confirm body/HTML has links |
| DB insert errors on `vt_*` | Schema not migrated | Run `migrate_vt.sql` in Supabase |
| Supabase storage growing | Resolved / stale alerts kept forever | Use **Database Cleanup**; pending auto-expires after 7 days |

---

## Security notes

- This is intended for **local / demo** use. Supabase RLS policies in `schema.sql` are permissive for the anon key.
- Prefer a dedicated Gmail account or label-scoped workflow for experiments.
- Rotate App Passwords and API keys if they are ever exposed.
- Tighten Supabase policies before any shared or production deployment.

---

## License

Use and modify for personal learning and local security tooling as needed.
