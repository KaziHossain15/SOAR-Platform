"""VirusTotal URL reputation lookups for email link scanning."""

from __future__ import annotations

import base64
import json
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Optional

from logger import get_logger

logger = get_logger(__name__)

VT_API_BASE = "https://www.virustotal.com/api/v3"
# Keep lookups small so Scan Inbox stays responsive.
MAX_URLS_PER_EMAIL = 2
MAX_URLS_PER_SCAN = 10
REQUEST_TIMEOUT_SECONDS = 20
# Soft pacing; on HTTP 429 we stop further lookups for the scan.
MIN_INTERVAL_SECONDS = 1.0

_URL_RE = re.compile(
    r"https?://[^\s<>\"'\)\]\}]+",
    re.IGNORECASE,
)


@dataclass
class VirusTotalUrlResult:
    """Reputation summary for a single URL."""

    url: str
    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    total: int = 0
    permalink: str = ""
    error: str = ""


@dataclass
class VirusTotalScanResult:
    """Aggregate VirusTotal outcome for an email's links."""

    urls_checked: list[str] = field(default_factory=list)
    results: list[VirusTotalUrlResult] = field(default_factory=list)
    malicious: int = 0
    suspicious: int = 0
    total_engines: int = 0
    # Convenience score shown in the UI (worst malicious count across links).
    vt_score: int = 0
    worst_url: str = ""
    enabled: bool = False
    skipped_reason: str = ""

    @property
    def is_malicious(self) -> bool:
        return self.malicious > 0


def extract_urls(*texts: str, limit: int = MAX_URLS_PER_EMAIL) -> list[str]:
    """Extract unique http(s) URLs from text snippets."""
    found: list[str] = []
    seen: set[str] = set()
    for text in texts:
        if not text:
            continue
        for match in _URL_RE.findall(text):
            url = match.rstrip(".,;:!?)]}>\"'")
            key = url.lower()
            if key in seen:
                continue
            seen.add(key)
            found.append(url)
            if limit and len(found) >= limit:
                return found
    return found


def url_id(url: str) -> str:
    """VirusTotal URL identifier (URL-safe base64 without padding)."""
    return base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")


def _vt_get(api_key: str, path: str) -> dict[str, Any]:
    req = urllib.request.Request(
        f"{VT_API_BASE}{path}",
        headers={"x-apikey": api_key, "Accept": "application/json"},
        method="GET",
    )
    with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT_SECONDS) as resp:
        return json.loads(resp.read().decode("utf-8"))


def lookup_url(api_key: str, url: str) -> VirusTotalUrlResult:
    """Fetch existing VirusTotal analysis for a URL (no new upload)."""
    result = VirusTotalUrlResult(url=url)
    try:
        payload = _vt_get(api_key, f"/urls/{url_id(url)}")
        attrs = (payload.get("data") or {}).get("attributes") or {}
        stats = attrs.get("last_analysis_stats") or {}
        result.malicious = int(stats.get("malicious") or 0)
        result.suspicious = int(stats.get("suspicious") or 0)
        result.harmless = int(stats.get("harmless") or 0)
        result.undetected = int(stats.get("undetected") or 0)
        result.total = (
            result.malicious
            + result.suspicious
            + result.harmless
            + result.undetected
            + int(stats.get("timeout") or 0)
        )
        result.permalink = f"https://www.virustotal.com/gui/url/{url_id(url)}"
    except urllib.error.HTTPError as exc:
        body = ""
        try:
            body = exc.read().decode("utf-8", errors="replace")[:300]
        except Exception:
            pass
        if exc.code == 404:
            result.error = "not_found"
            logger.info("VirusTotal has no report yet for url=%s", url[:120])
        else:
            result.error = f"http_{exc.code}"
            logger.warning(
                "VirusTotal HTTP %s for url=%s body=%s",
                exc.code,
                url[:120],
                body,
            )
    except Exception as exc:
        result.error = "request_failed"
        logger.warning("VirusTotal lookup failed for url=%s: %s", url[:120], exc)
    return result


class VirusTotalClient:
    """Rate-limited VirusTotal URL scanner for a single scan run."""

    def __init__(self, api_key: str) -> None:
        self._api_key = (api_key or "").strip()
        self._lookups = 0
        self._last_call = 0.0
        self.rate_limited = False

    @property
    def enabled(self) -> bool:
        return bool(self._api_key)

    def _throttle(self) -> None:
        if self._last_call <= 0:
            return
        elapsed = time.monotonic() - self._last_call
        wait = MIN_INTERVAL_SECONDS - elapsed
        if wait > 0:
            time.sleep(wait)

    def scan_email_urls(
        self,
        subject: str,
        body: str,
        *,
        scan_budget_remaining: Optional[int] = None,
    ) -> VirusTotalScanResult:
        """Extract and look up URLs from an email."""
        aggregate = VirusTotalScanResult(enabled=self.enabled)
        if not self.enabled:
            aggregate.skipped_reason = "VIRUSTOTAL_API_KEY not configured"
            return aggregate
        if self.rate_limited:
            aggregate.skipped_reason = "rate_limited"
            return aggregate

        urls = extract_urls(subject, body, limit=MAX_URLS_PER_EMAIL)
        if not urls:
            aggregate.skipped_reason = "no_urls"
            return aggregate

        budget = (
            MAX_URLS_PER_SCAN
            if scan_budget_remaining is None
            else max(0, scan_budget_remaining)
        )
        to_check = urls[: min(len(urls), budget, MAX_URLS_PER_EMAIL)]
        if not to_check:
            aggregate.skipped_reason = "scan_budget_exhausted"
            return aggregate

        worst = 0
        worst_url = ""
        for url in to_check:
            if self.rate_limited:
                break
            self._throttle()
            item = lookup_url(self._api_key, url)
            self._last_call = time.monotonic()
            self._lookups += 1
            if item.error == "http_429":
                self.rate_limited = True
                logger.warning("VirusTotal rate limited; skipping further URL checks")
                break
            aggregate.results.append(item)
            aggregate.urls_checked.append(url)
            if item.malicious > worst:
                worst = item.malicious
                worst_url = url
            aggregate.malicious = max(aggregate.malicious, item.malicious)
            aggregate.suspicious = max(aggregate.suspicious, item.suspicious)
            aggregate.total_engines = max(aggregate.total_engines, item.total)

        aggregate.vt_score = worst
        aggregate.worst_url = worst_url
        return aggregate


def format_vt_score(alert_or_result: Any) -> str:
    """Human-readable VirusTotal score line for the UI."""
    if isinstance(alert_or_result, VirusTotalScanResult):
        if not alert_or_result.enabled:
            return "n/a (no API key)"
        if alert_or_result.skipped_reason == "no_urls":
            return "n/a (no links)"
        if not alert_or_result.urls_checked:
            return f"n/a ({alert_or_result.skipped_reason or 'skipped'})"
        total = alert_or_result.total_engines or 0
        return f"{alert_or_result.vt_score}/{total} malicious"

    malicious = int(alert_or_result.get("vt_malicious") or alert_or_result.get("vt_score") or 0)
    total = int(alert_or_result.get("vt_total") or 0)
    checked = alert_or_result.get("vt_urls") or []
    if not checked and malicious == 0 and total == 0:
        return "n/a"
    if total:
        return f"{malicious}/{total} malicious"
    return str(malicious)
