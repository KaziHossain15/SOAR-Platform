"""Threat scoring engine for email triage.

The public API is score_email(). Future intelligence sources can be wired
in via the placeholder helpers without changing the Streamlit UI.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional, Protocol

from logger import get_logger

logger = get_logger(__name__)


@dataclass
class TriageResult:
    """Result of scoring a single email."""

    threat_score: int
    matched_keywords: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)


class KeywordRule(Protocol):
    """Minimal shape expected for keyword rule records."""

    # Protocol is structural; dicts from Supabase also work via mapping access.


def score_email(
    subject: str,
    body: str,
    keyword_rules: list[dict[str, Any]],
) -> TriageResult:
    """Score an email using enabled keyword rules.

    Matching is case-insensitive and supports multi-word phrases.
    Weights from all matching rules are accumulated.

    Args:
        subject: Email subject line.
        body: Email body text (plain or decoded).
        keyword_rules: List of rule dicts with keys keyword, weight, enabled.

    Returns:
        TriageResult with threat_score and matched_keywords.
    """
    haystack = f"{subject or ''}\n{body or ''}".lower()
    matched: list[str] = []
    score = 0

    for rule in keyword_rules:
        if not rule.get("enabled", True):
            continue
        keyword = (rule.get("keyword") or "").strip()
        if not keyword:
            continue
        weight = int(rule.get("weight") or 0)
        if weight <= 0:
            continue

        needle = keyword.lower()
        if needle in haystack:
            matched.append(keyword)
            score += weight

    # Deduplicate while preserving order
    seen: set[str] = set()
    unique_matched: list[str] = []
    for kw in matched:
        key = kw.lower()
        if key not in seen:
            seen.add(key)
            unique_matched.append(kw)

    result = TriageResult(threat_score=score, matched_keywords=unique_matched)
    logger.debug(
        "Scored email subject=%r score=%s matches=%s",
        (subject or "")[:80],
        score,
        unique_matched,
    )
    return result


def is_suspicious(result: TriageResult, threshold: int = 1) -> bool:
    """Return True if the triage result meets the quarantine threshold."""
    return result.threat_score >= threshold


# ---------------------------------------------------------------------------
# Future extensibility — placeholder integrations
# Wire these into score_email / a composite scorer without changing the UI.
# ---------------------------------------------------------------------------


def analyze_with_openai(subject: str, body: str) -> Optional[TriageResult]:
    """TODO: Call OpenAI (or similar) for phishing intent analysis.

    Should return a TriageResult or None if the integration is disabled.
    """
    # TODO: Implement OpenAI phishing analysis
    _ = (subject, body)
    return None


def check_virustotal(urls: list[str], hashes: list[str]) -> Optional[TriageResult]:
    """Query VirusTotal for URL reputation (hashes reserved for future use).

    Returns a TriageResult whose threat_score is the worst malicious engine
    count across URLs, or None when no API key / no URLs.
    """
    from config import load_settings
    from virustotal import VirusTotalClient

    _ = hashes
    try:
        api_key = load_settings().virustotal_api_key
    except Exception:
        api_key = ""
    client = VirusTotalClient(api_key)
    if not client.enabled or not urls:
        return None

    # Reuse email scanner by joining URLs into a synthetic body.
    result = client.scan_email_urls("", "\n".join(urls))
    if not result.urls_checked:
        return None
    return TriageResult(
        threat_score=result.vt_score,
        matched_keywords=[f"vt:{u}" for u in result.urls_checked[:3]],
        details={
            "virustotal": {
                "malicious": result.malicious,
                "suspicious": result.suspicious,
                "total": result.total_engines,
                "urls": result.urls_checked,
                "worst_url": result.worst_url,
            }
        },
    )


def check_abuseipdb(ip_addresses: list[str]) -> Optional[TriageResult]:
    """TODO: Query AbuseIPDB for IP reputation.

    Should return a TriageResult or None if the integration is disabled.
    """
    # TODO: Implement AbuseIPDB lookup
    _ = ip_addresses
    return None


def check_url_reputation(urls: list[str]) -> Optional[TriageResult]:
    """TODO: Check URL reputation via a dedicated reputation service.

    Should return a TriageResult or None if the integration is disabled.
    """
    # TODO: Implement URL reputation checks
    _ = urls
    return None


def scan_attachments(attachments: list[dict[str, Any]]) -> Optional[TriageResult]:
    """TODO: Scan email attachments for malware.

    Each attachment dict may include filename, content_type, and bytes/hash.
    Should return a TriageResult or None if the integration is disabled.
    """
    # TODO: Implement attachment malware scanning
    _ = attachments
    return None


def validate_spf(raw_headers: str) -> Optional[TriageResult]:
    """TODO: Validate SPF authentication results from headers.

    Should return a TriageResult or None if the integration is disabled.
    """
    # TODO: Implement SPF validation
    _ = raw_headers
    return None


def validate_dkim(raw_headers: str) -> Optional[TriageResult]:
    """TODO: Validate DKIM authentication results from headers.

    Should return a TriageResult or None if the integration is disabled.
    """
    # TODO: Implement DKIM validation
    _ = raw_headers
    return None


def validate_dmarc(raw_headers: str) -> Optional[TriageResult]:
    """TODO: Validate DMARC authentication results from headers.

    Should return a TriageResult or None if the integration is disabled.
    """
    # TODO: Implement DMARC validation
    _ = raw_headers
    return None


def merge_triage_results(*results: Optional[TriageResult]) -> TriageResult:
    """Combine multiple triage signals into a single result.

    Useful when composing keyword scoring with future intel sources.
    """
    total = 0
    keywords: list[str] = []
    details: dict[str, Any] = {}
    for idx, result in enumerate(results):
        if result is None:
            continue
        total += result.threat_score
        keywords.extend(result.matched_keywords)
        details[f"source_{idx}"] = result.details

    seen: set[str] = set()
    unique: list[str] = []
    for kw in keywords:
        key = kw.lower()
        if key not in seen:
            seen.add(key)
            unique.append(kw)

    return TriageResult(threat_score=total, matched_keywords=unique, details=details)
