"""Unit tests for VirusTotal URL extraction and scoring helpers."""

from __future__ import annotations

import unittest
from unittest.mock import patch

from virustotal import (
    VirusTotalClient,
    VirusTotalScanResult,
    VirusTotalUrlResult,
    extract_urls,
    format_vt_score,
)


class TestExtractUrls(unittest.TestCase):
    def test_extracts_unique_http_urls(self) -> None:
        text = "Go to https://evil.example/phish and https://evil.example/phish again"
        self.assertEqual(extract_urls(text), ["https://evil.example/phish"])

    def test_strips_trailing_punctuation(self) -> None:
        self.assertEqual(
            extract_urls("See https://a.example/x."),
            ["https://a.example/x"],
        )

    def test_respects_limit(self) -> None:
        body = "https://a.test/1 https://b.test/2 https://c.test/3"
        self.assertEqual(len(extract_urls(body, limit=2)), 2)

    def test_extracts_href_from_html(self) -> None:
        html = '<a href="https://phish.example/login">Click</a> and <img src="https://cdn.example/x.png">'
        urls = extract_urls(html, limit=5)
        self.assertEqual(
            urls,
            ["https://phish.example/login", "https://cdn.example/x.png"],
        )

    def test_unescapes_html_entities_in_href(self) -> None:
        html = '<a href="https://evil.test/a?x=1&amp;y=2">go</a>'
        self.assertEqual(extract_urls(html), ["https://evil.test/a?x=1&y=2"])


class TestFormatVtScore(unittest.TestCase):
    def test_alert_dict(self) -> None:
        self.assertEqual(
            format_vt_score({"vt_malicious": 3, "vt_total": 70, "vt_urls": ["https://x"]}),
            "3/70 malicious",
        )

    def test_disabled_result(self) -> None:
        result = VirusTotalScanResult(enabled=False, skipped_reason="no key")
        self.assertIn("no API key", format_vt_score(result))


class TestVirusTotalClient(unittest.TestCase):
    def test_disabled_without_key(self) -> None:
        client = VirusTotalClient("")
        result = client.scan_email_urls("hi", "https://example.com")
        self.assertFalse(result.enabled)
        self.assertEqual(result.vt_score, 0)

    @patch("virustotal.lookup_url")
    def test_aggregates_worst_malicious(self, mock_lookup) -> None:
        mock_lookup.side_effect = [
            VirusTotalUrlResult(
                url="https://a.test",
                malicious=1,
                total=70,
                permalink="https://www.virustotal.com/gui/url/a",
            ),
            VirusTotalUrlResult(
                url="https://b.test",
                malicious=5,
                total=70,
                permalink="https://www.virustotal.com/gui/url/b",
            ),
        ]
        client = VirusTotalClient("fake-key")
        result = client.scan_email_urls(
            "subj",
            "https://a.test https://b.test",
            scan_budget_remaining=5,
        )
        self.assertEqual(result.vt_score, 5)
        self.assertEqual(result.worst_url, "https://b.test")
        self.assertTrue(result.is_malicious)


if __name__ == "__main__":
    unittest.main()
