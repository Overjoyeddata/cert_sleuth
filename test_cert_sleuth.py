"""Offline unit tests for cert_sleuth (no network required)."""

import tempfile
import unittest
from pathlib import Path

from cert_sleuth import (
    filter_subdomains,
    parse_subdomains,
    save_subdomains,
    validate_domain,
)


class ValidateDomainTests(unittest.TestCase):
    def test_normalizes_case_and_trailing_dot(self):
        domain, error = validate_domain("EXAMPLE.COM.")
        self.assertEqual(domain, "example.com")
        self.assertIsNone(error)

    def test_rejects_urls_and_spaces(self):
        for bad in ("https://example.com", "example.com/path", "not a domain", ""):
            domain, error = validate_domain(bad)
            self.assertIsNone(domain)
            self.assertIsNotNone(error)

    def test_rejects_wildcards(self):
        domain, error = validate_domain("*.example.com")
        self.assertIsNone(domain)
        self.assertIn("Wildcard", error)


class ParseSubdomainsTests(unittest.TestCase):
    def test_splits_newlines_dedupes_and_drops_wildcards(self):
        raw = [
            {"name_value": "WWW.Example.com\n*.example.com"},
            {"name_value": "www.example.com"},
            {"name_value": "api.example.com"},
        ]
        self.assertEqual(
            parse_subdomains(raw),
            ["api.example.com", "www.example.com"],
        )


class FilterSubdomainsTests(unittest.TestCase):
    def test_keeps_only_in_scope_hosts(self):
        names = [
            "example.com",
            "www.example.com",
            "notexample.com",
            "evil.com",
            "cdn.evil-example.com",
        ]
        self.assertEqual(
            filter_subdomains(names, "example.com"),
            ["example.com", "www.example.com"],
        )


class SaveSubdomainsTests(unittest.TestCase):
    def test_writes_one_host_per_line(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "out.txt"
            save_subdomains(["a.example.com", "b.example.com"], path)
            self.assertEqual(
                path.read_text(encoding="utf-8"),
                "a.example.com\nb.example.com\n",
            )


if __name__ == "__main__":
    unittest.main()
