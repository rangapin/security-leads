"""Tests for domain validation."""

import pytest
from security_lead_scorer.main import validate_domain


class TestValidateDomain:
    """Tests for the validate_domain function."""

    def test_valid_domain(self):
        """Valid domain returns normalized form."""
        assert validate_domain("example.com") == "example.com"

    def test_domain_with_https(self):
        """Domain with https:// prefix is normalized."""
        assert validate_domain("https://example.com") == "example.com"

    def test_domain_with_http(self):
        """Domain with http:// prefix is normalized."""
        assert validate_domain("http://example.com") == "example.com"

    def test_domain_with_path(self):
        """Domain with path is normalized."""
        assert validate_domain("example.com/some/path") == "example.com"

    def test_domain_with_subdomain(self):
        """Subdomain is preserved."""
        assert validate_domain("www.example.com") == "example.com"

    def test_domain_with_complex_tld(self):
        """Complex TLDs like .co.uk work."""
        assert validate_domain("example.co.uk") == "example.co.uk"

    def test_invalid_domain_no_tld(self):
        """Domain without TLD returns None."""
        assert validate_domain("localhost") is None

    def test_invalid_domain_empty(self):
        """Empty string returns None."""
        assert validate_domain("") is None
