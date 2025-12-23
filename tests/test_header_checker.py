"""Tests for header checker with mocked HTTP responses."""

import pytest
from pytest_httpx import HTTPXMock

from security_lead_scorer.scanner.header_checker import check_headers


class TestHeaderChecker:
    """Tests for the check_headers function."""

    def test_all_headers_present(self, httpx_mock: HTTPXMock):
        """When all security headers are present, score should be 0."""
        httpx_mock.add_response(
            url="https://example.com",
            headers={
                "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
                "Content-Security-Policy": "default-src 'self'",
                "X-Frame-Options": "DENY",
                "X-Content-Type-Options": "nosniff",
                "X-XSS-Protection": "1; mode=block",
                "Referrer-Policy": "strict-origin-when-cross-origin",
                "Permissions-Policy": "geolocation=()",
            },
        )

        result = check_headers("example.com")

        assert result["score"] == 0
        assert len(result["headers_missing"]) == 0
        assert result["severity"] == "low"

    def test_missing_critical_headers(self, httpx_mock: HTTPXMock):
        """When critical headers are missing, score should increase."""
        httpx_mock.add_response(
            url="https://example.com",
            headers={},  # No security headers
        )

        result = check_headers("example.com")

        assert result["score"] > 0
        assert "Strict-Transport-Security" in result["headers_missing"]
        assert "Content-Security-Policy" in result["headers_missing"]
        assert result["severity"] in ("medium", "high")

    def test_partial_headers(self, httpx_mock: HTTPXMock):
        """When some headers present, score reflects missing ones."""
        httpx_mock.add_response(
            url="https://example.com",
            headers={
                "Strict-Transport-Security": "max-age=31536000",
                "X-Frame-Options": "SAMEORIGIN",
            },
        )

        result = check_headers("example.com")

        assert "Strict-Transport-Security" in result["headers_present"]
        assert "X-Frame-Options" in result["headers_present"]
        assert "Content-Security-Policy" in result["headers_missing"]

    def test_connection_error_handled(self, httpx_mock: HTTPXMock):
        """Connection errors are handled gracefully."""
        httpx_mock.add_exception(Exception("Connection refused"))

        result = check_headers("example.com")

        assert result["severity"] == "unknown"
        assert len(result["issues"]) > 0
