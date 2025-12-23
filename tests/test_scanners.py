"""Tests for Phase 2 scanners."""

import pytest
from unittest.mock import patch, MagicMock

from security_lead_scorer.config import DNS_SCORES, PORT_SCORES, COOKIE_SCORES, CMS_SCORES


class TestDNSChecker:
    """Tests for DNS checker configuration."""

    def test_dns_scores_defined(self):
        """DNS scores are properly defined."""
        assert "no_spf" in DNS_SCORES
        assert "no_dmarc" in DNS_SCORES
        assert "no_dkim" in DNS_SCORES
        assert DNS_SCORES["no_spf"] > 0
        assert DNS_SCORES["no_dmarc"] > 0


class TestPortScanner:
    """Tests for port scanner configuration."""

    def test_risky_ports_defined(self):
        """Risky ports are properly defined."""
        # Database ports should be critical
        assert 3306 in PORT_SCORES  # MySQL
        assert 5432 in PORT_SCORES  # PostgreSQL
        assert 27017 in PORT_SCORES  # MongoDB

    def test_database_ports_are_critical(self):
        """Database ports should have high scores."""
        assert PORT_SCORES[3306]["severity"] == "critical"
        assert PORT_SCORES[5432]["severity"] == "critical"
        assert PORT_SCORES[27017]["severity"] == "critical"

    def test_ssh_is_medium_severity(self):
        """SSH is medium severity (depends on config)."""
        assert PORT_SCORES[22]["severity"] == "medium"


class TestCookieChecker:
    """Tests for cookie checker configuration."""

    def test_cookie_scores_defined(self):
        """Cookie scores are properly defined."""
        assert "no_secure" in COOKIE_SCORES
        assert "no_httponly" in COOKIE_SCORES
        assert "no_samesite" in COOKIE_SCORES

    def test_secure_flag_has_points(self):
        """Missing Secure flag should have points."""
        assert COOKIE_SCORES["no_secure"] > 0


class TestCMSDetector:
    """Tests for CMS detector configuration."""

    def test_cms_scores_defined(self):
        """CMS scores are properly defined."""
        assert "version_unknown" in CMS_SCORES
        assert "one_major_behind" in CMS_SCORES
        assert "two_major_behind" in CMS_SCORES

    def test_outdated_cms_is_penalized(self):
        """Outdated CMS should be heavily penalized."""
        assert CMS_SCORES["two_major_behind"] > CMS_SCORES["one_major_behind"]
