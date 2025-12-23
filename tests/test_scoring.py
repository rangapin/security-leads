"""Tests for scoring and grading logic."""

import pytest
from security_lead_scorer.config import SCORE_THRESHOLDS, TEMPERATURE_MAP, SSL_SCORES, SECURITY_HEADERS


class TestScoreThresholds:
    """Tests for grade thresholds configuration."""

    def test_grade_a_range(self):
        """Grade A is 0-15."""
        assert SCORE_THRESHOLDS["A"] == (0, 15)

    def test_grade_b_range(self):
        """Grade B is 16-35."""
        assert SCORE_THRESHOLDS["B"] == (16, 35)

    def test_grade_c_range(self):
        """Grade C is 36-55."""
        assert SCORE_THRESHOLDS["C"] == (36, 55)

    def test_grade_d_range(self):
        """Grade D is 56-75."""
        assert SCORE_THRESHOLDS["D"] == (56, 75)

    def test_grade_f_range(self):
        """Grade F is 76-100."""
        assert SCORE_THRESHOLDS["F"] == (76, 100)


class TestTemperatureMap:
    """Tests for lead temperature mapping."""

    def test_grade_a_is_cold(self):
        """Grade A leads are cold."""
        assert TEMPERATURE_MAP["A"] == "cold"

    def test_grade_b_is_warm(self):
        """Grade B leads are warm."""
        assert TEMPERATURE_MAP["B"] == "warm"

    def test_grade_c_is_hot(self):
        """Grade C leads are hot."""
        assert TEMPERATURE_MAP["C"] == "hot"

    def test_grade_f_is_on_fire(self):
        """Grade F leads are on fire."""
        assert TEMPERATURE_MAP["F"] == "on_fire"


class TestScoringWeights:
    """Tests for scoring weight configuration."""

    def test_no_ssl_is_severe(self):
        """No SSL should be heavily penalized."""
        assert SSL_SCORES["no_ssl"] >= 25

    def test_expired_ssl_is_severe(self):
        """Expired SSL should be heavily penalized."""
        assert SSL_SCORES["expired"] >= 20

    def test_missing_hsts_has_points(self):
        """Missing HSTS header has points assigned."""
        assert SECURITY_HEADERS["Strict-Transport-Security"]["points"] > 0

    def test_missing_csp_has_points(self):
        """Missing CSP header has points assigned."""
        assert SECURITY_HEADERS["Content-Security-Policy"]["points"] > 0

    def test_required_headers_marked(self):
        """Critical headers are marked as required."""
        assert SECURITY_HEADERS["Strict-Transport-Security"]["required"] is True
        assert SECURITY_HEADERS["Content-Security-Policy"]["required"] is True
        assert SECURITY_HEADERS["X-Frame-Options"]["required"] is True
