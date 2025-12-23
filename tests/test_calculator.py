"""Tests for scoring calculator module."""

import pytest
from security_lead_scorer.scoring import calculate_score, get_grade, get_temperature


class TestGetGrade:
    """Tests for get_grade function."""

    def test_grade_a_low_boundary(self):
        """Score 0 is grade A."""
        assert get_grade(0) == "A"

    def test_grade_a_high_boundary(self):
        """Score 15 is grade A."""
        assert get_grade(15) == "A"

    def test_grade_b_low_boundary(self):
        """Score 16 is grade B."""
        assert get_grade(16) == "B"

    def test_grade_b_high_boundary(self):
        """Score 35 is grade B."""
        assert get_grade(35) == "B"

    def test_grade_c_mid_range(self):
        """Score 45 is grade C."""
        assert get_grade(45) == "C"

    def test_grade_d_mid_range(self):
        """Score 65 is grade D."""
        assert get_grade(65) == "D"

    def test_grade_f_low_boundary(self):
        """Score 76 is grade F."""
        assert get_grade(76) == "F"

    def test_grade_f_high_score(self):
        """Score 100 is grade F."""
        assert get_grade(100) == "F"

    def test_grade_over_100_is_f(self):
        """Score over 100 defaults to F."""
        assert get_grade(150) == "F"


class TestGetTemperature:
    """Tests for get_temperature function."""

    def test_grade_a_is_cold(self):
        """Grade A produces cold temperature."""
        assert get_temperature("A") == "cold"

    def test_grade_b_is_warm(self):
        """Grade B produces warm temperature."""
        assert get_temperature("B") == "warm"

    def test_grade_c_is_hot(self):
        """Grade C produces hot temperature."""
        assert get_temperature("C") == "hot"

    def test_grade_d_is_hot(self):
        """Grade D produces hot temperature."""
        assert get_temperature("D") == "hot"

    def test_grade_f_is_on_fire(self):
        """Grade F produces on_fire temperature."""
        assert get_temperature("F") == "on_fire"

    def test_unknown_grade_returns_unknown(self):
        """Unknown grade returns unknown temperature."""
        assert get_temperature("X") == "unknown"


class TestCalculateScore:
    """Tests for calculate_score function."""

    def test_empty_checks_returns_zero(self):
        """Empty checks produce zero score."""
        result = calculate_score({"checks": {}})
        assert result["total_score"] == 0
        assert result["grade"] == "A"
        assert result["lead_temperature"] == "cold"

    def test_single_check_score(self):
        """Single check score is aggregated."""
        scan_results = {
            "checks": {
                "ssl": {"score": 25, "severity": "high", "issues": ["No SSL"]}
            }
        }
        result = calculate_score(scan_results)
        assert result["total_score"] == 25
        assert result["category_scores"]["ssl"] == 25

    def test_multiple_checks_aggregated(self):
        """Multiple check scores are summed."""
        scan_results = {
            "checks": {
                "ssl": {"score": 20, "severity": "high", "issues": []},
                "headers": {"score": 15, "severity": "medium", "issues": []},
            }
        }
        result = calculate_score(scan_results)
        assert result["total_score"] == 35
        assert result["raw_score"] == 35

    def test_score_capped_at_100(self):
        """Total score is capped at 100."""
        scan_results = {
            "checks": {
                "ssl": {"score": 40, "severity": "critical", "issues": []},
                "headers": {"score": 40, "severity": "high", "issues": []},
                "dns": {"score": 40, "severity": "high", "issues": []},
            }
        }
        result = calculate_score(scan_results)
        assert result["total_score"] == 100
        assert result["raw_score"] == 120  # Raw is uncapped

    def test_issues_collected_and_sorted(self):
        """Issues are collected and sorted by severity."""
        scan_results = {
            "checks": {
                "ssl": {"score": 20, "severity": "medium", "issues": ["Medium issue"]},
                "dns": {"score": 30, "severity": "critical", "issues": ["Critical issue"]},
            }
        }
        result = calculate_score(scan_results)
        # Critical should come first
        assert "CRITICAL" in result["top_issues"][0]
        assert "MEDIUM" in result["top_issues"][1]

    def test_top_issues_limited_to_five(self):
        """Only top 5 issues are returned."""
        scan_results = {
            "checks": {
                "test": {
                    "score": 50,
                    "severity": "high",
                    "issues": [f"Issue {i}" for i in range(10)]
                }
            }
        }
        result = calculate_score(scan_results)
        assert len(result["top_issues"]) == 5

    def test_issue_counts_by_severity(self):
        """Issue counts are tracked by severity."""
        scan_results = {
            "checks": {
                "ssl": {"score": 20, "severity": "critical", "issues": ["A"]},
                "headers": {"score": 15, "severity": "high", "issues": ["B"]},
                "dns": {"score": 10, "severity": "medium", "issues": ["C"]},
            }
        }
        result = calculate_score(scan_results)
        assert result["issue_count"]["critical"] == 1
        assert result["issue_count"]["high"] == 1
        assert result["issue_count"]["medium"] == 1

    def test_missing_checks_key_handled(self):
        """Missing checks key doesn't cause error."""
        result = calculate_score({})
        assert result["total_score"] == 0
