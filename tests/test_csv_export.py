"""Tests for CSV export module."""

import csv
import pytest
from pathlib import Path
from security_lead_scorer.output.csv_export import export_to_csv, export_single_to_csv


@pytest.fixture
def sample_result():
    """Sample scan result for testing."""
    return {
        "domain": "example.com",
        "total_score": 45,
        "grade": "C",
        "temperature": "hot",
        "issues": ["No SSL", "Missing HSTS"],
        "talking_points": ["Your SSL is missing"],
        "checks": {
            "ssl": {
                "score": 30,
                "issues": ["No SSL certificate"],
                "has_ssl": False,
            },
            "headers": {
                "score": 15,
                "headers_missing": ["Strict-Transport-Security", "Content-Security-Policy"],
            },
            "redirects": {
                "score": 0,
                "http_redirects_to_https": True,
                "mixed_content": {"detected": False},
            },
            "dns": {
                "score": 0,
                "spf": {"present": True},
                "dmarc": {"present": True},
            },
            "cms": {
                "cms_detected": "WordPress",
                "cms_version": "6.4",
                "is_outdated": False,
            },
            "ports": {
                "score": 0,
                "open_ports": [80, 443],
            },
            "cookies": {
                "score": 0,
                "cookies_without_secure": 0,
                "cookies_without_httponly": 0,
            },
        },
    }


class TestExportToCsv:
    """Tests for export_to_csv function."""

    def test_creates_csv_file(self, tmp_path, sample_result):
        """CSV file is created at specified path."""
        output_file = tmp_path / "results.csv"
        export_to_csv([sample_result], str(output_file))
        assert output_file.exists()

    def test_csv_has_header_row(self, tmp_path, sample_result):
        """CSV has correct header row."""
        output_file = tmp_path / "results.csv"
        export_to_csv([sample_result], str(output_file))

        with output_file.open("r", encoding="utf-8") as f:
            reader = csv.reader(f)
            headers = next(reader)
            assert "domain" in headers
            assert "total_score" in headers
            assert "grade" in headers
            assert "lead_temperature" in headers

    def test_csv_contains_domain(self, tmp_path, sample_result):
        """CSV contains the scanned domain."""
        output_file = tmp_path / "results.csv"
        export_to_csv([sample_result], str(output_file))

        with output_file.open("r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            row = next(reader)
            assert row["domain"] == "example.com"

    def test_csv_contains_scores(self, tmp_path, sample_result):
        """CSV contains score data."""
        output_file = tmp_path / "results.csv"
        export_to_csv([sample_result], str(output_file))

        with output_file.open("r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            row = next(reader)
            assert row["total_score"] == "45"
            assert row["grade"] == "C"
            assert row["lead_temperature"] == "hot"

    def test_csv_ssl_fields(self, tmp_path, sample_result):
        """CSV contains SSL check fields."""
        output_file = tmp_path / "results.csv"
        export_to_csv([sample_result], str(output_file))

        with output_file.open("r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            row = next(reader)
            assert row["ssl_score"] == "30"
            assert "No SSL certificate" in row["ssl_issues"]

    def test_csv_headers_missing(self, tmp_path, sample_result):
        """CSV contains missing headers."""
        output_file = tmp_path / "results.csv"
        export_to_csv([sample_result], str(output_file))

        with output_file.open("r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            row = next(reader)
            assert "Strict-Transport-Security" in row["headers_missing"]

    def test_csv_dns_fields(self, tmp_path, sample_result):
        """CSV contains DNS check fields."""
        output_file = tmp_path / "results.csv"
        export_to_csv([sample_result], str(output_file))

        with output_file.open("r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            row = next(reader)
            assert row["spf_present"] == "Yes"
            assert row["dmarc_present"] == "Yes"

    def test_csv_cms_fields(self, tmp_path, sample_result):
        """CSV contains CMS detection fields."""
        output_file = tmp_path / "results.csv"
        export_to_csv([sample_result], str(output_file))

        with output_file.open("r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            row = next(reader)
            assert row["cms_detected"] == "WordPress"
            assert row["cms_version"] == "6.4"
            assert row["cms_outdated"] == "No"

    def test_multiple_results(self, tmp_path, sample_result):
        """Multiple results create multiple rows."""
        second_result = sample_result.copy()
        second_result["domain"] = "test.com"
        output_file = tmp_path / "results.csv"

        export_to_csv([sample_result, second_result], str(output_file))

        with output_file.open("r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
            assert len(rows) == 2
            assert rows[0]["domain"] == "example.com"
            assert rows[1]["domain"] == "test.com"

    def test_empty_results_no_file(self, tmp_path):
        """Empty results list doesn't create file."""
        output_file = tmp_path / "results.csv"
        export_to_csv([], str(output_file))
        # File should not be created for empty results
        assert not output_file.exists()

    def test_talking_points_in_csv(self, tmp_path, sample_result):
        """Talking points are included in CSV."""
        output_file = tmp_path / "results.csv"
        export_to_csv([sample_result], str(output_file))

        with output_file.open("r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            row = next(reader)
            assert "Your SSL is missing" in row["talking_points"]


class TestExportSingleToCsv:
    """Tests for export_single_to_csv function."""

    def test_exports_single_result(self, tmp_path, sample_result):
        """Single result exports correctly."""
        output_file = tmp_path / "single.csv"
        export_single_to_csv(sample_result, str(output_file))

        assert output_file.exists()
        with output_file.open("r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
            assert len(rows) == 1
            assert rows[0]["domain"] == "example.com"
