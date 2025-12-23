"""Tests for talking points generator."""

import pytest
from security_lead_scorer.output.talking_points import (
    generate_talking_points,
    _get_ssl_talking_points,
    _get_header_talking_points,
    _get_redirect_talking_points,
    _get_dns_talking_points,
    _get_cms_talking_points,
    _get_port_talking_points,
    _get_cookie_talking_points,
)


class TestGenerateTalkingPoints:
    """Tests for main generate_talking_points function."""

    def test_empty_checks_returns_empty(self):
        """Empty checks returns empty list."""
        result = generate_talking_points({"checks": {}})
        assert result == []

    def test_returns_list_of_strings(self):
        """Returns list of string talking points."""
        scan_result = {
            "checks": {
                "ssl": {"has_ssl": False}
            }
        }
        result = generate_talking_points(scan_result)
        assert isinstance(result, list)
        assert all(isinstance(p, str) for p in result)

    def test_max_five_talking_points(self):
        """Returns at most 5 talking points."""
        scan_result = {
            "checks": {
                "ssl": {"has_ssl": False},
                "headers": {"headers_missing": ["Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options"]},
                "redirects": {"http_redirects_to_https": False, "mixed_content": {"detected": True}},
                "dns": {"spf": {"present": False}, "dmarc": {"present": False}},
            }
        }
        result = generate_talking_points(scan_result)
        assert len(result) <= 5

    def test_critical_issues_prioritized(self):
        """Critical issues appear before lower severity."""
        scan_result = {
            "checks": {
                "headers": {"headers_missing": ["X-Frame-Options"]},  # medium
                "ssl": {"has_ssl": False},  # critical
            }
        }
        result = generate_talking_points(scan_result)
        # SSL (critical) should come first
        assert "SSL" in result[0] or "Secure" in result[0]


class TestSSLTalkingPoints:
    """Tests for SSL talking points."""

    def test_no_ssl_is_critical(self):
        """No SSL generates critical talking point."""
        ssl = {"has_ssl": False}
        points = _get_ssl_talking_points(ssl)
        assert len(points) == 1
        assert points[0][0] == "critical"
        assert "SSL" in points[0][1]

    def test_expired_ssl(self):
        """Expired SSL generates critical talking point."""
        ssl = {"has_ssl": True, "days_until_expiry": -5}
        points = _get_ssl_talking_points(ssl)
        assert any(p[0] == "critical" and "expired" in p[1].lower() for p in points)

    def test_expiring_soon_ssl(self):
        """SSL expiring in <7 days generates high talking point."""
        ssl = {"has_ssl": True, "days_until_expiry": 3}
        points = _get_ssl_talking_points(ssl)
        assert any(p[0] == "high" and "3 days" in p[1] for p in points)

    def test_expiring_within_month(self):
        """SSL expiring in <30 days generates medium talking point."""
        ssl = {"has_ssl": True, "days_until_expiry": 20}
        points = _get_ssl_talking_points(ssl)
        assert any(p[0] == "medium" and "20 days" in p[1] for p in points)

    def test_outdated_tls(self):
        """Outdated TLS version generates high talking point."""
        ssl = {"has_ssl": True, "tls_version": "TLSv1.1", "days_until_expiry": 90}
        points = _get_ssl_talking_points(ssl)
        assert any(p[0] == "high" and "TLS" in p[1] for p in points)


class TestHeaderTalkingPoints:
    """Tests for header talking points."""

    def test_missing_hsts(self):
        """Missing HSTS generates high talking point."""
        headers = {"headers_missing": ["Strict-Transport-Security"]}
        points = _get_header_talking_points(headers)
        assert any(p[0] == "high" and "HSTS" in p[1] for p in points)

    def test_missing_csp(self):
        """Missing CSP generates high talking point."""
        headers = {"headers_missing": ["Content-Security-Policy"]}
        points = _get_header_talking_points(headers)
        assert any(p[0] == "high" and "CSP" in p[1] or "Security Policy" in p[1] for p in points)

    def test_missing_xframe(self):
        """Missing X-Frame-Options generates medium talking point."""
        headers = {"headers_missing": ["X-Frame-Options"]}
        points = _get_header_talking_points(headers)
        assert any(p[0] == "medium" and "Frame" in p[1] for p in points)

    def test_no_missing_headers(self):
        """No missing headers returns empty list."""
        headers = {"headers_missing": []}
        points = _get_header_talking_points(headers)
        assert points == []


class TestRedirectTalkingPoints:
    """Tests for redirect talking points."""

    def test_no_https_redirect(self):
        """No HTTPS redirect generates high talking point."""
        redirects = {"http_redirects_to_https": False}
        points = _get_redirect_talking_points(redirects)
        assert any(p[0] == "high" and "HTTPS" in p[1] for p in points)

    def test_mixed_content(self):
        """Mixed content generates medium talking point."""
        redirects = {"http_redirects_to_https": True, "mixed_content": {"detected": True}}
        points = _get_redirect_talking_points(redirects)
        assert any(p[0] == "medium" and "insecure" in p[1].lower() for p in points)

    def test_302_redirect(self):
        """302 redirect generates low talking point."""
        redirects = {"http_redirects_to_https": True, "redirect_type": 302}
        points = _get_redirect_talking_points(redirects)
        assert any(p[0] == "low" and "302" in p[1] for p in points)


class TestDNSTalkingPoints:
    """Tests for DNS talking points."""

    def test_no_spf(self):
        """No SPF generates high talking point."""
        dns = {"spf": {"present": False}}
        points = _get_dns_talking_points(dns)
        assert any(p[0] == "high" and "SPF" in p[1] for p in points)

    def test_no_dmarc(self):
        """No DMARC generates high talking point."""
        dns = {"dmarc": {"present": False}}
        points = _get_dns_talking_points(dns)
        assert any(p[0] == "high" and "DMARC" in p[1] for p in points)

    def test_weak_spf(self):
        """Weak SPF generates medium talking point."""
        dns = {"spf": {"present": True, "policy_strength": "weak"}}
        points = _get_dns_talking_points(dns)
        assert any(p[0] == "medium" and "soft fail" in p[1] for p in points)


class TestCMSTalkingPoints:
    """Tests for CMS talking points."""

    def test_outdated_cms(self):
        """Outdated CMS generates high talking point."""
        cms = {"cms_detected": "WordPress", "is_outdated": True, "cms_version": "5.9"}
        points = _get_cms_talking_points(cms)
        assert any(p[0] == "high" and "WordPress" in p[1] for p in points)

    def test_severely_outdated_cms(self):
        """Severely outdated CMS generates critical talking point."""
        cms = {"cms_detected": "WordPress", "is_outdated": True, "cms_version": "5.0", "versions_behind": 3}
        points = _get_cms_talking_points(cms)
        assert any(p[0] == "critical" and "major versions" in p[1] for p in points)

    def test_exposed_wp_api(self):
        """Exposed WP API generates medium talking point."""
        cms = {"cms_detected": "WordPress", "exposed_files": ["wp-json API"]}
        points = _get_cms_talking_points(cms)
        assert any(p[0] == "medium" and "API" in p[1] for p in points)


class TestPortTalkingPoints:
    """Tests for port talking points."""

    def test_exposed_mysql(self):
        """Exposed MySQL generates critical talking point."""
        ports = {"open_ports": [3306]}
        points = _get_port_talking_points(ports)
        assert any(p[0] == "critical" and "MySQL" in p[1] for p in points)

    def test_exposed_postgresql(self):
        """Exposed PostgreSQL generates critical talking point."""
        ports = {"open_ports": [5432]}
        points = _get_port_talking_points(ports)
        assert any(p[0] == "critical" and "PostgreSQL" in p[1] for p in points)

    def test_exposed_ssh(self):
        """Exposed SSH generates medium talking point."""
        ports = {"open_ports": [22]}
        points = _get_port_talking_points(ports)
        assert any(p[0] == "medium" and "SSH" in p[1] for p in points)

    def test_exposed_rdp(self):
        """Exposed RDP generates critical talking point."""
        ports = {"open_ports": [3389]}
        points = _get_port_talking_points(ports)
        assert any(p[0] == "critical" and "RDP" in p[1] for p in points)


class TestCookieTalkingPoints:
    """Tests for cookie talking points."""

    def test_cookies_without_secure(self):
        """Cookies without Secure flag generate medium talking point."""
        cookies = {"cookies_without_secure": 2}
        points = _get_cookie_talking_points(cookies)
        assert any(p[0] == "medium" and "Secure" in p[1] for p in points)

    def test_cookies_without_httponly(self):
        """Cookies without HttpOnly flag generate medium talking point."""
        cookies = {"cookies_without_httponly": 2}
        points = _get_cookie_talking_points(cookies)
        assert any(p[0] == "medium" and "HttpOnly" in p[1] or "JavaScript" in p[1] for p in points)

    def test_no_cookie_issues(self):
        """No cookie issues returns empty list."""
        cookies = {"cookies_without_secure": 0, "cookies_without_httponly": 0}
        points = _get_cookie_talking_points(cookies)
        assert points == []
