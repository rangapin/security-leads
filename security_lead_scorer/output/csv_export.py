"""CSV export for scan results."""

import csv
from datetime import datetime
from pathlib import Path


def export_to_csv(results: list[dict], output_path: str) -> None:
    """
    Export scan results to CSV.

    Args:
        results: List of scan result dicts
        output_path: Path to output CSV file
    """
    if not results:
        return

    fieldnames = [
        "domain",
        "total_score",
        "grade",
        "lead_temperature",
        "ssl_score",
        "ssl_issues",
        "headers_score",
        "headers_missing",
        "redirects_score",
        "https_redirect",
        "mixed_content",
        "dns_score",
        "spf_present",
        "dmarc_present",
        "cms_detected",
        "cms_version",
        "cms_outdated",
        "ports_score",
        "open_ports",
        "cookies_score",
        "cookies_insecure",
        "top_issues",
        "talking_points",
        "scanned_at",
    ]

    rows = []
    for result in results:
        checks = result.get("checks", {})
        row = _result_to_row(result, checks)
        rows.append(row)

    path = Path(output_path)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def _result_to_row(result: dict, checks: dict) -> dict:
    """Convert a scan result to a CSV row."""
    # SSL
    ssl = checks.get("ssl", {})
    ssl_issues = ssl.get("issues", [])

    # Headers
    headers = checks.get("headers", {})
    headers_missing = headers.get("headers_missing", [])

    # Redirects
    redirects = checks.get("redirects", {})
    mixed = redirects.get("mixed_content", {})

    # DNS
    dns = checks.get("dns", {})
    spf = dns.get("spf", {})
    dmarc = dns.get("dmarc", {})

    # CMS
    cms = checks.get("cms", {})

    # Ports
    ports = checks.get("ports", {})
    open_ports = ports.get("open_ports", [])

    # Cookies
    cookies = checks.get("cookies", {})
    cookies_insecure = (
        cookies.get("cookies_without_secure", 0) +
        cookies.get("cookies_without_httponly", 0)
    )

    return {
        "domain": result.get("domain", ""),
        "total_score": result.get("total_score", 0),
        "grade": result.get("grade", ""),
        "lead_temperature": result.get("temperature", ""),
        "ssl_score": ssl.get("score", 0),
        "ssl_issues": "; ".join(ssl_issues),
        "headers_score": headers.get("score", 0),
        "headers_missing": "; ".join(headers_missing),
        "redirects_score": redirects.get("score", 0),
        "https_redirect": "Yes" if redirects.get("http_redirects_to_https") else "No",
        "mixed_content": "Yes" if mixed.get("detected") else "No",
        "dns_score": dns.get("score", 0),
        "spf_present": "Yes" if spf.get("present") else "No",
        "dmarc_present": "Yes" if dmarc.get("present") else "No",
        "cms_detected": cms.get("cms_detected") or "",
        "cms_version": cms.get("cms_version") or "",
        "cms_outdated": "Yes" if cms.get("is_outdated") else "No",
        "ports_score": ports.get("score", 0),
        "open_ports": "; ".join(str(p) for p in open_ports),
        "cookies_score": cookies.get("score", 0),
        "cookies_insecure": cookies_insecure,
        "top_issues": "; ".join(result.get("issues", [])[:5]),
        "talking_points": "; ".join(result.get("talking_points", [])),
        "scanned_at": datetime.now().isoformat(),
    }


def export_single_to_csv(result: dict, output_path: str) -> None:
    """Export a single scan result to CSV."""
    export_to_csv([result], output_path)
