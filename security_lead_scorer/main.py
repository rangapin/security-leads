"""CLI entry point for Security Lead Scorer."""

from typing import Optional
import typer
from rich.console import Console
import tldextract

from .scanner import (
    check_ssl,
    check_headers,
    check_redirects,
    check_dns,
    check_cms,
    check_ports,
    check_cookies,
)
from .output import format_table, format_json

app = typer.Typer(
    name="security-leads",
    help="Analyze prospect domains for security vulnerabilities and generate lead scores.",
    add_completion=False,
)
console = Console()

AVAILABLE_CHECKS = ["ssl", "headers", "redirects", "dns", "cms", "ports", "cookies"]


def validate_domain(domain: str) -> str | None:
    """Validate and normalize domain. Returns normalized domain or None if invalid."""
    domain = domain.replace("https://", "").replace("http://", "")
    domain = domain.split("/")[0]

    extracted = tldextract.extract(domain)
    if not extracted.domain or not extracted.suffix:
        return None

    return f"{extracted.domain}.{extracted.suffix}"


def run_checks(domain: str, checks: list[str]) -> dict:
    """Run specified security checks on domain."""
    results = {
        "domain": domain,
        "checks": {},
        "total_score": 0,
        "issues": [],
    }

    if "ssl" in checks:
        ssl_result = check_ssl(domain)
        results["checks"]["ssl"] = ssl_result
        results["total_score"] += ssl_result.get("score", 0)
        results["issues"].extend(ssl_result.get("issues", []))

    if "headers" in checks:
        headers_result = check_headers(domain)
        results["checks"]["headers"] = headers_result
        results["total_score"] += headers_result.get("score", 0)
        results["issues"].extend(headers_result.get("issues", []))

    if "redirects" in checks:
        redirects_result = check_redirects(domain)
        results["checks"]["redirects"] = redirects_result
        results["total_score"] += redirects_result.get("score", 0)
        results["issues"].extend(redirects_result.get("issues", []))

    if "dns" in checks:
        dns_result = check_dns(domain)
        results["checks"]["dns"] = dns_result
        results["total_score"] += dns_result.get("score", 0)
        results["issues"].extend(dns_result.get("issues", []))

    if "cms" in checks:
        cms_result = check_cms(domain)
        results["checks"]["cms"] = cms_result
        results["total_score"] += cms_result.get("score", 0)
        results["issues"].extend(cms_result.get("issues", []))

    if "ports" in checks:
        ports_result = check_ports(domain)
        results["checks"]["ports"] = ports_result
        results["total_score"] += ports_result.get("score", 0)
        results["issues"].extend(ports_result.get("issues", []))

    if "cookies" in checks:
        cookies_result = check_cookies(domain)
        results["checks"]["cookies"] = cookies_result
        results["total_score"] += cookies_result.get("score", 0)
        results["issues"].extend(cookies_result.get("issues", []))

    # Cap score at 100
    results["total_score"] = min(100, results["total_score"])

    # Calculate grade
    score = results["total_score"]
    if score <= 15:
        results["grade"] = "A"
        results["temperature"] = "cold"
    elif score <= 35:
        results["grade"] = "B"
        results["temperature"] = "warm"
    elif score <= 55:
        results["grade"] = "C"
        results["temperature"] = "hot"
    elif score <= 75:
        results["grade"] = "D"
        results["temperature"] = "hot"
    else:
        results["grade"] = "F"
        results["temperature"] = "on_fire"

    return results


@app.command()
def scan(
    domain: str = typer.Argument(..., help="Domain to scan (e.g., example.com)"),
    checks: Optional[str] = typer.Option(
        None,
        "--checks",
        "-c",
        help=f"Comma-separated list of checks to run. Available: {', '.join(AVAILABLE_CHECKS)}",
    ),
    output_format: str = typer.Option(
        "table",
        "--format",
        "-f",
        help="Output format: table or json",
    ),
) -> None:
    """Scan a single domain for security issues."""
    # Validate domain
    normalized = validate_domain(domain)
    if not normalized:
        console.print(f"[red]Invalid domain: {domain}[/red]")
        raise typer.Exit(1)

    # Parse checks
    if checks:
        check_list = [c.strip().lower() for c in checks.split(",")]
        invalid = [c for c in check_list if c not in AVAILABLE_CHECKS]
        if invalid:
            console.print(f"[red]Invalid checks: {', '.join(invalid)}[/red]")
            console.print(f"Available checks: {', '.join(AVAILABLE_CHECKS)}")
            raise typer.Exit(1)
    else:
        check_list = AVAILABLE_CHECKS

    # Run scan
    console.print(f"[cyan]Scanning {normalized}...[/cyan]")
    results = run_checks(normalized, check_list)

    # Output results
    if output_format == "json":
        format_json(results, console)
    else:
        format_table(results, console)


@app.command()
def version() -> None:
    """Show version information."""
    from . import __version__
    console.print(f"security-leads version {__version__}")


if __name__ == "__main__":
    app()
