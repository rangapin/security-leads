"""CLI entry point for Security Lead Scorer."""

from typing import Optional
import typer
from rich.console import Console
import tldextract

from .scanner import check_ssl, check_headers, check_redirects
from .output import format_table, format_json

app = typer.Typer(
    name="security-leads",
    help="Analyze prospect domains for security vulnerabilities and generate lead scores.",
    add_completion=False,
)
console = Console()

AVAILABLE_CHECKS = ["ssl", "headers", "redirects"]


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
