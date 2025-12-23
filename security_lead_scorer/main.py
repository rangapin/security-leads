"""CLI entry point for Security Lead Scorer."""

import asyncio
import csv
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
import tldextract

from .config import DEFAULT_CONCURRENCY, DEFAULT_RATE_LIMIT, CACHE_DIR, CACHE_TTL
from .scanner import (
    check_ssl,
    check_headers,
    check_redirects,
    check_dns,
    check_cms,
    check_ports,
    check_cookies,
)
from .scoring import get_grade, get_temperature
from .output import format_table, format_json, export_to_csv, generate_talking_points
from .utils import ScanCache, run_bulk_scans

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

    # Calculate grade and temperature
    results["grade"] = get_grade(results["total_score"])
    results["temperature"] = get_temperature(results["grade"])

    # Generate talking points
    results["talking_points"] = generate_talking_points(results)

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
    output: Optional[str] = typer.Option(
        None,
        "--output",
        "-o",
        help="Output file path (CSV format)",
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
    if output:
        export_to_csv([results], output)
        console.print(f"[green]Results saved to {output}[/green]")
    elif output_format == "json":
        format_json(results, console)
    else:
        format_table(results, console)


@app.command("scan-bulk")
def scan_bulk(
    input_file: str = typer.Argument(..., help="CSV file with domains (one per line or 'domain' column)"),
    output: Optional[str] = typer.Option(
        None,
        "--output",
        "-o",
        help="Output CSV file path",
    ),
    checks: Optional[str] = typer.Option(
        None,
        "--checks",
        "-c",
        help=f"Comma-separated list of checks. Available: {', '.join(AVAILABLE_CHECKS)}",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Show progress for each domain",
    ),
    concurrency: int = typer.Option(
        DEFAULT_CONCURRENCY,
        "--concurrency",
        help="Number of concurrent scans",
    ),
    use_cache: bool = typer.Option(
        False,
        "--cache",
        help="Use cache to skip recently scanned domains",
    ),
    cache_ttl: int = typer.Option(
        CACHE_TTL,
        "--cache-ttl",
        help="Cache TTL in seconds (default: 86400 = 24 hours)",
    ),
) -> None:
    """Scan multiple domains from a CSV file."""
    # Read domains from file
    input_path = Path(input_file)
    if not input_path.exists():
        console.print(f"[red]File not found: {input_file}[/red]")
        raise typer.Exit(1)

    domains = _read_domains_from_csv(input_path)
    if not domains:
        console.print("[red]No valid domains found in file[/red]")
        raise typer.Exit(1)

    console.print(f"[cyan]Found {len(domains)} domains to scan[/cyan]")

    # Parse checks
    if checks:
        check_list = [c.strip().lower() for c in checks.split(",")]
        invalid = [c for c in check_list if c not in AVAILABLE_CHECKS]
        if invalid:
            console.print(f"[red]Invalid checks: {', '.join(invalid)}[/red]")
            raise typer.Exit(1)
    else:
        check_list = AVAILABLE_CHECKS

    # Validate and normalize domains first
    valid_domains = []
    for domain in domains:
        normalized = validate_domain(domain)
        if normalized:
            valid_domains.append(normalized)
        elif verbose:
            console.print(f"[yellow]Skipping invalid domain: {domain}[/yellow]")

    if not valid_domains:
        console.print("[red]No valid domains after validation[/red]")
        raise typer.Exit(1)

    console.print(f"[cyan]Scanning {len(valid_domains)} valid domains (concurrency: {concurrency})...[/cyan]")

    # Setup cache if enabled
    cache = ScanCache(CACHE_DIR, cache_ttl) if use_cache else None
    if use_cache:
        console.print(f"[dim]Cache enabled (TTL: {cache_ttl}s)[/dim]")

    # Create scan function with selected checks
    def scan_domain(domain: str) -> dict:
        return run_checks(domain, check_list)

    # Run async bulk scan
    results = []
    cached_count = 0

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Scanning...", total=len(valid_domains))

        def on_progress(domain: str, result: dict | None, error: Exception | None):
            nonlocal cached_count
            progress.advance(task)

            if result and result.get("from_cache"):
                cached_count += 1
                if verbose:
                    console.print(f"  [dim]{domain}[/dim]: [cyan](cached)[/cyan]")
            elif verbose:
                if error:
                    console.print(f"  [red]Error: {domain}: {error}[/red]")
                elif result:
                    grade = result.get("grade", "?")
                    score = result.get("total_score", 0)
                    console.print(f"  [dim]{domain}[/dim]: {score}/100 (Grade {grade})")

        # Run the async scan
        results = asyncio.run(
            run_bulk_scans(
                domains=valid_domains,
                scan_func=scan_domain,
                concurrency=concurrency,
                rate_limit=DEFAULT_RATE_LIMIT,
                cache=cache,
                on_progress=on_progress,
            )
        )

    console.print(f"\n[green]Completed scanning {len(results)} domains[/green]")

    # Summary stats
    if results:
        hot_leads = sum(1 for r in results if r.get("temperature") in ("hot", "on_fire"))
        console.print(f"[cyan]Hot leads: {hot_leads}/{len(results)}[/cyan]")
        if cached_count > 0:
            console.print(f"[dim]From cache: {cached_count}[/dim]")

    # Output
    if output:
        export_to_csv(results, output)
        console.print(f"[green]Results saved to {output}[/green]")
    else:
        # Print summary table
        console.print("\n[bold]Results Summary:[/bold]")
        for result in results[:10]:  # Show first 10
            domain = result.get("domain", "?")
            score = result.get("total_score", 0)
            grade = result.get("grade", "?")
            temp = result.get("temperature", "?")
            cached = " [cyan](cached)[/cyan]" if result.get("from_cache") else ""
            console.print(f"  {domain}: {score}/100 (Grade {grade}, {temp}){cached}")

        if len(results) > 10:
            console.print(f"  ... and {len(results) - 10} more")
        console.print("\n[dim]Use --output to save full results to CSV[/dim]")


def _read_domains_from_csv(path: Path) -> list[str]:
    """Read domains from a CSV file."""
    domains = []

    with path.open("r", encoding="utf-8") as f:
        # Try to detect if it's a CSV with headers
        sample = f.read(1024)
        f.seek(0)

        if "," in sample or "domain" in sample.lower():
            # It's a CSV, try to find domain column
            reader = csv.DictReader(f)
            fieldnames = [fn.lower() for fn in (reader.fieldnames or [])]

            if "domain" in fieldnames:
                for row in reader:
                    domain = row.get("domain") or row.get("Domain") or ""
                    if domain.strip():
                        domains.append(domain.strip())
            else:
                # No domain column, take first column
                f.seek(0)
                reader = csv.reader(f)
                next(reader, None)  # Skip header
                for row in reader:
                    if row and row[0].strip():
                        domains.append(row[0].strip())
        else:
            # Plain text file, one domain per line
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    domains.append(line)

    return domains


@app.command()
def version() -> None:
    """Show version information."""
    from . import __version__
    console.print(f"security-leads version {__version__}")


if __name__ == "__main__":
    app()
