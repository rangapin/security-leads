"""Output formatters for scan results."""

import json

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text


SEVERITY_COLORS = {
    "critical": "red",
    "high": "red",
    "medium": "yellow",
    "low": "green",
    "unknown": "dim",
}

TEMPERATURE_EMOJI = {
    "cold": "[blue]cold[/blue]",
    "warm": "[yellow]warm[/yellow]",
    "hot": "[red]HOT[/red]",
    "on_fire": "[bold red]ON FIRE[/bold red]",
}


def format_table(results: dict, console: Console) -> None:
    """Format and print results as a rich table."""
    domain = results["domain"]
    score = results["total_score"]
    grade = results["grade"]
    temperature = results["temperature"]

    # Header panel
    temp_display = TEMPERATURE_EMOJI.get(temperature, temperature)
    header = Text()
    header.append(f"Security Lead Score: {domain}\n", style="bold cyan")
    header.append(f"Score: {score}/100  |  Grade: {grade}  |  Lead Temperature: {temp_display}")

    console.print(Panel(header, title="[bold]Scan Results[/bold]", border_style="cyan"))
    console.print()

    # Results table
    table = Table(show_header=True, header_style="bold")
    table.add_column("Check", style="cyan", width=12)
    table.add_column("Score", justify="right", width=8)
    table.add_column("Severity", width=10)
    table.add_column("Findings", width=50)

    for check_name, check_data in results.get("checks", {}).items():
        check_score = check_data.get("score", 0)
        severity = check_data.get("severity", "unknown")
        issues = check_data.get("issues", [])

        severity_color = SEVERITY_COLORS.get(severity, "white")
        severity_display = f"[{severity_color}]{severity}[/{severity_color}]"

        if issues:
            findings = "\n".join(f"- {issue}" for issue in issues[:3])
            if len(issues) > 3:
                findings += f"\n... and {len(issues) - 3} more"
        else:
            findings = "[green]No issues found[/green]"

        table.add_row(
            check_name.upper(),
            f"+{check_score}",
            severity_display,
            findings,
        )

    console.print(table)
    console.print()

    # Additional details for each check
    checks = results.get("checks", {})

    # SSL details
    if "ssl" in checks:
        ssl_data = checks["ssl"]
        ssl_table = Table(show_header=False, box=None, padding=(0, 2))
        ssl_table.add_column("Key", style="dim")
        ssl_table.add_column("Value")

        ssl_table.add_row("Has SSL", _bool_display(ssl_data.get("has_ssl")))
        ssl_table.add_row("Valid", _bool_display(ssl_data.get("is_valid")))
        ssl_table.add_row("Issuer", str(ssl_data.get("issuer") or "N/A"))
        ssl_table.add_row("TLS Version", str(ssl_data.get("tls_version") or "N/A"))

        days = ssl_data.get("days_until_expiry")
        if days is not None:
            if days < 0:
                expiry_display = f"[red]Expired {abs(days)} days ago[/red]"
            elif days < 7:
                expiry_display = f"[red]{days} days[/red]"
            elif days < 30:
                expiry_display = f"[yellow]{days} days[/yellow]"
            else:
                expiry_display = f"[green]{days} days[/green]"
            ssl_table.add_row("Expires In", expiry_display)

        console.print(Panel(ssl_table, title="[bold]SSL Details[/bold]", border_style="dim"))
        console.print()

    # Headers details
    if "headers" in checks:
        headers_data = checks["headers"]
        present = headers_data.get("headers_present", [])
        missing = headers_data.get("headers_missing", [])

        headers_table = Table(show_header=False, box=None, padding=(0, 2))
        headers_table.add_column("Status", width=10)
        headers_table.add_column("Headers")

        if present:
            headers_table.add_row("[green]Present[/green]", ", ".join(present))
        if missing:
            headers_table.add_row("[red]Missing[/red]", ", ".join(missing))

        console.print(Panel(headers_table, title="[bold]Security Headers[/bold]", border_style="dim"))
        console.print()

    # Redirect details
    if "redirects" in checks:
        redirect_data = checks["redirects"]
        redirect_table = Table(show_header=False, box=None, padding=(0, 2))
        redirect_table.add_column("Key", style="dim")
        redirect_table.add_column("Value")

        redirect_table.add_row("HTTP->HTTPS", _bool_display(redirect_data.get("http_redirects_to_https")))
        redirect_table.add_row("Redirect Type", str(redirect_data.get("redirect_type") or "N/A"))
        redirect_table.add_row("Final URL", str(redirect_data.get("final_url") or "N/A"))

        mixed = redirect_data.get("mixed_content", {})
        if mixed.get("detected"):
            redirect_table.add_row(
                "Mixed Content",
                f"[red]Yes ({len(mixed.get('insecure_resources', []))} resources)[/red]"
            )
        else:
            redirect_table.add_row("Mixed Content", "[green]No[/green]")

        console.print(Panel(redirect_table, title="[bold]Redirects[/bold]", border_style="dim"))
        console.print()


def format_json(results: dict, console: Console) -> None:
    """Format and print results as JSON."""
    console.print_json(json.dumps(results, indent=2, default=str))


def _bool_display(value: bool | None) -> str:
    """Convert boolean to colored display string."""
    if value is True:
        return "[green]Yes[/green]"
    elif value is False:
        return "[red]No[/red]"
    else:
        return "[dim]Unknown[/dim]"
