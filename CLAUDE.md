# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Security Lead Scorer is a Python CLI tool that analyzes prospect domains for security vulnerabilities and hygiene issues. It outputs a lead score (0-100, higher = worse security = better prospect for security product outreach) with detailed findings.

## Project Structure

```
security-leads/
├── pyproject.toml                    # Package config, dependencies, CLI entry point
├── security_lead_scorer/
│   ├── __init__.py
│   ├── main.py                       # CLI entry point (typer)
│   ├── config.py                     # Configuration constants and scoring weights
│   ├── scanner/
│   │   ├── __init__.py
│   │   ├── ssl_checker.py            # SSL/TLS certificate analysis
│   │   ├── header_checker.py         # HTTP security headers
│   │   ├── redirect_checker.py       # HTTPS redirect and mixed content
│   │   ├── dns_checker.py            # SPF, DKIM, DMARC verification
│   │   ├── cms_detector.py           # CMS and version detection
│   │   ├── port_scanner.py           # Risky open port detection
│   │   └── cookie_checker.py         # Cookie security flags
│   ├── scoring/
│   │   ├── __init__.py
│   │   └── calculator.py             # Score aggregation and grading
│   └── output/
│       ├── __init__.py
│       ├── formatters.py             # Rich table and JSON output
│       ├── csv_export.py             # CSV export for bulk results
│       └── talking_points.py         # Outreach talking points generator
├── tests/                            # pytest test suite (98 tests)
└── docs.md                           # Full project specification
```

## Development

```bash
# Install in development mode
pip install -e .

# Run tests
pytest tests/ -v

# Run CLI - single domain
security-leads scan example.com
security-leads scan example.com --checks ssl,headers
security-leads scan example.com --format json
security-leads scan example.com --output results.csv

# Run CLI - bulk scanning
security-leads scan-bulk domains.csv --output results.csv
security-leads scan-bulk domains.csv --checks ssl,headers,dns -v
```

## Architecture

### Scanner Modules
Each scanner module (`scanner/*.py`) returns a dict with:
- Module-specific findings (e.g., `has_ssl`, `headers_present`)
- `issues: list[str]` - detected problems
- `severity: "low" | "medium" | "high" | "critical" | "unknown"`
- `score: int` - points contributed to total

### Scoring System
- Each scanner contributes points based on findings
- Total score capped at 100
- Grade mapping: A (0-15), B (16-35), C (36-55), D (56-75), F (76-100)
- Lead temperature: cold (A), warm (B), hot (C/D), on_fire (F)

### Key Scoring Weights (see `config.py`)
- SSL: No SSL +30, Expired +25, Expiring <7d +20, TLS 1.0/1.1 +15
- Headers: Missing CSP/HSTS +10 each, X-Frame-Options +8, X-Content-Type-Options +5
- Redirects: No HTTPS redirect +15, 302 instead of 301 +5, mixed content +10
- DNS: No SPF +10, No DMARC +10, No DKIM +5, weak SPF +5
- CMS: 2+ versions behind +20, 1 version behind +10, version unknown +5
- Ports: Exposed database (MySQL/PostgreSQL/MongoDB) +25, Telnet +20, RDP +20
- Cookies: Missing Secure +5, Missing HttpOnly +5, Missing SameSite +3

## Tech Stack
- **CLI**: typer + rich
- **HTTP**: httpx
- **HTML parsing**: beautifulsoup4
- **Domain validation**: tldextract
- **DNS queries**: dnspython

## Planned Features (Phase 4)
- Async bulk scanning for improved performance
- Rate limiting and caching
- PyPI packaging
