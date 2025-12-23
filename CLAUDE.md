# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Security Lead Scorer is a Python CLI tool that analyzes prospect domains for security vulnerabilities and hygiene issues. It outputs a lead score (0-100, higher = worse security = better prospect for security product outreach) with detailed findings and talking points.

## Project Structure

```
security-lead-scorer/
├── main.py                 # CLI entry point (argparse)
├── scanner/                # Security check modules
│   ├── ssl_checker.py      # SSL/TLS certificate analysis
│   ├── header_checker.py   # HTTP security headers
│   ├── cms_detector.py     # CMS and version detection
│   ├── dns_checker.py      # SPF, DKIM, DMARC verification
│   ├── port_scanner.py     # Basic open port detection
│   ├── redirect_checker.py # HTTPS redirect and mixed content
│   └── cookie_checker.py   # Cookie security flags
├── scoring/
│   └── calculator.py       # Risk score calculation logic
├── output/
│   ├── csv_export.py       # CSV output formatting
│   ├── json_export.py      # JSON output formatting
│   └── talking_points.py   # Generate outreach talking points
├── utils/
│   ├── rate_limiter.py     # Token bucket rate limiter
│   ├── cache.py            # File-based scan cache
│   └── async_runner.py     # Async domain processing
├── config.py               # Configuration constants
└── requirements.txt
```

## CLI Commands

```bash
# Single domain scan
python main.py scan example.com
python main.py scan example.com --checks ssl,headers,cms
python main.py scan example.com --format json

# Bulk scan from CSV
python main.py scan-bulk domains.csv --output results.csv
python main.py scan-bulk domains.csv --format json --concurrency 10
python main.py scan-bulk domains.csv --cache --cache-ttl 86400 -v
```

## Architecture

### Scanner Modules
Each scanner module returns a dict with:
- Module-specific findings
- `issues: list[str]` - list of detected problems
- `severity: "low" | "medium" | "high" | "critical"` - overall severity

### Scoring System
- Each scanner contributes points based on severity
- Total score capped at 100
- Grade mapping: A (0-15), B (16-35), C (36-55), D (56-75), F (76-100)
- Lead temperature: cold (A), warm (B), hot (C/D), on_fire (F)

### Key Scoring Weights
- SSL: No SSL +30, Expired +25, TLS 1.0/1.1 +15
- Headers: Missing CSP/HSTS +10 each, X-Frame-Options +8
- CMS: 2+ versions behind +20, version unknown +5
- DNS: No SPF/DMARC +10 each
- Ports: Exposed database ports +25, Telnet +20
- Redirects: No HTTPS redirect +15, mixed content +10

## Dependencies

- requests, beautifulsoup4 - HTTP/HTML
- dnspython - DNS queries
- tldextract - Domain parsing
- rich - CLI output formatting

## Implementation Notes

- All scanner modules should handle errors gracefully and return partial results
- Port scanning uses minimal timeouts (2s) and only checks risky ports
- Rate limiting default: 10 requests/second
- Cache uses MD5 hash of domain for file keys
- User-Agent should identify the tool for transparency
