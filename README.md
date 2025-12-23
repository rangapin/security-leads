# Security Lead Scorer

A Python CLI tool that analyzes domains for security vulnerabilities and generates lead scores for sales outreach. Higher scores indicate worse security posture, making them better prospects for security products.

## Why?

Companies with poor security hygiene are the ideal customers for security products. This tool automates the process of identifying these prospects by scanning for common security issues and generating actionable talking points for outreach.

## Installation

### From PyPI (recommended)

```bash
pip install security-lead-scorer
```

### From source

```bash
git clone https://github.com/rangapin/security-leads.git
cd security-leads
pip install -e .
```

## Quick Start

```bash
# Scan a single domain
security-leads scan example.com

# Scan multiple domains from a CSV file
security-leads scan-bulk domains.csv --output results.csv
```

## What It Checks

| Check | What it analyzes | Points |
|-------|------------------|--------|
| **SSL/TLS** | Certificate validity, expiration, TLS version | 0-30 |
| **Headers** | HSTS, CSP, X-Frame-Options, etc. | 0-46 |
| **Redirects** | HTTP→HTTPS redirect, mixed content | 0-30 |
| **DNS** | SPF, DKIM, DMARC email authentication | 0-25 |
| **CMS** | WordPress/Joomla/Drupal version detection | 0-25 |
| **Ports** | Exposed databases (MySQL, MongoDB, Redis) | 0-25+ |
| **Cookies** | Secure, HttpOnly, SameSite flags | 0-13 |

## Scoring System

Domains are scored 0-100 based on security issues found:

| Score | Grade | Lead Temperature | Meaning |
|-------|-------|------------------|---------|
| 0-15 | A | Cold | Good security - low priority |
| 16-35 | B | Warm | Minor issues - potential lead |
| 36-55 | C | Hot | Multiple issues - good prospect |
| 56-75 | D | Hot | Significant problems - strong prospect |
| 76-100 | F | On Fire | Critical issues - urgent prospect |

## CLI Usage

### Single Domain Scan

```bash
# Basic scan (all checks)
security-leads scan example.com

# Run specific checks only
security-leads scan example.com --checks ssl,headers,dns

# Output as JSON
security-leads scan example.com --format json

# Save to CSV
security-leads scan example.com --output result.csv
```

### Bulk Scanning

```bash
# Scan domains from CSV file
security-leads scan-bulk domains.csv --output results.csv

# With options
security-leads scan-bulk domains.csv \
  --output results.csv \
  --checks ssl,headers,dns \
  --concurrency 10 \
  --cache \
  --verbose
```

**Bulk scan options:**

| Option | Description | Default |
|--------|-------------|---------|
| `--output, -o` | Output CSV file path | stdout |
| `--checks, -c` | Comma-separated checks to run | all |
| `--concurrency` | Parallel scans | 5 |
| `--cache` | Skip recently scanned domains | off |
| `--cache-ttl` | Cache expiry in seconds | 86400 |
| `--verbose, -v` | Show progress per domain | off |

### Input File Format

The input CSV can be:
- One domain per line (no header)
- CSV with a `domain` column
- Any CSV (first column used as domain)

```csv
domain
example.com
another-site.com
test.org
```

## Output

### Table Output (default)

```
┌─────────────────────────────────────────────────────────────────┐
│                Security Lead Score: example.com                  │
├─────────────────────────────────────────────────────────────────┤
│  TOTAL SCORE: 67/100                    Grade: D                 │
│  Lead Temperature: HOT                                           │
├─────────────────────────────────────────────────────────────────┤
│  Category Breakdown:                                             │
│  ├── SSL/TLS:        15 pts  Certificate expires in 12 days      │
│  ├── Headers:        23 pts  Missing CSP, HSTS                   │
│  ├── DNS:            10 pts  No DMARC record                     │
│  └── ...                                                         │
├─────────────────────────────────────────────────────────────────┤
│  Talking Points:                                                 │
│  • Your SSL cert expires in 12 days                              │
│  • Missing security headers leave your site exposed              │
│  • No DMARC means anyone can spoof emails from your domain       │
└─────────────────────────────────────────────────────────────────┘
```

### CSV Output

Includes all scan data plus generated talking points for outreach:

```csv
domain,total_score,grade,temperature,ssl_score,headers_score,...,talking_points
example.com,67,D,hot,15,23,...,"SSL expiring; Missing CSP; No DMARC"
```

## Development

```bash
# Clone and install in dev mode
git clone https://github.com/rangapin/security-leads.git
cd security-leads
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Run specific test file
pytest tests/test_ssl_checker.py -v
```

### Project Structure

```
security-leads/
├── security_lead_scorer/
│   ├── main.py              # CLI entry point
│   ├── config.py            # Scoring weights and constants
│   ├── scanner/             # Security check modules
│   │   ├── ssl_checker.py
│   │   ├── header_checker.py
│   │   ├── redirect_checker.py
│   │   ├── dns_checker.py
│   │   ├── cms_detector.py
│   │   ├── port_scanner.py
│   │   └── cookie_checker.py
│   ├── scoring/
│   │   └── calculator.py    # Score aggregation
│   ├── output/
│   │   ├── formatters.py    # Table/JSON output
│   │   ├── csv_export.py    # CSV export
│   │   └── talking_points.py
│   └── utils/
│       ├── rate_limiter.py  # Request throttling
│       ├── cache.py         # Result caching
│       └── async_runner.py  # Concurrent scanning
└── tests/                   # 146 tests
```

## Legal & Ethical Use

This tool performs **passive reconnaissance only**:

- No exploitation or penetration testing
- Minimal, polite port scanning with timeouts
- Identifies User-Agent in requests
- Respects rate limits

**Only scan domains you have legitimate business interest in.**

## License

MIT
