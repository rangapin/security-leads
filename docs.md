# Security Lead Scorer — Claude Code Project Specification

## Executive Summary

Build a Python CLI tool that analyzes prospect domains for security vulnerabilities and hygiene issues. The tool outputs a lead score (0-100, where higher = worse security = hotter lead for Achilleus.so outreach) along with detailed findings and recommended talking points.

This tool fills a gap in GTM engineering: no one is doing security-based lead qualification. For Achilleus (security monitoring SaaS for digital agencies at $27/month per site), prospects with poor security hygiene are the exact ICP.

---

## Project Structure

```
security-lead-scorer/
├── main.py                 # CLI entry point
├── scanner/
│   ├── __init__.py
│   ├── ssl_checker.py      # SSL/TLS certificate analysis
│   ├── header_checker.py   # HTTP security headers
│   ├── cms_detector.py     # CMS and version detection
│   ├── dns_checker.py      # SPF, DKIM, DMARC verification
│   ├── port_scanner.py     # Basic open port detection
│   ├── redirect_checker.py # HTTPS redirect and mixed content
│   └── cookie_checker.py   # Cookie security flags
├── scoring/
│   ├── __init__.py
│   └── calculator.py       # Risk score calculation logic
├── output/
│   ├── __init__.py
│   ├── csv_export.py       # CSV output formatting
│   ├── json_export.py      # JSON output formatting
│   └── talking_points.py   # Generate outreach talking points
├── utils/
│   ├── __init__.py
│   ├── rate_limiter.py     # Rate limiting for bulk scans
│   ├── cache.py            # Simple file-based cache
│   └── async_runner.py     # Async domain processing
├── config.py               # Configuration constants
├── requirements.txt        # Dependencies
└── README.md               # Usage documentation
```

---

## Core Functionality

### 1. SSL/TLS Certificate Checker (`scanner/ssl_checker.py`)

**Purpose:** Analyze SSL certificate validity, expiration, and configuration.

**Checks to perform:**
- Certificate present (yes/no)
- Certificate valid (not self-signed, trusted CA)
- Expiration date (flag if < 30 days, critical if < 7 days or expired)
- Certificate chain complete
- TLS version supported (flag TLS 1.0/1.1, prefer 1.2/1.3)
- Common name matches domain

**Implementation approach:**
```python
import ssl
import socket
from datetime import datetime, timedelta

def check_ssl(domain: str, port: int = 443) -> dict:
    """
    Returns:
    {
        "has_ssl": bool,
        "is_valid": bool,
        "issuer": str,
        "expires": str (ISO format),
        "days_until_expiry": int,
        "expiry_status": "valid" | "expiring_soon" | "critical" | "expired",
        "tls_version": str,
        "tls_status": "secure" | "outdated" | "insecure",
        "chain_complete": bool,
        "issues": list[str],
        "severity": "low" | "medium" | "high" | "critical"
    }
    """
    # Create SSL context
    context = ssl.create_default_context()
    
    # Connect and retrieve certificate
    # Handle exceptions for invalid/missing certs
    # Parse certificate details
    # Calculate days until expiry
    # Determine severity based on findings
```

**Scoring contribution:**
- No SSL: +30 points
- Expired: +25 points
- Expiring < 7 days: +20 points
- Expiring < 30 days: +10 points
- TLS 1.0/1.1: +15 points
- Self-signed: +20 points
- Incomplete chain: +10 points

---

### 2. HTTP Security Headers Checker (`scanner/header_checker.py`)

**Purpose:** Verify presence and configuration of security headers.

**Headers to check:**

| Header | Purpose | Missing = Points |
|--------|---------|------------------|
| Strict-Transport-Security (HSTS) | Force HTTPS | +10 |
| Content-Security-Policy (CSP) | Prevent XSS | +10 |
| X-Frame-Options | Prevent clickjacking | +8 |
| X-Content-Type-Options | Prevent MIME sniffing | +5 |
| X-XSS-Protection | Legacy XSS filter | +3 |
| Referrer-Policy | Control referrer info | +5 |
| Permissions-Policy | Control browser features | +5 |

**Implementation approach:**
```python
import requests

SECURITY_HEADERS = {
    "Strict-Transport-Security": {"required": True, "points": 10},
    "Content-Security-Policy": {"required": True, "points": 10},
    "X-Frame-Options": {"required": True, "points": 8},
    "X-Content-Type-Options": {"required": True, "points": 5},
    "X-XSS-Protection": {"required": False, "points": 3},
    "Referrer-Policy": {"required": False, "points": 5},
    "Permissions-Policy": {"required": False, "points": 5},
}

def check_headers(domain: str) -> dict:
    """
    Returns:
    {
        "headers_present": list[str],
        "headers_missing": list[str],
        "header_details": {
            "header_name": {
                "present": bool,
                "value": str | None,
                "is_configured_properly": bool,
                "issues": list[str]
            }
        },
        "issues": list[str],
        "severity": "low" | "medium" | "high"
    }
    """
    # Make GET request with timeout
    # Parse response headers
    # Check each security header
    # Validate header values where applicable
    # e.g., HSTS should have max-age > 31536000
```

---

### 3. CMS Detector (`scanner/cms_detector.py`)

**Purpose:** Identify CMS platform and version, flag if outdated.

**CMS to detect:**
- WordPress (check /wp-content/, meta generator, /wp-json/)
- Joomla (check /administrator/, meta generator)
- Drupal (check /core/, /sites/, meta generator)
- Wix (check meta generator, script sources)
- Squarespace (check meta generator, script sources)
- Shopify (check meta generator, /cdn.shopify.com/)
- Webflow (check meta generator)
- Ghost (check meta generator)
- Custom/Unknown

**Version detection:**
- WordPress: `/wp-json/` endpoint, meta generator tag, readme.html
- Parse version from detected sources
- Compare against known latest stable versions (hardcode or fetch from API)

**Implementation approach:**
```python
import requests
from bs4 import BeautifulSoup
import re

# Known latest versions (update periodically or fetch from API)
LATEST_VERSIONS = {
    "wordpress": "6.7.1",
    "joomla": "5.2.3",
    "drupal": "10.3.10",
}

def detect_cms(domain: str) -> dict:
    """
    Returns:
    {
        "cms_detected": str | None,
        "cms_version": str | None,
        "latest_version": str | None,
        "is_outdated": bool,
        "versions_behind": int | None,
        "detection_method": str,
        "issues": list[str],
        "severity": "low" | "medium" | "high" | "critical"
    }
    """
    # Fetch homepage
    # Check meta generator tag
    # Check known paths
    # Check script sources
    # Extract version if possible
    # Compare to latest
```

**Scoring contribution:**
- CMS detected but version unknown: +5 points
- CMS 1 major version behind: +10 points
- CMS 2+ major versions behind: +20 points
- CMS severely outdated (2+ years): +25 points
- WordPress with exposed wp-json: +5 points
- WordPress with exposed readme.html: +5 points

---

### 4. DNS Security Checker (`scanner/dns_checker.py`)

**Purpose:** Verify email authentication records that indicate security awareness.

**Records to check:**
- SPF (Sender Policy Framework): TXT record starting with "v=spf1"
- DKIM: Difficult without knowing selector, check for common selectors
- DMARC: TXT record at _dmarc.domain.com

**Implementation approach:**
```python
import dns.resolver

def check_dns_security(domain: str) -> dict:
    """
    Returns:
    {
        "spf": {
            "present": bool,
            "record": str | None,
            "is_valid": bool,
            "policy_strength": "weak" | "moderate" | "strict",
            "issues": list[str]
        },
        "dmarc": {
            "present": bool,
            "record": str | None,
            "policy": "none" | "quarantine" | "reject" | None,
            "issues": list[str]
        },
        "dkim_selectors_found": list[str],
        "overall_email_security": "poor" | "basic" | "good" | "excellent",
        "issues": list[str],
        "severity": "low" | "medium" | "high"
    }
    """
    # Query TXT records for domain
    # Look for SPF record
    # Query _dmarc.domain.com
    # Try common DKIM selectors (google, default, mail, etc.)
```

**Scoring contribution:**
- No SPF record: +10 points
- Weak SPF (ends with ~all or ?all): +5 points
- No DMARC record: +10 points
- DMARC policy=none: +5 points
- No DKIM detectable: +5 points

---

### 5. Port Scanner (`scanner/port_scanner.py`)

**Purpose:** Identify potentially dangerous open ports.

**Ports to check:**
| Port | Service | Risk if Open |
|------|---------|--------------|
| 21 | FTP | High - unencrypted file transfer |
| 22 | SSH | Medium - depends on config |
| 23 | Telnet | Critical - unencrypted remote access |
| 25 | SMTP | Medium - potential relay |
| 3306 | MySQL | Critical - database exposure |
| 5432 | PostgreSQL | Critical - database exposure |
| 3389 | RDP | Critical - remote desktop |
| 27017 | MongoDB | Critical - database exposure |
| 6379 | Redis | Critical - cache/db exposure |

**Implementation approach:**
```python
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

RISKY_PORTS = {
    21: {"service": "FTP", "severity": "high", "points": 15},
    22: {"service": "SSH", "severity": "medium", "points": 5},
    23: {"service": "Telnet", "severity": "critical", "points": 20},
    25: {"service": "SMTP", "severity": "medium", "points": 5},
    3306: {"service": "MySQL", "severity": "critical", "points": 25},
    5432: {"service": "PostgreSQL", "severity": "critical", "points": 25},
    3389: {"service": "RDP", "severity": "critical", "points": 20},
    27017: {"service": "MongoDB", "severity": "critical", "points": 25},
    6379: {"service": "Redis", "severity": "critical", "points": 25},
}

def scan_ports(domain: str, timeout: float = 2.0) -> dict:
    """
    Returns:
    {
        "open_ports": list[int],
        "port_details": {
            port: {
                "service": str,
                "is_open": bool,
                "severity": str,
                "issue": str
            }
        },
        "issues": list[str],
        "severity": "low" | "medium" | "high" | "critical"
    }
    """
    # Resolve domain to IP
    # Use ThreadPoolExecutor for concurrent scanning
    # Attempt socket connection with timeout
    # Return findings
```

**Important:** Keep port scanning minimal and polite. Use appropriate timeouts. This is reconnaissance, not penetration testing.

---

### 6. HTTPS Redirect Checker (`scanner/redirect_checker.py`)

**Purpose:** Verify proper HTTPS enforcement and detect mixed content issues.

**Checks:**
- HTTP → HTTPS redirect present
- Redirect is 301 (permanent) not 302 (temporary)
- No redirect loops
- Final destination uses HTTPS
- Check for mixed content (HTTP resources on HTTPS page)

**Implementation approach:**
```python
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse

def check_redirects(domain: str) -> dict:
    """
    Returns:
    {
        "http_redirects_to_https": bool,
        "redirect_type": int | None,  # 301, 302, etc.
        "redirect_chain": list[str],
        "final_url": str,
        "final_is_https": bool,
        "has_redirect_loop": bool,
        "mixed_content": {
            "detected": bool,
            "insecure_resources": list[str]  # URLs of HTTP resources
        },
        "issues": list[str],
        "severity": "low" | "medium" | "high"
    }
    """
    # Request HTTP version with allow_redirects=False
    # Follow redirects manually, tracking chain
    # Check final page for mixed content
    # Parse HTML, look for http:// in src/href attributes
```

**Scoring contribution:**
- No HTTP → HTTPS redirect: +15 points
- Redirect is 302 not 301: +5 points
- Mixed content detected: +10 points
- Redirect loop: +10 points

---

### 7. Cookie Security Checker (`scanner/cookie_checker.py`)

**Purpose:** Analyze cookie security flags.

**Flags to check:**
- Secure: Cookie only sent over HTTPS
- HttpOnly: Cookie not accessible via JavaScript
- SameSite: CSRF protection (Strict, Lax, None)

**Implementation approach:**
```python
import requests

def check_cookies(domain: str) -> dict:
    """
    Returns:
    {
        "cookies_found": int,
        "cookie_details": [
            {
                "name": str,
                "secure": bool,
                "httponly": bool,
                "samesite": str | None,
                "issues": list[str]
            }
        ],
        "cookies_without_secure": int,
        "cookies_without_httponly": int,
        "cookies_without_samesite": int,
        "issues": list[str],
        "severity": "low" | "medium" | "high"
    }
    """
    # Make request, capture Set-Cookie headers
    # Parse each cookie's attributes
    # Flag missing security attributes
```

**Scoring contribution:**
- Any cookie without Secure flag: +5 points
- Any cookie without HttpOnly flag: +5 points
- Any cookie without SameSite: +3 points

---

## Scoring System (`scoring/calculator.py`)

### Score Calculation

```python
def calculate_score(scan_results: dict) -> dict:
    """
    Aggregate all findings into a single lead score.
    
    Returns:
    {
        "total_score": int,  # 0-100, capped
        "raw_score": int,    # Uncapped for reference
        "grade": "A" | "B" | "C" | "D" | "F",
        "lead_temperature": "cold" | "warm" | "hot" | "on_fire",
        "category_scores": {
            "ssl": int,
            "headers": int,
            "cms": int,
            "dns": int,
            "ports": int,
            "redirects": int,
            "cookies": int
        },
        "top_issues": list[str],  # Top 5 most severe
        "issue_count": {
            "critical": int,
            "high": int,
            "medium": int,
            "low": int
        }
    }
    """
```

### Grade Mapping

| Score | Grade | Lead Temperature | Meaning |
|-------|-------|------------------|---------|
| 0-15 | A | Cold | Good security, not a priority lead |
| 16-35 | B | Warm | Minor issues, potential lead |
| 36-55 | C | Hot | Multiple issues, good prospect |
| 56-75 | D | Hot | Significant problems, strong prospect |
| 76-100 | F | On Fire | Critical issues, urgent prospect |

---

## Output Generation

### 1. CSV Export (`output/csv_export.py`)

```python
def export_to_csv(results: list[dict], output_path: str) -> None:
    """
    Export scan results to CSV.
    
    Columns:
    - domain
    - total_score
    - grade
    - lead_temperature
    - ssl_score
    - ssl_issues (semicolon-separated)
    - headers_score
    - headers_missing (semicolon-separated)
    - cms_detected
    - cms_version
    - cms_outdated
    - dns_score
    - spf_present
    - dmarc_present
    - open_ports (semicolon-separated)
    - https_redirect
    - mixed_content
    - top_issues (semicolon-separated)
    - talking_points (semicolon-separated)
    - scanned_at (ISO timestamp)
    """
```

### 2. JSON Export (`output/json_export.py`)

```python
def export_to_json(results: list[dict], output_path: str) -> None:
    """
    Export full scan results to JSON for programmatic use.
    Includes all raw data from each scanner module.
    """
```

### 3. Talking Points Generator (`output/talking_points.py`)

**Purpose:** Generate personalized outreach angles based on findings.

```python
TALKING_POINT_TEMPLATES = {
    "ssl_expired": "Your SSL certificate expired {days} days ago — visitors are seeing security warnings.",
    "ssl_expiring": "Your SSL certificate expires in {days} days — worth renewing before it impacts SEO.",
    "no_https_redirect": "Your site doesn't redirect HTTP to HTTPS — Google penalizes this in rankings.",
    "missing_hsts": "Your site is missing HSTS headers — makes visitors vulnerable to downgrade attacks.",
    "missing_csp": "No Content Security Policy detected — leaves your site exposed to XSS attacks.",
    "wordpress_outdated": "Your WordPress installation ({version}) is {versions_behind} versions behind — known vulnerabilities exist.",
    "exposed_database": "Port {port} ({service}) is publicly accessible — this is a critical security risk.",
    "no_spf": "No SPF record found — anyone can spoof emails from your domain.",
    "no_dmarc": "No DMARC policy — you have no visibility into email spoofing attempts.",
    "mixed_content": "Your site loads insecure resources over HTTP — triggers browser warnings.",
}

def generate_talking_points(scan_result: dict) -> list[str]:
    """
    Returns list of 3-5 most compelling talking points for outreach,
    ordered by severity/impact.
    """
```

---

## CLI Interface (`main.py`)

### Usage

```bash
# Scan single domain
python main.py scan example.com

# Scan multiple domains from CSV
python main.py scan-bulk domains.csv --output results.csv

# Scan with specific checks only
python main.py scan example.com --checks ssl,headers,cms

# Output formats
python main.py scan example.com --format json
python main.py scan-bulk domains.csv --output results.json --format json

# Verbose mode (show progress)
python main.py scan-bulk domains.csv -v

# Set concurrency for bulk scans
python main.py scan-bulk domains.csv --concurrency 10

# Use cache (skip recently scanned domains)
python main.py scan-bulk domains.csv --cache --cache-ttl 86400
```

### Implementation

```python
import argparse
import asyncio
from pathlib import Path

def main():
    parser = argparse.ArgumentParser(
        description="Security Lead Scorer - Analyze domains for security issues"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    
    # Single domain scan
    scan_parser = subparsers.add_parser("scan", help="Scan a single domain")
    scan_parser.add_argument("domain", help="Domain to scan")
    scan_parser.add_argument("--checks", help="Comma-separated list of checks to run")
    scan_parser.add_argument("--format", choices=["table", "json"], default="table")
    
    # Bulk scan
    bulk_parser = subparsers.add_parser("scan-bulk", help="Scan domains from CSV")
    bulk_parser.add_argument("input_file", help="CSV file with domains")
    bulk_parser.add_argument("--output", "-o", help="Output file path")
    bulk_parser.add_argument("--format", choices=["csv", "json"], default="csv")
    bulk_parser.add_argument("--concurrency", type=int, default=5)
    bulk_parser.add_argument("--cache", action="store_true")
    bulk_parser.add_argument("--cache-ttl", type=int, default=86400)
    bulk_parser.add_argument("-v", "--verbose", action="store_true")
    
    args = parser.parse_args()
    
    if args.command == "scan":
        result = scan_domain(args.domain, args.checks)
        output_single_result(result, args.format)
    elif args.command == "scan-bulk":
        results = scan_bulk(
            args.input_file,
            concurrency=args.concurrency,
            use_cache=args.cache,
            cache_ttl=args.cache_ttl,
            verbose=args.verbose
        )
        export_results(results, args.output, args.format)

if __name__ == "__main__":
    main()
```

---

## Utility Modules

### Rate Limiter (`utils/rate_limiter.py`)

```python
import asyncio
from collections import deque
from time import time

class RateLimiter:
    """
    Token bucket rate limiter for polite scanning.
    Default: 10 requests per second.
    """
    
    def __init__(self, rate: int = 10, per: float = 1.0):
        self.rate = rate
        self.per = per
        self.tokens = rate
        self.last_update = time()
        self._lock = asyncio.Lock()
    
    async def acquire(self):
        async with self._lock:
            now = time()
            elapsed = now - self.last_update
            self.tokens = min(self.rate, self.tokens + elapsed * (self.rate / self.per))
            self.last_update = now
            
            if self.tokens < 1:
                wait_time = (1 - self.tokens) * (self.per / self.rate)
                await asyncio.sleep(wait_time)
                self.tokens = 0
            else:
                self.tokens -= 1
```

### Cache (`utils/cache.py`)

```python
import json
from pathlib import Path
from datetime import datetime, timedelta
from hashlib import md5

class ScanCache:
    """
    Simple file-based cache for scan results.
    Avoids re-scanning recently checked domains.
    """
    
    def __init__(self, cache_dir: str = ".cache", ttl_seconds: int = 86400):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)
        self.ttl = timedelta(seconds=ttl_seconds)
    
    def _cache_key(self, domain: str) -> str:
        return md5(domain.encode()).hexdigest()
    
    def get(self, domain: str) -> dict | None:
        cache_file = self.cache_dir / f"{self._cache_key(domain)}.json"
        if not cache_file.exists():
            return None
        
        data = json.loads(cache_file.read_text())
        cached_at = datetime.fromisoformat(data["cached_at"])
        
        if datetime.now() - cached_at > self.ttl:
            cache_file.unlink()
            return None
        
        return data["result"]
    
    def set(self, domain: str, result: dict) -> None:
        cache_file = self.cache_dir / f"{self._cache_key(domain)}.json"
        cache_file.write_text(json.dumps({
            "cached_at": datetime.now().isoformat(),
            "result": result
        }))
```

### Async Runner (`utils/async_runner.py`)

```python
import asyncio
from typing import Callable
from .rate_limiter import RateLimiter

async def run_bulk_scans(
    domains: list[str],
    scan_func: Callable,
    concurrency: int = 5,
    rate_limit: int = 10,
    verbose: bool = False
) -> list[dict]:
    """
    Run scans concurrently with rate limiting.
    """
    rate_limiter = RateLimiter(rate=rate_limit)
    semaphore = asyncio.Semaphore(concurrency)
    results = []
    
    async def scan_with_limit(domain: str) -> dict:
        async with semaphore:
            await rate_limiter.acquire()
            if verbose:
                print(f"Scanning: {domain}")
            try:
                return await scan_func(domain)
            except Exception as e:
                return {"domain": domain, "error": str(e)}
    
    tasks = [scan_with_limit(domain) for domain in domains]
    results = await asyncio.gather(*tasks)
    
    return results
```

---

## Configuration (`config.py`)

```python
# Timeouts (seconds)
HTTP_TIMEOUT = 10
SSL_TIMEOUT = 5
PORT_SCAN_TIMEOUT = 2
DNS_TIMEOUT = 5

# Rate limiting
DEFAULT_RATE_LIMIT = 10  # requests per second
DEFAULT_CONCURRENCY = 5  # parallel scans

# Cache
CACHE_DIR = ".cache"
CACHE_TTL = 86400  # 24 hours

# User agent
USER_AGENT = "SecurityLeadScorer/1.0 (Security Research)"

# Score thresholds
SCORE_THRESHOLDS = {
    "A": (0, 15),
    "B": (16, 35),
    "C": (36, 55),
    "D": (56, 75),
    "F": (76, 100),
}

TEMPERATURE_MAP = {
    "A": "cold",
    "B": "warm",
    "C": "hot",
    "D": "hot",
    "F": "on_fire",
}

# CMS latest versions (update periodically)
CMS_LATEST_VERSIONS = {
    "wordpress": "6.7.1",
    "joomla": "5.2.3",
    "drupal": "10.3.10",
    "ghost": "5.97.0",
}
```

---

## Dependencies (`requirements.txt`)

```
requests>=2.31.0
beautifulsoup4>=4.12.0
dnspython>=2.4.0
python-nmap>=0.7.1  # Optional, for advanced port scanning
tldextract>=5.1.0
rich>=13.7.0  # For nice CLI output
```

---

## Example Output

### Single Domain Scan (Table Format)

```
┌─────────────────────────────────────────────────────────────────┐
│                    Security Lead Score: example.com              │
├─────────────────────────────────────────────────────────────────┤
│  TOTAL SCORE: 67/100                    Grade: D                 │
│  Lead Temperature: 🔥 HOT                                        │
├─────────────────────────────────────────────────────────────────┤
│  Category Breakdown:                                             │
│  ├── SSL/TLS:        15 pts  ⚠️  Certificate expires in 12 days  │
│  ├── Headers:        23 pts  ❌  Missing CSP, HSTS, X-Frame      │
│  ├── CMS:            10 pts  ⚠️  WordPress 6.4 (1 version behind)│
│  ├── DNS:            10 pts  ❌  No DMARC record                 │
│  ├── Ports:           0 pts  ✅  No risky ports exposed          │
│  ├── Redirects:       5 pts  ⚠️  Using 302 instead of 301       │
│  └── Cookies:         4 pts  ⚠️  2 cookies missing Secure flag  │
├─────────────────────────────────────────────────────────────────┤
│  Top Issues:                                                     │
│  1. [HIGH] SSL certificate expires in 12 days                    │
│  2. [HIGH] Missing Content-Security-Policy header                │
│  3. [HIGH] Missing Strict-Transport-Security header              │
│  4. [MEDIUM] No DMARC record - email spoofing possible           │
│  5. [MEDIUM] WordPress version outdated                          │
├─────────────────────────────────────────────────────────────────┤
│  Talking Points for Outreach:                                    │
│  • Your SSL cert expires in 12 days — visitors will see warnings │
│  • Missing security headers leave your site exposed to XSS       │
│  • No DMARC means anyone can spoof emails from your domain       │
└─────────────────────────────────────────────────────────────────┘
```

### Bulk Scan CSV Output

```csv
domain,total_score,grade,lead_temperature,ssl_score,ssl_issues,headers_score,headers_missing,cms_detected,cms_version,cms_outdated,dns_score,spf_present,dmarc_present,open_ports,https_redirect,mixed_content,top_issues,talking_points,scanned_at
example.com,67,D,hot,15,Certificate expires in 12 days,23,CSP;HSTS;X-Frame-Options,wordpress,6.4,true,10,true,false,,true,false,SSL expiring;Missing CSP;No DMARC,Your SSL cert expires soon;Missing security headers;No DMARC policy,2024-01-15T14:32:00Z
another-site.com,23,B,warm,0,,8,X-Frame-Options,squarespace,,false,10,true,false,,true,false,No DMARC;Missing X-Frame-Options,No DMARC policy detected,2024-01-15T14:32:05Z
```

---

## Error Handling

### Graceful Failures

Each scanner module should handle errors gracefully and return partial results:

```python
def check_ssl(domain: str) -> dict:
    try:
        # ... scanning logic ...
    except socket.timeout:
        return {
            "has_ssl": None,
            "error": "Connection timeout",
            "issues": ["Could not connect to verify SSL"],
            "severity": "unknown"
        }
    except ssl.SSLError as e:
        return {
            "has_ssl": False,
            "error": str(e),
            "issues": ["SSL connection failed - likely invalid certificate"],
            "severity": "high"
        }
    except Exception as e:
        return {
            "has_ssl": None,
            "error": f"Unexpected error: {e}",
            "issues": ["Could not complete SSL check"],
            "severity": "unknown"
        }
```

### Domain Validation

```python
import tldextract

def validate_domain(domain: str) -> str | None:
    """
    Validate and normalize domain.
    Returns normalized domain or None if invalid.
    """
    # Remove protocol if present
    domain = domain.replace("https://", "").replace("http://", "")
    domain = domain.split("/")[0]  # Remove path
    
    extracted = tldextract.extract(domain)
    if not extracted.domain or not extracted.suffix:
        return None
    
    return f"{extracted.domain}.{extracted.suffix}"
```

---

## Testing

Create a few test domains for development:

```python
# test_domains.csv
example.com
wordpress.org
badssl.com
httpbin.org
```

Run manual verification:
```bash
python main.py scan badssl.com  # Known SSL issues
python main.py scan wordpress.org  # Should detect WordPress
```

---

## Future Enhancements (Out of Scope for V1)

- Shodan API integration for deeper port/service analysis
- Screenshot capture of websites
- Technology stack detection (Wappalyzer API)
- WAF detection
- Subdomain enumeration
- Historical data tracking (score changes over time)
- Slack/webhook notifications for high-score leads
- Integration with Clay via HTTP API wrapper
- Web UI dashboard

---

## Legal & Ethical Notes

- This tool performs passive reconnaissance only
- Port scanning is minimal and uses standard timeouts
- Respect robots.txt where applicable
- Include identifying User-Agent
- Don't scan at aggressive rates
- Only scan domains you have legitimate business interest in
- This is not penetration testing — no exploitation attempts

---

## Quick Start for Claude Code

1. Create the project structure as outlined above
2. Implement each scanner module with the specified interfaces
3. Implement the scoring calculator
4. Implement output exporters
5. Wire everything together in main.py
6. Test with sample domains
7. Refine scoring weights based on results

Start with SSL and headers checkers — they're the simplest and most impactful. Add other modules incrementally.