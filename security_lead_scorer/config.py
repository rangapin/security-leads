"""Configuration constants for Security Lead Scorer."""

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

# SSL Scoring
SSL_SCORES = {
    "no_ssl": 30,
    "expired": 25,
    "expiring_critical": 20,  # < 7 days
    "expiring_soon": 10,      # < 30 days
    "tls_outdated": 15,       # TLS 1.0/1.1
    "self_signed": 20,
    "incomplete_chain": 10,
}

# Security Headers Scoring
SECURITY_HEADERS = {
    "Strict-Transport-Security": {"required": True, "points": 10},
    "Content-Security-Policy": {"required": True, "points": 10},
    "X-Frame-Options": {"required": True, "points": 8},
    "X-Content-Type-Options": {"required": True, "points": 5},
    "X-XSS-Protection": {"required": False, "points": 3},
    "Referrer-Policy": {"required": False, "points": 5},
    "Permissions-Policy": {"required": False, "points": 5},
}

# Redirect Scoring
REDIRECT_SCORES = {
    "no_https_redirect": 15,
    "redirect_302": 5,  # Should be 301
    "mixed_content": 10,
    "redirect_loop": 10,
}

# DNS Scoring
DNS_SCORES = {
    "no_spf": 10,
    "weak_spf": 5,
    "no_dmarc": 10,
    "dmarc_none": 5,
    "no_dkim": 5,
}

# Port Scoring
PORT_SCORES = {
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

# CMS Scoring
CMS_SCORES = {
    "version_unknown": 5,
    "one_major_behind": 10,
    "two_major_behind": 20,
    "severely_outdated": 25,
    "exposed_wpjson": 5,
    "exposed_readme": 5,
}

# Cookie Scoring
COOKIE_SCORES = {
    "no_secure": 5,
    "no_httponly": 5,
    "no_samesite": 3,
}

# Grade thresholds
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
