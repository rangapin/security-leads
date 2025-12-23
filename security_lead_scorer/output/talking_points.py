"""Generate personalized outreach talking points based on scan findings."""


# Templates for different issues
TALKING_POINT_TEMPLATES = {
    # SSL issues
    "ssl_expired": "Your SSL certificate expired {days} days ago - visitors are seeing security warnings.",
    "ssl_expiring_critical": "Your SSL certificate expires in {days} days - worth renewing before it impacts SEO.",
    "ssl_expiring_soon": "Your SSL certificate expires in {days} days - a good time to plan renewal.",
    "ssl_no_ssl": "Your site doesn't have SSL - visitors see 'Not Secure' warnings and Google penalizes this.",
    "ssl_outdated_tls": "Your site uses outdated TLS {version} - modern browsers may block connections.",

    # Header issues
    "no_hsts": "Your site is missing HSTS headers - makes visitors vulnerable to downgrade attacks.",
    "no_csp": "No Content Security Policy detected - leaves your site exposed to XSS attacks.",
    "no_xframe": "Missing X-Frame-Options header - your site could be embedded in malicious frames.",

    # Redirect issues
    "no_https_redirect": "Your site doesn't redirect HTTP to HTTPS - Google penalizes this in rankings.",
    "mixed_content": "Your site loads insecure resources over HTTP - triggers browser warnings.",
    "redirect_302": "Using temporary (302) redirects instead of permanent (301) - hurts SEO.",

    # DNS issues
    "no_spf": "No SPF record found - anyone can spoof emails from your domain.",
    "no_dmarc": "No DMARC policy - you have no visibility into email spoofing attempts.",
    "weak_spf": "Your SPF record uses soft fail - provides limited protection against spoofing.",

    # CMS issues
    "cms_outdated": "Your {cms} installation (v{version}) is outdated - known vulnerabilities may exist.",
    "cms_severely_outdated": "Your {cms} is {versions} major versions behind - this is a significant security risk.",
    "wp_exposed_api": "Your WordPress REST API is publicly accessible - exposes site information.",

    # Port issues
    "exposed_database": "Port {port} ({service}) is publicly accessible - this is a critical security risk.",
    "exposed_ssh": "SSH (port 22) is exposed - ensure it's properly secured with key-based auth.",
    "exposed_rdp": "RDP (port 3389) is publicly accessible - a common target for ransomware attacks.",

    # Cookie issues
    "cookies_no_secure": "Some cookies are missing the Secure flag - could be intercepted over HTTP.",
    "cookies_no_httponly": "Some cookies are accessible to JavaScript - XSS attacks could steal them.",
}


def generate_talking_points(scan_result: dict) -> list[str]:
    """
    Generate 3-5 most compelling talking points for outreach.

    Args:
        scan_result: Complete scan result dict

    Returns:
        List of talking point strings, ordered by severity/impact
    """
    talking_points = []
    checks = scan_result.get("checks", {})

    # SSL talking points
    ssl = checks.get("ssl", {})
    if ssl:
        talking_points.extend(_get_ssl_talking_points(ssl))

    # Header talking points
    headers = checks.get("headers", {})
    if headers:
        talking_points.extend(_get_header_talking_points(headers))

    # Redirect talking points
    redirects = checks.get("redirects", {})
    if redirects:
        talking_points.extend(_get_redirect_talking_points(redirects))

    # DNS talking points
    dns = checks.get("dns", {})
    if dns:
        talking_points.extend(_get_dns_talking_points(dns))

    # CMS talking points
    cms = checks.get("cms", {})
    if cms:
        talking_points.extend(_get_cms_talking_points(cms))

    # Port talking points
    ports = checks.get("ports", {})
    if ports:
        talking_points.extend(_get_port_talking_points(ports))

    # Cookie talking points
    cookies = checks.get("cookies", {})
    if cookies:
        talking_points.extend(_get_cookie_talking_points(cookies))

    # Sort by priority and return top 5
    priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    sorted_points = sorted(talking_points, key=lambda x: priority_order.get(x[0], 4))

    return [point[1] for point in sorted_points[:5]]


def _get_ssl_talking_points(ssl: dict) -> list[tuple[str, str]]:
    """Generate SSL-related talking points."""
    points = []
    days = ssl.get("days_until_expiry")

    if not ssl.get("has_ssl"):
        points.append(("critical", TALKING_POINT_TEMPLATES["ssl_no_ssl"]))
    elif days is not None:
        if days < 0:
            points.append(("critical", TALKING_POINT_TEMPLATES["ssl_expired"].format(days=abs(days))))
        elif days < 7:
            points.append(("high", TALKING_POINT_TEMPLATES["ssl_expiring_critical"].format(days=days)))
        elif days < 30:
            points.append(("medium", TALKING_POINT_TEMPLATES["ssl_expiring_soon"].format(days=days)))

    tls_version = ssl.get("tls_version", "")
    if tls_version and tls_version in ("TLSv1", "TLSv1.0", "TLSv1.1"):
        points.append(("high", TALKING_POINT_TEMPLATES["ssl_outdated_tls"].format(version=tls_version)))

    return points


def _get_header_talking_points(headers: dict) -> list[tuple[str, str]]:
    """Generate header-related talking points."""
    points = []
    missing = headers.get("headers_missing", [])

    if "Strict-Transport-Security" in missing:
        points.append(("high", TALKING_POINT_TEMPLATES["no_hsts"]))
    if "Content-Security-Policy" in missing:
        points.append(("high", TALKING_POINT_TEMPLATES["no_csp"]))
    if "X-Frame-Options" in missing:
        points.append(("medium", TALKING_POINT_TEMPLATES["no_xframe"]))

    return points


def _get_redirect_talking_points(redirects: dict) -> list[tuple[str, str]]:
    """Generate redirect-related talking points."""
    points = []

    if not redirects.get("http_redirects_to_https"):
        points.append(("high", TALKING_POINT_TEMPLATES["no_https_redirect"]))

    mixed = redirects.get("mixed_content", {})
    if mixed.get("detected"):
        points.append(("medium", TALKING_POINT_TEMPLATES["mixed_content"]))

    if redirects.get("redirect_type") == 302:
        points.append(("low", TALKING_POINT_TEMPLATES["redirect_302"]))

    return points


def _get_dns_talking_points(dns: dict) -> list[tuple[str, str]]:
    """Generate DNS-related talking points."""
    points = []

    spf = dns.get("spf", {})
    if not spf.get("present"):
        points.append(("high", TALKING_POINT_TEMPLATES["no_spf"]))
    elif spf.get("policy_strength") == "weak":
        points.append(("medium", TALKING_POINT_TEMPLATES["weak_spf"]))

    dmarc = dns.get("dmarc", {})
    if not dmarc.get("present"):
        points.append(("high", TALKING_POINT_TEMPLATES["no_dmarc"]))

    return points


def _get_cms_talking_points(cms: dict) -> list[tuple[str, str]]:
    """Generate CMS-related talking points."""
    points = []
    cms_name = cms.get("cms_detected")

    if cms_name and cms.get("is_outdated"):
        version = cms.get("cms_version", "unknown")
        versions_behind = cms.get("versions_behind", 0)

        if versions_behind and versions_behind >= 2:
            points.append(("critical", TALKING_POINT_TEMPLATES["cms_severely_outdated"].format(
                cms=cms_name, versions=versions_behind
            )))
        else:
            points.append(("high", TALKING_POINT_TEMPLATES["cms_outdated"].format(
                cms=cms_name, version=version
            )))

    exposed = cms.get("exposed_files", [])
    if "wp-json API" in exposed:
        points.append(("medium", TALKING_POINT_TEMPLATES["wp_exposed_api"]))

    return points


def _get_port_talking_points(ports: dict) -> list[tuple[str, str]]:
    """Generate port-related talking points."""
    points = []
    open_ports = ports.get("open_ports", [])
    port_details = ports.get("port_details", {})

    # Database ports are critical
    db_ports = {3306: "MySQL", 5432: "PostgreSQL", 27017: "MongoDB", 6379: "Redis"}
    for port, service in db_ports.items():
        if port in open_ports:
            points.append(("critical", TALKING_POINT_TEMPLATES["exposed_database"].format(
                port=port, service=service
            )))

    if 22 in open_ports:
        points.append(("medium", TALKING_POINT_TEMPLATES["exposed_ssh"]))

    if 3389 in open_ports:
        points.append(("critical", TALKING_POINT_TEMPLATES["exposed_rdp"]))

    return points


def _get_cookie_talking_points(cookies: dict) -> list[tuple[str, str]]:
    """Generate cookie-related talking points."""
    points = []

    if cookies.get("cookies_without_secure", 0) > 0:
        points.append(("medium", TALKING_POINT_TEMPLATES["cookies_no_secure"]))

    if cookies.get("cookies_without_httponly", 0) > 0:
        points.append(("medium", TALKING_POINT_TEMPLATES["cookies_no_httponly"]))

    return points
