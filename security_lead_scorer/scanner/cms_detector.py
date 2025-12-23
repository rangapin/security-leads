"""CMS detection and version checking."""

import re

import httpx
from bs4 import BeautifulSoup

from ..config import CMS_SCORES, CMS_LATEST_VERSIONS, HTTP_TIMEOUT, USER_AGENT


def check_cms(domain: str) -> dict:
    """
    Detect CMS platform and version, flag if outdated.

    Returns:
        dict with keys: cms_detected, cms_version, latest_version, is_outdated,
        versions_behind, detection_method, issues, severity, score
    """
    result = {
        "cms_detected": None,
        "cms_version": None,
        "latest_version": None,
        "is_outdated": False,
        "versions_behind": None,
        "detection_method": None,
        "exposed_files": [],
        "issues": [],
        "severity": "low",
        "score": 0,
    }

    try:
        url = f"https://{domain}"
        with httpx.Client(timeout=HTTP_TIMEOUT, follow_redirects=True) as client:
            response = client.get(url, headers={"User-Agent": USER_AGENT})
            html = response.text

            # Try to detect CMS
            cms, method = _detect_cms(html, response.headers, domain, client)

            if cms:
                result["cms_detected"] = cms
                result["detection_method"] = method

                # Try to get version
                version = _detect_version(cms, html, domain, client)
                if version:
                    result["cms_version"] = version

                    # Check if outdated
                    latest = CMS_LATEST_VERSIONS.get(cms.lower())
                    if latest:
                        result["latest_version"] = latest
                        is_outdated, versions_behind = _compare_versions(version, latest)
                        result["is_outdated"] = is_outdated
                        result["versions_behind"] = versions_behind

                        if is_outdated:
                            if versions_behind and versions_behind >= 2:
                                result["issues"].append(f"{cms} is {versions_behind} major versions behind (v{version} vs v{latest})")
                                result["score"] += CMS_SCORES["two_major_behind"]
                                result["severity"] = "high"
                            elif versions_behind and versions_behind >= 1:
                                result["issues"].append(f"{cms} is 1 major version behind (v{version} vs v{latest})")
                                result["score"] += CMS_SCORES["one_major_behind"]
                                result["severity"] = "medium"
                else:
                    result["issues"].append(f"{cms} detected but version unknown")
                    result["score"] += CMS_SCORES["version_unknown"]

                # Check for exposed files (WordPress specific)
                if cms.lower() == "wordpress":
                    _check_wordpress_exposure(domain, client, result)

    except httpx.TimeoutException:
        result["issues"].append("Request timeout - could not detect CMS")
        result["severity"] = "unknown"
    except httpx.ConnectError as e:
        result["issues"].append(f"Connection error: {e}")
        result["severity"] = "unknown"
    except Exception as e:
        result["issues"].append(f"Error detecting CMS: {e}")
        result["severity"] = "unknown"

    return result


def _detect_cms(html: str, headers: dict, domain: str, client: httpx.Client) -> tuple[str | None, str | None]:
    """Detect CMS from HTML content and headers."""
    soup = BeautifulSoup(html, "html.parser")

    # Check meta generator tag
    generator = soup.find("meta", {"name": "generator"})
    if generator:
        content = generator.get("content", "").lower()
        if "wordpress" in content:
            return "WordPress", "meta_generator"
        elif "joomla" in content:
            return "Joomla", "meta_generator"
        elif "drupal" in content:
            return "Drupal", "meta_generator"
        elif "wix" in content:
            return "Wix", "meta_generator"
        elif "squarespace" in content:
            return "Squarespace", "meta_generator"
        elif "ghost" in content:
            return "Ghost", "meta_generator"
        elif "webflow" in content:
            return "Webflow", "meta_generator"
        elif "shopify" in content:
            return "Shopify", "meta_generator"

    # Check for WordPress indicators
    if "/wp-content/" in html or "/wp-includes/" in html:
        return "WordPress", "path_detection"

    # Check for Shopify
    if "cdn.shopify.com" in html:
        return "Shopify", "cdn_detection"

    # Check for Wix
    if "static.wixstatic.com" in html or "wix.com" in html:
        return "Wix", "cdn_detection"

    # Check for Squarespace
    if "squarespace.com" in html or "static1.squarespace.com" in html:
        return "Squarespace", "cdn_detection"

    # Check for Webflow
    if "assets.website-files.com" in html or "webflow" in html.lower():
        return "Webflow", "cdn_detection"

    # Check for Drupal
    if 'data-drupal' in html or '/sites/default/files/' in html:
        return "Drupal", "path_detection"

    # Check for Joomla
    if '/media/jui/' in html or '/components/com_' in html:
        return "Joomla", "path_detection"

    # Try WordPress REST API
    try:
        wp_response = client.get(f"https://{domain}/wp-json/", headers={"User-Agent": USER_AGENT})
        if wp_response.status_code == 200 and "wp" in wp_response.text.lower():
            return "WordPress", "api_detection"
    except Exception:
        pass

    return None, None


def _detect_version(cms: str, html: str, domain: str, client: httpx.Client) -> str | None:
    """Try to detect CMS version."""
    cms_lower = cms.lower()

    if cms_lower == "wordpress":
        # Try meta generator
        match = re.search(r'content="WordPress\s+([\d.]+)"', html, re.IGNORECASE)
        if match:
            return match.group(1)

        # Try wp-json
        try:
            response = client.get(f"https://{domain}/wp-json/", headers={"User-Agent": USER_AGENT})
            if response.status_code == 200:
                data = response.json()
                if "version" in data.get("generator", ""):
                    match = re.search(r'WordPress\s+([\d.]+)', data.get("generator", ""))
                    if match:
                        return match.group(1)
        except Exception:
            pass

        # Try readme.html
        try:
            response = client.get(f"https://{domain}/readme.html", headers={"User-Agent": USER_AGENT})
            if response.status_code == 200:
                match = re.search(r'Version\s+([\d.]+)', response.text)
                if match:
                    return match.group(1)
        except Exception:
            pass

    elif cms_lower == "joomla":
        match = re.search(r'content="Joomla!\s*-?\s*([\d.]+)"', html, re.IGNORECASE)
        if match:
            return match.group(1)

    elif cms_lower == "drupal":
        match = re.search(r'content="Drupal\s+([\d.]+)"', html, re.IGNORECASE)
        if match:
            return match.group(1)

    elif cms_lower == "ghost":
        match = re.search(r'content="Ghost\s+([\d.]+)"', html, re.IGNORECASE)
        if match:
            return match.group(1)

    return None


def _compare_versions(current: str, latest: str) -> tuple[bool, int | None]:
    """Compare version strings, return (is_outdated, major_versions_behind)."""
    try:
        current_parts = [int(x) for x in current.split(".")[:2]]
        latest_parts = [int(x) for x in latest.split(".")[:2]]

        current_major = current_parts[0] if current_parts else 0
        latest_major = latest_parts[0] if latest_parts else 0

        current_minor = current_parts[1] if len(current_parts) > 1 else 0
        latest_minor = latest_parts[1] if len(latest_parts) > 1 else 0

        if current_major < latest_major:
            return True, latest_major - current_major
        elif current_major == latest_major and current_minor < latest_minor:
            return True, 0  # Same major, but minor version behind
        return False, 0
    except Exception:
        return False, None


def _check_wordpress_exposure(domain: str, client: httpx.Client, result: dict) -> None:
    """Check for exposed WordPress files."""
    exposed_paths = [
        ("/wp-json/", "wp-json API"),
        ("/readme.html", "readme.html"),
        ("/license.txt", "license.txt"),
        ("/wp-config.php.bak", "wp-config backup"),
        ("/debug.log", "debug.log"),
    ]

    for path, name in exposed_paths:
        try:
            response = client.head(f"https://{domain}{path}", headers={"User-Agent": USER_AGENT})
            if response.status_code == 200:
                result["exposed_files"].append(name)
        except Exception:
            continue

    if "wp-json API" in result["exposed_files"]:
        result["issues"].append("WordPress REST API is publicly accessible")
        result["score"] += CMS_SCORES["exposed_wpjson"]

    if "readme.html" in result["exposed_files"]:
        result["issues"].append("WordPress readme.html is exposed (reveals version)")
        result["score"] += CMS_SCORES["exposed_readme"]

    if "debug.log" in result["exposed_files"]:
        result["issues"].append("WordPress debug.log is exposed (may contain sensitive info)")
        result["score"] += 15  # Critical exposure
        result["severity"] = "critical"
