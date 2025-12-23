"""Cookie security checker."""

import httpx

from ..config import COOKIE_SCORES, HTTP_TIMEOUT, USER_AGENT


def check_cookies(domain: str) -> dict:
    """
    Analyze cookie security flags.

    Returns:
        dict with keys: cookies_found, cookie_details, cookies_without_secure,
        cookies_without_httponly, cookies_without_samesite, issues, severity, score
    """
    result = {
        "cookies_found": 0,
        "cookie_details": [],
        "cookies_without_secure": 0,
        "cookies_without_httponly": 0,
        "cookies_without_samesite": 0,
        "issues": [],
        "severity": "low",
        "score": 0,
    }

    try:
        url = f"https://{domain}"
        with httpx.Client(timeout=HTTP_TIMEOUT, follow_redirects=True) as client:
            response = client.get(url, headers={"User-Agent": USER_AGENT})

            # Get Set-Cookie headers
            set_cookie_headers = response.headers.get_list("set-cookie")

            if not set_cookie_headers:
                return result

            result["cookies_found"] = len(set_cookie_headers)

            for cookie_header in set_cookie_headers:
                cookie_info = _parse_cookie(cookie_header)
                result["cookie_details"].append(cookie_info)

                if not cookie_info["secure"]:
                    result["cookies_without_secure"] += 1
                if not cookie_info["httponly"]:
                    result["cookies_without_httponly"] += 1
                if not cookie_info["samesite"]:
                    result["cookies_without_samesite"] += 1

            # Calculate score and issues
            if result["cookies_without_secure"] > 0:
                result["score"] += COOKIE_SCORES["no_secure"]
                result["issues"].append(
                    f"{result['cookies_without_secure']} cookie(s) missing Secure flag"
                )

            if result["cookies_without_httponly"] > 0:
                result["score"] += COOKIE_SCORES["no_httponly"]
                result["issues"].append(
                    f"{result['cookies_without_httponly']} cookie(s) missing HttpOnly flag"
                )

            if result["cookies_without_samesite"] > 0:
                result["score"] += COOKIE_SCORES["no_samesite"]
                result["issues"].append(
                    f"{result['cookies_without_samesite']} cookie(s) missing SameSite attribute"
                )

            # Determine severity
            if result["cookies_without_secure"] > 0 or result["cookies_without_httponly"] > 0:
                result["severity"] = "medium"
            elif result["cookies_without_samesite"] > 0:
                result["severity"] = "low"

    except httpx.TimeoutException:
        result["issues"].append("Request timeout - could not check cookies")
        result["severity"] = "unknown"
    except httpx.ConnectError as e:
        result["issues"].append(f"Connection error: {e}")
        result["severity"] = "unknown"
    except Exception as e:
        result["issues"].append(f"Error checking cookies: {e}")
        result["severity"] = "unknown"

    return result


def _parse_cookie(cookie_header: str) -> dict:
    """Parse a Set-Cookie header and extract security attributes."""
    cookie_info = {
        "name": None,
        "secure": False,
        "httponly": False,
        "samesite": None,
        "issues": [],
    }

    parts = cookie_header.split(";")

    # First part is name=value
    if parts:
        name_value = parts[0].strip()
        if "=" in name_value:
            cookie_info["name"] = name_value.split("=")[0].strip()

    # Check attributes
    header_lower = cookie_header.lower()

    if "secure" in header_lower:
        cookie_info["secure"] = True
    else:
        cookie_info["issues"].append("Missing Secure flag")

    if "httponly" in header_lower:
        cookie_info["httponly"] = True
    else:
        cookie_info["issues"].append("Missing HttpOnly flag")

    if "samesite=strict" in header_lower:
        cookie_info["samesite"] = "Strict"
    elif "samesite=lax" in header_lower:
        cookie_info["samesite"] = "Lax"
    elif "samesite=none" in header_lower:
        cookie_info["samesite"] = "None"
    else:
        cookie_info["issues"].append("Missing SameSite attribute")

    return cookie_info
