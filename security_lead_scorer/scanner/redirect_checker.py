"""HTTPS redirect and mixed content checker."""

import re
from urllib.parse import urlparse

import httpx
from bs4 import BeautifulSoup

from ..config import REDIRECT_SCORES, HTTP_TIMEOUT, USER_AGENT


def check_redirects(domain: str) -> dict:
    """
    Check for proper HTTPS enforcement and mixed content issues.

    Returns:
        dict with keys: http_redirects_to_https, redirect_type, redirect_chain,
        final_url, final_is_https, has_redirect_loop, mixed_content, issues,
        severity, score
    """
    result = {
        "http_redirects_to_https": False,
        "redirect_type": None,
        "redirect_chain": [],
        "final_url": None,
        "final_is_https": False,
        "has_redirect_loop": False,
        "mixed_content": {
            "detected": False,
            "insecure_resources": [],
        },
        "issues": [],
        "severity": "low",
        "score": 0,
    }

    try:
        # Check HTTP to HTTPS redirect
        http_url = f"http://{domain}"
        result["redirect_chain"].append(http_url)

        with httpx.Client(timeout=HTTP_TIMEOUT, follow_redirects=False) as client:
            # First request - don't follow redirects
            response = client.get(http_url, headers={"User-Agent": USER_AGENT})

            if response.status_code in (301, 302, 303, 307, 308):
                result["redirect_type"] = response.status_code
                location = response.headers.get("location", "")

                if location:
                    result["redirect_chain"].append(location)

                    # Check if redirects to HTTPS
                    if location.startswith("https://"):
                        result["http_redirects_to_https"] = True
                    elif location.startswith("/"):
                        # Relative redirect - check if the server uses HTTPS
                        result["http_redirects_to_https"] = False
                        result["issues"].append("HTTP redirects to relative path, not HTTPS")
                        result["score"] += REDIRECT_SCORES["no_https_redirect"]
                    else:
                        result["issues"].append("HTTP does not redirect to HTTPS")
                        result["score"] += REDIRECT_SCORES["no_https_redirect"]

                    # Check if 302 instead of 301
                    if result["http_redirects_to_https"] and response.status_code == 302:
                        result["issues"].append("Using 302 (temporary) redirect instead of 301 (permanent)")
                        result["score"] += REDIRECT_SCORES["redirect_302"]
            else:
                result["issues"].append("No HTTP to HTTPS redirect")
                result["score"] += REDIRECT_SCORES["no_https_redirect"]

        # Now follow all redirects to get final URL and check for mixed content
        with httpx.Client(timeout=HTTP_TIMEOUT, follow_redirects=True, max_redirects=10) as client:
            try:
                response = client.get(f"https://{domain}", headers={"User-Agent": USER_AGENT})
                result["final_url"] = str(response.url)
                result["final_is_https"] = response.url.scheme == "https"

                # Track redirect chain
                for hist in response.history:
                    if str(hist.url) not in result["redirect_chain"]:
                        result["redirect_chain"].append(str(hist.url))
                if str(response.url) not in result["redirect_chain"]:
                    result["redirect_chain"].append(str(response.url))

                # Check for mixed content
                if response.status_code == 200:
                    mixed_content = _check_mixed_content(response.text, str(response.url))
                    result["mixed_content"] = mixed_content

                    if mixed_content["detected"]:
                        result["issues"].append(
                            f"Mixed content detected: {len(mixed_content['insecure_resources'])} insecure resources"
                        )
                        result["score"] += REDIRECT_SCORES["mixed_content"]

            except httpx.TooManyRedirects:
                result["has_redirect_loop"] = True
                result["issues"].append("Redirect loop detected")
                result["score"] += REDIRECT_SCORES["redirect_loop"]

        # Determine severity
        if result["has_redirect_loop"] or not result["http_redirects_to_https"]:
            result["severity"] = "high"
        elif result["mixed_content"]["detected"] or result["redirect_type"] == 302:
            result["severity"] = "medium"

    except httpx.TimeoutException:
        result["issues"].append("Request timeout")
        result["severity"] = "unknown"

    except httpx.ConnectError as e:
        result["issues"].append(f"Connection error: {e}")
        result["severity"] = "unknown"

    except Exception as e:
        result["issues"].append(f"Error checking redirects: {e}")
        result["severity"] = "unknown"

    return result


def _check_mixed_content(html: str, base_url: str) -> dict:
    """Check HTML for mixed content (HTTP resources on HTTPS page)."""
    mixed = {
        "detected": False,
        "insecure_resources": [],
    }

    parsed_base = urlparse(base_url)
    if parsed_base.scheme != "https":
        return mixed

    try:
        soup = BeautifulSoup(html, "html.parser")

        # Check common resource attributes
        resource_attrs = [
            ("script", "src"),
            ("link", "href"),
            ("img", "src"),
            ("iframe", "src"),
            ("video", "src"),
            ("audio", "src"),
            ("source", "src"),
            ("object", "data"),
            ("embed", "src"),
        ]

        for tag_name, attr in resource_attrs:
            for tag in soup.find_all(tag_name):
                url = tag.get(attr, "")
                if url and url.startswith("http://"):
                    mixed["insecure_resources"].append(url)

        # Check inline styles for http:// URLs
        style_pattern = re.compile(r'url\(["\']?(http://[^"\')\s]+)["\']?\)', re.IGNORECASE)
        for tag in soup.find_all(style=True):
            matches = style_pattern.findall(tag.get("style", ""))
            mixed["insecure_resources"].extend(matches)

        # Check style tags
        for style_tag in soup.find_all("style"):
            if style_tag.string:
                matches = style_pattern.findall(style_tag.string)
                mixed["insecure_resources"].extend(matches)

        if mixed["insecure_resources"]:
            mixed["detected"] = True
            # Limit to first 10 for brevity
            mixed["insecure_resources"] = mixed["insecure_resources"][:10]

    except Exception:
        pass

    return mixed
