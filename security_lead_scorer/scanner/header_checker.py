"""HTTP security headers checker."""

import httpx

from ..config import SECURITY_HEADERS, HTTP_TIMEOUT, USER_AGENT


def check_headers(domain: str) -> dict:
    """
    Check for presence and configuration of security headers.

    Returns:
        dict with keys: headers_present, headers_missing, header_details,
        issues, severity, score
    """
    result = {
        "headers_present": [],
        "headers_missing": [],
        "header_details": {},
        "issues": [],
        "severity": "low",
        "score": 0,
    }

    try:
        url = f"https://{domain}"
        with httpx.Client(timeout=HTTP_TIMEOUT, follow_redirects=True) as client:
            response = client.get(url, headers={"User-Agent": USER_AGENT})

        response_headers = response.headers

        for header_name, config in SECURITY_HEADERS.items():
            header_value = response_headers.get(header_name)
            header_lower = header_name.lower()

            detail = {
                "present": header_value is not None,
                "value": header_value,
                "is_configured_properly": False,
                "issues": [],
            }

            if header_value:
                result["headers_present"].append(header_name)
                detail["is_configured_properly"] = True

                # Validate specific headers
                if header_name == "Strict-Transport-Security":
                    if "max-age=" in header_value:
                        try:
                            max_age = int(header_value.split("max-age=")[1].split(";")[0].strip())
                            if max_age < 31536000:  # Less than 1 year
                                detail["issues"].append(f"HSTS max-age too short: {max_age}s (should be >= 31536000)")
                                detail["is_configured_properly"] = False
                        except (ValueError, IndexError):
                            pass

                elif header_name == "X-Frame-Options":
                    value_upper = header_value.upper()
                    if value_upper not in ("DENY", "SAMEORIGIN"):
                        detail["issues"].append(f"X-Frame-Options should be DENY or SAMEORIGIN, got: {header_value}")
                        detail["is_configured_properly"] = False

                elif header_name == "X-Content-Type-Options":
                    if header_value.lower() != "nosniff":
                        detail["issues"].append(f"X-Content-Type-Options should be 'nosniff', got: {header_value}")
                        detail["is_configured_properly"] = False

            else:
                result["headers_missing"].append(header_name)
                result["score"] += config["points"]
                detail["issues"].append(f"Missing {header_name} header")

                if config["required"]:
                    result["issues"].append(f"Missing required header: {header_name}")

            result["header_details"][header_name] = detail

        # Determine severity based on missing headers
        missing_required = [h for h in result["headers_missing"] if SECURITY_HEADERS[h]["required"]]
        if len(missing_required) >= 3:
            result["severity"] = "high"
        elif len(missing_required) >= 1:
            result["severity"] = "medium"
        elif result["headers_missing"]:
            result["severity"] = "low"

    except httpx.TimeoutException:
        result["issues"].append("Request timeout - could not fetch headers")
        result["severity"] = "unknown"

    except httpx.ConnectError as e:
        result["issues"].append(f"Connection error: {e}")
        result["severity"] = "unknown"

    except httpx.HTTPStatusError as e:
        result["issues"].append(f"HTTP error: {e.response.status_code}")
        result["severity"] = "unknown"

    except Exception as e:
        result["issues"].append(f"Error checking headers: {e}")
        result["severity"] = "unknown"

    return result
