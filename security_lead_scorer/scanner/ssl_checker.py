"""SSL/TLS certificate analysis."""

import socket
import ssl
from datetime import datetime, timezone

from ..config import SSL_SCORES, SSL_TIMEOUT


def check_ssl(domain: str, port: int = 443) -> dict:
    """
    Analyze SSL/TLS certificate for a domain.

    Returns:
        dict with keys: has_ssl, is_valid, issuer, expires, days_until_expiry,
        expiry_status, tls_version, issues, severity, score
    """
    result = {
        "has_ssl": False,
        "is_valid": False,
        "issuer": None,
        "expires": None,
        "days_until_expiry": None,
        "expiry_status": None,
        "tls_version": None,
        "chain_complete": None,
        "issues": [],
        "severity": "low",
        "score": 0,
    }

    try:
        # Create SSL context
        context = ssl.create_default_context()

        # Connect to the server
        with socket.create_connection((domain, port), timeout=SSL_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                result["has_ssl"] = True
                result["tls_version"] = ssock.version()

                # Get certificate
                cert = ssock.getpeercert()

                if cert:
                    result["is_valid"] = True

                    # Parse issuer
                    issuer_dict = dict(x[0] for x in cert.get("issuer", []))
                    result["issuer"] = issuer_dict.get("organizationName", "Unknown")

                    # Parse expiration
                    not_after = cert.get("notAfter")
                    if not_after:
                        # Parse SSL date format: 'Mon DD HH:MM:SS YYYY GMT'
                        expires = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                        expires = expires.replace(tzinfo=timezone.utc)
                        result["expires"] = expires.isoformat()

                        now = datetime.now(timezone.utc)
                        days_left = (expires - now).days
                        result["days_until_expiry"] = days_left

                        if days_left < 0:
                            result["expiry_status"] = "expired"
                            result["issues"].append(f"Certificate expired {abs(days_left)} days ago")
                            result["score"] += SSL_SCORES["expired"]
                            result["severity"] = "critical"
                        elif days_left < 7:
                            result["expiry_status"] = "critical"
                            result["issues"].append(f"Certificate expires in {days_left} days (critical)")
                            result["score"] += SSL_SCORES["expiring_critical"]
                            result["severity"] = "high"
                        elif days_left < 30:
                            result["expiry_status"] = "expiring_soon"
                            result["issues"].append(f"Certificate expires in {days_left} days")
                            result["score"] += SSL_SCORES["expiring_soon"]
                            result["severity"] = "medium"
                        else:
                            result["expiry_status"] = "valid"

                    # Check TLS version
                    tls_version = result["tls_version"]
                    if tls_version in ("TLSv1", "TLSv1.0", "TLSv1.1"):
                        result["issues"].append(f"Outdated TLS version: {tls_version}")
                        result["score"] += SSL_SCORES["tls_outdated"]
                        if result["severity"] == "low":
                            result["severity"] = "medium"

    except ssl.SSLCertVerificationError as e:
        result["has_ssl"] = True
        result["is_valid"] = False
        error_msg = str(e)

        if "self-signed" in error_msg.lower() or "self signed" in error_msg.lower():
            result["issues"].append("Self-signed certificate")
            result["score"] += SSL_SCORES["self_signed"]
        elif "certificate verify failed" in error_msg.lower():
            result["issues"].append("Certificate verification failed")
            result["score"] += SSL_SCORES["incomplete_chain"]
        else:
            result["issues"].append(f"SSL error: {error_msg}")
            result["score"] += SSL_SCORES["self_signed"]

        result["severity"] = "high"

    except ssl.SSLError as e:
        result["has_ssl"] = True
        result["is_valid"] = False
        result["issues"].append(f"SSL connection error: {e}")
        result["score"] += SSL_SCORES["incomplete_chain"]
        result["severity"] = "high"

    except socket.timeout:
        result["issues"].append("Connection timeout - could not verify SSL")
        result["severity"] = "unknown"

    except socket.gaierror:
        result["issues"].append("Could not resolve domain")
        result["severity"] = "unknown"

    except ConnectionRefusedError:
        result["issues"].append("Connection refused on port 443")
        result["score"] += SSL_SCORES["no_ssl"]
        result["severity"] = "high"

    except OSError as e:
        if "No route to host" in str(e):
            result["issues"].append("No route to host")
        else:
            result["issues"].append(f"Connection error: {e}")
        result["severity"] = "unknown"

    # If we couldn't connect at all, assume no SSL
    if not result["has_ssl"] and result["score"] == 0 and not result["issues"]:
        result["issues"].append("No SSL/TLS certificate found")
        result["score"] = SSL_SCORES["no_ssl"]
        result["severity"] = "critical"

    return result
