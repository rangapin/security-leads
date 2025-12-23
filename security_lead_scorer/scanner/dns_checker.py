"""DNS security checker for SPF, DKIM, and DMARC records."""

import dns.resolver
import dns.exception

from ..config import DNS_SCORES, DNS_TIMEOUT

# Common DKIM selectors to check
COMMON_DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "mail", "email", "dkim", "k1"]


def check_dns(domain: str) -> dict:
    """
    Check DNS security records (SPF, DKIM, DMARC).

    Returns:
        dict with keys: spf, dmarc, dkim_selectors_found, overall_email_security,
        issues, severity, score
    """
    result = {
        "spf": {
            "present": False,
            "record": None,
            "is_valid": False,
            "policy_strength": None,
            "issues": [],
        },
        "dmarc": {
            "present": False,
            "record": None,
            "policy": None,
            "issues": [],
        },
        "dkim_selectors_found": [],
        "overall_email_security": "poor",
        "issues": [],
        "severity": "low",
        "score": 0,
    }

    # Configure resolver with timeout
    resolver = dns.resolver.Resolver()
    resolver.timeout = DNS_TIMEOUT
    resolver.lifetime = DNS_TIMEOUT

    # Check SPF
    _check_spf(domain, resolver, result)

    # Check DMARC
    _check_dmarc(domain, resolver, result)

    # Check DKIM (try common selectors)
    _check_dkim(domain, resolver, result)

    # Calculate overall email security rating
    _calculate_overall_security(result)

    return result


def _check_spf(domain: str, resolver: dns.resolver.Resolver, result: dict) -> None:
    """Check for SPF record."""
    try:
        answers = resolver.resolve(domain, "TXT")
        for rdata in answers:
            txt_record = str(rdata).strip('"')
            if txt_record.startswith("v=spf1"):
                result["spf"]["present"] = True
                result["spf"]["record"] = txt_record
                result["spf"]["is_valid"] = True

                # Check policy strength
                if txt_record.endswith("-all"):
                    result["spf"]["policy_strength"] = "strict"
                elif txt_record.endswith("~all"):
                    result["spf"]["policy_strength"] = "weak"
                    result["spf"]["issues"].append("SPF uses soft fail (~all), consider using hard fail (-all)")
                    result["score"] += DNS_SCORES["weak_spf"]
                elif txt_record.endswith("?all"):
                    result["spf"]["policy_strength"] = "weak"
                    result["spf"]["issues"].append("SPF uses neutral (?all), provides no protection")
                    result["score"] += DNS_SCORES["weak_spf"]
                elif "+all" in txt_record:
                    result["spf"]["policy_strength"] = "weak"
                    result["spf"]["issues"].append("SPF uses pass-all (+all), effectively disables SPF")
                    result["score"] += DNS_SCORES["weak_spf"]
                else:
                    result["spf"]["policy_strength"] = "moderate"
                break

        if not result["spf"]["present"]:
            result["spf"]["issues"].append("No SPF record found")
            result["issues"].append("No SPF record - email spoofing possible")
            result["score"] += DNS_SCORES["no_spf"]

    except dns.resolver.NXDOMAIN:
        result["spf"]["issues"].append("Domain does not exist")
        result["issues"].append("Domain does not exist in DNS")
    except dns.resolver.NoAnswer:
        result["spf"]["issues"].append("No TXT records found")
        result["issues"].append("No SPF record - email spoofing possible")
        result["score"] += DNS_SCORES["no_spf"]
    except dns.exception.Timeout:
        result["spf"]["issues"].append("DNS query timeout")
    except Exception as e:
        result["spf"]["issues"].append(f"Error checking SPF: {e}")


def _check_dmarc(domain: str, resolver: dns.resolver.Resolver, result: dict) -> None:
    """Check for DMARC record."""
    dmarc_domain = f"_dmarc.{domain}"
    try:
        answers = resolver.resolve(dmarc_domain, "TXT")
        for rdata in answers:
            txt_record = str(rdata).strip('"')
            if txt_record.startswith("v=DMARC1"):
                result["dmarc"]["present"] = True
                result["dmarc"]["record"] = txt_record

                # Extract policy
                if "p=reject" in txt_record:
                    result["dmarc"]["policy"] = "reject"
                elif "p=quarantine" in txt_record:
                    result["dmarc"]["policy"] = "quarantine"
                elif "p=none" in txt_record:
                    result["dmarc"]["policy"] = "none"
                    result["dmarc"]["issues"].append("DMARC policy is 'none' - only monitoring, no enforcement")
                    result["issues"].append("DMARC policy is 'none' - no protection against spoofing")
                    result["score"] += DNS_SCORES["dmarc_none"]
                break

        if not result["dmarc"]["present"]:
            result["dmarc"]["issues"].append("No DMARC record found")
            result["issues"].append("No DMARC record - no visibility into email spoofing")
            result["score"] += DNS_SCORES["no_dmarc"]

    except dns.resolver.NXDOMAIN:
        result["dmarc"]["issues"].append("DMARC record not found")
        result["issues"].append("No DMARC record - no visibility into email spoofing")
        result["score"] += DNS_SCORES["no_dmarc"]
    except dns.resolver.NoAnswer:
        result["dmarc"]["issues"].append("No DMARC record found")
        result["issues"].append("No DMARC record - no visibility into email spoofing")
        result["score"] += DNS_SCORES["no_dmarc"]
    except dns.exception.Timeout:
        result["dmarc"]["issues"].append("DNS query timeout")
    except Exception as e:
        result["dmarc"]["issues"].append(f"Error checking DMARC: {e}")


def _check_dkim(domain: str, resolver: dns.resolver.Resolver, result: dict) -> None:
    """Check for DKIM records using common selectors."""
    for selector in COMMON_DKIM_SELECTORS:
        dkim_domain = f"{selector}._domainkey.{domain}"
        try:
            answers = resolver.resolve(dkim_domain, "TXT")
            for rdata in answers:
                txt_record = str(rdata).strip('"')
                if "v=DKIM1" in txt_record or "p=" in txt_record:
                    result["dkim_selectors_found"].append(selector)
                    break
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
            continue
        except Exception:
            continue

    if not result["dkim_selectors_found"]:
        result["issues"].append("No DKIM records found (checked common selectors)")
        result["score"] += DNS_SCORES["no_dkim"]


def _calculate_overall_security(result: dict) -> None:
    """Calculate overall email security rating."""
    has_spf = result["spf"]["present"] and result["spf"]["policy_strength"] in ("strict", "moderate")
    has_dmarc = result["dmarc"]["present"] and result["dmarc"]["policy"] in ("reject", "quarantine")
    has_dkim = len(result["dkim_selectors_found"]) > 0

    if has_spf and has_dmarc and has_dkim:
        result["overall_email_security"] = "excellent"
        result["severity"] = "low"
    elif has_spf and has_dmarc:
        result["overall_email_security"] = "good"
        result["severity"] = "low"
    elif has_spf or has_dmarc:
        result["overall_email_security"] = "basic"
        result["severity"] = "medium"
    else:
        result["overall_email_security"] = "poor"
        result["severity"] = "high"
