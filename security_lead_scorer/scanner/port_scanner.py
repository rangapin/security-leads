"""Basic port scanner for risky open ports."""

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..config import PORT_SCORES, PORT_SCAN_TIMEOUT


def check_ports(domain: str) -> dict:
    """
    Scan for potentially dangerous open ports.

    Returns:
        dict with keys: open_ports, port_details, issues, severity, score
    """
    result = {
        "open_ports": [],
        "port_details": {},
        "issues": [],
        "severity": "low",
        "score": 0,
    }

    # Resolve domain to IP
    try:
        ip = socket.gethostbyname(domain)
    except socket.gaierror:
        result["issues"].append("Could not resolve domain to IP")
        result["severity"] = "unknown"
        return result

    # Scan risky ports concurrently
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {
            executor.submit(_check_port, ip, port): port
            for port in PORT_SCORES.keys()
        }

        for future in as_completed(futures):
            port = futures[future]
            try:
                is_open = future.result()
                port_info = PORT_SCORES[port]

                result["port_details"][port] = {
                    "service": port_info["service"],
                    "is_open": is_open,
                    "severity": port_info["severity"] if is_open else "low",
                }

                if is_open:
                    result["open_ports"].append(port)
                    result["score"] += port_info["points"]
                    result["issues"].append(
                        f"Port {port} ({port_info['service']}) is open - {port_info['severity']} risk"
                    )

            except Exception:
                result["port_details"][port] = {
                    "service": PORT_SCORES[port]["service"],
                    "is_open": None,
                    "severity": "unknown",
                }

    # Determine overall severity
    if result["open_ports"]:
        severities = [PORT_SCORES[p]["severity"] for p in result["open_ports"]]
        if "critical" in severities:
            result["severity"] = "critical"
        elif "high" in severities:
            result["severity"] = "high"
        elif "medium" in severities:
            result["severity"] = "medium"

    return result


def _check_port(ip: str, port: int) -> bool:
    """Check if a single port is open."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(PORT_SCAN_TIMEOUT)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except Exception:
        return False
