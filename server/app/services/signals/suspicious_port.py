"""Detect non-standard ports which can indicate phishing or malicious intent."""


# Standard web ports
_STANDARD_PORTS = frozenset({80, 443, None})


def suspicious_port_signal(port: int | None) -> dict:
    """Check if URL uses a non-standard port."""
    if port in _STANDARD_PORTS:
        return {
            "id": "suspicious_port",
            "status": "ok",
            "concern": False,
            "port": port,
            "summary": "URL uses a standard web port." if port else "URL uses default port.",
        }

    return {
        "id": "suspicious_port",
        "status": "ok",
        "concern": True,
        "port": port,
        "summary": f"URL uses non-standard port {port} — uncommon for legitimate websites.",
    }
