def domain_age_signal() -> dict:
    """RDAP/WHOIS not wired in MVP — explicit unknown."""
    return {
        "id": "domain_age",
        "status": "unknown",
        "concern": False,
        "summary": "Domain registration age was not checked in this build (RDAP/WHOIS pending).",
    }
