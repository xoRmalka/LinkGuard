"""Detect suspicious subdomain patterns used in phishing."""

import re

# Keywords commonly used in phishing subdomains
_SUSPICIOUS_KEYWORDS = frozenset({
    "login", "signin", "sign-in", "signon", "sign-on",
    "secure", "security", "account", "accounts",
    "verify", "verification", "confirm", "confirmation",
    "update", "authenticate", "auth", "password",
    "banking", "wallet", "payment", "pay",
    "support", "help", "service", "customer",
})


def suspicious_subdomain_signal(host: str) -> dict:
    """Check for suspicious subdomain patterns."""
    if not host:
        return {
            "id": "suspicious_subdomain",
            "status": "error",
            "concern": False,
            "summary": "No hostname provided.",
        }

    # Remove port and lowercase
    host_clean = host.lower().split(":")[0]
    parts = host_clean.split(".")

    if len(parts) < 2:
        return {
            "id": "suspicious_subdomain",
            "status": "ok",
            "concern": False,
            "summary": "No subdomains to analyze.",
        }

    # Subdomains are everything except the last two parts (domain.tld)
    # For co.uk style TLDs this isn't perfect, but good enough for this use case
    subdomains = parts[:-2] if len(parts) > 2 else []

    concerns = []

    # Check 1: Excessive subdomain depth (>3 levels is suspicious)
    if len(subdomains) > 3:
        concerns.append(f"Unusually deep subdomain structure ({len(subdomains)} levels)")

    # Check 2: Suspicious keywords in subdomains
    subdomain_text = ".".join(subdomains)
    found_keywords = []
    for keyword in _SUSPICIOUS_KEYWORDS:
        if keyword in subdomain_text:
            found_keywords.append(keyword)

    if found_keywords:
        concerns.append(f"Contains security-sensitive keywords: {', '.join(found_keywords[:3])}")

    # Check 3: Multiple hyphens (e.g., "secure-login-verify")
    hyphen_count = subdomain_text.count("-")
    if hyphen_count >= 3:
        concerns.append("Multiple hyphens in subdomain (common phishing pattern)")

    if concerns:
        return {
            "id": "suspicious_subdomain",
            "status": "ok",
            "concern": True,
            "subdomain_depth": len(subdomains),
            "found_keywords": found_keywords[:5],
            "summary": "; ".join(concerns) + ".",
        }

    return {
        "id": "suspicious_subdomain",
        "status": "ok",
        "concern": False,
        "subdomain_depth": len(subdomains),
        "summary": "Subdomain structure looks normal.",
    }
