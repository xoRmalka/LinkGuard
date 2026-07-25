"""Detect suspicious subdomain patterns used in phishing."""

import re

from app.services.signals.domain_utils import BRANDS, parse_domain

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

    parts = parse_domain(host)
    if parts.is_ip or not parts.subdomains:
        return {
            "id": "suspicious_subdomain",
            "status": "ok",
            "concern": False,
            "subdomain_depth": 0,
            "summary": "No subdomains to analyze.",
        }

    subdomains = parts.subdomains
    concerns = []

    # Check 1: Excessive subdomain depth (>3 levels is suspicious)
    if len(subdomains) > 3:
        concerns.append(f"Unusually deep subdomain structure ({len(subdomains)} levels)")

    # Check: a known brand name appears as a subdomain label of a domain
    # that isn't actually owned by that brand, e.g. paypal.com.evil.xyz or
    # login.google.com.evil.com. This is a highly realistic impersonation
    # vector regardless of TLD, since the registrable domain is foreign.
    brand_matches = sorted(brand for brand in BRANDS if brand in subdomains)
    if brand_matches:
        concerns.append(
            f"Impersonates known brand(s) in subdomain of a foreign domain: {', '.join(brand_matches)}"
        )

    # Check 2: clustered security-sensitive keywords in subdomains. A single
    # ordinary label such as login.microsoft.com is common and should not be
    # enough on its own to mark a legitimate domain as suspicious.
    subdomain_text = ".".join(subdomains)
    tokens = {token for token in re.split(r"[^a-z0-9]+", subdomain_text) if token}
    found_keywords = sorted(keyword for keyword in _SUSPICIOUS_KEYWORDS if keyword in tokens)

    hyphen_count = subdomain_text.count("-")
    keyword_cluster = len(found_keywords) >= 2
    keyword_with_obfuscation = bool(found_keywords) and (len(subdomains) >= 2 or hyphen_count >= 2)
    if keyword_cluster or keyword_with_obfuscation:
        concerns.append(f"Contains clustered security-sensitive keywords: {', '.join(found_keywords[:3])}")

    # Check 3: Multiple hyphens (e.g., "secure-login-verify")
    if hyphen_count >= 3:
        concerns.append("Multiple hyphens in subdomain (common phishing pattern)")

    if concerns:
        return {
            "id": "suspicious_subdomain",
            "status": "ok",
            "concern": True,
            "subdomain_depth": len(subdomains),
            "found_keywords": found_keywords[:5],
            "brand_impersonation": brand_matches or None,
            "summary": "; ".join(concerns) + ".",
        }

    return {
        "id": "suspicious_subdomain",
        "status": "ok",
        "concern": False,
        "subdomain_depth": len(subdomains),
        "summary": "Subdomain structure looks normal.",
    }
