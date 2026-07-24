"""Detect high-abuse TLDs commonly used in phishing."""

# TLDs with high abuse rates for phishing/malware
_SUSPICIOUS_TLDS = frozenset({
    # Free TLDs heavily abused
    "tk", "ml", "ga", "cf", "gq",
    # Cheap TLDs with high abuse
    "top", "xyz", "buzz", "club", "work",
    "icu", "cam", "monster", "rest", "bar",
    # Additional high-risk TLDs
    "pw", "cc", "ws", "su",  # Known for abuse
    "link", "click", "download",  # Action-oriented, often phishing
    "zip", "mov",  # New Google TLDs that look like file extensions
    "info", "biz",  # Older TLDs with elevated abuse
    "online", "site", "website",  # Generic, often abused
    "live", "life", "world",  # Commonly used in scams
})


def suspicious_tld_signal(host: str) -> dict:
    """Check if domain uses a TLD known for high abuse rates."""
    if not host:
        return {
            "id": "suspicious_tld",
            "status": "error",
            "concern": False,
            "summary": "No hostname provided.",
        }

    # Extract TLD
    parts = host.lower().split(".")
    if len(parts) < 2:
        return {
            "id": "suspicious_tld",
            "status": "ok",
            "concern": False,
            "summary": "Could not extract TLD from hostname.",
        }

    tld = parts[-1].split(":")[0]  # Remove port if present

    if tld in _SUSPICIOUS_TLDS:
        return {
            "id": "suspicious_tld",
            "status": "ok",
            "concern": True,
            "tld": tld,
            "summary": f"The .{tld} TLD has high abuse rates and is commonly used in phishing.",
        }

    return {
        "id": "suspicious_tld",
        "status": "ok",
        "concern": False,
        "tld": tld,
        "summary": "TLD does not have elevated abuse rates.",
    }
