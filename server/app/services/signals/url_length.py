"""Detect excessively long URLs which can indicate obfuscation."""


def url_length_signal(url: str) -> dict:
    """Check if URL is excessively long (potential obfuscation)."""
    if not url:
        return {
            "id": "url_length",
            "status": "error",
            "concern": False,
            "summary": "No URL provided.",
        }

    length = len(url)

    if length > 200:
        return {
            "id": "url_length",
            "status": "ok",
            "concern": True,
            "length": length,
            "summary": f"URL is very long ({length} characters) — often used to hide malicious content.",
        }

    if length > 100:
        return {
            "id": "url_length",
            "status": "ok",
            "concern": True,
            "severity": "moderate",
            "length": length,
            "summary": f"URL is unusually long ({length} characters) — review carefully.",
        }

    return {
        "id": "url_length",
        "status": "ok",
        "concern": False,
        "length": length,
        "summary": "URL length is normal.",
    }
