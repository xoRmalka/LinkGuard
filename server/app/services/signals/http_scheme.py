"""Penalize plain HTTP (non-HTTPS) URLs."""


def http_scheme_signal(scheme: str) -> dict:
    """Check if URL uses insecure HTTP instead of HTTPS."""
    scheme_lower = (scheme or "").lower()

    if scheme_lower == "http":
        return {
            "id": "http_scheme",
            "status": "ok",
            "concern": True,
            "summary": "URL uses plain HTTP — data is not encrypted in transit.",
        }

    if scheme_lower == "https":
        return {
            "id": "http_scheme",
            "status": "ok",
            "concern": False,
            "summary": "URL uses HTTPS (encrypted connection).",
        }

    # Shouldn't happen given normalize.py filters, but handle gracefully
    return {
        "id": "http_scheme",
        "status": "error",
        "concern": False,
        "summary": f"Unexpected scheme: {scheme}",
    }
