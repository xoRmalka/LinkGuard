"""Detect punycode/IDN domains which can be used in homograph attacks."""


def punycode_signal(punycode_applied: bool, host_display: str | None, host: str | None) -> dict:
    """Check if domain uses punycode (internationalized domain name)."""
    if not punycode_applied:
        return {
            "id": "punycode",
            "status": "ok",
            "concern": False,
            "summary": "Domain uses standard ASCII characters.",
        }

    # Punycode was applied - this is a potential homograph attack
    display = host_display or host or "unknown"
    ascii_form = host or "unknown"

    return {
        "id": "punycode",
        "status": "ok",
        "concern": True,
        "display_form": display,
        "ascii_form": ascii_form,
        "summary": f"Domain uses international characters ({display}) — potential homograph attack.",
    }
