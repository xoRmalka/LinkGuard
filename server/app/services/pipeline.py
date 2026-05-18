from __future__ import annotations

from urllib.parse import urlsplit

from flask import current_app

from app.services.integrations.safe_browsing import check_safe_browsing
from app.services.normalize import normalize_url
from app.services.scoring import aggregate_score
from app.services.signals.domain_age import domain_age_signal
from app.services.signals.entropy import entropy_signal
from app.services.signals.ip_host import ip_host_signal
from app.services.signals.parse import parse_signal
from app.services.signals.shortener import shortener_signal
# SSL check removed - security risk (direct connection to malicious hosts) and high false positive rate
# from app.services.signals.ssl_check import ssl_signal
from app.services.signals.typosquatting import typosquatting_signal


def run_pipeline(raw_url: str) -> dict:
    norm = normalize_url(raw_url)
    if not norm.ok:
        return {
            "ok": False,
            "error": norm.error or "invalid",
            "message": "Could not parse this as a supported HTTP(S) URL.",
        }

    parts = urlsplit(norm.normalized_url or "")
    path_query = (parts.path or "/") + (("?" + parts.query) if parts.query else "")

    signals: list[dict] = []
    signals.append(parse_signal(True))
    signals.append(ip_host_signal(norm.is_ip_host))
    signals.append(shortener_signal(norm.host or ""))
    signals.append(typosquatting_signal(norm.host_display or norm.host or ""))
    signals.append(entropy_signal(path_query))
    signals.append(domain_age_signal(norm.host or ""))
    # SSL check removed - causes security issues (direct connection) and false positives
    # signals.append(ssl_signal(norm.normalized_url or ""))

    api_key = current_app.config.get("GOOGLE_SAFE_BROWSING_API_KEY", "")
    signals.append(check_safe_browsing(norm.normalized_url or "", api_key))

    wv = current_app.config.get("WEIGHTS_VERSION", "unknown")
    agg = aggregate_score(signals, wv)

    explanation, actions = _copy_for_result(agg)

    return {
        "ok": True,
        "input_url": norm.input_url,
        "normalized_url": norm.normalized_url,
        "host": norm.host,
        "host_display": norm.host_display,
        "scheme": norm.scheme,
        "is_ip_host": norm.is_ip_host,
        "punycode_applied": norm.punycode_applied,
        **agg,
        "explanation": explanation,
        "recommended_actions": actions,
    }


def _copy_for_result(agg: dict) -> tuple[list[str], list[str]]:
    """Generate user-facing explanation and recommended actions based on safety score."""
    lines: list[str] = []
    actions: list[str] = []
    verdict = agg["verdict"]
    score = agg["score"]

    if verdict == "insufficient_data":
        lines.append(
            "We couldn't verify all security signals, so our confidence in this assessment is limited."
        )
        lines.extend(agg.get("insufficient_reasons") or [])
        actions.append("Try scanning again later, or sign in if the service was temporarily rate-limited.")
        actions.append("Avoid entering credentials or downloading files until you can get stronger confirmation.")
        return lines, actions

    if verdict == "dangerous" or verdict == "high_risk":
        lines.append(
            f"This link appears unsafe ({score}% safety confidence). Multiple security concerns were detected."
        )
        actions.append("Do not enter credentials, download files, or click this link.")
        actions.append("If you already opened it, close the page immediately.")
        actions.append("Report this link if it came from an unexpected message or email.")
        return lines, actions

    if verdict == "moderate_risk":
        lines.append(
            f"This link shows some concerning patterns ({score}% safety confidence). Proceed with caution."
        )
        actions.append("Verify the sender through a second channel before taking any action.")
        actions.append("If this is for login or payment, navigate to the site directly by typing the known URL.")
        actions.append("Look for signs of legitimacy: official domain name, HTTPS, familiar branding.")
        return lines, actions

    if verdict == "low_risk":
        lines.append(
            f"This link appears mostly safe ({score}% safety confidence), but stay alert."
        )
        lines.append(
            "No major red flags detected, though this doesn't guarantee the link is completely harmless."
        )
        actions.append("If the link was unsolicited, verify through another channel before logging in or paying.")
        actions.append("Keep your device and browser updated for defense in depth.")
        return lines, actions

    # verdict == "safe"
    lines.append(
        f"This link appears safe ({score}% safety confidence). No significant security concerns detected."
    )
    lines.append(
        "All automated checks passed, though you should always stay cautious with unexpected links."
    )
    actions.append("If this link came from an unknown sender, verify it through another channel first.")
    actions.append("Keep device and browser updates enabled for ongoing protection.")
    return lines, actions
