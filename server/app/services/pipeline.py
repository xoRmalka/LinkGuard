from __future__ import annotations

from urllib.parse import urlsplit

from flask import current_app

from app.services.integrations.safe_browsing import check_safe_browsing
from app.services.normalize import normalize_url
from app.services.scoring import aggregate_score
from app.services.signals.domain_age import domain_age_signal
from app.services.signals.entropy import entropy_signal
from app.services.signals.http_scheme import http_scheme_signal
from app.services.signals.internal_host import internal_host_signal
from app.services.signals.ip_host import ip_host_signal
from app.services.signals.parse import parse_signal
from app.services.signals.punycode import punycode_signal
from app.services.signals.shortener import shortener_signal
from app.services.signals.suspicious_port import suspicious_port_signal
from app.services.signals.suspicious_subdomain import suspicious_subdomain_signal
from app.services.signals.suspicious_tld import suspicious_tld_signal
from app.services.signals.typosquatting import typosquatting_signal
from app.services.signals.url_length import url_length_signal
from app.services.signals.userinfo import userinfo_signal


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

    # Extract port from normalized URL
    try:
        port = parts.port
    except ValueError:
        port = None

    signals: list[dict] = []

    # URL structure signals
    signals.append(parse_signal(True))
    signals.append(http_scheme_signal(norm.scheme or ""))
    signals.append(url_length_signal(norm.normalized_url or ""))
    signals.append(suspicious_port_signal(port))
    signals.append(userinfo_signal(norm.has_userinfo))

    # Domain signals
    signals.append(ip_host_signal(norm.is_ip_host))
    signals.append(internal_host_signal(norm.host))
    signals.append(punycode_signal(norm.punycode_applied, norm.host_display, norm.host))
    signals.append(shortener_signal(norm.host or ""))
    signals.append(typosquatting_signal(norm.host_display or norm.host or ""))
    signals.append(suspicious_tld_signal(norm.host or ""))
    signals.append(suspicious_subdomain_signal(norm.host or ""))
    signals.append(domain_age_signal(norm.host or ""))

    # Content signals
    signals.append(entropy_signal(path_query))

    # Threat intelligence
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
        "has_userinfo": norm.has_userinfo,
        **agg,
        "explanation": explanation,
        "recommended_actions": actions,
        "explanation_keys": explanation,
        "action_keys": actions,
    }


def _copy_for_result(agg: dict) -> tuple[list[str], list[str]]:
    """Generate user-facing explanation and recommended actions using i18n keys."""
    verdict = agg["verdict"]

    if verdict == "insufficient_data":
        return (
            ["explanation.insufficient_data.main"],
            ["action.insufficient_data.retry", "action.insufficient_data.avoid"],
        )

    if verdict == "dangerous" or verdict == "high_risk":
        return (
            ["explanation.dangerous.main"],
            ["action.dangerous.stop", "action.dangerous.report"],
        )

    if verdict == "moderate_risk":
        return (
            ["explanation.suspicious.main"],
            ["action.suspicious.verify", "action.suspicious.navigate"],
        )

    if verdict == "low_risk":
        return (
            ["explanation.low_risk.main", "explanation.low_risk.caveat"],
            ["action.low_risk.verify", "action.low_risk.updates"],
        )

    # verdict == "likely_safe"
    return (
        ["explanation.likely_safe.main", "explanation.likely_safe.caveat"],
        ["action.safe.verify", "action.safe.updates"],
    )
