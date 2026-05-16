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
from app.services.signals.ssl_check import ssl_signal
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
    signals.append(domain_age_signal())
    signals.append(ssl_signal(norm.normalized_url or ""))

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
        "explanation_keys": explanation,
        "action_keys": actions,
    }


def _copy_for_result(agg: dict) -> tuple[list[str], list[str]]:
    if agg["verdict"] == "insufficient_data":
        return (
            ["explanation.insufficient_data.main"],
            ["action.insufficient_data.retry", "action.insufficient_data.avoid"],
        )

    if agg["verdict"] == "dangerous":
        return (
            ["explanation.dangerous.main"],
            ["action.dangerous.stop", "action.dangerous.report"],
        )

    if agg["verdict"] == "suspicious":
        return (
            ["explanation.suspicious.main"],
            ["action.suspicious.verify", "action.suspicious.navigate"],
        )

    return (
        ["explanation.safe.main", "explanation.safe.caveat"],
        ["action.safe.verify", "action.safe.updates"],
    )
