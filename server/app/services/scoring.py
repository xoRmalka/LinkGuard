from __future__ import annotations

import json
import os
from typing import Any


def _weights_path() -> str:
    return os.path.join(os.path.dirname(__file__), "weights.json")


def load_weights() -> dict[str, Any]:
    with open(_weights_path(), encoding="utf-8") as f:
        return json.load(f)


def _partial_for_signal(sig: dict, cfg: dict, weights: dict) -> float:
    """
    Calculate penalty points for a signal.

    Penalties are applied when:
    - concern is True: full max_points (or 50% if severity is "moderate")
    - status is error/skipped: 40% of max_points (uncertainty penalty)
    - status is unknown: 50% of max_points (uncertainty penalty)
    """
    max_pts = float(cfg.get("max_points", 0))
    sid = sig.get("id")
    status = sig.get("status")
    concern = bool(sig.get("concern"))
    severity = sig.get("severity")

    # Parse errors are always full penalty
    if sid == "parse" and status == "error":
        return max_pts

    # Concern detected
    if concern:
        # Moderate severity gets partial penalty (e.g., domain age 30-180 days, url length 100-200)
        if severity == "moderate":
            moderate_mult = weights.get("moderate_severity_multiplier", 0.5)
            return max_pts * moderate_mult
        return max_pts

    # Uncertainty penalties - missing/failed data should reduce confidence
    uncertainty = weights.get("uncertainty_penalties", {})
    if status == "error":
        return max_pts * uncertainty.get("error_multiplier", 0.40)
    if status == "skipped":
        return max_pts * uncertainty.get("skipped_multiplier", 0.40)
    if status == "unknown":
        return max_pts * uncertainty.get("unknown_multiplier", 0.50)

    return 0.0


def _calculate_confidence(signals: list[dict]) -> dict:
    """
    Calculate confidence level based on how many checks completed successfully.

    Returns:
        dict with checks_completed, checks_total, confidence_level
    """
    total = len(signals)
    completed = sum(
        1 for s in signals
        if s.get("status") == "ok"
    )

    incomplete = total - completed

    if incomplete == 0:
        level = "high"
    elif incomplete <= 2:
        level = "medium"
    else:
        level = "low"

    return {
        "checks_completed": completed,
        "checks_total": total,
        "confidence_level": level,
    }


def aggregate_score(signals: list[dict], weights_version: str) -> dict[str, Any]:
    """
    Calculate safety confidence score (0-95%).

    Higher score = Safer link
    Lower score = More risky link

    Key principles:
    - Maximum score is capped at 95% (no automated analysis can guarantee safety)
    - Uncertainty is heavily penalized (missing/failed checks reduce score)
    - Multiple concerns trigger additional penalty
    - Multiple failed checks trigger insufficient_data verdict
    """
    weights = load_weights()
    cfg_map = weights.get("signals", {})
    max_score = weights.get("max_score", 95)
    likely_safe_threshold = weights.get("likely_safe_threshold", 90)

    total_penalty = 0.0
    breakdown_scores: list[dict] = []

    # Track incomplete signals and concerns
    incomplete_signals: list[str] = []
    concern_signals: list[str] = []

    # Calculate total penalty from all signals
    for sig in signals:
        sid = sig.get("id")
        cfg = cfg_map.get(sid, {"max_points": 0})
        penalty = _partial_for_signal(sig, cfg, weights)
        total_penalty += penalty

        # Track incomplete checks
        if sig.get("status") in ("error", "skipped", "unknown"):
            incomplete_signals.append(sid)

        # Track concerns
        if sig.get("concern"):
            concern_signals.append(sid)

        breakdown_scores.append({**sig, "points": round(penalty, 2)})

    # Apply multiple concerns penalty
    concerns_threshold = weights.get("multiple_concerns_threshold", 3)
    concerns_penalty = weights.get("multiple_concerns_penalty", 10)
    if len(concern_signals) >= concerns_threshold:
        total_penalty += concerns_penalty

    # Convert penalty to safety score, capped at max_score
    raw_score = max(0.0, 100.0 - total_penalty)
    safety_score = int(round(min(raw_score, max_score)))

    # Calculate confidence metrics
    confidence = _calculate_confidence(signals)

    # Hard cap if domain age is unknown
    domain_age = next((s for s in signals if s.get("id") == "domain_age"), None)
    domain_age_unknown = domain_age and domain_age.get("status") in ("unknown", "error")
    if domain_age_unknown:
        domain_age_cap = weights.get("domain_age_unknown_cap", 85)
        safety_score = min(safety_score, domain_age_cap)

    # Hard overrides for known threats
    sb = next((s for s in signals if s.get("id") == "safe_browsing"), None)
    sb_threat = bool(sb and sb.get("concern"))
    if sb_threat:
        safety_score = min(safety_score, 20)

    # Typosquatting is a near-certain indicator of phishing
    typo = next((s for s in signals if s.get("id") == "typosquatting"), None)
    if typo and typo.get("concern"):
        safety_score = min(safety_score, 45)

    userinfo = next((s for s in signals if s.get("id") == "userinfo"), None)
    if userinfo and userinfo.get("concern"):
        safety_score = min(safety_score, 45)

    internal_host = next((s for s in signals if s.get("id") == "internal_host"), None)
    if internal_host and internal_host.get("concern"):
        safety_score = min(safety_score, 45)

    # A suspicious subdomain pattern (brand impersonation, clustered phishing
    # keywords, excessive depth) is a strong standalone signal on its own —
    # it should not need an also-suspicious TLD to be forced into high_risk.
    suspicious_subdomain = next((s for s in signals if s.get("id") == "suspicious_subdomain"), None)
    if suspicious_subdomain and suspicious_subdomain.get("concern"):
        safety_score = min(safety_score, 45)

    suspicious_tld = next((s for s in signals if s.get("id") == "suspicious_tld"), None)
    if (
        suspicious_tld and suspicious_tld.get("concern")
        and suspicious_subdomain and suspicious_subdomain.get("concern")
    ):
        safety_score = min(safety_score, 49)

    # "Likely safe" should mean no checks found a concrete concern.
    if concern_signals and safety_score >= likely_safe_threshold:
        safety_score = max(0, likely_safe_threshold - 1)

    # Risk bands based on safety percentage
    if safety_score >= likely_safe_threshold:
        band = "safe"
    elif safety_score >= 70:
        band = "low_risk"
    elif safety_score >= 50:
        band = "moderate_risk"
    else:
        band = "high_risk"

    # Insufficient data detection
    insufficient = False
    reasons: list[str] = []

    # Safe Browsing unavailable
    sb_skipped = sb and sb.get("status") == "skipped"
    sb_error = sb and sb.get("status") == "error"
    if sb_skipped:
        reasons.append("insufficient.reason.safe_browsing_skipped")
    if sb_error:
        reasons.append("insufficient.reason.safe_browsing_error")

    # URL shorteners hide destination
    shortener = next((s for s in signals if s.get("id") == "shortener"), None)
    if shortener and shortener.get("concern"):
        reasons.append("insufficient.reason.shortener")
        if safety_score > 60:
            insufficient = True

    # Domain age unknown
    if domain_age_unknown:
        reasons.append("insufficient.reason.domain_age_unknown")

    # Multiple incomplete checks = low confidence
    if len(incomplete_signals) >= 3:
        insufficient = True
        if "insufficient.reason.multiple_checks_failed" not in reasons:
            reasons.append("insufficient.reason.multiple_checks_failed")

    # High score but critical checks missing
    if (sb_skipped or sb_error) and safety_score > 80:
        insufficient = True

    # Determine verdict
    if sb_threat:
        verdict = "dangerous"
    elif insufficient:
        verdict = "insufficient_data"
    elif safety_score >= likely_safe_threshold:
        verdict = "likely_safe"
    elif safety_score >= 70:
        verdict = "low_risk"
    elif safety_score >= 50:
        verdict = "moderate_risk"
    else:
        verdict = "high_risk"

    return {
        "score": safety_score,
        "risk_band": band,
        "verdict": verdict,
        "breakdown": breakdown_scores,
        "weights_version": weights.get("version", weights_version),
        "insufficient": verdict == "insufficient_data",
        "insufficient_reasons": reasons,
        "concerns_count": len(concern_signals),
        **confidence,
    }
