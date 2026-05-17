from __future__ import annotations

import json
import os
from typing import Any


def _weights_path() -> str:
    return os.path.join(os.path.dirname(__file__), "weights.json")


def load_weights() -> dict[str, Any]:
    with open(_weights_path(), encoding="utf-8") as f:
        return json.load(f)


def _partial_for_signal(sig: dict, cfg: dict) -> float:
    max_pts = float(cfg.get("max_points", 0))
    sid = sig.get("id")
    status = sig.get("status")
    concern = bool(sig.get("concern"))

    if sid == "parse" and status == "error":
        return max_pts
    if concern:
        return max_pts
    if status in ("error", "skipped"):
        return max_pts * 0.15
    if status == "unknown":
        return max_pts * 0.2
    return 0.0


def aggregate_score(signals: list[dict], weights_version: str) -> dict[str, Any]:
    """
    Calculate safety confidence score (0-100%).

    Higher score = Safer link
    Lower score = More risky link

    This is inverted from the old model which accumulated danger points.
    """
    weights = load_weights()
    cfg_map = weights.get("signals", {})
    total_penalty = 0.0
    breakdown_scores: list[dict] = []

    # Calculate total penalty from all concerning signals
    for sig in signals:
        sid = sig.get("id")
        cfg = cfg_map.get(sid, {"max_points": 0})
        penalty = _partial_for_signal(sig, cfg)
        total_penalty += penalty
        # Keep field name as "points" for backward compatibility (represents penalty deducted from 100)
        breakdown_scores.append({**sig, "points": round(penalty, 2)})

    # Convert penalty to safety score: Start at 100% safe, subtract penalties
    safety_score = int(round(max(0.0, 100.0 - total_penalty)))

    # Risk bands based on safety percentage (higher = safer)
    if safety_score >= 85:
        band = "safe"
    elif safety_score >= 70:
        band = "low_risk"
    elif safety_score >= 50:
        band = "moderate_risk"
    else:
        band = "high_risk"

    # Check for insufficient data conditions
    sb = next((s for s in signals if s.get("id") == "safe_browsing"), None)
    sb_skipped = sb and sb.get("status") == "skipped"
    sb_error = sb and sb.get("status") == "error"

    insufficient = False
    reasons: list[str] = []
    if sb_skipped:
        reasons.append("Threat intelligence (Google Safe Browsing) was not queried (missing API key).")
    if sb_error and safety_score > 80:
        # Only mark insufficient if we'd otherwise say it's safe but can't verify
        insufficient = True
        reasons.append("Google Safe Browsing could not be reached or returned an error.")

    # Determine verdict based on safety score
    # Safe Browsing concern overrides everything
    if next((s for s in signals if s.get("id") == "safe_browsing" and s.get("concern")), None):
        verdict = "dangerous"
    elif insufficient:
        verdict = "insufficient_data"
    elif safety_score >= 85:
        verdict = "safe"
    elif safety_score >= 70:
        verdict = "low_risk"
    elif safety_score >= 50:
        verdict = "moderate_risk"
    else:
        verdict = "high_risk"

    return {
        "score": safety_score,  # Now represents % safe (0-100)
        "risk_band": band,
        "verdict": verdict,
        "breakdown": breakdown_scores,
        "weights_version": weights_version,
        "insufficient": verdict == "insufficient_data",
        "insufficient_reasons": reasons,
    }
