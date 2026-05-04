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
    weights = load_weights()
    cfg_map = weights.get("signals", {})
    total = 0.0
    breakdown_scores: list[dict] = []

    for sig in signals:
        sid = sig.get("id")
        cfg = cfg_map.get(sid, {"max_points": 0})
        pts = _partial_for_signal(sig, cfg)
        total += pts
        breakdown_scores.append({**sig, "points": round(pts, 2)})

    score = int(round(min(100.0, total)))

    if score <= 24:
        band = "low"
    elif score <= 49:
        band = "medium"
    elif score <= 74:
        band = "high"
    else:
        band = "critical"

    sb = next((s for s in signals if s.get("id") == "safe_browsing"), None)
    sb_skipped = sb and sb.get("status") == "skipped"
    sb_error = sb and sb.get("status") == "error"

    insufficient = False
    reasons: list[str] = []
    if sb_skipped:
        reasons.append("Threat intelligence (Google Safe Browsing) was not queried (missing API key).")
    if sb_error and score < 20:
        insufficient = True
        reasons.append("Google Safe Browsing could not be reached or returned an error.")

    verdict = "safe_low"
    if next((s for s in signals if s.get("id") == "safe_browsing" and s.get("concern")), None):
        verdict = "dangerous"
    elif insufficient:
        verdict = "insufficient_data"
    elif score >= 75:
        verdict = "dangerous"
    elif score >= 25:
        verdict = "suspicious"
    else:
        verdict = "safe_low"

    return {
        "score": score,
        "risk_band": band,
        "verdict": verdict,
        "breakdown": breakdown_scores,
        "weights_version": weights_version,
        "insufficient": verdict == "insufficient_data",
        "insufficient_reasons": reasons,
    }
