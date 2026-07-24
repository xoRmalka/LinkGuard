from app.services.scoring import aggregate_score


def _signals(safe_browsing: dict) -> list[dict]:
    return [
        {"id": "parse", "status": "ok", "concern": False},
        {"id": "domain_age", "status": "ok", "concern": False},
        {"id": "typosquatting", "status": "ok", "concern": False},
        {"id": "ip_host", "status": "ok", "concern": False},
        {"id": "entropy", "status": "ok", "concern": False},
        {"id": "shortener", "status": "ok", "concern": False},
        safe_browsing,
    ]


def test_safe_browsing_threat_forces_dangerous_high_risk_score():
    result = aggregate_score(
        _signals({"id": "safe_browsing", "status": "ok", "concern": True}),
        "test",
    )

    assert result["score"] <= 20
    assert result["risk_band"] == "high_risk"
    assert result["verdict"] == "dangerous"


def test_clean_safe_browsing_result_keeps_regular_score():
    """All clean signals should return max score (capped at 95 - no automated analysis is 100% safe)."""
    result = aggregate_score(
        _signals({"id": "safe_browsing", "status": "ok", "concern": False}),
        "test",
    )

    assert result["score"] == 95  # Max score capped at 95%
    assert result["risk_band"] == "safe"
    assert result["verdict"] == "likely_safe"


def test_skipped_safe_browsing_prevents_safe_verdict():
    result = aggregate_score(
        _signals({"id": "safe_browsing", "status": "skipped", "concern": False}),
        "test",
    )

    assert result["score"] > 80
    assert result["verdict"] == "insufficient_data"
    assert result["insufficient"] is True
    assert result["insufficient_reasons"]


def test_safe_browsing_error_prevents_safe_verdict():
    result = aggregate_score(
        _signals({"id": "safe_browsing", "status": "error", "concern": False}),
        "test",
    )

    assert result["score"] > 80
    assert result["verdict"] == "insufficient_data"
    assert result["insufficient"] is True
