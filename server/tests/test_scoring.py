"""Tests for the scoring module."""

from app.services.scoring import aggregate_score


def _base_signals() -> list[dict]:
    """Return a baseline set of all-clean signals."""
    return [
        {"id": "parse", "status": "ok", "concern": False},
        {"id": "http_scheme", "status": "ok", "concern": False},
        {"id": "url_length", "status": "ok", "concern": False},
        {"id": "suspicious_port", "status": "ok", "concern": False},
        {"id": "userinfo", "status": "ok", "concern": False},
        {"id": "ip_host", "status": "ok", "concern": False},
        {"id": "internal_host", "status": "ok", "concern": False},
        {"id": "punycode", "status": "ok", "concern": False},
        {"id": "shortener", "status": "ok", "concern": False},
        {"id": "typosquatting", "status": "ok", "concern": False},
        {"id": "suspicious_tld", "status": "ok", "concern": False},
        {"id": "suspicious_subdomain", "status": "ok", "concern": False},
        {"id": "domain_age", "status": "ok", "concern": False},
        {"id": "entropy", "status": "ok", "concern": False},
        {"id": "safe_browsing", "status": "ok", "concern": False},
    ]


def _signals_with(overrides: dict) -> list[dict]:
    """Return base signals with specified signals overridden."""
    signals = _base_signals()
    for sig in signals:
        if sig["id"] in overrides:
            sig.update(overrides[sig["id"]])
    return signals


# =============================================================================
# Core Scoring Tests
# =============================================================================


def test_max_score_is_95_not_100():
    """Max score should be capped at 95% - no automated analysis can guarantee safety."""
    result = aggregate_score(_base_signals(), "test")

    assert result["score"] == 95
    assert result["score"] < 100


def test_all_clean_signals_return_likely_safe():
    """All clean signals should return likely_safe verdict (requires score >= 90)."""
    result = aggregate_score(_base_signals(), "test")

    assert result["verdict"] == "likely_safe"
    assert result["risk_band"] == "safe"


def test_confidence_tracking_all_complete():
    """All signals completing should give high confidence."""
    result = aggregate_score(_base_signals(), "test")

    assert result["checks_completed"] == 15
    assert result["checks_total"] == 15
    assert result["confidence_level"] == "high"


# =============================================================================
# Safe Browsing Override Tests
# =============================================================================


def test_safe_browsing_threat_forces_dangerous():
    """Safe Browsing threat match must override score to dangerous."""
    signals = _signals_with({
        "safe_browsing": {"status": "ok", "concern": True}
    })
    result = aggregate_score(signals, "test")

    assert result["score"] <= 20
    assert result["verdict"] == "dangerous"
    assert result["risk_band"] == "high_risk"


def test_safe_browsing_skipped_triggers_insufficient():
    """Skipped Safe Browsing with high score should trigger insufficient_data."""
    signals = _signals_with({
        "safe_browsing": {"status": "skipped", "concern": False}
    })
    result = aggregate_score(signals, "test")

    assert result["verdict"] == "insufficient_data"
    assert result["insufficient"] is True
    assert "insufficient.reason.safe_browsing_skipped" in result["insufficient_reasons"]


def test_safe_browsing_error_triggers_insufficient():
    """Safe Browsing error with high score should trigger insufficient_data."""
    signals = _signals_with({
        "safe_browsing": {"status": "error", "concern": False}
    })
    result = aggregate_score(signals, "test")

    assert result["verdict"] == "insufficient_data"
    assert result["insufficient"] is True
    assert "insufficient.reason.safe_browsing_error" in result["insufficient_reasons"]


# =============================================================================
# Typosquatting Tests
# =============================================================================


def test_typosquatting_caps_score_at_45():
    """Typosquatting concern must cap score at 45%."""
    signals = _signals_with({
        "typosquatting": {"status": "ok", "concern": True}
    })
    result = aggregate_score(signals, "test")

    assert result["score"] <= 45
    assert result["verdict"] == "moderate_risk" or result["verdict"] == "high_risk"


# =============================================================================
# Uncertainty Penalty Tests
# =============================================================================


def test_unknown_status_applies_penalty():
    """Unknown status should apply penalty and cap score."""
    signals = _signals_with({
        "domain_age": {"status": "unknown", "concern": False}
    })
    result = aggregate_score(signals, "test")

    # Capped at 85 due to domain_age_unknown_cap
    assert result["score"] <= 85
    assert result["score"] < 95


def test_error_status_applies_penalty():
    """Error status should apply penalty."""
    signals = _signals_with({
        "suspicious_tld": {"status": "error", "concern": False}
    })
    result = aggregate_score(signals, "test")

    # Should be lower than max
    assert result["score"] < 95


def test_three_incomplete_signals_triggers_insufficient():
    """Three or more incomplete signals should trigger insufficient_data."""
    signals = _signals_with({
        "domain_age": {"status": "unknown", "concern": False},
        "safe_browsing": {"status": "error", "concern": False},
        "suspicious_tld": {"status": "error", "concern": False},
    })
    result = aggregate_score(signals, "test")

    assert result["insufficient"] is True
    assert result["verdict"] == "insufficient_data"
    assert "insufficient.reason.multiple_checks_failed" in result["insufficient_reasons"]
    assert result["confidence_level"] == "low"


def test_confidence_medium_with_two_incomplete():
    """Two incomplete signals should give medium confidence."""
    signals = _signals_with({
        "suspicious_tld": {"status": "error", "concern": False},
        "entropy": {"status": "error", "concern": False},
    })
    result = aggregate_score(signals, "test")

    assert result["confidence_level"] == "medium"
    assert result["checks_completed"] == 13


# =============================================================================
# Domain Age Tests
# =============================================================================


def test_domain_age_unknown_caps_at_85():
    """Domain age unknown should cap score at 85%."""
    signals = _signals_with({
        "domain_age": {"status": "unknown", "concern": False}
    })
    result = aggregate_score(signals, "test")

    assert result["score"] <= 85


def test_domain_age_moderate_severity_gets_partial_penalty():
    """Domain age with moderate severity should get partial penalty."""
    signals = _signals_with({
        "domain_age": {"status": "ok", "concern": True, "severity": "moderate"}
    })
    result = aggregate_score(signals, "test")

    # Should be between full penalty and no penalty
    assert result["score"] < 95
    assert result["score"] > 70  # Not full 25 point penalty


def test_domain_age_full_concern_gets_full_penalty():
    """Domain age with full concern (no severity) should get full penalty."""
    signals = _signals_with({
        "domain_age": {"status": "ok", "concern": True}
    })
    result = aggregate_score(signals, "test")

    # Full 25 point penalty: 95 - 25 = 70 (may round up)
    assert result["score"] <= 75


# =============================================================================
# Shortener Tests
# =============================================================================


def test_shortener_triggers_insufficient_with_high_score():
    """Shortener with otherwise high score should trigger insufficient_data."""
    signals = _signals_with({
        "shortener": {"status": "ok", "concern": True}
    })
    result = aggregate_score(signals, "test")

    assert result["insufficient"] is True
    assert "insufficient.reason.shortener" in result["insufficient_reasons"]


# =============================================================================
# New Signal Tests
# =============================================================================


def test_suspicious_tld_applies_penalty():
    """Suspicious TLD concern should apply penalty."""
    signals = _signals_with({
        "suspicious_tld": {"status": "ok", "concern": True}
    })
    result = aggregate_score(signals, "test")

    assert result["score"] < 95


def test_suspicious_subdomain_applies_penalty():
    """Suspicious subdomain concern should apply penalty."""
    signals = _signals_with({
        "suspicious_subdomain": {"status": "ok", "concern": True}
    })
    result = aggregate_score(signals, "test")

    assert result["score"] < 95


def test_http_scheme_applies_penalty():
    """HTTP scheme (non-HTTPS) concern should apply penalty."""
    signals = _signals_with({
        "http_scheme": {"status": "ok", "concern": True}
    })
    result = aggregate_score(signals, "test")

    # Verify penalty was applied by checking breakdown
    http_signal = next(b for b in result["breakdown"] if b["id"] == "http_scheme")
    assert http_signal["points"] > 0


def test_likely_safe_requires_no_concerns():
    """A URL with any concrete concern should not receive the top verdict."""
    signals = _signals_with({
        "http_scheme": {"status": "ok", "concern": True}
    })
    result = aggregate_score(signals, "test")

    assert result["score"] < 90
    assert result["risk_band"] == "low_risk"
    assert result["verdict"] == "low_risk"


def test_ip_host_applies_penalty():
    """IP host concern should apply penalty."""
    signals = _signals_with({
        "ip_host": {"status": "ok", "concern": True}
    })
    result = aggregate_score(signals, "test")

    assert result["score"] < 95


def test_ip_host_high_severity_caps_score():
    """IP host with high severity (obfuscated/private) should cap score at 40."""
    signals = _signals_with({
        "ip_host": {"status": "ok", "concern": True, "severity": "high"}
    })
    result = aggregate_score(signals, "test")

    assert result["score"] <= 40
    assert result["risk_band"] == "high_risk"


def test_suspicious_port_applies_penalty():
    """Suspicious port concern should apply penalty."""
    signals = _signals_with({
        "suspicious_port": {"status": "ok", "concern": True}
    })
    result = aggregate_score(signals, "test")

    assert result["score"] < 95


def test_url_length_applies_penalty():
    """URL length concern should apply penalty."""
    signals = _signals_with({
        "url_length": {"status": "ok", "concern": True}
    })
    result = aggregate_score(signals, "test")

    # Verify penalty was applied by checking breakdown
    url_signal = next(b for b in result["breakdown"] if b["id"] == "url_length")
    assert url_signal["points"] > 0


def test_punycode_applies_penalty():
    """Punycode concern should apply penalty."""
    signals = _signals_with({
        "punycode": {"status": "ok", "concern": True}
    })
    result = aggregate_score(signals, "test")

    assert result["score"] < 95


def test_userinfo_caps_score():
    """Deceptive userinfo should force a high-risk score cap."""
    signals = _signals_with({
        "userinfo": {"status": "ok", "concern": True}
    })
    result = aggregate_score(signals, "test")

    assert result["score"] <= 45
    assert result["risk_band"] == "high_risk"


def test_internal_host_caps_score():
    """Local/private hosts should force a high-risk score cap."""
    signals = _signals_with({
        "internal_host": {"status": "ok", "concern": True}
    })
    result = aggregate_score(signals, "test")

    assert result["score"] <= 45
    assert result["risk_band"] == "high_risk"


def test_suspicious_tld_and_subdomain_combo_is_high_risk():
    """Phishing-style subdomain on an abusive TLD should not stay moderate."""
    signals = _signals_with({
        "suspicious_tld": {"status": "ok", "concern": True},
        "suspicious_subdomain": {"status": "ok", "concern": True},
    })
    result = aggregate_score(signals, "test")

    assert result["score"] <= 49
    assert result["risk_band"] == "high_risk"


# =============================================================================
# Combined/Conflicting Signal Tests
# =============================================================================


def test_multiple_concerns_add_extra_penalty():
    """Three or more concerns should trigger additional penalty."""
    signals = _signals_with({
        "ip_host": {"status": "ok", "concern": True},
        "suspicious_tld": {"status": "ok", "concern": True},
        "http_scheme": {"status": "ok", "concern": True},
    })
    result = aggregate_score(signals, "test")

    assert result["concerns_count"] == 3
    # Multiple penalties accumulate
    assert result["score"] < 70


def test_highly_suspicious_url_gets_high_risk():
    """URL with many red flags should get high_risk verdict."""
    signals = _signals_with({
        "ip_host": {"status": "ok", "concern": True},
        "suspicious_tld": {"status": "ok", "concern": True},
        "http_scheme": {"status": "ok", "concern": True},
        "entropy": {"status": "ok", "concern": True},
        "domain_age": {"status": "ok", "concern": True},
    })
    result = aggregate_score(signals, "test")

    assert result["score"] < 50
    assert result["verdict"] == "high_risk"


def test_old_domain_typosquatting_still_capped():
    """Typosquatting on old domain should still cap score."""
    signals = _signals_with({
        "domain_age": {"status": "ok", "concern": False, "age_days": 3650},
        "typosquatting": {"status": "ok", "concern": True},
    })
    result = aggregate_score(signals, "test")

    assert result["score"] <= 45


# =============================================================================
# Risk Band Tests
# =============================================================================


def test_risk_band_safe_at_90_plus():
    """Score >= 90 should get safe risk band and likely_safe verdict."""
    result = aggregate_score(_base_signals(), "test")

    assert result["score"] >= 90
    assert result["risk_band"] == "safe"
    assert result["verdict"] == "likely_safe"


def test_risk_band_low_risk_at_70_to_89():
    """Score 70-89 should get low_risk band."""
    signals = _signals_with({
        "domain_age": {"status": "ok", "concern": True, "severity": "moderate"},
        "http_scheme": {"status": "ok", "concern": True},
    })
    result = aggregate_score(signals, "test")

    assert 70 <= result["score"] < 90
    assert result["risk_band"] == "low_risk"


def test_risk_band_moderate_at_50_to_69():
    """Score 50-69 should get moderate_risk band."""
    signals = _signals_with({
        "domain_age": {"status": "ok", "concern": True},
        "suspicious_tld": {"status": "ok", "concern": True},
    })
    result = aggregate_score(signals, "test")

    assert 50 <= result["score"] < 70
    assert result["risk_band"] == "moderate_risk"


def test_risk_band_high_below_50():
    """Score < 50 should get high_risk band."""
    signals = _signals_with({
        "domain_age": {"status": "ok", "concern": True},
        "ip_host": {"status": "ok", "concern": True},
        "suspicious_tld": {"status": "ok", "concern": True},
    })
    result = aggregate_score(signals, "test")

    assert result["score"] < 50
    assert result["risk_band"] == "high_risk"
