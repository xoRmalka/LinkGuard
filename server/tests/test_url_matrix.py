import pytest

from app import create_app
from app.config import Config


def _domain_age_ok(host):
    return {
        "id": "domain_age",
        "status": "ok",
        "concern": False,
        "age_days": 3650,
        "summary": f"{host} is an established domain.",
    }


def _safe_browsing_ok(url, api_key):
    return {
        "id": "safe_browsing",
        "status": "ok",
        "concern": False,
        "summary": "No threat match.",
        "matches": [],
    }


@pytest.fixture()
def client(tmp_path, monkeypatch):
    database_path = tmp_path / "linkguard-url-matrix.db"
    monkeypatch.setattr(Config, "SQLALCHEMY_DATABASE_URI", f"sqlite:///{database_path}")
    monkeypatch.setattr(
        Config,
        "SQLALCHEMY_ENGINE_OPTIONS",
        {"connect_args": {"check_same_thread": False}},
    )
    monkeypatch.setattr("app.services.pipeline.domain_age_signal", _domain_age_ok)
    monkeypatch.setattr("app.services.pipeline.check_safe_browsing", _safe_browsing_ok)

    app = create_app()
    app.config.update(TESTING=True)
    return app.test_client()


def _scan(client, raw_url, ip_suffix=10):
    return client.post(
        "/api/v1/scans",
        json={"url": raw_url},
        headers={"X-Forwarded-For": f"198.51.100.{ip_suffix}"},
    )


def _signals(payload):
    return {row["id"]: row for row in payload["breakdown"]}


@pytest.mark.parametrize(
    ("raw_url", "expected_normalized", "expected_host"),
    [
        ("example.com/login", "https://example.com/login", "example.com"),
        (" HTTPS://Example.COM:443/a?b=2&a=1#frag ", "https://example.com/a?b=2&a=1", "example.com"),
        ("http://example.com:80/path", "http://example.com/path", "example.com"),
    ],
)
def test_scan_accepts_and_normalizes_common_url_forms(
    client,
    raw_url,
    expected_normalized,
    expected_host,
):
    response = _scan(client, raw_url)

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["normalized_url"] == expected_normalized
    assert payload["host"] == expected_host


@pytest.mark.parametrize(
    ("raw_url", "expected_error"),
    [
        ("", "empty"),
        ("ftp://example.com", "unsupported_scheme"),
        ("javascript:alert(1)", "unsupported_scheme"),
        ("https://", "missing_host"),
        ("https://example.com:abc/path", "invalid_port"),
        ("https://example.com:70000/path", "invalid_port"),
    ],
)
def test_scan_rejects_invalid_or_unsupported_urls(client, raw_url, expected_error):
    response = _scan(client, raw_url)

    assert response.status_code == 400
    assert response.get_json()["error"] == expected_error


@pytest.mark.parametrize(
    ("raw_url", "expected_signal"),
    [
        ("http://example.com/login", "http_scheme"),
        ("https://192.0.2.1/login", "ip_host"),
        ("http://127.0.0.1/admin", "internal_host"),
        ("https://bit.ly/example-demo", "shortener"),
        ("https://paypa1.com/login", "typosquatting"),
        ("paypal.com@evil.com", "userinfo"),
        ("https://secure-login-paypal.com.xyz/login", "suspicious_tld"),
        ("https://secure.login.paypal.com.evil.xyz/login", "suspicious_subdomain"),
        ("https://example.com/reset/9fd8a7s6d5f4g3h2j1k0q9w8e7r6t5y4u3i2o1p0", "entropy"),
        ("https://\u0430pple.com/login", "punycode"),
    ],
)
def test_scan_flags_representative_risky_url_patterns(client, raw_url, expected_signal):
    response = _scan(client, raw_url)

    assert response.status_code == 200
    payload = response.get_json()
    signals = _signals(payload)
    assert signals[expected_signal]["concern"] is True
    assert payload["verdict"] != "likely_safe"


@pytest.mark.parametrize(
    "raw_url",
    [
        "https://login.microsoft.com",
        "https://accounts.google.com/signin",
        "https://support.apple.com/kb/index",
    ],
)
def test_scan_allows_legitimate_single_auth_subdomains(client, raw_url):
    response = _scan(client, raw_url)

    assert response.status_code == 200
    payload = response.get_json()
    signals = _signals(payload)
    assert signals["typosquatting"]["concern"] is False
    assert signals["suspicious_subdomain"]["concern"] is False
    assert payload["verdict"] in ("likely_safe", "low_risk")


@pytest.mark.parametrize(
    "raw_url",
    [
        "https://paypal.com.evil.xyz/login",
        "https://login.google.com.evil.com/login",
        "https://a.b.c.d.evil.com/login",
    ],
)
def test_brand_impersonation_and_deep_subdomain_obfuscation_are_high_risk(client, raw_url):
    response = _scan(client, raw_url)

    assert response.status_code == 200
    payload = response.get_json()
    signals = _signals(payload)
    assert signals["suspicious_subdomain"]["concern"] is True
    assert payload["verdict"] == "high_risk"


@pytest.mark.parametrize(
    ("raw_url", "expected_host"),
    [
        ("http://2130706433/admin", "127.0.0.1"),
        ("http://0x7f000001/admin", "127.0.0.1"),
        ("http://0177.0.0.1/admin", "127.0.0.1"),
        ("http://127.1/admin", "127.0.0.1"),
    ],
)
def test_obfuscated_loopback_ip_is_resolved_and_high_risk(client, raw_url, expected_host):
    response = _scan(client, raw_url)

    assert response.status_code == 200
    payload = response.get_json()
    signals = _signals(payload)
    assert payload["host"] == expected_host
    assert payload["is_ip_host"] is True
    assert signals["internal_host"]["concern"] is True
    assert payload["verdict"] == "high_risk"


def test_deceptive_userinfo_url_is_high_risk(client):
    response = _scan(client, "paypal.com@evil.com")

    assert response.status_code == 200
    payload = response.get_json()
    signals = _signals(payload)
    assert payload["host"] == "evil.com"
    assert payload["has_userinfo"] is True
    assert signals["userinfo"]["concern"] is True
    assert payload["verdict"] == "high_risk"


def test_ascii_punycode_and_unicode_homograph_are_scored_consistently(client):
    unicode_response = _scan(client, "https://аpple.com/login", ip_suffix=210)
    ascii_response = _scan(client, "https://xn--pple-43d.com/login", ip_suffix=211)

    assert unicode_response.status_code == 200
    assert ascii_response.status_code == 200
    unicode_payload = unicode_response.get_json()
    ascii_payload = ascii_response.get_json()
    assert unicode_payload["host"] == ascii_payload["host"]
    assert unicode_payload["host_display"] == ascii_payload["host_display"]
    assert unicode_payload["verdict"] == ascii_payload["verdict"]
    assert ascii_payload["verdict"] == "high_risk"


def test_suspicious_tld_subdomain_combo_is_high_risk(client):
    response = _scan(client, "https://secure-login-paypal.com.xyz/login")

    assert response.status_code == 200
    payload = response.get_json()
    signals = _signals(payload)
    assert signals["suspicious_tld"]["concern"] is True
    assert signals["suspicious_subdomain"]["concern"] is True
    assert payload["verdict"] == "high_risk"


def test_safe_browsing_threat_overrides_clean_url(tmp_path, monkeypatch):
    database_path = tmp_path / "linkguard-safe-browsing-threat.db"
    monkeypatch.setattr(Config, "SQLALCHEMY_DATABASE_URI", f"sqlite:///{database_path}")
    monkeypatch.setattr(
        Config,
        "SQLALCHEMY_ENGINE_OPTIONS",
        {"connect_args": {"check_same_thread": False}},
    )
    monkeypatch.setattr("app.services.pipeline.domain_age_signal", _domain_age_ok)
    monkeypatch.setattr(
        "app.services.pipeline.check_safe_browsing",
        lambda url, api_key: {
            "id": "safe_browsing",
            "status": "ok",
            "concern": True,
            "summary": "Threat match.",
            "matches": [{"threatType": "MALWARE"}],
        },
    )

    app = create_app()
    app.config.update(TESTING=True)
    response = app.test_client().post(
        "/api/v1/scans",
        json={"url": "https://example.com"},
        headers={"X-Forwarded-For": "198.51.100.240"},
    )

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["verdict"] == "dangerous"
    assert payload["score"] <= 20
