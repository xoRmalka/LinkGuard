from app.services.signals.domain_utils import parse_domain
from app.services.signals.suspicious_subdomain import suspicious_subdomain_signal
from app.services.signals.typosquatting import typosquatting_signal


def test_parse_domain_extracts_registrable_domain_from_service_subdomain():
    parts = parse_domain("login.microsoft.com")

    assert parts.registrable_domain == "microsoft.com"
    assert parts.domain_label == "microsoft"
    assert parts.subdomains == ("login",)


def test_parse_domain_handles_common_multi_label_suffix():
    parts = parse_domain("accounts.bank.co.il")

    assert parts.registrable_domain == "bank.co.il"
    assert parts.domain_label == "bank"
    assert parts.subdomains == ("accounts",)


def test_typosquatting_uses_registered_domain_not_login_subdomain():
    result = typosquatting_signal("login.microsoft.com")

    assert result["concern"] is False
    assert result["closest_brand"] == "microsoft"
    assert result["distance"] == 0


def test_suspicious_subdomain_allows_common_single_auth_subdomains():
    for host in ("login.microsoft.com", "accounts.google.com", "support.apple.com"):
        result = suspicious_subdomain_signal(host)
        assert result["concern"] is False


def test_suspicious_subdomain_flags_clustered_phishing_terms():
    result = suspicious_subdomain_signal("secure-login-paypal.com.xyz")

    assert result["concern"] is True
    assert "login" in result["found_keywords"]
    assert "secure" in result["found_keywords"]

def test_typosquatting_does_not_fuzzy_match_short_generic_labels():
    result = typosquatting_signal("secure-login-paypal.com.xyz")

    assert result["concern"] is False
