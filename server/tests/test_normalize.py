import pytest

from app.services.normalize import normalize_url


def test_normalize_adds_https():
    r = normalize_url("example.com/foo")
    assert r.ok
    assert r.normalized_url.startswith("https://example.com")
    assert r.host == "example.com"


def test_normalize_rejects_empty():
    r = normalize_url("  ")
    assert not r.ok


def test_normalize_ip_host():
    r = normalize_url("https://192.0.2.1/path")
    assert r.ok
    assert r.is_ip_host


def test_normalize_rejects_non_numeric_port():
    r = normalize_url("https://example.com:abc/path")

    assert not r.ok
    assert r.error == "invalid_port"


def test_normalize_rejects_out_of_range_port():
    r = normalize_url("https://example.com:70000/path")

    assert not r.ok
    assert r.error == "invalid_port"


def test_normalize_preserves_ipv6_brackets():
    r = normalize_url("https://[2001:db8::1]:8443/login")

    assert r.ok
    assert r.host == "2001:db8::1"
    assert r.is_ip_host
    assert r.normalized_url == "https://[2001:db8::1]:8443/login"


def test_normalize_drops_only_scheme_default_port():
    https_default = normalize_url("https://example.com:443/path")
    https_non_default = normalize_url("https://example.com:80/path")

    assert https_default.normalized_url == "https://example.com/path"
    assert https_non_default.normalized_url == "https://example.com:80/path"
