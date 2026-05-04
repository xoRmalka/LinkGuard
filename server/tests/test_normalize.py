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
