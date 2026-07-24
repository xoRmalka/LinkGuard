"""Tests for IP host signal including obfuscated IP detection."""

import pytest
from app.services.signals.ip_host import (
    ip_host_signal,
    _decode_obfuscated_ip,
    _is_private_or_reserved,
)


class TestDecodeObfuscatedIP:
    """Test obfuscated IP decoding."""

    def test_decimal_ip(self):
        """Test decimal encoding: 2130706433 -> 127.0.0.1"""
        result = _decode_obfuscated_ip("2130706433")
        assert result == "127.0.0.1"

    def test_decimal_ip_google(self):
        """Test decimal encoding for a real IP: 3232235777 -> 192.168.1.1"""
        result = _decode_obfuscated_ip("3232235777")
        assert result == "192.168.1.1"

    def test_octal_ip(self):
        """Test octal encoding: 0177.0.0.01 -> 127.0.0.1"""
        result = _decode_obfuscated_ip("0177.0.0.01")
        assert result == "127.0.0.1"

    def test_hex_ip(self):
        """Test hex encoding: 0x7f.0x0.0x0.0x1 -> 127.0.0.1"""
        result = _decode_obfuscated_ip("0x7f.0x0.0x0.0x1")
        assert result == "127.0.0.1"

    def test_mixed_encoding(self):
        """Test mixed octal/decimal: 0177.0.0.1 -> 127.0.0.1"""
        result = _decode_obfuscated_ip("0177.0.0.1")
        assert result == "127.0.0.1"

    def test_normal_domain_returns_none(self):
        """Normal domains should return None."""
        assert _decode_obfuscated_ip("google.com") is None
        assert _decode_obfuscated_ip("example.org") is None

    def test_standard_ip_returns_none(self):
        """Standard dotted decimal IPs should return None (not obfuscated)."""
        # Standard IPs are detected by the normal is_ip_host check
        assert _decode_obfuscated_ip("192.168.1.1") is None

    def test_invalid_decimal_returns_none(self):
        """Invalid decimal values should return None."""
        assert _decode_obfuscated_ip("999999999999999") is None
        assert _decode_obfuscated_ip("-1") is None

    def test_empty_returns_none(self):
        """Empty input should return None."""
        assert _decode_obfuscated_ip("") is None
        assert _decode_obfuscated_ip(None) is None


class TestPrivateOrReserved:
    """Test private/reserved IP detection."""

    def test_localhost_ipv4(self):
        """127.x.x.x should be detected as private."""
        assert _is_private_or_reserved("127.0.0.1") is True
        assert _is_private_or_reserved("127.255.255.255") is True

    def test_localhost_ipv6(self):
        """::1 should be detected as private."""
        assert _is_private_or_reserved("::1") is True

    def test_private_class_a(self):
        """10.x.x.x should be detected as private."""
        assert _is_private_or_reserved("10.0.0.1") is True
        assert _is_private_or_reserved("10.255.255.255") is True

    def test_private_class_b(self):
        """172.16-31.x.x should be detected as private."""
        assert _is_private_or_reserved("172.16.0.1") is True
        assert _is_private_or_reserved("172.31.255.255") is True
        # 172.32.x.x is NOT private
        assert _is_private_or_reserved("172.32.0.1") is False

    def test_private_class_c(self):
        """192.168.x.x should be detected as private."""
        assert _is_private_or_reserved("192.168.0.1") is True
        assert _is_private_or_reserved("192.168.255.255") is True

    def test_public_ip(self):
        """Public IPs should NOT be detected as private."""
        assert _is_private_or_reserved("8.8.8.8") is False
        assert _is_private_or_reserved("1.1.1.1") is False
        assert _is_private_or_reserved("142.250.185.46") is False  # google.com

    def test_link_local(self):
        """Link-local addresses should be detected."""
        assert _is_private_or_reserved("169.254.0.1") is True
        assert _is_private_or_reserved("169.254.255.255") is True


class TestIPHostSignal:
    """Test the full ip_host_signal function."""

    def test_domain_name_no_concern(self):
        """Domain names should not trigger concern."""
        result = ip_host_signal(False, "google.com")
        assert result["concern"] is False
        assert result["status"] == "ok"

    def test_public_ip_moderate_concern(self):
        """Public IPs should trigger moderate concern."""
        result = ip_host_signal(True, "142.250.185.46")
        assert result["concern"] is True
        assert result["severity"] == "moderate"

    def test_private_ip_high_concern(self):
        """Private IPs should trigger high concern."""
        result = ip_host_signal(True, "192.168.1.1")
        assert result["concern"] is True
        assert result["severity"] == "high"
        assert "private" in result["summary"].lower() or "localhost" in result["summary"].lower()

    def test_localhost_high_concern(self):
        """Localhost should trigger high concern."""
        result = ip_host_signal(True, "127.0.0.1")
        assert result["concern"] is True
        assert result["severity"] == "high"

    def test_obfuscated_decimal_ip_detected(self):
        """Obfuscated decimal IP should be detected even when is_ip_host=False."""
        result = ip_host_signal(False, "2130706433")
        assert result["concern"] is True
        assert result["severity"] == "high"
        assert "obfuscated" in result["summary"].lower()
        assert result["decoded_ip"] == "127.0.0.1"

    def test_obfuscated_hex_ip_detected(self):
        """Obfuscated hex IP should be detected."""
        result = ip_host_signal(False, "0x7f.0x0.0x0.0x1")
        assert result["concern"] is True
        assert result["severity"] == "high"
        assert "obfuscated" in result["summary"].lower()

    def test_obfuscated_octal_ip_detected(self):
        """Obfuscated octal IP should be detected."""
        result = ip_host_signal(False, "0177.0.0.01")
        assert result["concern"] is True
        assert result["severity"] == "high"
