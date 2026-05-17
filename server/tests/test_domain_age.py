"""Tests for domain age signal."""

import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

from app.services.signals.domain_age import (
    _extract_registration_date,
    _parse_rdap_date,
    _query_rdap,
    domain_age_signal,
)


class TestDomainAgeSignal(unittest.TestCase):
    """Test domain age detection and scoring."""

    def test_parse_rdap_date_with_z_suffix(self):
        """Test parsing ISO 8601 date with Z suffix."""
        date_str = "2024-01-15T12:34:56Z"
        result = _parse_rdap_date(date_str)
        self.assertIsNotNone(result)
        self.assertEqual(result.year, 2024)
        self.assertEqual(result.month, 1)
        self.assertEqual(result.day, 15)

    def test_parse_rdap_date_invalid(self):
        """Test parsing invalid date returns None."""
        result = _parse_rdap_date("not-a-date")
        self.assertIsNone(result)

        result = _parse_rdap_date(None)
        self.assertIsNone(result)

    def test_extract_registration_date_from_events(self):
        """Test extracting registration date from RDAP events."""
        rdap_data = {
            "events": [
                {"eventAction": "registration", "eventDate": "2024-01-15T12:34:56Z"},
                {"eventAction": "last changed", "eventDate": "2024-03-20T10:00:00Z"},
            ]
        }
        result = _extract_registration_date(rdap_data)
        self.assertIsNotNone(result)
        self.assertEqual(result.year, 2024)
        self.assertEqual(result.month, 1)

    def test_extract_registration_date_fallback_to_created(self):
        """Test fallback to 'created' event if 'registration' not found."""
        rdap_data = {
            "events": [
                {"eventAction": "created", "eventDate": "2023-05-10T08:00:00Z"},
                {"eventAction": "last changed", "eventDate": "2024-03-20T10:00:00Z"},
            ]
        }
        result = _extract_registration_date(rdap_data)
        self.assertIsNotNone(result)
        self.assertEqual(result.year, 2023)
        self.assertEqual(result.month, 5)

    def test_extract_registration_date_no_events(self):
        """Test returns None when no events found."""
        rdap_data = {"events": []}
        result = _extract_registration_date(rdap_data)
        self.assertIsNone(result)

        rdap_data = {}
        result = _extract_registration_date(rdap_data)
        self.assertIsNone(result)

    @patch("app.services.signals.domain_age._query_rdap")
    def test_domain_age_signal_very_new_domain(self, mock_query):
        """Test domain < 30 days old triggers high concern."""
        # Mock RDAP response for domain registered 10 days ago
        reg_date = datetime.now(timezone.utc) - timedelta(days=10)
        mock_query.return_value = {
            "events": [{"eventAction": "registration", "eventDate": reg_date.isoformat()}]
        }

        result = domain_age_signal("newphishing.com")

        self.assertEqual(result["id"], "domain_age")
        self.assertEqual(result["status"], "ok")
        self.assertTrue(result["concern"])
        self.assertEqual(result["age_days"], 10)
        self.assertIn("10 days ago", result["summary"])
        self.assertIn("phishing", result["summary"])

    @patch("app.services.signals.domain_age._query_rdap")
    def test_domain_age_signal_moderately_new_domain(self, mock_query):
        """Test domain 30-180 days old has moderate concern (no flag)."""
        # Mock RDAP response for domain registered 90 days ago
        reg_date = datetime.now(timezone.utc) - timedelta(days=90)
        mock_query.return_value = {
            "events": [{"eventAction": "registration", "eventDate": reg_date.isoformat()}]
        }

        result = domain_age_signal("medium-age.com")

        self.assertEqual(result["id"], "domain_age")
        self.assertEqual(result["status"], "ok")
        self.assertFalse(result["concern"])
        self.assertEqual(result["age_days"], 90)
        self.assertIn("90 days ago", result["summary"])
        self.assertIn("moderately new", result["summary"])

    @patch("app.services.signals.domain_age._query_rdap")
    def test_domain_age_signal_established_domain(self, mock_query):
        """Test domain > 180 days old is considered established."""
        # Mock RDAP response for domain registered 5 years ago
        reg_date = datetime.now(timezone.utc) - timedelta(days=365 * 5)
        mock_query.return_value = {
            "events": [{"eventAction": "registration", "eventDate": reg_date.isoformat()}]
        }

        result = domain_age_signal("google.com")

        self.assertEqual(result["id"], "domain_age")
        self.assertEqual(result["status"], "ok")
        self.assertFalse(result["concern"])
        self.assertGreater(result["age_days"], 365)
        self.assertIn("years ago", result["summary"])
        self.assertIn("established", result["summary"])

    @patch("app.services.signals.domain_age._query_rdap")
    def test_domain_age_signal_rdap_failed(self, mock_query):
        """Test RDAP lookup failure returns unknown status."""
        mock_query.return_value = None

        result = domain_age_signal("unknown.com")

        self.assertEqual(result["id"], "domain_age")
        self.assertEqual(result["status"], "unknown")
        self.assertFalse(result["concern"])
        self.assertIn("Could not retrieve", result["summary"])

    @patch("app.services.signals.domain_age._query_rdap")
    def test_domain_age_signal_no_registration_date(self, mock_query):
        """Test RDAP data without registration date returns unknown."""
        mock_query.return_value = {"events": [{"eventAction": "other", "eventDate": "2024-01-01T00:00:00Z"}]}

        result = domain_age_signal("nodate.com")

        self.assertEqual(result["id"], "domain_age")
        self.assertEqual(result["status"], "unknown")
        self.assertFalse(result["concern"])
        self.assertIn("Registration date not found", result["summary"])

    def test_domain_age_signal_empty_host(self):
        """Test empty hostname returns error."""
        result = domain_age_signal("")

        self.assertEqual(result["id"], "domain_age")
        self.assertEqual(result["status"], "error")
        self.assertFalse(result["concern"])
        self.assertIn("No hostname", result["summary"])

    @patch("app.services.signals.domain_age._query_rdap")
    def test_domain_age_signal_strips_www(self, mock_query):
        """Test www. prefix is stripped for RDAP lookup."""
        reg_date = datetime.now(timezone.utc) - timedelta(days=500)
        mock_query.return_value = {
            "events": [{"eventAction": "registration", "eventDate": reg_date.isoformat()}]
        }

        result = domain_age_signal("www.example.com")

        # Verify mock was called with domain without www.
        mock_query.assert_called_once_with("example.com")
        self.assertEqual(result["status"], "ok")

    @patch("app.services.signals.domain_age._query_rdap")
    def test_domain_age_signal_strips_port(self, mock_query):
        """Test port number is stripped from hostname."""
        reg_date = datetime.now(timezone.utc) - timedelta(days=500)
        mock_query.return_value = {
            "events": [{"eventAction": "registration", "eventDate": reg_date.isoformat()}]
        }

        result = domain_age_signal("example.com:8080")

        # Verify mock was called with domain without port
        mock_query.assert_called_once_with("example.com")
        self.assertEqual(result["status"], "ok")

    @patch("app.services.signals.domain_age._query_rdap")
    def test_domain_age_signal_future_date_error(self, mock_query):
        """Test future registration date returns error."""
        # Mock RDAP response with future date
        reg_date = datetime.now(timezone.utc) + timedelta(days=30)
        mock_query.return_value = {
            "events": [{"eventAction": "registration", "eventDate": reg_date.isoformat()}]
        }

        result = domain_age_signal("future.com")

        self.assertEqual(result["id"], "domain_age")
        self.assertEqual(result["status"], "error")
        self.assertFalse(result["concern"])
        self.assertIn("future", result["summary"].lower())


if __name__ == "__main__":
    unittest.main()
