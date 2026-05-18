from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

import requests

logger = logging.getLogger(__name__)

# RDAP Bootstrap Service - provides RDAP servers for each TLD
RDAP_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"

# Fallback RDAP servers for common TLDs
RDAP_SERVERS = {
    "com": "https://rdap.verisign.com/com/v1/",
    "net": "https://rdap.verisign.com/net/v1/",
    "org": "https://rdap.publicinterestregistry.org/rdap/",
    "io": "https://rdap.nic.io/",
    "dev": "https://rdap.nic.google/",
    "app": "https://rdap.nic.google/",
}


def _get_rdap_server(domain: str) -> str | None:
    """Get the appropriate RDAP server for a domain's TLD."""
    parts = domain.lower().split(".")
    if len(parts) < 2:
        return None

    tld = parts[-1]
    return RDAP_SERVERS.get(tld)


def _parse_rdap_date(date_str: str | None) -> datetime | None:
    """Parse ISO 8601 date from RDAP response."""
    if not date_str:
        return None

    try:
        # RDAP dates are ISO 8601: "2024-01-15T12:34:56Z"
        if date_str.endswith("Z"):
            date_str = date_str[:-1] + "+00:00"
        return datetime.fromisoformat(date_str)
    except (ValueError, AttributeError):
        return None


def _query_rdap(domain: str, timeout: float = 5.0) -> dict[str, Any] | None:
    """Query RDAP for domain registration data."""
    rdap_server = _get_rdap_server(domain)
    if not rdap_server:
        logger.debug(f"No RDAP server found for domain: {domain}")
        return None

    url = f"{rdap_server}domain/{domain}"

    try:
        response = requests.get(url, timeout=timeout)
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 404:
            logger.debug(f"Domain not found in RDAP: {domain}")
            return None
        else:
            logger.warning(f"RDAP query failed with status {response.status_code}: {domain}")
            return None
    except requests.RequestException as e:
        logger.debug(f"RDAP request failed for {domain}: {e.__class__.__name__}")
        return None


def _extract_registration_date(rdap_data: dict) -> datetime | None:
    """Extract registration date from RDAP response."""
    # RDAP standard events
    events = rdap_data.get("events", [])
    for event in events:
        if not isinstance(event, dict):
            continue

        # Look for "registration" event
        if event.get("eventAction") == "registration":
            date_str = event.get("eventDate")
            parsed = _parse_rdap_date(date_str)
            if parsed:
                return parsed

    # Fallback: try "created" in some RDAP implementations
    for event in events:
        if not isinstance(event, dict):
            continue
        if event.get("eventAction") in ("created", "creation"):
            date_str = event.get("eventDate")
            parsed = _parse_rdap_date(date_str)
            if parsed:
                return parsed

    return None


def domain_age_signal(host: str) -> dict:
    """
    Check domain registration age via RDAP.

    Thresholds:
    - < 30 days: HIGH CONCERN (most phishing domains)
    - 30-180 days: MODERATE CONCERN (young domain)
    - > 180 days: LOW CONCERN (established)
    """
    if not host:
        return {
            "id": "domain_age",
            "status": "error",
            "concern": False,
            "summary": "No hostname provided.",
        }

    # Strip port if present
    domain = host.split(":")[0].lower()

    # Remove "www." prefix for RDAP lookup
    if domain.startswith("www."):
        domain = domain[4:]

    # Query RDAP
    rdap_data = _query_rdap(domain)

    if not rdap_data:
        return {
            "id": "domain_age",
            "status": "unknown",
            "concern": False,
            "summary": f"Could not retrieve registration data for {domain} (RDAP lookup failed or domain not found).",
        }

    # Extract registration date
    reg_date = _extract_registration_date(rdap_data)

    if not reg_date:
        return {
            "id": "domain_age",
            "status": "unknown",
            "concern": False,
            "summary": f"Registration date not found in RDAP data for {domain}.",
        }

    # Calculate age
    now = datetime.now(timezone.utc)
    age_delta = now - reg_date.replace(tzinfo=timezone.utc)
    age_days = age_delta.days

    # Determine concern level
    if age_days < 0:
        # Future date (clock skew or data error)
        return {
            "id": "domain_age",
            "status": "error",
            "concern": False,
            "summary": f"Domain registration date appears to be in the future ({reg_date.date()}).",
        }

    if age_days < 30:
        return {
            "id": "domain_age",
            "status": "ok",
            "concern": True,
            "age_days": age_days,
            "registered_date": reg_date.date().isoformat(),
            "summary": f"Domain registered {age_days} day{'s' if age_days != 1 else ''} ago — very new domains are often used in phishing attacks.",
        }

    if age_days < 180:
        return {
            "id": "domain_age",
            "status": "ok",
            "concern": False,
            "age_days": age_days,
            "registered_date": reg_date.date().isoformat(),
            "summary": f"Domain registered {age_days} days ago (moderately new, but past the highest-risk period).",
        }

    # Established domain
    if age_days < 365:
        years = 0
        days = age_days
    else:
        years = age_days // 365
        days = age_days

    summary = f"Domain registered {years} year{'s' if years != 1 else ''} ago" if years > 0 else f"Domain registered {days} days ago"
    summary += " (established domain)."

    return {
        "id": "domain_age",
        "status": "ok",
        "concern": False,
        "age_days": age_days,
        "registered_date": reg_date.date().isoformat(),
        "summary": summary,
    }
