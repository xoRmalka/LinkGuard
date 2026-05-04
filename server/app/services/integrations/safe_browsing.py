from typing import Any

import requests

SB_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"


def check_safe_browsing(url: str, api_key: str | None) -> dict[str, Any]:
    if not api_key:
        return {
            "id": "safe_browsing",
            "status": "skipped",
            "concern": False,
            "summary": "Google Safe Browsing was not configured (missing API key).",
            "matches": [],
        }

    body = {
        "client": {"clientId": "linkguard", "clientVersion": "1.0.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    try:
        r = requests.post(
            SB_URL,
            params={"key": api_key},
            json=body,
            timeout=10,
        )
        if r.status_code != 200:
            return {
                "id": "safe_browsing",
                "status": "error",
                "concern": False,
                "summary": f"Safe Browsing API error (HTTP {r.status_code}).",
                "matches": [],
            }
        data = r.json()
        matches = data.get("matches") or []
        if matches:
            return {
                "id": "safe_browsing",
                "status": "ok",
                "concern": True,
                "summary": "Google Safe Browsing reported a known threat match for this URL.",
                "matches": matches,
            }
        return {
            "id": "safe_browsing",
            "status": "ok",
            "concern": False,
            "summary": "Google Safe Browsing did not return a threat match for this URL.",
            "matches": [],
        }
    except requests.RequestException as e:
        return {
            "id": "safe_browsing",
            "status": "error",
            "concern": False,
            "summary": f"Safe Browsing request failed: {e.__class__.__name__}",
            "matches": [],
        }
