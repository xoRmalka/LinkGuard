from __future__ import annotations

import logging
from typing import Any

import requests
from flask import current_app

logger = logging.getLogger(__name__)

CLERK_API_V1 = "https://api.clerk.com/v1"


class ClerkBackendError(Exception):
    def __init__(self, message: str, status_code: int | None = None, body: Any = None):
        super().__init__(message)
        self.status_code = status_code
        self.body = body


def _secret() -> str:
    return (current_app.config.get("CLERK_SECRET_KEY") or "").strip()


def _headers() -> dict[str, str]:
    return {
        "Authorization": f"Bearer {_secret()}",
        "Content-Type": "application/json",
    }


def clerk_get_user(user_id: str) -> dict[str, Any]:
    if not _secret():
        raise ClerkBackendError("CLERK_SECRET_KEY is not configured", status_code=503)
    url = f"{CLERK_API_V1}/users/{user_id}"
    r = requests.get(url, headers=_headers(), timeout=20)
    if r.status_code == 404:
        raise ClerkBackendError("User not found in Clerk", status_code=404, body=r.text)
    if not r.ok:
        logger.warning("Clerk GET user failed: %s %s", r.status_code, r.text[:500])
        raise ClerkBackendError("Clerk API error", status_code=r.status_code, body=r.text)
    return r.json()


def clerk_patch_user(user_id: str, body: dict[str, Any]) -> dict[str, Any]:
    if not _secret():
        raise ClerkBackendError("CLERK_SECRET_KEY is not configured", status_code=503)
    url = f"{CLERK_API_V1}/users/{user_id}"
    r = requests.patch(url, headers=_headers(), json=body, timeout=20)
    if not r.ok:
        logger.warning("Clerk PATCH user failed: %s %s", r.status_code, r.text[:500])
        raise ClerkBackendError("Clerk API error", status_code=r.status_code, body=r.text)
    return r.json()


def clerk_merge_public_metadata(user_id: str, merge: dict[str, Any]) -> dict[str, Any]:
    current = clerk_get_user(user_id)
    pub = current.get("public_metadata") if isinstance(current.get("public_metadata"), dict) else {}
    merged = {**pub, **merge}
    return clerk_patch_user(user_id, {"public_metadata": merged})


def clerk_list_users(*, limit: int = 50, offset: int = 0) -> dict[str, Any]:
    """
    GET /v1/users — Clerk returns either a JSON array or `{ "data": [...], "totalCount"?: n }`.
    Normalize to {"data": [...], "total_count": int | None} for callers.
    """
    if not _secret():
        raise ClerkBackendError("CLERK_SECRET_KEY is not configured", status_code=503)
    r = requests.get(
        f"{CLERK_API_V1}/users",
        headers=_headers(),
        params={"limit": min(max(limit, 1), 100), "offset": max(offset, 0)},
        timeout=30,
    )
    if not r.ok:
        logger.warning("Clerk list users failed: %s %s", r.status_code, r.text[:500])
        raise ClerkBackendError("Clerk API error", status_code=r.status_code, body=r.text)
    raw: Any = r.json()
    if isinstance(raw, list):
        return {"data": raw, "total_count": None}
    if isinstance(raw, dict):
        data = raw.get("data")
        if isinstance(data, list):
            total = raw.get("total_count")
            if total is None:
                total = raw.get("totalCount")
            return {"data": data, "total_count": total}
        logger.warning("Clerk list users: expected `data` array, keys=%s", list(raw.keys())[:12])
        total = raw.get("total_count")
        if total is None:
            total = raw.get("totalCount")
        return {"data": [], "total_count": total}
    return {"data": [], "total_count": None}


def clerk_delete_user(user_id: str) -> None:
    if not _secret():
        raise ClerkBackendError("CLERK_SECRET_KEY is not configured", status_code=503)
    r = requests.delete(f"{CLERK_API_V1}/users/{user_id}", headers=_headers(), timeout=30)
    if r.status_code == 404:
        return
    if not r.ok:
        logger.warning("Clerk DELETE user failed: %s %s", r.status_code, r.text[:500])
        raise ClerkBackendError("Clerk API error", status_code=r.status_code, body=r.text)


def clerk_create_invitation(
    email: str,
    *,
    redirect_url: str | None = None,
    public_metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if not _secret():
        raise ClerkBackendError("CLERK_SECRET_KEY is not configured", status_code=503)
    body: dict[str, Any] = {
        "email_address": email.strip(),
        "ignore_existing": True,
        "notify": True,
    }
    if redirect_url:
        body["redirect_url"] = redirect_url
    if public_metadata is not None:
        body["public_metadata"] = public_metadata
    r = requests.post(f"{CLERK_API_V1}/invitations", headers=_headers(), json=body, timeout=30)
    if not r.ok:
        logger.warning("Clerk create invitation failed: %s %s", r.status_code, r.text[:500])
        raise ClerkBackendError("Clerk API error", status_code=r.status_code, body=r.text)
    return r.json()
