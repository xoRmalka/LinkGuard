from __future__ import annotations

import logging
import time
from typing import Any

from app.integrations.clerk_backend import ClerkBackendError, clerk_get_user, clerk_merge_public_metadata

logger = logging.getLogger(__name__)

ROLE_KEY = "role"
_CACHE: dict[str, tuple[str, float]] = {}
_CACHE_TTL_SEC = 60.0


def _cache_get(user_id: str) -> str | None:
    hit = _CACHE.get(user_id)
    if not hit:
        return None
    role, exp = hit
    if time.monotonic() > exp:
        del _CACHE[user_id]
        return None
    return role


def _cache_set(user_id: str, role: str) -> None:
    _CACHE[user_id] = (role, time.monotonic() + _CACHE_TTL_SEC)


def _cache_invalidate(user_id: str) -> None:
    _CACHE.pop(user_id, None)


def _raw_from_public_metadata(obj: Any) -> Any:
    if isinstance(obj, dict):
        return obj.get(ROLE_KEY)
    return None


def _role_from_jwt_payload(payload: dict[str, Any]) -> str | None:
    pm = payload.get("public_metadata")
    raw = _raw_from_public_metadata(pm)
    if raw is None:
        raw = payload.get(ROLE_KEY)
    return str(raw).strip().lower() if raw is not None and str(raw).strip() else None


def normalize_clerk_role(raw: str | None) -> str | None:
    """MVP: `admin` | `user`; `contributor` maps to `user`. Unknown → `user` for safety."""
    if not raw:
        return None
    v = str(raw).strip().lower()
    if v == "admin":
        return "admin"
    if v in ("user", "contributor", "member"):
        return "user"
    return "user"


def ensure_lazy_default_and_resolve(user_id: str, jwt_payload: dict[str, Any]) -> str:
    """
    Hybrid: JWT `public_metadata.role` first; if missing, GET Clerk user (cached).
    If still missing, PATCH default `role: user` in Clerk (requires CLERK_SECRET_KEY).
    """
    from flask import current_app

    jwt_role = normalize_clerk_role(_role_from_jwt_payload(jwt_payload))
    if jwt_role == "admin":
        _cache_set(user_id, "admin")
        return "admin"
    if jwt_role == "user":
        _cache_set(user_id, "user")
        return "user"

    cached = _cache_get(user_id)
    if cached in ("user", "admin"):
        return cached

    secret = (current_app.config.get("CLERK_SECRET_KEY") or "").strip()
    if not secret:
        if jwt_role is None:
            logger.debug("No CLERK_SECRET_KEY; defaulting role to user for sub=%s", user_id[:16])
        return "user"

    try:
        remote = clerk_get_user(user_id)
    except ClerkBackendError as e:
        logger.warning("Clerk get user failed for lazy role: %s", e)
        return "user"

    pub = remote.get("public_metadata") if isinstance(remote.get("public_metadata"), dict) else {}
    r_raw = pub.get(ROLE_KEY) if isinstance(pub, dict) else None
    resolved = normalize_clerk_role(str(r_raw) if r_raw is not None else None)
    if resolved in ("user", "admin"):
        _cache_set(user_id, resolved)
        return resolved

    try:
        clerk_merge_public_metadata(user_id, {ROLE_KEY: "user"})
        _cache_invalidate(user_id)
        _cache_set(user_id, "user")
        logger.info("Clerk public_metadata: set default role=user for user_id=%s", user_id)
    except ClerkBackendError as e:
        logger.warning("Clerk merge default role failed: %s", e)
        return "user"
    return "user"


def invalidate_clerk_role_cache(user_id: str) -> None:
    _cache_invalidate(user_id)
