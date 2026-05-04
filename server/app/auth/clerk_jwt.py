from __future__ import annotations

from functools import wraps
from typing import Any, Callable

import jwt
from flask import current_app, jsonify, request
from jwt import PyJWKClient


def get_bearer_token() -> str | None:
    auth = request.headers.get("Authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip() or None
    return None


def verify_clerk_jwt(token: str) -> dict[str, Any] | None:
    issuer = (current_app.config.get("CLERK_ISSUER") or "").rstrip("/")
    if not issuer:
        return None
    jwks_url = f"{issuer}/.well-known/jwks.json"
    try:
        jwk_client = PyJWKClient(jwks_url, cache_keys=True)
        signing_key = jwk_client.get_signing_key_from_jwt(token)
        payload = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            issuer=issuer,
            options={"verify_aud": False},
        )
        return payload
    except Exception:
        return None


def require_auth(fn: Callable) -> Callable:
    @wraps(fn)
    def wrapper(*args, **kwargs):
        token = get_bearer_token()
        if not token:
            return jsonify({"error": "unauthorized", "message": "Authentication required."}), 401
        payload = verify_clerk_jwt(token)
        if not payload:
            return jsonify({"error": "unauthorized", "message": "Invalid or expired session."}), 401
        request.clerk_user = payload  # type: ignore[attr-defined]
        return fn(*args, **kwargs)

    return wrapper


def require_admin(fn: Callable) -> Callable:
    @wraps(fn)
    def wrapper(*args, **kwargs):
        token = get_bearer_token()
        if not token:
            return jsonify({"error": "unauthorized", "message": "Authentication required."}), 401
        payload = verify_clerk_jwt(token)
        if not payload:
            return jsonify({"error": "unauthorized", "message": "Invalid or expired session."}), 401
        request.clerk_user = payload  # type: ignore[attr-defined]
        from app.models.tables import User

        uid = payload.get("sub")
        user = User.query.filter_by(id=uid, deleted_at=None).first()
        if not user or user.role != "admin":
            return jsonify({"error": "forbidden", "message": "Admin role required."}), 403
        return fn(*args, **kwargs)

    return wrapper
