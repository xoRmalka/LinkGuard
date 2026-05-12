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


def _decode_options() -> dict[str, bool]:
    """Clerk session tokens can fail locally if `nbf` is slightly ahead (clock skew)."""
    return {
        "verify_signature": True,
        "verify_aud": False,
        "verify_nbf": False,
        "verify_exp": True,
    }


def verify_clerk_jwt(token: str) -> tuple[dict[str, Any] | None, str | None]:
    """
    Verify a Clerk session JWT via CLERK_JWT_KEY (PEM) or JWKS at {issuer}/.well-known/jwks.json.

    Returns (payload, None) on success, or (None, reason).
    """
    issuer = (current_app.config.get("CLERK_ISSUER") or "").strip().rstrip("/")
    if not issuer:
        return None, "missing_issuer"

    try:
        unverified = jwt.decode(
            token,
            options={
                "verify_signature": False,
                "verify_aud": False,
                "verify_exp": False,
                "verify_nbf": False,
            },
        )
    except (jwt.InvalidTokenError, jwt.PyJWTError, ValueError):
        return None, "malformed_token"

    token_iss = str(unverified.get("iss") or "").strip().rstrip("/")
    if token_iss and token_iss != issuer:
        current_app.logger.warning(
            "Clerk JWT iss mismatch: token iss=%r CLERK_ISSUER=%r",
            token_iss,
            issuer,
        )
        return None, "issuer_mismatch_token"

    try:
        header = jwt.get_unverified_header(token)
    except (jwt.InvalidTokenError, jwt.PyJWTError, ValueError):
        return None, "malformed_token"

    alg = header.get("alg") or "RS256"
    if alg not in ("RS256", "ES256"):
        current_app.logger.warning("Clerk JWT unexpected alg: %s", alg)
        return None, "unsupported_alg"

    pem = (current_app.config.get("CLERK_JWT_KEY") or "").strip()
    decode_kw: dict[str, Any] = {
        "algorithms": [alg],
        "issuer": issuer,
        "options": _decode_options(),
        "leeway": 120,
    }

    try:
        if pem:
            payload = jwt.decode(token, pem, **decode_kw)
            return payload, None

        jwks_url = f"{issuer}/.well-known/jwks.json"
        jwk_client = PyJWKClient(jwks_url, cache_keys=True)
        signing_key = jwk_client.get_signing_key_from_jwt(token)
        payload = jwt.decode(token, signing_key.key, **decode_kw)
        return payload, None
    except jwt.ExpiredSignatureError:
        return None, "expired"
    except jwt.InvalidIssuerError:
        return None, "invalid_issuer"
    except jwt.ImmatureSignatureError:
        return None, "immature_token"
    except jwt.InvalidSignatureError:
        return None, "invalid_signature"
    except (jwt.InvalidTokenError, jwt.PyJWTError) as e:
        current_app.logger.warning("Clerk JWT rejected: %s: %s", type(e).__name__, e)
        return None, "invalid_token"
    except Exception:
        current_app.logger.exception("Clerk JWT verification failed (issuer JWKS: %s)", issuer)
        return None, "jwks_error"


def clerk_verify_error_message(reason: str | None) -> str:
    if reason == "missing_issuer":
        return (
            "Server is missing CLERK_ISSUER. Set it in server/.env to your Clerk "
            "Frontend API URL — the same value as the iss claim on the session JWT "
            "(e.g. https://YOUR-INSTANCE.clerk.accounts.dev). See Clerk → "
            "API keys or decode a token at jwt.io to copy iss exactly."
        )
    if reason == "expired":
        return "Session token expired. Sign out and sign in again."
    if reason == "invalid_issuer":
        return (
            "CLERK_ISSUER does not match this token's issuer (iss). "
            "Update CLERK_ISSUER in server/.env to match the iss claim from your Clerk session JWT."
        )
    if reason == "issuer_mismatch_token":
        return (
            "The session token's issuer (iss) does not match CLERK_ISSUER in server/.env. "
            "Use the same Clerk application: copy iss from jwt.io into CLERK_ISSUER, "
            "or ensure VITE_CLERK_PUBLISHABLE_KEY and CLERK_ISSUER are from one instance."
        )
    if reason == "malformed_token":
        return "Authorization token is not a valid JWT. Ensure the client sends Clerk getToken() output."
    if reason == "unsupported_alg":
        return "Session token uses an unexpected signing algorithm. Open an issue with the JWT header alg value."
    if reason == "immature_token":
        return (
            "Session token is not yet valid (nbf). Check your computer's clock, or set "
            "CLERK_JWT_KEY in server/.env to the JWKS Public Key (PEM) from the Clerk dashboard."
        )
    if reason == "invalid_signature":
        return (
            "JWT signature did not verify. Set CLERK_JWT_KEY in server/.env to the "
            "'JWKS Public Key' (PEM) from Clerk → API keys (same instance as CLERK_ISSUER), "
            "or confirm CLERK_ISSUER matches the token iss exactly."
        )
    if reason in ("invalid_token", "jwks_error", "verify_failed"):
        return (
            "Could not verify the session token. Set CLERK_JWT_KEY (PEM from Clerk dashboard), "
            "confirm CLERK_ISSUER equals Frontend API URL, and ensure the client sends getToken() output."
        )
    return "Invalid or expired authentication token."


def require_auth(fn: Callable) -> Callable:
    @wraps(fn)
    def wrapper(*args, **kwargs):
        token = get_bearer_token()
        if not token:
            return jsonify({"error": "unauthorized", "message": "Authentication required."}), 401
        payload, err = verify_clerk_jwt(token)
        if not payload:
            return (
                jsonify(
                    {
                        "error": "unauthorized",
                        "message": clerk_verify_error_message(err),
                        "verify_reason": err,
                    }
                ),
                401,
            )
        request.clerk_user = payload  # type: ignore[attr-defined]
        return fn(*args, **kwargs)

    return wrapper


def require_admin(fn: Callable) -> Callable:
    @wraps(fn)
    def wrapper(*args, **kwargs):
        token = get_bearer_token()
        if not token:
            return jsonify({"error": "unauthorized", "message": "Authentication required."}), 401
        payload, err = verify_clerk_jwt(token)
        if not payload:
            return (
                jsonify(
                    {
                        "error": "unauthorized",
                        "message": clerk_verify_error_message(err),
                        "verify_reason": err,
                    }
                ),
                401,
            )
        request.clerk_user = payload  # type: ignore[attr-defined]
        from app.models.tables import User

        uid = payload.get("sub")
        user = User.query.filter_by(id=uid, deleted_at=None).first()
        if not user or user.role != "admin":
            return jsonify({"error": "forbidden", "message": "Admin role required."}), 403
        return fn(*args, **kwargs)

    return wrapper
