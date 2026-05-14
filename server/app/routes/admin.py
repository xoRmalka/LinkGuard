from __future__ import annotations

from flask import Blueprint, current_app, jsonify, request

from app.auth.clerk_jwt import require_admin
from app.auth.clerk_roles import invalidate_clerk_role_cache, normalize_clerk_role
from app.extensions import db
from app.integrations.clerk_backend import (
    ClerkBackendError,
    clerk_create_invitation,
    clerk_delete_user,
    clerk_list_users,
    clerk_merge_public_metadata,
)
from app.models.tables import User

bp = Blueprint("admin", __name__)


def _primary_email(u: dict) -> str:
    emails = u.get("email_addresses") or []
    primary_id = u.get("primary_email_address_id")
    for e in emails:
        if isinstance(e, dict) and e.get("id") == primary_id:
            return str(e.get("email_address") or "").strip()
    if emails and isinstance(emails[0], dict):
        return str(emails[0].get("email_address") or "").strip()
    return ""


def _created_iso(u: dict) -> str | None:
    v = u.get("created_at")
    if v is None:
        return None
    if isinstance(v, (int, float)):
        ts = float(v) / 1000.0 if float(v) > 1_000_000_000_000 else float(v)
        from datetime import datetime, timezone

        return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
    return str(v)


def _role_from_clerk_user(u: dict) -> str:
    pub = u.get("public_metadata") if isinstance(u.get("public_metadata"), dict) else {}
    raw = pub.get("role") if isinstance(pub, dict) else None
    r = normalize_clerk_role(str(raw) if raw is not None else None)
    return r if r in ("user", "admin") else "user"


@bp.get("/admin/users")
@require_admin
def list_users():
    limit = min(max(int(request.args.get("limit", 50)), 1), 100)
    offset = max(int(request.args.get("offset", 0)), 0)
    try:
        data = clerk_list_users(limit=limit, offset=offset)
    except ClerkBackendError as e:
        return (
            jsonify(
                {
                    "error": "clerk_error",
                    "message": str(e),
                    "status": e.status_code,
                }
            ),
            e.status_code or 502,
        )
    items_out = []
    for u in data.get("data") or []:
        if not isinstance(u, dict):
            continue
        uid = str(u.get("id") or "")
        if not uid:
            continue
        items_out.append(
            {
                "id": uid,
                "email": _primary_email(u) or "—",
                "role": _role_from_clerk_user(u),
                "created_at": _created_iso(u),
            }
        )
    total = data.get("total_count")
    if total is None:
        total = len(items_out)
    return jsonify({"items": items_out, "total": int(total), "limit": limit, "offset": offset})


@bp.patch("/admin/users/<user_id>")
@require_admin
def patch_user_role(user_id: str):
    body = request.get_json(silent=True) or {}
    raw = str(body.get("role") or "").strip().lower()
    if raw not in ("user", "admin"):
        return jsonify({"error": "validation", "message": "role must be user or admin"}), 400
    try:
        clerk_merge_public_metadata(user_id, {"role": raw})
    except ClerkBackendError as e:
        return (
            jsonify({"error": "clerk_error", "message": str(e), "status": e.status_code}),
            e.status_code or 502,
        )
    invalidate_clerk_role_cache(user_id)
    return jsonify({"ok": True, "id": user_id, "role": raw})


@bp.post("/admin/invites")
@require_admin
def invite_user():
    body = request.get_json(silent=True) or {}
    email = (body.get("email") or "").strip()
    raw_role = str(body.get("role") or "user").strip().lower()
    if not email:
        return jsonify({"error": "validation", "message": "email is required"}), 400
    if raw_role not in ("user", "admin"):
        return jsonify({"error": "validation", "message": "role must be user or admin"}), 400
    redirect_url = (body.get("redirect_url") or "").strip()
    if not redirect_url:
        origins = current_app.config.get("CORS_ORIGINS") or []
        redirect_url = origins[0] if origins else "http://localhost:5173"
    try:
        inv = clerk_create_invitation(
            email,
            redirect_url=redirect_url,
            public_metadata={"role": raw_role},
        )
    except ClerkBackendError as e:
        return (
            jsonify({"error": "clerk_error", "message": str(e), "status": e.status_code}),
            e.status_code or 502,
        )
    return jsonify({"ok": True, "id": inv.get("id"), "email": email, "role": raw_role}), 201


@bp.delete("/admin/users/<user_id>")
@require_admin
def deactivate_user(user_id: str):
    actor = str((getattr(request, "clerk_user", None) or {}).get("sub") or "")
    if actor and actor == user_id:
        return jsonify({"error": "validation", "message": "Cannot remove your own account."}), 400
    try:
        clerk_delete_user(user_id)
    except ClerkBackendError as e:
        return (
            jsonify({"error": "clerk_error", "message": str(e), "status": e.status_code}),
            e.status_code or 502,
        )
    user = User.query.filter_by(id=user_id).first()
    if user:
        from datetime import datetime, timezone

        user.deleted_at = datetime.now(timezone.utc)
        db.session.commit()
    return jsonify({"ok": True})
