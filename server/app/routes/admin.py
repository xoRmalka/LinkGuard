from __future__ import annotations

from flask import Blueprint, jsonify, request

from app.auth.clerk_jwt import require_admin
from app.extensions import db
from app.models.tables import User

bp = Blueprint("admin", __name__)


@bp.get("/admin/users")
@require_admin
def list_users():
    users = User.query.filter_by(deleted_at=None).order_by(User.created_at.desc()).all()
    return jsonify({"items": [u.to_public_dict() for u in users]})


@bp.post("/admin/invites")
@require_admin
def invite_user():
    """
    MVP: record intent only. Production should call Clerk Invitations API with a server secret.
    """
    body = request.get_json(silent=True) or {}
    email = (body.get("email") or "").strip()
    role = (body.get("role") or "user").strip()
    if not email:
        return jsonify({"error": "validation", "message": "email is required"}), 400
    if role not in ("user", "contributor", "admin"):
        return jsonify({"error": "validation", "message": "invalid role"}), 400
    return (
        jsonify(
            {
                "ok": True,
                "note": "Wire this to Clerk Invitations (Backend API) in production.",
                "email": email,
                "role": role,
            }
        ),
        202,
    )


@bp.delete("/admin/users/<user_id>")
@require_admin
def deactivate_user(user_id: str):
    user = User.query.filter_by(id=user_id).first()
    if not user:
        return jsonify({"error": "not_found"}), 404
    from datetime import datetime, timezone

    user.deleted_at = datetime.now(timezone.utc)
    db.session.commit()
    return jsonify({"ok": True})
