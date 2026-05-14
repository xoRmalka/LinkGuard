from __future__ import annotations

from flask import Blueprint, current_app, jsonify, request

from app.auth.clerk_jwt import (
    clerk_verify_error_message,
    get_bearer_token,
    require_auth,
    verify_clerk_jwt,
)
from app.extensions import db
from app.models.tables import Favorite, Report, Scan, User
from app.services.guest_limit import check_and_consume_guest_scan
from app.services.pipeline import run_pipeline

bp = Blueprint("scans", __name__)


def _client_ip() -> str:
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()[:64]
    return (request.remote_addr or "0.0.0.0")[:64]


def _ensure_user(payload: dict) -> User:
    uid = payload.get("sub")
    if not uid:
        raise ValueError("missing sub")
    email = (
        payload.get("email")
        or payload.get("primary_email_address_id")
        or f"{uid}@placeholder.invalid"
    )
    if isinstance(email, dict):
        email = email.get("email") or str(uid) + "@placeholder.invalid"
    user = User.query.filter_by(id=uid).first()
    if user is None:
        user = User(id=str(uid), email=str(email)[:320])
        db.session.add(user)
        db.session.commit()
    else:
        if user.deleted_at is not None:
            user.deleted_at = None
        ne = str(email)[:320]
        if user.email != ne:
            user.email = ne
        db.session.commit()
    return user


@bp.get("/me")
@require_auth
def get_me():
    """Lightweight session bootstrap: runs lazy default `public_metadata.role` and returns resolved role."""
    payload = request.clerk_user  # type: ignore[attr-defined]
    role = getattr(request, "clerk_effective_role", "user")
    return jsonify({"user_id": str(payload.get("sub")), "role": role})


@bp.post("/scans")
def create_scan():
    body = request.get_json(silent=True) or {}
    url = body.get("url", "")
    token = get_bearer_token()
    payload = None
    if token:
        payload, verify_err = verify_clerk_jwt(token)
        if not payload:
            return (
                jsonify(
                    {
                        "error": "unauthorized",
                        "message": clerk_verify_error_message(verify_err),
                        "verify_reason": verify_err,
                    }
                ),
                401,
            )
    else:
        allowed, _count = check_and_consume_guest_scan(
            _client_ip(), int(current_app.config.get("GUEST_SCANS_PER_DAY", 3))
        )
        if not allowed:
            return (
                jsonify(
                    {
                        "error": "rate_limited",
                        "message": "Guest scan limit reached (3 per UTC day for this network). Sign in to save history and unlock higher limits later.",
                    }
                ),
                429,
            )

    result = run_pipeline(url)
    if not result.get("ok"):
        return (
            jsonify(
                {
                    "error": result.get("error", "invalid"),
                    "message": result.get("message", "Invalid URL."),
                }
            ),
            400,
        )

    if payload:
        uid = str(payload.get("sub"))
        _ensure_user(payload)
        scan = Scan(
            user_id=uid,
            input_url=result["input_url"],
            normalized_url=result["normalized_url"],
            host=result.get("host") or "",
            score=int(result["score"]),
            verdict=str(result["verdict"]),
            risk_band=str(result["risk_band"]),
            breakdown=result["breakdown"],
            explanation=list(result.get("explanation") or []),
            recommended_actions=list(result.get("recommended_actions") or []),
            weights_version=str(result["weights_version"]),
        )
        db.session.add(scan)
        db.session.commit()
        out = {**result, "scan_id": scan.id}
        return jsonify(out), 201

    public = {k: v for k, v in result.items() if k not in ("user_id",)}
    public["scan_id"] = None
    return jsonify(public), 200


@bp.get("/scans/<scan_id>")
@require_auth
def get_scan(scan_id: str):
    payload = request.clerk_user  # type: ignore[attr-defined]
    uid = str(payload.get("sub"))
    scan = Scan.query.filter_by(id=scan_id).first()
    if not scan:
        return jsonify({"error": "not_found", "message": "Scan not found."}), 404
    is_admin = getattr(request, "clerk_effective_role", None) == "admin"
    if scan.user_id != uid and not is_admin:
        return jsonify({"error": "forbidden", "message": "You cannot access this scan."}), 403
    return jsonify(scan.to_dict())


@bp.get("/me/scans")
@require_auth
def list_my_scans():
    payload = request.clerk_user  # type: ignore[attr-defined]
    uid = str(payload.get("sub"))
    page = max(int(request.args.get("page", 1)), 1)
    per = min(max(int(request.args.get("per", 20)), 1), 100)
    q = (
        Scan.query.filter_by(user_id=uid)
        .order_by(Scan.created_at.desc())
        .paginate(page=page, per_page=per, error_out=False)
    )
    items = [
        {
            "id": s.id,
            "normalized_url": s.normalized_url,
            "score": s.score,
            "verdict": s.verdict,
            "risk_band": s.risk_band,
            "created_at": s.created_at.isoformat() if s.created_at else None,
        }
        for s in q.items
    ]
    return jsonify({"items": items, "page": page, "per": per, "total": q.total})


@bp.post("/scans/<scan_id>/favorite")
@require_auth
def toggle_favorite(scan_id: str):
    payload = request.clerk_user  # type: ignore[attr-defined]
    uid = str(payload.get("sub"))
    scan = Scan.query.filter_by(id=scan_id, user_id=uid).first()
    if not scan:
        return jsonify({"error": "not_found", "message": "Scan not found."}), 404
    existing = Favorite.query.filter_by(user_id=uid, scan_id=scan_id).first()
    if existing:
        db.session.delete(existing)
        db.session.commit()
        return jsonify({"favorited": False})
    db.session.add(Favorite(user_id=uid, scan_id=scan_id))
    db.session.commit()
    return jsonify({"favorited": True})


@bp.post("/reports")
@require_auth
def create_report():
    payload = request.clerk_user  # type: ignore[attr-defined]
    uid = str(payload.get("sub"))
    body = request.get_json(silent=True) or {}
    url = (body.get("url") or "").strip()
    note = body.get("note")
    scan_id = body.get("scan_id")
    if not url:
        return jsonify({"error": "validation", "message": "url is required"}), 400
    r = Report(user_id=uid, url=url, scan_id=scan_id, note=note)
    db.session.add(r)
    db.session.commit()
    return jsonify({"id": r.id, "status": r.status}), 201
