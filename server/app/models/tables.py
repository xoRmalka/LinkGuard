import uuid
from datetime import datetime, timezone

from app.extensions import db


def utcnow():
    return datetime.now(timezone.utc)


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.String(64), primary_key=True)  # Clerk user id (sub)
    email = db.Column(db.String(320), nullable=False, index=True)
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = db.Column(db.DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)
    deleted_at = db.Column(db.DateTime(timezone=True), nullable=True)

    scans = db.relationship("Scan", backref="user", lazy="dynamic")
    favorites = db.relationship("Favorite", backref="user", lazy="dynamic")
    reports = db.relationship("Report", backref="user", lazy="dynamic")

    def to_public_dict(self):
        return {
            "id": self.id,
            "email": self.email,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "deleted_at": self.deleted_at.isoformat() if self.deleted_at else None,
        }


class Scan(db.Model):
    __tablename__ = "scans"

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(64), db.ForeignKey("users.id"), nullable=False, index=True)
    input_url = db.Column(db.Text, nullable=False)
    normalized_url = db.Column(db.Text, nullable=False)
    host = db.Column(db.String(512), nullable=False, index=True)
    score = db.Column(db.Integer, nullable=False)
    verdict = db.Column(db.String(32), nullable=False)
    risk_band = db.Column(db.String(32), nullable=False)
    breakdown = db.Column(db.JSON, nullable=False)
    explanation = db.Column(db.JSON, nullable=True)
    recommended_actions = db.Column(db.JSON, nullable=True)
    weights_version = db.Column(db.String(64), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False, index=True)

    favorites = db.relationship("Favorite", backref="scan", lazy="dynamic")

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "input_url": self.input_url,
            "normalized_url": self.normalized_url,
            "host": self.host,
            "score": self.score,
            "verdict": self.verdict,
            "risk_band": self.risk_band,
            "breakdown": self.breakdown,
            "explanation": self.explanation or [],
            "recommended_actions": self.recommended_actions or [],
            "weights_version": self.weights_version,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class Favorite(db.Model):
    __tablename__ = "favorites"

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(64), db.ForeignKey("users.id"), nullable=False, index=True)
    scan_id = db.Column(db.String(36), db.ForeignKey("scans.id"), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)

    __table_args__ = (db.UniqueConstraint("user_id", "scan_id", name="uq_favorite_user_scan"),)


class Report(db.Model):
    __tablename__ = "reports"

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(64), db.ForeignKey("users.id"), nullable=False, index=True)
    url = db.Column(db.Text, nullable=False)
    scan_id = db.Column(db.String(36), db.ForeignKey("scans.id"), nullable=True)
    note = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(32), nullable=False, default="open")
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)


class GuestScanDay(db.Model):
    """Tracks guest scan counts per IP per UTC calendar day."""

    __tablename__ = "guest_scan_days"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    ip = db.Column(db.String(64), nullable=False, index=True)
    day = db.Column(db.Date, nullable=False, index=True)
    count = db.Column(db.Integer, nullable=False, default=0)

    __table_args__ = (db.UniqueConstraint("ip", "day", name="uq_guest_ip_day"),)
