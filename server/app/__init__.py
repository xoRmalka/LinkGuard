from __future__ import annotations

from flask import Flask
from flask_cors import CORS

from app.config import Config
from app.extensions import db
from app.routes.admin import bp as admin_bp
from app.routes.health import bp as health_bp
from app.routes.scans import bp as scans_bp


def create_app() -> Flask:
    app = Flask(__name__)
    app.config.from_object(Config)

    origins = app.config.get("CORS_ORIGINS") or [
        "http://127.0.0.1:5173",
        "http://localhost:5173",
    ]
    CORS(
        app,
        resources={r"/api/*": {"origins": origins}},
        supports_credentials=True,
        allow_headers=["Authorization", "Content-Type"],
    )

    db.init_app(app)

    app.register_blueprint(health_bp, url_prefix="/api/v1")
    app.register_blueprint(scans_bp, url_prefix="/api/v1")
    app.register_blueprint(admin_bp, url_prefix="/api/v1")

    with app.app_context():
        db.create_all()

    return app
