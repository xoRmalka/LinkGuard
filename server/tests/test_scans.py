from app import create_app
from app.config import Config
from app.extensions import db
from app.models.tables import Scan, User


def test_create_scan_returns_validation_error_for_invalid_port(tmp_path, monkeypatch):
    database_path = tmp_path / "linkguard-test.db"
    monkeypatch.setattr(Config, "SQLALCHEMY_DATABASE_URI", f"sqlite:///{database_path}")
    monkeypatch.setattr(
        Config,
        "SQLALCHEMY_ENGINE_OPTIONS",
        {"connect_args": {"check_same_thread": False}},
    )

    app = create_app()
    app.config.update(TESTING=True)

    response = app.test_client().post(
        "/api/v1/scans",
        json={"url": "https://example.com:abc/path"},
        headers={"X-Forwarded-For": "192.0.2.200"},
    )

    assert response.status_code == 400
    assert response.get_json()["error"] == "invalid_port"


def test_legitimate_login_subdomain_is_not_high_risk(tmp_path, monkeypatch):
    database_path = tmp_path / "linkguard-login-subdomain-test.db"
    monkeypatch.setattr(Config, "SQLALCHEMY_DATABASE_URI", f"sqlite:///{database_path}")
    monkeypatch.setattr(
        Config,
        "SQLALCHEMY_ENGINE_OPTIONS",
        {"connect_args": {"check_same_thread": False}},
    )
    monkeypatch.setattr(
        "app.services.pipeline.domain_age_signal",
        lambda host: {
            "id": "domain_age",
            "status": "ok",
            "concern": False,
            "age_days": 3650,
            "summary": "Established domain.",
        },
    )
    monkeypatch.setattr(
        "app.services.pipeline.check_safe_browsing",
        lambda url, api_key: {
            "id": "safe_browsing",
            "status": "ok",
            "concern": False,
            "summary": "No threat match.",
            "matches": [],
        },
    )

    app = create_app()
    app.config.update(TESTING=True)

    response = app.test_client().post(
        "/api/v1/scans",
        json={"url": "https://login.microsoft.com"},
        headers={"X-Forwarded-For": "192.0.2.201"},
    )

    assert response.status_code == 200
    data = response.get_json()
    assert data["score"] >= 70
    assert data["verdict"] != "high_risk"
    signals = {row["id"]: row for row in data["breakdown"]}
    assert signals["typosquatting"]["concern"] is False
    assert signals["suspicious_subdomain"]["concern"] is False

def test_authenticated_scan_provisions_user_before_saving_scan(tmp_path, monkeypatch):
    database_path = tmp_path / "linkguard-auth-scan-test.db"
    monkeypatch.setattr(Config, "SQLALCHEMY_DATABASE_URI", f"sqlite:///{database_path}")
    monkeypatch.setattr(
        Config,
        "SQLALCHEMY_ENGINE_OPTIONS",
        {"connect_args": {"check_same_thread": False}},
    )
    monkeypatch.setattr(
        "app.routes.scans.verify_clerk_jwt",
        lambda token: ({"sub": "user_auth_scan", "email": "scan@example.com"}, None),
    )
    monkeypatch.setattr(
        "app.routes.scans.run_pipeline",
        lambda url: {
            "ok": True,
            "input_url": url,
            "normalized_url": "https://example.com/",
            "host": "example.com",
            "score": 95,
            "verdict": "likely_safe",
            "risk_band": "safe",
            "breakdown": [],
            "explanation": [],
            "recommended_actions": [],
            "weights_version": "test",
        },
    )

    app = create_app()
    app.config.update(TESTING=True)

    response = app.test_client().post(
        "/api/v1/scans",
        json={"url": "example.com"},
        headers={"Authorization": "Bearer test-token"},
    )

    assert response.status_code == 201
    with app.app_context():
        assert db.session.get(User, "user_auth_scan") is not None
        assert Scan.query.filter_by(user_id="user_auth_scan").count() == 1


def test_authenticated_report_provisions_user_before_saving_report(tmp_path, monkeypatch):
    database_path = tmp_path / "linkguard-auth-report-test.db"
    monkeypatch.setattr(Config, "SQLALCHEMY_DATABASE_URI", f"sqlite:///{database_path}")
    monkeypatch.setattr(
        Config,
        "SQLALCHEMY_ENGINE_OPTIONS",
        {"connect_args": {"check_same_thread": False}},
    )
    monkeypatch.setattr(
        "app.auth.clerk_jwt.verify_clerk_jwt",
        lambda token: ({"sub": "user_auth_report", "email": "report@example.com"}, None),
    )
    monkeypatch.setattr(
        "app.auth.clerk_jwt.ensure_lazy_default_and_resolve",
        lambda user_id, payload: "user",
    )

    app = create_app()
    app.config.update(TESTING=True)

    response = app.test_client().post(
        "/api/v1/reports",
        json={"url": "https://example.com"},
        headers={"Authorization": "Bearer test-token"},
    )

    assert response.status_code == 201
    with app.app_context():
        user = db.session.get(User, "user_auth_report")
        assert user is not None
        assert user.reports.count() == 1
