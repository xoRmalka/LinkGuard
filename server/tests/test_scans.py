from app import create_app
from app.config import Config


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
