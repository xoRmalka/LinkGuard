import os

from dotenv import load_dotenv

load_dotenv()


def _database_uri() -> str:
    uri = os.environ.get("DATABASE_URL", "").strip()
    if uri:
        if uri.startswith("postgres://"):
            uri = uri.replace("postgres://", "postgresql://", 1)
        return uri
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    return f"sqlite:///{os.path.join(root, 'linkguard.db')}"


_DATABASE_URI = _database_uri()


def _clerk_issuer() -> str:
    raw = (os.environ.get("CLERK_ISSUER") or "").strip()
    raw = raw.strip('"').strip("'")
    return raw.rstrip("/")


def _clerk_jwt_key_pem() -> str:
    """Optional PEM public key from Clerk Dashboard (JWKS Public Key) for offline JWT verify."""
    raw = (os.environ.get("CLERK_JWT_KEY") or "").strip()
    if not raw:
        return ""
    return raw.replace("\\n", "\n").strip()


class Config:
    SQLALCHEMY_DATABASE_URI = _DATABASE_URI
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = (
        {"pool_pre_ping": True}
        if _DATABASE_URI.startswith("postgresql")
        else {"connect_args": {"check_same_thread": False}}
    )

    GUEST_SCANS_PER_DAY = 3
    WEIGHTS_VERSION = "2026-05-17-v2"

    CLERK_ISSUER = _clerk_issuer()
    CLERK_JWT_KEY = _clerk_jwt_key_pem()
    GOOGLE_SAFE_BROWSING_API_KEY = os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()

    CLERK_SECRET_KEY = os.environ.get("CLERK_SECRET_KEY", "").strip()

    _cors = os.environ.get(
        "CORS_ORIGINS",
        "http://127.0.0.1:5173,http://localhost:5173",
    )
    CORS_ORIGINS = [o.strip() for o in _cors.split(",") if o.strip()]
