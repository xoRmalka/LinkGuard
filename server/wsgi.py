"""WSGI entry for production (gunicorn wsgi:app)."""
from app import create_app

app = create_app()
