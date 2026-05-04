import socket
import ssl
from urllib.parse import urlsplit


def ssl_signal(normalized_url: str, timeout: float = 5.0) -> dict:
    try:
        parts = urlsplit(normalized_url)
        host = parts.hostname
        port = parts.port or (443 if parts.scheme == "https" else 80)
        if not host or parts.scheme != "https":
            return {
                "id": "ssl",
                "status": "skipped",
                "concern": parts.scheme != "https",
                "summary": "Not an HTTPS URL — connection is not TLS-protected to the origin."
                if parts.scheme != "https"
                else "Could not read host for TLS check.",
            }
    except Exception:
        return {
            "id": "ssl",
            "status": "error",
            "concern": True,
            "summary": "TLS check could not start.",
        }

    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                if not cert:
                    return {
                        "id": "ssl",
                        "status": "ok",
                        "concern": True,
                        "summary": "TLS connected but no certificate details returned.",
                    }
                return {
                    "id": "ssl",
                    "status": "ok",
                    "concern": False,
                    "summary": "TLS certificate presented and hostname validation succeeded for this check.",
                }
    except ssl.SSLError as e:
        return {
            "id": "ssl",
            "status": "ok",
            "concern": True,
            "summary": f"TLS issue: {e.__class__.__name__}",
        }
    except OSError as e:
        return {
            "id": "ssl",
            "status": "error",
            "concern": False,
            "summary": f"Could not complete TLS handshake: {e.__class__.__name__}",
        }
