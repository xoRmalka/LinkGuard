from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

_SCHEMES = frozenset({"http", "https"})

# Dangerous schemes that should be explicitly rejected
_DANGEROUS_SCHEMES = frozenset({
    "javascript",  # XSS attacks
    "data",        # Can embed malicious content
    "vbscript",    # IE scripting attacks
    "file",        # Local file access
})


@dataclass
class NormalizeResult:
    ok: bool
    error: str | None
    input_url: str
    normalized_url: str | None
    host: str | None
    host_display: str | None
    scheme: str | None
    is_ip_host: bool
    punycode_applied: bool
    has_userinfo: bool


def _host_is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.split("%")[0])
        return True
    except ValueError:
        return False


def normalize_url(raw: str) -> NormalizeResult:
    text = (raw or "").strip()
    if not text:
        return NormalizeResult(
            False, "empty", text, None, None, None, None, False, False, False
        )

    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", text):
        text = "https://" + text

    try:
        parts = urlsplit(text)
    except ValueError:
        return NormalizeResult(
            False, "invalid_url", raw, None, None, None, None, False, False, False
        )

    scheme = (parts.scheme or "").lower()

    # Explicitly reject dangerous schemes with a specific error
    if scheme in _DANGEROUS_SCHEMES:
        return NormalizeResult(
            False,
            "dangerous_scheme",
            raw,
            None,
            None,
            None,
            None,
            False,
            False,
            False,
        )

    if scheme not in _SCHEMES:
        return NormalizeResult(
            False,
            "unsupported_scheme",
            raw,
            None,
            None,
            None,
            None,
            False,
            False,
            False,
        )

    try:
        host = parts.hostname
        port = parts.port
    except ValueError:
        return NormalizeResult(
            False, "invalid_port", raw, None, None, None, None, False, False, False
        )

    if not host:
        return NormalizeResult(
            False, "missing_host", raw, None, None, None, None, False, False, False
        )

    has_userinfo = parts.username is not None or parts.password is not None
    host_display = host
    try:
        ascii_host = host.encode("idna").decode("ascii").lower()
        decoded_host = ascii_host.encode("ascii").decode("idna")
    except (UnicodeError, UnicodeDecodeError):
        return NormalizeResult(
            False, "invalid_host", raw, None, None, None, None, False, False, False
        )
    punycode_applied = ascii_host != host.lower() or any(
        label.startswith("xn--") for label in ascii_host.split(".")
    )
    if punycode_applied:
        host_display = decoded_host
    host = ascii_host

    is_ip = _host_is_ip(host)

    host_for_netloc = f"[{host}]" if ":" in host else host
    default_port = 443 if scheme == "https" else 80
    netloc = host_for_netloc
    if port and port != default_port:
        netloc = f"{host_for_netloc}:{port}"

    path = parts.path or "/"
    query_pairs = parse_qsl(parts.query, keep_blank_values=True)
    normalized_query = urlencode(query_pairs, doseq=True)
    fragment = ""

    normalized = urlunsplit((scheme, netloc, path, normalized_query, fragment))

    return NormalizeResult(
        True,
        None,
        raw,
        normalized,
        host,
        host_display,
        scheme,
        is_ip,
        punycode_applied,
        has_userinfo,
    )
