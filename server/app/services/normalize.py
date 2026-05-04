from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

_SCHEMES = frozenset({"http", "https"})


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
            False, "empty", text, None, None, None, None, False, False
        )

    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", text):
        text = "https://" + text

    try:
        parts = urlsplit(text)
    except ValueError:
        return NormalizeResult(
            False, "invalid_url", raw, None, None, None, None, False, False
        )

    scheme = (parts.scheme or "").lower()
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
        )

    host = parts.hostname
    if not host:
        return NormalizeResult(
            False, "missing_host", raw, None, None, None, None, False, False
        )

    punycode_applied = False
    host_display = host
    try:
        if host.encode("ascii", "strict") != host.encode("utf-8"):
            punycode_applied = True
        ascii_host = host.encode("idna").decode("ascii")
        host_display = host
        host = ascii_host
    except (UnicodeError, UnicodeDecodeError):
        return NormalizeResult(
            False, "invalid_host", raw, None, None, None, None, False, False
        )

    is_ip = _host_is_ip(host)

    netloc = host
    if parts.port and parts.port not in (80, 443):
        netloc = f"{host}:{parts.port}"

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
    )
