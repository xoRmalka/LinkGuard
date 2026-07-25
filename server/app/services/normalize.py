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
    has_userinfo: bool


_IPV4_OCTET_RE = re.compile(r"0[xX][0-9a-fA-F]+|0[0-7]+|0|[1-9][0-9]*")


def _parse_legacy_ipv4(host: str) -> str | None:
    """Parse legacy numeric IPv4 notations the way browsers/curl resolve
    hostnames (WHATWG URL host parsing / BSD inet_aton semantics): a bare
    32-bit integer, hex (0x7f000001), octal (leading-zero octets like
    0177.0.0.1), and shorthand forms (127.1 -> 127.0.0.1). Returns the
    canonical dotted-quad string, or None if not a legacy IPv4 host.
    """
    parts = host.split(".")
    if not 1 <= len(parts) <= 4:
        return None

    values: list[int] = []
    for part in parts:
        if not _IPV4_OCTET_RE.fullmatch(part):
            return None
        if part[:2] in ("0x", "0X"):
            values.append(int(part, 16))
        elif part != "0" and part.startswith("0"):
            values.append(int(part, 8))
        else:
            values.append(int(part, 10))

    # All but the last part must fit in a byte; the last part absorbs the
    # remaining bits, matching inet_aton shorthand forms like "127.1".
    if any(v > 0xFF for v in values[:-1]):
        return None
    remaining_bits = 32 - 8 * (len(values) - 1)
    if values[-1] >= (1 << remaining_bits):
        return None

    total = 0
    for v in values[:-1]:
        total = (total << 8) | v
    total = (total << remaining_bits) | values[-1]

    return str(ipaddress.IPv4Address(total))


def _canonical_ip(host: str) -> str | None:
    candidate = host.split("%")[0]
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        pass
    return _parse_legacy_ipv4(candidate)


def _host_is_ip(host: str) -> bool:
    return _canonical_ip(host) is not None


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

    canonical_ip = _canonical_ip(host)
    is_ip = canonical_ip is not None
    if is_ip:
        host = canonical_ip
        host_display = canonical_ip

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
