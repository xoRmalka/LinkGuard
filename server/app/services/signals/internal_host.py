"""Detect localhost and private/special-purpose IP destinations."""

import ipaddress

_LOCAL_HOSTS = frozenset({"localhost", "localhost.localdomain"})


def internal_host_signal(host: str | None) -> dict:
    h = (host or "").strip().lower().rstrip(".")
    if not h:
        return {
            "id": "internal_host",
            "status": "error",
            "concern": False,
            "summary": "No hostname provided.",
        }

    if h in _LOCAL_HOSTS or h.endswith(".localhost"):
        return {
            "id": "internal_host",
            "status": "ok",
            "concern": True,
            "category": "localhost",
            "summary": "Host points to localhost, which should not appear in a public link scan.",
        }

    try:
        ip = ipaddress.ip_address(h.split("%")[0])
    except ValueError:
        return {
            "id": "internal_host",
            "status": "ok",
            "concern": False,
            "summary": "Host is not a local or private IP address.",
        }

    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    ):
        return {
            "id": "internal_host",
            "status": "ok",
            "concern": True,
            "category": "special_ip",
            "summary": "Host is a private, local, or special-purpose IP address.",
        }

    return {
        "id": "internal_host",
        "status": "ok",
        "concern": False,
        "summary": "Host is a public IP address.",
    }
