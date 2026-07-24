from __future__ import annotations

import ipaddress
from dataclasses import dataclass


_MULTI_LABEL_SUFFIXES = frozenset(
    {
        "ac.il",
        "co.il",
        "org.il",
        "net.il",
        "gov.il",
        "co.uk",
        "org.uk",
        "ac.uk",
        "gov.uk",
        "com.au",
        "net.au",
        "org.au",
        "co.nz",
        "com.br",
        "com.cn",
        "co.jp",
        "com.tr",
        "com.mx",
    }
)


@dataclass(frozen=True)
class DomainParts:
    host: str
    registrable_domain: str
    domain_label: str
    subdomains: tuple[str, ...]
    is_ip: bool


def _clean_host(host: str) -> str:
    cleaned = (host or "").strip().lower().strip("[]")
    if not cleaned:
        return ""

    try:
        ipaddress.ip_address(cleaned.split("%")[0])
        return cleaned
    except ValueError:
        pass

    if cleaned.count(":") == 1:
        host_part, port_part = cleaned.rsplit(":", 1)
        if port_part.isdigit():
            return host_part

    return cleaned.rstrip(".")


def parse_domain(host: str) -> DomainParts:
    cleaned = _clean_host(host)
    if not cleaned:
        return DomainParts("", "", "", (), False)

    try:
        ipaddress.ip_address(cleaned.split("%")[0])
        return DomainParts(cleaned, cleaned, cleaned, (), True)
    except ValueError:
        pass

    labels = tuple(part for part in cleaned.split(".") if part)
    if len(labels) <= 1:
        label = labels[0] if labels else cleaned
        return DomainParts(cleaned, cleaned, label, (), False)

    suffix_len = 1
    if len(labels) >= 3 and ".".join(labels[-2:]) in _MULTI_LABEL_SUFFIXES:
        suffix_len = 2

    registrable_start = max(0, len(labels) - suffix_len - 1)
    registrable_domain = ".".join(labels[registrable_start:])
    domain_label = labels[registrable_start]
    subdomains = labels[:registrable_start]

    if subdomains == ("www",):
        subdomains = ()

    return DomainParts(cleaned, registrable_domain, domain_label, subdomains, False)
