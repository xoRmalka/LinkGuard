import ipaddress
import re


# Private/reserved ranges that should never appear in legitimate public links
_SUSPICIOUS_RANGES = [
    ipaddress.ip_network("127.0.0.0/8"),      # Loopback
    ipaddress.ip_network("10.0.0.0/8"),       # Private
    ipaddress.ip_network("172.16.0.0/12"),    # Private
    ipaddress.ip_network("192.168.0.0/16"),   # Private
    ipaddress.ip_network("0.0.0.0/8"),        # "This" network
    ipaddress.ip_network("169.254.0.0/16"),   # Link-local
    ipaddress.ip_network("::1/128"),          # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),         # IPv6 unique local
    ipaddress.ip_network("fe80::/10"),        # IPv6 link-local
]


def _decode_obfuscated_ip(host: str) -> str | None:
    """
    Attempt to decode obfuscated IP representations.
    Returns the decoded IP string if found, None otherwise.

    Handles:
    - Decimal: 2130706433 -> 127.0.0.1
    - Octal: 0177.0.0.1 -> 127.0.0.1
    - Hex: 0x7f.0x0.0x0.0x1 -> 127.0.0.1
    - Mixed: 0x7f.0.0.1 -> 127.0.0.1
    """
    if not host:
        return None

    host = host.lower().strip()

    # Check for single decimal number (e.g., 2130706433)
    if re.match(r"^\d+$", host):
        try:
            num = int(host)
            if 0 <= num <= 0xFFFFFFFF:
                return str(ipaddress.ip_address(num))
        except (ValueError, OverflowError):
            pass

    # Check for dotted notation with octal/hex components
    if "." in host:
        parts = host.split(".")
        if len(parts) == 4:
            octets = []
            has_obfuscation = False
            for part in parts:
                try:
                    if part.startswith("0x"):
                        octets.append(int(part, 16))
                        has_obfuscation = True
                    elif part.startswith("0") and len(part) > 1 and part.isdigit():
                        octets.append(int(part, 8))
                        has_obfuscation = True
                    else:
                        octets.append(int(part))
                except ValueError:
                    break

            # Only return if there was actual obfuscation (not standard dotted decimal)
            if len(octets) == 4 and all(0 <= o <= 255 for o in octets) and has_obfuscation:
                return f"{octets[0]}.{octets[1]}.{octets[2]}.{octets[3]}"

    return None


def _is_private_or_reserved(ip_str: str) -> bool:
    """Check if an IP address is in a private or reserved range."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return any(ip in network for network in _SUSPICIOUS_RANGES)
    except ValueError:
        return False


def ip_host_signal(is_ip_host: bool, host: str | None = None) -> dict:
    """
    Check if host is an IP address and assess its risk level.

    Risk levels:
    - Private/localhost IP: HIGH (almost never legitimate in shared links)
    - Obfuscated IP: HIGH (deliberate evasion technique)
    - Public IP: MODERATE (unusual but sometimes legitimate)
    """
    # First check for obfuscated IPs that weren't caught by standard parsing
    obfuscated_ip = None
    if host and not is_ip_host:
        obfuscated_ip = _decode_obfuscated_ip(host)
        if obfuscated_ip:
            is_ip_host = True

    if not is_ip_host:
        return {
            "id": "ip_host",
            "status": "ok",
            "concern": False,
            "summary": "Host is a domain name.",
        }

    # Determine the actual IP for analysis
    ip_to_check = obfuscated_ip or host

    # Check if it's obfuscated
    if obfuscated_ip:
        return {
            "id": "ip_host",
            "status": "ok",
            "concern": True,
            "severity": "high",
            "decoded_ip": obfuscated_ip,
            "summary": f"Host uses obfuscated IP encoding (decodes to {obfuscated_ip}) — a deliberate evasion technique.",
        }

    # Check if it's a private/reserved range
    if ip_to_check and _is_private_or_reserved(ip_to_check):
        return {
            "id": "ip_host",
            "status": "ok",
            "concern": True,
            "severity": "high",
            "summary": "Host is a private/localhost IP address — never legitimate in shared links.",
        }

    # Public IP - moderate concern
    return {
        "id": "ip_host",
        "status": "ok",
        "concern": True,
        "severity": "moderate",
        "summary": "Host is a raw IP address — unusual for legitimate websites.",
    }
