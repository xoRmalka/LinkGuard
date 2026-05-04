def ip_host_signal(is_ip_host: bool) -> dict:
    return {
        "id": "ip_host",
        "status": "ok",
        "concern": is_ip_host,
        "summary": "Host is a raw IP address, which is sometimes used in phishing."
        if is_ip_host
        else "Host is a domain name.",
    }
