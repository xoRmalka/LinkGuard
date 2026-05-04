def parse_signal(ok: bool) -> dict:
    return {
        "id": "parse",
        "status": "ok" if ok else "error",
        "concern": not ok,
        "summary": "URL parsed and normalized successfully."
        if ok
        else "URL could not be normalized.",
    }
