_SHORTENERS = frozenset(
    {
        "bit.ly",
        "goo.gl",
        "tinyurl.com",
        "t.co",
        "ow.ly",
        "buff.ly",
        "is.gd",
        "cutt.ly",
        "rebrand.ly",
        "short.link",
    }
)


def shortener_signal(host: str) -> dict:
    h = (host or "").lower()
    hit = h in _SHORTENERS or any(h.endswith("." + s) for s in _SHORTENERS)
    return {
        "id": "shortener",
        "status": "ok",
        "concern": hit,
        "summary": "Known link shortener — destination is hidden until resolved."
        if hit
        else "Not a known shortener domain.",
    }
