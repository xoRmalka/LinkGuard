_SHORTENERS = frozenset({
    # Popular shorteners
    "bit.ly", "goo.gl", "tinyurl.com", "t.co", "ow.ly",
    "buff.ly", "is.gd", "cutt.ly", "rebrand.ly", "short.link",
    # Additional shorteners
    "rb.gy", "s.id", "shorturl.at", "v.gd", "clck.ru",
    "tiny.cc", "lnkd.in", "bit.do", "qr.ae", "j.mp",
    "bl.ink", "soo.gd", "s.coop", "u.nu", "t.ly",
    "fa.by", "bc.vc", "trib.al", "su.pr", "shor.by",
})


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
