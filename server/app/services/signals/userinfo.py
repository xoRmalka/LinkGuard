"""Detect deceptive URL userinfo such as brand.com@evil.com."""


def userinfo_signal(has_userinfo: bool) -> dict:
    return {
        "id": "userinfo",
        "status": "ok",
        "concern": has_userinfo,
        "summary": (
            "URL contains username/password-style userinfo before the host; this can hide the real destination."
            if has_userinfo
            else "URL does not contain userinfo before the host."
        ),
    }
