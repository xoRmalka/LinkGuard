import re

_BRANDS = (
    "google",
    "facebook",
    "amazon",
    "paypal",
    "microsoft",
    "apple",
    "netflix",
    "instagram",
    "whatsapp",
    "linkedin",
)


def _levenshtein(a: str, b: str) -> int:
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            ins, delete, sub = cur[j - 1] + 1, prev[j] + 1, prev[j - 1] + (ca != cb)
            cur.append(min(ins, delete, sub))
        prev = cur
    return prev[-1]


def _mixed_script(host: str) -> bool:
    letters = [c for c in host if c.isalpha()]
    if len(letters) < 4:
        return False
    scripts = set()
    for c in letters:
        o = ord(c)
        if 0x0041 <= o <= 0x007A or 0x0061 <= o <= 0x007A:
            scripts.add("latin")
        elif 0x0400 <= o <= 0x04FF:
            scripts.add("cyrillic")
        elif 0x0590 <= o <= 0x05FF:
            scripts.add("hebrew")
        elif 0x0600 <= o <= 0x06FF:
            scripts.add("arabic")
        elif 0x4E00 <= o <= 0x9FFF:
            scripts.add("han")
    return len(scripts) >= 2


def typosquatting_signal(host: str) -> dict:
    base = re.sub(r"^www\.", "", (host or "").lower())
    base = base.split(":")[0]

    # Extract just the domain name without TLD for comparison
    domain_label = base.split(".")[0]

    best = None
    best_d = 99
    for brand in _BRANDS:
        if base == brand or base.endswith("." + brand):
            best_d = 0
            best = brand
            break
        d = _levenshtein(domain_label, brand)
        if d < best_d:
            best_d = d
            best = brand

    concern = False
    summary = "No strong typosquatting heuristic matched."
    if best_d == 1 and best:
        concern = True
        summary = f'Host is very close to "{best}" - possible typosquatting.'
    elif best_d == 2 and best and len(domain_label) <= len(best) + 3:
        concern = True
        summary = f'Host somewhat resembles "{best}" - review carefully.'

    mixed = _mixed_script(host or "")
    if mixed:
        concern = True
        summary = (summary + " ") if summary else ""
        summary += "Mixed scripts in hostname - possible homograph attack."

    return {
        "id": "typosquatting",
        "status": "ok",
        "concern": concern,
        "closest_brand": best,
        "distance": best_d if best else None,
        "summary": summary.strip(),
    }
