import unicodedata

HOMOGLYPHS = {
    "а": "a", "е": "e", "о": "o",
    "р": "p", "с": "c", "ӏ": "l",
    "0": "o", "1": "l", "3": "e",
    "5": "s", "6": "g", "8": "b",
}

def normalize_domain(domain: str) -> str:
    domain = unicodedata.normalize("NFKC", domain)
    for k, v in HOMOGLYPHS.items():
        domain = domain.replace(k, v)
    return domain.lower().strip()