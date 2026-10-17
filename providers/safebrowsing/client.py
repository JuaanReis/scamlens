from json import loads
from ..http.connect import request
from scamLens import get_settings

settings = get_settings()
_ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

THREAT_TYPES = [
    "MALWARE",
    "SOCIAL_ENGINEERING",
    "UNWANTED_SOFTWARE",
    "POTENTIALLY_HARMFUL_APPLICATION",
]

def fetch_safe_browsing(url: str | list[str]) -> dict | None:
    api_key = settings.google_safe_browsing_key
    if not api_key:
        return None

    urls = list(dict.fromkeys(url if isinstance(url, list) else [url]))
    payload = {
        "client": {"clientId": "scurl", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": THREAT_TYPES,
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": entry} for entry in urls],
        },
    }

    try:
        r = request(
            method="POST", url=f"{_ENDPOINT}?key={api_key}", data=payload, timeout=5
        )
        if not r or r.status != 200 or getattr(r, "truncated", False):
            return None

        data = loads(r.body)
        if not isinstance(data, dict) or "error" in data:
            return None
        matches = data.get("matches", [])
        if not isinstance(matches, list):
            return None
        return {
            "flagged": len(matches) > 0,
            "threat_types": [m.get("threatType") for m in matches],
        }
    except Exception:
        return None
