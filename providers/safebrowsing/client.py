from json import loads
from ..http.connect import post_response
from scamLens import get_settings

settings = get_settings()
_ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

THREAT_TYPES = [
    "MALWARE",
    "SOCIAL_ENGINEERING",
    "UNWANTED_SOFTWARE",
    "POTENTIALLY_HARMFUL_APPLICATION"
]

def fetch_safe_browsing(url: str) -> dict | None:
    api_key = settings.google_safe_browsing_key
    if not api_key:
        return None

    payload = {
        "client": {"clientId": "scurl", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": THREAT_TYPES,
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    try:
        r = post_response(
            f"{_ENDPOINT}?key={api_key}",
            data=payload,
            timeout=5
        )
        if not r:
            return None

        data = loads(r.body)
        matches = data.get("matches", [])
        return {
            "flagged": len(matches) > 0,
            "threat_types": [m.get("threatType") for m in matches]
        }
    except Exception:
        return None