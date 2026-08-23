from re import sub

def sanitize_url(url: str) -> str:
    return sub(
        r"([?&](?:key|api_key|apikey|token|access_token)=)[^&]+",
        r"\1***",
        url,
        flags=2,
    )