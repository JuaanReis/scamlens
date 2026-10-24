from re import search, I
from starlette.requests import Request
from scamLens import config

_TRUST_PROXY = config["logging"]["trust_proxy"]

def get_client_ip(request: Request) -> str:
    if _TRUST_PROXY:
        forwarded = request.headers.get("X-Forwarded-For", "")

        if forwarded:
            return forwarded.split(",")[0].strip()

    return request.client.host if request.client else "-"

def get_user_agent(request: Request) -> str:
    ua = request.headers.get("User-Agent", "-").strip()

    if not ua or ua == "-":
        return "-"

    match = search(
        r"(Edg|OPR|Chrome|Firefox|Safari)/([\d.]+)",
        ua,
    )

    if match:
        browser, version = match.groups()

        if browser == "Safari" and "Chrome" in ua:
            chrome = search(r"Chrome/([\d.]+)", ua)

            if chrome:
                return f"Chrome/{chrome.group(1).split('.')[0]}"

        return f"{browser}/{version.split('.')[0]}"

    match = search(r"curl/([\d.]+)", ua, I)

    if match:
        return f"curl/{match.group(1)}"

    return ua.split()[0][:30]

def get_referer(request: Request) -> str:
    return request.headers.get("Referer", "-")
