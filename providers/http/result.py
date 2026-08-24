from providers.http.http_result import HTTPResult

def extract_redirect_chain(response) -> list:
    chain = [
        {
            "url": str(r.url),
            "status": r.status_code,
            "location": r.headers.get("location"),
        }
        for r in response.history
    ]

    chain.append({
        "url": str(response.url),
        "status": response.status_code,
        "location": None,
    })

    return chain

def build_result(response) -> HTTPResult:
    headers = dict(response.headers)

    headers.pop("set-cookie", None)
    headers.pop("Set-Cookie", None)

    return HTTPResult(
        url=str(response.url),
        status=response.status_code,
        headers=headers,
        body=response.text,
        elapsed=response.elapsed.total_seconds(),
        size=len(response.content),
        redirects=len(response.history),
        redirect_chain=extract_redirect_chain(response),
    )