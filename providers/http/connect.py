import logging
from time import sleep
from .client import scan_client
from .retry import backoff_delay, should_retry, get_retry_after
from httpx import HTTPStatusError, ConnectError, RequestError
from plugins.scurl.models.http_result import HTTPResult

logger = logging.getLogger(__name__)

def extract_redirect_chain(response) -> list:
    chain = []
    for r in response.history:
        chain.append({
            "url": str(r.url),
            "status": r.status_code,
            "location": r.headers.get("location")
        })
    chain.append({
        "url": str(response.url),
        "status": response.status_code,
        "location": None
    })
    return chain

def _build_result(response) -> HTTPResult:
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
        redirect_chain=extract_redirect_chain(response)
    )

def get_response(url: str, retries: int = 3, delay: float = 0.6, timeout: float = 5, allow_redirects: bool = False) -> HTTPResult | None:
    for attempt in range(retries):
        try:
            response = scan_client.get(
                url,
                timeout=timeout,
                follow_redirects=allow_redirects,
            )
            return _build_result(response)

        except HTTPStatusError as e:
            response = e.response
            if should_retry(response.status_code):
                sleep(get_retry_after(dict(response.headers)))
                continue
            return _build_result(response)

        except (ConnectError, RequestError) as e:
            logger.warning("Tentativa %d/%d falhou para %s: %s", attempt + 1, retries, url, e)
            if attempt < retries - 1:
                backoff_delay(attempt, base_delay=delay)

    return None

def post_response(url: str, data: dict | None = None, retries: int = 3, delay: float = 0.6, timeout: float = 5) -> HTTPResult | None:
    for attempt in range(retries):
        try:
            response = scan_client.post(
                url,
                json=data,
                timeout=timeout,
            )
            return _build_result(response)

        except HTTPStatusError as e:
            response = e.response
            if should_retry(response.status_code):
                sleep(get_retry_after(dict(response.headers)))
                continue
            return _build_result(response)

        except (ConnectError, RequestError) as e:
            logger.warning(
                "Tentativa %d/%d falhou para %s: %s",
                attempt + 1,
                retries,
                url,
                e
            )
            if attempt < retries - 1:
                backoff_delay(attempt, base_delay=delay)

    return None