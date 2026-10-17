import logging
from time import perf_counter, sleep
import httpx
from .client import scan_client
from .http_result import HTTPResult
from .url_sanitizer_log import sanitize_url
from scamLens import config

http_config = config["http"]
logger = logging.getLogger("scanner.request")
MAX_BODY_BYTES = http_config["max_body_bytes"]

def request(
    method,
    url,
    *,
    data=None,
    retries=3,
    delay=0.2,
    timeout=5,
    allow_redirects=False,
    max_bytes=MAX_BODY_BYTES,
    resolved_ip=None,
):
    if not 1 <= retries <= 5:
        raise ValueError("retries must be 1..5")
    
    if resolved_ip is not None and allow_redirects:
        raise ValueError("pinned targets require guarded redirects")
    
    for attempt in range(retries):
        start = perf_counter()
        try:
            logical_url = url
            transport_url = url
            headers = {}
            extensions = {}
            if resolved_ip is not None:
                original = httpx.URL(url)
                transport_url = original.copy_with(host=resolved_ip)
                headers = {
                    "Host": original.netloc.decode("ascii"),
                    "Connection": "close",
                }
                extensions = {"sni_hostname": original.host}

            with scan_client.stream(
                method,
                transport_url,
                json=data,
                timeout=timeout,
                follow_redirects=allow_redirects,
                headers=headers,
                extensions=extensions,
            ) as response:
                if (
                    response.status_code in (408, 429, 500, 502, 503, 504)
                    and attempt + 1 < retries
                ):
                    sleep(min(delay * (2**attempt), 2))
                    continue

                chunks = []

                size = 0

                truncated = False

                for chunk in response.iter_bytes():
                    if size + len(chunk) > max_bytes:
                        chunks.append(chunk[: max_bytes - size])
                        size = max_bytes
                        truncated = True
                        break
                    chunks.append(chunk)
                    size += len(chunk)
                raw = b"".join(chunks)
                try:
                    body = raw.decode(response.encoding or "utf-8", errors="replace")

                except LookupError:
                    body = raw.decode("utf-8", errors="replace")

                headers = dict(response.headers)
                headers.pop("set-cookie", None)
                logger.info(
                    "%s %s status=%d attempt=%d/%d",
                    method,
                    sanitize_url(url),
                    response.status_code,
                    attempt + 1,
                    retries,
                )

                return HTTPResult(
                    logical_url if resolved_ip is not None else str(response.url),
                    response.status_code,
                    headers,
                    body,
                    perf_counter() - start,
                    size,
                    redirect_chain=[],
                    truncated=truncated,
                )
            
        except (httpx.RequestError, httpx.InvalidURL) as exc:
            logger.warning(
                "%s %s attempt=%d/%d error=%s",
                method,
                sanitize_url(url),
                attempt + 1,
                retries,
                type(exc).__name__,
            )

            if attempt + 1 < retries:
                sleep(min(delay * (2**attempt), 2))

    return None
