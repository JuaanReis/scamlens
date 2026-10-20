import logging
from time import sleep
from httpx import (
    HTTPStatusError,
    ConnectError,
    RequestError,
)
from .client import scan_client
from .retry import (
    backoff_delay,
    should_retry,
    get_retry_after,
)
from .result import build_result
from .url_sanitizer_log import sanitize_url
from scamLens import config

logger = logging.getLogger("scanner.request")

def request(method: str, url: str, *, data: dict | None = None, retries: int | None = None, delay: float | None = None, timeout: float | None = None, allow_redirects: bool = False):
    http_config = config["http"]
    retries = http_config["retries"] if retries is None else retries
    delay = http_config["retry_delay"] if delay is None else delay
    timeout = http_config["timeout"] if timeout is None else timeout
    for attempt in range(retries):
        try:
            response = scan_client.request(
                method,
                url,
                json=data,
                timeout=timeout,
                follow_redirects=allow_redirects,
            )

            logger.info(
                "%s %s status=%d attempt=%d/%d",
                method,
                sanitize_url(url),
                response.status_code,
                attempt + 1,
                retries,
            )

            if should_retry(response.status_code) and attempt < retries - 1:
                sleep(get_retry_after(dict(response.headers), default=delay * (2 ** attempt)))
                continue
            return build_result(response)

        except HTTPStatusError as e:
            response = e.response

            if should_retry(response.status_code):
                logger.warning(
                    "%s %s status=%d attempt=%d/%d retry",
                    method,
                    sanitize_url(url),
                    response.status_code,
                    attempt + 1,
                    retries,
                )

                sleep(
                    get_retry_after(
                        dict(response.headers)
                    )
                )

                continue

            logger.warning(
                "%s %s status=%d no retry",
                method,
                sanitize_url(url),
                response.status_code,
            )

            return build_result(response)

        except (ConnectError, RequestError) as e:
            logger.warning(
                "%s %s attempt=%d/%d error=%s",
                method,
                sanitize_url(url),
                attempt + 1,
                retries,
                e,
            )

            if attempt < retries - 1:
                backoff_delay(
                    attempt,
                    base_delay=delay,
                )

    logger.error(
        "%s %s all %d attempts failed",
        method,
        sanitize_url(url),
        retries,
    )

    return None
