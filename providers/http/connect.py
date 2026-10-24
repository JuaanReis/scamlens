import logging
from contextlib import ExitStack
from time import sleep
from httpx import RequestError, URL
from .client import make_scan_client
from .security import resolve_and_validate_addresses
from .retry import backoff_delay, should_retry, get_retry_after
from .result import build_result
from .url_sanitizer_log import sanitize_url
from scamLens import config

logger = logging.getLogger("scanner.request")

def request(method: str, url: str, *, data: dict | None = None, retries: int | None = None,
            delay: float | None = None, timeout: float | None = None,
            allow_redirects: bool = False, client=None, addresses=None):
    if allow_redirects:
        raise ValueError("Redirects must be validated before each request")
    options = config["http"]
    retries = options["retries"] if retries is None else retries
    delay = options["retry_delay"] if delay is None else delay
    timeout = options["timeout"] if timeout is None else timeout
    if addresses is None:
        reason, addresses = resolve_and_validate_addresses(URL(url).host)
        if reason:
            logger.warning("%s blocked=%s", sanitize_url(url), reason)
            return None
    with ExitStack() as stack:
        if client is None:
            client = stack.enter_context(make_scan_client(options["rotate_user_agent"]))
        for attempt in range(retries):
            try:
                response = client.request(
                    method, url, json=data, timeout=timeout, follow_redirects=False,
                    extensions={"scamlens_addresses": tuple(str(address) for address in addresses)},
                )
                logger.info("%s %s status=%d attempt=%d/%d", method, sanitize_url(url),
                            response.status_code, attempt + 1, retries)
                if should_retry(response.status_code) and attempt < retries - 1:
                    sleep(get_retry_after(dict(response.headers), default=delay * (2 ** attempt)))
                    response.close()
                    continue
                return build_result(response)
            except RequestError as error:
                logger.warning("%s %s attempt=%d/%d error=%s",
                               method, sanitize_url(url), attempt + 1, retries, error)
                if attempt < retries - 1:
                    backoff_delay(attempt, base_delay=delay)
    logger.error("%s %s all %d attempts failed", method, sanitize_url(url), retries)
    return None
