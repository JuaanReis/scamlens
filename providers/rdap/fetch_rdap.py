import logging
import threading
import httpx
from providers.domain.structure import extract
from .client import rdap_client
from scamLens import config

logger = logging.getLogger("scanner.rdap")

_rdap_config = config["rdap"]
_MAX_CONCURRENT_PER_SERVER = _rdap_config["max_concurrent_per_server"]
_FALLBACK_MAX_CONCURRENT = _rdap_config["fallback_max_concurrent"]

_RDAP_SERVERS: dict[str, str] = {
    "com": "https://rdap.verisign.com/com/v1/domain/",
    "net": "https://rdap.verisign.com/net/v1/domain/",
    "org": "https://rdap.publicinterestregistry.org/rdap/domain/",
    "io": "https://rdap.nic.io/domain/",
    "br": "https://rdap.registro.br/domain/",
    "gov": "https://rdap.arin.net/registry/domain/",
    "edu": "https://rdap.arin.net/registry/domain/",
    "info": "https://rdap.afilias.info/rdap/info/domain/",
    "biz": "https://rdap.nic.biz/domain/",
    "co": "https://rdap.nic.co/domain/",
    "us": "https://rdap.arin.net/registry/domain/",
    "uk": "https://rdap.nominet.uk/uk/domain/",
    "de": "https://rdap.denic.de/domain/",
    "fr": "https://rdap.nic.fr/domain/",
    "host": "https://rdap.centralnic.com/host/domain/",
}

_RDAP_FALLBACK = "https://rdap.org/domain/"

_cache: dict[str, dict | None] = {}
_cache_lock = threading.Lock()
_semaphores: dict[str, threading.Semaphore] = {}
_sem_lock = threading.Lock()


def _get_semaphore(server_base: str) -> threading.Semaphore:
    with _sem_lock:
        if server_base not in _semaphores:
            limit = (
                _FALLBACK_MAX_CONCURRENT
                if "rdap.org" in server_base
                else _MAX_CONCURRENT_PER_SERVER
            )

            _semaphores[server_base] = threading.Semaphore(limit)

        return _semaphores[server_base]


def _server_base(url: str) -> str:
    parts = url.split("/")
    return "/".join(parts[:3])


def resolve_rdap_url(hostname: str) -> tuple[str, str]:
    extracted = extract(hostname)

    registered = f"{extracted.domain}.{extracted.suffix}"
    tld = extracted.suffix.lower()

    base = _RDAP_SERVERS.get(tld, _RDAP_FALLBACK)

    return f"{base}{registered}", registered


def fetch_rdap(hostname: str) -> dict | None:
    if not hostname:
        logger.warning("hostname empty")
        return None

    rdap_url, registered = resolve_rdap_url(hostname)
    server_base = _server_base(rdap_url)

    with _cache_lock:
        if registered in _cache:
            logger.info(
                "GET %s cache=hit",
                registered,
            )
            return _cache[registered]

    sem = _get_semaphore(server_base)

    result = None
    should_cache = True

    with sem:
        with _cache_lock:
            if registered in _cache:
                logger.info(
                    "GET %s cache=hit",
                    registered,
                )
                return _cache[registered]

        try:
            response = rdap_client.get(rdap_url)
            response.raise_for_status()

            data = response.json()
            result = None if "errorCode" in data else data

            logger.info(
                "GET %s status=%d cache=miss",
                registered,
                response.status_code,
            )

        except httpx.PoolTimeout:
            result = None
            should_cache = False

            logger.warning(
                "GET %s error=pool_timeout cache=no",
                registered,
            )

        except httpx.TimeoutException:
            result = None
            should_cache = False

            logger.warning(
                "GET %s error=timeout cache=no",
                registered,
            )

        except httpx.HTTPStatusError as e:
            status = e.response.status_code if e.response is not None else 0

            logger.warning(
                "GET %s status=%d error=http",
                registered,
                status,
            )

            if status >= 500:
                should_cache = False

        except Exception as e:
            result = None
            should_cache = False

            logger.warning(
                "GET %s error=%s cache=no",
                registered,
                type(e).__name__,
            )

    if should_cache:
        with _cache_lock:
            _cache[registered] = result

    return result


def clear_cache() -> None:
    with _cache_lock:
        size = len(_cache)
        _cache.clear()

    logger.info(
        "cache cleared entries=%d",
        size,
    )
