from .client import rdap_client
import threading
import tldextract

_MAX_CONCURRENT_PER_SERVER = 8
_FALLBACK_MAX_CONCURRENT = 4

_RDAP_SERVERS: dict[str, str] = {
    "com":  "https://rdap.verisign.com/com/v1/domain/",
    "net":  "https://rdap.verisign.com/net/v1/domain/",
    "org":  "https://rdap.publicinterestregistry.org/rdap/domain/",
    "io":   "https://rdap.nic.io/domain/",
    "br":   "https://rdap.registro.br/domain/",
    "gov":  "https://rdap.arin.net/registry/domain/",
    "edu":  "https://rdap.arin.net/registry/domain/",
    "info": "https://rdap.afilias.info/rdap/info/domain/",
    "biz":  "https://rdap.nic.biz/domain/",
    "co":   "https://rdap.nic.co/domain/",
    "us":   "https://rdap.arin.net/registry/domain/",
    "uk":   "https://rdap.nominet.uk/uk/domain/",
    "de":   "https://rdap.denic.de/domain/",
    "fr":   "https://rdap.nic.fr/domain/",
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
            limit = _FALLBACK_MAX_CONCURRENT if "rdap.org" in server_base else _MAX_CONCURRENT_PER_SERVER
            _semaphores[server_base] = threading.Semaphore(limit)
        return _semaphores[server_base]

def _server_base(url: str) -> str:
    parts = url.split("/")
    return "/".join(parts[:3])  

def resolve_rdap_url(hostname: str) -> tuple[str, str]:
    extracted = tldextract.extract(hostname)
    registered = f"{extracted.domain}.{extracted.suffix}"
    tld = extracted.suffix.lower()
    base = _RDAP_SERVERS.get(tld, _RDAP_FALLBACK)
    return f"{base}{registered}", registered

def fetch_rdap(hostname: str) -> dict | None:
    if not hostname:
        return None

    rdap_url, registered = resolve_rdap_url(hostname)

    with _cache_lock:
        if registered in _cache:
            return _cache[registered]
        
    server_base = _server_base(rdap_url)
    sem = _get_semaphore(server_base)

    result = None
    with sem:
        with _cache_lock:
            if registered in _cache:
                return _cache[registered]

        try:
            response = rdap_client.get(rdap_url)
            response.raise_for_status()
            data = response.json()
            result = None if "errorCode" in data else data
        except Exception:
            result = None

    with _cache_lock:
        _cache[registered] = result

    return result

def clear_cache() -> None:
    with _cache_lock:
        _cache.clear()