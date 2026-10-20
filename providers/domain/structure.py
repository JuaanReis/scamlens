from functools import lru_cache
from ipaddress import ip_address
from tldextract import TLDExtract
from scamLens import config

domain_config = config["domain"]

_EXTRACTOR = TLDExtract(suffix_list_urls=(), cache_dir=None)

@lru_cache(maxsize=domain_config["cache_size"])
def extract(hostname: str, private: bool = False):
    return _EXTRACTOR(hostname, include_psl_private_domains=private)

def owner(hostname: str) -> str:
    hostname = (hostname or "").lower().rstrip(".")
    try:
        return str(ip_address(hostname))
    except ValueError:
        pass
    result = extract(hostname, True)
    return result.top_domain_under_public_suffix or hostname

def same_owner(left: str, right: str) -> bool:
    return bool(left and right and owner(left) == owner(right))
