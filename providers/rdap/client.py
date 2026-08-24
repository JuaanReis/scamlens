from httpx import Client, Limits, Timeout
from scamLens import __version__, config

rdap_config = config.get("rdap", {})

def _base_limits() -> Limits:
    return Limits(
        max_keepalive_connections=rdap_config.get("max_keepalive_connections", 20),
        max_connections=rdap_config.get("max_connections", 120)
    )

def make_rdap_client() -> Client:
    return Client(
        http2=rdap_config.get("http2", False),
        verify=rdap_config.get("verify", True),
        follow_redirects=rdap_config.get("follow_redirects", True),
        timeout=Timeout(connect=rdap_config.get("connect", 2.0), read=rdap_config.get("read", 3.0), write=rdap_config.get("write", 2.0), pool=rdap_config.get("pool", 1.0)),
        limits=_base_limits(),
        headers={
            "User-Agent": f"ScamLens/{__version__}",
        },
    )

rdap_client: Client = make_rdap_client()