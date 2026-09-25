from httpx import Client, Limits, Timeout
from scamLens import __version__, config

rdap_config = config["rdap"]

def _base_limits() -> Limits:
    return Limits(
        max_keepalive_connections=rdap_config["max_keepalive_connections"],
        max_connections=rdap_config["max_connections"]
    )

def make_rdap_client() -> Client:
    return Client(
        http2=rdap_config["http2"],
        verify=rdap_config["verify"],
        follow_redirects=rdap_config["follow_redirects"],
        timeout=Timeout(connect=rdap_config["connect"], read=rdap_config["read"], write=rdap_config["write"], pool=rdap_config["pool"]),
        limits=_base_limits(),
        headers={
            "User-Agent": f"ScamLens/{__version__}",
        },
    )

rdap_client: Client = make_rdap_client()