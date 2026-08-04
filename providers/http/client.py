from httpx import Client, Timeout, Limits
from providers.http.headers import build_headers
from scamLens import __version__
from scamLens import config

def _base_limits() -> Limits:
    return Limits(max_keepalive_connections=20, max_connections=50)

def make_scan_client(rotate_ua: bool = True) -> Client:
    client_config = config.get("http", {})
    return Client(
        http2=client_config.get("http2", False),
        verify=client_config.get("verify_ssl", True),
        follow_redirects=client_config.get("follow_redirects", True),
        timeout=Timeout(timeout=6.0, connect=1.5, read=3.0),
        limits=_base_limits(),
        headers=build_headers(rotate_ua=rotate_ua),
    )

scan_client: Client = make_scan_client()