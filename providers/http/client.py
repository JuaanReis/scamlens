from httpx import Client, Timeout, Limits
from providers.http.headers import build_headers
from scamLens import __version__
from plugins.scurl import config

def _base_limits() -> Limits:
    return Limits(max_keepalive_connections=20, max_connections=50)

def make_scan_client(rotate_ua: bool = True) -> Client:
    scanner_config = config.get("scanner", {})
    return Client(
        http2=scanner_config.get("http2", False),
        verify=scanner_config.get("verify_ssl", True),
        follow_redirects=scanner_config.get("follow_redirects", True),
        timeout=Timeout(timeout=6.0, connect=1.5, read=3.0),
        limits=_base_limits(),
        headers=build_headers(rotate_ua=rotate_ua),
    )

scan_client: Client = make_scan_client()