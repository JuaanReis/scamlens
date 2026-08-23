from httpx import Client, Timeout, Limits
from providers.http.headers import build_headers
from scamLens import __version__
from scamLens import config

client_config = config.get("http", {})

def _base_limits() -> Limits:
    return Limits(max_keepalive_connections=client_config.get("max_keepalive_connections"),
                    max_connections=client_config.get("max_connections", 50)
            )

def make_scan_client(rotate_ua: bool = True) -> Client:
    return Client(
        http2=client_config.get("http2", False),
        verify=client_config.get("verify_ssl", True),
        follow_redirects=client_config.get("follow_redirects", False),
        timeout=Timeout(timeout=client_config.get("timeout", 6.0),
                        connect=client_config.get("connect", 1.5), 
                        read=client_config.get("read", 3.0)
                        ),
        limits=_base_limits(),
        headers=build_headers(rotate_ua=rotate_ua),
    )

scan_client: Client = make_scan_client(client_config.get("rotate_user_agent", True))