from httpx import Client, Timeout, Limits
from providers.http.headers import build_headers
from scamLens import __version__
from scamLens import config

client_config = config["http"]

def _base_limits() -> Limits:
    return Limits(max_keepalive_connections=client_config["max_keepalive_connections"],
                    max_connections=client_config["max_connections"]
            )

def make_scan_client(rotate_ua: bool = True) -> Client:
    return Client(
        http2=client_config["http2"],
        verify=client_config["verify_ssl"],
        follow_redirects=client_config["follow_redirects"],
        timeout=Timeout(timeout=client_config["timeout"],
                        connect=client_config["connect"],
                read=client_config["read"]
                        ),
        limits=_base_limits(),
        headers=build_headers(rotate_ua=rotate_ua),
    )

scan_client: Client = make_scan_client(client_config["rotate_user_agent"])