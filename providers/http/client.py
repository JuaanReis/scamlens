from httpx import BaseTransport, Client, ConnectError, ConnectTimeout, HTTPTransport, Limits, Request, Timeout
from providers.http.headers import build_headers
from providers.http.security import address_block_reason
from scamLens import config
import ipaddress

client_config = config["http"]

def _base_limits() -> Limits:
    return Limits(max_keepalive_connections=client_config["max_keepalive_connections"],
                  max_connections=client_config["max_connections"])

class PinnedTransport(BaseTransport):
    def __init__(self):
        self.transports = {}

    def handle_request(self, request):
        addresses = request.extensions.get("scamlens_addresses", ())
        if not addresses:
            raise ConnectError("Target address was not validated", request=request)
        try:
            addresses = tuple(ipaddress.ip_address(address) for address in addresses)
            if any(address_block_reason(address) for address in addresses):
                raise ValueError("Target address is blocked")
        except ValueError as error:
            raise ConnectError(str(error), request=request) from error
        host = request.url.raw_host.decode("ascii")
        headers = request.headers.copy()
        headers["Host"] = request.url.netloc.decode("ascii")
        extensions = {**request.extensions, "sni_hostname": host}
        for index, address in enumerate(addresses):
            key = (request.url.scheme, host, request.url.port, str(address))
            if key not in self.transports:
                self.transports[key] = HTTPTransport(
                    verify=client_config["verify_ssl"], http2=client_config["http2"],
                    limits=_base_limits(), trust_env=False, retries=0,
                )
            pinned = Request(request.method, request.url.copy_with(host=str(address)),
                             headers=headers, stream=request.stream, extensions=extensions)
            try:
                response = self.transports[key].handle_request(pinned)
                response.extensions["scamlens_resolved_ip"] = str(address)
                return response
            except (ConnectError, ConnectTimeout):
                if index == len(addresses) - 1:
                    raise
        raise ConnectError("No validated target address", request=request)

    def close(self):
        for transport in self.transports.values():
            transport.close()
        self.transports.clear()

def make_scan_client(rotate_ua: bool = True) -> Client:
    return Client(
        transport=PinnedTransport(), trust_env=False, follow_redirects=False,
        timeout=Timeout(timeout=client_config["timeout"], connect=client_config["connect"],
                        read=client_config["read"]),
        headers=build_headers(rotate_ua=rotate_ua),
    )
