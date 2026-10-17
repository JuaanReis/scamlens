import ipaddress
import socket
from urllib.parse import urlparse
from plugins.scurl import config, __version__

BLOCKED_RANGES = [ipaddress.ip_network("100.64.0.0/10")]

def _error_response(url, error_type, message):
    return dict(
        status="error",
        meta=dict(url=url, scan_time_s=0, version=__version__),
        error=dict(type=error_type, message=message),
    )

def _is_blocked_ip(ip):
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        return _is_blocked_ip(ip.ipv4_mapped)
    return (
        not ip.is_global
        or ip.is_multicast
        or any(ip in net for net in BLOCKED_RANGES if ip.version == net.version)
    )

def resolve_all(host):
    host = host.rstrip(".").lower()
    if (host == "localhost" or host.endswith((".localhost", ".local"))) and not config[
        "security"
    ]["allow_localhost"]:
        return "localhost", []
    try:
        ips = [ipaddress.ip_address(host)]
    except ValueError:
        try:
            ips = list(
                dict.fromkeys(
                    ipaddress.ip_address(row[4][0])
                    for row in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
                )
            )

        except (OSError, ValueError):
            return "error", []
        
    if not ips:
        return "error", []
    
    if not config["security"]["allow_private_ips"] and any(
        _is_blocked_ip(ip) for ip in ips
    ):
        return "private_ip", []
    
    return None, ips

def resolve_and_validate_host(host):
    reason, ips = resolve_all(host)
    return reason, ips[0] if ips else None

def _url_validator(url):
    if not isinstance(url, str) or not url:
        return _error_response(url, "missing_url", "URL não informada"), None
    
    if len(url) > 2048:
        return _error_response(url, "url_too_long", "URL muito longa"), None
    
    if any(ord(c) < 32 or ord(c) == 127 for c in url) or "\\" in url:
        return _error_response(url, "invalid_url", "Caracteres ambíguos na URL"), None
    
    try:
        parsed = urlparse(url)
        port = parsed.port
        host = parsed.hostname

        if not host:
            raise ValueError("missing host")
        
        host.encode("idna")

    except (ValueError, UnicodeError):
        return _error_response(url, "invalid_host", "Host ou porta inválidos"), None
    
    if parsed.scheme not in ("http", "https"):
        return _error_response(url, "missing_protocol", "Protocolo não permitido"), None
    
    reason, ips = resolve_all(host)
    if reason:
        return (
            _error_response(
                url,
                {
                    "localhost": "localhost_blocked",
                    "private_ip": "private_ip_blocked",
                    "error": "dns_resolution_error",
                }[reason],
                "Destino bloqueado ou não resolvido",
            ),
            None,
        )
    
    return None, ips

def validate_target(ctx):
    error, ips = _url_validator(ctx.target.url)

    if error:
        return error
    
    ctx.meta.resolved_ips = ips
    ctx.meta.resolved_ip = ips[0]
    
    return None
