from plugins.scurl.models.scan_context import ScanContext
import ipaddress
import socket
from urllib.parse import urlparse
from plugins.scurl import config, __version__

BLOCKED_RANGES: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = [
    ipaddress.ip_network("0.0.0.0/8"),       
    ipaddress.ip_network("100.64.0.0/10"),    
    ipaddress.ip_network("169.254.0.0/16"),  
    ipaddress.ip_network("192.0.2.0/24"),       
    ipaddress.ip_network("198.51.100.0/24"),    
    ipaddress.ip_network("203.0.113.0/24"),     
    ipaddress.ip_network("240.0.0.0/4"),         
    ipaddress.ip_network("::ffff:0:0/96"),      
]

def _error_response(url: str | None, error_type: str, message: str) -> dict:
    return {
        "status": "error",
        "meta": {"url": url, "scan_time_s": 0, "version": __version__},
        "error": {"type": error_type, "message": message},
    }

def _is_blocked_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """
    Retorna True se o IP for considerado bloqueado.

    Cobre:
    - Loopback, link-local e privado (via flags nativas do Python)
    - IPv4-mapped IPv6 (ex: ::ffff:127.0.0.1) — desempacota e reavalia
    - Ranges adicionais não cobertos pelo Python < 3.11
    """
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        return _is_blocked_ip(ip.ipv4_mapped)

    if ip.is_private or ip.is_loopback or ip.is_link_local:
        return True

    return any(ip in r for r in BLOCKED_RANGES)

def resolve_and_validate_host(host: str) -> tuple[str | None, ipaddress.IPv4Address | ipaddress.IPv6Address | None]:
    """
    Resolve o hostname para IP e valida se é seguro.

    Retorna:
        (None, ip)         → host resolvido e seguro
        ("localhost", None) → bloqueado como localhost
        ("private_ip", None) → bloqueado como IP privado
        ("error", None)    → falha na resolução DNS
    """
    localhost_strings = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}
    if host in localhost_strings or host.endswith(".local"):
        if not config.get("security", {}).get("allow_localhost", False):
            return "localhost", None

    try:
        ip = ipaddress.ip_address(host)
        if _is_blocked_ip(ip) and not config.get("security", {}).get("allow_private_ips", False):
            return "private_ip", None
        return None, ip
    except ValueError:
        pass

    try:
        resolved = socket.gethostbyname(host)
        ip = ipaddress.ip_address(resolved)
        if _is_blocked_ip(ip) and not config.get("security", {}).get("allow_private_ips", False):
            return "private_ip", None
        return None, ip
    except socket.gaierror:
        return "error", None
    except Exception:
        return "error", None

def _url_validator(url: str) -> tuple[dict | None, ipaddress.IPv4Address | ipaddress.IPv6Address | None]:
    """
    Valida a URL e retorna (erro, ip_resolvido).

    O IP resolvido é retornado quando válido para que o collect step
    possa fixá-lo na requisição, prevenindo DNS rebinding.
    """
    if not url:
        return _error_response(None, "missing_url", "URL não informada"), None

    if len(url) > 2048:
        return _error_response(url, "url_too_long", "URL muito longa"), None

    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https"):
        return _error_response(url, "missing_protocol", "URL inválida"), None

    host = parsed.hostname
    if not host:
        return _error_response(url, "invalid_host", "Host ausente na URL"), None

    block_reason, resolved_ip = resolve_and_validate_host(host)

    if block_reason == "localhost":
        return _error_response(url, "localhost_blocked", "Acesso a localhost não permitido"), None

    if block_reason == "private_ip":
        return _error_response(url, "private_ip_blocked", "Acesso a IPs privados não permitido"), None

    if block_reason == "error":
        return _error_response(url, "dns_resolution_error", "Não foi possível resolver o host"), None

    return None, resolved_ip

def validate_target(ctx: ScanContext) -> dict | None:
    """
    Valida a URL de entrada e armazena o IP resolvido no contexto.

    O IP é salvo em ctx.meta para uso posterior no collect step,
    prevenindo DNS rebinding entre a validação e a requisição HTTP.

    Retorna:
        None           → URL válida, pipeline pode continuar
        dict           → erro, pipeline deve abortar
    """

    error, resolved_ip = _url_validator(ctx.target.url)

    if error:
        return error

    ctx.meta.resolved_ip = resolved_ip

    return None