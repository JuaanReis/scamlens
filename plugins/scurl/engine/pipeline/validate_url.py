from urllib.parse import urlparse
from plugins.scurl.models.scan_context import ScanContext
from plugins.scurl import config, __version__
from providers.http.security import (
    BLOCKED_RANGES, _is_blocked_ip, resolve_and_validate_addresses, resolve_and_validate_host,
)

def _error_response(url: str | None, error_type: str, message: str) -> dict:
    return {
        "status": "error",
        "meta": {"url": url, "scan_time_s": 0, "version": __version__},
        "error": {"type": error_type, "message": message},
    }

def _url_validator(url: str):
    if not url:
        return _error_response(None, "missing_url", "URL não informada"), ()
    if len(url) > config["security"]["max_url_length"]:
        return _error_response(url, "url_too_long", "URL muito longa"), ()
    try:
        parsed = urlparse(url)
        port = parsed.port
    except ValueError:
        return _error_response(url, "invalid_host", "Host ou porta inválidos"), ()
    if parsed.scheme not in ("http", "https"):
        return _error_response(url, "missing_protocol", "URL inválida"), ()
    if not parsed.hostname:
        return _error_response(url, "invalid_host", "Host ausente na URL"), ()
    reason, addresses = resolve_and_validate_addresses(parsed.hostname)
    errors = {
        "localhost": ("localhost_blocked", "Acesso a localhost não permitido"),
        "private_ip": ("private_ip_blocked", "Acesso a IPs privados não permitido"),
        "error": ("dns_resolution_error", "Não foi possível resolver o host"),
    }
    if reason:
        error_type, message = errors[reason]
        return _error_response(url, error_type, message), ()
    return None, addresses

def validate_target(ctx: ScanContext) -> dict | None:
    error, addresses = _url_validator(ctx.target.url)
    if error:
        return error
    ctx.meta.resolved_addresses = addresses
    ctx.meta.resolved_ip = addresses[0]
    return None
