from urllib.parse import urlparse, urljoin
from plugins.scurl.models.scan_context import ScanContext
from plugins.scurl.engine.pipeline.validate_response import response_validator
from plugins.scurl.engine.pipeline.target_structure import get_structure
from providers.http.connect import request
from providers.http.client import make_scan_client
from providers.http.security import resolve_and_validate_addresses
from providers.rdap.fetch_rdap import fetch_rdap
from plugins.scurl.parsers.html_parser import parse_html
from providers.safebrowsing.client import fetch_safe_browsing
from providers.ssl.info_ssl import get_ssl_cert
from providers.dns.info_dns import get_dns_info
from plugins.scurl import config

MAX_REDIRECTS = config["scanner"]["max_redirects"]

def _redirect_addresses(location):
    try:
        parsed = urlparse(location)
        port = parsed.port
    except ValueError:
        return ()
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return ()
    reason, addresses = resolve_and_validate_addresses(parsed.hostname)
    return addresses if reason is None else ()

def _is_safe_redirect(location: str) -> bool:
    return bool(_redirect_addresses(location))

def _fetch_with_redirect_guard(url: str, timeout: float, retries: int, addresses=None):
    current_url = url
    chain = []
    seen = set()
    with make_scan_client() as client:
        for hops in range(MAX_REDIRECTS + 1):
            if current_url in seen:
                return None
            seen.add(current_url)
            approved = addresses if hops == 0 and addresses else _redirect_addresses(current_url)
            if not approved:
                return None
            response = request(
                method="GET", url=current_url, timeout=timeout, retries=retries,
                allow_redirects=False, client=client, addresses=approved,
            )
            if response is None:
                return None
            chain.append({"url": current_url, "status": response.status,
                          "location": response.headers.get("location")})
            response.redirects = hops
            response.redirect_chain = chain
            if response.status not in (301, 302, 303, 307, 308):
                return response
            location = response.headers.get("location", "").strip()
            if not location:
                return response
            current_url = urljoin(current_url, location)
    return None

def collect_target_data(ctx: ScanContext, timeout: float = 5, retries: int = 3) -> dict | None:
    structure = get_structure(ctx.target.url)
    ctx.target.structure = structure
    ctx.target.safe_browsing = fetch_safe_browsing(ctx.target.url)
    response = _fetch_with_redirect_guard(
        ctx.target.url, timeout, retries, addresses=ctx.meta.resolved_addresses,
    )
    ctx.target.response = response
    ctx.target.size_kb = round(response.size / 1024, 2) if response else 0
    if error := response_validator(response, ctx.target.url, ctx.meta.start):
        return error
    structure = get_structure(response.url)
    ctx.target.structure = structure
    if response.body and "html" in response.headers.get("content-type", "").lower():
        ctx.target.html = parse_html(response.body)
    ctx.target.dns = get_dns_info(structure.get("hostname", ""))
    ctx.target.ssl = get_ssl_cert(structure, response.resolved_ip)
    ctx.target.rdap = fetch_rdap(structure.get("hostname", ""))
    return None
