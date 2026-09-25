from plugins.scurl.models.scan_context import ScanContext
from plugins.scurl.engine.pipeline.validate_response import response_validator
from plugins.scurl.engine.pipeline.target_structure import get_structure
from providers.http.connect import request
from providers.rdap.fetch_rdap import fetch_rdap
from plugins.scurl.parsers.html_parser import parse_html
from providers.safebrowsing.client import fetch_safe_browsing
from providers.ssl.info_ssl import get_ssl_cert
from providers.dns.info_dns import get_dns_info
from plugins.scurl.engine.pipeline.validate_url import resolve_and_validate_host
from urllib.parse import urlparse
from plugins.scurl import config

MAX_REDIRECTS = config["scanner"]["max_redirects"]

def _is_safe_redirect(location: str) -> bool:
    parsed = urlparse(location)

    if parsed.scheme not in ("http", "https"):
        return False

    host = parsed.hostname
    if not host:
        return False

    block_reason, _ = resolve_and_validate_host(host)
    return block_reason is None

def _fetch_with_redirect_guard(url: str, timeout: float, retries: int) -> object:
    current_url = url
    hops = 0

    while hops < MAX_REDIRECTS:
        response = request(
            method="GET",
            url=current_url,
            timeout=timeout,
            retries=retries,
            allow_redirects=False,
        )

        if response is None:
            return None

        if response.status not in (301, 302, 303, 307, 308):
            return response

        location = response.headers.get("location", "").strip()
        if not location:
            return response

        if location.startswith("/"):
            parsed_current = urlparse(current_url)
            location = f"{parsed_current.scheme}://{parsed_current.netloc}{location}"

        if not _is_safe_redirect(location):
            logger_msg = f"Redirect bloqueado: {current_url} -> {location}"
            return None

        current_url = location
        hops += 1

    return None

def collect_target_data(ctx: ScanContext, timeout: float = 5, retries: int = 3) -> dict | None:
    structure = get_structure(ctx.target.url)
    ctx.target.structure = structure
    ctx.target.safe_browsing = fetch_safe_browsing(ctx.target.url)

    response = _fetch_with_redirect_guard(
        url=ctx.target.url,
        timeout=timeout,
        retries=retries,
    )

    ctx.target.response = response
    ctx.target.size_kb = round(response.size / 1024, 2) if response else 0

    if response and response.body:
        content_type = response.headers.get("content-type", "")
        if "html" in content_type.lower():
            ctx.target.html = parse_html(response.body)

    ctx.target.dns = get_dns_info(structure.get("hostname", ""))
    ctx.target.ssl = get_ssl_cert(structure)
    ctx.target.rdap = fetch_rdap(structure.get("hostname", ""))

    return response_validator(response, ctx.target.url, ctx.meta.start)