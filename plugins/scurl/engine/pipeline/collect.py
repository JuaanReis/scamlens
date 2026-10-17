from concurrent.futures import ThreadPoolExecutor
from time import perf_counter
from urllib.parse import urlparse, urljoin, urlunparse
from plugins.scurl.engine.pipeline.validate_response import response_validator
from plugins.scurl.engine.pipeline.target_structure import get_structure
from plugins.scurl.parsers.html_parser import parse_html
from plugins.scurl.engine.pipeline.validate_url import resolve_and_validate_host
from providers.http.connect import request
from providers.rdap.fetch_rdap import fetch_rdap
from providers.safebrowsing.client import fetch_safe_browsing
from providers.ssl.info_ssl import get_ssl_cert
from providers.dns.info_dns import get_dns_info
from plugins.scurl import config

MAX_REDIRECTS = config["scanner"].get("max_redirects", 10)

def _network_url(url):
    parsed = urlparse(url)
    authority = parsed.netloc.rsplit("@", 1)[-1]
    return urlunparse(parsed._replace(netloc=authority, fragment=""))

def _is_safe_redirect(location):
    try:
        parsed = urlparse(location)
        _ = parsed.port
        if (
            parsed.scheme not in ("http", "https")
            or not parsed.hostname
            or "\\" in location
        ):
            return False
        reason, _ = resolve_and_validate_host(parsed.hostname)
        return reason is None
    except (ValueError, UnicodeError):
        return False

def _fetch_with_redirect_guard(url, timeout, retries):
    current_url = _network_url(url)
    chain = []
    seen = set()
    elapsed = 0.0

    for hop in range(MAX_REDIRECTS + 1):
        if current_url in seen:
            return None
        
        seen.add(current_url)
        parsed = urlparse(current_url)
        reason, address = resolve_and_validate_host(parsed.hostname)

        if reason is not None:
            return None
        
        response = request(
            method="GET",
            url=current_url,
            timeout=timeout,
            retries=retries,
            allow_redirects=False,
            resolved_ip=str(address),
        )

        if response is None:
            return None
        
        response.resolved_ip = str(address)
        elapsed += response.elapsed
        location = response.headers.get("location", "").strip()
        chain.append(
            dict(url=current_url, status=response.status, location=location or None)
        )

        if response.status not in (301, 302, 303, 307, 308) or not location:
            response.redirects = hop
            response.redirect_chain = chain
            response.elapsed = elapsed
            return response
        
        location = urljoin(current_url, location)
        if hop >= MAX_REDIRECTS or not _is_safe_redirect(location):
            return None
        
        current_url = _network_url(location)

    return None

def collect_target_data(ctx, timeout=5, retries=3, processors=2):
    ctx.target.structure = get_structure(ctx.target.url)
    workers = max(1, min(int(processors), 2))

    def timed(name, fn, *args, **kw):
        start = perf_counter()
        try:
            return fn(*args, **kw)
        except Exception as exc:
            ctx.warnings.append(name + " unavailable (" + type(exc).__name__ + ")")
            return None
        finally:
            ctx.meta.timings[name + "_s"] = perf_counter() - start

    with ThreadPoolExecutor(max_workers=workers) as executor:
        http_future = executor.submit(
            timed, "http", _fetch_with_redirect_guard, ctx.target.url, timeout, retries
        )

        response = http_future.result()
        ctx.target.response = response
        if response is None:
            return response_validator(response, ctx.target.url, ctx.meta.start)
        
        ctx.target.final_structure = get_structure(response.url)

        final = ctx.target.final_structure
        checked_urls = list(
            dict.fromkeys(
                [_network_url(ctx.target.url)]
                + [hop["url"] for hop in response.redirect_chain or []]
                + [response.url]
            )
        )

        reputation = executor.submit(
            timed, "safe_browsing", fetch_safe_browsing, checked_urls
        )

        dns_future = executor.submit(
            timed,
            "dns",
            get_dns_info,
            final.get("hostname", ""),
            timeout=min(timeout, 2),
        )

        tls_future = executor.submit(
            timed,
            "tls",
            get_ssl_cert,
            final,
            timeout=min(timeout, 3),
            resolved_ip=getattr(response, "resolved_ip", None),
        )

        rdap_future = executor.submit(
            timed, "rdap", fetch_rdap, final.get("hostname", "")
        )

        ctx.target.safe_browsing = reputation.result()
        ctx.target.dns = dns_future.result()
        ctx.target.ssl = tls_future.result()
        ctx.target.rdap = rdap_future.result()

    ctx.meta.threads = workers
    ctx.target.size_kb = round(response.size / 1024, 2)

    if response.body and "html" in response.headers.get("content-type", "").lower():
        ctx.target.html = parse_html(response.body)

    if getattr(response, "truncated", False):
        ctx.warnings.append("HTTP body truncated; coverage reduced")

    if ctx.target.dns and ctx.target.dns.get("errors"):
        ctx.warnings.append("DNS records partially unavailable")

    if ctx.target.ssl and any(
        ctx.target.ssl.get(k)
        for k in ("timeout", "unknown", "connection_error", "dns_error")
    ):
        ctx.warnings.append("TLS metadata unavailable")

    if ctx.target.rdap is None:
        ctx.warnings.append("RDAP unavailable")

    if response.status >= 400:
        ctx.warnings.append(
            "HTTP status "
            + str(response.status)
            + "; content may be an error/challenge page"
        )

    return None
