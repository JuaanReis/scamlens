import re
import socket
from urllib.parse import urlparse
from ipwhois import IPWhois
from plugins.scurl.models.result_base import ResultBase
from plugins.scurl.parsers.html_parser import HTMLParser
from plugins.scurl.parsers.normalize_domain import normalize_domain
from ..registry import register
import sys
TRUSTED_DOMAINS = {normalize_domain(d) for d in {
    "cdn.jsdelivr.net", "cdnjs.cloudflare.com", "ajax.googleapis.com",
    "code.jquery.com", "stackpath.bootstrapcdn.com", "unpkg.com",
    "fonts.googleapis.com", "fonts.gstatic.com",
    "static.cloudflareinsights.com", "www.googletagmanager.com",
    "googletagmanager.com", "www.google-analytics.com", "google-analytics.com",
    "www.google.com", "recaptcha.google.com", "google.com",
    "cloudfront.net",
}}

TRUSTED_ASNS: dict[str, str] = {
    "13335":  "Cloudflare",
    "209242": "Cloudflare",
    "14061":  "DigitalOcean",
    "16509":  "Amazon AWS",
    "14618":  "Amazon AWS",
    "15169":  "Google",
    "396982": "Google Cloud",
    "8075":   "Microsoft Azure",
    "8068":   "Microsoft",
    "20940":  "Akamai",
    "16625":  "Akamai",
    "54113":  "Fastly",
    "22822":  "Limelight",
    "21501":  "GoDaddy",
    "398101": "GoDaddy",
    "46606":  "Unified Layer / Hostgator",
    "19871":  "Network Solutions",
    "26347":  "DreamHost",
    "55293":  "A2 Hosting",
    "40034":  "Contabo",
    "28573":  "Claro Brasil",
    "18881":  "Vivo / Telefonica Brasil",
    "7738":   "Telemar / Oi",
    "16735":  "Algar Telecom",
    "53006":  "Algar Telecom",
    "52925":  "Locaweb",
    "27715":  "Locaweb",
    "262965": "Hostgator Brasil",
    "263576": "UOL Host",
}

RESOURCE_CATEGORY = {
    "cdn":       {normalize_domain(d) for d in {
                    "cdn.jsdelivr.net", "cdnjs.cloudflare.com", "unpkg.com",
                    "stackpath.bootstrapcdn.com", "code.jquery.com"}},
    "analytics": {normalize_domain(d) for d in {
                    "www.googletagmanager.com", "googletagmanager.com",
                    "www.google-analytics.com", "google-analytics.com",
                    "static.cloudflareinsights.com"}},
    "font":      {normalize_domain(d) for d in {
                    "fonts.googleapis.com", "fonts.gstatic.com"}},
    "captcha":   {normalize_domain(d) for d in {
                    "www.google.com", "recaptcha.google.com", "google.com"}},
}

HARVEST_PATTERNS = [
    re.compile(r'fetch\s*\('),
    re.compile(r'XMLHttpRequest'),
    re.compile(r'\.open\s*\(\s*["\']POST'),
    re.compile(r'form\.submit\s*\('),
    re.compile(r'addEventListener\s*\(\s*["\']submit'),
    re.compile(r'FormData\s*\('),
]

_asn_cache: dict[str, str | None] = {}

def _get_asn(domain: str) -> str | None:
    norm = normalize_domain(domain)
    if norm in _asn_cache:
        return _asn_cache[norm]
    try:
        ip = socket.gethostbyname(norm)
        asn = IPWhois(ip).lookup_rdap(depth=1).get("asn")
        _asn_cache[norm] = asn
        return asn
    except Exception:
        _asn_cache[norm] = None
        return None

def _is_trusted_asn(domain: str) -> bool:
    asn = _get_asn(domain)
    return asn is not None and asn in TRUSTED_ASNS

def _categorize(domain: str) -> str:
    norm = normalize_domain(domain)
    for category, domains in RESOURCE_CATEGORY.items():
        if any(norm.endswith(d) for d in domains):
            return category
    asn = _get_asn(norm)
    if asn and asn in TRUSTED_ASNS:
        return f"trusted_cdn ({TRUSTED_ASNS[asn]})"
    return "unknown"

def _detect_harvest(tree: HTMLParser, external_domains: set[str]) -> list[str]:
    findings = []
    for script in tree.css("script:not([src])"):
        text = script.text() or ""
        has_harvest = any(p.search(text) for p in HARVEST_PATTERNS)
        if not has_harvest:
            continue
        for domain in external_domains:
            if normalize_domain(domain) in text:
                findings.append(domain)
    return findings

@register(name="external_script", category="html", severity="medium", weight=3.0, tags=["html", "external", "script"])
def external_script(structure: dict) -> ResultBase:
    tree = structure.get("html_parser")
    if tree is None:
        return ResultBase(
            value=0,
            normalized=None,
            details={"error": "HTML não disponível"}
        )

    original_domain = normalize_domain(structure.get("hostname", ""))
    page_asn = _get_asn(original_domain)

    scripts = tree.css('script[src]')
    external_scripts   = []
    suspicious_scripts = []
    domain_categories  = {}
    external_domains   = set()

    for script in scripts:
        src = script.attributes.get('src', '')
        if not src:
            continue
        parsed = urlparse(src)
        script_domain = normalize_domain(parsed.netloc)
        if not script_domain or script_domain == original_domain:
            continue

        external_scripts.append(src)
        external_domains.add(script_domain)

        if any(script_domain.endswith(t) for t in TRUSTED_DOMAINS):
            domain_categories[script_domain] = _categorize(script_domain)
            continue

        if _is_trusted_asn(script_domain):
            domain_categories[script_domain] = _categorize(script_domain)
            continue

        if _is_trusted_asn(script_domain):
            domain_categories[script_domain] = _categorize(script_domain)
            continue

        script_asn = _get_asn(script_domain)
        if page_asn and script_asn and page_asn == script_asn:
            domain_categories[script_domain] = "same_infra"
            continue

        domain_categories[script_domain] = "unknown"
        suspicious_scripts.append(src)

    unique_external = len(external_domains)
    harvest_domains = _detect_harvest(tree, external_domains)

    has_suspicious = len(suspicious_scripts) > 0
    has_harvest    = len(harvest_domains) > 0

    if has_harvest:
        score = 1.0
    elif has_suspicious:
        ratio = min(len(suspicious_scripts) / max(len(external_scripts), 1), 1.0)
        score = 0.5 + 0.5 * ratio
    else:
        score = 0.0

    return ResultBase(
        value=score,
        normalized=score if score > 0 else None,
        details={
            "has_suspicious_external_script": has_suspicious,
            "external_script_count": len(external_scripts),
            "suspicious_script_count": len(suspicious_scripts),
            "unique_external_domains": unique_external,
            "domain_categories": domain_categories,
            "suspicious_scripts": suspicious_scripts,
            "harvest_detected": has_harvest,
            "harvest_domains": harvest_domains,
        }
    )