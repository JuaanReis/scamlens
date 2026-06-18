from urllib.parse import urlparse
from plugins.scurl.models.result_base import ResultBase
from plugins.scurl.parsers.normalize_domain import normalize_domain
import tldextract
from ..registry import register

def same_owner(domain_a: str, domain_b: str) -> bool:
    a = tldextract.extract(domain_a)
    b = tldextract.extract(domain_b)
    return a.domain == b.domain and a.suffix == b.suffix

@register(name="favicon_check", category="html", severity="low", weight=2.0, tags=["html", "favicon"])
def favicon_check(structure: dict) -> ResultBase:
    tree = structure.get("html_parser")
    if tree is None:
        return ResultBase(
            value=0,
            normalized=None,
            details={"error": "HTML não disponível"}
        )
 
    original_domain = structure.get("hostname", "")
 
    favicon = (
        tree.css_first('link[rel="icon"]') or
        tree.css_first('link[rel="shortcut icon"]') or
        tree.css_first('link[rel="apple-touch-icon"]')
    )
 
    if favicon is None:
        return ResultBase(
            value=0.0,
            normalized=None,
            details={"favicon_found": False}
        )
 
    href = favicon.attributes.get("href", "")
    parsed = urlparse(href)
    is_external = not same_owner(normalize_domain(parsed.netloc), normalize_domain(original_domain))
 
    return ResultBase(
        value=1.0 if is_external else 0.0,
        normalized=1.0 if is_external else None,
        details={
            "favicon_found": True,
            "favicon_url": href,
            "favicon_domain": parsed.netloc or original_domain,
            "is_external_favicon": is_external
        }
    )
