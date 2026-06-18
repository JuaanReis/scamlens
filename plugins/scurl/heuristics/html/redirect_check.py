import re
from urllib.parse import urlparse
from plugins.scurl.models.result_base import ResultBase
from plugins.scurl.parsers.normalize_domain import normalize_domain
from ..registry import register

JS_ASSIGNMENT_PATTERN = re.compile(
    r'(?:window\.location|window\.location\.href|location\.replace\s*\()\s*=\s*["\']([^"\']+)["\']'
)

@register(name="redirect_check", category="html", severity="high", weight=3.0, tags=["html", "redirect", "phishing"])
def redirect_check(structure: dict) -> ResultBase:
    tree = structure.get("html_parser")
    if tree is None:
        return ResultBase(
            value=0,
            normalized=None,
            details={
                "error": "HTML não disponível"
            }
        )

    original_domain = structure.get("hostname", "")
    redirects = []

    for meta in tree.css('meta[http-equiv="refresh"]'):
        content = meta.attributes.get("content", "")
        if "url=" in content.lower():
            url_part = content.lower().split("url=")[-1].strip()
            parsed = urlparse(url_part)
            if parsed.netloc and normalize_domain(parsed.netloc) != normalize_domain(original_domain):
                redirects.append({"type": "meta_refresh", "target": url_part})

    for script in tree.css("script"):
        text = script.text() or ""
        for match in JS_ASSIGNMENT_PATTERN.finditer(text):
            target = match.group(1)
            parsed = urlparse(target)
            if parsed.netloc and normalize_domain(parsed.netloc) != normalize_domain(original_domain):
                redirects.append({"type": "js_redirect", "target": target})

    has_redirect = len(redirects) > 0

    return ResultBase(
        value=1.0 if has_redirect else 0.0,
        normalized=1.0 if has_redirect else None,
        details={
            "has_external_redirect": has_redirect,
            "redirect_count": len(redirects),
            "redirects": redirects
        }
    )