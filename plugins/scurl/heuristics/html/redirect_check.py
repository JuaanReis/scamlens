import re
from plugins.scurl.models.result_base import ResultBase
from plugins.scurl.parsers.resources import external
from ..registry import register

JS_ASSIGNMENT_PATTERN = re.compile(
    r'(?:(?:window\.)?location(?:\.href)?\s*=\s*|(?:window\.)?location\.(?:replace|assign)\s*\(\s*)["\']([^"\']+)["\']'
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

    redirects = []

    for meta in tree.css('meta[http-equiv="refresh"]'):
        content = meta.attributes.get("content", "")
        if "url=" in content.lower():
            url_part = re.split("url=", content, flags=re.I)[-1].strip().strip("\"'")
            if external(url_part, structure):
                redirects.append({"type": "meta_refresh", "target": url_part})

    for script in tree.css("script"):
        text = script.text() or ""
        for match in JS_ASSIGNMENT_PATTERN.finditer(text):
            target = match.group(1)
            if external(target, structure):
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
