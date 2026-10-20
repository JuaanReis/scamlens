from plugins.scurl.models.result_base import ResultBase
from plugins.scurl.parsers.resources import external, destination
from ..registry import register

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
    parsed = destination(href, structure)
    is_external = external(href, structure)
 
    return ResultBase(
        value=1.0 if is_external else 0.0,
        normalized=1.0 if is_external else None,
        details={
            "favicon_found": True,
            "favicon_url": href,
            "favicon_domain": parsed.hostname if parsed else original_domain,
            "is_external_favicon": is_external
        }
    )
