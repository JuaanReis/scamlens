from plugins.scurl.models.result_base import ResultBase
from plugins.scurl.parsers.resources import external
from providers.domain.structure import same_owner
from ..registry import register


@register(
    name="favicon_check",
    category="html",
    severity="low",
    weight=0.5,
    tags=["html", "favicon"],
)
def favicon_check(structure):
    tree = structure.get("html_parser")
    if tree is None:
        return ResultBase(0, None, {"error": "HTML não disponível"})
    node = tree.css_first('link[rel~="icon"]') or tree.css_first(
        'link[rel="apple-touch-icon"]'
    )
    href = node.attributes.get("href", "") if node else ""
    outside = bool(href and external(href, structure))
    return ResultBase(
        int(outside),
        0.15 if outside else 0,
        dict(favicon_found=bool(node), favicon_url=href, is_external_favicon=outside),
    )
