"""Pure DOM rule. No DNS, ASN, WHOIS or HTTP from a heuristic."""

from plugins.scurl.models.result_base import ResultBase
from plugins.scurl.parsers.resources import external, has_password
from ..registry import register


@register(
    name="external_script",
    category="html",
    severity="low",
    weight=1.0,
    tags=["html", "external", "script"],
)
def external_script(structure):
    tree = structure.get("html_parser")
    if tree is None:
        return ResultBase(0, None, {"error": "HTML não disponível"})
    urls = [
        n.attributes["src"]
        for n in tree.css("script[src]")
        if external(n.attributes["src"], structure)
    ]
    # Merely embedding a different site is routine. Never trust an ASN as ownership.
    score = 0.15 if urls and has_password(tree) else 0.05 if urls else 0
    return ResultBase(
        len(urls),
        score,
        dict(external_script_count=len(urls), samples=urls[:12], network_lookups=0),
    )
