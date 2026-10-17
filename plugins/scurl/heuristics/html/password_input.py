from plugins.scurl.models.result_base import ResultBase
from plugins.scurl.parsers.resources import has_password
from ..registry import register


@register(
    name="password_input_check",
    category="html",
    severity="low",
    weight=0.5,
    tags=["html", "password", "login"],
)
def password_input_check(structure):
    tree = structure.get("html_parser")
    if tree is None:
        return ResultBase(0, None, {"error": "HTML não disponível"})
    count = sum(
        n.attributes.get("type", "").lower() == "password" for n in tree.css("input")
    )
    return ResultBase(
        count,
        0,
        dict(
            has_password_input=bool(count),
            password_input_count=count,
            context_only=True,
        ),
    )
