from plugins.scurl.models.result_base import ResultBase
from ..registry import register

@register(name="password_input_check", category="html", severity="medium", weight=3.0, tags=["html", "password", "login"])
def password_input_check(structure: dict) -> ResultBase:
    tree = structure.get("html_parser")
    if tree is None:
        return ResultBase(
            value=0,
            normalized=None,
            details={"error": "HTML não disponível"}
        )
 
    password_inputs = tree.css('input[type="password"]')
    has_password = len(password_inputs) > 0
 
    return ResultBase(
        value=1.0 if has_password else 0.0,
        normalized=1.0 if has_password else None,
        details={
            "has_password_input": has_password,
            "password_input_count": len(password_inputs)
        }
    )