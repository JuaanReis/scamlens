from plugins.scurl.models.result_base import ResultBase
from ..registry import register

@register(name="missing_form_tag", category="html", severity="medium", weight=2.0, tags=["html", "form", "phishing"])
def missing_form_tag(structure: dict) -> ResultBase:
    tree = structure.get("html_parser")
    if tree is None:
        return ResultBase(value=0, normalized=None, details={"error": "HTML não disponível"})

    inputs = tree.css("input[type='email'], input[type='password'], input[type='text']")
    forms = tree.css("form")

    input_count = len(inputs)
    form_count = len(forms)
    suspicious = input_count > 0 and form_count == 0

    return ResultBase(
        value=1.0 if suspicious else 0.0,
        normalized=1.0 if suspicious else None,
        details={
            "input_count": input_count,
            "form_count": form_count,
            "suspicious": suspicious
        }
    )