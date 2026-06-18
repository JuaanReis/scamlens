from plugins.scurl.models.result_base import ResultBase
from ..registry import register

HIDDEN_FIELD_THRESHOLD = 10
HIDDEN_FIELD_MIN = 4

@register(name="hidden_fields_check", category="html", severity="medium", weight=2.0, tags=["html", "form", "hidden"])
def hidden_fields_check(structure: dict) -> ResultBase:
    tree = structure.get("html_parser")
    if tree is None:
        return ResultBase(
            value=0,
            normalized=None,
            details={
                "error": "HTML não disponível"
            }
        )
 
    hidden_inputs = tree.css('input[type="hidden"]')
    count = len(hidden_inputs)
    
    if count <= HIDDEN_FIELD_MIN:
        normalized = None
    else:
        normalized = min((count - HIDDEN_FIELD_MIN) / (HIDDEN_FIELD_THRESHOLD - HIDDEN_FIELD_MIN), 1.0)
 
    return ResultBase(
        value=float(count),
        normalized=normalized,
        details={
            "hidden_field_count": count,
            "threshold": HIDDEN_FIELD_THRESHOLD,
            "above_threshold": count >= HIDDEN_FIELD_THRESHOLD
        }
    )