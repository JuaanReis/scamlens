from plugins.scurl.models.result_base import ResultBase
from plugins.scurl.parsers.resources import external
from ..registry import register

@register(name="form_action_check", category="html", severity="high", weight=3.0, tags=["html", "form", "phishing"])
def form_action_check(structure: dict) -> ResultBase:
    tree = structure.get("html_parser")
    if tree is None:
        return ResultBase(
            value=0,
            normalized=None,
            details={
                "error": "HTML não disponível"
            }
        )
 
    forms = tree.css('form')
    external_actions = []
 
    for form in forms:
        action = form.attributes.get('action', '')
        if not action:
            continue
        if external(action, structure):
            external_actions.append(action)
 
    has_external_action = len(external_actions) > 0
 
    return ResultBase(
        value=1.0 if has_external_action else 0.0,
        normalized=1.0 if has_external_action else None,
        details={
            "has_external_form_action": has_external_action,
            "form_count": len(forms),
            "external_actions": external_actions
        }
    )
