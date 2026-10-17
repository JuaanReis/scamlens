from plugins.scurl.models.result_base import ResultBase
from plugins.scurl.parsers.resources import (
    destination,
    external,
    has_password,
    page_url,
)
from ..registry import register


@register(
    name="form_action_check",
    category="html",
    severity="high",
    weight=4.0,
    tags=["html", "form", "phishing"],
)
def form_action_check(structure):
    tree = structure.get("html_parser")
    if tree is None:
        return ResultBase(0, None, {"error": "HTML não disponível"})
    findings = []
    credential = False
    for form in tree.css("form"):
        action = form.attributes.get("action") or ""
        # Missing/empty action submits to the document URL, not an external base.
        if not action.strip():
            continue
        if external(action, structure):
            findings.append(action)
            credential = credential or has_password(form)
    score = 1.0 if credential else 0.2 if findings else 0
    return ResultBase(
        len(findings),
        score,
        dict(
            has_external_form_action=bool(findings),
            credential_form=credential,
            external_actions=findings[:12],
            form_count=len(tree.css("form")),
        ),
    )
