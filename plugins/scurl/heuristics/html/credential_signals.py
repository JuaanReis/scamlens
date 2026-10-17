import re
from urllib.parse import urlparse
from plugins.scurl.models.result_base import ResultBase
from plugins.scurl.parsers.resources import has_password, external, destination
from ..registry import register


@register(
    name="credential_cleartext",
    category="html",
    severity="high",
    weight=4.0,
    tags=["credentials", "transport"],
)
def credential_cleartext(structure):
    tree = structure.get("html_parser")
    if tree is None:
        return ResultBase(0, None, {"error": "HTML não disponível"})
    insecure = has_password(tree) and structure.get("scheme") == "http"
    for form in tree.css("form"):
        action = form.attributes.get("action", "")
        parsed = destination(action, structure) if action else None
        insecure = insecure or (
            has_password(form) and parsed is not None and parsed.scheme == "http"
        )
    return ResultBase(
        int(bool(insecure)),
        1.0 if insecure else 0,
        {"password_over_cleartext": bool(insecure)},
    )


@register(
    name="credential_exfiltration",
    category="html",
    severity="high",
    weight=4.0,
    tags=["credentials", "javascript"],
)
def credential_exfiltration(structure):
    tree = structure.get("html_parser")
    if tree is None:
        return ResultBase(0, None, {"error": "HTML não disponível"})
    findings = []
    if has_password(tree):
        for script in tree.css("script:not([src])"):
            text = script.text() or ""
            # Require credential reference + outgoing request + a foreign URL in the same script.
            if not re.search(
                r"password|passwd|credential", text, re.I
            ) or not re.search(
                r"fetch\s*\(|XMLHttpRequest|sendBeacon\s*\(", text, re.I
            ):
                continue
            for url in re.findall(r"https?://[^\s\"\'<>]+", text):
                if external(url, structure):
                    findings.append(url[:300])
    return ResultBase(
        len(findings),
        1.0 if findings else 0,
        dict(cooccurrence_only=True, external_targets=findings[:12]),
    )


@register(
    name="misleading_link",
    category="html",
    severity="medium",
    weight=2.0,
    tags=["deception", "links"],
)
def misleading_link(structure):
    tree = structure.get("html_parser")
    if tree is None:
        return ResultBase(0, None, {"error": "HTML não disponível"})
    from providers.domain.structure import same_owner

    hits = []
    for anchor in tree.css("a[href]"):
        displayed = anchor.text().strip()
        if not displayed.startswith(("https://", "http://")):
            continue
        try:
            shown = urlparse(displayed).hostname
            actual = destination(anchor.attributes["href"], structure)
        except ValueError:
            continue
        if (
            shown
            and actual
            and actual.hostname
            and not same_owner(shown, actual.hostname)
        ):
            hits.append(dict(displayed=displayed[:200], target=actual.hostname))
    return ResultBase(len(hits), 0.7 if hits else 0, dict(mismatched_links=hits[:12]))
