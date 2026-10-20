import re
from urllib.parse import urlparse
from plugins.scurl.models.result_base import ResultBase
from plugins.scurl.parsers.resources import has_password, external, destination
from providers.domain.structure import same_owner
from ..registry import register


@register(name="credential_cleartext", category="html", severity="high", weight=4.0, tags=["credentials", "transport"])
def credential_cleartext(structure: dict) -> ResultBase:
    """Verifica se campos de senha usam transporte HTTP."""
    tree = structure.get("html_parser")
    if tree is None:
        return ResultBase(value=0, normalized=None, details={"error": "HTML não disponível"})
    insecure = has_password(tree) and structure.get("scheme") == "http"
    for form in tree.css("form"):
        action = form.attributes.get("action", "")
        parsed = destination(action, structure) if action else None
        insecure = insecure or (
            has_password(form) and parsed is not None and parsed.scheme == "http"
        )
    return ResultBase(
        value=int(bool(insecure)),
        normalized=1.0 if insecure else 0,
        details={"password_over_cleartext": bool(insecure)},
    )


@register(name="credential_exfiltration", category="html", severity="high", weight=4.0, tags=["credentials", "javascript"])
def credential_exfiltration(structure: dict, max_findings: int = 12, max_url_length: int = 300) -> ResultBase:
    """Procura referências a credenciais e envio externo no mesmo script."""
    tree = structure.get("html_parser")
    if tree is None:
        return ResultBase(value=0, normalized=None, details={"error": "HTML não disponível"})
    findings = []
    if has_password(tree):
        for script in tree.css("script:not([src])"):
            text = script.text() or ""
            if not re.search(
                r"password|passwd|credential", text, re.I
            ) or not re.search(
                r"fetch\s*\(|XMLHttpRequest|sendBeacon\s*\(", text, re.I
            ):
                continue
            for url in re.findall(r"https?://[^\s\"\'<>]+", text):
                if external(url, structure):
                    findings.append(url[:max_url_length])
    return ResultBase(
        value=len(findings),
        normalized=1.0 if findings else 0,
        details={"cooccurrence_only": True, "external_targets": findings[:max_findings]},
    )


@register(name="misleading_link", category="html", severity="medium", weight=2.0, tags=["deception", "links"])
def misleading_link(structure: dict, normalized: float = 0.7, max_findings: int = 12, max_text_length: int = 200) -> ResultBase:
    """Compara o domínio exibido no link com o destino efetivo."""
    tree = structure.get("html_parser")
    if tree is None:
        return ResultBase(value=0, normalized=None, details={"error": "HTML não disponível"})

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
            hits.append({"displayed": displayed[:max_text_length], "target": actual.hostname})
    return ResultBase(
        value=len(hits),
        normalized=normalized if hits else 0,
        details={"mismatched_links": hits[:max_findings]}
    )
