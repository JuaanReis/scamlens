from plugins.scurl.models.result_base import ResultBase
from plugins.scurl.parsers.resources import external
from ..registry import register

@register(name="script_integrity_absent", category="html", severity="medium", weight=2.0, tags=["html", "script", "supply-chain"])
def script_integrity_absent(structure: dict) -> ResultBase:
    tree = structure.get("html_parser")
    if tree is None:
        return ResultBase(value=0, normalized=None, details={"error": "HTML não disponível"})

    external_scripts = []
    missing_integrity = []

    for script in tree.css("script[src]"):
        src = script.attributes.get("src", "")
        if not external(src, structure):
            continue
        external_scripts.append(src)
        if not script.attributes.get("integrity"):
            missing_integrity.append(src)

    total = len(external_scripts)
    missing = len(missing_integrity)
    normalized = round(missing / total, 2) if total > 0 else None

    return ResultBase(
        value=float(missing),
        normalized=normalized,
        details={
            "external_scripts": total,
            "missing_integrity": missing,
            "samples": missing_integrity[:5]
        }
    )
