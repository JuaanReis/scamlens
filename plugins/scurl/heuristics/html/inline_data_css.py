from plugins.scurl.models.result_base import ResultBase
from ..registry import register

@register(name="inline_data_uri", category="html", severity="medium", weight=1.5, tags=["html", "obfuscation", "phishing"])
def inline_data_uri(structure: dict) -> ResultBase:
    tree = structure.get("html_parser")
    if tree is None:
        return ResultBase(value=0, normalized=None, details={"error": "HTML não disponível"})

    data_uris = []

    for tag in tree.css("img, script, iframe, embed, object, source"):
        for attr in ("src", "data", "href"):
            val = tag.attributes.get(attr) or ""
            if val.startswith("data:"):
                data_uris.append({"tag": tag.tag, "prefix": val[:40]})

    count = len(data_uris)
    normalized = min(count / 5, 1.0) if count > 0 else None

    return ResultBase(
        value=float(count),
        normalized=round(normalized, 2) if normalized else None,
        details={
            "data_uri_count": count,
            "samples": data_uris[:5]
        }
    )