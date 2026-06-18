from ..registry import register
from plugins.scurl.models.result_base import ResultBase

@register(name="client_hints_collection", category="html", severity="low", weight=1.0, tags=["html", "fingerprint", "privacy"])
def client_hints_collection(structure: dict) -> ResultBase:
    headers = structure.get("headers", {})
    accept_ch = headers.get("accept-ch", "")

    if not accept_ch:
        return ResultBase(value=0, normalized=None, details={"hints": []})

    hints = [h.strip() for h in accept_ch.split(",") if h.strip()]
    sensitive = [h for h in hints if any(k in h.lower() for k in ["memory", "arch", "model", "bitness", "wow64"])]

    count = len(sensitive)
    normalized = min(count / 4, 1.0) if count > 0 else None

    return ResultBase(
        value=float(count),
        normalized=round(normalized, 2) if normalized else None,
        details={
            "hint_count": len(hints),
            "sensitive_count": count,
            "sensitive_hints": sensitive
        }
    )