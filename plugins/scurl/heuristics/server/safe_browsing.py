from plugins.scurl.models.result_base import ResultBase
from ..registry import register

@register(name="safe_browsing", category="server", severity="high", weight=4.0, tags=["reputation", "google", "blacklist"])
def safe_browsing(structure: dict) -> ResultBase:
    data = structure.get("safe_browsing")

    if data is None:
        return ResultBase(value=0, normalized=None, details={"error": "Safe Browsing não disponível"})

    flagged = data.get("flagged", False)
    threat_types = data.get("threat_types", [])

    return ResultBase(
        value=1.0 if flagged else 0.0,
        normalized=1.0 if flagged else None,
        details={
            "flagged": flagged,
            "threat_types": threat_types
        }
    )