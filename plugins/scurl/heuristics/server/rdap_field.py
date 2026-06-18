from plugins.scurl.models.result_base import ResultBase
from ..registry import register

@register(name="rdap_metadata_incompleteness", category="server", severity="low", weight=3.5, tags=["server", "rdap", "metadata"])
def rdap_metadata_incompleteness(structure: dict) -> ResultBase:
    data = structure.get("rdap")

    if not data:
        return ResultBase(
            value=None,
            normalized=None,
            details={"error": "RDAP data unavailable"}
        )

    fields = [
        data.get("entities"),
        data.get("nameservers"),
        data.get("events"),
    ]

    missing = sum(1 for f in fields if f is None)
    score = missing / len(fields)

    return ResultBase(
        value=missing,
        normalized=score,
        details={"missing_fields": missing}
    )