from datetime import datetime, timezone
from plugins.scurl.models.result_base import ResultBase
from plugins.math.exponential_decay import domain_age_score
from ..registry import register

@register(name="domain_age", category="server", severity="medium", weight=4.0, tags=["server", "domain", "age"])
def domain_age(structure: dict) -> ResultBase:
    data = structure.get("rdap")

    if not data:
        return ResultBase(
            value=None,
            normalized=None,
            details={"error": "RDAP data unavailable"}
        )

    creation = _extract_creation_date(data)

    if creation is None:
        return ResultBase(
            value=None,
            normalized=None,
            details={"error": "Creation date not available"}
        )

    now = datetime.now(timezone.utc)
    age = now - creation
    score = domain_age_score(age.days)

    return ResultBase(
        value=age.days,
        normalized=score,  
        details={
            "creation_date": creation.isoformat(),
            "age_days": max(0, age.days)
        }
    )

def _extract_creation_date(data: dict) -> datetime | None:
    for event in data.get("events", []):
        if event.get("eventAction") == "registration":
            raw = event.get("eventDate")
            if raw:
                return _parse_rdap_date(raw)
    return None

def _parse_rdap_date(raw: str) -> datetime | None:
    try:
        dt = datetime.fromisoformat(raw)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        return None