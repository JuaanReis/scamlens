from plugins.scurl.models.result_base import ResultBase
from ...registry import register


@register(
    name="dns_score",
    category="server",
    severity="low",
    weight=0.5,
    tags=["server", "dns"],
)
def dns_score(structure):
    data = structure.get("dns")
    if not data or data.get("errors") or data.get("failed"):
        return ResultBase(None, None, {"error": "DNS metadata unavailable or partial"})
    # Mail configuration, CDN address counts and short TTLs do not prove phishing.
    ttl = data.get("ttl")
    score = 0.1 if ttl is not None and ttl < 30 else 0
    return ResultBase(score, score, dict(ttl=ttl, mail_policy_not_scored=True))
