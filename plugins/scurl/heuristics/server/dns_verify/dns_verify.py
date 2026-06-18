from .dns_scoring import dns_mx, dns_ttl, dns_a, dns_dkim, dns_spf
from plugins.scurl.models.result_base import ResultBase
from plugins.scurl.scoring.sigmoid import sigmoid
from ...registry import register

@register(name="dns_score", category="server", severity="medium", weight=3.5, tags=["server", "dns", "security"])
def dns_score(structure: dict) -> ResultBase:
    hostname = structure.get("hostname", "")

    if not hostname:
        return ResultBase(
            value=None,
            normalized=0.5,
            details={"error": "No hostname provided"}
        )

    dns_data = structure.get("dns", {})

    if not dns_data or dns_data.get("failed", False):
        return ResultBase(
            value=None,
            normalized=1.0,
            details={"error": "DNS resolution failed", "dns_failed": True}
        )

    has_mx   = dns_data.get("has_mx")
    ttl      = dns_data.get("ttl")
    ips      = dns_data.get("a", [])
    txt      = dns_data.get("txt", [])
    dkim_found = dns_data.get("dkim", False)

    scores = [
        dns_mx(has_mx),
        dns_ttl(ttl, has_mx=has_mx),
        dns_a(ips, ttl=ttl),
        dns_spf(txt, has_mx=has_mx),
        dns_dkim(txt, has_mx=has_mx, dkim_found=dkim_found),
    ]

    values  = [r.normalized for r in scores]
    weights = [r.weight for r in scores]

    score = sigmoid(values, weights, k=5) / 100 if sum(weights) > 0 else 0.0

    return ResultBase(
        value=sum(v for v in values if v is not None),
        normalized=score,
        details={
            "has_mx":   has_mx,
            "ttl":      ttl,
            "ip_count": len(ips),
            "ips":      ips,
            "scores": {
                "mx":   values[0],
                "ttl":  values[1],
                "a":    values[2],
                "spf":  values[3],
                "dkim": values[4],
            }
        }
    )