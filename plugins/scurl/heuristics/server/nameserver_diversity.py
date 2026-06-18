import tldextract
from plugins.scurl.models.result_base import ResultBase
from ..registry import register

@register(name="nameserver_diversity", category="server", severity="medium", weight=3.0, tags=["server", "nameserver", "dns"])
def nameserver_diversity(structure: dict) -> ResultBase:
    data = structure.get("rdap")

    if not data:
        return ResultBase(
            value=None,
            normalized=None,
            details={"error": "RDAP data unavailable"}
        )

    nameservers = data.get("nameservers") or []

    if not nameservers:
        return ResultBase(
            value=0,
            normalized=1.0,
            details={"unique_ns_domains": 0, "nameserver_count": 0}
        )

    domains = set()
    for ns in nameservers:
        name = ns.get("ldhName")
        if not name:
            continue
        ext = tldextract.extract(name)
        if ext.domain and ext.suffix:
            domains.add(f"{ext.domain}.{ext.suffix}")

    ns_count = len(nameservers)
    unique_domains = len(domains)
    diversity_ratio = unique_domains / ns_count

    if ns_count == 1:
        score = 0.9
    elif ns_count == 2 and diversity_ratio == 1:
        score = 0.6
    elif diversity_ratio > 0.8:
        score = 0.5
    else:
        score = 0.0

    return ResultBase(
        value=unique_domains,
        normalized=score,
        details={
            "unique_ns_domains": unique_domains,
            "nameserver_count": ns_count,
            "diversity_ratio": round(diversity_ratio, 2)
        }
    )