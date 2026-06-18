from .normalize import normalize_domain
from plugins.math.levenshtein import levenshtein
from plugins.math.shannon_entropy import shannon_entropy
from plugins.scurl.models.result_base import ResultBase
from plugins.math.value_normalizator import minmax

def detect(domain: str, by_len: dict, max_dist: int = 2) -> ResultBase:
    domain = normalize_domain(domain)

    if not domain or domain.isdigit() or len(domain) < 4:
        return ResultBase(value=0, normalized=None, details={"error": "domínio inválido ou curto demais"})

    domain_len = len(domain)
    best_distance = float("inf")
    best_match = None

    for l in range(domain_len - max_dist, domain_len + max_dist + 1):
        for legit in by_len.get(l, ()):
            if not legit or legit[0] != domain[0]:
                continue

            if abs(len(legit) - domain_len) > max_dist:
                continue

            d = levenshtein(domain, legit)

            if d == 0:
                return ResultBase(value=0, normalized=None, details={"match": "exact", "domain": domain})

            if d < best_distance:
                best_distance = d
                best_match = legit

        if best_distance == 1:
            break

    if best_match is None or best_distance > max_dist:
        return ResultBase(value=0, normalized=None, details={"match": None, "domain": domain})

    max_len = max(domain_len, len(best_match))
    similarity = 1 - (best_distance / max_len)

    entropy = shannon_entropy(domain)
    entropy_penalty = min(entropy / 4.7, 1.0) * 0.1

    risk_score = round(similarity - entropy_penalty, 4)
    risk_score = max(0.0, min(risk_score, 1.0))

    return ResultBase(
        value=risk_score,
        normalized=round(minmax(risk_score, 0.5, 1.0), 4) if risk_score > 0 else None,
        details={
            "domain": domain,
            "best_match": best_match,
            "distance": best_distance,
            "similarity": round(similarity, 4),
            "entropy": round(entropy, 4),
        }
    )