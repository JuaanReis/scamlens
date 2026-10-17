from plugins.scurl.models.result_base import ResultBase
from plugins.math.levenshtein import levenshtein
from .normalize import normalize_domain


def detect(domain, by_len, max_dist=1):
    raw = domain.strip().casefold()
    exact = by_len.get("_exact")
    if exact is None:
        exact = frozenset(x for k, v in by_len.items() if isinstance(k, int) for x in v)
    if raw in exact:
        return ResultBase(0, 0, {"match": "exact", "domain": raw})
    if not 6 <= len(raw) <= 63 or raw.isdigit():
        return ResultBase(0, 0, {"match": None, "domain": raw})
    skeleton = normalize_domain(raw)
    if skeleton != raw and skeleton in exact:
        return ResultBase(
            0.85, 0.85, dict(domain=raw, best_match=skeleton, homoglyph=True)
        )
    deletion_index = by_len.get("_deletions", {})
    variants = {raw[:i] + raw[i + 1 :] for i in range(len(raw))}
    candidates = set(deletion_index.get(raw, ()))
    candidates.update(variants & exact)
    for variant in variants:
        candidates.update(deletion_index.get(variant, ()))
    if not deletion_index:
        candidates.update(
            x
            for n in range(len(raw) - 1, len(raw) + 2)
            for x in by_len.get(n, ())[:256]
        )
    for candidate in sorted(candidates)[:256]:
        if levenshtein(raw, candidate) == 1:
            return ResultBase(
                0.6,
                0.6,
                dict(
                    domain=raw, best_match=candidate, distance=1, candidate_budget=256
                ),
            )
    return ResultBase(0, 0, {"match": None, "domain": raw})
