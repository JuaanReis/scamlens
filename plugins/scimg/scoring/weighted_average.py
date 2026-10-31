def weighted_average(scores: list, weights: list) -> float:
    """Implementação compatível com scurl: None não participa da média."""
    if len(scores) != len(weights):
        raise ValueError("scores and weights must have same length")
    numerator = sum(s * w for s, w in zip(scores, weights) if s is not None)
    denominator = sum(w for s, w in zip(scores, weights) if s is not None)
    if denominator == 0:
        return 0.0
    return numerator / denominator
