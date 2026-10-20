from math import isfinite

def weighted_average(scores, weights):
    if len(scores) != len(weights):
        raise ValueError("scores and weights must have same length")
    numerator = denominator = 0.0
    for score, weight in zip(scores, weights):
        if not isfinite(weight) or weight <= 0:
            raise ValueError("weights must be finite and positive")
        if score is None:
            continue
        if not isfinite(score) or not 0 <= score <= 1:
            raise ValueError("rule scores must be finite and within [0, 1]")
        numerator += score * weight
        denominator += weight
    return numerator / denominator if denominator else None
