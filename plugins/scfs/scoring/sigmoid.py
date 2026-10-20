from math import exp, isfinite
from .weighted_average import weighted_average

def sigmoid(scores, weights, k=5.0):
    if not isfinite(k) or not 0.1 <= k <= 20:
        raise ValueError("k must be between 0.1 and 20")
    value = weighted_average(scores, weights)
    return None if value is None else 100 / (1 + exp(-k * (value - 0.5)))
