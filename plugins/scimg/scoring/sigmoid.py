from math import exp
from .weighted_average import weighted_average

def sigmoid(scores: list, weights: list, k: float = 5.0) -> float:
    """A mesma sigmoid numericamente estável do scurl."""
    value = k * (weighted_average(scores, weights) - .5)
    if value >= 0:
        return 100 / (1 + exp(-value))
    exponential = exp(value)
    return 100 * exponential / (1 + exponential)
