"""Classificação experimental de suspeita, não probabilidade de IA."""
def classify(score):
    if not 0 <= score <= 100:
        return "invalid", "unknown"
    if score < 30:
        return "inconclusive", "low"
    if score < 60:
        return "inconclusive", "moderate"
    return "suspicious", "high"
