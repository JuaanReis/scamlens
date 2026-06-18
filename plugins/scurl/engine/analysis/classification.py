CLASS_TABLE = [
    (10, ("safe", "very low")),
    (25, ("safe", "low")),
    (40, ("suspicious", "moderate")),
    (55, ("suspicious", "elevated")),
    (70, ("dangerous", "high")),
    (85, ("dangerous", "very high"))
]

def classify(score: float) -> tuple[str, str]:

    if not 0 <= score <= 100:
        return "invalid", "unknown" 

    for threshold, result in CLASS_TABLE:
        if score < threshold:
            return result

    return "malicious", "critical"