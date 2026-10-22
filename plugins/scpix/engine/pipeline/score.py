"""Score relativo de anomalias; não é probabilidade de golpe."""
from math import prod

GROUP_WEIGHTS = {
    "integrity": 0.28,
    "structure": 0.20,
    "account": 0.16,
    "transaction": 0.09,
    "location": 0.18,
    "context": 0.09,
}

CRITICAL_FLOORS = {
    "crc_mismatch": 75.0,
    "missing_crc": 65.0,
    "crc_not_last": 65.0,
    "crc_invalid_format": 65.0,
    "private_or_ip_location": 70.0,
    "unsafe_location_authority": 70.0,
    "insecure_location_scheme": 70.0,
    "unexpected_pix_key": 75.0,
    "unexpected_amount": 70.0,
    "unexpected_location_host": 70.0,
}


def calculate_score(ctx, k: float):
    grouped = {}
    for name, weight in GROUP_WEIGHTS.items():
        values = sorted((min(0.99, rule["score"] * rule["weight"] / (k + 2))
                         for rule in ctx.heuristics
                         if rule["status"] == "ok" and rule["group"] == name and rule["score"] > 0), reverse=True)[:3]
        grouped[name] = {"risk": round(1 - prod(1 - value for value in values), 6),
                         "weight": weight, "signals": len(values)}

    raw = sum(value["risk"] * value["weight"] for value in grouped.values())
    triggered = {r["name"] for r in ctx.heuristics if r["triggered"]}
    floor = max((value for name, value in CRITICAL_FLOORS.items() if name in triggered), default=0.0)
    ctx.raw_score = round(raw, 6)
    ctx.score = round(max(min(100.0, 100 * raw ** 0.8), floor), 2)
    if ctx.score == 0:
        ctx.classification, ctx.risk = "no_structural_anomalies", "low"
    elif ctx.score < 25:
        ctx.classification, ctx.risk = "review", "low"
    elif ctx.score < 60:
        ctx.classification, ctx.risk = "anomalous", "medium"
    else:
        ctx.classification, ctx.risk = "high_anomaly", "high"
    ctx.scoring = {
        "method": "grouped_top3_noisy_or_with_critical_floors",
        "model": "grouped", "k": k, "groups": grouped,
        "critical_floor": floor, "raw_score": ctx.raw_score,
        "calibrated": False,
        "calibration_scope": "engineering_controls_only",
        "score_is_probability": False,
        "score_semantics": "conformance_and_context_anomaly_not_fraud_probability",
    }
