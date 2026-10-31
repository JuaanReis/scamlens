"""Cálculo comum às heurísticas métricas, sem registro implícito."""
from plugins.scimg.models.result_base import ResultBase

def evaluate_metric(features: dict, *, key: str, direction: str,
                    threshold: float, span: float) -> ResultBase:
    metric = features.get("metrics", {}).get(key)
    if metric is None:
        return ResultBase(value=0, normalized=None,
                          details={"reason": "metric_not_applicable", "metric": key})
    if span <= 0:
        raise ValueError("span precisa ser positivo")
    delta = (metric - threshold) if direction == "high" else (threshold - metric)
    value = max(0.0, min(1.0, delta / span))
    return ResultBase(value=float(metric), normalized=round(value, 6),
                      details={"metric": key, "observed": round(metric, 6),
                               "threshold": threshold, "direction": direction,
                               "limitation": "Sinal estatístico inespecífico e não calibrado"})
