from plugins.scurl.engine.pipeline.context_apply import apply_dependencies
from plugins.scurl.models.scan_context import ScanContext
from plugins.scurl.engine.analysis.classification import classify
from plugins.scurl.scoring.sigmoid import sigmoid
from plugins.scurl.scoring.calibration import GROUPS, CAPS
from plugins.scurl import config

def calculate_score(ctx: ScanContext, k: int | None = None, score_model: str | None = None) -> None:
    k = config["scanner"]["k"] if k is None else k
    score_model = score_model or config["scanner"]["score_model"]
    if score_model not in ("legacy", "grouped"):
        raise ValueError(f"Modelo de score desconhecido: {score_model}")
    ctx.scores.clear()
    ctx.weights.clear()
    ctx.heuristics.clear()
    groups = {}
    for result in ctx.results:
        adj_value, adj_weight, dep_reasons = apply_dependencies(
            result.name,
            result.value,
            result.weight,
            ctx.results_map
        )
    
        if adj_value is None:
            continue

        if score_model == "grouped":
            adj_value = min(adj_value, CAPS.get(result.name, 1.0))
            group = GROUPS.get(result.name, result.name)
            previous = groups.get(group)
            if previous is None or adj_value * adj_weight > previous[0] * previous[1]:
                groups[group] = (adj_value, adj_weight)
        else:
            ctx.scores.append(adj_value)
            ctx.weights.append(adj_weight)

        if adj_value > 0:
            ctx.heuristics.append({
                "name": result.name,
                "category": result.category,
                "value": round(adj_value, 2),
                "weight": round(adj_weight, 2),
                "contribution": round(adj_value * adj_weight, 1),
                "details": result.details,
                "reasons": dep_reasons
            })

    if score_model == "grouped":
        ctx.scores = [value for value, weight in groups.values()]
        ctx.weights = [weight for value, weight in groups.values()]
    ctx.score = sigmoid(ctx.scores, ctx.weights, k)
    ctx.classification, ctx.risk = classify(ctx.score)
