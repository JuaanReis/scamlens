from plugins.scurl.engine.pipeline.context_apply import apply_dependencies
from plugins.scurl.models.scan_context import ScanContext
from plugins.scurl.engine.analysis.classification import classify
from plugins.scurl.scoring.sigmoid import sigmoid

def calculate_score(ctx: ScanContext, k: int = 5) -> None:
    for result in ctx.results:
        adj_value, adj_weight, dep_reasons = apply_dependencies(
            result.name,
            result.value,
            result.weight,
            ctx.results_map
        )
    
        if adj_value is None:
            continue

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

    ctx.score = sigmoid(ctx.scores, ctx.weights, k)
    ctx.classification, ctx.risk = classify(ctx.score)