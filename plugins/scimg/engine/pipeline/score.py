"""Mesma ordem do scurl: dependências -> caps -> grupos -> média/sigmoid -> classificação."""
from math import isfinite
from plugins.scimg.scoring.sigmoid import sigmoid
from plugins.scimg.scoring.weighted_average import weighted_average
from plugins.scimg.scoring.calibration import GROUPS, CAPS, DEFAULT_K
from plugins.scimg.engine.pipeline.context_apply import apply_dependencies
from plugins.scimg.engine.analysis.classification import classify

DEFAULT_CAPS = {"provenance": .95, "pixel": .60, "color": .60,
                "texture": .60, "noise": .60, "compression": .60,
                "geometry": .60, "frequency": .60}

def calculate_score(ctx, k=None, score_model="grouped", caps=None, groups_config=None):
    k = DEFAULT_K if k is None else k
    if type(k) not in (int, float) or not isfinite(k) or not .1 <= k <= 20:
        raise ValueError("k inválido")
    if score_model not in ("legacy", "grouped"):
        raise ValueError("score_model inválido")
    caps = {**DEFAULT_CAPS, **CAPS, **(caps or {})}
    groups_config = {**GROUPS, **(groups_config or {})}
    for name, cap in caps.items():
        if type(cap) not in (int, float) or not isfinite(cap) or not 0 <= cap <= 1:
            raise ValueError(f"Teto de score inválido: {name}")
    ctx.scores.clear()
    ctx.weights.clear()
    ctx.heuristics.clear()
    groups = {}
    ctx.results_map = {r.name: r.value for r in ctx.results}
    for result in ctx.results:
        value, weight, reasons = apply_dependencies(result.name, result.value,
                                                    result.weight, ctx.results_map)
        if value is None:
            continue
        if score_model == "grouped":
            value = min(value, caps.get(result.name, caps.get(result.category, 1.0)))
            group = groups_config.get(result.name, result.group)
            previous = groups.get(group)
            if previous is None or value * weight > previous[0] * previous[1]:
                groups[group] = (value, weight)
        else:
            ctx.scores.append(value)
            ctx.weights.append(weight)
        if value > 0:
            ctx.heuristics.append({"name": result.name, "category": result.category,
                                   "value": round(value, 4), "weight": round(weight, 2),
                                   "contribution": round(value * weight, 4),
                                   "details": result.details, "reasons": reasons})
    if score_model == "grouped":
        ctx.scores = [v for v, w in groups.values()]
        ctx.weights = [w for v, w in groups.values()]
    if not ctx.weights or sum(ctx.weights) <= 0:
        raise ValueError("no_rule_coverage")
    ctx.score = sigmoid(ctx.scores, ctx.weights, k)
    ctx.classification, ctx.risk = classify(ctx.score)
    return weighted_average(ctx.scores, ctx.weights)
