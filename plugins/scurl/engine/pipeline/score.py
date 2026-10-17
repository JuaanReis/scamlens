from math import isfinite
from plugins.scurl.engine.pipeline.context_apply import apply_dependencies
from plugins.scurl.engine.analysis.classification import classify
from plugins.scurl.scoring.sigmoid import sigmoid
from plugins.scurl.scoring.calibration import GROUPS, CAPS

def calculate_score(ctx, k=5, model="grouped"):
    if not isfinite(k) or not 0.1 <= k <= 20:
        raise ValueError("k must be finite and between .1 and 20")
    
    ctx.scores.clear()
    ctx.weights.clear()
    ctx.heuristics.clear()
    ctx.all_heuristics.clear()
    groups = {}
    for result in ctx.results:
        value = result.value
        reasons = []
        if model == "legacy":
            value, weight, reasons = apply_dependencies(
                result.name, value, result.weight, ctx.results_map
            )

        else:
            weight = result.weight
        row = dict(
            name=result.name,
            category=result.category,
            value=round(value, 4) if value is not None else None,
            weight=weight,
            contribution=round(value * weight, 4) if value is not None else None,
            details=result.details or {},
            reasons=reasons,
        )

        row["status"] = ctx.rule_status.get(
            result.name, "unavailable" if value is None else "ok"
        )

        ctx.all_heuristics.append(row)
        if value is None:
            continue

        ctx.scores.append(value)
        ctx.weights.append(weight)
        if value > 0:
            ctx.heuristics.append(row)

        group = GROUPS.get(result.name, result.category)
        strength = min(value, CAPS.get(result.name, 1.0)) * min(weight / 3.0, 1.0)
        if model == "grouped":
            row.update(group=group, effective_strength=round(strength, 6))

        if group not in groups or strength > groups[group]["strength"]:
            groups[group] = dict(group=group, strength=strength, rule=result.name)

    if model == "legacy":
        ctx.score = sigmoid(ctx.scores, ctx.weights, k)
        ctx.scoring = dict(method="legacy_weighted_sigmoid", k=k)

    else:
        ranked = sorted(groups.values(), key=lambda x: (-x["strength"], x["group"]))
        selected = [x for x in ranked if x["strength"] > 0][:3]
        slots = [x["strength"] for x in selected] + [0.0] * (3 - len(selected))
        raw = sum(v * w for v, w in zip(slots, (3, 2, 1))) / 6
        reputation = ctx.results_map.get("safe_browsing")

        if reputation is not None and reputation >= 0.5:
            raw = max(raw, 0.95)

        ctx.score = sigmoid([raw], [1], k)
        ctx.scoring = dict(
            method="grouped-top3-v1",
            k=k,
            raw_score=raw,
            groups=ranked,
            selected_groups=selected,
            slot_scores=slots,
            slot_weights=[3, 2, 1],
            reputation_floor_applied=reputation is not None and reputation >= 0.5,
            calibrated=False,
            score_is_probability=False,
        )
        
    ctx.classification, ctx.risk = classify(ctx.score)
