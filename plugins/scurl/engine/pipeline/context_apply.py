from plugins.scurl.scoring.dependencies import DEPENDENCIES

def _eval_condition(condition: dict, value) -> bool:
    op = condition["op"]
    if op == "is_none":
        return value is None
    if value is None:
        return False
    val = condition["val"]
    return {
        "<":  value < val,
        "<=": value <= val,
        ">":  value > val,
        ">=": value >= val,
        "==": value == val,
    }[op]

def apply_dependencies(name: str, value: float | None, weight: float, results_map: dict[str, float | None]) -> tuple[float | None, float, list[str]]:
    reasons: list[str] = []

    if value is None:
        return None, weight, reasons

    reduce_factors: list[float] = []
    best_increase: float | None = None
    reduce_reasons: list[str] = []
    increase_reasons: list[str] = []

    for dep in DEPENDENCIES.get(name, []):
        source_value = results_map.get(dep["depends_on"])

        try:
            triggered = _eval_condition(dep["condition"], source_value)
        except Exception:
            continue

        if not triggered:
            continue

        action = dep["action"]

        if action == "skip":
            reasons.append(dep["reason"])
            return None, weight, reasons

        elif action == "reduce":
            reduce_factors.append(dep["factor"])
            reduce_reasons.append(dep["reason"])

        elif action == "increase":
            if best_increase is None or dep["factor"] > best_increase:
                best_increase = dep["factor"]
                increase_reasons = [dep["reason"]]
            elif dep["factor"] == best_increase:
                increase_reasons.append(dep["reason"])

    adj_value = value
    combined_reduce = 1.0
    for f in reduce_factors:
        combined_reduce *= f

    if reduce_factors and best_increase is not None:
        adj_value *= combined_reduce
        reasons.extend(reduce_reasons)

    elif reduce_factors:
        adj_value *= combined_reduce
        reasons.extend(reduce_reasons)

    elif best_increase is not None:
        adj_value = min(1.0, adj_value * best_increase)
        reasons.extend(increase_reasons)

    return adj_value, weight, reasons