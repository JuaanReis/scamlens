"""Aplica dependências entre regras, conforme o contrato do scurl."""
from plugins.scimg.scoring.dependencies import DEPENDENCIES

def _condition(condition, value):
    op = condition["op"]
    if op == "is_none":
        return value is None
    if value is None:
        return False
    threshold = condition["val"]
    return {"<": lambda: value < threshold, "<=": lambda: value <= threshold,
            ">": lambda: value > threshold, ">=": lambda: value >= threshold,
            "==": lambda: value == threshold}[op]()

def apply_dependencies(name, value, weight, results_map):
    if value is None:
        return None, weight, []
    reasons, reduction, increase = [], 1.0, None
    for dep in DEPENDENCIES.get(name, []):
        try:
            if not _condition(dep["condition"], results_map.get(dep["depends_on"])):
                continue
        except (KeyError, TypeError, ValueError):
            continue
        action = dep["action"]
        reasons.append(dep.get("reason", ""))
        if action == "skip":
            return None, weight, reasons
        if action == "reduce":
            reduction *= dep["factor"]
        if action == "increase":
            increase = max(increase or 0.0, dep["factor"])
    value *= reduction
    if increase is not None and reduction == 1.0:
        value = min(1.0, value * increase)
    return value, weight, reasons
