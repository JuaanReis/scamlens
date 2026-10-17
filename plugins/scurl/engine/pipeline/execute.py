from math import isfinite
from time import perf_counter
from plugins.scurl.models.scan_result import ScanResult

def execute_rules(ctx, rules, processors=2):
    start = perf_counter()
    frozen = dict(ctx.target.structure)
    frozen.update(ctx.target.final_structure)
    frozen["original_url"] = ctx.target.url
    frozen["html_parser"] = ctx.target.html
    frozen["headers"] = dict(ctx.target.response.headers) if ctx.target.response else {}
    for field in ("dns", "ssl", "rdap", "safe_browsing"):
        frozen[field] = getattr(ctx.target, field)

    for rule in rules:
        try:
            data = rule.fn(frozen)
            if data is None:
                raise ValueError("rule returned None")
            if data.normalized is not None and (
                not isfinite(data.normalized) or not 0 <= data.normalized <= 1
            ):
                raise ValueError("invalid normalized score")
            
            ctx.results.append(
                ScanResult(
                    name=rule.name,
                    value=data.normalized,
                    weight=rule.weight,
                    category=rule.category,
                    severity=rule.severity,
                    details=data.details or {},
                )
            )
            
            ctx.rule_status[rule.name] = (
                "unavailable" if data.normalized is None else "ok"
            )

        except Exception as exc:
            ctx.results.append(
                ScanResult(
                    name=rule.name,
                    value=None,
                    weight=rule.weight,
                    category=rule.category,
                    severity=rule.severity,
                    details={"error": type(exc).__name__},
                )
            )

            ctx.rule_status[rule.name] = "error"
            ctx.warnings.append(
                "rule failed: " + rule.name + " (" + type(exc).__name__ + ")"
            )

    ctx.results_map = {r.name: r.value for r in ctx.results}
    ctx.meta.timings["heuristics_s"] = perf_counter() - start

    if not any(r.value is not None for r in ctx.results):
        return dict(
            error=dict(
                error_type="execution_error", message="Nenhuma regra pôde ser avaliada"
            )
        )
    
    return None
