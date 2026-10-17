from math import isfinite

def execute_rules(ctx, rules, disabled):
    for rule in rules:
        status = "ok"
        
        if rule.name in disabled:
            score, message, evidence = None, "Regra desabilitada.", []
            status = "disabled"

        else:
            try:
                score, message, evidence = rule.fn(ctx)
                if score is not None and (not isfinite(score) or not 0 <= score <= 1):
                    raise ValueError("invalid rule score")
                
                if score is None:
                    status = "unavailable"

            except Exception as exc:
                score, message, evidence = None, "Falha: " + type(exc).__name__, []
                status = "error"
                ctx.warnings.append("rule failed: " + rule.name)

        ctx.heuristics.append(dict(name=rule.name, category=rule.category, severity=rule.severity,
                                   weight=rule.weight, tags=list(rule.tags), group=rule.extra["group"], score=score,
                                   status=status, triggered=score is not None and score > 0,
                                   message=message, evidence=evidence))
