from math import isfinite


def execute_rules(ctx, rules, disabled):
    """Erros isolados de regras não interrompem toda a análise."""
    for rule in rules:
        if rule.name in disabled:
            score, message, evidence, status = None, "Regra desabilitada.", [], "disabled"
        else:
            try:
                score, message, evidence = rule.fn(ctx)
                if score is not None and (type(score) not in (int, float) or not isfinite(score) or not 0 <= score <= 1):
                    raise ValueError("pontuação de regra deve estar entre 0 e 1")
                if not isinstance(message, str) or not isinstance(evidence, list) or not all(isinstance(e, str) for e in evidence):
                    raise ValueError("formato de evidência inválido")
                status = "unavailable" if score is None else "ok"
            except Exception as exc:
                score, message, evidence, status = None, "Falha ao executar a regra: " + type(exc).__name__, [], "error"
                ctx.warnings.append("regra indisponível por erro: " + rule.name)

        ctx.heuristics.append({
            "name": rule.name, "category": rule.category, "severity": rule.severity,
            "weight": rule.weight, "tags": list(rule.tags), "group": rule.extra["group"],
            "score": score, "status": status,
            "triggered": score is not None and score > 0,
            "message": message, "evidence": evidence,
        })
