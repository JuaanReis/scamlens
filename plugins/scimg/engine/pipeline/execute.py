import logging
from math import isfinite
from time import monotonic
from plugins.scimg.models.scan_result import ScanResult
from .input_data import error

logger = logging.getLogger(__name__)

def execute_rules(ctx, rules, max_seconds=12.0):
    """Executor sequencial e determinístico; limita a execução entre regras.

    Observação: deadline não interrompe uma regra Python que estiver bloqueada.
    """
    deadline = monotonic() + max_seconds
    ctx.results.clear()
    ctx.results_map.clear()
    ctx.skipped.clear()
    for rule in rules:
        if monotonic() >= deadline:
            return error("scan_timeout", "Orçamento de execução ultrapassado")
        try:
            result = rule.fn(ctx.features, **rule.extra.get("parameters", {}))
            if result is None or result.normalized is None:
                ctx.skipped.append(rule.name)
                continue
            score = result.normalized
            if type(score) not in (int, float) or not isfinite(score) or not 0 <= score <= 1:
                raise ValueError("Score normalizado inválido")
            ctx.results.append(ScanResult(name=rule.name, value=float(score),
                                          weight=rule.weight, category=rule.category,
                                          severity=rule.severity,
                                          group=rule.extra.get("group", rule.category),
                                          details=result.details or {}))
        except Exception:
            logger.exception("Falha em %s", rule.name)
            return error("execution_error", f"Falha ao executar regra {rule.name}")
    if not any(r.weight > 0 for r in ctx.results):
        return error("no_rule_coverage", "Nenhuma regra aplicável")
    ctx.results_map = {r.name: r.value for r in ctx.results}
    return None
