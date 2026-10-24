import copy
import logging
from math import isfinite
from time import monotonic
from plugins.scurl.models.scan_context import ScanContext
from plugins.scurl.models.scan_result import ScanResult
from plugins.scurl import config

logger = logging.getLogger(__name__)
MAX_SCAN_SECONDS = config["scanner"]["max_rule_seconds"]

def _execution_error(error_type, message):
    return {"status": "error", "error": {"type": error_type, "message": message}}

def execute_rules(ctx: ScanContext, rules: list, processors: int) -> dict | None:
    frozen = copy.deepcopy(dict(ctx.target.structure))
    frozen["html_parser"] = ctx.target.html
    frozen["headers"] = dict(ctx.target.response.headers) if ctx.target.response else {}
    frozen["dns"] = copy.deepcopy(ctx.target.dns)
    frozen["ssl"] = copy.deepcopy(ctx.target.ssl)
    frozen["rdap"] = copy.deepcopy(ctx.target.rdap)
    frozen["safe_browsing"] = copy.deepcopy(ctx.target.safe_browsing)
    deadline = monotonic() + MAX_SCAN_SECONDS
    ctx.results.clear()
    ctx.results_map.clear()
    for rule in rules:
        if monotonic() >= deadline:
            return _execution_error("scan_timeout", "Orçamento de tempo das regras excedido")
        try:
            data = rule.fn(frozen, **rule.extra.get("parameters", {}))
            if monotonic() >= deadline:
                return _execution_error("scan_timeout", "Orçamento de tempo das regras excedido")
            if data is None or data.normalized is None:
                continue
            value = data.normalized
            if type(value) not in (int, float) or not isfinite(value) or not 0 <= value <= 1:
                raise ValueError("Resultado numérico inválido")
            if type(rule.weight) not in (int, float) or not isfinite(rule.weight) or rule.weight < 0:
                raise ValueError("Peso inválido")
            ctx.results.append(ScanResult(
                name=rule.name, value=value, weight=rule.weight, category=rule.category,
                severity=rule.severity, details=data.details,
            ))
        except Exception:
            logger.exception("Rule %s falhou", rule.name)
            return _execution_error("execution_error", "Não foi possível concluir a avaliação das regras")
    if not any(result.weight > 0 for result in ctx.results):
        return _execution_error("no_rule_coverage", "Nenhuma regra produziu uma avaliação numérica válida")
    ctx.results_map = {result.name: result.value for result in ctx.results}
    return None
