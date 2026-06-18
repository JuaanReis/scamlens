import copy
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FuturesTimeout
from plugins.scurl.models.scan_context import ScanContext
from plugins.scurl.models.scan_result import ScanResult

logger = logging.getLogger(__name__)

MAX_SCAN_SECONDS = 15
MAX_WORKERS = 8
MIN_WORKERS = 1

def execute_rules(ctx: ScanContext, rules: list, processors: int) -> dict | None:
    workers = max(MIN_WORKERS, min(processors, MAX_WORKERS))
    frozen = copy.deepcopy(dict(ctx.target.structure))
    frozen["html_parser"] = ctx.target.html
    frozen["headers"] = dict(ctx.target.response.headers) if ctx.target.response else {}
    frozen["dns"] = copy.deepcopy(ctx.target.dns)
    frozen["ssl"] = copy.deepcopy(ctx.target.ssl)
    frozen["rdap"] = copy.deepcopy(ctx.target.rdap)
    frozen["safe_browsing"] = copy.deepcopy(ctx.target.safe_browsing)

    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_map = {executor.submit(rule.fn, frozen): rule for rule in rules}
        timed_out = False
        futures_iter = as_completed(future_map, timeout=MAX_SCAN_SECONDS)

        try:
            while True:
                try:
                    future = next(futures_iter)
                except StopIteration:
                    break
                except FuturesTimeout:
                    timed_out = True
                    logger.error("Scan timeout para %s — aproveitando resultados parciais", ctx.target.url)
                    executor.shutdown(wait=False, cancel_futures=True)
                    break

                rule = future_map[future]
                try:
                    data = future.result()
                except Exception as e:
                    logger.error("Rule %s falhou com exceção: %s", rule.name, e, exc_info=True)
                    continue

                if data is None:
                    logger.warning("Rule %s retornou None, ignorando", rule.name)
                    continue

                ctx.results.append(ScanResult(
                    name=rule.name,
                    value=data.normalized,
                    weight=rule.weight,
                    category=rule.category,
                    severity=rule.severity,
                    details=data.details,
                ))

        except Exception as e:
            logger.critical("Erro inesperado no loop de execução das rules: %s", e, exc_info=True)
            return {
                "status": "error",
                "error": {
                    "type": "execution_error",
                    "message": str(e),
                }
            }

    if timed_out and not ctx.results:
        return {
            "status": "error",
            "error": {
                "type": "scan_timeout",
                "message": "Scan excedeu o tempo limite e nenhuma rule completou",
            }
        }

    ctx.results_map = {r.name: r.value for r in ctx.results}
    return None