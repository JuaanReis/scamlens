from pathlib import Path
from math import isfinite
from scamLens import config as app_config
from scamLens import scoring_fingerprint
from providers.database.connection import init_db
import plugins.scurl.heuristics as heuristics
from plugins.scurl.models.scan_context import ScanContext, TargetData
from plugins.scurl.heuristics.registry import get_rules
from providers.database.cache import load_cache, persist_scan
from plugins.scurl import config
from plugins.scurl.engine.pipeline import (
    validate_target, collect_target_data,
    execute_rules, calculate_score,
    build_response, build_error_response,
    meta_attribute, validate_input_qr
)

def run_engine(source: str | Path | bytes, k: int | None = None, timeout: float | None = None, processors: int | None = None, retries: int | None = None, use_cache: bool = False, *, score_model: str | None = None) -> tuple[dict, dict]:
    scanner_config = config["scanner"]
    k = scanner_config["k"] if k is None else k
    timeout = scanner_config["timeout"] if timeout is None else timeout
    processors = scanner_config["threads"] if processors is None else processors
    retries = scanner_config["retries"] if retries is None else retries
    score_model = scanner_config["score_model"] if score_model is None else score_model
    if any(type(value) not in (int, float) or not isfinite(value) or value <= 0 for value in (k, timeout, processors, retries)):
        raise ValueError("k, timeout, processors e retries devem ser positivos")
    if type(processors) is not int or type(retries) is not int:
        raise ValueError("processors e retries devem ser inteiros")
    if score_model not in ("legacy", "grouped"):
        raise ValueError(f"Modelo de score desconhecido: {score_model}")
    qr_result = validate_input_qr(source)

    if qr_result.get("status") == "error":
        return qr_result, {}

    url = qr_result.get("meta", {}).get("data", source)

    ctx = ScanContext(target=TargetData(url=url))

    if error := validate_target(ctx):
        return error, {}

    cache_enabled = use_cache and scanner_config["cache"]
    if cache_enabled:
        init_db()
        if cached := load_cache(ctx.meta.url_hash, k=k, score_model=score_model):
            return cached

    if error := collect_target_data(ctx, timeout, retries):
        return error, {}

    rules = get_rules()

    if error := execute_rules(ctx, rules, processors):
        return build_error_response(ctx, error_type=error["error"]["type"],
                                    message=error["error"]["message"]), {}

    meta_attribute(ctx, 1)
    calculate_score(ctx, k, score_model)

    if (not ctx.weights or not isfinite(sum(ctx.weights)) or sum(ctx.weights) <= 0
            or not isfinite(ctx.score)):
        return build_error_response(ctx, error_type="no_rule_coverage",
                                    message="Nenhuma regra efetiva disponível para calcular o risco"), {}

    scan_result, target_data = build_response(ctx, rules_total=len(rules))
    scan_result["scoring"] = {"model": score_model, "k": k, "config_hash": scoring_fingerprint(app_config)}
    if cache_enabled:
        persist_scan(scan_result, target_data)

    return scan_result, target_data
