from pathlib import Path
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

def run_engine(source: str | Path | bytes, k: int = 5, timeout: float = 5, processors: int = 2, retries: int = 3, use_cache: bool = False) -> tuple[dict, dict]:
    qr_result = validate_input_qr(source) 

    if qr_result.get("status") == "error":
        return qr_result, {}

    url = qr_result.get("meta", {}).get("data", source) 

    ctx = ScanContext(target=TargetData(url=url))

    if use_cache and config.get("scanner", {}).get("cache", False):
        if cached := load_cache(ctx.meta.url_hash):
            return cached

    if error := validate_target(ctx):
        return error, {}

    if error := collect_target_data(ctx, timeout, retries):
        return error, {}

    rules = get_rules()

    if error := execute_rules(ctx, rules, processors):
        return build_error_response(ctx, **error["error"]), {}

    meta_attribute(ctx, processors)
    calculate_score(ctx, k)

    scan_result, target_data = build_response(ctx, rules_total=len(rules))
    persist_scan(scan_result, target_data)

    return scan_result, target_data