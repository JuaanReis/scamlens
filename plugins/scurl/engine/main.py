from pathlib import Path
from time import perf_counter
from math import isfinite
from datetime import datetime, timezone
import plugins.scurl.heuristics
from plugins.scurl.models.scan_context import ScanContext, TargetData
from plugins.scurl.heuristics.registry import get_rules
from providers.database.cache import load_cache, persist_scan
from plugins.scurl import config, __version__
from plugins.scurl.engine.pipeline import (
    validate_target,
    collect_target_data,
    execute_rules,
    calculate_score,
    build_response,
    build_error_response,
    meta_attribute,
    validate_input_qr,
)

def run_engine(
    source: str | Path | bytes,
    k: float = 5,
    timeout: float = 5,
    processors: int = 2,
    retries: int = 3,
    use_cache: bool = False,
    *,
    score_model: str | None = None,
) -> tuple[dict, dict]:
    if not isfinite(k) or not 0.1 <= k <= 20:
        raise ValueError("k must be .1..20")
    
    if not isfinite(timeout) or timeout <= 0:
        raise ValueError("timeout must be positive")
    
    if not isinstance(retries, int) or not 1 <= retries <= 5:
        raise ValueError("retries must be 1..5")
    
    if not isinstance(processors, int) or not 1 <= processors <= 8:
        raise ValueError("processors must be 1..8")
    
    score_model = score_model or config["scanner"].get("score_model", "grouped")

    if score_model not in ("grouped", "legacy"):
        raise ValueError("invalid score_model")
    
    qr_result = validate_input_qr(source)
    if qr_result.get("status") == "error":
        return qr_result, {}
    
    url = qr_result.get("meta", {}).get("data", source)
    ctx = ScanContext(target=TargetData(url=url))
    start = perf_counter()

    if error := validate_target(ctx):
        return error, {}
    
    ctx.meta.timings["validation_s"] = perf_counter() - start
    cache_enabled = use_cache and config["scanner"]["cache"]

    if cache_enabled:
        cached = load_cache(ctx.meta.url_hash)
        if cached:
            scan, target = cached
            try:
                age = (
                    datetime.now(timezone.utc)
                    - datetime.fromisoformat(scan["meta"]["timestamp"])
                ).total_seconds()
                if (
                    0 <= age < config["scanner"].get("cache_ttl_seconds", 300)
                    and scan["engine"]["version"] == __version__
                    and scan.get("scoring", {}).get("k") == k
                    and scan.get("scoring", {}).get("model") == score_model
                ):
                    return scan, target
            except (KeyError, TypeError, ValueError):
                pass

    if error := collect_target_data(ctx, timeout, retries, processors):
        return error, {}
    
    rules = get_rules()
    if error := execute_rules(ctx, rules, processors):
        return build_error_response(ctx, **error["error"]), {}
    
    meta_attribute(ctx, max(1, min(processors, 2)))
    calculate_score(ctx, k, score_model)
    ctx.scoring["model"] = score_model
    scan, target = build_response(ctx, rules_total=len(rules))
    
    if cache_enabled:
        persist_scan(scan, target)
        
    return scan, target
