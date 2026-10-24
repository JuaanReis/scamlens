from providers.database.repository import find_by_hash, save_scan
from datetime import datetime, timezone
from scamLens import config
from scamLens import scoring_fingerprint

def load_cache(url_hash: str, *, k: int | None = None, score_model: str | None = None) -> tuple[dict, dict] | None:
    from plugins.scurl import __version__

    scanner_config = config["scurl"]["scanner"]
    cached = find_by_hash(url_hash)
    if not cached:
        return None
    scan, target = cached
    if scan.get("status") != "ok":
        return None
    k = scanner_config["k"] if k is None else k
    score_model = scanner_config["score_model"] if score_model is None else score_model
    if scan.get("engine", {}).get("version") != __version__:
        return None
    if scan.get("scoring") != {"model": score_model, "k": k, "config_hash": scoring_fingerprint(config)}:
        return None
    try:
        timestamp = datetime.fromisoformat(scan["meta"]["timestamp"])
        age = (datetime.now(timezone.utc) - timestamp).total_seconds()
    except (KeyError, TypeError, ValueError):
        return None
    if not 0 <= age < scanner_config["cache_ttl_seconds"]:
        return None
    return scan, target

def persist_scan(scan_result: dict, target_data: dict) -> None:
    save_scan(scan_result, target_data)
